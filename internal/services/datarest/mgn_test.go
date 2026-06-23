package datarest

import (
	"testing"

	mgntypes "github.com/aws/aws-sdk-go-v2/service/mgn/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestMGNAssetForClassification is the regulator-honesty guardrail for the MGN
// replication-template at-rest classifier. MGN staging volumes are EBS volumes,
// always encrypted (AES-256-XTS), so the posture must be UNCONDITIONALLY
// SymmetricOnly and NEVER PostureNoEncryption — the EbsEncryption field only
// selects the KEY TIER (customer CMK vs AWS default EBS key), never an off state.
//
// It drives the pure assetFor classifier directly (no AWS client, no context)
// and asserts the EXACT posture constant and the EXACT Property keys/values:
//   - CUSTOM + EbsEncryptionKeyArn -> SymmetricOnly, kmsKeyId = the CMK ARN.
//   - CUSTOM without an ARN        -> SymmetricOnly, kmsKeyId sentinel (no fabricated CMK).
//   - DEFAULT                      -> SymmetricOnly, AWS_DEFAULT_EBS_KEY + the
//     "no customer key custody / not a clean all-clear" note (NOT no-encryption).
//   - empty/unset (zero value)     -> degrades to the DEFAULT branch, never crashes,
//     never a fabricated all-clear.
func TestMGNAssetForClassification(t *testing.T) {
	const (
		acct   = "111122223333"
		region = "us-east-1"
		cmkARN = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	)

	str := func(s string) *string { return &s }

	cases := []struct {
		name string
		tmpl mgntypes.ReplicationConfigurationTemplate

		wantPosture  models.CryptoPosture
		wantKMS      string            // expected Properties["kmsKeyId"]
		wantProps    map[string]string // additional exact Property key/value assertions
		wantAbsent   []string          // Property keys that must NOT be present
		wantAlgoName string            // CryptoProps.AlgorithmProperties.AlgorithmName
	}{
		{
			name: "custom CMK present -> customer key custody",
			tmpl: mgntypes.ReplicationConfigurationTemplate{
				ReplicationConfigurationTemplateID: str("rct-custom"),
				EbsEncryption:                      mgntypes.ReplicationConfigurationEbsEncryptionCustom,
				EbsEncryptionKeyArn:                str(cmkARN),
			},
			wantPosture: models.PostureSymmetricOnly,
			wantKMS:     cmkARN,
			wantProps: map[string]string{
				"ebsEncryption": "CUSTOM",
			},
			// CUSTOM with a real CMK is NOT the AWS-default branch: no
			// aws-managed-default keyTier, no "no custody" note.
			wantAbsent:   []string{"keyTier", "note"},
			wantAlgoName: "AES-256-XTS",
		},
		{
			name: "custom selected but ARN missing -> sentinel, no fabricated key",
			tmpl: mgntypes.ReplicationConfigurationTemplate{
				ReplicationConfigurationTemplateID: str("rct-custom-noarn"),
				EbsEncryption:                      mgntypes.ReplicationConfigurationEbsEncryptionCustom,
				// EbsEncryptionKeyArn deliberately nil.
			},
			wantPosture: models.PostureSymmetricOnly,
			wantKMS:     "CUSTOM_KEY_UNRESOLVED",
			wantProps: map[string]string{
				"ebsEncryption": "CUSTOM",
			},
			wantAbsent:   []string{"keyTier", "note"},
			wantAlgoName: "AES-256-XTS",
		},
		{
			name: "DEFAULT -> AWS-managed default key, not a clean all-clear",
			tmpl: mgntypes.ReplicationConfigurationTemplate{
				ReplicationConfigurationTemplateID: str("rct-default"),
				EbsEncryption:                      mgntypes.ReplicationConfigurationEbsEncryptionDefault,
			},
			wantPosture: models.PostureSymmetricOnly,
			wantKMS:     "AWS_DEFAULT_EBS_KEY",
			wantProps: map[string]string{
				"ebsEncryption": "DEFAULT",
				"keyTier":       "aws-managed-default",
				"note":          "MGN staging volumes use the account default EBS encryption key (aws/ebs); AES-256 at rest but no customer key custody.",
			},
			wantAlgoName: "AES-256-XTS",
		},
		{
			name: "empty/unset zero value -> degrades to DEFAULT branch, no crash, no all-clear",
			tmpl: mgntypes.ReplicationConfigurationTemplate{
				// No ID, no EbsEncryption (zero value "") -> default branch.
			},
			wantPosture: models.PostureSymmetricOnly,
			wantKMS:     "AWS_DEFAULT_EBS_KEY",
			wantProps: map[string]string{
				"ebsEncryption": "",
				"keyTier":       "aws-managed-default",
				"note":          "MGN staging volumes use the account default EBS encryption key (aws/ebs); AES-256 at rest but no customer key custody.",
			},
			wantAlgoName: "AES-256-XTS",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := MGNScanner{}.assetFor(acct, region, c.tmpl)

			// HONESTY CONTRACT: an always-encrypted service must NEVER report
			// no-encryption; posture must be exactly the encrypted constant.
			if got := a.Properties["posture"]; got != string(c.wantPosture) {
				t.Errorf("posture = %q, want %q", got, c.wantPosture)
			}
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Errorf("posture is %q for an always-encrypted EBS-backed service — false no-encryption", models.PostureNoEncryption)
			}

			if got := a.Properties["kmsKeyId"]; got != c.wantKMS {
				t.Errorf("kmsKeyId = %q, want %q", got, c.wantKMS)
			}

			for k, want := range c.wantProps {
				if got := a.Properties[k]; got != want {
					t.Errorf("Properties[%q] = %q, want %q", k, got, want)
				}
			}
			for _, k := range c.wantAbsent {
				if got, ok := a.Properties[k]; ok {
					t.Errorf("Properties[%q] = %q, want ABSENT", k, got)
				}
			}

			// EBS is AES-256-XTS, not GCM — must use the XTS at-rest cipher.
			if a.CryptoProps.AlgorithmProperties == nil {
				t.Fatalf("AlgorithmProperties is nil; want %s", c.wantAlgoName)
			}
			if got := a.CryptoProps.AlgorithmProperties.AlgorithmName; got != c.wantAlgoName {
				t.Errorf("AlgorithmName = %q, want %q", got, c.wantAlgoName)
			}

			if a.ResourceType != "AWS::MGN::ReplicationConfigurationTemplate" {
				t.Errorf("ResourceType = %q, want AWS::MGN::ReplicationConfigurationTemplate", a.ResourceType)
			}

			// DEFAULT branch MUST carry the "no customer key custody" note so an
			// AWS-managed default can never masquerade as a clean all-clear.
			if c.wantKMS == "AWS_DEFAULT_EBS_KEY" {
				if note := a.Properties["note"]; note == "" {
					t.Errorf("AWS-default branch missing the 'no customer key custody' note — risks a false clean all-clear")
				}
			}
		})
	}
}
