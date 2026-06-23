package certmgmt

import (
	"strings"
	"testing"

	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifySESDKIM is the regulator-honesty guardrail for the SES DKIM signing
// scanner. DKIM is a SIGNING surface, not encryption, so NO branch may ever return
// PostureNoEncryption — the table asserts the exact posture constant and the exact
// Property keys/values for every real branch:
//   - signing ENABLED  -> NonPQCClassical (active classical RSA, quantum-vulnerable),
//     with key length + custody (AWS_SES Easy-DKIM vs EXTERNAL BYODKIM) recorded.
//   - signing DISABLED -> Unknown (no active signature surface; not a finding),
//     NEVER no-encryption.
//   - nil DkimAttributes -> Unknown (DKIM not configured), degrades safely, no crash,
//     no fabricated all-clear.
func TestClassifySESDKIM(t *testing.T) {
	const (
		acct   = "111122223333"
		region = "us-east-1"
	)

	cases := []struct {
		name         string
		identityType sesv2types.IdentityType
		dkim         *sesv2types.DkimAttributes
		wantPosture  models.CryptoPosture
		wantProps    map[string]string // exact key/value assertions
		// noteContains: substrings that MUST appear in the note (custody / honesty).
		noteContains []string
		// signature-surface invariants (always-true for this signing scanner)
		wantPrimitive models.AlgorithmPrimitive
		wantAlgo      string
	}{
		{
			// Easy-DKIM enabled with RSA_2048: AWS holds the private key.
			name:         "enabled_easy_dkim_aws_ses_rsa2048",
			identityType: sesv2types.IdentityTypeDomain,
			dkim: &sesv2types.DkimAttributes{
				SigningEnabled:          true,
				SigningAttributesOrigin: sesv2types.DkimSigningAttributesOriginAwsSes,
				Status:                  sesv2types.DkimStatusSuccess,
				CurrentSigningKeyLength: sesv2types.DkimSigningKeyLengthRsa2048Bit,
			},
			wantPosture: models.PostureNonPQCClassical,
			wantProps: map[string]string{
				"signingEnabled":          "true",
				"signingAttributesOrigin": "AWS_SES",
				"dkimStatus":              "SUCCESS",
				"signingKeyLength":        "RSA_2048_BIT",
				"identityType":            "DOMAIN",
				"posture":                 "non-pqc-classical",
				"source":                  "observed",
				"confidence":              "high",
			},
			noteContains: []string{
				"classical RSA signature",
				"RSA_2048_BIT",
				"quantum-vulnerable",
				"Easy-DKIM (AWS_SES): AWS holds the DKIM private key",
			},
			wantPrimitive: models.PrimitiveSignature,
			wantAlgo:      "RSA",
		},
		{
			// BYODKIM (EXTERNAL): customer-supplied key, no length reported.
			name:         "enabled_byodkim_external_no_keylen",
			identityType: sesv2types.IdentityTypeEmailAddress,
			dkim: &sesv2types.DkimAttributes{
				SigningEnabled:          true,
				SigningAttributesOrigin: sesv2types.DkimSigningAttributesOriginExternal,
				Status:                  sesv2types.DkimStatusSuccess,
				// CurrentSigningKeyLength intentionally zero-value (not reported).
			},
			wantPosture: models.PostureNonPQCClassical,
			wantProps: map[string]string{
				"signingEnabled":          "true",
				"signingAttributesOrigin": "EXTERNAL",
				"posture":                 "non-pqc-classical",
				"source":                  "observed",
			},
			noteContains: []string{
				"classical RSA signature",
				"BYODKIM (EXTERNAL): customer-supplied DKIM key",
			},
			wantPrimitive: models.PrimitiveSignature,
			wantAlgo:      "RSA",
		},
		{
			// Signing DISABLED: honest Unknown, never no-encryption.
			name:         "disabled_signing_unknown",
			identityType: sesv2types.IdentityTypeDomain,
			dkim: &sesv2types.DkimAttributes{
				SigningEnabled: false,
				Status:         sesv2types.DkimStatusNotStarted,
			},
			wantPosture: models.PostureUnknown,
			wantProps: map[string]string{
				"signingEnabled": "false",
				"dkimStatus":     "NOT_STARTED",
				"posture":        "unknown",
				"source":         "observed",
			},
			noteContains: []string{
				"signing is NOT enabled",
				"signing), not encryption",
			},
			wantPrimitive: models.PrimitiveSignature,
			wantAlgo:      "RSA",
		},
		{
			// nil DkimAttributes: degrade safely to Unknown, no crash, no all-clear.
			name:         "nil_dkim_attributes_unknown",
			identityType: sesv2types.IdentityTypeDomain,
			dkim:         nil,
			wantPosture:  models.PostureUnknown,
			wantProps: map[string]string{
				"signingEnabled": "false",
				"posture":        "unknown",
				"identityType":   "DOMAIN",
			},
			noteContains: []string{
				"no DKIM attributes",
				"signing), not encryption",
			},
			wantPrimitive: models.PrimitiveSignature,
			wantAlgo:      "RSA",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := classifySESDKIM(acct, region, "example.com", c.identityType, c.dkim)

			// HONESTY CONTRACT: DKIM is signing, NEVER encryption. No branch may
			// claim posture "no-encryption", and the asset must never be shaped as
			// a no-encryption at-rest block.
			if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
				t.Fatalf("DKIM signing scanner emitted no-encryption posture %q — DKIM is signing, not encryption", got)
			}

			if got := models.CryptoPosture(a.Properties["posture"]); got != c.wantPosture {
				t.Errorf("posture = %q, want %q", got, c.wantPosture)
			}

			// Always a classical RSA SIGNATURE surface, regardless of enabled state.
			if a.CryptoProps.AlgorithmProperties == nil {
				t.Fatalf("AlgorithmProperties is nil; expected a signature block")
			}
			if got := a.CryptoProps.AlgorithmProperties.Primitive; got != c.wantPrimitive {
				t.Errorf("primitive = %q, want %q", got, c.wantPrimitive)
			}
			if got := a.CryptoProps.AlgorithmProperties.AlgorithmName; got != c.wantAlgo {
				t.Errorf("algorithmName = %q, want %q", got, c.wantAlgo)
			}
			// Classical signature => no NIST PQ level.
			if got := a.CryptoProps.AlgorithmProperties.NistQuantumSecurityLevel; got != 0 {
				t.Errorf("nistQuantumSecurityLevel = %d, want 0 (classical RSA)", got)
			}

			// Exact resource shape.
			if a.ResourceType != "AWS::SES::EmailIdentity" {
				t.Errorf("resourceType = %q, want AWS::SES::EmailIdentity", a.ResourceType)
			}

			for k, want := range c.wantProps {
				if got := a.Properties[k]; got != want {
					t.Errorf("Properties[%q] = %q, want %q", k, got, want)
				}
			}

			note := a.Properties["note"]
			if note == "" {
				t.Errorf("note is empty; expected an explicit honesty note")
			}
			for _, sub := range c.noteContains {
				if !strings.Contains(note, sub) {
					t.Errorf("note %q does not contain %q", note, sub)
				}
			}
		})
	}
}
