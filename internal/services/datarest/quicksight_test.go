package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	qstypes "github.com/aws/aws-sdk-go-v2/service/quicksight/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyQuickSightKeyRegistration is the regulator-honesty guardrail for the
// QuickSight at-rest scanner. QuickSight stored data is ALWAYS AES-256 at rest with
// no "disable encryption" surface, so EVERY branch below must classify as
// PostureSymmetricOnly — never PostureNoEncryption, never a fabricated all-clear.
// The customer-CMK vs AWS-managed-default distinction is carried by kmsKeyId /
// keyTier / note, not by the posture.
func TestClassifyQuickSightKeyRegistration(t *testing.T) {
	const (
		acct   = "111122223333"
		region = "us-east-1"
		cmkArn = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	)

	cases := []struct {
		name string
		reg  []qstypes.RegisteredCustomerManagedKey

		wantCount    int
		wantPosture  models.CryptoPosture
		wantKMSKeyID string // checked on assets[0]
		wantKeyTier  string
		// wantDefaultKeyPresent: whether the "defaultKey" property must be set on assets[0].
		wantDefaultKeyPresent bool
		// wantNoCustodyNote: assets[0].note must mention there is no customer key custody.
		wantNoCustodyNote bool
	}{
		{
			// Customer CMK present (also the account default) -> SymmetricOnly,
			// kmsKeyId = the CMK ARN, keyTier customer-managed, defaultKey=true.
			name: "customer-cmk-default",
			reg: []qstypes.RegisteredCustomerManagedKey{
				{KeyArn: aws.String(cmkArn), DefaultKey: true},
			},
			wantCount:             1,
			wantPosture:           models.PostureSymmetricOnly,
			wantKMSKeyID:          cmkArn,
			wantKeyTier:           "customer-managed",
			wantDefaultKeyPresent: true,
			wantNoCustodyNote:     false,
		},
		{
			// Customer CMK present but NOT the default key -> defaultKey property
			// must be ABSENT (we only stamp it when true).
			name: "customer-cmk-nondefault",
			reg: []qstypes.RegisteredCustomerManagedKey{
				{KeyArn: aws.String(cmkArn), DefaultKey: false},
			},
			wantCount:             1,
			wantPosture:           models.PostureSymmetricOnly,
			wantKMSKeyID:          cmkArn,
			wantKeyTier:           "customer-managed",
			wantDefaultKeyPresent: false,
			wantNoCustodyNote:     false,
		},
		{
			// Multiple registered CMKs -> one asset per key.
			name: "multiple-cmks",
			reg: []qstypes.RegisteredCustomerManagedKey{
				{KeyArn: aws.String(cmkArn), DefaultKey: true},
				{KeyArn: aws.String("arn:aws:kms:us-east-1:111122223333:key/efgh-5678"), DefaultKey: false},
			},
			wantCount:             2,
			wantPosture:           models.PostureSymmetricOnly,
			wantKMSKeyID:          cmkArn,
			wantKeyTier:           "customer-managed",
			wantDefaultKeyPresent: true,
			wantNoCustodyNote:     false,
		},
		{
			// Empty registration -> AWS-managed default key. STILL SymmetricOnly
			// (always-encrypted), kmsKeyId = AWS_MANAGED_DEFAULT sentinel, and the
			// note must flag "no customer key custody" so it is never read as a clean
			// all-clear.
			name:                  "empty-aws-managed-default",
			reg:                   []qstypes.RegisteredCustomerManagedKey{},
			wantCount:             1,
			wantPosture:           models.PostureSymmetricOnly,
			wantKMSKeyID:          "AWS_MANAGED_DEFAULT",
			wantKeyTier:           "aws-managed-default",
			wantDefaultKeyPresent: false,
			wantNoCustodyNote:     true,
		},
		{
			// Nil registration must degrade to the AWS-managed-default branch, never
			// crash and never fabricate an all-clear.
			name:                  "nil-aws-managed-default",
			reg:                   nil,
			wantCount:             1,
			wantPosture:           models.PostureSymmetricOnly,
			wantKMSKeyID:          "AWS_MANAGED_DEFAULT",
			wantKeyTier:           "aws-managed-default",
			wantDefaultKeyPresent: false,
			wantNoCustodyNote:     true,
		},
		{
			// Registered entry with a nil KeyArn (still a customer-managed
			// registration). Must not crash; kmsKeyId property is omitted (no ARN)
			// but keyTier stays customer-managed and posture stays SymmetricOnly.
			name: "customer-cmk-nil-arn",
			reg: []qstypes.RegisteredCustomerManagedKey{
				{KeyArn: nil, DefaultKey: false},
			},
			wantCount:             1,
			wantPosture:           models.PostureSymmetricOnly,
			wantKMSKeyID:          "", // no kmsKeyId property expected
			wantKeyTier:           "customer-managed",
			wantDefaultKeyPresent: false,
			wantNoCustodyNote:     false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assets := classifyQuickSightKeyRegistration(c.reg, acct, region)

			if len(assets) != c.wantCount {
				t.Fatalf("asset count = %d, want %d", len(assets), c.wantCount)
			}

			// EVERY asset must be the always-encrypted symmetric posture — never
			// no-encryption for this service.
			for i, a := range assets {
				if got := a.Properties["posture"]; got != string(c.wantPosture) {
					t.Errorf("assets[%d] posture = %q, want %q", i, got, c.wantPosture)
				}
				if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
					t.Errorf("assets[%d] posture is no-encryption for an always-encrypted service", i)
				}
				if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
					t.Errorf("assets[%d] algorithm = %+v, want AES-256", i, a.CryptoProps.AlgorithmProperties)
				}
			}

			a0 := assets[0]

			if c.wantKMSKeyID == "" {
				if v, ok := a0.Properties["kmsKeyId"]; ok {
					t.Errorf("assets[0] kmsKeyId = %q, want property absent", v)
				}
			} else if got := a0.Properties["kmsKeyId"]; got != c.wantKMSKeyID {
				t.Errorf("assets[0] kmsKeyId = %q, want %q", got, c.wantKMSKeyID)
			}

			if got := a0.Properties["keyTier"]; got != c.wantKeyTier {
				t.Errorf("assets[0] keyTier = %q, want %q", got, c.wantKeyTier)
			}

			_, hasDefault := a0.Properties["defaultKey"]
			if hasDefault != c.wantDefaultKeyPresent {
				t.Errorf("assets[0] defaultKey present = %v, want %v", hasDefault, c.wantDefaultKeyPresent)
			}

			// Honesty contract: the AWS-managed default branch must NOT read as a
			// clean all-clear — its note must spell out "no customer key custody".
			note := a0.Properties["note"]
			if c.wantNoCustodyNote {
				if !contains(note, "no customer key custody") {
					t.Errorf("assets[0] note = %q, want it to flag no customer key custody", note)
				}
				if !contains(note, "not a no-encryption finding") {
					t.Errorf("assets[0] note = %q, want it to clarify this is not no-encryption", note)
				}
			}

			// All branches must record the AWS-doc provenance for the universal
			// always-encrypted guarantee.
			if got := a0.Properties["source"]; got != "aws-doc" {
				t.Errorf("assets[0] source = %q, want aws-doc", got)
			}
		})
	}
}

// contains is a tiny substring helper kept local to avoid pulling strings into
// the test surface for one call site.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
