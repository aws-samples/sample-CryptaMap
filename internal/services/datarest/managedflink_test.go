package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	kav2types "github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2/types"
)

// TestClassifyFlinkKeyTier is the regulator-honesty guardrail for the managed
// Flink at-rest key-custody classification. Managed Service for Apache Flink
// ALWAYS encrypts durable application state at rest with AES-256 (no toggle), so
// the POSTURE is unconditionally SymmetricOnly and is asserted at the Scan level,
// never here — this helper only resolves the key tier. The cases lock in:
//   - a customer CMK is surfaced as the CMK id with customer-managed custody,
//   - an AWS-owned key (observed) is still encrypted but is NOT a clean all-clear,
//   - an absent encryption-config block degrades to the AWS-owned DEFAULT (sentinel
//   - honesty note), NEVER to no-encryption and NEVER to a fabricated all-clear.
func TestClassifyFlinkKeyTier(t *testing.T) {
	const cmkARN = "arn:aws:kms:us-east-1:111122223333:key/abcd-ef01-2345"
	const ownedSentinel = "AWS_OWNED_KMS_KEY"

	cases := []struct {
		name string
		in   *kav2types.ApplicationEncryptionConfigurationDescription

		wantKMSKeyID string
		wantKeyTier  string
		wantKeyType  string // expected keyType property ("" => Scan omits the property)
		wantObserved bool
		wantHasNote  bool // honesty note expected (absent-block AWS-owned default)
	}{
		{
			name: "customer CMK present",
			in: &kav2types.ApplicationEncryptionConfigurationDescription{
				KeyType: kav2types.KeyTypeCustomerManagedKey,
				KeyId:   aws.String(cmkARN),
			},
			wantKMSKeyID: cmkARN,
			wantKeyTier:  "customer-managed",
			wantKeyType:  "CUSTOMER_MANAGED_KEY",
			wantObserved: true,
			wantHasNote:  false,
		},
		{
			name: "customer CMK type but empty KeyId -> still customer tier, sentinel id",
			in: &kav2types.ApplicationEncryptionConfigurationDescription{
				KeyType: kav2types.KeyTypeCustomerManagedKey,
				KeyId:   aws.String(""),
			},
			wantKMSKeyID: ownedSentinel,
			wantKeyTier:  "customer-managed",
			wantKeyType:  "CUSTOMER_MANAGED_KEY",
			wantObserved: true,
			wantHasNote:  false,
		},
		{
			name: "AWS-owned key observed -> encrypted but no customer custody, not a clean all-clear",
			in: &kav2types.ApplicationEncryptionConfigurationDescription{
				KeyType: kav2types.KeyTypeAwsOwnedKey,
			},
			wantKMSKeyID: ownedSentinel,
			wantKeyTier:  "aws-owned",
			wantKeyType:  "AWS_OWNED_KEY",
			wantObserved: true,
			wantHasNote:  false,
		},
		{
			name: "non-nil block with empty KeyType -> AWS-managed default, not observed",
			in: &kav2types.ApplicationEncryptionConfigurationDescription{
				KeyType: "",
			},
			wantKMSKeyID: ownedSentinel,
			wantKeyTier:  "aws-managed-default",
			wantKeyType:  "", // empty enum -> Scan omits the keyType property
			wantObserved: false,
			wantHasNote:  false,
		},
		{
			name:         "nil encryption-config block -> AWS-owned default with honesty note",
			in:           nil,
			wantKMSKeyID: ownedSentinel,
			wantKeyTier:  "aws-managed-default",
			wantKeyType:  "",
			wantObserved: false,
			wantHasNote:  true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyFlinkKeyTier(c.in)

			if got.kmsKeyID != c.wantKMSKeyID {
				t.Errorf("kmsKeyID = %q, want %q", got.kmsKeyID, c.wantKMSKeyID)
			}
			if got.keyTier != c.wantKeyTier {
				t.Errorf("keyTier = %q, want %q", got.keyTier, c.wantKeyTier)
			}
			if got.keyTypeProp != c.wantKeyType {
				t.Errorf("keyTypeProp = %q, want %q", got.keyTypeProp, c.wantKeyType)
			}
			if got.observed != c.wantObserved {
				t.Errorf("observed = %v, want %v", got.observed, c.wantObserved)
			}
			if (got.note != "") != c.wantHasNote {
				t.Errorf("note present = %v (note=%q), want present = %v", got.note != "", got.note, c.wantHasNote)
			}

			// HONESTY CONTRACT: the at-rest key NEVER fabricates a clean all-clear.
			// Whenever the resolved key is the AWS-owned/managed sentinel, the tier
			// MUST be an AWS-owned/managed-default tier (never "customer-managed"
			// with the sentinel implying customer custody), so the dashboard cannot
			// render an AWS-owned default as a verified-safe customer key.
			if got.kmsKeyID == ownedSentinel && got.keyTier == "customer-managed" {
				// Allowed only when the API explicitly reported CUSTOMER_MANAGED_KEY
				// (observed) but withheld the id; that is a surfaced custody claim,
				// not a fabricated all-clear, so require it to be observed.
				if !got.observed {
					t.Errorf("AWS-owned sentinel with customer-managed tier must be an observed API claim, not a fabricated all-clear")
				}
			}

			// HONESTY CONTRACT: the absent-block fallback (nil) MUST carry the
			// no-customer-key-custody note and MUST NOT be marked observed — it is a
			// documented universal-guarantee fallback, not a live tier reading.
			if c.in == nil {
				if got.note == "" {
					t.Errorf("nil block must carry the no-customer-key-custody honesty note")
				}
				if got.observed {
					t.Errorf("nil block must NOT be observed (it is a doc-fact fallback, not a live API reading)")
				}
			}
		})
	}
}
