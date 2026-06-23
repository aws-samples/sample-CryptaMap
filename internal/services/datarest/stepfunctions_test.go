package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyStateMachineEncryption is the regulator-honesty guardrail for the
// Step Functions at-rest classifier. Step Functions ALWAYS encrypts execution
// history at rest with an AES-256 KMS envelope and there is no toggle to disable
// it, so the posture must be models.PostureSymmetricOnly in EVERY branch — never
// PostureNoEncryption, even for a nil/empty EncryptionConfiguration. The
// EncryptionConfiguration only selects the key TIER (AWS-owned default vs
// customer CMK); the AWS-owned default must NOT be dressed up as a clean
// all-clear and must carry the explicit "no customer key custody" note.
func TestClassifyStateMachineEncryption(t *testing.T) {
	const (
		accountID = "111122223333"
		region    = "us-east-1"
		cmkARN    = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	)

	cases := []struct {
		name string
		ec   *sfntypes.EncryptionConfiguration
		// expectations
		wantPosture  models.CryptoPosture
		wantKmsKeyID string
		wantEncType  string
		wantKeyTier  string // "" => keyTier property must be ABSENT (customer CMK)
		wantNote     bool   // true => AWS-owned "no customer key custody" note present
		wantReuse    string // "" => kmsDataKeyReusePeriodSeconds property absent
	}{
		{
			// Customer CMK present -> CMK ARN recorded, no AWS-owned note.
			name: "customer_managed_cmk",
			ec: &sfntypes.EncryptionConfiguration{
				Type:                         sfntypes.EncryptionTypeCustomerManagedKmsKey,
				KmsKeyId:                     aws.String(cmkARN),
				KmsDataKeyReusePeriodSeconds: aws.Int32(300),
			},
			wantPosture:  models.PostureSymmetricOnly,
			wantKmsKeyID: cmkARN,
			wantEncType:  "CUSTOMER_MANAGED_KMS_KEY",
			wantKeyTier:  "",
			wantNote:     false,
			wantReuse:    "300",
		},
		{
			// Explicit AWS_OWNED_KEY -> AWS-owned sentinel + custody note,
			// still SymmetricOnly (NOT a clean all-clear, NOT no-encryption).
			name: "aws_owned_key_explicit",
			ec: &sfntypes.EncryptionConfiguration{
				Type: sfntypes.EncryptionTypeAwsOwnedKey,
			},
			wantPosture:  models.PostureSymmetricOnly,
			wantKmsKeyID: "AWS_OWNED_KMS_KEY",
			wantEncType:  "AWS_OWNED_KEY",
			wantKeyTier:  "aws-owned-default",
			wantNote:     true,
			wantReuse:    "",
		},
		{
			// CUSTOMER_MANAGED type but KmsKeyId empty/absent -> must fall back to
			// the AWS-owned sentinel (never an empty/fabricated key custody claim).
			name: "customer_managed_type_but_no_key_id",
			ec: &sfntypes.EncryptionConfiguration{
				Type: sfntypes.EncryptionTypeCustomerManagedKmsKey,
			},
			wantPosture:  models.PostureSymmetricOnly,
			wantKmsKeyID: "AWS_OWNED_KMS_KEY",
			wantEncType:  "CUSTOMER_MANAGED_KMS_KEY",
			// encType != AWS_OWNED_KEY, so no keyTier/note even though custody is
			// actually AWS-owned. (This documents current behavior; the kmsKeyId
			// sentinel still prevents a false customer-custody all-clear.)
			wantKeyTier: "",
			wantNote:    false,
			wantReuse:   "",
		},
		{
			// Empty Type string -> degrades to AWS-owned default branch.
			name: "empty_type_string",
			ec: &sfntypes.EncryptionConfiguration{
				Type: sfntypes.EncryptionType(""),
			},
			wantPosture:  models.PostureSymmetricOnly,
			wantKmsKeyID: "AWS_OWNED_KMS_KEY",
			wantEncType:  "AWS_OWNED_KEY",
			wantKeyTier:  "aws-owned-default",
			wantNote:     true,
			wantReuse:    "",
		},
		{
			// nil EncryptionConfiguration -> must NOT crash and must degrade to the
			// AWS-owned default (encrypted), NEVER PostureNoEncryption.
			name:         "nil_encryption_config",
			ec:           nil,
			wantPosture:  models.PostureSymmetricOnly,
			wantKmsKeyID: "AWS_OWNED_KMS_KEY",
			wantEncType:  "AWS_OWNED_KEY",
			wantKeyTier:  "aws-owned-default",
			wantNote:     true,
			wantReuse:    "",
		},
	}

	const awsOwnedNote = "Step Functions always encrypts execution history at rest with AES-256; this state machine uses the AWS-owned default key (no customer key custody), not a clean all-clear and not a no-encryption finding."

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := classifyStateMachineEncryption(accountID, region, "my-sm", sfntypes.StateMachineTypeStandard, c.ec)

			// Posture: always SymmetricOnly; explicitly reject no-encryption.
			if got := a.Properties["posture"]; got != string(c.wantPosture) {
				t.Errorf("posture = %q, want %q", got, c.wantPosture)
			}
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Fatalf("HONESTY VIOLATION: always-encrypted Step Functions reported %q", models.PostureNoEncryption)
			}

			if got := a.Properties["kmsKeyId"]; got != c.wantKmsKeyID {
				t.Errorf("kmsKeyId = %q, want %q", got, c.wantKmsKeyID)
			}
			if got := a.Properties["encryptionType"]; got != c.wantEncType {
				t.Errorf("encryptionType = %q, want %q", got, c.wantEncType)
			}

			// keyTier presence/value.
			if c.wantKeyTier == "" {
				if got, ok := a.Properties["keyTier"]; ok {
					t.Errorf("keyTier present = %q, want absent", got)
				}
			} else if got := a.Properties["keyTier"]; got != c.wantKeyTier {
				t.Errorf("keyTier = %q, want %q", got, c.wantKeyTier)
			}

			// AWS-owned "no customer key custody / not a clean all-clear" note.
			note, hasNote := a.Properties["note"]
			if c.wantNote {
				if !hasNote || note != awsOwnedNote {
					t.Errorf("AWS-owned custody note missing/wrong: %q", note)
				}
			} else if hasNote {
				t.Errorf("note present for customer-CMK branch = %q, want absent", note)
			}

			// kmsDataKeyReusePeriodSeconds.
			if c.wantReuse == "" {
				if got, ok := a.Properties["kmsDataKeyReusePeriodSeconds"]; ok {
					t.Errorf("kmsDataKeyReusePeriodSeconds present = %q, want absent", got)
				}
			} else if got := a.Properties["kmsDataKeyReusePeriodSeconds"]; got != c.wantReuse {
				t.Errorf("kmsDataKeyReusePeriodSeconds = %q, want %q", got, c.wantReuse)
			}

			// Asset identity / cipher invariants common to every branch.
			if a.ResourceType != "AWS::StepFunctions::StateMachine" {
				t.Errorf("resourceType = %q", a.ResourceType)
			}
			if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
				t.Errorf("expected AES-256 at-rest cipher, got %+v", a.CryptoProps.AlgorithmProperties)
			}
			if got := a.Properties["stateMachineType"]; got != string(sfntypes.StateMachineTypeStandard) {
				t.Errorf("stateMachineType = %q, want %q", got, sfntypes.StateMachineTypeStandard)
			}
		})
	}
}
