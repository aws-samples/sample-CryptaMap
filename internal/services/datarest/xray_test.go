package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	xraytypes "github.com/aws/aws-sdk-go-v2/service/xray/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyXRayEncryption is the regulator-honesty guardrail for the X-Ray
// at-rest classifier. X-Ray ALWAYS encrypts trace data at rest with AES-256 and
// it cannot be disabled, so every branch MUST classify as PostureSymmetricOnly —
// the test fails loudly if anyone later makes this always-encrypted service
// report no-encryption, or makes the AWS-owned internal default look like a clean
// all-clear (it carries a "no customer key custody" note and the
// AWS_DEFAULT_ENCRYPTION sentinel, never a customer KeyId).
func TestClassifyXRayEncryption(t *testing.T) {
	const custodyNote = "X-Ray always encrypts at rest; default is AWS-owned internal encryption, no customer key custody"
	const cmkArn = "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456"

	cases := []struct {
		name            string
		ec              *xraytypes.EncryptionConfig
		wantKmsKeyID    string
		wantEncType     string // expected "encryptionType" property; "" => key absent
		wantStatus      string // expected "status" property; "" => key absent
		wantNote        bool   // whether the custody note must be present
		wantCustomerKey bool   // whether this is a real customer CMK (no note)
	}{
		{
			// Customer CMK present -> record its KeyId; NO custody note.
			name: "customer CMK (Type=KMS) with KeyId",
			ec: &xraytypes.EncryptionConfig{
				Type:   xraytypes.EncryptionTypeKms,
				KeyId:  aws.String(cmkArn),
				Status: xraytypes.EncryptionStatusActive,
			},
			wantKmsKeyID:    cmkArn,
			wantEncType:     "KMS",
			wantStatus:      "ACTIVE",
			wantNote:        false,
			wantCustomerKey: true,
		},
		{
			// Type=NONE -> AWS internal default encryption. STILL SymmetricOnly,
			// sentinel kmsKeyId, custody note present (NOT a clean all-clear).
			name: "AWS internal default (Type=NONE)",
			ec: &xraytypes.EncryptionConfig{
				Type:   xraytypes.EncryptionTypeNone,
				Status: xraytypes.EncryptionStatusActive,
			},
			wantKmsKeyID: "AWS_DEFAULT_ENCRYPTION",
			wantEncType:  "NONE",
			wantStatus:   "ACTIVE",
			wantNote:     true,
		},
		{
			// Type=KMS but empty KeyId -> degrade to AWS default sentinel + note,
			// never fabricate a customer key from an empty string.
			name: "Type=KMS but empty KeyId degrades to default",
			ec: &xraytypes.EncryptionConfig{
				Type:  xraytypes.EncryptionTypeKms,
				KeyId: aws.String(""),
			},
			wantKmsKeyID: "AWS_DEFAULT_ENCRYPTION",
			wantEncType:  "KMS",
			wantStatus:   "",
			wantNote:     true,
		},
		{
			// UPDATING is a normal key-switch state, NOT a no-encryption signal:
			// posture stays SymmetricOnly and the customer key is still recorded.
			name: "customer CMK while UPDATING",
			ec: &xraytypes.EncryptionConfig{
				Type:   xraytypes.EncryptionTypeKms,
				KeyId:  aws.String(cmkArn),
				Status: xraytypes.EncryptionStatusUpdating,
			},
			wantKmsKeyID:    cmkArn,
			wantEncType:     "KMS",
			wantStatus:      "UPDATING",
			wantNote:        false,
			wantCustomerKey: true,
		},
		{
			// nil config -> must degrade to the AWS-default branch, never crash and
			// never fabricate an all-clear. No encryptionType/status keys are set.
			name:         "nil EncryptionConfig degrades to default, never crashes",
			ec:           nil,
			wantKmsKeyID: "AWS_DEFAULT_ENCRYPTION",
			wantEncType:  "",
			wantStatus:   "",
			wantNote:     true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := classifyXRayEncryption(c.ec, "111122223333", "us-east-1")

			// HONESTY CONTRACT: posture is ALWAYS SymmetricOnly, NEVER no-encryption.
			if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
				t.Errorf("posture = %q, want %q (X-Ray is always encrypted)", got, models.PostureSymmetricOnly)
			}
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Fatalf("X-Ray classified as PostureNoEncryption — forbidden: X-Ray cannot disable at-rest encryption")
			}

			// Cipher is AES-256 (quantum-resistant), always set.
			if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
				t.Errorf("CryptoProps not AES-256: %+v", a.CryptoProps.AlgorithmProperties)
			}

			// Key tier evidence.
			if got := a.Properties["kmsKeyId"]; got != c.wantKmsKeyID {
				t.Errorf("kmsKeyId = %q, want %q", got, c.wantKmsKeyID)
			}
			if got := a.Properties["encryptionType"]; got != c.wantEncType {
				t.Errorf("encryptionType = %q, want %q", got, c.wantEncType)
			}
			if got := a.Properties["status"]; got != c.wantStatus {
				t.Errorf("status = %q, want %q", got, c.wantStatus)
			}

			// Custody-note honesty: the AWS-owned default MUST carry the
			// "no customer key custody" note (not a clean all-clear); a real
			// customer CMK must NOT.
			note, hasNote := a.Properties["note"]
			if c.wantNote {
				if !hasNote || note != custodyNote {
					t.Errorf("expected custody note %q, got present=%v value=%q", custodyNote, hasNote, note)
				}
			} else if hasNote {
				t.Errorf("customer CMK must NOT carry custody note, got %q", note)
			}

			if c.wantCustomerKey && a.Properties["kmsKeyId"] == "AWS_DEFAULT_ENCRYPTION" {
				t.Errorf("customer CMK case produced AWS_DEFAULT_ENCRYPTION sentinel")
			}

			// Provenance: doc-fact stamped (universal AWS-doc guarantee).
			if a.Properties["source"] != "aws-doc" {
				t.Errorf("source = %q, want aws-doc", a.Properties["source"])
			}

			// Exactly one account-level asset shape.
			if a.ResourceType != "AWS::XRay::EncryptionConfig" {
				t.Errorf("ResourceType = %q, want AWS::XRay::EncryptionConfig", a.ResourceType)
			}
			if a.ResourceID != "encryption-config" {
				t.Errorf("ResourceID = %q, want encryption-config", a.ResourceID)
			}
		})
	}
}
