package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyEventBus is the regulator-honesty guardrail for the EventBridge
// at-rest classification. EventBridge ALWAYS encrypts event data at rest with
// AES-256 (there is no per-bus disable), so the posture must be SymmetricOnly in
// EVERY case — including when the customer-managed KmsKeyIdentifier is absent.
// These cases fail loudly if someone later turns the AWS-owned-default tier into a
// no-encryption verdict (false alarm) or hides the missing customer key custody by
// dropping the explicit "no customer key custody" note (false all-clear).
func TestClassifyEventBus(t *testing.T) {
	const (
		acct   = "111122223333"
		region = "us-east-1"
		id     = "arn:aws:events:us-east-1:111122223333:event-bus/orders"
		cmkARN = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	)

	cases := []struct {
		name            string
		kmsKeyID        *string
		wantPosture     models.CryptoPosture
		wantKmsKeyID    string
		wantKeyTier     string // "" means the keyTier property must be ABSENT
		wantNotePresent bool
	}{
		{
			// Customer CMK present -> SymmetricOnly, kmsKeyId = the CMK ARN,
			// and NO aws-owned-default note (real customer key custody).
			name:         "customer-cmk",
			kmsKeyID:     aws.String(cmkARN),
			wantPosture:  models.PostureSymmetricOnly,
			wantKmsKeyID: cmkARN,
			wantKeyTier:  "",
		},
		{
			// CMK absent (nil) -> STILL SymmetricOnly (always-encrypted service),
			// kmsKeyId = the AWS-owned sentinel, keyTier=aws-owned-default, and the
			// "no customer key custody / not a clean all-clear" note MUST be present.
			name:            "aws-owned-default-nil",
			kmsKeyID:        nil,
			wantPosture:     models.PostureSymmetricOnly,
			wantKmsKeyID:    "AWS_OWNED_KMS_KEY",
			wantKeyTier:     "aws-owned-default",
			wantNotePresent: true,
		},
		{
			// Empty-string identifier degrades to the AWS-owned-default branch,
			// identical to nil — never a crash, never a fabricated CMK.
			name:            "aws-owned-default-empty",
			kmsKeyID:        aws.String(""),
			wantPosture:     models.PostureSymmetricOnly,
			wantKmsKeyID:    "AWS_OWNED_KMS_KEY",
			wantKeyTier:     "aws-owned-default",
			wantNotePresent: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := classifyEventBus(acct, region, id, c.kmsKeyID)

			// Posture: an always-encrypted service must NEVER report no-encryption.
			if a.Properties["posture"] != string(c.wantPosture) {
				t.Errorf("posture = %q, want %q", a.Properties["posture"], c.wantPosture)
			}
			if c.wantPosture == models.PostureSymmetricOnly && a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Errorf("always-encrypted EventBridge bus must never be classified no-encryption")
			}

			// kmsKeyId evidence.
			if a.Properties["kmsKeyId"] != c.wantKmsKeyID {
				t.Errorf("kmsKeyId = %q, want %q", a.Properties["kmsKeyId"], c.wantKmsKeyID)
			}

			// keyTier evidence (present only for the AWS-owned-default tier).
			if gotTier, ok := a.Properties["keyTier"]; c.wantKeyTier == "" {
				if ok {
					t.Errorf("keyTier should be absent for customer CMK, got %q", gotTier)
				}
			} else if gotTier != c.wantKeyTier {
				t.Errorf("keyTier = %q, want %q", gotTier, c.wantKeyTier)
			}

			// Honesty note: the AWS-owned-default tier must carry the explicit
			// "no customer key custody" note so it is never mistaken for a clean
			// all-clear; the customer-CMK tier must NOT carry it.
			note, hasNote := a.Properties["note"]
			if c.wantNotePresent {
				if !hasNote || note == "" {
					t.Errorf("expected no-customer-key-custody note to be present for AWS-owned-default tier")
				}
			} else if hasNote {
				t.Errorf("note should be absent for customer CMK, got %q", note)
			}

			// Spot-check the at-rest cipher block is the quantum-resistant AES-256 baseline,
			// not a fabricated or empty algorithm.
			if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
				t.Errorf("expected AES-256 at-rest algorithm, got %+v", a.CryptoProps.AlgorithmProperties)
			}

			// Asset identity is preserved on the classify path.
			if a.ResourceType != "AWS::Events::EventBus" {
				t.Errorf("resourceType = %q, want AWS::Events::EventBus", a.ResourceType)
			}
		})
	}
}
