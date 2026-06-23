package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyCodeBuildProject is the regulator-honesty guardrail for the
// CodeBuild at-rest classifier. CodeBuild ALWAYS encrypts build artifacts at rest
// with a symmetric AES-256 KMS envelope (no disable toggle), so EVERY case must
// land on PostureSymmetricOnly — never PostureNoEncryption, never a fabricated
// all-clear. The EncryptionKey field only selects the KEY TIER:
//   - a customer CMK ARN/alias       -> keyTier=customer-cmk, kmsKeyId=that value, no "no custody" note
//   - empty/nil OR alias/aws/s3      -> keyTier=aws-managed-default, kmsKeyId=alias/aws/s3, custody note present
//
// These assertions fail loudly if anyone later flips an always-encrypted service
// to report no-encryption, or dresses the AWS-managed default up as a clean
// all-clear (a customer-managed-key claim with no custody note).
func TestClassifyCodeBuildProject(t *testing.T) {
	const (
		acct        = "123456789012"
		region      = "us-east-1"
		custodyNote = "CodeBuild build artifacts are always encrypted at rest; this project uses the AWS-managed aws/s3 key (no customer key custody), not a customer CMK."
	)

	cases := []struct {
		name          string
		projectName   string
		arn           *string
		encryptionKey *string

		wantPosture models.CryptoPosture
		wantKeyID   string
		wantKeyTier string
		wantNote    bool // true => the AWS-managed "no custody / not an all-clear" note must be present
	}{
		{
			// Customer CMK present -> customer-managed key tier, kmsKeyId = the ARN, NO custody note.
			name:          "customer CMK ARN",
			projectName:   "build-with-cmk",
			arn:           aws.String("arn:aws:codebuild:us-east-1:123456789012:project/build-with-cmk"),
			encryptionKey: aws.String("arn:aws:kms:us-east-1:123456789012:key/abcd-1234"),
			wantPosture:   models.PostureSymmetricOnly,
			wantKeyID:     "arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
			wantKeyTier:   "customer-cmk",
			wantNote:      false,
		},
		{
			// Customer CMK alias (non-default) -> still customer-cmk.
			name:          "customer CMK alias",
			projectName:   "build-with-alias",
			encryptionKey: aws.String("alias/my-team-key"),
			wantPosture:   models.PostureSymmetricOnly,
			wantKeyID:     "alias/my-team-key",
			wantKeyTier:   "customer-cmk",
			wantNote:      false,
		},
		{
			// Explicit AWS-managed default alias -> aws-managed-default, custody note present.
			// STILL the encrypted posture, NOT a clean all-clear.
			name:          "explicit aws/s3 default alias",
			projectName:   "build-default-explicit",
			encryptionKey: aws.String("alias/aws/s3"),
			wantPosture:   models.PostureSymmetricOnly,
			wantKeyID:     "alias/aws/s3",
			wantKeyTier:   "aws-managed-default",
			wantNote:      true,
		},
		{
			// REGRESSION (live-validated 2026-06-17): DescribeProjects returns the
			// AWS-managed default key as the FULLY-QUALIFIED ARN, not the bare alias.
			// This MUST classify as aws-managed-default (custody note present) — the
			// prior exact-string check misread it as customer-cmk (a false key-custody
			// positive that would mislead a regulated/BFSI customer).
			name:          "aws-managed default returned as fully-qualified ARN (live form)",
			projectName:   "build-default-arn",
			encryptionKey: aws.String("arn:aws:kms:ap-south-1:123456789012:alias/aws/s3"),
			wantPosture:   models.PostureSymmetricOnly,
			// Normalized to the bare alias once recognized as the AWS-managed default.
			wantKeyID:   "alias/aws/s3",
			wantKeyTier: "aws-managed-default",
			wantNote:    true,
		},
		{
			// EncryptionKey absent (nil) -> degrades to AWS-managed default, never a crash,
			// never no-encryption, custody note present.
			name:          "nil EncryptionKey degrades to aws-managed default",
			projectName:   "build-no-key",
			encryptionKey: nil,
			wantPosture:   models.PostureSymmetricOnly,
			wantKeyID:     "alias/aws/s3",
			wantKeyTier:   "aws-managed-default",
			wantNote:      true,
		},
		{
			// Empty-string EncryptionKey -> same AWS-managed default branch.
			name:          "empty EncryptionKey degrades to aws-managed default",
			projectName:   "build-empty-key",
			encryptionKey: aws.String(""),
			wantPosture:   models.PostureSymmetricOnly,
			wantKeyID:     "alias/aws/s3",
			wantKeyTier:   "aws-managed-default",
			wantNote:      true,
		},
		{
			// Mixed case of the default alias -> case-insensitive match -> aws-managed default.
			name:          "case-insensitive default alias",
			projectName:   "build-mixed-case",
			encryptionKey: aws.String("ALIAS/AWS/S3"),
			wantPosture:   models.PostureSymmetricOnly,
			wantKeyID:     "alias/aws/s3",
			wantKeyTier:   "aws-managed-default",
			wantNote:      true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := classifyCodeBuildProject(acct, region, c.projectName, c.arn, c.encryptionKey)

			// Posture: an always-encrypted service must NEVER report no-encryption.
			if got := a.Properties["posture"]; got != string(c.wantPosture) {
				t.Errorf("posture = %q, want %q", got, c.wantPosture)
			}
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Fatalf("HONESTY VIOLATION: CodeBuild is always-encrypted but posture reported as no-encryption")
			}

			if got := a.Properties["kmsKeyId"]; got != c.wantKeyID {
				t.Errorf("kmsKeyId = %q, want %q", got, c.wantKeyID)
			}
			if got := a.Properties["keyTier"]; got != c.wantKeyTier {
				t.Errorf("keyTier = %q, want %q", got, c.wantKeyTier)
			}

			note, hasNote := a.Properties["note"]
			if c.wantNote {
				// AWS-managed default MUST carry the "no custody / not an all-clear" note.
				if !hasNote || note != custodyNote {
					t.Errorf("aws-managed-default must carry the no-custody note; got note=%q present=%v", note, hasNote)
				}
			} else {
				// Customer CMK must NOT carry the AWS-managed default note.
				if hasNote {
					t.Errorf("customer-cmk must not carry the aws-managed-default note; got note=%q", note)
				}
			}

			// ARN is recorded only when supplied (non-nil/non-empty).
			if c.arn != nil && *c.arn != "" {
				if got := a.Properties["arn"]; got != *c.arn {
					t.Errorf("arn = %q, want %q", got, *c.arn)
				}
			}

			// Asset shell sanity: always-encrypted AES-256 cipher, correct resource type.
			if a.ResourceType != "AWS::CodeBuild::Project" {
				t.Errorf("resourceType = %q, want AWS::CodeBuild::Project", a.ResourceType)
			}
			if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
				t.Errorf("expected AES-256 at-rest cipher, got %+v", a.CryptoProps.AlgorithmProperties)
			}
		})
	}
}
