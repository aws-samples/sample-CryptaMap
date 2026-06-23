package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	wswtypes "github.com/aws/aws-sdk-go-v2/service/workspacesweb/types"
)

// TestClassifyWorkSpacesWebKeyTier is the regulator-honesty guardrail for the
// WorkSpaces Secure Browser scanner. WorkSpaces Web is a Type-A always-encrypted
// at-rest surface (AES-256 KMS envelope, no per-resource disable), so the asset
// posture is unconditionally SymmetricOnly — this helper only selects the KEY
// TIER. The test asserts the EXACT kmsKeyId / keyTier / note values Scan stamps
// and that an absent CMK (or a nil portal) degrades to the AWS-owned default and
// is NEVER presented as a clean all-clear or no-encryption.
func TestClassifyWorkSpacesWebKeyTier(t *testing.T) {
	const (
		awsOwnedSentinel = "AWS_OWNED_KMS_KEY"
		tierAWSOwned     = "aws-owned-default"
		tierCustomer     = "customer-managed"
		cmkARN           = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	)

	cases := []struct {
		name        string
		portal      *wswtypes.Portal
		wantKmsKey  string
		wantKeyTier string
	}{
		{
			// Customer CMK present -> customer key custody, kmsKeyId = the CMK ARN.
			name:        "customer_managed_cmk",
			portal:      &wswtypes.Portal{CustomerManagedKey: aws.String(cmkARN)},
			wantKmsKey:  cmkARN,
			wantKeyTier: tierCustomer,
		},
		{
			// CMK field nil -> AWS-owned default. STILL encrypted (SymmetricOnly),
			// kmsKeyId = AWS-owned sentinel, "no customer key custody" note.
			name:        "aws_owned_default_nil_cmk",
			portal:      &wswtypes.Portal{},
			wantKmsKey:  awsOwnedSentinel,
			wantKeyTier: tierAWSOwned,
		},
		{
			// CMK present but empty string -> treated as AWS-owned default, not a
			// fabricated customer key.
			name:        "empty_cmk_string_is_aws_owned",
			portal:      &wswtypes.Portal{CustomerManagedKey: aws.String("")},
			wantKmsKey:  awsOwnedSentinel,
			wantKeyTier: tierAWSOwned,
		},
		{
			// Nil portal (empty GetPortal response) -> degrades to AWS-owned
			// default. Must NOT crash and must NOT fabricate an all-clear.
			name:        "nil_portal_degrades_to_aws_owned",
			portal:      nil,
			wantKmsKey:  awsOwnedSentinel,
			wantKeyTier: tierAWSOwned,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotKey, gotTier, gotNote := classifyWorkSpacesWebKeyTier(c.portal)

			if gotKey != c.wantKmsKey {
				t.Errorf("kmsKeyId = %q, want %q", gotKey, c.wantKmsKey)
			}
			if gotTier != c.wantKeyTier {
				t.Errorf("keyTier = %q, want %q", gotTier, c.wantKeyTier)
			}
			if gotNote == "" {
				t.Fatalf("note must never be empty (it is the honesty evidence)")
			}

			// HONESTY CONTRACT: an always-encrypted service must never be portrayed
			// as no-encryption, and the AWS-owned default must never read as a clean
			// all-clear. The note must always affirm at-rest encryption, and the
			// AWS-owned branch must explicitly disclaim customer key custody.
			if !containsSub(gotNote, "always encrypts") {
				t.Errorf("note must affirm always-on at-rest encryption (never no-encryption): %q", gotNote)
			}
			if c.wantKeyTier == tierAWSOwned {
				if gotKey != awsOwnedSentinel {
					t.Errorf("AWS-owned default must use the %q sentinel, got %q", awsOwnedSentinel, gotKey)
				}
				if !containsSub(gotNote, "no customer key custody") {
					t.Errorf("AWS-owned default note must disclaim customer key custody (not a clean all-clear): %q", gotNote)
				}
			}
			if c.wantKeyTier == tierCustomer && !containsSub(gotNote, "customer-managed CMK") {
				t.Errorf("customer-managed note must name the customer-managed CMK: %q", gotNote)
			}
		})
	}
}

// containsSub is a tiny substring check kept local to avoid importing strings for
// a single use in the assertion block.
func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
