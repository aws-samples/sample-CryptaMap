package datarest

import (
	"strings"
	"testing"
)

// TestCPKeyCustody verifies the Customer Profiles key-custody classifier. The
// at-rest cipher is ALWAYS AES-256 (SymmetricOnly is asserted in Scan), so this
// helper only decides KEY CUSTODY. The honesty contract under test:
//
//   - a customer CMK ARN is surfaced verbatim with keyTier "customer-cmk" and NO note;
//   - an empty OR nil DefaultEncryptionKey (the field is Required:No) degrades to the
//     AWS_MANAGED_DEFAULT sentinel with keyTier "aws-managed-default" and a note that
//     explicitly says "No customer key custody" / "not a clean all-clear" — it is
//     NEVER silently presented as a clean all-clear and NEVER as no-encryption.
//
// A nil pointer must take the AWS-managed-default branch, never crash.
func TestCPKeyCustody(t *testing.T) {
	cmkARN := "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456"
	empty := ""

	cases := []struct {
		name        string
		input       *string
		wantKeyID   string
		wantTier    string
		wantNoteSet bool
	}{
		{
			name:        "customer CMK present",
			input:       &cmkARN,
			wantKeyID:   cmkARN,
			wantTier:    "customer-cmk",
			wantNoteSet: false,
		},
		{
			name:        "empty string -> AWS-managed default (not a clean all-clear)",
			input:       &empty,
			wantKeyID:   "AWS_MANAGED_DEFAULT",
			wantTier:    "aws-managed-default",
			wantNoteSet: true,
		},
		{
			name:        "nil pointer -> AWS-managed default, no crash",
			input:       nil,
			wantKeyID:   "AWS_MANAGED_DEFAULT",
			wantTier:    "aws-managed-default",
			wantNoteSet: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kmsKeyID, keyTier, note := cpKeyCustody(c.input)

			if kmsKeyID != c.wantKeyID {
				t.Errorf("kmsKeyId = %q, want %q", kmsKeyID, c.wantKeyID)
			}
			if keyTier != c.wantTier {
				t.Errorf("keyTier = %q, want %q", keyTier, c.wantTier)
			}
			if (note != "") != c.wantNoteSet {
				t.Errorf("note set = %v (note=%q), want set = %v", note != "", note, c.wantNoteSet)
			}

			// HONESTY CONTRACT: the AWS-managed-default branch must carry the
			// no-custody warning and must NEVER look like a clean all-clear.
			if c.wantNoteSet {
				if want := "No customer key custody"; !strings.Contains(note, want) {
					t.Errorf("AWS-managed-default note must mention %q; got %q", want, note)
				}
				if want := "not a clean all-clear"; !strings.Contains(note, want) {
					t.Errorf("AWS-managed-default note must mention %q; got %q", want, note)
				}
			}

			// The classifier never fabricates a no-encryption state: there is no
			// sentinel for that here, and the AWS-managed key is still a real
			// AES-256 key — only custody differs. Guard against a future edit that
			// blanks the sentinel and makes the asset look unkeyed.
			if kmsKeyID == "" {
				t.Errorf("kmsKeyId must never be empty (would erase the always-encrypted guarantee)")
			}
		})
	}
}
