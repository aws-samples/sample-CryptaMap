package datarest

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifySNS enforces the honesty contract for SNS at-rest classification:
//   - a GetTopicAttributes read failure MUST yield Unknown (with a note), NEVER
//     NoEncryption (a false alarm);
//   - a present KmsMasterKeyId MUST yield SymmetricOnly;
//   - no error AND no KMS key MUST yield NoEncryption (SSE-SNS is off by default,
//     so this is a genuine finding, not a false alarm).
func TestClassifySNS(t *testing.T) {
	cases := []struct {
		name        string
		attrs       *sns.GetTopicAttributesOutput
		readErr     error
		wantPosture models.CryptoPosture
		wantKey     string
		wantNote    bool
	}{
		{
			name:        "read error -> Unknown, never NoEncryption",
			attrs:       nil,
			readErr:     errors.New("AccessDenied"),
			wantPosture: models.PostureUnknown,
			wantKey:     "",
			wantNote:    true,
		},
		{
			name:        "read error with attrs present still -> Unknown",
			attrs:       &sns.GetTopicAttributesOutput{Attributes: map[string]string{"KmsMasterKeyId": "alias/aws/sns"}},
			readErr:     errors.New("Throttling"),
			wantPosture: models.PostureUnknown,
			wantKey:     "",
			wantNote:    true,
		},
		{
			name:        "KMS key present -> SymmetricOnly",
			attrs:       &sns.GetTopicAttributesOutput{Attributes: map[string]string{"KmsMasterKeyId": "alias/aws/sns"}},
			readErr:     nil,
			wantPosture: models.PostureSymmetricOnly,
			wantKey:     "alias/aws/sns",
			wantNote:    false,
		},
		{
			name:        "no error, no KMS key -> NoEncryption",
			attrs:       &sns.GetTopicAttributesOutput{Attributes: map[string]string{}},
			readErr:     nil,
			wantPosture: models.PostureNoEncryption,
			wantKey:     "",
			wantNote:    false,
		},
		{
			name:        "no error, empty KMS key value -> NoEncryption",
			attrs:       &sns.GetTopicAttributesOutput{Attributes: map[string]string{"KmsMasterKeyId": ""}},
			readErr:     nil,
			wantPosture: models.PostureNoEncryption,
			wantKey:     "",
			wantNote:    false,
		},
		{
			name:        "no error, nil attrs -> NoEncryption",
			attrs:       nil,
			readErr:     nil,
			wantPosture: models.PostureNoEncryption,
			wantKey:     "",
			wantNote:    false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			posture, _, key, note := classifySNS(c.attrs, c.readErr)
			if posture != c.wantPosture {
				t.Errorf("posture = %v, want %v", posture, c.wantPosture)
			}
			// Belt-and-suspenders: a read failure must never look encrypted-or-not.
			if c.readErr != nil && posture == models.PostureNoEncryption {
				t.Errorf("read failure produced NoEncryption (false alarm); want Unknown")
			}
			if key != c.wantKey {
				t.Errorf("kmsKey = %q, want %q", key, c.wantKey)
			}
			if (note != "") != c.wantNote {
				t.Errorf("note presence = %v (note=%q), want %v", note != "", note, c.wantNote)
			}
		})
	}
}
