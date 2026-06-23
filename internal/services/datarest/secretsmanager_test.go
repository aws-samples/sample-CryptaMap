package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeSecretsManagerClient is a hand-rolled secretsmanagerAPI for unit-testing
// the scanner's pagination + error propagation without a live AWS client.
// pages is returned page-by-page (each call consumes the next page) and the
// NextToken is wired so the scanner loops through every page; err forces a
// ListSecrets failure on the first call.
type fakeSecretsManagerClient struct {
	pages []*secretsmanager.ListSecretsOutput
	calls int
	err   error
}

func (f *fakeSecretsManagerClient) ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &secretsmanager.ListSecretsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func smstrptr(s string) *string { return &s }

// TestSecretsManagerScanPaginates verifies the ListSecrets NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' secrets as
// assets. Without the pagination loop, only the first page's secret survives —
// the commonest real bug in dense accounts.
func TestSecretsManagerScanPaginates(t *testing.T) {
	client := &fakeSecretsManagerClient{
		pages: []*secretsmanager.ListSecretsOutput{
			{
				SecretList: []smtypes.SecretListEntry{{Name: smstrptr("secret-page1")}},
				NextToken:  smstrptr("tok-page2"),
			},
			{
				SecretList: []smtypes.SecretListEntry{{Name: smstrptr("secret-page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := SecretsManagerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListSecrets to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"secret-page1", "secret-page2"} {
		if !got[want] {
			t.Errorf("expected secret %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestSecretsManagerScanListErrorPropagates verifies the incompleteness decision:
// a ListSecrets failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestSecretsManagerScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform secretsmanager:ListSecrets")
	client := &fakeSecretsManagerClient{err: sentinel}
	assets, err := SecretsManagerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListSecrets fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListSecrets failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a top-level List error, got %d", len(assets))
	}
}

// TestSecretsManagerScanPostureHonesty verifies the at-rest honesty mapping for a
// domain where encryption is ALWAYS on (every Secrets Manager secret is encrypted
// at rest). The posture must be SymmetricOnly — never NoEncryption — and the
// algorithm must be the documented AES-256. CMK presence/absence is recorded
// without an absence ever masquerading as a clean all-clear: an absent KmsKeyId
// records the AWS-managed default key rather than dropping the field.
func TestSecretsManagerScanPostureHonesty(t *testing.T) {
	client := &fakeSecretsManagerClient{
		pages: []*secretsmanager.ListSecretsOutput{
			{
				SecretList: []smtypes.SecretListEntry{
					{Name: smstrptr("cmk-secret"), KmsKeyId: smstrptr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
					{Name: smstrptr("default-secret")}, // no KmsKeyId -> AWS-managed
				},
			},
		},
	}
	assets, err := SecretsManagerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}

	for _, a := range assets {
		// Secrets Manager is always-encrypted: never NoEncryption, always SymmetricOnly.
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("secret %q: expected posture %q (always-encrypted domain), got %q",
				a.ResourceID, models.PostureSymmetricOnly, got)
		}
		if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
			t.Errorf("secret %q: posture must never be NoEncryption for an always-encrypted secret", a.ResourceID)
		}
		if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
			t.Errorf("secret %q: expected AES-256 at-rest algorithm, got %+v", a.ResourceID, a.CryptoProps.AlgorithmProperties)
		}
	}

	// CMK present -> recorded verbatim.
	if got := byID["cmk-secret"].Properties["kmsKeyId"]; got != "arn:aws:kms:us-east-1:111122223333:key/abc-123" {
		t.Errorf("cmk-secret: expected customer KMS key ARN recorded, got %q", got)
	}
	// CMK absent -> AWS-managed default recorded (NOT dropped / NOT a clean all-clear).
	if got := byID["default-secret"].Properties["kmsKeyId"]; got != "aws/secretsmanager" {
		t.Errorf("default-secret: expected AWS-managed key default %q recorded, got %q", "aws/secretsmanager", got)
	}
}
