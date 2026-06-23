package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeSSMClient is a hand-rolled ssmAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so
// the scanner loops through every page; err forces a DescribeParameters failure
// on the first call.
type fakeSSMClient struct {
	pages []*ssm.DescribeParametersOutput
	calls int
	err   error
}

func (f *fakeSSMClient) DescribeParameters(ctx context.Context, in *ssm.DescribeParametersInput, optFns ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &ssm.DescribeParametersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func ssmstrptr(s string) *string { return &s }

// TestSSMScanPaginates verifies the DescribeParameters NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' parameters
// as assets. Without the pagination loop, only the first page's parameter
// survives — the commonest real bug in dense accounts.
func TestSSMScanPaginates(t *testing.T) {
	client := &fakeSSMClient{
		pages: []*ssm.DescribeParametersOutput{
			{
				Parameters: []ssmtypes.ParameterMetadata{{Name: ssmstrptr("param-page1")}},
				NextToken:  ssmstrptr("tok-page2"),
			},
			{
				Parameters: []ssmtypes.ParameterMetadata{{Name: ssmstrptr("param-page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeParameters to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"param-page1", "param-page2"} {
		if !got[want] {
			t.Errorf("expected parameter %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestSSMScanDescribeErrorPropagates verifies the incompleteness decision: a
// DescribeParameters failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestSSMScanDescribeErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform ssm:DescribeParameters")
	client := &fakeSSMClient{err: sentinel}
	assets, err := SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeParameters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeParameters failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a top-level Describe error, got %d", len(assets))
	}
}

// TestSSMScanPostureHonesty verifies the at-rest honesty mapping for a domain
// where encryption is ALWAYS on: every Parameter Store parameter is encrypted
// at rest regardless of type (String/StringList under an AWS-owned key,
// SecureString under a customer-controlled KMS envelope). The posture must
// therefore be SymmetricOnly — never NoEncryption, even for a plain String —
// and the algorithm must be the documented AES-256. The KMS key tier is
// recorded honestly: SecureString with no explicit KeyId records the AWS-managed
// alias/aws/ssm (not dropped), a String records the AWS-owned key, and an
// explicit CMK KeyId is recorded verbatim.
func TestSSMScanPostureHonesty(t *testing.T) {
	client := &fakeSSMClient{
		pages: []*ssm.DescribeParametersOutput{
			{
				Parameters: []ssmtypes.ParameterMetadata{
					// Plain String -> AWS-owned key, still encrypted at rest.
					{Name: ssmstrptr("plain-string"), Type: ssmtypes.ParameterTypeString},
					// SecureString, no explicit KeyId -> AWS-managed alias/aws/ssm default.
					{Name: ssmstrptr("secure-default"), Type: ssmtypes.ParameterTypeSecureString},
					// SecureString with a customer CMK -> recorded verbatim.
					{Name: ssmstrptr("secure-cmk"), Type: ssmtypes.ParameterTypeSecureString, KeyId: ssmstrptr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
				},
			},
		},
	}
	assets, err := SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 assets, got %d", len(assets))
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}

	for _, a := range assets {
		// Parameter Store is always-encrypted: never NoEncryption, always SymmetricOnly.
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("param %q: expected posture %q (always-encrypted domain), got %q",
				a.ResourceID, models.PostureSymmetricOnly, got)
		}
		if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
			t.Errorf("param %q: posture must never be NoEncryption for an always-encrypted parameter", a.ResourceID)
		}
		if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
			t.Errorf("param %q: expected AES-256 at-rest algorithm, got %+v", a.ResourceID, a.CryptoProps.AlgorithmProperties)
		}
	}

	// Plain String -> AWS-owned key recorded (NOT dropped / NOT a clean all-clear).
	if got := byID["plain-string"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("plain-string: expected AWS-owned key default recorded, got %q", got)
	}
	if got := byID["plain-string"].Properties["parameterType"]; got != string(ssmtypes.ParameterTypeString) {
		t.Errorf("plain-string: expected parameterType %q recorded, got %q", ssmtypes.ParameterTypeString, got)
	}
	// SecureString, no explicit KeyId -> AWS-managed alias/aws/ssm default (NOT dropped).
	if got := byID["secure-default"].Properties["kmsKeyId"]; got != "alias/aws/ssm" {
		t.Errorf("secure-default: expected AWS-managed key default %q recorded, got %q", "alias/aws/ssm", got)
	}
	// SecureString with explicit CMK -> recorded verbatim.
	if got := byID["secure-cmk"].Properties["kmsKeyId"]; got != "arn:aws:kms:us-east-1:111122223333:key/abc-123" {
		t.Errorf("secure-cmk: expected customer KMS key ARN recorded, got %q", got)
	}
}
