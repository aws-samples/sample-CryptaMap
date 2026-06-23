package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/emrserverless"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emrserverless/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeEMRServerlessClient is a hand-rolled emrServerlessAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err forces a ListApplications
// failure.
type fakeEMRServerlessClient struct {
	pages []*emrserverless.ListApplicationsOutput
	calls int
	err   error
}

func (f *fakeEMRServerlessClient) ListApplications(ctx context.Context, in *emrserverless.ListApplicationsInput, optFns ...func(*emrserverless.Options)) (*emrserverless.ListApplicationsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &emrserverless.ListApplicationsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func emrsp(s string) *string { return &s }

// TestEMRServerlessScanPaginates verifies the ListApplications NextToken loop: a
// fake that returns 2 pages (NextToken on page 1) must yield BOTH pages'
// applications as assets. Without the pagination loop, only the first page's
// application would survive.
func TestEMRServerlessScanPaginates(t *testing.T) {
	client := &fakeEMRServerlessClient{
		pages: []*emrserverless.ListApplicationsOutput{
			{
				Applications: []emrtypes.ApplicationSummary{
					{Arn: emrsp("arn:aws:emr-serverless:us-east-1:111122223333:/applications/app-page1"), Name: emrsp("page1")},
				},
				NextToken: emrsp("tok-page2"),
			},
			{
				Applications: []emrtypes.ApplicationSummary{
					{Arn: emrsp("arn:aws:emr-serverless:us-east-1:111122223333:/applications/app-page2"), Name: emrsp("page2")},
				},
				// no NextToken -> last page
			},
		},
	}

	assets, err := EMRServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListApplications to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{
		"arn:aws:emr-serverless:us-east-1:111122223333:/applications/app-page1",
		"arn:aws:emr-serverless:us-east-1:111122223333:/applications/app-page2",
	} {
		if !got[want] {
			t.Errorf("expected application %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestEMRServerlessScanListErrorPropagates verifies the owner's incompleteness
// decision: a ListApplications failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestEMRServerlessScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform emr-serverless:ListApplications")
	client := &fakeEMRServerlessClient{err: sentinel}

	assets, err := EMRServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListApplications fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListApplications failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on error, got %d", len(assets))
	}
}

// TestEMRServerlessScanHonestyPosture verifies the at-rest honesty contract for an
// always-encrypted service: EMR Serverless encrypts worker disks unconditionally,
// so posture must be SymmetricOnly (never NoEncryption). Because the default key
// is service-owned (no customer CMK opt-in is read here), the asset must record
// the AWS-owned-key default WITHOUT presenting a clean all-clear / PQC-safe verdict.
func TestEMRServerlessScanHonestyPosture(t *testing.T) {
	client := &fakeEMRServerlessClient{
		pages: []*emrserverless.ListApplicationsOutput{
			{
				Applications: []emrtypes.ApplicationSummary{
					{Arn: emrsp("arn:aws:emr-serverless:us-east-1:111122223333:/applications/app-1"), Name: emrsp("analytics")},
				},
			},
		},
	}

	assets, err := EMRServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset, got %d", len(assets))
	}
	a := assets[0]

	posture := a.Properties["posture"]
	if posture == string(models.PostureNoEncryption) {
		t.Errorf("EMR Serverless always encrypts at rest; posture must NOT be NoEncryption, got %q", posture)
	}
	if posture != string(models.PostureSymmetricOnly) {
		t.Errorf("expected posture %q (always-on AES-256), got %q", models.PostureSymmetricOnly, posture)
	}
	// Default key is AWS-owned: recorded explicitly, not silently treated as a CMK.
	if a.Properties["kmsKeyId"] != "AWS_OWNED_KMS_KEY" {
		t.Errorf("expected AWS-owned-key default recorded in kmsKeyId, got %q", a.Properties["kmsKeyId"])
	}
	// The asset must carry an honest note explaining the AES-256 always-on default
	// and that a customer CMK is only a key-tier refinement (no clean all-clear).
	if a.Properties["note"] == "" {
		t.Error("expected an honesty note on the always-encrypted default, got empty")
	}
	if a.Properties["applicationName"] != "analytics" {
		t.Errorf("expected applicationName to be recorded, got %q", a.Properties["applicationName"])
	}
}
