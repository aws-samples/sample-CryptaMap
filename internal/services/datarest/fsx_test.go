package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeFSxClient is a hand-rolled fsxAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so
// the scanner loops through every page; err forces a DescribeFileSystems failure.
type fakeFSxClient struct {
	pages []*fsx.DescribeFileSystemsOutput
	calls int
	err   error
}

func (f *fakeFSxClient) DescribeFileSystems(ctx context.Context, in *fsx.DescribeFileSystemsInput, optFns ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &fsx.DescribeFileSystemsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func fsxStrptr(s string) *string { return &s }

// TestFSxScanPaginates verifies the DescribeFileSystems NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' file systems
// as assets. Without the pagination loop, only the first page survives.
func TestFSxScanPaginates(t *testing.T) {
	client := &fakeFSxClient{
		pages: []*fsx.DescribeFileSystemsOutput{
			{
				FileSystems: []fsxtypes.FileSystem{
					{FileSystemId: fsxStrptr("fs-page1"), KmsKeyId: fsxStrptr("arn:aws:kms:us-east-1:111122223333:key/abc")},
				},
				NextToken: fsxStrptr("tok-page2"),
			},
			{
				FileSystems: []fsxtypes.FileSystem{
					{FileSystemId: fsxStrptr("fs-page2")},
					// no NextToken -> last page
				},
			},
		},
	}
	assets, err := FSxScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeFileSystems to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"fs-page1", "fs-page2"} {
		if !got[want] {
			t.Errorf("expected file system %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestFSxScanErrorPropagates verifies the incompleteness decision: a
// DescribeFileSystems failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestFSxScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform fsx:DescribeFileSystems")
	client := &fakeFSxClient{err: sentinel}
	_, err := FSxScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeFileSystems fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeFileSystems failure, got: %v", err)
	}
}

// TestFSxScanHonestyPosture asserts the FSx-domain posture mapping: FSx encrypts
// every file system at rest with AES-256-XTS and it cannot be disabled, so the
// posture is UNCONDITIONALLY SymmetricOnly (never NoEncryption), and the key tier
// is recorded — the customer/AWS-managed CMK when present, else the FSx-managed
// AWS-owned key (e.g. scratch Lustre with no KmsKeyId). A missing KmsKeyId must
// NOT be treated as no-encryption.
func TestFSxScanHonestyPosture(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/abc"
	client := &fakeFSxClient{
		pages: []*fsx.DescribeFileSystemsOutput{
			{
				FileSystems: []fsxtypes.FileSystem{
					// persistent system: exposes a CMK -> recorded verbatim
					{FileSystemId: fsxStrptr("fs-cmk"), KmsKeyId: fsxStrptr(cmk)},
					// scratch Lustre: no KmsKeyId -> AWS-owned default, still encrypted
					{FileSystemId: fsxStrptr("fs-nokms")},
					// empty-string KmsKeyId treated like absent -> AWS-owned default
					{FileSystemId: fsxStrptr("fs-emptykms"), KmsKeyId: fsxStrptr("")},
				},
			},
		},
	}
	assets, err := FSxScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
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

	for _, id := range []string{"fs-cmk", "fs-nokms", "fs-emptykms"} {
		a, ok := byID[id]
		if !ok {
			t.Fatalf("expected asset %q to be present", id)
		}
		// Posture is unconditionally SymmetricOnly — never NoEncryption — because
		// FSx at-rest AES-256-XTS cannot be turned off.
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("%s: expected posture %q (FSx always-encrypted), got %q",
				id, models.PostureSymmetricOnly, got)
		}
		if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
			t.Errorf("%s: posture must NEVER be NoEncryption for always-encrypted FSx", id)
		}
		if a.Properties == nil {
			t.Errorf("%s: expected Properties map populated", id)
		}
	}

	// CMK present -> recorded verbatim.
	if got := byID["fs-cmk"].Properties["kmsKeyId"]; got != cmk {
		t.Errorf("fs-cmk: expected kmsKeyId %q recorded, got %q", cmk, got)
	}
	// CMK absent -> AWS-owned default key recorded WITHOUT being treated as
	// unencrypted (no clean all-clear via a missing key).
	if got := byID["fs-nokms"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("fs-nokms: expected AWS-owned default key recorded, got %q", got)
	}
	if got := byID["fs-emptykms"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("fs-emptykms: expected AWS-owned default key recorded for empty KmsKeyId, got %q", got)
	}
}
