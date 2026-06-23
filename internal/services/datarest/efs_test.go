package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeEFSClient is a hand-rolled efsAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the NextMarker is wired so
// the scanner loops through every page; err forces a DescribeFileSystems failure.
type fakeEFSClient struct {
	pages []*efs.DescribeFileSystemsOutput
	calls int
	err   error
}

func (f *fakeEFSClient) DescribeFileSystems(ctx context.Context, in *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &efs.DescribeFileSystemsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func sptr(s string) *string { return &s }
func bptr(b bool) *bool     { return &b }

// TestEFSScanPaginates verifies the DescribeFileSystems Marker loop: a fake that
// returns 2 pages (NextMarker on page 1) must yield BOTH pages' file systems as
// assets. Without the pagination loop, only the first page's file system
// survives — the commonest real bug in dense accounts.
func TestEFSScanPaginates(t *testing.T) {
	client := &fakeEFSClient{
		pages: []*efs.DescribeFileSystemsOutput{
			{
				FileSystems: []efstypes.FileSystemDescription{
					{FileSystemId: sptr("fs-page1"), Encrypted: bptr(true)},
				},
				NextMarker: sptr("marker-page2"),
			},
			{
				FileSystems: []efstypes.FileSystemDescription{
					{FileSystemId: sptr("fs-page2"), Encrypted: bptr(true)},
				},
				// no NextMarker -> last page
			},
		},
	}
	assets, err := EFSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
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

// TestEFSScanErrorPropagates verifies the owner's incompleteness decision: a
// DescribeFileSystems failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil wrapping error — NOT a silent empty success.
func TestEFSScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticfilesystem:DescribeFileSystems")
	client := &fakeEFSClient{err: sentinel}
	assets, err := EFSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when DescribeFileSystems fails, got nil (silent empty success); assets=%v", assets)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeFileSystems failure, got: %v", err)
	}
}

// TestEFSScanPostureHonesty verifies the at-rest posture mapping for EFS, whose
// encryption-at-rest is opt-in and set only at creation:
//   - encrypted with a customer-managed CMK -> SymmetricOnly, kmsKeyId recorded.
//   - encrypted without an explicit CMK in the response -> SymmetricOnly, no
//     kmsKeyId property (AWS-managed/owned default, not surfaced as a CMK).
//   - genuinely not encrypted -> NoEncryption (honest: EFS opt-in really is off).
func TestEFSScanPostureHonesty(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	client := &fakeEFSClient{
		pages: []*efs.DescribeFileSystemsOutput{
			{
				FileSystems: []efstypes.FileSystemDescription{
					{FileSystemId: sptr("fs-cmk"), Encrypted: bptr(true), KmsKeyId: sptr(cmk)},
					{FileSystemId: sptr("fs-default"), Encrypted: bptr(true)},
					{FileSystemId: sptr("fs-plain"), Encrypted: bptr(false)},
					{FileSystemId: sptr("fs-nilenc")}, // Encrypted nil -> treated as off
				},
			},
		},
	}
	assets, err := EFSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}

	// Encrypted with CMK: symmetric-only posture, CMK recorded, never NoEncryption.
	cmkAsset, ok := byID["fs-cmk"]
	if !ok {
		t.Fatal("expected fs-cmk asset to be present")
	}
	if got := cmkAsset.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("fs-cmk: expected posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if got := cmkAsset.Properties["kmsKeyId"]; got != cmk {
		t.Errorf("fs-cmk: expected kmsKeyId %q to be recorded, got %q", cmk, got)
	}

	// Encrypted without explicit CMK: still symmetric-only, but no fabricated CMK.
	defAsset := byID["fs-default"]
	if got := defAsset.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("fs-default: expected posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if got, present := defAsset.Properties["kmsKeyId"]; present && got != "" {
		t.Errorf("fs-default: expected no kmsKeyId for AWS-managed default, got %q", got)
	}

	// Genuinely not encrypted: NoEncryption is the honest verdict (opt-in is off).
	for _, id := range []string{"fs-plain", "fs-nilenc"} {
		a, ok := byID[id]
		if !ok {
			t.Fatalf("expected %s asset to be present", id)
		}
		if got := a.Properties["posture"]; got != string(models.PostureNoEncryption) {
			t.Errorf("%s: expected posture %q (genuinely off), got %q", id, models.PostureNoEncryption, got)
		}
		if got, present := a.Properties["kmsKeyId"]; present && got != "" {
			t.Errorf("%s: expected no kmsKeyId on an unencrypted file system, got %q", id, got)
		}
	}
}
