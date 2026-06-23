package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	memorydbtypes "github.com/aws/aws-sdk-go-v2/service/memorydb/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeMemoryDBClient is a hand-rolled memorydbDescribeAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err forces a DescribeClusters
// failure on the first call.
type fakeMemoryDBClient struct {
	pages []*memorydb.DescribeClustersOutput
	calls int
	err   error
}

func (f *fakeMemoryDBClient) DescribeClusters(ctx context.Context, in *memorydb.DescribeClustersInput, optFns ...func(*memorydb.Options)) (*memorydb.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &memorydb.DescribeClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func memdbStrptr(s string) *string { return &s }

// TestMemoryDBScanPaginates verifies the DescribeClusters NextToken loop: a fake
// returning 2 pages (NextToken on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination loop, only the first page's cluster survives —
// the single commonest real bug this guards.
func TestMemoryDBScanPaginates(t *testing.T) {
	client := &fakeMemoryDBClient{
		pages: []*memorydb.DescribeClustersOutput{
			{
				Clusters:  []memorydbtypes.Cluster{{Name: memdbStrptr("cluster-page1")}},
				NextToken: memdbStrptr("tok-page2"),
			},
			{
				Clusters: []memorydbtypes.Cluster{{Name: memdbStrptr("cluster-page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := MemoryDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected DescribeClusters to be called 2 times (paginated), got %d", c)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if !got[want] {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestMemoryDBScanDescribeErrorPropagates verifies the owner's incompleteness
// decision: a DescribeClusters failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestMemoryDBScanDescribeErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform memorydb:DescribeClusters")
	client := &fakeMemoryDBClient{err: sentinel}
	assets, err := MemoryDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClusters failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on a top-level error, got %v", assets)
	}
}

// TestMemoryDBScanHonestyPosture verifies the at-rest honesty mapping. MemoryDB
// at-rest encryption is always on (AES-256, cannot be disabled), so posture must
// be unconditionally SymmetricOnly — never NoEncryption. KmsKeyId selects the key
// tier only: a customer-managed CMK when present is recorded verbatim; when absent
// the asset records the AWS-owned default key (NOT a clean all-clear, NOT
// no-encryption).
func TestMemoryDBScanHonestyPosture(t *testing.T) {
	const cmkArn = "arn:aws:kms:us-east-1:111122223333:key/abcd-cmk"
	client := &fakeMemoryDBClient{
		pages: []*memorydb.DescribeClustersOutput{
			{
				Clusters: []memorydbtypes.Cluster{
					// CMK present -> recorded verbatim.
					{Name: memdbStrptr("cluster-cmk"), KmsKeyId: memdbStrptr(cmkArn)},
					// KmsKeyId absent -> AWS-owned default key, still encrypted.
					{Name: memdbStrptr("cluster-default")},
					// KmsKeyId empty string -> treated as absent (AWS-owned default).
					{Name: memdbStrptr("cluster-empty"), KmsKeyId: memdbStrptr("")},
					// Nil name -> skipped, must not panic or appear.
					{Name: nil, KmsKeyId: memdbStrptr(cmkArn)},
				},
			},
		},
	}
	assets, err := MemoryDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}

	if len(byID) != 3 {
		t.Fatalf("expected 3 assets (nil-name cluster skipped), got %d: %v", len(byID), byID)
	}

	for _, name := range []string{"cluster-cmk", "cluster-default", "cluster-empty"} {
		a, ok := byID[name]
		if !ok {
			t.Errorf("expected asset for %q", name)
			continue
		}
		// Always-encrypted domain: SymmetricOnly, never NoEncryption. The scanner
		// records posture via services.PostureProperty into Properties["posture"].
		posture := a.Properties["posture"]
		if posture != string(models.PostureSymmetricOnly) {
			t.Errorf("%s: expected posture SymmetricOnly (at-rest always on), got %q", name, posture)
		}
		if posture == string(models.PostureNoEncryption) {
			t.Errorf("%s: posture must never be NoEncryption for always-encrypted MemoryDB", name)
		}
		if a.ResourceType != "AWS::MemoryDB::Cluster" {
			t.Errorf("%s: unexpected resourceType %q", name, a.ResourceType)
		}
	}

	// CMK present -> recorded verbatim.
	if got := byID["cluster-cmk"].Properties["kmsKeyId"]; got != cmkArn {
		t.Errorf("cluster-cmk: expected kmsKeyId recorded as the CMK ARN %q, got %q", cmkArn, got)
	}
	// Absent / empty KmsKeyId -> AWS-owned default key sentinel (not a clean all-clear).
	if got := byID["cluster-default"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("cluster-default: expected AWS-owned default key sentinel, got %q", got)
	}
	if got := byID["cluster-empty"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("cluster-empty: expected AWS-owned default key sentinel for empty KmsKeyId, got %q", got)
	}
}
