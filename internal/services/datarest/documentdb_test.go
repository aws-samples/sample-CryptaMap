package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeDocDBClient is a hand-rolled docdbDescribeClustersAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the Marker is
// wired so the scanner loops through every page; err forces a failure.
type fakeDocDBClient struct {
	pages []*docdb.DescribeDBClustersOutput
	calls int
	err   error
}

func (f *fakeDocDBClient) DescribeDBClusters(ctx context.Context, in *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &docdb.DescribeDBClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func docdbStr(s string) *string { return &s }
func docdbBool(b bool) *bool    { return &b }

// TestDocumentDBScanPaginates verifies the DescribeDBClusters Marker loop: a fake
// that returns 2 pages (Marker on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination restore, only the first page's cluster survives
// — the commonest real bug in dense accounts.
func TestDocumentDBScanPaginates(t *testing.T) {
	client := &fakeDocDBClient{
		pages: []*docdb.DescribeDBClustersOutput{
			{
				DBClusters: []docdbtypes.DBCluster{
					{DBClusterIdentifier: docdbStr("cluster-page1"), StorageEncrypted: docdbBool(true)},
				},
				Marker: docdbStr("marker-page2"),
			},
			{
				DBClusters: []docdbtypes.DBCluster{
					{DBClusterIdentifier: docdbStr("cluster-page2"), StorageEncrypted: docdbBool(true)},
				},
				// no Marker -> last page
			},
		},
	}
	assets, err := DocumentDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeDBClusters to be called 2 times (paginated), got %d", client.calls)
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

// TestDocumentDBScanErrorPropagates verifies the owner's incompleteness decision:
// a DescribeDBClusters failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestDocumentDBScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBClusters")
	client := &fakeDocDBClient{err: sentinel}
	assets, err := DocumentDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDBClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDBClusters failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on error, got %v", assets)
	}
}

// TestDocumentDBScanHonestyPosture verifies the at-rest posture mapping for the
// instance-based DocumentDB domain, where storage encryption is OPT-IN at cluster
// creation:
//   - StorageEncrypted=false (or unset) -> NoEncryption (a genuine off-state, not
//     a hidden default that should be masked).
//   - StorageEncrypted=true + customer CMK present -> SymmetricOnly, CMK recorded
//     verbatim.
//   - StorageEncrypted=true + no key -> SymmetricOnly with the AWS-managed default
//     recorded; the absent key must NOT downgrade posture or imply no-encryption.
func TestDocumentDBScanHonestyPosture(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	client := &fakeDocDBClient{
		pages: []*docdb.DescribeDBClustersOutput{
			{
				DBClusters: []docdbtypes.DBCluster{
					{DBClusterIdentifier: docdbStr("unencrypted")}, // StorageEncrypted nil -> off
					{DBClusterIdentifier: docdbStr("encrypted-off"), StorageEncrypted: docdbBool(false)},
					{DBClusterIdentifier: docdbStr("encrypted-cmk"), StorageEncrypted: docdbBool(true), KmsKeyId: docdbStr(cmk)},
					{DBClusterIdentifier: docdbStr("encrypted-default"), StorageEncrypted: docdbBool(true)},
				},
			},
		},
	}
	assets, err := DocumentDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}

	t.Run("StorageEncrypted unset is NoEncryption", func(t *testing.T) {
		a, ok := byID["unencrypted"]
		if !ok {
			t.Fatal("missing asset for unencrypted cluster")
		}
		if got := a.Properties["posture"]; got != string(models.PostureNoEncryption) {
			t.Errorf("posture = %q, want %q (opt-in SSE genuinely off)", got, models.PostureNoEncryption)
		}
		if _, present := a.Properties["kmsKeyId"]; present {
			t.Errorf("kmsKeyId must NOT be recorded for an unencrypted cluster")
		}
	})

	t.Run("StorageEncrypted=false is NoEncryption", func(t *testing.T) {
		a := byID["encrypted-off"]
		if got := a.Properties["posture"]; got != string(models.PostureNoEncryption) {
			t.Errorf("posture = %q, want %q", got, models.PostureNoEncryption)
		}
	})

	t.Run("encrypted with customer CMK -> SymmetricOnly, key recorded verbatim", func(t *testing.T) {
		a, ok := byID["encrypted-cmk"]
		if !ok {
			t.Fatal("missing asset for encrypted-cmk cluster")
		}
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("posture = %q, want %q", got, models.PostureSymmetricOnly)
		}
		if got := a.Properties["kmsKeyId"]; got != cmk {
			t.Errorf("kmsKeyId = %q, want %q (customer key recorded as-is)", got, cmk)
		}
		if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
			t.Errorf("expected AES-256 at-rest algorithm props, got %+v", a.CryptoProps.AlgorithmProperties)
		}
	})

	t.Run("encrypted with no key -> SymmetricOnly, AWS-managed default recorded, no downgrade", func(t *testing.T) {
		a, ok := byID["encrypted-default"]
		if !ok {
			t.Fatal("missing asset for encrypted-default cluster")
		}
		// The crux: an absent key on an encrypted cluster must NOT downgrade posture.
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("posture = %q, want %q (absent key must NOT downgrade)", got, models.PostureSymmetricOnly)
		}
		if got := a.Properties["kmsKeyId"]; got != "AWS_MANAGED_KMS_KEY" {
			t.Errorf("kmsKeyId = %q, want AWS_MANAGED_KMS_KEY (default key, no clean all-clear omission)", got)
		}
	})
}

// TestDocumentDBScanSkipsNilIdentifier verifies a cluster with no identifier is
// skipped rather than emitting a malformed asset.
func TestDocumentDBScanSkipsNilIdentifier(t *testing.T) {
	client := &fakeDocDBClient{
		pages: []*docdb.DescribeDBClustersOutput{
			{DBClusters: []docdbtypes.DBCluster{{StorageEncrypted: docdbBool(true)}}},
		},
	}
	assets, err := DocumentDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected 0 assets for a cluster with nil identifier, got %d", len(assets))
	}
}
