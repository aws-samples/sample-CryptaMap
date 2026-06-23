package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeNeptuneTransitClient is a hand-rolled neptuneTransitAPI for unit-testing
// the scanner's pagination + error propagation without a live AWS client.
// clustersPages / instancesPages are returned page-by-page (each call consumes
// the next page) with Markers wired so the scanner loops through every page;
// clustersErr / instancesErr force the respective calls to fail.
type fakeNeptuneTransitClient struct {
	clustersPages []*neptune.DescribeDBClustersOutput
	clusterCalls  int
	clustersErr   error

	instancesPages []*neptune.DescribeDBInstancesOutput
	instanceCalls  int
	instancesErr   error
}

func (f *fakeNeptuneTransitClient) DescribeDBClusters(ctx context.Context, in *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error) {
	if f.clustersErr != nil {
		return nil, f.clustersErr
	}
	if f.clusterCalls >= len(f.clustersPages) {
		return &neptune.DescribeDBClustersOutput{}, nil
	}
	out := f.clustersPages[f.clusterCalls]
	f.clusterCalls++
	return out, nil
}

func (f *fakeNeptuneTransitClient) DescribeDBInstances(ctx context.Context, in *neptune.DescribeDBInstancesInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBInstancesOutput, error) {
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	if f.instanceCalls >= len(f.instancesPages) {
		return &neptune.DescribeDBInstancesOutput{}, nil
	}
	out := f.instancesPages[f.instanceCalls]
	f.instanceCalls++
	return out, nil
}

func neptunetransitStrptr(s string) *string { return &s }

func neptunetransitAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

func neptunetransitPostureOf(a models.CryptoAsset) string {
	if a.Properties == nil {
		return ""
	}
	return a.Properties["posture"]
}

// TestNeptuneTransitScanPaginatesClusters verifies the DescribeDBClusters Marker
// loop: a fake that returns 2 pages (Marker set on page 1) must yield BOTH
// pages' clusters as assets. Without the pagination loop, only the first page's
// cluster survives.
func TestNeptuneTransitScanPaginatesClusters(t *testing.T) {
	client := &fakeNeptuneTransitClient{
		clustersPages: []*neptune.DescribeDBClustersOutput{
			{
				DBClusters: []neptunetypes.DBCluster{{DBClusterIdentifier: neptunetransitStrptr("neptune-page1")}},
				Marker:     neptunetransitStrptr("marker-page2"),
			},
			{
				DBClusters: []neptunetypes.DBCluster{{DBClusterIdentifier: neptunetransitStrptr("neptune-page2")}},
				// no Marker -> last page
			},
		},
	}
	assets, err := NeptuneTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.clusterCalls; c != 2 {
		t.Errorf("expected DescribeDBClusters to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"neptune-page1", "neptune-page2"} {
		if _, ok := neptunetransitAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestNeptuneTransitScanClustersErrorPropagates verifies the incompleteness
// contract: a DescribeDBClusters failure (denied/rate-limited) must make the
// scan VISIBLY incomplete by returning a non-nil error — NOT a silent empty
// success.
func TestNeptuneTransitScanClustersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBClusters")
	client := &fakeNeptuneTransitClient{
		clustersErr: sentinel,
	}
	_, err := NeptuneTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDBClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDBClusters failure, got: %v", err)
	}
}

// TestNeptuneTransitScanInstancesErrorIsNonFatal verifies that a
// DescribeDBInstances failure does NOT abort the scan or fabricate a CA cert:
// the cluster pass still runs (TLS is enforced via SSL/HTTPS-only) but the
// ca_identifier is left unknown rather than invented.
func TestNeptuneTransitScanInstancesErrorIsNonFatal(t *testing.T) {
	client := &fakeNeptuneTransitClient{
		clustersPages: []*neptune.DescribeDBClustersOutput{
			{DBClusters: []neptunetypes.DBCluster{{DBClusterIdentifier: neptunetransitStrptr("neptune-1")}}},
		},
		instancesErr: errors.New("AccessDeniedException: rds:DescribeDBInstances"),
	}
	assets, err := NeptuneTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan should not propagate the DescribeDBInstances error, got: %v", err)
	}
	a, ok := neptunetransitAssetByID(assets, "neptune-1")
	if !ok {
		t.Fatal("expected the cluster asset to still be produced despite the instances error")
	}
	if _, present := a.Properties["ca_identifier"]; present {
		t.Errorf("expected ca_identifier to be absent (unknown) when DescribeDBInstances failed, got %q", a.Properties["ca_identifier"])
	}
}

// TestNeptuneTransitScanHonestyPosture verifies the transit honesty contract for
// Neptune: connections are SSL/HTTPS-only (TLS enforced, plaintext rejected), so
// the cipher family is classical and the asset MUST be PostureNonPQCClassical —
// it must NEVER be marked as having no encryption. The CA-cert id discovered
// from the member instance also populates the cert key family (ecdsa-256 here)
// without clobbering the doc-fact-derived transit verdict.
func TestNeptuneTransitScanHonestyPosture(t *testing.T) {
	client := &fakeNeptuneTransitClient{
		clustersPages: []*neptune.DescribeDBClustersOutput{
			{DBClusters: []neptunetypes.DBCluster{{DBClusterIdentifier: neptunetransitStrptr("neptune-secured")}}},
		},
		instancesPages: []*neptune.DescribeDBInstancesOutput{
			{
				DBInstances: []neptunetypes.DBInstance{{
					DBClusterIdentifier:     neptunetransitStrptr("neptune-secured"),
					CACertificateIdentifier: neptunetransitStrptr("rds-ca-ecc256-g1"),
				}},
			},
		},
	}
	assets, err := NeptuneTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := neptunetransitAssetByID(assets, "neptune-secured")
	if !ok {
		t.Fatal("expected the neptune-secured cluster to appear as an asset")
	}

	posture := neptunetransitPostureOf(a)
	if posture == string(models.PostureNoEncryption) {
		t.Fatalf("Neptune enforces SSL/HTTPS-only: posture must NOT be NoEncryption, got %q", posture)
	}
	if posture != string(models.PostureNonPQCClassical) {
		t.Errorf("expected PostureNonPQCClassical for a TLS-enforced classical-cipher Neptune cluster, got %q", posture)
	}

	// The CA-cert family must be joined onto the asset, proving the
	// instances->cluster join wired through without fabrication.
	if got := a.Properties["ca_identifier"]; got != "rds-ca-ecc256-g1" {
		t.Errorf("expected ca_identifier from the member instance, got %q", got)
	}
	if a.Properties == nil {
		t.Fatal("expected populated Properties")
	}
}
