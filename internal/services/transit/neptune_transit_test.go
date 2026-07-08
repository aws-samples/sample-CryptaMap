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
				DBClusters: []neptunetypes.DBCluster{{
					DBClusterIdentifier: neptunetransitStrptr("neptune-page1"),
					Engine:              neptunetransitStrptr("neptune"),
					EngineVersion:       neptunetransitStrptr("1.2.0.1"),
				}},
				Marker: neptunetransitStrptr("marker-page2"),
			},
			{
				DBClusters: []neptunetypes.DBCluster{{
					DBClusterIdentifier: neptunetransitStrptr("neptune-page2"),
					Engine:              neptunetransitStrptr("neptune"),
					EngineVersion:       neptunetransitStrptr("1.2.0.1"),
				}},
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
			{DBClusters: []neptunetypes.DBCluster{{
				DBClusterIdentifier: neptunetransitStrptr("neptune-1"),
				Engine:              neptunetransitStrptr("neptune"),
				EngineVersion:       neptunetransitStrptr("1.2.0.1"),
			}}},
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
// a Neptune cluster on engine version 1.0.4.0+: those engines only accept HTTPS
// (TLS enforced, plaintext rejected), so the cipher family is classical and the
// asset MUST be PostureNonPQCClassical — it must NEVER be marked as having no
// encryption. The CA-cert id discovered from the member instance also populates
// the cert key family (ecdsa-256 here) without clobbering the doc-fact-derived
// transit verdict.
func TestNeptuneTransitScanHonestyPosture(t *testing.T) {
	client := &fakeNeptuneTransitClient{
		clustersPages: []*neptune.DescribeDBClustersOutput{
			{DBClusters: []neptunetypes.DBCluster{{
				DBClusterIdentifier: neptunetransitStrptr("neptune-secured"),
				Engine:              neptunetransitStrptr("neptune"),
				EngineVersion:       neptunetransitStrptr("1.0.4.0"),
			}}},
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

// TestNeptuneTransitSkipsForeignEngines verifies the shared-control-plane
// honesty contract: DescribeDBClusters on the RDS control plane returns
// RDS/Aurora/Neptune/DocDB clusters alike, and this scanner must NOT stamp
// Neptune's "SSL/HTTPS-only" verdict on a foreign or engine-less cluster. Only
// the Engine=="neptune" cluster may be emitted.
func TestNeptuneTransitSkipsForeignEngines(t *testing.T) {
	client := &fakeNeptuneTransitClient{
		clustersPages: []*neptune.DescribeDBClustersOutput{
			{DBClusters: []neptunetypes.DBCluster{
				{
					DBClusterIdentifier: neptunetransitStrptr("aurora-foreign"),
					Engine:              neptunetransitStrptr("aurora-mysql"),
				},
				{
					DBClusterIdentifier: neptunetransitStrptr("docdb-foreign"),
					Engine:              neptunetransitStrptr("docdb"),
				},
				{
					DBClusterIdentifier: neptunetransitStrptr("engineless"),
					// Engine nil: unprovable -> must be skipped, not stamped.
				},
				{
					DBClusterIdentifier: neptunetransitStrptr("neptune-real"),
					Engine:              neptunetransitStrptr("neptune"),
					EngineVersion:       neptunetransitStrptr("1.3.0.0"),
				},
			}},
		},
	}
	assets, err := NeptuneTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (the neptune cluster), got %d: %+v", len(assets), assets)
	}
	for _, foreign := range []string{"aurora-foreign", "docdb-foreign", "engineless"} {
		if _, ok := neptunetransitAssetByID(assets, foreign); ok {
			t.Errorf("foreign/engine-less cluster %q must NOT be emitted by the neptune scanner", foreign)
		}
	}
	a, ok := neptunetransitAssetByID(assets, "neptune-real")
	if !ok {
		t.Fatal("expected the real neptune cluster to be emitted")
	}
	if p := neptunetransitPostureOf(a); p != string(models.PostureNonPQCClassical) {
		t.Errorf("neptune 1.3.0.0 cluster (HTTPS-only) must be %q, got %q", models.PostureNonPQCClassical, p)
	}
}

// TestNeptuneTransitOldEngineVersionIsUnknown verifies the version gate on the
// HTTPS-only doc fact: engines before 1.0.4.0 also accepted plaintext HTTP, and
// a missing EngineVersion leaves the guarantee unprovable — both must yield
// PostureUnknown with an explanatory note, never a fabricated TLS-enforced
// classical verdict.
func TestNeptuneTransitOldEngineVersionIsUnknown(t *testing.T) {
	client := &fakeNeptuneTransitClient{
		clustersPages: []*neptune.DescribeDBClustersOutput{
			{DBClusters: []neptunetypes.DBCluster{
				{
					DBClusterIdentifier: neptunetransitStrptr("neptune-old"),
					Engine:              neptunetransitStrptr("neptune"),
					EngineVersion:       neptunetransitStrptr("1.0.3.0"),
				},
				{
					DBClusterIdentifier: neptunetransitStrptr("neptune-noversion"),
					Engine:              neptunetransitStrptr("neptune"),
					// EngineVersion nil: guarantee unprovable.
				},
			}},
		},
	}
	assets, err := NeptuneTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	for _, id := range []string{"neptune-old", "neptune-noversion"} {
		a, ok := neptunetransitAssetByID(assets, id)
		if !ok {
			t.Fatalf("expected %q to still appear as an asset (never silently dropped)", id)
		}
		if p := neptunetransitPostureOf(a); p != string(models.PostureUnknown) {
			t.Errorf("%s: pre-1.0.4.0/unknown engine version must be posture %q (HTTP was accepted / unprovable), got %q", id, models.PostureUnknown, p)
		}
		if a.Properties["note"] == "" {
			t.Errorf("%s: expected an explanatory note naming the unprovable HTTPS-only guarantee, got none", id)
		}
	}
}

// TestNeptuneVersionAtLeast pins the dotted-version comparator used to gate the
// HTTPS-only doc fact, including the fail-closed behaviour for unparseable
// input (an unreadable version must never satisfy the guarantee).
func TestNeptuneVersionAtLeast(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"1.0.4.0", true},
		{"1.0.5.1", true},
		{"1.2.0.1", true},
		{"1.0.3.0", false},
		{"1.0.2.2", false},
		{"", false},
		{"not-a-version", false},
		{"1.0.4", true}, // missing trailing segment == 0
		{"1.0", false},  // 1.0.0.0 < 1.0.4.0
		{"1.0.10.0", true},
	}
	for _, c := range cases {
		if got := neptuneVersionAtLeast(c.version, "1.0.4.0"); got != c.want {
			t.Errorf("neptuneVersionAtLeast(%q, 1.0.4.0) = %v, want %v", c.version, got, c.want)
		}
	}
}
