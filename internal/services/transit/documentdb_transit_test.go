package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeDocumentDBTransitClient is a hand-rolled docdbTransitAPI for unit-testing
// the scanner's pagination + error propagation without a live AWS client. Each
// *Pages slice is returned page-by-page (each call consumes the next page) and
// the Marker is wired so the scanner loops through every page. The *Err fields
// force the corresponding call to fail.
type fakeDocumentDBTransitClient struct {
	clusterPages []*docdb.DescribeDBClustersOutput
	clusterCalls int
	clustersErr  error

	instancePages []*docdb.DescribeDBInstancesOutput
	instanceCalls int
	instancesErr  error

	// paramOut keyed by DBClusterParameterGroupName -> single-page parameters.
	paramOut  map[string]*docdb.DescribeDBClusterParametersOutput
	paramErr  error
	paramHits map[string]int
}

func (f *fakeDocumentDBTransitClient) DescribeDBClusters(ctx context.Context, in *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error) {
	if f.clustersErr != nil {
		return nil, f.clustersErr
	}
	if f.clusterCalls >= len(f.clusterPages) {
		return &docdb.DescribeDBClustersOutput{}, nil
	}
	out := f.clusterPages[f.clusterCalls]
	f.clusterCalls++
	return out, nil
}

func (f *fakeDocumentDBTransitClient) DescribeDBInstances(ctx context.Context, in *docdb.DescribeDBInstancesInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error) {
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	if f.instanceCalls >= len(f.instancePages) {
		return &docdb.DescribeDBInstancesOutput{}, nil
	}
	out := f.instancePages[f.instanceCalls]
	f.instanceCalls++
	return out, nil
}

func (f *fakeDocumentDBTransitClient) DescribeDBClusterParameters(ctx context.Context, in *docdb.DescribeDBClusterParametersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterParametersOutput, error) {
	if f.paramErr != nil {
		return nil, f.paramErr
	}
	name := ""
	if in.DBClusterParameterGroupName != nil {
		name = *in.DBClusterParameterGroupName
	}
	if f.paramHits == nil {
		f.paramHits = map[string]int{}
	}
	f.paramHits[name]++
	if f.paramOut != nil {
		if out, ok := f.paramOut[name]; ok {
			return out, nil
		}
	}
	return &docdb.DescribeDBClusterParametersOutput{}, nil
}

func documentdbtransitStrptr(s string) *string { return &s }

// documentdbtransitAssetByID indexes scan output by ResourceID for assertions.
func documentdbtransitAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

func documentdbtransitPostureOf(a models.CryptoAsset) string {
	return a.Properties["posture"]
}

// TestDocumentDBTransitScanPaginatesClusters verifies the DescribeDBClusters
// Marker loop: a fake that returns 2 pages (Marker on page 1) must yield BOTH
// pages' clusters as assets. Without the pagination loop, only the first page's
// cluster survives.
func TestDocumentDBTransitScanPaginatesClusters(t *testing.T) {
	client := &fakeDocumentDBTransitClient{
		clusterPages: []*docdb.DescribeDBClustersOutput{
			{
				DBClusters: []docdbtypes.DBCluster{{
					DBClusterIdentifier:     documentdbtransitStrptr("cluster-page1"),
					DBClusterParameterGroup: documentdbtransitStrptr("default.docdb5.0"),
				}},
				Marker: documentdbtransitStrptr("marker-page2"),
			},
			{
				DBClusters: []docdbtypes.DBCluster{{
					DBClusterIdentifier:     documentdbtransitStrptr("cluster-page2"),
					DBClusterParameterGroup: documentdbtransitStrptr("default.docdb5.0"),
				}},
				// no Marker -> last page
			},
		},
	}
	assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.clusterCalls != 2 {
		t.Errorf("expected DescribeDBClusters to be called 2 times (paginated), got %d", client.clusterCalls)
	}
	got := documentdbtransitAssetByID(assets)
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; assets=%v", want, keysOfDocumentDBTransit(got))
		}
	}
}

func keysOfDocumentDBTransit(m map[string]models.CryptoAsset) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestDocumentDBTransitScanClustersErrorPropagates verifies the incompleteness
// contract: a DescribeDBClusters failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestDocumentDBTransitScanClustersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBClusters")
	client := &fakeDocumentDBTransitClient{clustersErr: sentinel}
	_, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDBClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDBClusters failure, got: %v", err)
	}
}

// TestDocumentDBTransitTLSDisabledIsNoEncryption is the core honesty assertion:
// a cluster whose cluster parameter group sets tls=disabled accepts plaintext, so
// it MUST be posture no-encryption (a false all-clear here would hide an
// unencrypted-in-transit cluster), with an explanatory note.
func TestDocumentDBTransitTLSDisabledIsNoEncryption(t *testing.T) {
	client := &fakeDocumentDBTransitClient{
		clusterPages: []*docdb.DescribeDBClustersOutput{{
			DBClusters: []docdbtypes.DBCluster{{
				DBClusterIdentifier:     documentdbtransitStrptr("cluster-plaintext"),
				DBClusterParameterGroup: documentdbtransitStrptr("custom-pg"),
			}},
		}},
		paramOut: map[string]*docdb.DescribeDBClusterParametersOutput{
			"custom-pg": {Parameters: []docdbtypes.Parameter{{
				ParameterName:  documentdbtransitStrptr("tls"),
				ParameterValue: documentdbtransitStrptr("disabled"),
			}}},
		},
	}
	assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := documentdbtransitAssetByID(assets)["cluster-plaintext"]
	if !ok {
		t.Fatalf("cluster-plaintext not found in assets")
	}
	if p := documentdbtransitPostureOf(a); p != string(models.PostureNoEncryption) {
		t.Errorf("tls=disabled cluster must be posture %q (plaintext accepted), got %q", models.PostureNoEncryption, p)
	}
	if a.Properties["tlsEnforcement"] != string(docdbTLSDisabled) {
		t.Errorf("expected tlsEnforcement=%q, got %q", docdbTLSDisabled, a.Properties["tlsEnforcement"])
	}
	if a.Properties["note"] == "" {
		t.Error("expected an explanatory note on a tls=disabled cluster, got none")
	}
}

// TestDocumentDBTransitTLSEnabledIsClassical verifies an explicitly enforcing
// cluster parameter group (tls=enabled) is posture non-pqc-classical (TLS
// available + enforced, but RSA/ECDHE without ML-KEM) — never no-encryption.
func TestDocumentDBTransitTLSEnabledIsClassical(t *testing.T) {
	client := &fakeDocumentDBTransitClient{
		clusterPages: []*docdb.DescribeDBClustersOutput{{
			DBClusters: []docdbtypes.DBCluster{{
				DBClusterIdentifier:     documentdbtransitStrptr("cluster-tls"),
				DBClusterParameterGroup: documentdbtransitStrptr("custom-pg"),
			}},
		}},
		paramOut: map[string]*docdb.DescribeDBClusterParametersOutput{
			"custom-pg": {Parameters: []docdbtypes.Parameter{{
				ParameterName:  documentdbtransitStrptr("tls"),
				ParameterValue: documentdbtransitStrptr("enabled"),
			}}},
		},
	}
	assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := documentdbtransitAssetByID(assets)["cluster-tls"]
	if !ok {
		t.Fatalf("cluster-tls not found in assets")
	}
	if p := documentdbtransitPostureOf(a); p != string(models.PostureNonPQCClassical) {
		t.Errorf("tls=enabled cluster must be posture %q, got %q", models.PostureNonPQCClassical, p)
	}
	if a.Properties["tlsEnforcement"] != string(docdbTLSEnforced) {
		t.Errorf("expected tlsEnforcement=%q, got %q", docdbTLSEnforced, a.Properties["tlsEnforcement"])
	}
}

// TestDocumentDBTransitDefaultGroupIsEnforced verifies the immutable-default-group
// shortcut: a cluster on a "default.*" cluster parameter group is reported as
// enforced WITHOUT an extra DescribeDBClusterParameters call (tls cannot have been
// changed from its enabled default).
func TestDocumentDBTransitDefaultGroupIsEnforced(t *testing.T) {
	client := &fakeDocumentDBTransitClient{
		clusterPages: []*docdb.DescribeDBClustersOutput{{
			DBClusters: []docdbtypes.DBCluster{{
				DBClusterIdentifier:     documentdbtransitStrptr("cluster-default"),
				DBClusterParameterGroup: documentdbtransitStrptr("default.docdb5.0"),
			}},
		}},
	}
	assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := documentdbtransitAssetByID(assets)["cluster-default"]
	if p := documentdbtransitPostureOf(a); p != string(models.PostureNonPQCClassical) {
		t.Errorf("cluster on immutable default group must be enforced -> posture %q, got %q", models.PostureNonPQCClassical, p)
	}
	if client.paramHits["default.docdb5.0"] != 0 {
		t.Errorf("expected NO DescribeDBClusterParameters call for an immutable default group, got %d", client.paramHits["default.docdb5.0"])
	}
}

// TestDocumentDBTransitUnreadableTLSIsUnknown verifies the no-silent-drop / no-
// fabrication contract for an unprovable enforcement state: when the tls parameter
// cannot be read (DescribeDBClusterParameters fails on a custom group), the
// posture must be unknown — NOT a fabricated all-clear or alarm — with a note,
// and the cluster must still appear (never silently dropped).
func TestDocumentDBTransitUnreadableTLSIsUnknown(t *testing.T) {
	client := &fakeDocumentDBTransitClient{
		clusterPages: []*docdb.DescribeDBClustersOutput{{
			DBClusters: []docdbtypes.DBCluster{{
				DBClusterIdentifier:     documentdbtransitStrptr("cluster-opaque"),
				DBClusterParameterGroup: documentdbtransitStrptr("custom-pg"),
			}},
		}},
		paramErr: errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBClusterParameters"),
	}
	assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error (a parameter read failure must not fail the whole scan): %v", err)
	}
	a, ok := documentdbtransitAssetByID(assets)["cluster-opaque"]
	if !ok {
		t.Fatal("cluster-opaque was silently dropped when its tls parameter was unreadable")
	}
	if p := documentdbtransitPostureOf(a); p != string(models.PostureUnknown) {
		t.Errorf("unreadable tls parameter must yield posture %q (never a fabricated all-clear/alarm), got %q", models.PostureUnknown, p)
	}
	if a.Properties["note"] == "" {
		t.Error("expected an explanatory note when enforcement state is undetermined, got none")
	}
}

// TestDocumentDBTransitJoinsCertFromInstances verifies the cluster<-instance cert
// join + key-family classification: an instance reporting an ECC-384 CA id is
// joined onto its cluster, yielding the correct cert signature algorithm/key size
// without fabricating a TLS version (which no API exposes).
func TestDocumentDBTransitJoinsCertFromInstances(t *testing.T) {
	client := &fakeDocumentDBTransitClient{
		clusterPages: []*docdb.DescribeDBClustersOutput{{
			DBClusters: []docdbtypes.DBCluster{{
				DBClusterIdentifier:     documentdbtransitStrptr("cluster-cert"),
				DBClusterParameterGroup: documentdbtransitStrptr("default.docdb5.0"),
			}},
		}},
		instancePages: []*docdb.DescribeDBInstancesOutput{
			{
				DBInstances: []docdbtypes.DBInstance{{
					DBClusterIdentifier:     documentdbtransitStrptr("cluster-cert"),
					CACertificateIdentifier: documentdbtransitStrptr("rds-ca-ecc384-g1"),
				}},
				Marker: documentdbtransitStrptr("ins-page2"),
			},
			{
				DBInstances: []docdbtypes.DBInstance{{
					DBClusterIdentifier:     documentdbtransitStrptr("cluster-other"),
					CACertificateIdentifier: documentdbtransitStrptr("rds-ca-rsa2048-g1"),
				}},
			},
		},
	}
	assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.instanceCalls != 2 {
		t.Errorf("expected DescribeDBInstances to be called 2 times (paginated), got %d", client.instanceCalls)
	}
	a, ok := documentdbtransitAssetByID(assets)["cluster-cert"]
	if !ok {
		t.Fatalf("cluster-cert not found in assets")
	}
	if a.Properties["ca_identifier"] != "rds-ca-ecc384-g1" {
		t.Errorf("expected ca_identifier joined from instance, got %q", a.Properties["ca_identifier"])
	}
	if a.Properties == nil || a.Properties["posture"] != string(models.PostureNonPQCClassical) {
		t.Errorf("default-group ECC cluster must be posture %q, got %q", models.PostureNonPQCClassical, a.Properties["posture"])
	}
}
