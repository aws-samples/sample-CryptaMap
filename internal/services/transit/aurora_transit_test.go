package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// auroratransitStrptr returns a pointer to s. Prefixed to avoid colliding with
// other transit-package test helpers that share this build.
func auroratransitStrptr(s string) *string { return &s }

// auroratransitFakeRDS is a hand-rolled auroraTransitRDSAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client.
// clusterPages is returned page-by-page (each call consumes the next page) and
// the Marker is wired so the scanner loops through every page; clustersErr forces
// a DescribeDBClusters failure. paramPages maps a cluster-parameter-group name to
// its page sequence so the enforce-TLS toggle can be exercised, and paramErr
// (keyed by group name) forces a DescribeDBClusterParameters failure for that
// group.
type auroratransitFakeRDS struct {
	clusterPages []*rds.DescribeDBClustersOutput
	clusterCalls int
	clustersErr  error

	paramPages map[string][]*rds.DescribeDBClusterParametersOutput
	paramCalls map[string]int
	paramErr   map[string]error
}

func (f *auroratransitFakeRDS) DescribeDBClusters(ctx context.Context, in *rds.DescribeDBClustersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error) {
	if f.clustersErr != nil {
		return nil, f.clustersErr
	}
	if f.clusterCalls >= len(f.clusterPages) {
		return &rds.DescribeDBClustersOutput{}, nil
	}
	out := f.clusterPages[f.clusterCalls]
	f.clusterCalls++
	return out, nil
}

func (f *auroratransitFakeRDS) DescribeDBClusterParameters(ctx context.Context, in *rds.DescribeDBClusterParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClusterParametersOutput, error) {
	name := ""
	if in.DBClusterParameterGroupName != nil {
		name = *in.DBClusterParameterGroupName
	}
	if f.paramErr != nil {
		if err := f.paramErr[name]; err != nil {
			return nil, err
		}
	}
	if f.paramCalls == nil {
		f.paramCalls = map[string]int{}
	}
	pages := f.paramPages[name]
	idx := f.paramCalls[name]
	if idx >= len(pages) {
		return &rds.DescribeDBClusterParametersOutput{}, nil
	}
	f.paramCalls[name]++
	return pages[idx], nil
}

// auroratransitAssetByID returns the asset with the given ResourceID, or false.
func auroratransitAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// auroratransitClusterParam builds a single enforce-TLS parameter page.
func auroratransitClusterParam(name, value string) *rds.DescribeDBClusterParametersOutput {
	return &rds.DescribeDBClusterParametersOutput{
		Parameters: []rdstypes.Parameter{
			{ParameterName: auroratransitStrptr(name), ParameterValue: auroratransitStrptr(value)},
		},
	}
}

// TestAuroraTransitScanPaginatesClusters verifies the DescribeDBClusters Marker
// loop: a fake returning 2 pages (Marker on page 1) must yield BOTH pages'
// Aurora clusters as assets. Without the pagination restore only the first
// page's cluster survives.
func TestAuroraTransitScanPaginatesClusters(t *testing.T) {
	client := &auroratransitFakeRDS{
		clusterPages: []*rds.DescribeDBClustersOutput{
			{
				DBClusters: []rdstypes.DBCluster{{
					DBClusterIdentifier: auroratransitStrptr("aurora-page1"),
					Engine:              auroratransitStrptr("aurora-mysql"),
				}},
				Marker: auroratransitStrptr("marker-page2"),
			},
			{
				DBClusters: []rdstypes.DBCluster{{
					DBClusterIdentifier: auroratransitStrptr("aurora-page2"),
					Engine:              auroratransitStrptr("aurora-postgresql"),
				}},
				// no Marker -> last page
			},
		},
	}
	assets, err := AuroraTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.clusterCalls != 2 {
		t.Errorf("expected DescribeDBClusters to be called 2 times (paginated), got %d", client.clusterCalls)
	}
	for _, want := range []string{"aurora-page1", "aurora-page2"} {
		if _, ok := auroratransitAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; got %d assets", want, len(assets))
		}
	}
}

// TestAuroraTransitScanClustersErrorPropagates verifies the incompleteness
// contract: a DescribeDBClusters failure (denied/rate-limited) must make the
// scan VISIBLY incomplete by returning a non-nil wrapped error — NOT a silent
// empty success.
func TestAuroraTransitScanClustersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBClusters")
	client := &auroratransitFakeRDS{clustersErr: sentinel}
	_, err := AuroraTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDBClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDBClusters failure, got: %v", err)
	}
}

// TestAuroraTransitNonAuroraSkipped verifies the engine filter: a non-Aurora
// RDS cluster surfacing in DescribeDBClusters output is NOT emitted by this
// (Aurora-specific) scanner.
func TestAuroraTransitNonAuroraSkipped(t *testing.T) {
	client := &auroratransitFakeRDS{
		clusterPages: []*rds.DescribeDBClustersOutput{{
			DBClusters: []rdstypes.DBCluster{
				{DBClusterIdentifier: auroratransitStrptr("plain-mysql"), Engine: auroratransitStrptr("mysql")},
				{DBClusterIdentifier: auroratransitStrptr("aurora-1"), Engine: auroratransitStrptr("aurora-mysql")},
			},
		}},
	}
	assets, err := AuroraTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if _, ok := auroratransitAssetByID(assets, "plain-mysql"); ok {
		t.Error("non-Aurora engine 'mysql' must be skipped by aurora_transit, but it was emitted")
	}
	if _, ok := auroratransitAssetByID(assets, "aurora-1"); !ok {
		t.Error("aurora-mysql cluster should be emitted")
	}
}

// TestAuroraTransitEnforcementPosture is the honesty-posture matrix for the
// transit domain. TLS being AVAILABLE is not TLS being REQUIRED:
//   - require_secure_transport=1 -> enforced -> non-pqc-classical
//   - require_secure_transport=0 -> NOT enforced -> legacy-tls (plaintext
//     permitted is NOT a clean all-clear), note set
//   - param-group unreadable -> unknown (no fabricated all-clear, no alarm)
func TestAuroraTransitEnforcementPosture(t *testing.T) {
	cases := []struct {
		name        string
		groupName   string
		paramPages  map[string][]*rds.DescribeDBClusterParametersOutput
		paramErr    map[string]error
		wantPosture models.CryptoPosture
		wantEnforce string
		wantNote    bool
	}{
		{
			name:      "enforced",
			groupName: "pg-enforced",
			paramPages: map[string][]*rds.DescribeDBClusterParametersOutput{
				"pg-enforced": {auroratransitClusterParam("require_secure_transport", "1")},
			},
			wantPosture: models.PostureNonPQCClassical,
			wantEnforce: string(dbSSLEnforced),
			wantNote:    false,
		},
		{
			name:      "not-enforced-plaintext-allowed",
			groupName: "pg-open",
			paramPages: map[string][]*rds.DescribeDBClusterParametersOutput{
				"pg-open": {auroratransitClusterParam("rds.force_ssl", "0")},
			},
			wantPosture: models.PostureLegacyTLS,
			wantEnforce: string(dbSSLNotEnforced),
			wantNote:    true,
		},
		{
			name:        "param-group-unreadable-unknown",
			groupName:   "pg-denied",
			paramErr:    map[string]error{"pg-denied": errors.New("AccessDenied")},
			wantPosture: models.PostureUnknown,
			wantEnforce: string(dbSSLUnknown),
			wantNote:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &auroratransitFakeRDS{
				clusterPages: []*rds.DescribeDBClustersOutput{{
					DBClusters: []rdstypes.DBCluster{{
						DBClusterIdentifier:     auroratransitStrptr("aurora-c"),
						Engine:                  auroratransitStrptr("aurora-mysql"),
						DBClusterParameterGroup: auroratransitStrptr(tc.groupName),
					}},
				}},
				paramPages: tc.paramPages,
				paramErr:   tc.paramErr,
			}
			assets, err := AuroraTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			a, ok := auroratransitAssetByID(assets, "aurora-c")
			if !ok {
				t.Fatalf("expected asset 'aurora-c' to be emitted; got %d assets", len(assets))
			}
			if got := a.Properties["posture"]; got != string(tc.wantPosture) {
				t.Errorf("posture = %q, want %q", got, tc.wantPosture)
			}
			if got := a.Properties["tls_enforcement"]; got != tc.wantEnforce {
				t.Errorf("tls_enforcement = %q, want %q", got, tc.wantEnforce)
			}
			if _, has := a.Properties["note"]; has != tc.wantNote {
				t.Errorf("note present = %v, want %v (props=%v)", has, tc.wantNote, a.Properties)
			}
			// An always-classical Aurora cert must never read as no-encryption.
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Error("Aurora transit must never be classified NoEncryption")
			}
		})
	}
}

// TestAuroraTransitCertKeyFamilyAndUnknownTLS verifies the honesty contract on
// the cert/TLS detail: the CA identifier drives the leaf-cert key family
// (RSA-2048 vs ECDSA-P384) while the negotiated TLS version is left blank rather
// than fabricating "1.2", and an unrecognized CA id yields no fabricated family.
func TestAuroraTransitCertKeyFamilyAndUnknownTLS(t *testing.T) {
	client := &auroratransitFakeRDS{
		clusterPages: []*rds.DescribeDBClustersOutput{{
			DBClusters: []rdstypes.DBCluster{
				{
					DBClusterIdentifier: auroratransitStrptr("aurora-rsa"),
					Engine:              auroratransitStrptr("aurora-mysql"),
					CertificateDetails:  &rdstypes.CertificateDetails{CAIdentifier: auroratransitStrptr("rds-ca-rsa2048-g1")},
				},
				{
					DBClusterIdentifier: auroratransitStrptr("aurora-unknown-ca"),
					Engine:              auroratransitStrptr("aurora-postgresql"),
					CertificateDetails:  &rdstypes.CertificateDetails{CAIdentifier: auroratransitStrptr("some-future-ca-xyz")},
				},
			},
		}},
	}
	assets, err := AuroraTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	rsa, ok := auroratransitAssetByID(assets, "aurora-rsa")
	if !ok {
		t.Fatal("expected asset 'aurora-rsa'")
	}
	if rsa.Properties["ca_identifier"] != "rds-ca-rsa2048-g1" {
		t.Errorf("expected ca_identifier recorded, got %q", rsa.Properties["ca_identifier"])
	}
	// Negotiated TLS version is not exposed by any API and must not be fabricated.
	if v := rsa.Properties["tls_version"]; v == "1.2" || v == "1.3" {
		t.Errorf("aurora_transit must not fabricate a negotiated TLS version, got tls_version=%q", v)
	}

	unk, ok := auroratransitAssetByID(assets, "aurora-unknown-ca")
	if !ok {
		t.Fatal("expected asset 'aurora-unknown-ca'")
	}
	if unk.Properties["ca_identifier"] != "some-future-ca-xyz" {
		t.Errorf("expected ca_identifier recorded for unknown CA, got %q", unk.Properties["ca_identifier"])
	}
}
