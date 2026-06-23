package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeMSKTransitClient is a hand-rolled mskKafkaAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client.
// clustersPages is returned page-by-page (each call consumes the next page) and
// the NextToken is wired so the scanner loops through every page; listErr forces
// a ListClustersV2 failure on the first call.
type fakeMSKTransitClient struct {
	clustersPages []*kafka.ListClustersV2Output
	listCalls     int
	listErr       error
}

func (f *fakeMSKTransitClient) ListClustersV2(ctx context.Context, in *kafka.ListClustersV2Input, optFns ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.clustersPages) {
		return &kafka.ListClustersV2Output{}, nil
	}
	out := f.clustersPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func msktransitStrptr(s string) *string { return &s }
func msktransitBoolptr(b bool) *bool    { return &b }

// msktransitProvisionedCluster builds a Provisioned MSK cluster with the given
// name, client-broker encryption mode, and in-cluster (broker-to-broker) flag.
func msktransitProvisionedCluster(name, clientBroker string, inCluster *bool) kafkatypes.Cluster {
	return kafkatypes.Cluster{
		ClusterName: msktransitStrptr(name),
		ClusterArn:  msktransitStrptr("arn:aws:kafka:us-east-1:111122223333:cluster/" + name),
		Provisioned: &kafkatypes.Provisioned{
			EncryptionInfo: &kafkatypes.EncryptionInfo{
				EncryptionInTransit: &kafkatypes.EncryptionInTransit{
					ClientBroker: kafkatypes.ClientBroker(clientBroker),
					InCluster:    inCluster,
				},
			},
		},
	}
}

// msktransitAssetByID indexes assets by ResourceID for easy lookup in tests.
func msktransitAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestMSKTransitScanPaginates verifies the ListClustersV2 NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination restore, only the first page's cluster survives.
func TestMSKTransitScanPaginates(t *testing.T) {
	client := &fakeMSKTransitClient{
		clustersPages: []*kafka.ListClustersV2Output{
			{
				ClusterInfoList: []kafkatypes.Cluster{
					msktransitProvisionedCluster("cluster-page1", "TLS", msktransitBoolptr(true)),
				},
				NextToken: msktransitStrptr("tok-page2"),
			},
			{
				ClusterInfoList: []kafkatypes.Cluster{
					msktransitProvisionedCluster("cluster-page2", "TLS", msktransitBoolptr(true)),
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := MSKTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.listCalls; c != 2 {
		t.Errorf("expected ListClustersV2 to be called 2 times (paginated), got %d", c)
	}
	got := msktransitAssetByID(assets)
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestMSKTransitScanListErrorPropagates verifies the incompleteness decision: a
// ListClustersV2 failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success that
// would masquerade as "no clusters found" / clean coverage.
func TestMSKTransitScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform kafka:ListClustersV2")
	client := &fakeMSKTransitClient{listErr: sentinel}
	_, err := MSKTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListClustersV2 fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListClustersV2 failure, got: %v", err)
	}
}

// TestMSKTransitHonestyPosture is the honesty gate for the transit domain: the
// ClientBroker enum must drive an accurate enforcement posture, and a cluster
// that PERMITS plaintext must NOT be reported as clean fully-enforced TLS.
//   - TLS         -> enforced, classical TLS (non-pqc-classical)
//   - TLS_PLAINTEXT-> plaintext still accepted -> NOT enforced, weakened (legacy-tls)
//   - PLAINTEXT   -> no encryption, NOT enforced (never a clean posture)
func TestMSKTransitHonestyPosture(t *testing.T) {
	client := &fakeMSKTransitClient{
		clustersPages: []*kafka.ListClustersV2Output{
			{
				ClusterInfoList: []kafkatypes.Cluster{
					msktransitProvisionedCluster("tls-only", "TLS", msktransitBoolptr(true)),
					msktransitProvisionedCluster("mixed-mode", "TLS_PLAINTEXT", msktransitBoolptr(true)),
					msktransitProvisionedCluster("plaintext", "PLAINTEXT", msktransitBoolptr(false)),
				},
			},
		},
	}
	assets, err := MSKTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := msktransitAssetByID(assets)

	cases := []struct {
		id            string
		wantPosture   models.CryptoPosture
		wantEnforced  string
		wantClientBkr string
	}{
		{"tls-only", models.PostureNonPQCClassical, "true", "TLS"},
		{"mixed-mode", models.PostureLegacyTLS, "false", "TLS_PLAINTEXT"},
		{"plaintext", models.PostureNoEncryption, "false", "PLAINTEXT"},
	}
	for _, tc := range cases {
		a, ok := byID[tc.id]
		if !ok {
			t.Errorf("expected asset %q to be present", tc.id)
			continue
		}
		if got := a.Properties["posture"]; got != string(tc.wantPosture) {
			t.Errorf("%s: posture = %q, want %q", tc.id, got, tc.wantPosture)
		}
		if got := a.Properties["transitEncryptionEnforced"]; got != tc.wantEnforced {
			t.Errorf("%s: transitEncryptionEnforced = %q, want %q", tc.id, got, tc.wantEnforced)
		}
		if got := a.Properties["clientBroker"]; got != tc.wantClientBkr {
			t.Errorf("%s: clientBroker = %q, want %q", tc.id, got, tc.wantClientBkr)
		}
	}

	// The plaintext-permitting clusters must NOT be reported as clean fully-enforced TLS.
	for _, badID := range []string{"mixed-mode", "plaintext"} {
		if byID[badID].Properties["transitEncryptionEnforced"] == "true" {
			t.Errorf("%s permits plaintext but was reported as fully-enforced TLS (false clean signal)", badID)
		}
	}
}

// TestMSKTransitNilEncryptionDefaults verifies the backward-compatible default
// path: a cluster with no Provisioned/EncryptionInfo (e.g. Serverless or a nil
// shape) is still emitted as an asset with the conservative classical-TLS
// default rather than being silently dropped.
func TestMSKTransitNilEncryptionDefaults(t *testing.T) {
	client := &fakeMSKTransitClient{
		clustersPages: []*kafka.ListClustersV2Output{
			{
				ClusterInfoList: []kafkatypes.Cluster{
					{
						ClusterName: msktransitStrptr("serverless-cluster"),
						ClusterArn:  msktransitStrptr("arn:aws:kafka:us-east-1:111122223333:cluster/serverless-cluster"),
						// no Provisioned -> default path
					},
					{
						// no ClusterArn -> must be skipped (cannot key the asset)
						ClusterName: msktransitStrptr("orphan-no-arn"),
					},
				},
			},
		},
	}
	assets, err := MSKTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := msktransitAssetByID(assets)
	a, ok := byID["serverless-cluster"]
	if !ok {
		t.Fatal("expected serverless-cluster (nil encryption info) to still be emitted as an asset")
	}
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("serverless-cluster default posture = %q, want %q", got, models.PostureNonPQCClassical)
	}
	if _, ok := byID["orphan-no-arn"]; ok {
		t.Error("cluster with nil ClusterArn must be skipped, but it appeared as an asset")
	}
}
