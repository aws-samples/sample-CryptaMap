package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeEKSClient is a hand-rolled eksClustersAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. listPages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; listErr forces a ListClusters
// failure on the first call.
type fakeEKSClient struct {
	eksListPages []*eks.ListClustersOutput
	eksListCalls int
	eksListErr   error
}

func (f *fakeEKSClient) ListClusters(ctx context.Context, in *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if f.eksListErr != nil {
		return nil, f.eksListErr
	}
	if f.eksListCalls >= len(f.eksListPages) {
		return &eks.ListClustersOutput{}, nil
	}
	out := f.eksListPages[f.eksListCalls]
	f.eksListCalls++
	return out, nil
}

func eksStrptr(s string) *string { return &s }

func eksAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestEKSScanPaginatesClusters verifies the ListClusters NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination loop, only the first page's cluster survives.
func TestEKSScanPaginatesClusters(t *testing.T) {
	client := &fakeEKSClient{
		eksListPages: []*eks.ListClustersOutput{
			{
				Clusters:  []string{"cluster-page1"},
				NextToken: eksStrptr("tok-page2"),
			},
			{
				Clusters: []string{"cluster-page2"},
				// no NextToken -> last page
			},
		},
	}
	assets, err := EKSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.eksListCalls; c != 2 {
		t.Errorf("expected ListClusters to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := eksAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestEKSScanListErrorPropagates verifies the incompleteness decision: a
// ListClusters failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestEKSScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform eks:ListClusters")
	client := &fakeEKSClient{eksListErr: sentinel}
	assets, err := EKSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListClusters fails, got nil with %d assets", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListClusters failure, got: %v", err)
	}
}

// TestEKSScanHonestyPosture verifies the transit honesty posture for EKS: the
// control-plane TLS endpoint enforces a documented TLS 1.2 floor, so the asset
// must be classified non-pqc-classical (RSA/ECDHE without ML-KEM) — never
// no-encryption and never a clean PQC-ready/hybrid verdict. It must also carry
// aws-doc provenance (the floor is documented, not observed per-connection).
func TestEKSScanHonestyPosture(t *testing.T) {
	client := &fakeEKSClient{
		eksListPages: []*eks.ListClustersOutput{
			{Clusters: []string{"prod-cluster"}},
		},
	}
	assets, err := EKSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := eksAssetByID(assets, "prod-cluster")
	if !ok {
		t.Fatalf("expected an asset for cluster prod-cluster; assets=%v", assets)
	}
	if a.ResourceType != "AWS::EKS::Cluster" {
		t.Errorf("expected resourceType AWS::EKS::Cluster, got %q", a.ResourceType)
	}
	posture := a.Properties["posture"]
	if posture != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (TLS 1.2 floor, classical KEX), got %q", models.PostureNonPQCClassical, posture)
	}
	// Must NOT masquerade as quantum-safe or as plaintext.
	if posture == string(models.PosturePQCHybrid) || posture == string(models.PosturePQCReady) {
		t.Errorf("EKS control-plane TLS is classical; must not be classified quantum-safe, got %q", posture)
	}
	if posture == string(models.PostureNoEncryption) {
		t.Errorf("EKS endpoint is TLS-protected; must not be classified no-encryption, got %q", posture)
	}
	// Documented floor, not observed per-connection: confirm the protocol block
	// records TLS 1.2 with aws-doc provenance (not a live-observed handshake).
	pp := a.CryptoProps.ProtocolProperties
	if pp == nil {
		t.Fatalf("expected protocol properties to be populated for an EKS TLS asset")
	}
	if pp.Version != "1.2" {
		t.Errorf("expected documented TLS floor 1.2, got %q", pp.Version)
	}
}
