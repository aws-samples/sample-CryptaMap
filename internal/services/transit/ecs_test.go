package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeECSClient is a hand-rolled ecsListAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. ecsPages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so
// the scanner loops through every page; ecsErr forces a ListClusters failure.
type fakeECSClient struct {
	ecsPages []*ecs.ListClustersOutput
	ecsCalls int
	ecsErr   error
}

func (f *fakeECSClient) ListClusters(ctx context.Context, in *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	if f.ecsErr != nil {
		return nil, f.ecsErr
	}
	if f.ecsCalls >= len(f.ecsPages) {
		return &ecs.ListClustersOutput{}, nil
	}
	out := f.ecsPages[f.ecsCalls]
	f.ecsCalls++
	return out, nil
}

func ecsStrptr(s string) *string { return &s }

// ecsAssetByID returns the asset with the given ResourceID, or false.
func ecsAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestECSScanPaginatesClusters verifies the ListClusters NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination loop, only the first page's cluster survives.
func TestECSScanPaginatesClusters(t *testing.T) {
	client := &fakeECSClient{
		ecsPages: []*ecs.ListClustersOutput{
			{
				ClusterArns: []string{"arn:aws:ecs:us-east-1:111122223333:cluster/page1"},
				NextToken:   ecsStrptr("tok-page2"),
			},
			{
				ClusterArns: []string{"arn:aws:ecs:us-east-1:111122223333:cluster/page2"},
				// no NextToken -> last page
			},
		},
	}
	assets, err := ECSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.ecsCalls; c != 2 {
		t.Errorf("expected ListClusters to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{
		"arn:aws:ecs:us-east-1:111122223333:cluster/page1",
		"arn:aws:ecs:us-east-1:111122223333:cluster/page2",
	} {
		if _, ok := ecsAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestECSScanListClustersErrorPropagates verifies the incompleteness posture: a
// ListClusters failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestECSScanListClustersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform ecs:ListClusters")
	client := &fakeECSClient{ecsErr: sentinel}
	assets, err := ECSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListClusters failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a propagated error, got %d", len(assets))
	}
}

// TestECSScanHonestyPosture verifies the transit honesty posture for ECS: the
// scanner records the AWS-documented TLS 1.2 floor (a real transport guarantee,
// never a no-encryption / clean-bypass posture) and classifies the cluster's
// classical TLS as NonPQCClassical (RSA/ECDHE handshake without ML-KEM is NOT
// quantum-safe and must not read as already-PQC or unencrypted).
func TestECSScanHonestyPosture(t *testing.T) {
	const arn = "arn:aws:ecs:us-east-1:111122223333:cluster/prod"
	client := &fakeECSClient{
		ecsPages: []*ecs.ListClustersOutput{
			{ClusterArns: []string{arn}},
		},
	}
	assets, err := ECSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := ecsAssetByID(assets, arn)
	if !ok {
		t.Fatalf("expected cluster %q to be classified as an asset; assets=%v", arn, assets)
	}
	if a.ResourceType != "AWS::ECS::Cluster" {
		t.Errorf("expected ResourceType AWS::ECS::Cluster, got %q", a.ResourceType)
	}
	if a.Category != models.CategoryDataInTransit {
		t.Errorf("expected CategoryDataInTransit, got %q", a.Category)
	}
	// Honesty: classical TLS handshake is non-PQC, never a no-encryption or
	// legacy/clean-bypass verdict. ECS documents a real TLS 1.2 floor, so the
	// posture must read as classical-but-quantum-vulnerable.
	posture := a.Properties["posture"]
	if posture != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (classical TLS, not PQC); got %q",
			models.PostureNonPQCClassical, posture)
	}
	if posture == string(models.PostureNoEncryption) || posture == string(models.PostureLegacyTLS) {
		t.Errorf("ECS documents a TLS 1.2 floor; posture %q misrepresents that guarantee", posture)
	}
	// The documented floor must be recorded as TLS 1.2 (a genuine universal
	// guarantee), not silently dropped or downgraded to a weaker version.
	if pp := a.CryptoProps.ProtocolProperties; pp == nil {
		t.Errorf("expected ProtocolProperties on a transit asset, got nil")
	} else if pp.Version != "1.2" {
		t.Errorf("expected documented TLS floor 1.2, got %q", pp.Version)
	}
}
