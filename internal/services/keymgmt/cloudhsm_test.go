package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
	cloudhsmv2types "github.com/aws/aws-sdk-go-v2/service/cloudhsmv2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// cloudhsmFakeClient is a hand-rolled cloudHSMv2API for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so the
// scanner loops through every page; err forces a DescribeClusters failure.
type cloudhsmFakeClient struct {
	pages []*cloudhsmv2.DescribeClustersOutput
	calls int
	err   error
}

func (f *cloudhsmFakeClient) DescribeClusters(ctx context.Context, in *cloudhsmv2.DescribeClustersInput, optFns ...func(*cloudhsmv2.Options)) (*cloudhsmv2.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &cloudhsmv2.DescribeClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func cloudhsmStrptr(s string) *string { return &s }

func cloudhsmAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestCloudHSMScanPaginates verifies the DescribeClusters NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination loop, only the first page's cluster survives.
func TestCloudHSMScanPaginates(t *testing.T) {
	client := &cloudhsmFakeClient{
		pages: []*cloudhsmv2.DescribeClustersOutput{
			{
				Clusters: []cloudhsmv2types.Cluster{
					{ClusterId: cloudhsmStrptr("cluster-page1")},
				},
				NextToken: cloudhsmStrptr("tok-page2"),
			},
			{
				Clusters: []cloudhsmv2types.Cluster{
					{ClusterId: cloudhsmStrptr("cluster-page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := CloudHSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeClusters to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := cloudhsmAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestCloudHSMScanErrorPropagates verifies the incompleteness decision: a
// DescribeClusters failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestCloudHSMScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform cloudhsm:DescribeClusters")
	client := &cloudhsmFakeClient{err: sentinel}
	_, err := CloudHSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClusters failure, got: %v", err)
	}
}

// TestCloudHSMScanPostureClassicalNotNoEncryption is the honesty posture for the
// key-management domain: a CloudHSM cluster holds key material and its PKCS#11
// mechanism set is classical-only (no ML-KEM/ML-DSA). It must be classified
// NonPQCClassical — NEVER a no-encryption / clean posture, and the cluster mode
// (FIPS) must be captured as the authoritative crypto-relevant fact.
func TestCloudHSMScanPostureClassicalNotNoEncryption(t *testing.T) {
	client := &cloudhsmFakeClient{
		pages: []*cloudhsmv2.DescribeClustersOutput{
			{
				Clusters: []cloudhsmv2types.Cluster{
					{
						ClusterId: cloudhsmStrptr("cluster-fips"),
						HsmType:   cloudhsmStrptr("hsm1.medium"),
						Mode:      cloudhsmv2types.ClusterModeFips,
						State:     cloudhsmv2types.ClusterStateActive,
					},
				},
			},
		},
	}
	assets, err := CloudHSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := cloudhsmAssetByID(assets, "cluster-fips")
	if !ok {
		t.Fatal("expected cluster-fips to appear as an asset")
	}
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (classical key material), got %q — must never be clean/no-encryption", models.PostureNonPQCClassical, got)
	}
	if got := a.Properties["mode"]; got != "FIPS" {
		t.Errorf("expected FIPS mode captured as authoritative crypto fact, got %q", got)
	}
	if got := a.Properties["hsmType"]; got != "hsm1.medium" {
		t.Errorf("expected hsmType %q, got %q", "hsm1.medium", got)
	}
	if a.Properties["state"] != "ACTIVE" {
		t.Errorf("expected state ACTIVE, got %q", a.Properties["state"])
	}
}

// TestCloudHSMScanSkipsNilClusterID verifies a cluster missing its ID is skipped
// (it cannot be a stable asset key) but does not abort the whole page — the valid
// sibling on the same page is still emitted, so no silent drop of good data.
func TestCloudHSMScanSkipsNilClusterID(t *testing.T) {
	client := &cloudhsmFakeClient{
		pages: []*cloudhsmv2.DescribeClustersOutput{
			{
				Clusters: []cloudhsmv2types.Cluster{
					{ClusterId: nil, HsmType: cloudhsmStrptr("hsm1.medium")},
					{ClusterId: cloudhsmStrptr("cluster-valid")},
				},
			},
		},
	}
	assets, err := CloudHSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil-ID cluster skipped, valid sibling kept), got %d", len(assets))
	}
	if _, ok := cloudhsmAssetByID(assets, "cluster-valid"); !ok {
		t.Error("expected the valid sibling cluster to survive the nil-ID skip")
	}
}
