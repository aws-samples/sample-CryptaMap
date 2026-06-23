package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeDAXClient is a hand-rolled daxAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) with NextToken wired so the
// scanner loops through every page; err forces a DescribeClusters failure on
// the first call.
type fakeDAXClient struct {
	pages []*dax.DescribeClustersOutput
	calls int
	err   error
}

func (f *fakeDAXClient) DescribeClusters(ctx context.Context, in *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &dax.DescribeClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func sp(s string) *string { return &s }

// findDAXAsset returns the asset whose ResourceID matches id, or nil.
func findDAXAsset(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// TestDAXScanPaginatesClusters verifies the DescribeClusters NextToken loop: a
// fake returning 2 pages (NextToken on page 1) must yield BOTH pages' clusters
// as assets. Without the pagination loop, only the first page survives — the
// commonest real bug.
func TestDAXScanPaginatesClusters(t *testing.T) {
	client := &fakeDAXClient{
		pages: []*dax.DescribeClustersOutput{
			{
				Clusters: []daxtypes.Cluster{
					{ClusterName: sp("clu-page1"), ClusterArn: sp("arn:aws:dax:us-east-1:111122223333:cache/clu-page1")},
				},
				NextToken: sp("tok-page2"),
			},
			{
				Clusters: []daxtypes.Cluster{
					{ClusterName: sp("clu-page2"), ClusterArn: sp("arn:aws:dax:us-east-1:111122223333:cache/clu-page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := DAXScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeClusters to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{
		"arn:aws:dax:us-east-1:111122223333:cache/clu-page1",
		"arn:aws:dax:us-east-1:111122223333:cache/clu-page2",
	} {
		if findDAXAsset(assets, want) == nil {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestDAXScanDescribeClustersErrorPropagates verifies the incompleteness
// decision: a DescribeClusters failure (denied/throttled) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestDAXScanDescribeClustersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform dax:DescribeClusters")
	client := &fakeDAXClient{err: sentinel}
	assets, err := DAXScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClusters failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a top-level list error, got %d", len(assets))
	}
}

// TestDAXScanPostureMapping locks the honesty posture for DAX's domain: at-rest
// encryption is opt-in and creation-time only, so an ENABLED SSEDescription maps
// to SymmetricOnly (AES-256, never NoEncryption), while an absent or DISABLED
// SSEDescription is a GENUINE NoEncryption finding carrying the
// cannot-encrypt-retroactively note — never a clean all-clear.
func TestDAXScanPostureMapping(t *testing.T) {
	client := &fakeDAXClient{
		pages: []*dax.DescribeClustersOutput{
			{
				Clusters: []daxtypes.Cluster{
					{
						ClusterName:    sp("clu-encrypted"),
						ClusterArn:     sp("arn:enc"),
						SSEDescription: &daxtypes.SSEDescription{Status: daxtypes.SSEStatusEnabled},
					},
					{
						ClusterName:    sp("clu-disabled"),
						ClusterArn:     sp("arn:dis"),
						SSEDescription: &daxtypes.SSEDescription{Status: daxtypes.SSEStatusDisabled},
					},
					{
						ClusterName: sp("clu-absent"),
						ClusterArn:  sp("arn:abs"),
						// SSEDescription nil -> genuine no-encryption
					},
				},
			},
		},
	}
	assets, err := DAXScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	enc := findDAXAsset(assets, "arn:enc")
	if enc == nil {
		t.Fatal("expected an asset for the ENABLED cluster")
	}
	if got := enc.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("ENABLED SSE: expected posture %q (AES-256), got %q", models.PostureSymmetricOnly, got)
	}
	if _, hasNote := enc.Properties["note"]; hasNote {
		t.Errorf("ENABLED SSE must not carry the no-encryption note")
	}
	if enc.Properties["sseStatus"] != "ENABLED" {
		t.Errorf("ENABLED SSE: expected sseStatus=ENABLED, got %q", enc.Properties["sseStatus"])
	}

	for _, id := range []string{"arn:dis", "arn:abs"} {
		a := findDAXAsset(assets, id)
		if a == nil {
			t.Fatalf("expected an asset for cluster %q", id)
		}
		if got := a.Properties["posture"]; got != string(models.PostureNoEncryption) {
			t.Errorf("cluster %q: opt-in SSE off must map to %q (genuine no-encryption), got %q", id, models.PostureNoEncryption, got)
		}
		if a.Properties["note"] == "" {
			t.Errorf("cluster %q: a no-encryption DAX cluster must carry the cannot-encrypt-retroactively note (no clean all-clear)", id)
		}
	}
}
