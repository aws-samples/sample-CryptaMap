package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRedshiftTransitClient is a hand-rolled redshiftDescribeClustersAPI for
// unit-testing the scanner's pagination + error propagation without a live AWS
// client. pages is returned page-by-page (each call consumes the next page) and
// the Marker is wired so the scanner loops through every page; err forces a
// DescribeClusters failure on the first call.
type fakeRedshiftTransitClient struct {
	pages []*redshift.DescribeClustersOutput
	calls int
	err   error
}

func (f *fakeRedshiftTransitClient) DescribeClusters(ctx context.Context, in *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &redshift.DescribeClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func redshifttransitStrptr(s string) *string { return &s }

// redshifttransitAssetByID indexes the returned assets by ResourceID.
func redshifttransitAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestRedshiftTransitScanPaginates verifies the DescribeClusters Marker loop: a
// fake that returns 2 pages (Marker on page 1) must yield BOTH pages' clusters
// as assets. Without the pagination restore, only the first page's cluster
// survives.
func TestRedshiftTransitScanPaginates(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{
				Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("cluster-page1")}},
				Marker:   redshifttransitStrptr("marker-page2"),
			},
			{
				Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("cluster-page2")}},
				// no Marker -> last page
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected DescribeClusters to be called 2 times (paginated), got %d", c)
	}
	got := redshifttransitAssetByID(assets)
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; got=%v", want, keysOfRedshiftTransit(got))
		}
	}
}

func keysOfRedshiftTransit(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRedshiftTransitScanErrorPropagates verifies the owner's incompleteness
// decision: a DescribeClusters failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestRedshiftTransitScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform redshift:DescribeClusters")
	client := &fakeRedshiftTransitClient{err: sentinel}
	resolver := newACMCertResolver(aws.Config{})
	_, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClusters failure, got: %v", err)
	}
}

// TestRedshiftTransitScanHonestyPosture verifies the scanner's honesty posture
// for the transit domain. Redshift always runs TLS-capable endpoints over an
// always-encrypted classical channel: every cluster MUST be classified
// non-pqc-classical and MUST NEVER be marked no-encryption. The scanner also
// must NOT fabricate an observed TLS version — the version field stays blank
// since no Redshift API returns the negotiated TLS version.
func TestRedshiftTransitScanHonestyPosture(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("plain-cluster")}}},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := redshifttransitAssetByID(assets)
	a, ok := got["plain-cluster"]
	if !ok {
		t.Fatalf("expected asset for plain-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if p := a.Properties["posture"]; p != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (always-encrypted classical transit), got %q", models.PostureNonPQCClassical, p)
	}
	if p := a.Properties["posture"]; p == string(models.PostureNoEncryption) {
		t.Errorf("redshift transit must NEVER be classified no-encryption; got %q", p)
	}
	if a.ResourceType != "AWS::Redshift::Cluster" {
		t.Errorf("expected resourceType AWS::Redshift::Cluster, got %q", a.ResourceType)
	}
	// No fabricated TLS version: the scanner leaves the version blank because no
	// Redshift API returns the negotiated TLS version.
	if pp := a.CryptoProps.ProtocolProperties; pp != nil && pp.Version != "" {
		t.Errorf("expected blank TLS version (not fabricated), got %q", pp.Version)
	}
}

// TestRedshiftTransitScanCustomDomainCert verifies that a custom-domain cert ARN
// is recorded and the asset is stamped observed (the only server-cert datum
// Redshift exposes), while a cluster WITHOUT a custom domain carries no
// fabricated cert ARN.
func TestRedshiftTransitScanCustomDomainCert(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{Clusters: []redshifttypes.Cluster{
				{
					ClusterIdentifier:          redshifttransitStrptr("custom-domain-cluster"),
					CustomDomainName:           redshifttransitStrptr("redshift.example.com"),
					CustomDomainCertificateArn: redshifttransitStrptr("arn:aws:acm:us-east-1:111122223333:certificate/abc"),
				},
				{ClusterIdentifier: redshifttransitStrptr("no-domain-cluster")},
			}},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := redshifttransitAssetByID(assets)

	cd, ok := got["custom-domain-cluster"]
	if !ok {
		t.Fatalf("expected asset for custom-domain-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if cd.Properties["customDomainName"] != "redshift.example.com" {
		t.Errorf("expected customDomainName recorded, got %q", cd.Properties["customDomainName"])
	}
	if cd.Properties["customDomainCertificateArn"] != "arn:aws:acm:us-east-1:111122223333:certificate/abc" {
		t.Errorf("expected customDomainCertificateArn recorded, got %q", cd.Properties["customDomainCertificateArn"])
	}

	nd, ok := got["no-domain-cluster"]
	if !ok {
		t.Fatalf("expected asset for no-domain-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if _, present := nd.Properties["customDomainCertificateArn"]; present {
		t.Errorf("expected NO customDomainCertificateArn for a cluster without a custom domain (no fabrication), got %q", nd.Properties["customDomainCertificateArn"])
	}
}
