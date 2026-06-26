package certmgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeCloudfrontCertsClient is a hand-rolled cloudfrontCertsAPI for unit-testing
// the scanner's pagination + error propagation without a live AWS client.
// cloudfrontcertsPages is returned page-by-page (each call consumes the next
// page) and the NextMarker is wired so the scanner loops through every page;
// cloudfrontcertsErr forces a ListDistributions failure.
type fakeCloudfrontCertsClient struct {
	cloudfrontcertsPages []*cloudfront.ListDistributionsOutput
	cloudfrontcertsCalls int
	cloudfrontcertsErr   error
}

func (f *fakeCloudfrontCertsClient) ListDistributions(ctx context.Context, in *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if f.cloudfrontcertsErr != nil {
		return nil, f.cloudfrontcertsErr
	}
	if f.cloudfrontcertsCalls >= len(f.cloudfrontcertsPages) {
		return &cloudfront.ListDistributionsOutput{}, nil
	}
	out := f.cloudfrontcertsPages[f.cloudfrontcertsCalls]
	f.cloudfrontcertsCalls++
	return out, nil
}

func cloudfrontcertsStrptr(s string) *string { return &s }

// cloudfrontcertsAssetByID indexes assets by ResourceID for assertions.
func cloudfrontcertsAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

func cloudfrontcertsPostureOf(a models.CryptoAsset) string {
	if a.Properties == nil {
		return ""
	}
	return a.Properties["posture"]
}

// TestCloudFrontCertsScanPaginates verifies the ListDistributions Marker loop: a
// fake that returns 2 pages (NextMarker on page 1) must yield BOTH pages'
// distributions as assets. Without the pagination loop, only the first page's
// distribution survives.
func TestCloudFrontCertsScanPaginates(t *testing.T) {
	client := &fakeCloudfrontCertsClient{
		cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cloudfronttypes.DistributionList{
					Items: []cloudfronttypes.DistributionSummary{
						{
							Id:         cloudfrontcertsStrptr("dist-page1"),
							DomainName: cloudfrontcertsStrptr("d1.cloudfront.net"),
							ViewerCertificate: &cloudfronttypes.ViewerCertificate{
								ACMCertificateArn: cloudfrontcertsStrptr("arn:aws:acm:us-east-1:111122223333:certificate/abc"),
							},
						},
					},
					NextMarker: cloudfrontcertsStrptr("marker-page2"),
				},
			},
			{
				DistributionList: &cloudfronttypes.DistributionList{
					Items: []cloudfronttypes.DistributionSummary{
						{
							Id:         cloudfrontcertsStrptr("dist-page2"),
							DomainName: cloudfrontcertsStrptr("d2.cloudfront.net"),
							ViewerCertificate: &cloudfronttypes.ViewerCertificate{
								IAMCertificateId: cloudfrontcertsStrptr("IAMCERT123"),
							},
						},
					},
					// no NextMarker -> last page
				},
			},
		},
	}
	assets, err := CloudFrontCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.cloudfrontcertsCalls; c != 2 {
		t.Errorf("expected ListDistributions to be called 2 times (paginated), got %d", c)
	}
	by := cloudfrontcertsAssetByID(assets)
	for _, want := range []string{"dist-page1", "dist-page2"} {
		if _, ok := by[want]; !ok {
			t.Errorf("expected distribution %q from a paginated page to appear as an asset; got %v", want, assets)
		}
	}
}

// TestCloudFrontCertsScanErrorPropagates verifies the owner's incompleteness
// decision: a ListDistributions failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestCloudFrontCertsScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform cloudfront:ListDistributions")
	client := &fakeCloudfrontCertsClient{
		cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
			{DistributionList: &cloudfronttypes.DistributionList{
				Items: []cloudfronttypes.DistributionSummary{
					{Id: cloudfrontcertsStrptr("dist-1"), DomainName: cloudfrontcertsStrptr("d1.cloudfront.net")},
				},
			}},
		},
		cloudfrontcertsErr: sentinel,
	}
	_, err := CloudFrontCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListDistributions fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListDistributions failure, got: %v", err)
	}
}

// TestCloudFrontCertsHonestyPosture pins the certificate-domain honesty posture:
// a CloudFront viewer certificate is RSA/ECDSA authentication — classical,
// Shor-broken — and ML-DSA PQC certs are NOT offered for CloudFront. The asset's
// posture MUST therefore be non-pqc-classical, never pqc-hybrid/pqc-ready
// (a false-safe that would mark classical auth as quantum-resistant / no-action) and
// never no-encryption (the cert exists, so encryption is present). This holds
// even when there is NO viewer certificate ARN, because CloudFront always serves
// the distribution over TLS with a (default) classical cert.
func TestCloudFrontCertsHonestyPosture(t *testing.T) {
	client := &fakeCloudfrontCertsClient{
		cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
			{DistributionList: &cloudfronttypes.DistributionList{
				Items: []cloudfronttypes.DistributionSummary{
					{
						Id:         cloudfrontcertsStrptr("dist-acm"),
						DomainName: cloudfrontcertsStrptr("acm.cloudfront.net"),
						ViewerCertificate: &cloudfronttypes.ViewerCertificate{
							ACMCertificateArn: cloudfrontcertsStrptr("arn:aws:acm:us-east-1:111122223333:certificate/xyz"),
						},
					},
					{
						// No viewer certificate block at all (default CloudFront cert).
						Id:         cloudfrontcertsStrptr("dist-default"),
						DomainName: cloudfrontcertsStrptr("default.cloudfront.net"),
					},
				},
			}},
		},
	}
	assets, err := CloudFrontCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	by := cloudfrontcertsAssetByID(assets)
	for _, id := range []string{"dist-acm", "dist-default"} {
		a, ok := by[id]
		if !ok {
			t.Fatalf("expected asset %q to be present", id)
		}
		posture := cloudfrontcertsPostureOf(a)
		if posture != string(models.PostureNonPQCClassical) {
			t.Errorf("asset %q: expected posture %q (classical cert is Shor-broken, not quantum-resistant), got %q",
				id, models.PostureNonPQCClassical, posture)
		}
		if posture == string(models.PostureNoEncryption) {
			t.Errorf("asset %q: a viewer certificate is an encryption channel — must NOT be classified no-encryption", id)
		}
		if posture == string(models.PosturePQCHybrid) || posture == string(models.PosturePQCReady) {
			t.Errorf("asset %q: false-safe — classical RSA/ECDSA cert must NOT be marked quantum-resistant (%q)", id, posture)
		}
	}
	// The ACM-backed asset must also carry its cert reference (no silent drop of
	// the binding that downstream key-size resolution depends on).
	if ref := by["dist-acm"].Properties["certificateRef"]; ref == "" {
		t.Errorf("expected dist-acm to record its certificateRef, got empty")
	}
}
