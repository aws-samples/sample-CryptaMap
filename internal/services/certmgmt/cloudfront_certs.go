package certmgmt

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CloudFrontCertsScanner discovers TLS certificates referenced by CloudFront distributions.
type CloudFrontCertsScanner struct{}

// Name returns the canonical scanner identifier.
func (CloudFrontCertsScanner) Name() string { return "cloudfront_certs" }

// Category returns the primary category for this scanner.
func (CloudFrontCertsScanner) Category() models.Category { return models.CategoryCertificate }

// cloudfrontCertsAPI is the minimal slice of the cloudfront client this scanner
// uses. ListDistributions is Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping distributions in accounts
// with many of them. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *cloudfront.Client
// satisfies it).
type cloudfrontCertsAPI interface {
	ListDistributions(ctx context.Context, in *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

// Scan lists CloudFront distributions and emits one asset per distribution that has a viewer certificate.
// Pagination via Marker; capped at 1000 items.
func (s CloudFrontCertsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cloudfront.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListDistributions via Marker and
// classifies each distribution's viewer certificate into a CryptoAsset. A
// ListDistributions error is NOT swallowed — it is returned so the engine records
// this scanner as errored (which surfaces in coverage), keeping a denied/throttled
// scan VISIBLY incomplete rather than a clean-looking empty success.
func (s CloudFrontCertsScanner) scan(ctx context.Context, client cloudfrontCertsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("cloudfront ListDistributions: %w", err)
		}
		if out.DistributionList == nil {
			break
		}
		for _, d := range out.DistributionList.Items {
			if d.Id == nil {
				continue
			}
			certRef := ""
			if d.ViewerCertificate != nil {
				if d.ViewerCertificate.ACMCertificateArn != nil && *d.ViewerCertificate.ACMCertificateArn != "" {
					certRef = *d.ViewerCertificate.ACMCertificateArn
				} else if d.ViewerCertificate.IAMCertificateId != nil && *d.ViewerCertificate.IAMCertificateId != "" {
					certRef = *d.ViewerCertificate.IAMCertificateId
				}
			}
			id := *d.Id
			subject := ""
			if d.DomainName != nil {
				subject = *d.DomainName
			}
			// certRef is the ACM ARN / IAM cert id of the viewer certificate — a
			// resource reference, NOT a signature algorithm. It must not go into
			// CertProps's signatureAlgorithmRef (a CycloneDX refType = bom-ref to an
			// algorithm component); it is preserved as the cryptamap:certificateRef
			// property below. The signature algorithm itself is not exposed by the
			// CloudFront API, so signatureAlgorithmRef is left empty (honest blank).
			props := services.CertProps(subject, "", "", time.Time{}, time.Time{})
			a := services.NewAsset("cloudfront_certs", models.CategoryCertificate, accountID, region, id, "AWS::CloudFront::Distribution", props)
			if certRef != "" {
				a.Properties["certificateRef"] = certRef
			}
			if d.ViewerCertificate != nil {
				a.Properties["minimumProtocolVersion"] = string(d.ViewerCertificate.MinimumProtocolVersion)
				a.Properties["sslSupportMethod"] = string(d.ViewerCertificate.SSLSupportMethod)
			}
			// This asset is the distribution's VIEWER CERTIFICATE (authentication),
			// not the key-exchange channel. CloudFront/ACM viewer certs are RSA or
			// ECDSA — classical, Shor-broken — and ML-DSA PQC certs are NOT offered
			// for CloudFront. So the cert's posture is non-pqc-classical. The genuine
			// hybrid ML-KEM *key exchange* capability lives on the transit
			// CloudFrontScanner asset, not here. (Hardcoding PosturePQCHybrid here was
			// a FALSE-SAFE: it marked classical RSA/ECDSA authentication as
			// quantum-safe / no-action.)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.DistributionList.NextMarker == nil || *out.DistributionList.NextMarker == "" {
			break
		}
		marker = out.DistributionList.NextMarker
	}
	return assets, nil
}
