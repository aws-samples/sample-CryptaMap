package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// cloudFrontPosture maps a CloudFront distribution's MinimumProtocolVersion to a
// crypto posture for the viewer-connection KEY EXCHANGE channel.
//
// CloudFront's MinimumProtocolVersion is a negotiation FLOOR, not a ceiling: the
// supported-protocols matrix shows TLS 1.3 available under EVERY CloudFront
// security policy, so a TLS-1.3-capable client negotiates the quantum-resistant hybrid
// groups (X25519MLKEM768) opportunistically regardless of the floor. Classifying
// a low-floor policy (SSLv3 / TLSv1 / TLSv1_2016 / TLSv1.1_2016) as LegacyTLS on
// the floor alone was a FALSE-ALARM — those distributions DO offer TLS 1.3 + ML-
// KEM. The weak floor is still a real concern (a downgrade-capable client can fall
// back to legacy TLS), but that is surfaced as a separate warning on the floor
// field (see cloudFrontFloorWarning), not by denying the PQC-hybrid capability.
func cloudFrontPosture(minProtocolVersion string) models.CryptoPosture {
	if minProtocolVersion == "" {
		// Unknown/unreadable floor: be conservative, do not assert quantum-resistant.
		return models.PostureNonPQCClassical
	}
	// All CloudFront security policies allow TLS 1.3 negotiation, so the hybrid
	// ML-KEM groups are available opportunistically on every distribution.
	return models.PosturePQCHybrid
}

// cloudFrontFloorWarning returns a downgrade-fallback warning when the policy's
// floor permits legacy TLS (SSLv3 / 1.0 / 1.1), else "". The distribution still
// offers TLS 1.3 + ML-KEM (so posture stays PQCHybrid), but a downgrade-capable
// client can negotiate the legacy floor and bypass the post-quantum key exchange.
func cloudFrontFloorWarning(minProtocolVersion string) string {
	switch minProtocolVersion {
	case "SSLv3":
		return "minimum protocol version SSLv3 permits a legacy SSL/TLS downgrade; a downgrade-capable client can bypass the TLS 1.3 / ML-KEM key exchange"
	case "TLSv1", "TLSv1_2016":
		return "minimum protocol version permits a legacy TLS 1.0 downgrade; a downgrade-capable client can bypass the TLS 1.3 / ML-KEM key exchange"
	case "TLSv1.1_2016":
		return "minimum protocol version permits a legacy TLS 1.1 downgrade; a downgrade-capable client can bypass the TLS 1.3 / ML-KEM key exchange"
	default:
		return ""
	}
}

// cloudFrontFloor maps a CloudFront MinimumProtocolVersion (which IS the
// negotiation floor) to a TLS floor string. Returns "" for an unreadable floor
// or for SSLv3 (an SSL-only policy has no TLS floor to assert), so we never
// fabricate a floor AWS does not report.
func cloudFrontFloor(minProtocolVersion string) string {
	switch minProtocolVersion {
	case "TLSv1", "TLSv1_2016":
		return "1.0"
	case "TLSv1.1_2016":
		return "1.1"
	case "TLSv1.2_2018", "TLSv1.2_2019", "TLSv1.2_2021", "TLSv1.2_2025":
		return "1.2"
	case "TLSv1.3_2025":
		return "1.3"
	default: // "" (unreadable) and "SSLv3" -> no TLS floor asserted
		return ""
	}
}

// CloudFrontScanner emits one data-in-transit asset per distribution, with a
// posture derived from the distribution's MinimumProtocolVersion (see
// cloudFrontPosture) — NOT a hardcoded PosturePQCHybrid.
type CloudFrontScanner struct{}

func (CloudFrontScanner) Name() string              { return "cloudfront" }
func (CloudFrontScanner) Category() models.Category { return models.CategoryDataInTransit }

// cloudFrontAPI is the minimal slice of the cloudfront client this scanner uses.
// ListDistributions is Marker-paginated, so the scanner must loop; defining it as
// an interface keeps the pagination + classification logic unit-testable with a
// fake (the concrete *cloudfront.Client satisfies it).
type cloudFrontAPI interface {
	ListDistributions(ctx context.Context, in *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

func (s CloudFrontScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cloudfront.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	// CloudFront viewer certs in ACM are ALWAYS in us-east-1 (CloudFront only
	// supports us-east-1 ACM certs), so resolve there regardless of scan region.
	certResolver := newACMCertResolverInRegion(cfg, "us-east-1")
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates ListDistributions and, per
// distribution, classifies the viewer-connection posture from the minimum
// protocol version. A ListDistributions error is NOT swallowed — it is returned
// so the engine records this scanner as errored rather than a silent empty
// success.
func (s CloudFrontScanner) scan(ctx context.Context, client cloudFrontAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
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
			minVer := ""
			certARN := ""
			if d.ViewerCertificate != nil {
				minVer = string(d.ViewerCertificate.MinimumProtocolVersion)
				// Only an ACM-sourced viewer cert is resolvable; the default
				// CloudFront cert (*.cloudfront.net) and IAM-uploaded certs are not.
				if d.ViewerCertificate.ACMCertificateArn != nil {
					certARN = *d.ViewerCertificate.ACMCertificateArn
				}
			}
			posture := cloudFrontPosture(minVer)
			// Highest negotiable version is TLS 1.3 wherever a floor is known (all
			// policies allow TLS 1.3); only an unreadable floor leaves it unasserted.
			tlsVer := "1.3"
			if minVer == "" {
				tlsVer = ""
			}
			props := services.TLSProtocolProps(tlsVer, minVer)
			if props.ProtocolProperties != nil {
				// MinimumProtocolVersion IS the negotiation floor (distinct from the
				// highest negotiable version). Empty for SSLv3/unreadable.
				props.ProtocolProperties.TLSMinVersion = cloudFrontFloor(minVer)
			}
			a := services.NewAsset("cloudfront", models.CategoryDataInTransit, accountID, region, *d.Id, "AWS::CloudFront::Distribution", props)
			services.PostureProperty(&a, posture)
			a.Properties["minimumProtocolVersion"] = minVer
			if w := cloudFrontFloorWarning(minVer); w != "" {
				a.Properties["warning"] = w
			}
			if certARN != "" {
				a.Properties["certificateArn"] = certARN
				resolveACMCert(ctx, certResolver, certARN, &a)
			}
			assets = append(assets, a)
		}
		if out.DistributionList.NextMarker == nil || *out.DistributionList.NextMarker == "" {
			break
		}
		marker = out.DistributionList.NextMarker
	}
	return assets, nil
}
