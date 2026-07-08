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
// crypto posture for the viewer-connection channel.
//
// HONESTY CONTRACT: the ONLY per-distribution fact this scanner reads is
// MinimumProtocolVersion — a negotiation FLOOR. Nothing in ListDistributions
// proves that TLS 1.3 was negotiated or that a hybrid ML-KEM group was ever
// selected, so this function must NEVER return PosturePQCHybrid: that posture
// maps to SeverityInformational and would suppress every PQC-migration finding
// on evidence we do not have. AWS documents that TLS 1.3 + ML-KEM is OFFERED
// under every CloudFront security policy — that documented capability is
// recorded as a doc-fact property on the asset (see scan), not as a posture.
//
//   - ""       -> PostureUnknown: the floor could not be read; assert nothing.
//   - SSLv3 / TLSv1 / TLSv1_2016 / TLSv1.1_2016 -> PostureLegacyTLS: the policy
//     PROVABLY permits legacy SSL/TLS negotiation, which is a real (non-
//     Informational) finding regardless of what stronger versions are also
//     offered.
//   - TLSv1.2_* / TLSv1.3_* -> PostureNonPQCClassical: a modern floor is
//     proven, but hybrid key exchange is not, so the distribution is
//     classical until a negotiated PQ group is actually observed.
func cloudFrontPosture(minProtocolVersion string) models.CryptoPosture {
	switch minProtocolVersion {
	case "":
		return models.PostureUnknown
	case "SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016":
		return models.PostureLegacyTLS
	default:
		// TLSv1.2_2018/2019/2021/2025 and TLSv1.3_2025: floor >= TLS 1.2 is
		// proven from the API-read policy; PQ-hybrid negotiation is not.
		return models.PostureNonPQCClassical
	}
}

// cloudFrontFloorWarning returns a legacy-floor warning when the policy's floor
// permits legacy SSL/TLS (SSLv3 / 1.0 / 1.1), else "". This supplements the
// PostureLegacyTLS classification with the concrete downgrade concern.
func cloudFrontFloorWarning(minProtocolVersion string) string {
	switch minProtocolVersion {
	case "SSLv3":
		return "minimum protocol version SSLv3 permits legacy SSL/TLS negotiation; clients can connect with protocols far below TLS 1.2"
	case "TLSv1", "TLSv1_2016":
		return "minimum protocol version permits TLS 1.0 negotiation; clients can connect below TLS 1.2"
	case "TLSv1.1_2016":
		return "minimum protocol version permits TLS 1.1 negotiation; clients can connect below TLS 1.2"
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
// cloudFrontPosture). It never asserts a negotiated TLS version or a PQ-hybrid
// posture from the floor alone.
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
			// Version is asserted ONLY when the floor proves it: a TLSv1.3_2025
			// floor permits nothing below TLS 1.3, so 1.3 is the only possible
			// version. Every other floor allows a range, and the negotiated
			// version is not observed — leave it unasserted.
			tlsVer := ""
			if minVer == "TLSv1.3_2025" {
				tlsVer = "1.3"
			}
			props := services.TLSProtocolProps(tlsVer, minVer)
			if props.ProtocolProperties != nil {
				// MinimumProtocolVersion IS the negotiation floor (distinct from the
				// highest negotiable version). Empty for SSLv3/unreadable.
				props.ProtocolProperties.TLSMinVersion = cloudFrontFloor(minVer)
			}
			// CloudFront is a GLOBAL service: ListDistributions returns the same
			// distributions from every region shard. Use the SDK's region-less
			// distribution ARN as the canonical dedup key so N region scans merge
			// into one asset instead of N duplicates (see NewAssetWithARN).
			arn := ""
			if d.ARN != nil {
				arn = *d.ARN
			} else {
				arn = fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", accountID, *d.Id)
			}
			a := services.NewAssetWithARN(arn, "cloudfront", models.CategoryDataInTransit, accountID, region, *d.Id, "AWS::CloudFront::Distribution", props)
			services.PostureProperty(&a, posture)
			a.Properties["minimumProtocolVersion"] = minVer
			// AWS documents that TLS 1.3 (and its hybrid ML-KEM groups) is offered
			// under every CloudFront security policy. Record that as a doc-fact
			// CAPABILITY only — negotiation is never observed here, so it must not
			// upgrade the posture to PQCHybrid.
			a.Properties["mlkemCapable"] = "true"
			a.Properties["mlkemCapableSource"] = "aws-doc"
			if minVer == "" {
				a.Properties["note"] = "ViewerCertificate.MinimumProtocolVersion could not be read from ListDistributions; the TLS floor and negotiated protocol version cannot be proven for this distribution."
			}
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
