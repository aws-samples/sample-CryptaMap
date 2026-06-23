package transit

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type RedshiftTransitScanner struct{}

func (RedshiftTransitScanner) Name() string              { return "redshift_transit" }
func (RedshiftTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// redshiftDescribeClustersAPI is the minimal slice of the redshift client this
// scanner uses. DescribeClusters is Marker-paginated, so the scanner must loop;
// a single call returns only the first page, silently dropping clusters in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *redshift.Client
// satisfies it).
type redshiftDescribeClustersAPI interface {
	DescribeClusters(ctx context.Context, in *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
}

func (s RedshiftTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := redshift.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates DescribeClusters via Marker and
// classifies each cluster into a CryptoAsset. A DescribeClusters error is NOT
// swallowed — it is returned so the engine records this scanner as errored
// (which surfaces in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s RedshiftTransitScanner) scan(ctx context.Context, client redshiftDescribeClustersAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeClusters(ctx, &redshift.DescribeClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("redshift_transit DescribeClusters: %w", err)
		}
		for _, c := range out.Clusters {
			if c.ClusterIdentifier == nil {
				continue
			}
			// Redshift exposes NO default per-cluster server-cert identifier and
			// no API returns the negotiated TLS version, so we do not fabricate a
			// "1.2"/"redshift-tls" observation — the version is left unknown. The
			// only server-cert data available is the CUSTOM-domain cert (ARN +
			// expiry), present only when a custom domain is configured; read it
			// when present.
			props := services.TLSProtocolPropsDetailed("", "redshift-tls", "", "", 0, false)
			a := services.NewAsset("redshift_transit", models.CategoryDataInTransit, accountID, region, *c.ClusterIdentifier, "AWS::Redshift::Cluster", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			if c.CustomDomainName != nil && *c.CustomDomainName != "" {
				a.Properties["customDomainName"] = *c.CustomDomainName
			}
			if c.CustomDomainCertificateArn != nil && *c.CustomDomainCertificateArn != "" {
				a.Properties["customDomainCertificateArn"] = *c.CustomDomainCertificateArn
				services.StampObserved(&a, "high")
				// Resolve the custom-domain ACM cert for signature algorithm + key size.
				resolveACMCert(ctx, certResolver, *c.CustomDomainCertificateArn, &a)
			}
			if c.CustomDomainCertificateExpiryDate != nil {
				a.Properties["customDomainCertificateExpiry"] = c.CustomDomainCertificateExpiryDate.UTC().Format(time.RFC3339)
			}
			assets = append(assets, a)
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return assets, nil
}
