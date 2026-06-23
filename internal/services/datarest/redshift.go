package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// RedshiftScanner inspects Redshift clusters for at-rest encryption.
type RedshiftScanner struct{}

// Name returns the canonical service identifier.
func (RedshiftScanner) Name() string { return "redshift" }

// Category returns the primary CryptaMap category.
func (RedshiftScanner) Category() models.Category { return models.CategoryDataAtRest }

// redshiftClustersAPI is the minimal slice of the redshift client this scanner
// uses. DescribeClusters is Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping clusters in dense accounts.
// Defining it as an interface keeps the pagination + error-propagation logic
// unit-testable with a fake (the concrete *redshift.Client satisfies it).
type redshiftClustersAPI interface {
	DescribeClusters(ctx context.Context, in *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
}

// Scan paginates DescribeClusters.
func (s RedshiftScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := redshift.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeClusters and classifies each
// cluster's at-rest encryption. A DescribeClusters error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s RedshiftScanner) scan(ctx context.Context, client redshiftClustersAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeClusters(ctx, &redshift.DescribeClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("redshift DescribeClusters: %w", err)
		}
		for _, c := range out.Clusters {
			if c.ClusterIdentifier == nil {
				continue
			}
			id := *c.ClusterIdentifier
			encrypted := c.Encrypted != nil && *c.Encrypted
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if encrypted {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("redshift", models.CategoryDataAtRest, accountID, region, id, "AWS::Redshift::Cluster", props)
			services.PostureProperty(&a, posture)
			// KmsKeyId is populated only for encrypted clusters, so the non-nil
			// guard naturally scopes it to the encrypted case. From the existing
			// DescribeClusters response — no extra API call.
			if c.KmsKeyId != nil {
				a.Properties["kmsKeyId"] = *c.KmsKeyId
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
