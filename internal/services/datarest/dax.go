package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// DAXScanner inspects DynamoDB Accelerator (DAX) clusters for at-rest encryption.
//
// IMPORTANT (opt-in, set only at creation): unlike DynamoDB tables, DAX at-rest
// encryption is NOT always-on — it can only be enabled at cluster creation and a
// cluster created without it cannot be encrypted later. So a cluster whose
// SSEDescription is absent/DISABLED is a GENUINE no-encryption finding, never a
// false all-clear. When enabled it is symmetric AES-256 -> SymmetricOnly. The
// in-transit endpoint-encryption type (NONE/TLS) is recorded as evidence.
type DAXScanner struct{}

// Name returns the canonical service identifier.
func (DAXScanner) Name() string { return "dax" }

// Category returns the primary CryptaMap category.
func (DAXScanner) Category() models.Category { return models.CategoryDataAtRest }

// daxAPI is the minimal slice of the dax client this scanner uses.
// DescribeClusters is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping clusters in dense
// accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *dax.Client
// satisfies it).
type daxAPI interface {
	DescribeClusters(ctx context.Context, in *dax.DescribeClustersInput, optFns ...func(*dax.Options)) (*dax.DescribeClustersOutput, error)
}

// Scan paginates DescribeClusters (which returns full Cluster objects inline).
func (s DAXScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := dax.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeClusters and classifies
// each cluster into a CryptoAsset. A DescribeClusters error is NOT swallowed —
// it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s DAXScanner) scan(ctx context.Context, client daxAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeClusters(ctx, &dax.DescribeClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("dax DescribeClusters: %w", err)
		}
		for _, c := range out.Clusters {
			name := ""
			if c.ClusterName != nil {
				name = *c.ClusterName
			}
			id := name
			if c.ClusterArn != nil && *c.ClusterArn != "" {
				id = *c.ClusterArn
			}

			// At-rest posture from SSEDescription.Status (opt-in, creation-time only).
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			sseStatus := ""
			if c.SSEDescription != nil {
				sseStatus = string(c.SSEDescription.Status)
				if c.SSEDescription.Status == daxtypes.SSEStatusEnabled {
					posture = models.PostureSymmetricOnly
					props = services.AESAtRest()
				}
			}

			a := services.NewAsset("dax", models.CategoryDataAtRest, accountID, region, id, "AWS::DAX::Cluster", props)
			services.PostureProperty(&a, posture)
			if sseStatus != "" {
				a.Properties["sseStatus"] = sseStatus
			}
			if c.ClusterEndpointEncryptionType != "" {
				a.Properties["endpointEncryptionType"] = string(c.ClusterEndpointEncryptionType)
			}
			if posture == models.PostureNoEncryption {
				a.Properties["note"] = "DAX at-rest encryption is opt-in and set only at cluster creation; this cluster is not encrypted at rest and cannot be encrypted retroactively."
			}
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
