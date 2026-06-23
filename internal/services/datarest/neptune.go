package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// NeptuneScanner inspects Neptune DB clusters for at-rest encryption.
type NeptuneScanner struct{}

// Name returns the canonical service identifier.
func (NeptuneScanner) Name() string { return "neptune" }

// Category returns the primary CryptaMap category.
func (NeptuneScanner) Category() models.Category { return models.CategoryDataAtRest }

// neptuneDescribeClustersAPI is the minimal slice of the neptune client this
// scanner uses. DescribeDBClusters is Marker-paginated, so the scanner must loop;
// a single call returns only the first page, silently dropping clusters in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *neptune.Client satisfies it).
type neptuneDescribeClustersAPI interface {
	DescribeDBClusters(ctx context.Context, in *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
}

// Scan paginates DescribeDBClusters. Neptune shares the RDS-style API surface.
func (s NeptuneScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := neptune.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeDBClusters via Marker and
// classifies each cluster into a CryptoAsset. A DescribeDBClusters error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success.
//
// Neptune storage encryption is OPT-IN at cluster creation (StorageEncrypted), so
// an unset/false flag is a genuine NoEncryption — not a hidden default. When
// encryption IS on, the backing CMK (KmsKeyId) is recorded verbatim when present;
// an absent key on an encrypted cluster is the AWS-managed default and does NOT
// downgrade the SymmetricOnly posture.
func (s NeptuneScanner) scan(ctx context.Context, client neptuneDescribeClustersAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("neptune DescribeDBClusters: %w", err)
		}
		for _, c := range out.DBClusters {
			if c.DBClusterIdentifier == nil {
				continue
			}
			id := *c.DBClusterIdentifier
			encrypted := c.StorageEncrypted != nil && *c.StorageEncrypted
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if encrypted {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("neptune", models.CategoryDataAtRest, accountID, region, id, "AWS::Neptune::DBCluster", props)
			services.PostureProperty(&a, posture)
			// Record the backing CMK when the cluster is encrypted and a key is
			// present. An absent key on an encrypted cluster is the AWS-managed
			// default — recorded as such WITHOUT downgrading posture.
			if encrypted {
				if c.KmsKeyId != nil && *c.KmsKeyId != "" {
					a.Properties["kmsKeyId"] = *c.KmsKeyId
				} else {
					a.Properties["kmsKeyId"] = "AWS_MANAGED_KMS_KEY"
				}
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
