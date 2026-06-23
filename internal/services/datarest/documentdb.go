package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// DocumentDBScanner inspects DocumentDB clusters for at-rest encryption.
//
// SCOPE: this scanner uses DescribeDBClusters, which enumerates instance-based
// DocumentDB clusters only. DocumentDB ELASTIC clusters are a distinct resource
// served by a separate API (docdb-elastic: ListClusters / GetCluster) and are
// covered by their own registered scanner (DocumentDBElasticScanner, see
// documentdb_elastic.go), which emits AWS::DocDBElastic::Cluster assets. The two
// scanners partition the surface cleanly, so neither misses nor double-counts a
// cluster.
type DocumentDBScanner struct{}

// Name returns the canonical service identifier.
func (DocumentDBScanner) Name() string { return "documentdb" }

// Category returns the primary CryptaMap category.
func (DocumentDBScanner) Category() models.Category { return models.CategoryDataAtRest }

// docdbDescribeClustersAPI is the minimal slice of the docdb client this scanner
// uses. DescribeDBClusters is Marker-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping clusters in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *docdb.Client satisfies it).
type docdbDescribeClustersAPI interface {
	DescribeDBClusters(ctx context.Context, in *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
}

// Scan paginates DescribeDBClusters.
func (s DocumentDBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := docdb.NewFromConfig(cfg)
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
// DocumentDB (instance-based) storage encryption is OPT-IN at cluster creation
// (StorageEncrypted), so an unset/false flag is a genuine NoEncryption — not a
// hidden default. When encryption IS on, the backing CMK (KmsKeyId) is recorded
// verbatim when present; an absent key on an encrypted cluster is the AWS-managed
// default and does NOT downgrade the SymmetricOnly posture.
func (s DocumentDBScanner) scan(ctx context.Context, client docdbDescribeClustersAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("documentdb DescribeDBClusters: %w", err)
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
			a := services.NewAsset("documentdb", models.CategoryDataAtRest, accountID, region, id, "AWS::DocDB::DBCluster", props)
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
