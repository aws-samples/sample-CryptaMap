package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// MemoryDBScanner inspects MemoryDB clusters for at-rest encryption.
//
// MemoryDB at-rest encryption is always enabled and cannot be disabled; it
// protects persistent data with AES-256 (universal AWS-doc guarantee, doc-fact
// "datarest/memorydb/at-rest-aes256"). KmsKeyId selects the key tier only: a
// customer-managed CMK when present, the AWS-owned default key when absent. So
// posture is unconditionally SymmetricOnly and a missing KmsKeyId is the AWS-owned
// default key — never no-encryption.
type MemoryDBScanner struct{}

// Name returns the canonical service identifier.
func (MemoryDBScanner) Name() string { return "memorydb" }

// Category returns the primary CryptaMap category.
func (MemoryDBScanner) Category() models.Category { return models.CategoryDataAtRest }

// memorydbDescribeAPI is the minimal slice of the memorydb client this scanner
// uses. DescribeClusters is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping clusters in dense
// accounts. Defining it as an interface keeps the pagination + error-propagation
// logic unit-testable with a fake (the concrete *memorydb.Client satisfies it).
type memorydbDescribeAPI interface {
	DescribeClusters(ctx context.Context, in *memorydb.DescribeClustersInput, optFns ...func(*memorydb.Options)) (*memorydb.DescribeClustersOutput, error)
}

// Scan paginates DescribeClusters.
func (s MemoryDBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := memorydb.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeClusters and classifies
// each cluster into a CryptoAsset. A DescribeClusters error is NOT swallowed —
// it is returned so the engine records this scanner as errored (which surfaces
// in coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s MemoryDBScanner) scan(ctx context.Context, client memorydbDescribeAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeClusters(ctx, &memorydb.DescribeClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("memorydb DescribeClusters: %w", err)
		}
		for _, c := range out.Clusters {
			if c.Name == nil {
				continue
			}
			name := *c.Name
			// At-rest encryption is always on for every MemoryDB cluster (cannot be
			// disabled), so posture is unconditionally SymmetricOnly. KmsKeyId selects
			// the key tier only: a customer-managed CMK when present, else the AWS-owned
			// default key.
			kmsKey := "AWS_OWNED_KMS_KEY"
			if c.KmsKeyId != nil && *c.KmsKeyId != "" {
				kmsKey = *c.KmsKeyId
			}
			a := services.NewAsset("memorydb", models.CategoryDataAtRest, accountID, region, name, "AWS::MemoryDB::Cluster", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/memorydb/at-rest-aes256")
			a.Properties["kmsKeyId"] = kmsKey
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
