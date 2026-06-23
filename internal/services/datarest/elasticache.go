package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ElastiCacheScanner inspects ElastiCache replication groups for at-rest encryption.
type ElastiCacheScanner struct{}

// Name returns the canonical service identifier.
func (ElastiCacheScanner) Name() string { return "elasticache" }

// Category returns the primary CryptaMap category.
func (ElastiCacheScanner) Category() models.Category { return models.CategoryDataAtRest }

// elasticacheAPI is the minimal slice of the elasticache client this scanner
// uses. DescribeReplicationGroups is Marker-paginated, so the scanner must loop;
// a single call returns only the first page, silently dropping replication
// groups in dense accounts. Defining it as an interface keeps the pagination +
// error propagation logic unit-testable with a fake (the concrete
// *elasticache.Client satisfies it).
type elasticacheAPI interface {
	DescribeReplicationGroups(ctx context.Context, in *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
}

// Scan paginates DescribeReplicationGroups.
func (s ElastiCacheScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := elasticache.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeReplicationGroups and
// classifies each into a CryptoAsset. A DescribeReplicationGroups error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success.
func (s ElastiCacheScanner) scan(ctx context.Context, client elasticacheAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("elasticache DescribeReplicationGroups: %w", err)
		}
		for _, g := range out.ReplicationGroups {
			if g.ReplicationGroupId == nil {
				continue
			}
			id := *g.ReplicationGroupId
			encrypted := g.AtRestEncryptionEnabled != nil && *g.AtRestEncryptionEnabled
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if encrypted {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("elasticache", models.CategoryDataAtRest, accountID, region, id, "AWS::ElastiCache::ReplicationGroup", props)
			services.PostureProperty(&a, posture)
			// ElastiCache only populates KmsKeyId when a customer-supplied CMK is
			// used; the AWS-managed default leaves it empty. Leave kmsKeyId unset
			// in that case rather than synthesizing a value. Already in the
			// DescribeReplicationGroups response — no extra API call.
			if g.KmsKeyId != nil && *g.KmsKeyId != "" {
				a.Properties["kmsKeyId"] = *g.KmsKeyId
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
