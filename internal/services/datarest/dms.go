package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// DMSScanner inspects DMS replication instances for KMS encryption.
type DMSScanner struct{}

// Name returns the canonical service identifier.
func (DMSScanner) Name() string { return "dms" }

// Category returns the primary CryptaMap category.
func (DMSScanner) Category() models.Category { return models.CategoryDataAtRest }

// dmsAPI is the minimal slice of the databasemigrationservice client this
// scanner uses. DescribeReplicationInstances is Marker-paginated, so the scanner
// must loop; a single call returns only the first page, silently dropping
// instances in accounts with many replication instances. Defining it as an
// interface keeps the pagination + error-propagation logic unit-testable with a
// fake (the concrete *databasemigrationservice.Client satisfies it).
type dmsAPI interface {
	DescribeReplicationInstances(ctx context.Context, in *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error)
}

// Scan paginates DescribeReplicationInstances.
func (s DMSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := databasemigrationservice.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeReplicationInstances and
// classifies each instance into a CryptoAsset. A DescribeReplicationInstances
// error is NOT swallowed — it is returned so the engine records this scanner as
// errored, keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s DMSScanner) scan(ctx context.Context, client dmsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("dms DescribeReplicationInstances: %w", err)
		}
		for _, ri := range out.ReplicationInstances {
			if ri.ReplicationInstanceIdentifier == nil {
				continue
			}
			id := *ri.ReplicationInstanceIdentifier
			// DMS always encrypts replication-instance storage at rest (cannot be
			// disabled), so posture is unconditionally SymmetricOnly. KmsKeyId selects
			// the key tier only: a customer/aws/dms CMK when present, else the aws/dms
			// default key.
			kmsKey := "AWS_OWNED_KMS_KEY"
			if ri.KmsKeyId != nil && *ri.KmsKeyId != "" {
				kmsKey = *ri.KmsKeyId
			}
			a := services.NewAsset("dms", models.CategoryDataAtRest, accountID, region, id, "AWS::DMS::ReplicationInstance", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/dms/at-rest-aes256")
			a.Properties["kmsKeyId"] = kmsKey
			assets = append(assets, a)
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return assets, nil
}
