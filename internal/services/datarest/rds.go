package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// RDSScanner inspects RDS DB instance storage encryption.
type RDSScanner struct{}

// Name returns the canonical service identifier.
func (RDSScanner) Name() string { return "rds" }

// Category returns the primary CryptaMap category.
func (RDSScanner) Category() models.Category { return models.CategoryDataAtRest }

// rdsAPI is the minimal slice of the rds client this scanner uses.
// DescribeDBInstances is Marker-paginated, so the scanner must loop; a single
// call returns only the first page (default ~100), silently dropping instances
// in dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *rds.Client
// satisfies it).
type rdsAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// Scan paginates DescribeDBInstances and emits one asset per instance.
func (s RDSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := rds.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeDBInstances and classifies
// each instance into a CryptoAsset. A DescribeDBInstances error is NOT swallowed
// — it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s RDSScanner) scan(ctx context.Context, client rdsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("rds DescribeDBInstances: %w", err)
		}
		for _, db := range out.DBInstances {
			if db.DBInstanceIdentifier == nil {
				continue
			}
			id := *db.DBInstanceIdentifier
			encrypted := db.StorageEncrypted != nil && *db.StorageEncrypted
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if encrypted {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("rds", models.CategoryDataAtRest, accountID, region, id, "AWS::RDS::DBInstance", props)
			services.PostureProperty(&a, posture)
			if db.KmsKeyId != nil {
				a.Properties["kmsKeyId"] = *db.KmsKeyId
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
