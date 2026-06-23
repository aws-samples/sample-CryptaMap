package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EFSScanner inspects EFS file systems for at-rest encryption.
type EFSScanner struct{}

// Name returns the canonical service identifier.
func (EFSScanner) Name() string { return "efs" }

// Category returns the primary CryptaMap category.
func (EFSScanner) Category() models.Category { return models.CategoryDataAtRest }

// efsAPI is the minimal slice of the efs client this scanner uses.
// DescribeFileSystems is Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping file systems in dense
// accounts. Defining it as an interface keeps the pagination + error-propagation
// logic unit-testable with a fake (the concrete *efs.Client satisfies it).
type efsAPI interface {
	DescribeFileSystems(ctx context.Context, in *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
}

// Scan paginates DescribeFileSystems.
func (s EFSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := efs.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeFileSystems via Marker and
// classifies each file system. A DescribeFileSystems error is NOT swallowed — it
// is returned so the engine records this scanner as errored (surfaced in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s EFSScanner) scan(ctx context.Context, client efsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("efs DescribeFileSystems: %w", err)
		}
		for _, fsd := range out.FileSystems {
			if fsd.FileSystemId == nil {
				continue
			}
			id := *fsd.FileSystemId
			encrypted := fsd.Encrypted != nil && *fsd.Encrypted
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if encrypted {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("efs", models.CategoryDataAtRest, accountID, region, id, "AWS::EFS::FileSystem", props)
			services.PostureProperty(&a, posture)
			// Capture the CMK identity already returned by DescribeFileSystems so
			// a customer-managed CMK is distinguishable from the aws/elasticfilesystem
			// default. Empty when not encrypted; no extra API call.
			if fsd.KmsKeyId != nil && *fsd.KmsKeyId != "" {
				a.Properties["kmsKeyId"] = *fsd.KmsKeyId
			}
			assets = append(assets, a)
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
