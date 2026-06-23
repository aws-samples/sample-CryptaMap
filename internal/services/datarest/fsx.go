package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// FSxScanner inspects FSx file systems for at-rest encryption.
//
// FSx encrypts every file system at rest with AES-256-XTS automatically and it
// cannot be turned off (universal AWS-doc guarantee, doc-fact
// "datarest/fsx/at-rest-aes256-xts"). A scratch FSx for Lustre file system reports
// no KmsKeyId because it is encrypted with keys Amazon FSx manages; persistent
// systems expose the KMS key. Either way the data is encrypted, so posture is
// unconditionally SymmetricOnly and a missing KmsKeyId is the FSx-managed key —
// never no-encryption.
type FSxScanner struct{}

// Name returns the canonical service identifier.
func (FSxScanner) Name() string { return "fsx" }

// Category returns the primary CryptaMap category.
func (FSxScanner) Category() models.Category { return models.CategoryDataAtRest }

// fsxAPI is the minimal slice of the fsx client this scanner uses.
// DescribeFileSystems is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping file systems in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *fsx.Client satisfies it).
type fsxAPI interface {
	DescribeFileSystems(ctx context.Context, in *fsx.DescribeFileSystemsInput, optFns ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error)
}

// Scan paginates DescribeFileSystems.
func (s FSxScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := fsx.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeFileSystems and classifies
// each file system into a CryptoAsset. A DescribeFileSystems error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success.
func (s FSxScanner) scan(ctx context.Context, client fsxAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("fsx DescribeFileSystems: %w", err)
		}
		for _, fsd := range out.FileSystems {
			if fsd.FileSystemId == nil {
				continue
			}
			id := *fsd.FileSystemId
			// Every FSx file system is AES-256-XTS encrypted at rest (cannot be
			// disabled), so posture is unconditionally SymmetricOnly. KmsKeyId selects
			// the key tier only: the customer/AWS-managed CMK when present, else the
			// Amazon-FSx-managed (AWS-owned) key (e.g. scratch Lustre).
			kmsKey := "AWS_OWNED_KMS_KEY"
			if fsd.KmsKeyId != nil && *fsd.KmsKeyId != "" {
				kmsKey = *fsd.KmsKeyId
			}
			a := services.NewAsset("fsx", models.CategoryDataAtRest, accountID, region, id, "AWS::FSx::FileSystem", services.AESXTSAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/fsx/at-rest-aes256-xts")
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
