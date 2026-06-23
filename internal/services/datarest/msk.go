package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// MSKScanner inspects MSK clusters for at-rest encryption KMS configuration.
type MSKScanner struct{}

// Name returns the canonical service identifier.
func (MSKScanner) Name() string { return "msk" }

// Category returns the primary CryptaMap category.
func (MSKScanner) Category() models.Category { return models.CategoryDataAtRest }

// The UNIVERSAL guarantee that MSK always encrypts at rest (provisioned AND
// serverless) is the doc-fact "datarest/msk/at-rest-aes256" (internal/pqc
// knowledge); stamped via services.StampDocFactKeyed below.

// mskAPI is the minimal slice of the kafka client this scanner uses.
// ListClustersV2 is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping clusters in dense
// accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *kafka.Client
// satisfies it).
type mskAPI interface {
	ListClustersV2(ctx context.Context, in *kafka.ListClustersV2Input, optFns ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error)
}

// Scan paginates ListClustersV2.
//
// MSK always encrypts data at rest (a universal AWS-doc guarantee that holds
// for both provisioned and serverless clusters), so every cluster is
// SymmetricOnly with that fact stamped as an aws-doc source. Provisioned
// clusters expose the data-volume KMS key via Provisioned.EncryptionInfo;
// serverless clusters expose no EncryptionInfo field at all, so we leave the
// key id unset (the doc says MSK uses an AWS-managed key on your behalf).
func (s MSKScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kafka.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListClustersV2 and classifies each
// cluster. A ListClustersV2 error is NOT swallowed — it is returned so the
// engine records this scanner as errored (which surfaces in coverage), keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success. accountID is passed in so the core needs no STS.
func (s MSKScanner) scan(ctx context.Context, client mskAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListClustersV2(ctx, &kafka.ListClustersV2Input{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("msk ListClustersV2: %w", err)
		}
		for _, c := range out.ClusterInfoList {
			if c.ClusterName == nil {
				continue
			}
			name := *c.ClusterName
			posture := models.PostureSymmetricOnly
			props := services.AESAtRest()
			var kmsKey string
			if c.Provisioned != nil && c.Provisioned.EncryptionInfo != nil &&
				c.Provisioned.EncryptionInfo.EncryptionAtRest != nil &&
				c.Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId != nil {
				kmsKey = *c.Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId
			}
			a := services.NewAsset("msk", models.CategoryDataAtRest, accountID, region, name, "AWS::MSK::Cluster", props)
			services.PostureProperty(&a, posture)
			// The "always encrypts at rest" classification rests on the AWS-doc
			// universal guarantee, not a per-resource observation — stamp it so
			// the basis is auditable rather than presented as verified.
			services.StampDocFactKeyed(&a, "datarest/msk/at-rest-aes256")
			if kmsKey != "" {
				a.Properties["kmsKeyId"] = kmsKey
			}
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
