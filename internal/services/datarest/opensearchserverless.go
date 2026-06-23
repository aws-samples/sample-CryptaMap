package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// OpenSearchServerlessScanner inspects OpenSearch Serverless collections for
// at-rest encryption. Distinct from the provisioned-domain opensearch scanner.
//
// Every collection is encrypted at rest with AES-256 via KMS (an encryption
// policy is required at creation), so posture is unconditionally SymmetricOnly;
// an absent KmsKeyArn means the AWS-owned default key, not no-encryption.
type OpenSearchServerlessScanner struct{}

// Name returns the canonical service identifier.
func (OpenSearchServerlessScanner) Name() string { return "opensearch_serverless" }

// Category returns the primary CryptaMap category.
func (OpenSearchServerlessScanner) Category() models.Category { return models.CategoryDataAtRest }

// ossCollectionsAPI is the minimal slice of the opensearchserverless client this
// scanner uses. ListCollections is NextToken-paginated, so the scanner must loop;
// a single call returns only the first page, silently dropping collections in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete
// *opensearchserverless.Client satisfies it).
type ossCollectionsAPI interface {
	ListCollections(ctx context.Context, in *opensearchserverless.ListCollectionsInput, optFns ...func(*opensearchserverless.Options)) (*opensearchserverless.ListCollectionsOutput, error)
}

// Scan paginates ListCollections (KmsKeyArn is on the summary, no detail call).
func (s OpenSearchServerlessScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := opensearchserverless.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListCollections and classifies each
// collection into a CryptoAsset. A ListCollections error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s OpenSearchServerlessScanner) scan(ctx context.Context, client ossCollectionsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListCollections(ctx, &opensearchserverless.ListCollectionsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("opensearch_serverless ListCollections: %w", err)
		}
		for _, c := range out.CollectionSummaries {
			name := ""
			if c.Name != nil {
				name = *c.Name
			}
			id := name
			if c.Arn != nil && *c.Arn != "" {
				id = *c.Arn
			} else if c.Id != nil {
				id = *c.Id
			}
			kmsKey := "AWS_OWNED_KMS_KEY"
			if c.KmsKeyArn != nil && *c.KmsKeyArn != "" {
				kmsKey = *c.KmsKeyArn
			}
			a := services.NewAsset("opensearch_serverless", models.CategoryDataAtRest, accountID, region, id, "AWS::OpenSearchServerless::Collection", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			a.Properties["kmsKeyId"] = kmsKey
			if name != "" {
				a.Properties["collectionName"] = name
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
