package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// RedshiftServerlessScanner inspects Redshift Serverless namespaces for at-rest
// encryption. Distinct from the provisioned-cluster redshift scanner.
//
// Redshift Serverless data is ALWAYS encrypted at rest with a KMS key (AES-256),
// with no opt-out — so posture is unconditionally SymmetricOnly. An absent
// KmsKeyId means the AWS-owned default key, not no-encryption.
type RedshiftServerlessScanner struct{}

// Name returns the canonical service identifier.
func (RedshiftServerlessScanner) Name() string { return "redshiftserverless" }

// Category returns the primary CryptaMap category.
func (RedshiftServerlessScanner) Category() models.Category { return models.CategoryDataAtRest }

// redshiftServerlessAPI is the minimal slice of the redshiftserverless client
// this scanner uses. ListNamespaces is NextToken-paginated, so the scanner must
// loop; a single call returns only the first page, silently dropping namespaces
// in dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete
// *redshiftserverless.Client satisfies it).
type redshiftServerlessAPI interface {
	ListNamespaces(ctx context.Context, in *redshiftserverless.ListNamespacesInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListNamespacesOutput, error)
}

// Scan paginates ListNamespaces (the namespace carries KmsKeyId inline).
func (s RedshiftServerlessScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := redshiftserverless.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListNamespaces and classifies each
// namespace into a CryptoAsset. A ListNamespaces error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s RedshiftServerlessScanner) scan(ctx context.Context, client redshiftServerlessAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListNamespaces(ctx, &redshiftserverless.ListNamespacesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("redshiftserverless ListNamespaces: %w", err)
		}
		for _, ns := range out.Namespaces {
			name := ""
			if ns.NamespaceName != nil {
				name = *ns.NamespaceName
			}
			id := name
			if ns.NamespaceArn != nil && *ns.NamespaceArn != "" {
				id = *ns.NamespaceArn
			}
			// Always-on KMS AES-256 at rest -> unconditionally SymmetricOnly.
			kmsKey := "AWS_OWNED_KMS_KEY"
			if ns.KmsKeyId != nil && *ns.KmsKeyId != "" {
				kmsKey = *ns.KmsKeyId
			}
			a := services.NewAsset("redshiftserverless", models.CategoryDataAtRest, accountID, region, id, "AWS::RedshiftServerless::Namespace", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/redshift/latest/mgmt/serverless-workgroups-and-namespaces-rotate-kms-key.html", "2026-06-16")
			a.Properties["kmsKeyId"] = kmsKey
			if name != "" {
				a.Properties["namespaceName"] = name
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
