package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SecretsManagerScanner enumerates Secrets Manager secrets.
//
// Every Secrets Manager secret is encrypted at rest. KmsKeyId is omitted when
// the secret is encrypted with the AWS-managed `aws/secretsmanager` key.
type SecretsManagerScanner struct{}

// Name returns the canonical service identifier.
func (SecretsManagerScanner) Name() string { return "secretsmanager" }

// Category returns the primary CryptaMap category.
func (SecretsManagerScanner) Category() models.Category { return models.CategoryDataAtRest }

// secretsmanagerAPI is the minimal slice of the secretsmanager client this
// scanner uses. ListSecrets is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping secrets in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *secretsmanager.Client satisfies it).
type secretsmanagerAPI interface {
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// Scan paginates ListSecrets.
func (s SecretsManagerScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := secretsmanager.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListSecrets and classifies each
// secret into a CryptoAsset. A ListSecrets error is NOT swallowed — it is
// returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s SecretsManagerScanner) scan(ctx context.Context, client secretsmanagerAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("secretsmanager ListSecrets: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE appending,
		// so a pathological account/region never emits more than the cap's worth of
		// assets (ListSecrets is unbounded).
		items := out.SecretList
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(items) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			items = items[:remaining]
		}
		for _, sec := range items {
			if sec.Name == nil {
				continue
			}
			name := *sec.Name
			a := services.NewAsset("secretsmanager", models.CategoryDataAtRest, accountID, region, name, "AWS::SecretsManager::Secret", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/secretsmanager/at-rest-aes256")
			if sec.KmsKeyId != nil && *sec.KmsKeyId != "" {
				a.Properties["kmsKeyId"] = *sec.KmsKeyId
			} else {
				a.Properties["kmsKeyId"] = "aws/secretsmanager"
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
