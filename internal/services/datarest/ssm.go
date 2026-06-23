package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SSMScanner inspects SSM Parameter Store parameters; SecureString → KMS,
// String/StringList → no encryption (treated as secret-grade for the report).
type SSMScanner struct{}

// Name returns the canonical service identifier.
func (SSMScanner) Name() string { return "ssm" }

// Category returns the primary CryptaMap category.
func (SSMScanner) Category() models.Category { return models.CategoryDataAtRest }

// ssmAPI is the minimal slice of the ssm client this scanner uses.
// DescribeParameters is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page (default ~50), silently dropping parameters
// in dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *ssm.Client satisfies it).
type ssmAPI interface {
	DescribeParameters(ctx context.Context, in *ssm.DescribeParametersInput, optFns ...func(*ssm.Options)) (*ssm.DescribeParametersOutput, error)
}

// Scan paginates DescribeParameters.
func (s SSMScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ssm.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeParameters and classifies
// each parameter into a CryptoAsset. A DescribeParameters error is NOT swallowed
// — it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s SSMScanner) scan(ctx context.Context, client ssmAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeParameters(ctx, &ssm.DescribeParametersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ssm DescribeParameters: %w", err)
		}
		for _, p := range out.Parameters {
			if p.Name == nil {
				continue
			}
			name := *p.Name
			// ALL Parameter Store parameters are encrypted at rest regardless of type:
			// String/StringList with an AWS-owned key, SecureString with customer-
			// controlled KMS envelope encryption. So posture is unconditionally
			// SymmetricOnly; String/StringList is NOT no-encryption. SecureString is
			// recorded as the higher-assurance key tier via its KeyId.
			a := services.NewAsset("ssm", models.CategoryDataAtRest, accountID, region, name, "AWS::SSM::Parameter", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/ssm/at-rest-aes256")
			a.Properties["parameterType"] = string(p.Type)
			kmsKey := "AWS_OWNED_KMS_KEY"
			if p.Type == ssmtypes.ParameterTypeSecureString {
				kmsKey = "alias/aws/ssm"
			}
			if p.KeyId != nil && *p.KeyId != "" {
				kmsKey = *p.KeyId
			}
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
