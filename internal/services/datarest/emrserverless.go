package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emrserverless"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EMRServerlessScanner inspects EMR Serverless applications for at-rest
// encryption. Distinct from the EMR-on-EC2 security-configuration scanner.
//
// EMR Serverless always encrypts all worker disks at rest with AES-256 (a
// service-owned key by default, optionally a customer KMS key), with no opt-out,
// so posture is unconditionally SymmetricOnly. (The optional customer CMK is a
// key-tier refinement, not an on/off toggle.)
type EMRServerlessScanner struct{}

// Name returns the canonical service identifier.
func (EMRServerlessScanner) Name() string { return "emr_serverless" }

// Category returns the primary CryptaMap category.
func (EMRServerlessScanner) Category() models.Category { return models.CategoryDataAtRest }

// emrServerlessAPI is the minimal slice of the emrserverless client this scanner
// uses. ListApplications is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping applications in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *emrserverless.Client
// satisfies it).
type emrServerlessAPI interface {
	ListApplications(ctx context.Context, in *emrserverless.ListApplicationsInput, optFns ...func(*emrserverless.Options)) (*emrserverless.ListApplicationsOutput, error)
}

// Scan paginates ListApplications (at-rest is always-on, so no detail call is
// needed to establish the posture). The AWS client + accountID are resolved here
// and the rest of the logic lives in the testable scan core.
func (s EMRServerlessScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := emrserverless.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListApplications and classifies each
// application into a CryptoAsset. A ListApplications error is NOT swallowed — it
// is returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s EMRServerlessScanner) scan(ctx context.Context, client emrServerlessAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListApplications(ctx, &emrserverless.ListApplicationsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("emr_serverless ListApplications: %w", err)
		}
		for _, app := range out.Applications {
			name := ""
			if app.Name != nil {
				name = *app.Name
			}
			id := name
			if app.Arn != nil && *app.Arn != "" {
				id = *app.Arn
			} else if app.Id != nil {
				id = *app.Id
			}
			a := services.NewAsset("emr_serverless", models.CategoryDataAtRest, accountID, region, id, "AWS::EMRServerless::Application", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			a.Properties["kmsKeyId"] = "AWS_OWNED_KMS_KEY"
			if name != "" {
				a.Properties["applicationName"] = name
			}
			a.Properties["note"] = "EMR Serverless always encrypts worker disks at rest with AES-256 (service-owned key by default; an optional customer KMS key is a key-tier refinement)."
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
