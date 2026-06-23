package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type LambdaScanner struct{}

func (LambdaScanner) Name() string              { return "lambda" }
func (LambdaScanner) Category() models.Category { return models.CategoryDataInTransit }

// lambdaListAPI is the minimal slice of the lambda client this scanner uses.
// ListFunctions is Marker-paginated, so the scanner must loop; a single call
// returns only the first page (default ~50), silently dropping functions in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *lambda.Client
// satisfies it).
type lambdaListAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

func (s LambdaScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := lambda.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListFunctions and classifies each
// function into a CryptoAsset. A ListFunctions error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s LambdaScanner) scan(ctx context.Context, client lambdaListAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("lambda ListFunctions: %w", err)
		}
		for _, fn := range out.Functions {
			if fn.FunctionName == nil {
				continue
			}
			// Lambda's TLS 1.2 floor is documented for the control-plane/management
			// API, NOT for served data-plane endpoints (Function URLs), whose minimum
			// version is undocumented. Leave the served version UNKNOWN rather than
			// asserting "1.2"; carry a low-confidence aws-doc provenance note.
			props := services.TLSProtocolPropsDoc("", "lambda-managed-tls", "low", "https://docs.aws.amazon.com/lambda/latest/dg/security-dataprotection.html")
			a := services.NewAsset("lambda", models.CategoryDataInTransit, accountID, region, *fn.FunctionName, "AWS::Lambda::Function", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "transit/lambda/aws-tls-policy")
			assets = append(assets, a)
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
