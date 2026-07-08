package transit

import (
	"context"
	"fmt"
	"os"

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
// dense accounts. ListFunctionUrlConfigs resolves whether a function actually
// serves an HTTPS endpoint (a Function URL) — the only per-function transit
// surface Lambda exposes to a read-only scanner; it requires the
// lambda:ListFunctionUrlConfigs IAM read action. Defining the pair as an
// interface keeps the pagination + error propagation + endpoint-resolution
// logic unit-testable with a fake (the concrete *lambda.Client satisfies it).
type lambdaListAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	ListFunctionUrlConfigs(ctx context.Context, in *lambda.ListFunctionUrlConfigsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionUrlConfigsOutput, error)
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
//
// Honesty contract: a plain Lambda function has NO served data-plane endpoint
// of its own, and no read API returns its invoke-path TLS configuration — so
// asserting a definite "classical TLS" transit posture for every function
// would be fabricated. The scanner therefore resolves each function's Function
// URL configs (the one provable HTTPS surface): a function WITH a Function URL
// serves a documented HTTPS-only endpoint and is classified classical TLS with
// the served version left unknown; a function WITHOUT one (or whose URL configs
// could not be read) is left PostureUnknown with a note naming exactly what
// could not be proven.
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
			name := *fn.FunctionName
			hasURL, urlOK := functionHasURL(ctx, client, name)
			// Lambda's TLS 1.2 floor is documented for the control-plane/management
			// API, NOT for served data-plane endpoints (Function URLs), whose minimum
			// version is undocumented. Leave the served version UNKNOWN rather than
			// asserting "1.2".
			props := services.TLSProtocolPropsDetailed("", "lambda-managed-tls", "", "", 0, false)
			a := services.NewAsset("lambda", models.CategoryDataInTransit, accountID, region, name, "AWS::Lambda::Function", props)
			switch {
			case hasURL:
				// A Function URL is a provable HTTPS-only served endpoint (Lambda
				// Function URLs accept only HTTPS), so a classical-TLS posture is
				// grounded in an observed per-function API result; the served TLS
				// version stays unknown (undocumented), per the doc-fact key.
				a.Properties["functionUrl"] = "true"
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				services.StampObserved(&a, "high")
				services.StampDocFactSubclaimKeyed(&a, "transit/lambda/aws-tls-policy")
			case urlOK:
				// Proven to have NO Function URL: the function serves no public
				// endpoint of its own, and no API exposes its invoke-path TLS
				// configuration — so no definite transit posture is provable.
				a.Properties["functionUrl"] = "false"
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "Lambda function has no Function URL (no served HTTPS endpoint of its own), and no read API returns the invoke-path TLS configuration; transit posture cannot be proven."
			default:
				// ListFunctionUrlConfigs failed (denied/throttled): whether the
				// function serves an HTTPS endpoint is unproven — never fabricate
				// a definite classical posture off an unreadable config.
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "Lambda Function URL configuration could not be read (lambda:ListFunctionUrlConfigs failed), so the presence of a served TLS endpoint is unproven."
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

// functionHasURL reports whether the named function has at least one Function
// URL config. ok=false means the answer could not be determined (API error) —
// logged to stderr and left to the caller to classify as unknown rather than
// silently becoming a fabricated verdict. Pagination stops early on the first
// config found (any config proves an HTTPS endpoint); an exhausted Marker loop
// with no configs proves there is none.
func functionHasURL(ctx context.Context, client lambdaListAPI, name string) (hasURL, ok bool) {
	var marker *string
	for {
		out, err := client.ListFunctionUrlConfigs(ctx, &lambda.ListFunctionUrlConfigsInput{
			FunctionName: aws.String(name),
			Marker:       marker,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "lambda ListFunctionUrlConfigs(%s): %v\n", name, err)
			return false, false
		}
		if len(out.FunctionUrlConfigs) > 0 {
			return true, true
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			return false, true
		}
		marker = out.NextMarker
	}
}
