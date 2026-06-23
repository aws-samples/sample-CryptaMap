// Package sdkpqc scans compute resources for SDK/runtime PQC capability.
package sdkpqc

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// LambdaRuntimeScanner inspects Lambda function runtimes and records runtime metadata.
type LambdaRuntimeScanner struct{}

// Name returns the canonical scanner identifier.
func (LambdaRuntimeScanner) Name() string { return "lambda_runtime" }

// Category returns the primary category for this scanner.
func (LambdaRuntimeScanner) Category() models.Category { return models.CategorySDKLibrary }

// lambdaListFunctionsAPI is the minimal slice of the lambda client this scanner
// uses. ListFunctions is Marker-paginated, so the scanner must loop; a single
// call returns only the first page (default ~50), silently dropping functions in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *lambda.Client
// satisfies it).
type lambdaListFunctionsAPI interface {
	ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

// Scan lists Lambda functions and emits one asset per function with runtime info.
// Pagination via Marker; capped at 1000 items.
//
// PQC posture is intentionally left UNKNOWN: neither ListFunctions nor GetFunction
// exposes the SDK/CRT version bundled in the deployment package or the
// postQuantumTlsEnabled opt-in, and there is no universal AWS guarantee tying a
// runtime identifier to PQ-TLS. PQ-TLS is opt-in, dependency-gated on the AWS
// Common Runtime, and Linux-only (https://docs.aws.amazon.com/kms/latest/developerguide/pqtls.html,
// "Supported Systems"), so a runtime string cannot determine the outbound posture.
// The runtime is recorded as metadata only. Real PQ-TLS use is observed elsewhere
// from CloudTrail tlsDetails.keyExchange=X25519MLKEM768 (see
// internal/services/runtime/cloudtrail_evidence.go), not inferred from a runtime name.
func (s LambdaRuntimeScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := lambda.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListFunctions via Marker and emits
// one asset per function. A ListFunctions error is NOT swallowed — it is returned
// so the engine records this scanner as errored (which surfaces in coverage),
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success.
func (s LambdaRuntimeScanner) scan(ctx context.Context, client lambdaListFunctionsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	const maxItems = 1000
	var marker *string
	for {
		out, err := client.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("lambda ListFunctions: %w", err)
		}
		for _, f := range out.Functions {
			if f.FunctionArn == nil {
				continue
			}
			id := *f.FunctionArn
			name := ""
			if f.FunctionName != nil {
				name = *f.FunctionName
			}
			runtime := string(f.Runtime)
			version := ""
			if f.Version != nil {
				version = *f.Version
			}
			// No ProtocolProperties cipher block: ListFunctions/FunctionConfiguration
			// exposes no negotiated TLS version or cipher suite, so emitting one would
			// be fabricated evidence. Carry only the runtime metadata we can observe.
			a := services.NewAsset("lambda_runtime", models.CategorySDKLibrary, accountID, region, id, "AWS::Lambda::Function", models.CryptoProperties{})
			a.Properties["functionName"] = name
			a.Properties["runtime"] = runtime
			a.Properties["version"] = version
			services.PostureProperty(&a, models.PostureUnknown)
			assets = append(assets, a)
			if len(assets) >= maxItems {
				return assets, nil
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
