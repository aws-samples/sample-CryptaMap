package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appsync"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type AppSyncScanner struct{}

func (AppSyncScanner) Name() string              { return "appsync" }
func (AppSyncScanner) Category() models.Category { return models.CategoryDataInTransit }

// appsyncGraphqlAPI is the minimal slice of the appsync client this scanner
// uses. ListGraphqlApis is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping APIs in accounts
// with many GraphQL APIs. Defining it as an interface keeps the pagination +
// error propagation logic unit-testable with a fake (the concrete
// *appsync.Client satisfies it).
type appsyncGraphqlAPI interface {
	ListGraphqlApis(ctx context.Context, in *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error)
}

func (s AppSyncScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := appsync.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListGraphqlApis and classifies each
// GraphQL API into a CryptoAsset. A ListGraphqlApis error is NOT swallowed — it
// is returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s AppSyncScanner) scan(ctx context.Context, client appsyncGraphqlAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListGraphqlApis(ctx, &appsync.ListGraphqlApisInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("appsync ListGraphqlApis: %w", err)
		}
		for _, api := range out.GraphqlApis {
			if api.ApiId == nil {
				continue
			}
			// AppSync documents a TLS 1.2 floor (1.3 recommended) for its served API
			// endpoints; the per-connection negotiated version is client-dependent, so
			// record the documented floor with high-confidence aws-doc provenance.
			props := services.TLSProtocolPropsDoc("1.2", "appsync-tls", "high", "https://docs.aws.amazon.com/appsync/latest/devguide/infrastructure-security.html")
			a := services.NewAsset("appsync", models.CategoryDataInTransit, accountID, region, *api.ApiId, "AWS::AppSync::GraphQLApi", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "transit/appsync/aws-tls-policy")
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
