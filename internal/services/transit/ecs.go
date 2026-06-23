package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type ECSScanner struct{}

func (ECSScanner) Name() string              { return "ecs" }
func (ECSScanner) Category() models.Category { return models.CategoryDataInTransit }

// ecsListAPI is the minimal slice of the ecs client this scanner uses.
// ListClusters is NextToken-paginated, so the scanner must loop; a single call
// returns only the first page (default ~100), silently dropping clusters in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *ecs.Client
// satisfies it).
type ecsListAPI interface {
	ListClusters(ctx context.Context, in *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
}

func (s ECSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ecs.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListClusters and classifies each
// cluster into a CryptoAsset. A ListClusters error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s ECSScanner) scan(ctx context.Context, client ecsListAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListClusters(ctx, &ecs.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ecs ListClusters: %w", err)
		}
		for _, arn := range out.ClusterArns {
			// ECS documents a TLS 1.2 floor (1.3 recommended) for its API endpoints;
			// the per-connection negotiated version is not pinned, so record the
			// documented floor with high-confidence aws-doc provenance.
			props := services.TLSProtocolPropsDoc("1.2", "ecs-tls", "high", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/infrastructure-security.html")
			a := services.NewAsset("ecs", models.CategoryDataInTransit, accountID, region, arn, "AWS::ECS::Cluster", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "transit/ecs/aws-tls-policy")
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
