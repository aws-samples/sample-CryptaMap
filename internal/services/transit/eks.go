package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type EKSScanner struct{}

func (EKSScanner) Name() string              { return "eks" }
func (EKSScanner) Category() models.Category { return models.CategoryDataInTransit }

// eksClustersAPI is the minimal slice of the eks client this scanner uses.
// ListClusters is NextToken-paginated, so the scanner must loop; a single call
// returns only the first page, silently dropping clusters in dense accounts.
// Defining it as an interface keeps the pagination + error propagation logic
// unit-testable with a fake (the concrete *eks.Client satisfies it).
type eksClustersAPI interface {
	ListClusters(ctx context.Context, in *eks.ListClustersInput, optFns ...func(*eks.Options)) (*eks.ListClustersOutput, error)
}

func (s EKSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := eks.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListClusters and classifies each
// cluster into a CryptoAsset. A ListClusters error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s EKSScanner) scan(ctx context.Context, client eksClustersAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListClusters(ctx, &eks.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("eks ListClusters: %w", err)
		}
		for _, name := range out.Clusters {
			// EKS documents a TLS 1.2 floor (1.3 supported) for its API/control-plane
			// endpoint; the exact negotiated version per connection is not pinned, so
			// record the documented floor with high-confidence aws-doc provenance.
			props := services.TLSProtocolPropsDoc("1.2", "eks-tls", "high", "https://docs.aws.amazon.com/eks/latest/userguide/infrastructure-security.html")
			a := services.NewAsset("eks", models.CategoryDataInTransit, accountID, region, name, "AWS::EKS::Cluster", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "transit/eks/aws-tls-policy")
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
