package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type MSKTransitScanner struct{}

func (MSKTransitScanner) Name() string              { return "msk_transit" }
func (MSKTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// mskKafkaAPI is the minimal slice of the kafka client this scanner uses.
// ListClustersV2 is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping clusters in dense
// accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *kafka.Client
// satisfies it).
type mskKafkaAPI interface {
	ListClustersV2(ctx context.Context, in *kafka.ListClustersV2Input, optFns ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error)
}

func (s MSKTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kafka.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListClustersV2 and classifies each
// cluster into a CryptoAsset. A ListClustersV2 error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s MSKTransitScanner) scan(ctx context.Context, client mskKafkaAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListClustersV2(ctx, &kafka.ListClustersV2Input{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("msk_transit ListClustersV2: %w", err)
		}
		for _, c := range out.ClusterInfoList {
			if c.ClusterArn == nil {
				continue
			}
			id := ""
			if c.ClusterName != nil {
				id = *c.ClusterName
			} else {
				id = *c.ClusterArn
			}
			// Defaults preserved for the Serverless cluster type and any nil
			// path (backward compatible).
			posture := models.PostureNonPQCClassical
			props := services.TLSProtocolProps("1.2", "AWS-managed")
			inClusterStr := ""
			clientBroker := ""
			enforced := ""
			if c.Provisioned != nil && c.Provisioned.EncryptionInfo != nil && c.Provisioned.EncryptionInfo.EncryptionInTransit != nil {
				eit := c.Provisioned.EncryptionInfo.EncryptionInTransit
				clientBroker = string(eit.ClientBroker)
				// Deepen: route both ClientBroker and the broker-to-broker
				// InCluster flag through the pure classifier. A TLS_PLAINTEXT
				// cluster still permits plaintext client-broker traffic, so it
				// is reported as not-fully-enforced rather than clean TLS.
				_, _, posture, props, inClusterStr, enforced = classifyMSKTransit(clientBroker, eit.InCluster)
			}
			a := services.NewAsset("msk_transit", models.CategoryDataInTransit, accountID, region, id, "AWS::MSK::Cluster", props)
			services.PostureProperty(&a, posture)
			if inClusterStr != "" {
				a.Properties["inClusterEncryption"] = inClusterStr
			}
			if clientBroker != "" {
				a.Properties["clientBroker"] = clientBroker
			}
			if enforced != "" {
				a.Properties["transitEncryptionEnforced"] = enforced
				// The TLS/TLS_PLAINTEXT/PLAINTEXT enum-to-behavior mapping is a
				// universal AWS guarantee, not an observed cipher negotiation.
				services.StampDocFactKeyed(&a, "transit/msk_transit/msk-encryption")
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
