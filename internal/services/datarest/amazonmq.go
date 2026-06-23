package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// AmazonMQScanner inspects Amazon MQ brokers (ActiveMQ / RabbitMQ) for at-rest
// encryption.
//
// Amazon MQ always encrypts at rest with a symmetric AES KMS key and it cannot be
// disabled, so posture is unconditionally SymmetricOnly. EncryptionOptions only
// selects the key tier: a customer/AWS-managed CMK (KmsKeyId) or the AWS-owned key
// (UseAwsOwnedKey, the default) — an absent EncryptionOptions is the AWS-owned key,
// NOT no-encryption. (Broker endpoints are TLS, but the API exposes no cipher/cert
// to classify, so transit is left to the active-prober backlog.)
type AmazonMQScanner struct{}

// amazonMQAPI is the minimal slice of the mq client this scanner uses. ListBrokers
// is NextToken-paginated (so the scanner must loop; a single call returns only the
// first page, silently dropping brokers in dense accounts) and DescribeBroker
// carries the per-broker EncryptionOptions. Defining it as an interface keeps the
// pagination + error-propagation + key-tier logic unit-testable with a fake (the
// concrete *mq.Client satisfies it).
type amazonMQAPI interface {
	ListBrokers(ctx context.Context, in *mq.ListBrokersInput, optFns ...func(*mq.Options)) (*mq.ListBrokersOutput, error)
	DescribeBroker(ctx context.Context, in *mq.DescribeBrokerInput, optFns ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error)
}

// Name returns the canonical service identifier.
func (AmazonMQScanner) Name() string { return "amazonmq" }

// Category returns the primary CryptaMap category.
func (AmazonMQScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists brokers, then DescribeBroker for each (the summary carries no crypto).
func (s AmazonMQScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := mq.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListBrokers and, per broker,
// DescribeBroker to read the key tier from EncryptionOptions. A ListBrokers error
// is NOT swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success. A per-broker DescribeBroker error does NOT silently emit a clean
// AWS-owned-key default (a false-safe): the broker is known to exist (it was in
// ListBrokers) but its key custody is undetermined, so it is recorded as
// PostureUnknown with a note (HONESTY CONTRACT: never an all-clear by omission).
func (s AmazonMQScanner) scan(ctx context.Context, client amazonMQAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListBrokers(ctx, &mq.ListBrokersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("amazonmq ListBrokers: %w", err)
		}
		brokers := out.BrokerSummaries
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(brokers) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			brokers = brokers[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, brokers,
			func(ctx context.Context, b mqtypes.BrokerSummary) (models.CryptoAsset, bool) {
				if b.BrokerId == nil {
					return models.CryptoAsset{}, false
				}
				id := *b.BrokerId
				if b.BrokerArn != nil && *b.BrokerArn != "" {
					id = *b.BrokerArn
				}

				d, derr := client.DescribeBroker(ctx, &mq.DescribeBrokerInput{BrokerId: b.BrokerId})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "amazonmq DescribeBroker %s: %v\n", id, derr)
					// The broker is known to exist (it was in ListBrokers) but its
					// encryption detail could not be read — keep it as PostureUnknown
					// rather than silently emitting a clean AWS-owned-key default
					// (HONESTY CONTRACT: never an all-clear by omission, never a
					// no-encryption false alarm).
					a := services.NewAsset("amazonmq", models.CategoryDataAtRest, accountID, region, id, "AWS::AmazonMQ::Broker", services.UnknownAtRest())
					services.PostureProperty(&a, models.PostureUnknown)
					a.Properties["note"] = "Could not read broker encryption (DescribeBroker failed); at-rest key custody undetermined."
					if b.BrokerName != nil {
						a.Properties["brokerName"] = *b.BrokerName
					}
					return a, true
				}

				// Always-on KMS AES-256 at rest -> SymmetricOnly; key tier from
				// EncryptionOptions (absent = AWS-owned key, still encrypted).
				kmsKey := "AWS_OWNED_KMS_KEY"
				if d.EncryptionOptions != nil && d.EncryptionOptions.KmsKeyId != nil && *d.EncryptionOptions.KmsKeyId != "" {
					kmsKey = *d.EncryptionOptions.KmsKeyId
				}
				a := services.NewAsset("amazonmq", models.CategoryDataAtRest, accountID, region, id, "AWS::AmazonMQ::Broker", services.AESAtRest())
				services.PostureProperty(&a, models.PostureSymmetricOnly)
				a.Properties["kmsKeyId"] = kmsKey
				if b.BrokerName != nil {
					a.Properties["brokerName"] = *b.BrokerName
				}
				if et := string(d.EngineType); et != "" {
					a.Properties["engineType"] = et
				}
				return a, true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
