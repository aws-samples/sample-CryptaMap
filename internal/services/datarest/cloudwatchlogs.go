package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CloudWatchLogsScanner inspects CloudWatch log groups for at-rest encryption.
//
// CloudWatch Logs always encrypts every log group at rest with AES-256-GCM
// (universal AWS-doc guarantee, doc-fact "datarest/cloudwatchlogs/at-rest-aes256"),
// and there is no way to disable it. The KmsKeyId field only selects the key tier:
// a customer/AWS-managed CMK when present, the CloudWatch-Logs-managed (AWS-owned)
// key when absent. So posture is unconditionally SymmetricOnly and a missing
// KmsKeyId is the AWS-owned default key — never no-encryption.
type CloudWatchLogsScanner struct{}

// Name returns the canonical service identifier.
func (CloudWatchLogsScanner) Name() string { return "cloudwatchlogs" }

// Category returns the primary CryptaMap category.
func (CloudWatchLogsScanner) Category() models.Category { return models.CategoryDataAtRest }

// cwLogsAPI is the minimal slice of the cloudwatchlogs client this scanner uses.
// DescribeLogGroups is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping log groups in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *cloudwatchlogs.Client satisfies it).
type cwLogsAPI interface {
	DescribeLogGroups(ctx context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
}

// Scan paginates DescribeLogGroups.
func (s CloudWatchLogsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cloudwatchlogs.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeLogGroups and classifies
// each log group into a CryptoAsset. A DescribeLogGroups error is NOT swallowed —
// it is returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s CloudWatchLogsScanner) scan(ctx context.Context, client cwLogsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("cloudwatchlogs DescribeLogGroups: %w", err)
		}
		for _, g := range out.LogGroups {
			if g.LogGroupName == nil {
				continue
			}
			name := *g.LogGroupName
			// All log groups are AES-256-GCM encrypted at rest (cannot be disabled),
			// so posture is unconditionally SymmetricOnly. KmsKeyId selects the key
			// tier only: a customer/AWS-managed CMK when present, else the AWS-owned
			// default key.
			kmsKey := "AWS_OWNED_KMS_KEY"
			if g.KmsKeyId != nil && *g.KmsKeyId != "" {
				kmsKey = *g.KmsKeyId
			}
			a := services.NewAsset("cloudwatchlogs", models.CategoryDataAtRest, accountID, region, name, "AWS::Logs::LogGroup", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/cloudwatchlogs/at-rest-aes256")
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
