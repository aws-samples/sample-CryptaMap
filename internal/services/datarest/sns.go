package datarest

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// snsAPI is the minimal slice of the sns client this scanner uses. ListTopics is
// NextToken-paginated, so the scanner loops; defining it as an interface keeps the
// pagination + per-topic classification logic unit-testable with a fake (the
// concrete *sns.Client satisfies it).
type snsAPI interface {
	ListTopics(ctx context.Context, in *sns.ListTopicsInput, optFns ...func(*sns.Options)) (*sns.ListTopicsOutput, error)
	GetTopicAttributes(ctx context.Context, in *sns.GetTopicAttributesInput, optFns ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error)
}

// SNSScanner inspects SNS topics for KMS encryption.
type SNSScanner struct{}

// Name returns the canonical service identifier.
func (SNSScanner) Name() string { return "sns" }

// Category returns the primary CryptaMap category.
func (SNSScanner) Category() models.Category { return models.CategoryDataAtRest }

// classifySNS maps a GetTopicAttributes result to a posture/properties/key/note
// tuple. SNS server-side encryption is OFF by default and is enabled only when a
// KmsMasterKeyId is set, so the classification is:
//   - GetTopicAttributes failed (readErr) -> Unknown (cannot assert either way);
//   - KmsMasterKeyId present and non-empty -> confirmed SymmetricOnly;
//   - no error AND no KMS key -> SSE is genuinely off: a real no-encryption finding.
//
// It is a pure helper (no AWS calls) so the honesty contract is unit-testable.
func classifySNS(attrs *sns.GetTopicAttributesOutput, readErr error) (models.CryptoPosture, models.CryptoProperties, string, string) {
	if readErr != nil {
		return models.PostureUnknown, services.UnknownAtRest(), "",
			"Could not read topic encryption attributes; at-rest state undetermined."
	}
	if attrs != nil {
		if v, ok := attrs.Attributes["KmsMasterKeyId"]; ok && v != "" {
			return models.PostureSymmetricOnly, services.AESAtRest(), v, ""
		}
	}
	// No error and no KMS key -> SSE-SNS is off (it is not default-on): a genuine
	// no-encryption finding, not a false alarm.
	return models.PostureNoEncryption, services.NoEncryption(), "", ""
}

// Scan paginates ListTopics, then GetTopicAttributes to check KmsMasterKeyId.
func (s SNSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := sns.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListTopics and classifies each
// topic's KMS encryption. A ListTopics error is returned (not swallowed) so a
// denied/throttled scan stays VISIBLY incomplete.
func (s SNSScanner) scan(ctx context.Context, client snsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListTopics(ctx, &sns.ListTopicsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("sns ListTopics: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// per-topic GetTopicAttributes calls, so a pathological region never
		// exceeds the cap.
		topics := out.Topics
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(topics) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			topics = topics[:remaining]
		}
		for _, t := range topics {
			if t.TopicArn == nil {
				continue
			}
			arn := *t.TopicArn
			parts := strings.Split(arn, ":")
			name := parts[len(parts)-1]
			attrs, aerr := client.GetTopicAttributes(ctx, &sns.GetTopicAttributesInput{TopicArn: t.TopicArn})
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "sns:%s GetTopicAttributes: %v\n", name, aerr)
			}
			posture, props, kmsKey, note := classifySNS(attrs, aerr)
			a := services.NewAsset("sns", models.CategoryDataAtRest, accountID, region, name, "AWS::SNS::Topic", props)
			services.PostureProperty(&a, posture)
			if kmsKey != "" {
				a.Properties["kmsKeyId"] = kmsKey
			}
			if note != "" {
				a.Properties["note"] = note
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
