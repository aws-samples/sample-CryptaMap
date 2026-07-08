package datarest

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SQSScanner inspects SQS queues for KMS or SQS-managed SSE.
type SQSScanner struct{}

// Name returns the canonical service identifier.
func (SQSScanner) Name() string { return "sqs" }

// Category returns the primary CryptaMap category.
func (SQSScanner) Category() models.Category { return models.CategoryDataAtRest }

// sqsAPI is the minimal slice of the sqs client this scanner uses. ListQueues is
// NextToken-paginated, so the scanner must loop; a single call returns only the
// first page (default ~1000), silently dropping queues in dense accounts.
// Defining it as an interface keeps the pagination + error/posture logic
// unit-testable with a fake (the concrete *sqs.Client satisfies it).
type sqsAPI interface {
	ListQueues(ctx context.Context, in *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error)
	GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
}

// Scan paginates ListQueues then GetQueueAttributes for KmsMasterKeyId / SqsManagedSseEnabled.
func (s SQSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := sqs.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListQueues and classifies each
// queue's at-rest posture. A ListQueues error is propagated so the engine records
// this scanner as errored (visibly incomplete) rather than a clean empty success;
// a per-queue GetQueueAttributes error is NOT silently dropped — the queue is
// still recorded as PostureUnknown with a note.
func (s SQSScanner) scan(ctx context.Context, client sqsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		// MaxResults MUST be set explicitly: per the SQS API, when MaxResults is
		// unset ListQueues returns up to 1,000 queue URLs and NEVER returns a
		// NextToken, so the pagination loop below would silently truncate at
		// ~1000 queues (a false all-clear by omission in dense accounts).
		out, err := client.ListQueues(ctx, &sqs.ListQueuesInput{
			NextToken:  nextToken,
			MaxResults: aws.Int32(1000),
		})
		if err != nil {
			return nil, fmt.Errorf("sqs ListQueues: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// per-queue attribute reads, so a pathological account never grows the
		// shard unbounded (and the truncation is LOUD, never silent).
		urls := out.QueueUrls
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(urls) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			urls = urls[:remaining]
			// The cap lands mid-page: this page fills the shard exactly, so the
			// remaining URLs here (and any later pages) are dropped. Emit the LOUD
			// truncation warning now — the remaining<=0 branch above only fires on a
			// SUBSEQUENT iteration, which never happens if this is the final page.
			services.TruncationCapReached(services.MaxAssetsPerScanner, s.Name(), region)
		}
		for _, url := range urls {
			u := url
			// Use the URL last path segment as the resource ID.
			parts := strings.Split(u, "/")
			name := parts[len(parts)-1]
			attrs, aerr := client.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
				QueueUrl: &u,
				AttributeNames: []sqstypes.QueueAttributeName{
					sqstypes.QueueAttributeNameKmsMasterKeyId,
					sqstypes.QueueAttributeNameSqsManagedSseEnabled,
				},
			})
			// SSE-SQS (AES-256) is enabled by DEFAULT for newly created queues, but it
			// CAN be disabled, so this is not an always-on guarantee. Classify on the
			// real attributes:
			//   - a KMS key id, or SqsManagedSseEnabled=true -> confirmed SymmetricOnly;
			//   - SqsManagedSseEnabled explicitly "false" with no KMS key -> SSE was
			//     turned off: a GENUINE no-encryption finding (not a false alarm);
			//   - attributes absent/unreadable -> Unknown (do not assert either way).
			posture := models.PostureUnknown
			props := services.UnknownAtRest()
			note := ""
			var kmsKey string
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "sqs:%s GetQueueAttributes: %v\n", name, aerr)
				note = "Could not read queue encryption attributes; at-rest state undetermined."
			} else if attrs != nil {
				kmsVal, hasKMS := attrs.Attributes[string(sqstypes.QueueAttributeNameKmsMasterKeyId)]
				sseVal, hasSSE := attrs.Attributes[string(sqstypes.QueueAttributeNameSqsManagedSseEnabled)]
				switch {
				case hasKMS && kmsVal != "":
					posture = models.PostureSymmetricOnly
					props = services.AESAtRest()
					kmsKey = kmsVal
				case hasSSE && strings.EqualFold(sseVal, "true"):
					posture = models.PostureSymmetricOnly
					props = services.AESAtRest()
					kmsKey = "alias/aws/sqs"
				case hasSSE && strings.EqualFold(sseVal, "false"):
					// SSE explicitly disabled and no KMS key -> genuinely unencrypted.
					posture = models.PostureNoEncryption
					props = services.NoEncryption()
				default:
					// Neither attribute returned: cannot confirm either way.
					note = "Queue encryption attributes not returned; SSE-SQS is default-on for queues created after 2022-12, but the state could not be confirmed here."
				}
			}
			a := services.NewAsset("sqs", models.CategoryDataAtRest, accountID, region, name, "AWS::SQS::Queue", props)
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
