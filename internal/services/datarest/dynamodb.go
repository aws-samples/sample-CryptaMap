package datarest

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// descSSE returns the table's SSE description from a DescribeTable output, or
// nil when the table or its SSE block is absent.
func descSSE(desc *dynamodb.DescribeTableOutput) *ddbtypes.SSEDescription {
	if desc == nil || desc.Table == nil {
		return nil
	}
	return desc.Table.SSEDescription
}

// dynamoDBAPI is the minimal slice of the dynamodb client this scanner uses.
// ListTables is ExclusiveStartTableName-paginated, so the scanner must loop; a
// single call returns only the first page (default ~100), silently dropping
// tables in dense accounts. Defining it as an interface keeps the pagination,
// describe-error, and posture logic unit-testable with a fake (the concrete
// *dynamodb.Client satisfies it).
type dynamoDBAPI interface {
	ListTables(ctx context.Context, in *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
}

// DynamoDBScanner inspects DynamoDB tables for SSE configuration.
type DynamoDBScanner struct{}

// Name returns the canonical service identifier.
func (DynamoDBScanner) Name() string { return "dynamodb" }

// Category returns the primary CryptaMap category.
func (DynamoDBScanner) Category() models.Category { return models.CategoryDataAtRest }

// The UNIVERSAL guarantee that DynamoDB always encrypts at rest with AES-256 and
// that encryption cannot be disabled is the doc-fact "datarest/dynamodb/at-rest-aes256"
// (internal/pqc knowledge); stamped via services.StampDocFactKeyed below.

// Scan lists tables, then describes each to inspect its SSE description.
// DynamoDB always encrypts data at rest with AES-256 (cannot be disabled), so
// every table is SymmetricOnly. The SSE description distinguishes the key tier:
// a populated KMSMasterKeyArn means an AWS-managed (aws/dynamodb) or customer
// CMK; an absent one means the AWS-owned default key (still AES-256). There is
// no at-rest DISABLED state, so Status is never used to downgrade posture
// (UPDATING is a normal key-rotation state, not a no-encryption signal).
func (s DynamoDBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := dynamodb.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListTables and describes each table
// to inspect its SSE description. A ListTables error is NOT swallowed — it is
// returned so the engine records this scanner as errored (a denied/throttled
// scan stays VISIBLY incomplete rather than a clean-looking empty success). A
// per-table DescribeTable error does NOT silently drop the table: it emits a
// PostureUnknown asset with a note so a read failure never reads as a clean
// all-clear by omission (and never fabricates a NoEncryption false alarm —
// DynamoDB has no at-rest DISABLED state).
func (s DynamoDBScanner) scan(ctx context.Context, client dynamoDBAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var lastEvaluated *string
	for {
		out, err := client.ListTables(ctx, &dynamodb.ListTablesInput{ExclusiveStartTableName: lastEvaluated})
		if err != nil {
			return nil, fmt.Errorf("dynamodb ListTables: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out, so a pathological region never launches more than the
		// cap's worth of goroutines.
		names := out.TableNames
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(names) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			names = names[:remaining]
		}
		// Describe tables concurrently (bounded). MapConcurrent preserves input
		// order. A DescribeTable error does NOT drop the table: it emits a
		// PostureUnknown asset with a note (key tier undetermined) so a read
		// failure never reads as a clean all-clear by omission.
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, names,
			func(ctx context.Context, n string) (models.CryptoAsset, bool) {
				desc, derr := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &n})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "dynamodb:%s DescribeTable: %v\n", n, derr)
					a := services.NewAsset("dynamodb", models.CategoryDataAtRest, accountID, region, n, "AWS::DynamoDB::Table", services.UnknownAtRest())
					services.PostureProperty(&a, models.PostureUnknown)
					a.Properties["note"] = "Could not read table SSE description; at-rest key tier undetermined."
					return a, true
				}
				// DynamoDB always encrypts at rest with AES-256 (universal AWS-doc
				// guarantee), so posture is unconditionally SymmetricOnly.
				a := services.NewAsset("dynamodb", models.CategoryDataAtRest, accountID, region, n, "AWS::DynamoDB::Table", services.AESAtRest())
				services.PostureProperty(&a, models.PostureSymmetricOnly)
				services.StampDocFactKeyed(&a, "datarest/dynamodb/at-rest-aes256")
				// Distinguish the key tier from the SSE description. A populated
				// KMSMasterKeyArn is an AWS-managed or customer CMK; its absence (or a
				// nil SSEDescription) is the AWS-owned default key. Status is captured
				// for evidence only — there is no at-rest DISABLED state, so it must
				// not downgrade posture (UPDATING is a normal key-switch state).
				kmsKey := "AWS_OWNED_KMS_KEY"
				if sse := descSSE(desc); sse != nil {
					if sse.KMSMasterKeyArn != nil && *sse.KMSMasterKeyArn != "" {
						kmsKey = *sse.KMSMasterKeyArn
					}
					if sse.SSEType != "" {
						a.Properties["sseType"] = string(sse.SSEType)
					}
					if sse.Status != "" {
						a.Properties["sseStatus"] = string(sse.Status)
					}
					if sse.InaccessibleEncryptionDateTime != nil {
						a.Properties["inaccessibleEncryptionDateTime"] = sse.InaccessibleEncryptionDateTime.UTC().Format(time.RFC3339)
					}
				}
				a.Properties["kmsKeyId"] = kmsKey
				return a, true
			})
		assets = append(assets, page...)
		if out.LastEvaluatedTableName == nil || *out.LastEvaluatedTableName == "" {
			break
		}
		lastEvaluated = out.LastEvaluatedTableName
	}
	return assets, nil
}
