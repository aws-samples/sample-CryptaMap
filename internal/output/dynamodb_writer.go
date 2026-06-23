package output

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// defaultRetentionDays mirrors the cdk.json `retentionScans` default (30 days,
// see cdk/bin/app.ts). It is the fallback used when RETENTION_DAYS is unset or
// unparseable so the TTL window still matches the documented default rather than
// silently never expiring.
const defaultRetentionDays = 30

// maxInlineFindingsBytes bounds the gzipped+base64 findings blob stored inline on
// the DynamoDB item. DynamoDB's hard item limit is 400KB across ALL attributes;
// we cap the findings attribute well below that to leave room for the summary +
// keys. On a dense shard whose compressed findings exceed this, we OMIT the inline
// blob (the full findings already live in S3 via cbomRef / the raw shard) rather
// than letting PutItem fail the entire scan record write.
const maxInlineFindingsBytes = 300 * 1024

// DynamoWriter persists scan summaries + compressed findings to DynamoDB.
type DynamoWriter struct {
	Table  string
	Client *dynamodb.Client
	// RetentionDays is the TTL window stamped onto each item's `expiresAt`
	// attribute. It mirrors the retentionScans CDK context so the scans table's
	// TTL ages records out on the same window as the results-bucket lifecycle.
	RetentionDays int
}

func NewDynamoWriter(cfg aws.Config, table string) *DynamoWriter {
	return &DynamoWriter{
		Table:         table,
		Client:        dynamodb.NewFromConfig(cfg),
		RetentionDays: retentionDaysFromEnv(),
	}
}

// retentionDaysFromEnv reads the RETENTION_DAYS env var (wired from the
// retentionScans CDK context in the scanner/org stacks) and falls back to
// defaultRetentionDays when it is unset, non-numeric, or non-positive.
func retentionDaysFromEnv() int {
	raw := os.Getenv("RETENTION_DAYS")
	if raw == "" {
		return defaultRetentionDays
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		fmt.Fprintf(os.Stderr,
			"[dynamo] invalid RETENTION_DAYS %q; falling back to %d-day TTL\n", raw, defaultRetentionDays)
		return defaultRetentionDays
	}
	return n
}

// PutScan writes a scan record. Findings are gzipped+base64 to keep item size down.
func (w *DynamoWriter) PutScan(ctx context.Context, scan models.ScanResult, cbomS3Key string) error {
	pk := fmt.Sprintf("ACCOUNT#%s#REGION#%s", scan.AccountID, scan.Region)
	sk := fmt.Sprintf("SCAN#%s", scan.CompletedAt.UTC().Format(time.RFC3339))

	findingsJSON, err := json.Marshal(scan.Findings)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(findingsJSON); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())

	summaryJSON, err := json.Marshal(scan.Summary)
	if err != nil {
		return err
	}

	// TTL attribute (epoch SECONDS) the scans table auto-deletes on; the table's
	// timeToLiveAttribute is 'expiresAt' (see cdk/lib/data-stack.ts). Stamped as
	// now + RetentionDays days (RETENTION_DAYS env, wired from the retentionScans
	// CDK context) so records age out on the same window as the results-bucket
	// lifecycle rule. DynamoDB TTL deletion is best-effort (typically within 48h).
	retentionDays := w.RetentionDays
	if retentionDays <= 0 {
		retentionDays = defaultRetentionDays
	}
	expiresAt := time.Now().Add(time.Duration(retentionDays) * 24 * time.Hour).Unix()

	item := map[string]ddbtypes.AttributeValue{
		"PK":        &ddbtypes.AttributeValueMemberS{Value: pk},
		"SK":        &ddbtypes.AttributeValueMemberS{Value: sk},
		"scanId":    &ddbtypes.AttributeValueMemberS{Value: scan.ScanID},
		"timestamp": &ddbtypes.AttributeValueMemberS{Value: scan.CompletedAt.UTC().Format(time.RFC3339)},
		"summary":   &ddbtypes.AttributeValueMemberS{Value: string(summaryJSON)},
		"cbomRef":   &ddbtypes.AttributeValueMemberS{Value: cbomS3Key},
		"expiresAt": &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", expiresAt)},
		"GSI1PK":    &ddbtypes.AttributeValueMemberS{Value: "FRAMEWORK#ALL"},
		"GSI1SK":    &ddbtypes.AttributeValueMemberS{Value: sk},
	}
	// Store the inline findings blob only when it fits comfortably under the 400KB
	// item ceiling; otherwise omit it (full findings remain in S3 via cbomRef) so a
	// dense shard does not fail the entire PutItem. The reader treats a missing
	// findings attribute as "fetch from S3".
	if len(encoded) <= maxInlineFindingsBytes {
		item["findings"] = &ddbtypes.AttributeValueMemberS{Value: encoded}
	} else {
		item["findingsTruncated"] = &ddbtypes.AttributeValueMemberBOOL{Value: true}
		fmt.Fprintf(os.Stderr,
			"[dynamo] %s %s: compressed findings %d bytes exceed inline cap %d; omitting inline blob (findings available in S3 at %s)\n",
			pk, sk, len(encoded), maxInlineFindingsBytes, cbomS3Key)
	}

	_, err = w.Client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(w.Table),
		Item:      item,
	})
	return err
}
