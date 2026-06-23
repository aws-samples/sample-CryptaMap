package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeDynamoDBClient is a hand-rolled dynamoDBAPI for unit-testing the scanner's
// pagination, error propagation, and posture mapping with no live AWS client.
// listPages is returned page-by-page (each ListTables call consumes the next
// page) and LastEvaluatedTableName is wired so the scanner loops through every
// page; listErr forces a ListTables failure. describe maps a table name to a
// canned DescribeTable result; describeErr maps a table name to a forced
// per-table DescribeTable error.
type fakeDynamoDBClient struct {
	listPages   []*dynamodb.ListTablesOutput
	listCalls   int
	listErr     error
	describe    map[string]*dynamodb.DescribeTableOutput
	describeErr map[string]error
}

func (f *fakeDynamoDBClient) ListTables(ctx context.Context, in *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &dynamodb.ListTablesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeDynamoDBClient) DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	name := ""
	if in.TableName != nil {
		name = *in.TableName
	}
	if f.describeErr != nil {
		if err := f.describeErr[name]; err != nil {
			return nil, err
		}
	}
	if f.describe != nil {
		if out, ok := f.describe[name]; ok {
			return out, nil
		}
	}
	// Default: a table with no SSE description (AWS-owned default key).
	return &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{}}, nil
}

// ddbStrptr / ddbAssetByID / ddbKeys are package-unique local helpers. They are
// intentionally NOT named strptr/assetByID/keys to avoid redeclaration clashes
// with sibling _test.go files in this same package, keeping this file's
// compilation independent of sibling churn.
func ddbStrptr(s string) *string { return &s }

func ddbAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

func ddbKeys(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestDynamoDBScanPaginates verifies the ListTables ExclusiveStartTableName loop:
// a fake returning 2 pages (LastEvaluatedTableName on page 1) must yield BOTH
// pages' tables as assets. Without the pagination loop, only page 1's table
// survives — the commonest real bug in dense accounts (default page ~100).
func TestDynamoDBScanPaginates(t *testing.T) {
	client := &fakeDynamoDBClient{
		listPages: []*dynamodb.ListTablesOutput{
			{
				TableNames:             []string{"table-page1"},
				LastEvaluatedTableName: ddbStrptr("table-page1"),
			},
			{
				TableNames: []string{"table-page2"},
				// no LastEvaluatedTableName -> last page
			},
		},
	}
	assets, err := DynamoDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.listCalls; c != 2 {
		t.Errorf("expected ListTables to be called 2 times (paginated), got %d", c)
	}
	got := ddbAssetByID(assets)
	for _, want := range []string{"table-page1", "table-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected table %q from a paginated page to appear as an asset; got %v", want, ddbKeys(got))
		}
	}
}

// TestDynamoDBScanListErrorPropagates verifies a top-level ListTables failure
// (denied/throttled) makes the scan VISIBLY incomplete by returning a non-nil
// error wrapping the failure — NOT a silent empty success.
func TestDynamoDBScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform dynamodb:ListTables")
	client := &fakeDynamoDBClient{listErr: sentinel}
	assets, err := DynamoDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListTables fails, got nil with %d assets", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListTables failure, got: %v", err)
	}
}

// TestDynamoDBScanDescribeErrorNotDropped verifies the batch-1 honesty fix: a
// per-table DescribeTable error must NOT silently drop the table. The table is
// still emitted, but as a PostureUnknown asset carrying a note — never omitted
// (which would read as a clean all-clear) and never a fabricated NoEncryption.
// A sibling healthy table on the same page must still be classified.
func TestDynamoDBScanDescribeErrorNotDropped(t *testing.T) {
	client := &fakeDynamoDBClient{
		listPages: []*dynamodb.ListTablesOutput{
			{TableNames: []string{"healthy", "denied"}},
		},
		describe: map[string]*dynamodb.DescribeTableOutput{
			"healthy": {Table: &ddbtypes.TableDescription{}},
		},
		describeErr: map[string]error{
			"denied": errors.New("AccessDeniedException: dynamodb:DescribeTable"),
		},
	}
	assets, err := DynamoDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := ddbAssetByID(assets)
	denied, ok := got["denied"]
	if !ok {
		t.Fatalf("table with DescribeTable error was silently dropped; assets=%v", ddbKeys(got))
	}
	if denied.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("describe-error table: expected posture %q, got %q", models.PostureUnknown, denied.Properties["posture"])
	}
	if denied.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Errorf("describe-error table must NEVER fabricate a NoEncryption false alarm; got %q", denied.Properties["posture"])
	}
	if denied.Properties["note"] == "" {
		t.Error("describe-error table: expected a note explaining the undetermined state, got empty")
	}
	if _, ok := got["healthy"]; !ok {
		t.Error("a sibling table's describe error should not affect the healthy table")
	}
}

// TestDynamoDBScanPostureMapping verifies the always-encrypted honesty rules for
// DynamoDB's at-rest domain:
//   - DynamoDB always encrypts at rest -> SymmetricOnly, never NoEncryption.
//   - A populated KMSMasterKeyArn (AWS-managed or customer CMK) is recorded as
//     kmsKeyId.
//   - An absent SSE description maps to the AWS-owned default key sentinel
//     (still encrypted; no clean all-clear and no NoEncryption).
//   - UPDATING is a normal key-rotation state and MUST NOT downgrade posture.
func TestDynamoDBScanPostureMapping(t *testing.T) {
	const cmkArn = "arn:aws:kms:us-east-1:111122223333:key/abcd-cmk"
	client := &fakeDynamoDBClient{
		listPages: []*dynamodb.ListTablesOutput{
			{TableNames: []string{"with-cmk", "owned-default", "updating"}},
		},
		describe: map[string]*dynamodb.DescribeTableOutput{
			"with-cmk": {Table: &ddbtypes.TableDescription{
				SSEDescription: &ddbtypes.SSEDescription{
					KMSMasterKeyArn: ddbStrptr(cmkArn),
					SSEType:         ddbtypes.SSETypeKms,
					Status:          ddbtypes.SSEStatusEnabled,
				},
			}},
			// no SSE description -> AWS-owned default key
			"owned-default": {Table: &ddbtypes.TableDescription{}},
			// UPDATING is a normal key-rotation state and MUST NOT downgrade posture
			"updating": {Table: &ddbtypes.TableDescription{
				SSEDescription: &ddbtypes.SSEDescription{
					KMSMasterKeyArn: ddbStrptr(cmkArn),
					Status:          ddbtypes.SSEStatusUpdating,
				},
			}},
		},
	}
	assets, err := DynamoDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := ddbAssetByID(assets)

	// Every table is always-encrypted: SymmetricOnly, never NoEncryption.
	for _, name := range []string{"with-cmk", "owned-default", "updating"} {
		a, ok := got[name]
		if !ok {
			t.Fatalf("expected asset for table %q; got %v", name, ddbKeys(got))
		}
		if a.Properties["posture"] == string(models.PostureNoEncryption) {
			t.Errorf("table %q: DynamoDB is always-encrypted; posture must never be NoEncryption", name)
		}
		if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
			t.Errorf("table %q: expected posture %q, got %q", name, models.PostureSymmetricOnly, a.Properties["posture"])
		}
	}

	// CMK present -> recorded as kmsKeyId.
	if got["with-cmk"].Properties["kmsKeyId"] != cmkArn {
		t.Errorf("with-cmk: expected kmsKeyId %q, got %q", cmkArn, got["with-cmk"].Properties["kmsKeyId"])
	}
	// Absent SSE -> AWS-owned default key sentinel (still encrypted, no all-clear).
	if got["owned-default"].Properties["kmsKeyId"] != "AWS_OWNED_KMS_KEY" {
		t.Errorf("owned-default: expected AWS-owned default key sentinel, got %q", got["owned-default"].Properties["kmsKeyId"])
	}
	// UPDATING must not downgrade posture (already asserted SymmetricOnly above);
	// confirm it is captured for evidence only.
	if got["updating"].Properties["sseStatus"] != string(ddbtypes.SSEStatusUpdating) {
		t.Errorf("updating: expected sseStatus %q captured for evidence, got %q", ddbtypes.SSEStatusUpdating, got["updating"].Properties["sseStatus"])
	}
}
