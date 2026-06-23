package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeCWLogsClient is a hand-rolled cwLogsAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) with NextToken wired so the
// scanner loops through every page; err forces a DescribeLogGroups failure.
type fakeCWLogsClient struct {
	pages []*cloudwatchlogs.DescribeLogGroupsOutput
	calls int
	err   error
}

func (f *fakeCWLogsClient) DescribeLogGroups(ctx context.Context, in *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &cloudwatchlogs.DescribeLogGroupsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func cwStrptr(s string) *string { return &s }

// TestCloudWatchLogsScanPaginates verifies the DescribeLogGroups NextToken loop:
// a fake that returns 2 pages (NextToken on page 1) must yield BOTH pages' log
// groups as assets. Without the pagination loop, only the first page survives —
// the commonest real-world scanner bug in dense accounts.
func TestCloudWatchLogsScanPaginates(t *testing.T) {
	client := &fakeCWLogsClient{
		pages: []*cloudwatchlogs.DescribeLogGroupsOutput{
			{
				LogGroups: []cwltypes.LogGroup{{LogGroupName: cwStrptr("/aws/lambda/page1")}},
				NextToken: cwStrptr("tok-page2"),
			},
			{
				LogGroups: []cwltypes.LogGroup{{LogGroupName: cwStrptr("/aws/lambda/page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := CloudWatchLogsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected DescribeLogGroups to be called 2 times (paginated), got %d", c)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"/aws/lambda/page1", "/aws/lambda/page2"} {
		if !got[want] {
			t.Errorf("expected log group %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestCloudWatchLogsScanErrorPropagates verifies the owner's incompleteness
// decision: a DescribeLogGroups failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestCloudWatchLogsScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform logs:DescribeLogGroups")
	client := &fakeCWLogsClient{err: sentinel}
	assets, err := CloudWatchLogsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when DescribeLogGroups fails, got nil (silent empty success); assets=%v", assets)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeLogGroups failure, got: %v", err)
	}
}

// TestCloudWatchLogsScanHonestyPosture verifies the at-rest honesty mapping for
// CloudWatch Logs: every log group is AES-256-GCM encrypted at rest and the
// encryption cannot be disabled, so posture is UNCONDITIONALLY SymmetricOnly —
// never NoEncryption. The KmsKeyId field selects key tier only: a CMK when present
// is recorded verbatim; when absent the asset records the AWS-owned default key
// (NOT a no-encryption / clean all-clear).
func TestCloudWatchLogsScanHonestyPosture(t *testing.T) {
	const cmkARN = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	client := &fakeCWLogsClient{
		pages: []*cloudwatchlogs.DescribeLogGroupsOutput{
			{
				LogGroups: []cwltypes.LogGroup{
					{LogGroupName: cwStrptr("/with/cmk"), KmsKeyId: cwStrptr(cmkARN)},
					{LogGroupName: cwStrptr("/no/cmk")}, // KmsKeyId nil -> AWS-owned default
				},
			},
		},
	}
	assets, err := CloudWatchLogsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}

	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}

	// Both log groups: SymmetricOnly, never NoEncryption. PostureProperty records
	// the posture in Properties["posture"] (the asset has no top-level field).
	for _, id := range []string{"/with/cmk", "/no/cmk"} {
		a, ok := byID[id]
		if !ok {
			t.Fatalf("missing asset for log group %q", id)
		}
		posture := a.Properties["posture"]
		if posture != string(models.PostureSymmetricOnly) {
			t.Errorf("log group %q: expected posture %q (always AES-256 at rest), got %q",
				id, models.PostureSymmetricOnly, posture)
		}
		if posture == string(models.PostureNoEncryption) {
			t.Errorf("log group %q: posture must NEVER be NoEncryption (encryption cannot be disabled)", id)
		}
	}

	// CMK present -> recorded verbatim.
	if got := byID["/with/cmk"].Properties["kmsKeyId"]; got != cmkARN {
		t.Errorf("expected CMK ARN %q recorded for /with/cmk, got %q", cmkARN, got)
	}
	// CMK absent -> AWS-owned default key recorded, NOT empty / NOT a clean all-clear.
	if got := byID["/no/cmk"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("expected AWS-owned default key recorded for /no/cmk, got %q", got)
	}
}
