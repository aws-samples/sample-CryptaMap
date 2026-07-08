package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
	tstypes "github.com/aws/aws-sdk-go-v2/service/timestreamwrite/types"
	"github.com/aws/smithy-go"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestIsTimestreamNotSubscribed pins the graceful-skip predicate to the TYPED
// AccessDeniedException carrying the exact documented "Only existing Timestream"
// message. Anything looser (substring matches on the flattened error text) would
// also swallow GENUINE IAM/SCP denials for real Timestream customers — silently
// converting their inventory into a clean empty success.
func TestIsTimestreamNotSubscribed(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{
			"typed-not-subscribed",
			&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "Only existing Timestream for LiveAnalytics customers can use this operation"},
			true,
		},
		{
			// A GENUINE SCP/IAM deny that happens to mention both "AccessDenied" and
			// "LiveAnalytics" must NOT be treated as not-subscribed (real customer,
			// real permission failure -> must stay a hard error).
			"genuine-scp-deny-mentioning-liveanalytics",
			&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "User arn:aws:iam::111122223333:role/scan is not authorized to perform timestream:ListDatabases on Timestream for LiveAnalytics with an explicit deny in an SCP"},
			false,
		},
		{
			// Untyped error text embedding the phrase must not skip either: only the
			// typed API error is trusted.
			"untyped-string-only",
			errors.New("AccessDeniedException: Only existing Timestream customers can use this operation"),
			false,
		},
		{
			"other-code-with-phrase",
			&smithy.GenericAPIError{Code: "ValidationException", Message: "Only existing Timestream customers can use this operation"},
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTimestreamNotSubscribed(c.err); got != c.want {
				t.Errorf("isTimestreamNotSubscribed(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// fakeTimestreamClient is a hand-rolled timestreamWriteAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err (when set) is returned on
// the first call to drive the error paths.
type fakeTimestreamClient struct {
	pages []*timestreamwrite.ListDatabasesOutput
	calls int
	err   error
}

func (f *fakeTimestreamClient) ListDatabases(ctx context.Context, in *timestreamwrite.ListDatabasesInput, optFns ...func(*timestreamwrite.Options)) (*timestreamwrite.ListDatabasesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &timestreamwrite.ListDatabasesOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func tsstr(s string) *string { return &s }

// TestTimestreamScanPaginates verifies the ListDatabases NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' databases as
// assets. Without the pagination loop, only the first page's database survives
// (the commonest real bug in dense accounts).
func TestTimestreamScanPaginates(t *testing.T) {
	client := &fakeTimestreamClient{
		pages: []*timestreamwrite.ListDatabasesOutput{
			{
				Databases: []tstypes.Database{{DatabaseName: tsstr("db-page1")}},
				NextToken: tsstr("tok-page2"),
			},
			{
				Databases: []tstypes.Database{{DatabaseName: tsstr("db-page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := TimestreamScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListDatabases to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"db-page1", "db-page2"} {
		if !got[want] {
			t.Errorf("expected database %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestTimestreamScanListErrorPropagates verifies the owner's incompleteness
// decision: a genuine ListDatabases failure (denied/rate-limited for an account
// that DOES use Timestream) must make the scan VISIBLY incomplete by returning a
// non-nil error wrapping the cause — NOT a silent empty success.
func TestTimestreamScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform timestream:ListDatabases")
	client := &fakeTimestreamClient{err: sentinel}
	assets, err := TimestreamScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListDatabases fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListDatabases failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a hard list error, got %d", len(assets))
	}
}

// TestTimestreamScanNotSubscribedSkips verifies the graceful service-not-in-use
// skip: the specific "Only existing Timestream" AccessDenied (account is not a
// Timestream-for-LiveAnalytics customer) must yield zero assets and nil error,
// NOT a hard error that flags the whole (account,region) shard as errored.
func TestTimestreamScanNotSubscribedSkips(t *testing.T) {
	notSub := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "Only existing Timestream for LiveAnalytics customers can use this operation"}
	client := &fakeTimestreamClient{err: notSub}
	assets, err := TimestreamScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("expected not-subscribed AccessDenied to be a graceful skip (nil error), got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected zero assets on a not-subscribed skip, got %d", len(assets))
	}
}

// TestTimestreamScanHonestyPosture verifies the at-rest honesty mapping for
// Timestream, whose encryption is always-on AES-256 (cannot be disabled):
//   - posture is SymmetricOnly, NEVER NoEncryption (no false-alarm);
//   - a present customer CMK is recorded verbatim in kmsKeyId;
//   - an absent KmsKeyId is recorded as the AWS-owned/managed default key
//     (AWS_OWNED_KMS_KEY), NOT a blank/clean all-clear and NOT no-encryption.
func TestTimestreamScanHonestyPosture(t *testing.T) {
	client := &fakeTimestreamClient{
		pages: []*timestreamwrite.ListDatabasesOutput{
			{
				Databases: []tstypes.Database{
					{DatabaseName: tsstr("db-cmk"), KmsKeyId: tsstr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
					{DatabaseName: tsstr("db-default")}, // no KmsKeyId -> AWS-owned default
				},
			},
		},
	}
	assets, err := TimestreamScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
		if a.Properties["posture"] == string(models.PostureNoEncryption) {
			t.Errorf("database %q classified NoEncryption; Timestream at-rest is always-on AES-256 and must never be NoEncryption", a.ResourceID)
		}
		if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
			t.Errorf("database %q expected posture SymmetricOnly, got %q", a.ResourceID, a.Properties["posture"])
		}
	}

	cmk, ok := byID["db-cmk"]
	if !ok {
		t.Fatal("expected db-cmk asset to be present")
	}
	if got := cmk.Properties["kmsKeyId"]; got != "arn:aws:kms:us-east-1:111122223333:key/abc-123" {
		t.Errorf("expected present CMK to be recorded verbatim in kmsKeyId, got %q", got)
	}

	def, ok := byID["db-default"]
	if !ok {
		t.Fatal("expected db-default asset to be present")
	}
	if got := def.Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("expected absent KmsKeyId to record the AWS-owned/managed default key (AWS_OWNED_KMS_KEY), got %q", got)
	}
}
