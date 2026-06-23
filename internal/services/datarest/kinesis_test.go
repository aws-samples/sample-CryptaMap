package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kintypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeKinesisClient is a hand-rolled kinesisAPI for unit-testing the scanner's
// pagination + per-stream error handling without a live AWS client. listPages is
// returned page-by-page (each ListStreams call consumes the next page) and
// HasMoreStreams/NextToken are wired so the scanner loops through every page;
// listErr forces a top-level ListStreams failure. summaries maps a stream name to
// its DescribeStreamSummary output, and describeErr (when set) forces every
// DescribeStreamSummary to fail.
type fakeKinesisClient struct {
	listPages   []*kinesis.ListStreamsOutput
	listCalls   int
	listErr     error
	summaries   map[string]*kinesis.DescribeStreamSummaryOutput
	describeErr error
}

func (f *fakeKinesisClient) ListStreams(ctx context.Context, in *kinesis.ListStreamsInput, optFns ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &kinesis.ListStreamsOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeKinesisClient) DescribeStreamSummary(ctx context.Context, in *kinesis.DescribeStreamSummaryInput, optFns ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if in.StreamName != nil {
		if out, ok := f.summaries[*in.StreamName]; ok {
			return out, nil
		}
	}
	// Default: a stream that exists but with no SSE configured (Kinesis at-rest
	// is opt-in; default EncryptionType is NONE).
	return &kinesis.DescribeStreamSummaryOutput{
		StreamDescriptionSummary: &kintypes.StreamDescriptionSummary{
			EncryptionType: kintypes.EncryptionTypeNone,
		},
	}, nil
}

// kinSptr/kinBptr are kinesis-test-local pointer helpers, uniquely named so this
// file is self-contained and never collides with sibling test helpers.
func kinSptr(s string) *string { return &s }
func kinBptr(b bool) *bool     { return &b }

// kmsSummary builds a DescribeStreamSummary output for a KMS-encrypted stream.
func kmsSummary() *kinesis.DescribeStreamSummaryOutput {
	return &kinesis.DescribeStreamSummaryOutput{
		StreamDescriptionSummary: &kintypes.StreamDescriptionSummary{
			EncryptionType: kintypes.EncryptionTypeKms,
		},
	}
}

// postureOf returns the recorded posture string for the asset with the given
// resource ID, or "" if not found.
func postureOf(assets []models.CryptoAsset, resourceID string) string {
	for _, a := range assets {
		if a.ResourceID == resourceID {
			return a.Properties["posture"]
		}
	}
	return ""
}

// TestKinesisScanPaginates verifies the ListStreams HasMoreStreams/NextToken
// loop: a fake returning 2 pages (HasMoreStreams=true + NextToken on page 1) must
// yield BOTH pages' streams as assets. Without the pagination loop, only the
// first page's stream survives — the commonest real bug.
func TestKinesisScanPaginates(t *testing.T) {
	client := &fakeKinesisClient{
		listPages: []*kinesis.ListStreamsOutput{
			{
				StreamNames:    []string{"stream-page1"},
				HasMoreStreams: kinBptr(true),
				NextToken:      kinSptr("tok-page2"),
			},
			{
				StreamNames:    []string{"stream-page2"},
				HasMoreStreams: kinBptr(false),
			},
		},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"stream-page1": kmsSummary(),
			"stream-page2": kmsSummary(),
		},
	}
	assets, err := KinesisScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListStreams to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"stream-page1", "stream-page2"} {
		if !got[want] {
			t.Errorf("expected stream %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestKinesisScanListErrorPropagates verifies a top-level ListStreams failure
// (denied/throttled) returns a non-nil error rather than an empty-success — a
// denied scan must be VISIBLY incomplete, not a clean all-clear.
func TestKinesisScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform kinesis:ListStreams")
	client := &fakeKinesisClient{listErr: sentinel}
	_, err := KinesisScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListStreams fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListStreams failure, got: %v", err)
	}
}

// TestKinesisScanDescribeErrorNotDropped verifies the honesty fix: a per-stream
// DescribeStreamSummary failure must NOT silently drop the stream. The stream is
// still accounted for as a PostureUnknown asset with an explanatory note — never
// omitted (false all-clear) and never fabricated as NoEncryption (false alarm).
func TestKinesisScanDescribeErrorNotDropped(t *testing.T) {
	client := &fakeKinesisClient{
		listPages: []*kinesis.ListStreamsOutput{
			{StreamNames: []string{"stream-denied"}, HasMoreStreams: kinBptr(false)},
		},
		describeErr: errors.New("AccessDeniedException: not authorized to perform kinesis:DescribeStreamSummary"),
	}
	assets, err := KinesisScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-stream describe error must not fail the whole scan, got: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected the un-describable stream to still be accounted for (1 asset), got %d", len(assets))
	}
	if got := postureOf(assets, "stream-denied"); got != string(models.PostureUnknown) {
		t.Errorf("expected PostureUnknown for an un-describable stream (no false all-clear, no false alarm), got %q", got)
	}
	if note := assets[0].Properties["note"]; note == "" {
		t.Errorf("expected a note explaining the undetermined at-rest state, got empty")
	}
}

// TestKinesisScanPostureMapping asserts the honesty posture mapping for Kinesis,
// whose at-rest SSE is OPT-IN (default OFF): a KMS-encrypted stream -> SymmetricOnly
// (never NoEncryption), and a stream with SSE genuinely off -> NoEncryption (which
// is correct here precisely because Kinesis does not encrypt at rest by default).
func TestKinesisScanPostureMapping(t *testing.T) {
	client := &fakeKinesisClient{
		listPages: []*kinesis.ListStreamsOutput{
			{StreamNames: []string{"stream-kms", "stream-off"}, HasMoreStreams: kinBptr(false)},
		},
		summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
			"stream-kms": kmsSummary(),
			"stream-off": {
				StreamDescriptionSummary: &kintypes.StreamDescriptionSummary{
					EncryptionType: kintypes.EncryptionTypeNone,
				},
			},
		},
	}
	assets, err := KinesisScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if got := postureOf(assets, "stream-kms"); got != string(models.PostureSymmetricOnly) {
		t.Errorf("KMS-encrypted stream: expected SymmetricOnly, got %q", got)
	}
	if got := postureOf(assets, "stream-off"); got != string(models.PostureNoEncryption) {
		t.Errorf("SSE-off stream (opt-in encryption genuinely disabled): expected NoEncryption, got %q", got)
	}
}
