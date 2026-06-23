package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	fhtypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeFirehoseClient is a hand-rolled firehoseAPI for unit-testing the scanner's
// name-cursor pagination, top-level error propagation, and per-stream
// describe-error handling without a live AWS client.
//
// listPages is returned page-by-page (each ListDeliveryStreams call consumes the
// next page); HasMoreDeliveryStreams on a page wires the scanner to loop.
// listErr forces a top-level ListDeliveryStreams failure. describeByName maps a
// stream name to a canned DescribeDeliveryStream output; describeErrFor names a
// stream whose Describe must fail (to exercise the no-silent-drop path).
type fakeFirehoseClient struct {
	listPages      []*firehose.ListDeliveryStreamsOutput
	listCalls      int
	listErr        error
	describeByName map[string]*firehose.DescribeDeliveryStreamOutput
	describeErrFor map[string]error
	describeCalls  int
}

func (f *fakeFirehoseClient) ListDeliveryStreams(ctx context.Context, in *firehose.ListDeliveryStreamsInput, optFns ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &firehose.ListDeliveryStreamsOutput{HasMoreDeliveryStreams: aws.Bool(false)}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeFirehoseClient) DescribeDeliveryStream(ctx context.Context, in *firehose.DescribeDeliveryStreamInput, optFns ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error) {
	f.describeCalls++
	name := ""
	if in.DeliveryStreamName != nil {
		name = *in.DeliveryStreamName
	}
	if err, ok := f.describeErrFor[name]; ok {
		return nil, err
	}
	if out, ok := f.describeByName[name]; ok {
		return out, nil
	}
	// Default: a stream with no encryption configuration at all (SSE never enabled).
	return &firehose.DescribeDeliveryStreamOutput{
		DeliveryStreamDescription: &fhtypes.DeliveryStreamDescription{},
	}, nil
}

func enabledDescribe(name, keyType, keyARN string) *firehose.DescribeDeliveryStreamOutput {
	return &firehose.DescribeDeliveryStreamOutput{
		DeliveryStreamDescription: &fhtypes.DeliveryStreamDescription{
			DeliveryStreamType: fhtypes.DeliveryStreamTypeDirectPut,
			DeliveryStreamEncryptionConfiguration: &fhtypes.DeliveryStreamEncryptionConfiguration{
				Status:  fhtypes.DeliveryStreamEncryptionStatusEnabled,
				KeyType: fhtypes.KeyType(keyType),
				KeyARN:  strPtrFH(keyARN),
			},
		},
	}
}

func disabledDescribe(name string) *firehose.DescribeDeliveryStreamOutput {
	return &firehose.DescribeDeliveryStreamOutput{
		DeliveryStreamDescription: &fhtypes.DeliveryStreamDescription{
			DeliveryStreamType: fhtypes.DeliveryStreamTypeDirectPut,
			DeliveryStreamEncryptionConfiguration: &fhtypes.DeliveryStreamEncryptionConfiguration{
				Status: fhtypes.DeliveryStreamEncryptionStatusDisabled,
			},
		},
	}
}

func strPtrFH(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func fhAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestFirehoseScanPaginates verifies the name-based cursor loop: a fake that
// returns 2 pages (HasMoreDeliveryStreams=true on page 1) must yield BOTH pages'
// streams as assets. Without the pagination loop, only page 1's streams survive
// (the commonest real bug for dense accounts).
func TestFirehoseScanPaginates(t *testing.T) {
	client := &fakeFirehoseClient{
		listPages: []*firehose.ListDeliveryStreamsOutput{
			{
				DeliveryStreamNames:    []string{"stream-page1"},
				HasMoreDeliveryStreams: aws.Bool(true),
			},
			{
				DeliveryStreamNames:    []string{"stream-page2"},
				HasMoreDeliveryStreams: aws.Bool(false),
			},
		},
		describeByName: map[string]*firehose.DescribeDeliveryStreamOutput{
			"stream-page1": enabledDescribe("stream-page1", "AWS_OWNED_CMK", ""),
			"stream-page2": disabledDescribe("stream-page2"),
		},
	}

	assets, err := FirehoseScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListDeliveryStreams to be called 2 times (paginated), got %d", client.listCalls)
	}
	for _, want := range []string{"stream-page1", "stream-page2"} {
		if _, ok := fhAssetByID(assets, want); !ok {
			t.Errorf("expected stream %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestFirehoseScanListErrorPropagates verifies a top-level ListDeliveryStreams
// failure (denied/throttled) returns a non-nil error rather than a silent empty
// success — keeping a partial scan VISIBLY incomplete.
func TestFirehoseScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform firehose:ListDeliveryStreams")
	client := &fakeFirehoseClient{listErr: sentinel}

	_, err := FirehoseScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListDeliveryStreams fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListDeliveryStreams failure, got: %v", err)
	}
}

// TestFirehoseScanDescribeErrorNotDropped verifies the honesty fix: a per-stream
// DescribeDeliveryStream failure must NOT silently drop the stream. The stream is
// still emitted as a PostureUnknown asset with a note — never vanished (which
// would be an all-clear by omission) and never stamped as a false NoEncryption.
func TestFirehoseScanDescribeErrorNotDropped(t *testing.T) {
	client := &fakeFirehoseClient{
		listPages: []*firehose.ListDeliveryStreamsOutput{
			{
				DeliveryStreamNames:    []string{"stream-denied"},
				HasMoreDeliveryStreams: aws.Bool(false),
			},
		},
		describeErrFor: map[string]error{
			"stream-denied": errors.New("AccessDeniedException: firehose:DescribeDeliveryStream"),
		},
	}

	assets, err := FirehoseScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-stream Describe error must not fail the whole scan; got: %v", err)
	}
	a, ok := fhAssetByID(assets, "stream-denied")
	if !ok {
		t.Fatal("expected stream-denied to still be emitted as an asset (not silently dropped)")
	}
	if got := a.Properties["posture"]; got != string(models.PostureUnknown) {
		t.Errorf("expected PostureUnknown on a stream whose Describe failed, got posture=%q", got)
	}
	if a.Properties["note"] == "" {
		t.Errorf("expected a note explaining the undetermined at-rest state, got empty")
	}
}

// TestFirehoseScanPostureMapping locks the honesty posture mapping for the
// Firehose domain (opt-in, Type-B SSE):
//   - ENABLED with a customer-managed CMK -> SymmetricOnly, CMK ARN recorded.
//   - genuinely DISABLED -> NoEncryption with an honest interim-buffer note (a
//     real finding, not a false alarm — SSE is off).
//   - no encryption config at all -> NoEncryption (never silently treated as safe).
func TestFirehoseScanPostureMapping(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	client := &fakeFirehoseClient{
		listPages: []*firehose.ListDeliveryStreamsOutput{
			{
				DeliveryStreamNames:    []string{"stream-enabled-cmk", "stream-disabled", "stream-noconfig"},
				HasMoreDeliveryStreams: aws.Bool(false),
			},
		},
		describeByName: map[string]*firehose.DescribeDeliveryStreamOutput{
			"stream-enabled-cmk": enabledDescribe("stream-enabled-cmk", "CUSTOMER_MANAGED_CMK", cmk),
			"stream-disabled":    disabledDescribe("stream-disabled"),
			// stream-noconfig falls through to the fake default (no encryption config).
		},
	}

	assets, err := FirehoseScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	enabled, ok := fhAssetByID(assets, "stream-enabled-cmk")
	if !ok {
		t.Fatal("missing stream-enabled-cmk asset")
	}
	if got := enabled.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("ENABLED stream: expected SymmetricOnly (AES-256 KMS envelope, not quantum-vulnerable), got %q", got)
	}
	if got := enabled.Properties["kmsKeyId"]; got != cmk {
		t.Errorf("ENABLED stream: expected CMK ARN %q recorded, got %q", cmk, got)
	}
	if got := enabled.Properties["keyType"]; got != "CUSTOMER_MANAGED_CMK" {
		t.Errorf("ENABLED stream: expected keyType CUSTOMER_MANAGED_CMK recorded, got %q", got)
	}

	disabled, ok := fhAssetByID(assets, "stream-disabled")
	if !ok {
		t.Fatal("missing stream-disabled asset")
	}
	if got := disabled.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("DISABLED stream: SSE genuinely off is a real NoEncryption finding, got %q", got)
	}
	if disabled.Properties["note"] == "" {
		t.Errorf("DISABLED stream: expected an honest interim-buffer note, got empty")
	}

	noconfig, ok := fhAssetByID(assets, "stream-noconfig")
	if !ok {
		t.Fatal("missing stream-noconfig asset")
	}
	if got := noconfig.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("no-config stream: opt-in SSE never enabled is NoEncryption, got %q", got)
	}
}
