package datarest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeAmazonMQClient is a hand-rolled amazonMQAPI for unit-testing the scanner's
// pagination + error propagation + key-tier classification without a live AWS
// client. listPages is returned page-by-page (each ListBrokers call consumes the
// next page) with NextToken wired so the scanner loops through every page;
// listErr forces a top-level ListBrokers failure. describeByID returns a canned
// DescribeBroker output per broker id, and describeErrByID forces a per-broker
// DescribeBroker failure.
type fakeAmazonMQClient struct {
	listPages       []*mq.ListBrokersOutput
	listCalls       int
	listErr         error
	describeByID    map[string]*mq.DescribeBrokerOutput
	describeErrByID map[string]error
}

func (f *fakeAmazonMQClient) ListBrokers(ctx context.Context, in *mq.ListBrokersInput, optFns ...func(*mq.Options)) (*mq.ListBrokersOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &mq.ListBrokersOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeAmazonMQClient) DescribeBroker(ctx context.Context, in *mq.DescribeBrokerInput, optFns ...func(*mq.Options)) (*mq.DescribeBrokerOutput, error) {
	id := ""
	if in.BrokerId != nil {
		id = *in.BrokerId
	}
	if err, ok := f.describeErrByID[id]; ok {
		return nil, err
	}
	if out, ok := f.describeByID[id]; ok {
		return out, nil
	}
	return &mq.DescribeBrokerOutput{}, nil
}

func mqSP(s string) *string { return &s }

// mqIndexByResourceID maps every emitted asset by its ResourceID for assertion.
func mqIndexByResourceID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestAmazonMQScanPaginates verifies the ListBrokers NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' brokers as assets.
// Without the pagination loop, only the first page's broker survives — the single
// commonest real scanner bug.
func TestAmazonMQScanPaginates(t *testing.T) {
	client := &fakeAmazonMQClient{
		listPages: []*mq.ListBrokersOutput{
			{
				BrokerSummaries: []mqtypes.BrokerSummary{{BrokerId: mqSP("b-page1")}},
				NextToken:       mqSP("tok-page2"),
			},
			{
				BrokerSummaries: []mqtypes.BrokerSummary{{BrokerId: mqSP("b-page2")}},
				// no NextToken -> last page
			},
		},
		describeByID: map[string]*mq.DescribeBrokerOutput{
			"b-page1": {EngineType: mqtypes.EngineTypeActivemq},
			"b-page2": {EngineType: mqtypes.EngineTypeRabbitmq},
		},
	}
	assets, err := AmazonMQScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListBrokers to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := mqIndexByResourceID(assets)
	for _, want := range []string{"b-page1", "b-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected broker %q from a paginated page to appear as an asset; got %v", want, mqKeys(got))
		}
	}
}

// TestAmazonMQScanListErrorPropagates verifies that a top-level ListBrokers failure
// (denied/rate-limited) makes the scan VISIBLY incomplete by returning a non-nil
// error wrapping the cause — NOT a silent empty success.
func TestAmazonMQScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform mq:ListBrokers")
	client := &fakeAmazonMQClient{listErr: sentinel}
	_, err := AmazonMQScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListBrokers fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListBrokers failure, got: %v", err)
	}
}

// TestAmazonMQScanDescribeErrorNotDropped verifies the HONESTY CONTRACT for a
// per-broker DescribeBroker failure: the broker is known to exist (it came back
// from ListBrokers) so it must NOT be silently dropped, and must NOT be emitted as
// a clean AWS-owned-key SymmetricOnly default (a false-safe). It must surface as a
// PostureUnknown asset carrying an explanatory note.
func TestAmazonMQScanDescribeErrorNotDropped(t *testing.T) {
	client := &fakeAmazonMQClient{
		listPages: []*mq.ListBrokersOutput{
			{BrokerSummaries: []mqtypes.BrokerSummary{{BrokerId: mqSP("b-denied"), BrokerName: mqSP("mybroker")}}},
		},
		describeErrByID: map[string]error{
			"b-denied": errors.New("ForbiddenException: not authorized to perform mq:DescribeBroker"),
		},
	}
	assets, err := AmazonMQScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := mqIndexByResourceID(assets)
	a, ok := got["b-denied"]
	if !ok {
		t.Fatalf("broker with a failed DescribeBroker was silently dropped; assets=%v", mqKeys(got))
	}
	if a.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("posture for un-describable broker = %q, want %q (must not be a clean SymmetricOnly false-safe)", a.Properties["posture"], models.PostureUnknown)
	}
	if note := a.Properties["note"]; !strings.Contains(strings.ToLower(note), "undetermined") {
		t.Errorf("un-describable broker must carry an undetermined-custody note; got note=%q", note)
	}
	// It must NOT be presented as a clean AWS-owned-key default.
	if a.Properties["kmsKeyId"] == "AWS_OWNED_KMS_KEY" {
		t.Errorf("un-describable broker must not be stamped with the clean AWS_OWNED_KMS_KEY default (false-safe)")
	}
}

// TestAmazonMQScanKeyTierClassification verifies the at-rest posture/key-tier
// HONESTY mapping. Amazon MQ always encrypts at rest with AES (no off switch), so
// posture is unconditionally SymmetricOnly — NEVER NoEncryption — and only the KEY
// TIER varies:
//   - EncryptionOptions.KmsKeyId set  -> that CMK ARN is recorded verbatim;
//   - EncryptionOptions absent/empty  -> AWS-owned key default sentinel, still
//     encrypted (recorded, not a no-encryption finding).
func TestAmazonMQScanKeyTierClassification(t *testing.T) {
	cmkARN := "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456"
	client := &fakeAmazonMQClient{
		listPages: []*mq.ListBrokersOutput{
			{BrokerSummaries: []mqtypes.BrokerSummary{
				{BrokerId: mqSP("b-cmk"), BrokerName: mqSP("withcmk")},
				{BrokerId: mqSP("b-owned"), BrokerName: mqSP("ownedkey")},
			}},
		},
		describeByID: map[string]*mq.DescribeBrokerOutput{
			"b-cmk": {
				EngineType:        mqtypes.EngineTypeActivemq,
				EncryptionOptions: &mqtypes.EncryptionOptions{KmsKeyId: &cmkARN},
			},
			// AWS-owned key: no EncryptionOptions at all -> default sentinel, still encrypted.
			"b-owned": {EngineType: mqtypes.EngineTypeRabbitmq},
		},
	}
	assets, err := AmazonMQScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := mqIndexByResourceID(assets)

	cmk, ok := got["b-cmk"]
	if !ok {
		t.Fatalf("CMK broker missing from assets; got %v", mqKeys(got))
	}
	if cmk.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("CMK broker posture = %q, want %q (MQ is always AES at rest)", cmk.Properties["posture"], models.PostureSymmetricOnly)
	}
	if cmk.Properties["kmsKeyId"] != cmkARN {
		t.Errorf("CMK broker kmsKeyId = %q, want the CMK ARN %q", cmk.Properties["kmsKeyId"], cmkARN)
	}

	owned, ok := got["b-owned"]
	if !ok {
		t.Fatalf("AWS-owned-key broker missing from assets; got %v", mqKeys(got))
	}
	if owned.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("AWS-owned broker posture = %q, want %q — absent EncryptionOptions is the AWS-owned key, NOT no-encryption", owned.Properties["posture"], models.PostureSymmetricOnly)
	}
	if owned.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Errorf("AWS-owned broker must never be classified as no-encryption (MQ has no at-rest off switch)")
	}
	if owned.Properties["kmsKeyId"] != "AWS_OWNED_KMS_KEY" {
		t.Errorf("AWS-owned broker kmsKeyId = %q, want the AWS_OWNED_KMS_KEY default sentinel (still encrypted)", owned.Properties["kmsKeyId"])
	}
}

func mqKeys(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
