package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeSQSClient is a hand-rolled sqsAPI for unit-testing the scanner's pagination,
// error propagation, and posture classification without a live AWS client.
// listPages is returned page-by-page (each call consumes the next page) with its
// NextToken wired so the scanner loops through every page; attrsByURL maps a queue
// URL to the attributes GetQueueAttributes returns, and attrsErrByURL forces a
// per-queue GetQueueAttributes failure.
type fakeSQSClient struct {
	listPages     []*sqs.ListQueuesOutput
	listCalls     int
	listErr       error
	attrsByURL    map[string]map[string]string
	attrsErrByURL map[string]error
}

func (f *fakeSQSClient) ListQueues(ctx context.Context, in *sqs.ListQueuesInput, optFns ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &sqs.ListQueuesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeSQSClient) GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	url := ""
	if in.QueueUrl != nil {
		url = *in.QueueUrl
	}
	if err, ok := f.attrsErrByURL[url]; ok {
		return nil, err
	}
	if attrs, ok := f.attrsByURL[url]; ok {
		return &sqs.GetQueueAttributesOutput{Attributes: attrs}, nil
	}
	// No attributes returned at all (neither key present).
	return &sqs.GetQueueAttributesOutput{}, nil
}

func sqsStrptr(s string) *string { return &s }

// sqsAssetByID is a small helper to locate a produced asset by resource ID.
func sqsAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestSQSScanPaginatesQueues verifies the ListQueues NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' queues as assets.
// Without the pagination loop, only the first page's queue survives.
func TestSQSScanPaginatesQueues(t *testing.T) {
	const q1 = "https://sqs.us-east-1.amazonaws.com/111122223333/queue-page1"
	const q2 = "https://sqs.us-east-1.amazonaws.com/111122223333/queue-page2"
	client := &fakeSQSClient{
		listPages: []*sqs.ListQueuesOutput{
			{
				QueueUrls: []string{q1},
				NextToken: sqsStrptr("tok-page2"),
			},
			{
				QueueUrls: []string{q2},
				// no NextToken -> last page
			},
		},
		attrsByURL: map[string]map[string]string{
			q1: {"SqsManagedSseEnabled": "true"},
			q2: {"SqsManagedSseEnabled": "true"},
		},
	}
	assets, err := SQSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListQueues to be called 2 times (paginated), got %d", client.listCalls)
	}
	for _, want := range []string{"queue-page1", "queue-page2"} {
		if _, ok := sqsAssetByID(assets, want); !ok {
			t.Errorf("expected queue %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestSQSScanListErrorPropagates verifies a top-level ListQueues failure
// (denied/rate-limited) makes the scan VISIBLY incomplete by returning a non-nil
// error — NOT a silent empty success.
func TestSQSScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform sqs:ListQueues")
	client := &fakeSQSClient{listErr: sentinel}
	_, err := SQSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListQueues fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListQueues failure, got: %v", err)
	}
}

// TestSQSScanGetAttributesErrorNotDropped verifies the honesty fix: a per-queue
// GetQueueAttributes failure must NOT silently drop the queue. The queue is still
// recorded — as PostureUnknown with an explanatory note — so a denied attribute
// read is visible rather than vanishing.
func TestSQSScanGetAttributesErrorNotDropped(t *testing.T) {
	const q = "https://sqs.us-east-1.amazonaws.com/111122223333/denied-queue"
	client := &fakeSQSClient{
		listPages: []*sqs.ListQueuesOutput{
			{QueueUrls: []string{q}},
		},
		attrsErrByURL: map[string]error{
			q: errors.New("AccessDeniedException: not authorized to perform sqs:GetQueueAttributes"),
		},
	}
	assets, err := SQSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := sqsAssetByID(assets, "denied-queue")
	if !ok {
		t.Fatalf("queue with unreadable attributes was dropped; expected it recorded as Unknown; assets=%v", assets)
	}
	if a.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("expected posture %q for unreadable attributes, got %q", models.PostureUnknown, a.Properties["posture"])
	}
	if a.Properties["note"] == "" {
		t.Errorf("expected an explanatory note for unreadable attributes, got none")
	}
}

// TestSQSScanPostureClassification verifies the at-rest honesty mapping across the
// scanner's domain:
//   - KMS key present -> SymmetricOnly, kmsKeyId recorded;
//   - SqsManagedSseEnabled=true (no CMK) -> SymmetricOnly, AWS-managed default key
//     recorded WITHOUT claiming a customer key;
//   - SqsManagedSseEnabled=false (no CMK) -> genuine NoEncryption (SSE turned off);
//   - neither attribute returned -> Unknown (no clean all-clear), with a note.
func TestSQSScanPostureClassification(t *testing.T) {
	const (
		qKMS     = "https://sqs.us-east-1.amazonaws.com/111122223333/kms-queue"
		qSSE     = "https://sqs.us-east-1.amazonaws.com/111122223333/sse-queue"
		qOff     = "https://sqs.us-east-1.amazonaws.com/111122223333/off-queue"
		qSilent  = "https://sqs.us-east-1.amazonaws.com/111122223333/silent-queue"
		cmkKeyID = "arn:aws:kms:us-east-1:111122223333:key/abc-123"
	)
	client := &fakeSQSClient{
		listPages: []*sqs.ListQueuesOutput{
			{QueueUrls: []string{qKMS, qSSE, qOff, qSilent}},
		},
		attrsByURL: map[string]map[string]string{
			qKMS: {"KmsMasterKeyId": cmkKeyID},
			qSSE: {"SqsManagedSseEnabled": "true"},
			qOff: {"SqsManagedSseEnabled": "false"},
			// qSilent: no attributes returned at all.
		},
	}
	assets, err := SQSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	cases := []struct {
		id          string
		wantPosture models.CryptoPosture
		wantKMS     string // exact kmsKeyId expected, "" means must be absent
		wantNote    bool
	}{
		{"kms-queue", models.PostureSymmetricOnly, cmkKeyID, false},
		{"sse-queue", models.PostureSymmetricOnly, "alias/aws/sqs", false},
		{"off-queue", models.PostureNoEncryption, "", false},
		{"silent-queue", models.PostureUnknown, "", true},
	}
	for _, c := range cases {
		a, ok := sqsAssetByID(assets, c.id)
		if !ok {
			t.Errorf("%s: expected an asset, none produced", c.id)
			continue
		}
		if got := a.Properties["posture"]; got != string(c.wantPosture) {
			t.Errorf("%s: expected posture %q, got %q", c.id, c.wantPosture, got)
		}
		gotKMS := a.Properties["kmsKeyId"]
		if c.wantKMS == "" {
			if gotKMS != "" {
				t.Errorf("%s: expected no kmsKeyId, got %q", c.id, gotKMS)
			}
		} else if gotKMS != c.wantKMS {
			t.Errorf("%s: expected kmsKeyId %q, got %q", c.id, c.wantKMS, gotKMS)
		}
		hasNote := a.Properties["note"] != ""
		if hasNote != c.wantNote {
			t.Errorf("%s: expected note-present=%v, got note=%q", c.id, c.wantNote, a.Properties["note"])
		}
	}
}
