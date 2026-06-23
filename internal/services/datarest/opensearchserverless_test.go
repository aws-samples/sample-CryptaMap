package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	osstypes "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeOSSClient is a hand-rolled ossCollectionsAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. listPages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so the
// scanner loops through every page; listErr forces a ListCollections failure.
type fakeOSSClient struct {
	listPages []*opensearchserverless.ListCollectionsOutput
	calls     int
	listErr   error
}

func (f *fakeOSSClient) ListCollections(ctx context.Context, in *opensearchserverless.ListCollectionsInput, optFns ...func(*opensearchserverless.Options)) (*opensearchserverless.ListCollectionsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.calls >= len(f.listPages) {
		return &opensearchserverless.ListCollectionsOutput{}, nil
	}
	out := f.listPages[f.calls]
	f.calls++
	return out, nil
}

func ossStrptr(s string) *string { return &s }

// TestOSSScanPaginates verifies the ListCollections NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' collections as
// assets. Without the pagination loop, only the first page's collection survives.
func TestOSSScanPaginates(t *testing.T) {
	client := &fakeOSSClient{
		listPages: []*opensearchserverless.ListCollectionsOutput{
			{
				CollectionSummaries: []osstypes.CollectionSummary{
					{Name: ossStrptr("coll-page1"), Arn: ossStrptr("arn:aws:aoss:us-east-1:111122223333:collection/c1")},
				},
				NextToken: ossStrptr("tok-page2"),
			},
			{
				CollectionSummaries: []osstypes.CollectionSummary{
					{Name: ossStrptr("coll-page2"), Arn: ossStrptr("arn:aws:aoss:us-east-1:111122223333:collection/c2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := OpenSearchServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListCollections to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.Properties["collectionName"]] = true
	}
	for _, want := range []string{"coll-page1", "coll-page2"} {
		if !got[want] {
			t.Errorf("expected collection %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestOSSScanListErrorPropagates verifies the owner's incompleteness decision: a
// ListCollections failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestOSSScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform aoss:ListCollections")
	client := &fakeOSSClient{listErr: sentinel}
	_, err := OpenSearchServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListCollections fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListCollections failure, got: %v", err)
	}
}

// TestOSSScanHonestyPosture verifies the at-rest honesty mapping for OpenSearch
// Serverless. Every collection is always encrypted at rest (AES-256 via KMS,
// encryption policy required at creation), so:
//   - posture is unconditionally SymmetricOnly, NEVER NoEncryption;
//   - a CMK present (KmsKeyArn set) is recorded verbatim in kmsKeyId;
//   - a CMK absent maps to the AWS-owned default key WITHOUT being a clean
//     all-clear (the kmsKeyId is the sentinel, posture stays SymmetricOnly).
func TestOSSScanHonestyPosture(t *testing.T) {
	cmkArn := "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	client := &fakeOSSClient{
		listPages: []*opensearchserverless.ListCollectionsOutput{
			{
				CollectionSummaries: []osstypes.CollectionSummary{
					{
						Name:      ossStrptr("with-cmk"),
						Arn:       ossStrptr("arn:aws:aoss:us-east-1:111122223333:collection/cmk"),
						KmsKeyArn: ossStrptr(cmkArn),
					},
					{
						Name: ossStrptr("no-cmk"),
						Arn:  ossStrptr("arn:aws:aoss:us-east-1:111122223333:collection/nocmk"),
						// KmsKeyArn nil -> AWS-owned default key
					},
				},
			},
		},
	}
	assets, err := OpenSearchServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}
	byName := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byName[a.Properties["collectionName"]] = a
	}

	withCMK, ok := byName["with-cmk"]
	if !ok {
		t.Fatalf("expected an asset for the CMK-encrypted collection")
	}
	if got := withCMK.Properties["kmsKeyId"]; got != cmkArn {
		t.Errorf("expected CMK collection to record its key ARN %q, got %q", cmkArn, got)
	}

	noCMK, ok := byName["no-cmk"]
	if !ok {
		t.Fatalf("expected an asset for the default-key collection")
	}
	if got := noCMK.Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("expected absent-CMK collection to map to the AWS-owned default key sentinel, got %q", got)
	}

	// Both collections are always encrypted -> SymmetricOnly, never NoEncryption.
	for _, a := range assets {
		posture := ossPostureOf(t, a)
		if posture == string(models.PostureNoEncryption) {
			t.Errorf("collection %q wrongly classified as NoEncryption; OSS is always encrypted at rest", a.Properties["collectionName"])
		}
		if posture != string(models.PostureSymmetricOnly) {
			t.Errorf("expected SymmetricOnly posture for always-encrypted OSS collection %q, got %q", a.Properties["collectionName"], posture)
		}
	}
}

// postureOf extracts the posture property stamped by PostureProperty so the test
// reads it the same way the engine does.
func ossPostureOf(t *testing.T, a models.CryptoAsset) string {
	t.Helper()
	if v, ok := a.Properties["posture"]; ok {
		return v
	}
	return ""
}
