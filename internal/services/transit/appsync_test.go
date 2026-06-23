package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeAppSyncClient is a hand-rolled appsyncGraphqlAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err forces a ListGraphqlApis
// failure on the first call.
type fakeAppSyncClient struct {
	pages []*appsync.ListGraphqlApisOutput
	calls int
	err   error
}

func (f *fakeAppSyncClient) ListGraphqlApis(ctx context.Context, in *appsync.ListGraphqlApisInput, optFns ...func(*appsync.Options)) (*appsync.ListGraphqlApisOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &appsync.ListGraphqlApisOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func appsyncStrptr(s string) *string { return &s }

func appsyncAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestAppSyncScanPaginates verifies the ListGraphqlApis NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' APIs as
// assets. Without the pagination loop, only the first page's API survives.
func TestAppSyncScanPaginates(t *testing.T) {
	client := &fakeAppSyncClient{
		pages: []*appsync.ListGraphqlApisOutput{
			{
				GraphqlApis: []appsynctypes.GraphqlApi{{ApiId: appsyncStrptr("api-page1")}},
				NextToken:   appsyncStrptr("tok-page2"),
			},
			{
				GraphqlApis: []appsynctypes.GraphqlApi{{ApiId: appsyncStrptr("api-page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := AppSyncScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected ListGraphqlApis to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"api-page1", "api-page2"} {
		if _, ok := appsyncAssetByID(assets, want); !ok {
			t.Errorf("expected API %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestAppSyncScanListErrorPropagates verifies the incompleteness posture: a
// ListGraphqlApis failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestAppSyncScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform appsync:ListGraphqlApis")
	client := &fakeAppSyncClient{err: sentinel}
	assets, err := AppSyncScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListGraphqlApis fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListGraphqlApis failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on error, got %d", len(assets))
	}
}

// TestAppSyncScanSkipsNilApiID verifies a GraphQL API with a nil ApiId is
// skipped (no panic, no zero-id asset) rather than producing a bogus asset.
func TestAppSyncScanSkipsNilApiID(t *testing.T) {
	client := &fakeAppSyncClient{
		pages: []*appsync.ListGraphqlApisOutput{
			{GraphqlApis: []appsynctypes.GraphqlApi{
				{ApiId: nil},
				{ApiId: appsyncStrptr("api-ok")},
			}},
		},
	}
	assets, err := AppSyncScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil ApiId skipped), got %d", len(assets))
	}
	if _, ok := appsyncAssetByID(assets, "api-ok"); !ok {
		t.Errorf("expected the non-nil API to be emitted; assets=%v", assets)
	}
}

// TestAppSyncScanHonestyPosture verifies the transit honesty contract for an
// always-TLS endpoint: AppSync serves over TLS (documented 1.2 floor), so the
// emitted asset MUST be classified non-pqc-classical (classical TLS handshake),
// NOT a clean/no-encryption all-clear, and must record the documented TLS floor.
func TestAppSyncScanHonestyPosture(t *testing.T) {
	client := &fakeAppSyncClient{
		pages: []*appsync.ListGraphqlApisOutput{
			{GraphqlApis: []appsynctypes.GraphqlApi{{ApiId: appsyncStrptr("api-tls")}}},
		},
	}
	assets, err := AppSyncScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := appsyncAssetByID(assets, "api-tls")
	if !ok {
		t.Fatalf("expected asset for api-tls; assets=%v", assets)
	}
	if a.ResourceType != "AWS::AppSync::GraphQLApi" {
		t.Errorf("expected resourceType AWS::AppSync::GraphQLApi, got %q", a.ResourceType)
	}
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (classical TLS, never a clean all-clear), got %q",
			models.PostureNonPQCClassical, got)
	}
	pp := a.CryptoProps.ProtocolProperties
	if pp == nil || pp.Version != "1.2" {
		t.Errorf("expected the documented TLS 1.2 floor recorded on the asset, got proto=%+v", pp)
	}
	if pp != nil && pp.Source != services.SourceAWSDoc {
		t.Errorf("expected aws-doc provenance (documented floor, not observed), got source=%q", pp.Source)
	}
}
