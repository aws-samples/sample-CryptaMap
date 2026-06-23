package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeLambdaListClient is a hand-rolled lambdaListAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client.
// functionsPages is returned page-by-page (each call consumes the next page) and
// the NextMarker is wired so the scanner loops through every page; listErr forces
// a ListFunctions failure.
type fakeLambdaListClient struct {
	functionsPages []*lambda.ListFunctionsOutput
	lambdaCalls    int
	listErr        error
}

func (f *fakeLambdaListClient) ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.lambdaCalls >= len(f.functionsPages) {
		return &lambda.ListFunctionsOutput{}, nil
	}
	out := f.functionsPages[f.lambdaCalls]
	f.lambdaCalls++
	return out, nil
}

func lambdaStrptr(s string) *string { return &s }

func lambdaAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestLambdaScanPaginatesFunctions verifies the ListFunctions NextMarker loop: a
// fake that returns 2 pages (NextMarker on page 1) must yield BOTH pages'
// functions as assets. Without the pagination restore, only the first page's
// function survives.
func TestLambdaScanPaginatesFunctions(t *testing.T) {
	client := &fakeLambdaListClient{
		functionsPages: []*lambda.ListFunctionsOutput{
			{
				Functions:  []lambdatypes.FunctionConfiguration{{FunctionName: lambdaStrptr("fn-page1")}},
				NextMarker: lambdaStrptr("mark-page2"),
			},
			{
				Functions: []lambdatypes.FunctionConfiguration{{FunctionName: lambdaStrptr("fn-page2")}},
				// no NextMarker -> last page
			},
		},
	}
	assets, err := LambdaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.lambdaCalls; c != 2 {
		t.Errorf("expected ListFunctions to be called 2 times (paginated), got %d", c)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"fn-page1", "fn-page2"} {
		if !got[want] {
			t.Errorf("expected function %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestLambdaScanListErrorPropagates verifies the incompleteness decision: a
// ListFunctions failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestLambdaScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform lambda:ListFunctions")
	client := &fakeLambdaListClient{
		functionsPages: []*lambda.ListFunctionsOutput{
			{Functions: []lambdatypes.FunctionConfiguration{{FunctionName: lambdaStrptr("fn-1")}}},
		},
		listErr: sentinel,
	}
	assets, err := LambdaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListFunctions fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListFunctions failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a propagated error, got %d", len(assets))
	}
}

// TestLambdaScanHonestyPosture verifies the scanner's domain honesty: a Lambda
// function (always TLS-fronted by AWS, never plaintext) must be classified as
// NonPQCClassical — never a clean/quantum-safe all-clear — and must NOT assert a
// concrete served TLS version, because the Function-URL data-plane minimum is
// undocumented (left UNKNOWN with low-confidence aws-doc provenance), not the
// control-plane "1.2".
func TestLambdaScanHonestyPosture(t *testing.T) {
	client := &fakeLambdaListClient{
		functionsPages: []*lambda.ListFunctionsOutput{
			{Functions: []lambdatypes.FunctionConfiguration{{FunctionName: lambdaStrptr("fn-honest")}}},
		},
	}
	assets, err := LambdaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := lambdaAssetByID(assets, "fn-honest")
	if !ok {
		t.Fatalf("expected an asset for fn-honest, got assets=%v", assets)
	}
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (TLS-fronted classical, NOT a clean all-clear), got %q",
			models.PostureNonPQCClassical, got)
	}
	if a.CryptoProps.ProtocolProperties == nil {
		t.Fatalf("expected protocol properties to be populated for a transit asset")
	}
	if v := a.CryptoProps.ProtocolProperties.Version; v != "" {
		t.Errorf("expected served TLS version to be UNKNOWN (empty) for an undocumented Function-URL data plane, got %q", v)
	}
	if a.ResourceType != "AWS::Lambda::Function" {
		t.Errorf("expected resourceType AWS::Lambda::Function, got %q", a.ResourceType)
	}
}

// TestLambdaScanSkipsNilName verifies a function with a nil FunctionName is
// skipped (cannot key an asset) without producing a phantom asset or panicking.
func TestLambdaScanSkipsNilName(t *testing.T) {
	client := &fakeLambdaListClient{
		functionsPages: []*lambda.ListFunctionsOutput{
			{Functions: []lambdatypes.FunctionConfiguration{
				{FunctionName: nil},
				{FunctionName: lambdaStrptr("fn-real")},
			}},
		},
	}
	assets, err := LambdaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil-named function skipped), got %d", len(assets))
	}
	if _, ok := lambdaAssetByID(assets, "fn-real"); !ok {
		t.Errorf("expected the named function fn-real to survive; assets=%v", assets)
	}
}
