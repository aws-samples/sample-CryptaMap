package sdkpqc

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// lambdaruntimeFakeClient is a hand-rolled lambdaListFunctionsAPI for unit-testing
// the scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextMarker is
// wired so the scanner loops through every page; err forces a ListFunctions
// failure on the (errAt)-th call (0-indexed).
type lambdaruntimeFakeClient struct {
	pages []*lambda.ListFunctionsOutput
	calls int
	err   error
	errAt int
}

func (f *lambdaruntimeFakeClient) ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if f.err != nil && f.calls == f.errAt {
		f.calls++
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &lambda.ListFunctionsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func lambdaruntimeStrptr(s string) *string { return &s }

func lambdaruntimeAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestLambdaRuntimeScanPaginates verifies the Marker loop: a fake that returns 2
// pages (NextMarker on page 1) must yield BOTH pages' functions as assets. Without
// the pagination, only the first page's function survives.
func TestLambdaRuntimeScanPaginates(t *testing.T) {
	client := &lambdaruntimeFakeClient{
		pages: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionArn: lambdaruntimeStrptr("arn-page1"), FunctionName: lambdaruntimeStrptr("fn1"), Runtime: lambdatypes.RuntimePython312, Version: lambdaruntimeStrptr("$LATEST")},
				},
				NextMarker: lambdaruntimeStrptr("marker-page2"),
			},
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionArn: lambdaruntimeStrptr("arn-page2"), FunctionName: lambdaruntimeStrptr("fn2"), Runtime: lambdatypes.RuntimeNodejs20x},
				},
				// no NextMarker -> last page
			},
		},
	}
	assets, err := LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListFunctions to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"arn-page1", "arn-page2"} {
		if _, ok := lambdaruntimeAssetByID(assets, want); !ok {
			t.Errorf("expected function %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestLambdaRuntimeScanListErrorPropagates verifies that a top-level ListFunctions
// failure (denied/rate-limited) makes the scan VISIBLY incomplete by returning a
// non-nil error wrapping the cause — NOT a silent empty success.
func TestLambdaRuntimeScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform lambda:ListFunctions")
	client := &lambdaruntimeFakeClient{
		err:   sentinel,
		errAt: 0,
	}
	_, err := LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListFunctions fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListFunctions failure, got: %v", err)
	}
}

// TestLambdaRuntimeScanErrorOnSecondPageNotSwallowed verifies the error is also
// propagated when it occurs mid-pagination — page-1 assets already collected must
// NOT be returned as a clean success that hides the truncated, errored page 2.
func TestLambdaRuntimeScanErrorOnSecondPageNotSwallowed(t *testing.T) {
	sentinel := errors.New("ThrottlingException: rate exceeded")
	client := &lambdaruntimeFakeClient{
		pages: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionArn: lambdaruntimeStrptr("arn-page1"), FunctionName: lambdaruntimeStrptr("fn1")},
				},
				NextMarker: lambdaruntimeStrptr("marker-page2"),
			},
		},
		err:   sentinel,
		errAt: 1, // first call succeeds (page 1), second call (page 2) errors
	}
	_, err := LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to propagate a mid-pagination ListFunctions error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the second-page failure, got: %v", err)
	}
}

// TestLambdaRuntimeScanHonestUnknownPosture pins the honesty posture for the
// SDK/runtime domain: a runtime string cannot determine the outbound TLS posture
// (PQ-TLS is opt-in, ACRT-gated, Linux-only), so the asset MUST be PostureUnknown.
// It must NOT be falsely clean (PQCReady/PQCHybrid) and must NOT be no-encryption —
// the absence of observable TLS evidence is honest uncertainty, not "broken".
func TestLambdaRuntimeScanHonestUnknownPosture(t *testing.T) {
	client := &lambdaruntimeFakeClient{
		pages: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionArn: lambdaruntimeStrptr("arn-fn"), FunctionName: lambdaruntimeStrptr("svc"), Runtime: lambdatypes.RuntimePython312, Version: lambdaruntimeStrptr("$LATEST")},
				},
			},
		},
	}
	assets, err := LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := lambdaruntimeAssetByID(assets, "arn-fn")
	if !ok {
		t.Fatal("expected the lambda function to appear as an asset")
	}
	if got := a.Properties["posture"]; got != string(models.PostureUnknown) {
		t.Errorf("expected PostureUnknown for a runtime asset (no observable TLS posture), got %q", got)
	}
	if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
		t.Errorf("runtime metadata must NOT be reported as no-encryption: %q", got)
	}
	if got := a.Properties["posture"]; got == string(models.PosturePQCReady) || got == string(models.PosturePQCHybrid) {
		t.Errorf("runtime string must NOT be inferred as quantum-resistant: %q", got)
	}
	// Runtime metadata we CAN observe must be carried faithfully.
	if a.Properties["runtime"] != "python3.12" {
		t.Errorf("expected runtime metadata python3.12, got %q", a.Properties["runtime"])
	}
	if a.Properties["functionName"] != "svc" {
		t.Errorf("expected functionName svc, got %q", a.Properties["functionName"])
	}
	if a.Properties["version"] != "$LATEST" {
		t.Errorf("expected version $LATEST, got %q", a.Properties["version"])
	}
	if a.ResourceType != "AWS::Lambda::Function" {
		t.Errorf("expected resourceType AWS::Lambda::Function, got %q", a.ResourceType)
	}
}

// TestLambdaRuntimeScanSkipsNilArn verifies a function with a nil ARN is skipped
// (cannot be uniquely identified) rather than emitted as a malformed asset, and
// does not abort the rest of the page.
func TestLambdaRuntimeScanSkipsNilArn(t *testing.T) {
	client := &lambdaruntimeFakeClient{
		pages: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionArn: nil, FunctionName: lambdaruntimeStrptr("ghost")},
					{FunctionArn: lambdaruntimeStrptr("arn-real"), FunctionName: lambdaruntimeStrptr("real")},
				},
			},
		},
	}
	assets, err := LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil-ARN skipped), got %d", len(assets))
	}
	if _, ok := lambdaruntimeAssetByID(assets, "arn-real"); !ok {
		t.Error("expected the function with a valid ARN to be emitted")
	}
}
