package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigwv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
)

// fakeAPIGWHTTPClient is a hand-rolled apigwv2HTTPAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. apisPages
// is returned page-by-page (each call consumes the next page) and the NextToken
// is wired so the scanner loops through every page; domainsErr forces a
// GetDomainNames failure.
type fakeAPIGWHTTPClient struct {
	apisPages  []*apigwv2.GetApisOutput
	apiCalls   int
	domainsOut *apigwv2.GetDomainNamesOutput
	domainsErr error
}

func (f *fakeAPIGWHTTPClient) GetApis(ctx context.Context, in *apigwv2.GetApisInput, optFns ...func(*apigwv2.Options)) (*apigwv2.GetApisOutput, error) {
	if f.apiCalls >= len(f.apisPages) {
		return &apigwv2.GetApisOutput{}, nil
	}
	out := f.apisPages[f.apiCalls]
	f.apiCalls++
	return out, nil
}

func (f *fakeAPIGWHTTPClient) GetDomainNames(ctx context.Context, in *apigwv2.GetDomainNamesInput, optFns ...func(*apigwv2.Options)) (*apigwv2.GetDomainNamesOutput, error) {
	if f.domainsErr != nil {
		return nil, f.domainsErr
	}
	if f.domainsOut != nil {
		return f.domainsOut, nil
	}
	return &apigwv2.GetDomainNamesOutput{}, nil
}

func strptr(s string) *string { return &s }

// TestAPIGWHTTPScanPaginatesApis verifies the GetApis NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' APIs as assets.
// Without the pagination restore, only the first page's API survives.
func TestAPIGWHTTPScanPaginatesApis(t *testing.T) {
	client := &fakeAPIGWHTTPClient{
		apisPages: []*apigwv2.GetApisOutput{
			{
				Items:     []apigwv2types.Api{{ApiId: strptr("api-page1")}},
				NextToken: strptr("tok-page2"),
			},
			{
				Items: []apigwv2types.Api{{ApiId: strptr("api-page2")}},
				// no NextToken -> last page
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := APIGWHTTPScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if f := client.apiCalls; f != 2 {
		t.Errorf("expected GetApis to be called 2 times (paginated), got %d", f)
	}
	got := map[string]bool{}
	for _, a := range assets {
		if a.ResourceType == "AWS::ApiGatewayV2::Api" {
			got[a.ResourceID] = true
		}
	}
	for _, want := range []string{"api-page1", "api-page2"} {
		if !got[want] {
			t.Errorf("expected API %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestAPIGWHTTPScanDomainNamesErrorPropagates verifies the owner's incompleteness
// decision: a GetDomainNames failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success
// (the pre-fix behavior swallowed the error with `if derr == nil`).
func TestAPIGWHTTPScanDomainNamesErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform apigateway:GET")
	client := &fakeAPIGWHTTPClient{
		apisPages: []*apigwv2.GetApisOutput{
			{Items: []apigwv2types.Api{{ApiId: strptr("api-1")}}},
		},
		domainsErr: sentinel,
	}
	resolver := newACMCertResolver(aws.Config{})
	_, err := APIGWHTTPScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when GetDomainNames fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the GetDomainNames failure, got: %v", err)
	}
}
