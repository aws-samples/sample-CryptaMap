package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeAPIGWRestClient is a hand-rolled apigwRestAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. Each
// *Pages slice is returned page-by-page (each call consumes the next page) and
// the Position is wired so the scanner loops through every page; *Err forces the
// corresponding call to fail.
type fakeAPIGWRestClient struct {
	apisPages    []*apigw.GetRestApisOutput
	apiCalls     int
	apisErr      error
	domainsPages []*apigw.GetDomainNamesOutput
	domainCalls  int
	domainsErr   error
}

func (f *fakeAPIGWRestClient) GetRestApis(ctx context.Context, in *apigw.GetRestApisInput, optFns ...func(*apigw.Options)) (*apigw.GetRestApisOutput, error) {
	if f.apisErr != nil {
		return nil, f.apisErr
	}
	if f.apiCalls >= len(f.apisPages) {
		return &apigw.GetRestApisOutput{}, nil
	}
	out := f.apisPages[f.apiCalls]
	f.apiCalls++
	return out, nil
}

func (f *fakeAPIGWRestClient) GetDomainNames(ctx context.Context, in *apigw.GetDomainNamesInput, optFns ...func(*apigw.Options)) (*apigw.GetDomainNamesOutput, error) {
	if f.domainsErr != nil {
		return nil, f.domainsErr
	}
	if f.domainCalls >= len(f.domainsPages) {
		return &apigw.GetDomainNamesOutput{}, nil
	}
	out := f.domainsPages[f.domainCalls]
	f.domainCalls++
	return out, nil
}

func apigwrestStrptr(s string) *string { return &s }

// apigwrestAssetByID returns the asset with the given ResourceID, or nil.
func apigwrestAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// apigwrestPostureOf returns the crypto posture recorded on the asset (empty if absent).
func apigwrestPostureOf(a *models.CryptoAsset) models.CryptoPosture {
	if a == nil || a.Properties == nil {
		return ""
	}
	if v, ok := a.Properties["posture"]; ok {
		return models.CryptoPosture(v)
	}
	return ""
}

// apigwrestTLSFloorOf returns the asset's recorded TLS minimum-version floor
// (empty if the asset has no protocol block — e.g. an UNKNOWN floor).
func apigwrestTLSFloorOf(a *models.CryptoAsset) string {
	if a == nil || a.CryptoProps.ProtocolProperties == nil {
		return ""
	}
	return a.CryptoProps.ProtocolProperties.TLSMinVersion
}

// TestAPIGWRestScanPaginatesApis verifies the GetRestApis Position loop: a fake
// returning 2 pages (Position set on page 1) must yield BOTH pages' REST APIs as
// assets. Without the pagination loop, only the first page's API survives.
func TestAPIGWRestScanPaginatesApis(t *testing.T) {
	client := &fakeAPIGWRestClient{
		apisPages: []*apigw.GetRestApisOutput{
			{
				Items:    []apigwtypes.RestApi{{Id: apigwrestStrptr("rest-page1")}},
				Position: apigwrestStrptr("pos-page2"),
			},
			{
				Items: []apigwtypes.RestApi{{Id: apigwrestStrptr("rest-page2")}},
				// no Position -> last page
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := APIGWRestScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.apiCalls; c != 2 {
		t.Errorf("expected GetRestApis to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"rest-page1", "rest-page2"} {
		if apigwrestAssetByID(assets, want) == nil {
			t.Errorf("expected REST API %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestAPIGWRestScanPaginatesDomains verifies the GetDomainNames Position loop:
// both pages of custom domains must surface as assets.
func TestAPIGWRestScanPaginatesDomains(t *testing.T) {
	client := &fakeAPIGWRestClient{
		domainsPages: []*apigw.GetDomainNamesOutput{
			{
				Items:    []apigwtypes.DomainName{{DomainName: apigwrestStrptr("d1.example.com"), SecurityPolicy: apigwtypes.SecurityPolicyTls12}},
				Position: apigwrestStrptr("pos-dom2"),
			},
			{
				Items: []apigwtypes.DomainName{{DomainName: apigwrestStrptr("d2.example.com"), SecurityPolicy: apigwtypes.SecurityPolicyTls12}},
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := APIGWRestScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.domainCalls; c != 2 {
		t.Errorf("expected GetDomainNames to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"d1.example.com", "d2.example.com"} {
		if apigwrestAssetByID(assets, want) == nil {
			t.Errorf("expected domain %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestAPIGWRestScanRestApisErrorPropagates verifies the no-silent-drop posture:
// a top-level GetRestApis failure (denied/throttled) must return a non-nil error
// so the scan is VISIBLY incomplete, NOT a clean-looking empty success.
func TestAPIGWRestScanRestApisErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform apigateway:GET")
	client := &fakeAPIGWRestClient{apisErr: sentinel}
	resolver := newACMCertResolver(aws.Config{})
	_, err := APIGWRestScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when GetRestApis fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the GetRestApis failure, got: %v", err)
	}
}

// TestAPIGWRestExecuteApiNotFalseClean asserts the honesty posture for the
// default execute-api endpoint: API Gateway's managed endpoint supports a TLS
// 1.0 floor per AWS docs, so the REST API baseline asset must NOT assert a clean
// "1.2" floor — the TLS version is left UNKNOWN (empty) and the posture is the
// classical (not-PQC) label, never silently dropped or marked safe.
func TestAPIGWRestExecuteApiNotFalseClean(t *testing.T) {
	client := &fakeAPIGWRestClient{
		apisPages: []*apigw.GetRestApisOutput{
			{Items: []apigwtypes.RestApi{{Id: apigwrestStrptr("rest-1")}}},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := APIGWRestScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := apigwrestAssetByID(assets, "rest-1")
	if a == nil {
		t.Fatal("expected the REST API baseline asset to be emitted")
	}
	if got := apigwrestPostureOf(a); got != models.PostureNonPQCClassical {
		t.Errorf("expected execute-api baseline posture %q, got %q", models.PostureNonPQCClassical, got)
	}
	if floor := apigwrestTLSFloorOf(a); floor != "" {
		t.Errorf("expected execute-api TLS floor left UNKNOWN (empty, not a clean 1.2 assertion), got %q", floor)
	}
}

// TestAPIGWRestSecurityPolicyHonesty exercises secPolicyToVersion across the
// domains that matter for transit honesty: a PQ-hybrid TLS 1.2-floor policy must
// NOT overstate its floor as 1.3, a PQ TLS-1.3-only policy is a true 1.3 floor,
// a legacy TLS_1_0 policy is flagged (never clean), and a plain TLS_1_2 policy is
// classical (not PQC). Each yields a sane TLS floor on the emitted domain asset.
func TestAPIGWRestSecurityPolicyHonesty(t *testing.T) {
	cases := []struct {
		name        string
		policy      string
		wantVer     string
		wantPosture models.CryptoPosture
	}{
		{"pq-1.2-floor-not-overstated", "TLS13_1_2_2025_09_PQ_2025_09", "1.2", models.PosturePQCHybrid},
		{"pq-1.3-only-true-floor", "TLS13_1_3_2025_09_PQ_2025_09", "1.3", models.PosturePQCHybrid},
		{"legacy-tls10-flagged", "TLS_1_0", "1.0", models.PostureLegacyTLS},
		{"classical-tls12", "TLS_1_2", "1.2", models.PostureNonPQCClassical},
		{"classical-tls13", "TLS_1_3", "1.3", models.PostureNonPQCClassical},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ver, posture := secPolicyToVersion(tc.policy)
			if ver != tc.wantVer {
				t.Errorf("secPolicyToVersion(%q) version = %q, want %q", tc.policy, ver, tc.wantVer)
			}
			if posture != tc.wantPosture {
				t.Errorf("secPolicyToVersion(%q) posture = %q, want %q", tc.policy, posture, tc.wantPosture)
			}

			client := &fakeAPIGWRestClient{
				domainsPages: []*apigw.GetDomainNamesOutput{
					{Items: []apigwtypes.DomainName{{
						DomainName:     apigwrestStrptr("dom-" + tc.name),
						SecurityPolicy: apigwtypes.SecurityPolicy(tc.policy),
					}}},
				},
			}
			resolver := newACMCertResolver(aws.Config{})
			assets, err := APIGWRestScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			a := apigwrestAssetByID(assets, "dom-"+tc.name)
			if a == nil {
				t.Fatalf("expected domain asset for policy %q", tc.policy)
			}
			if got := apigwrestPostureOf(a); got != tc.wantPosture {
				t.Errorf("domain posture for %q = %q, want %q", tc.policy, got, tc.wantPosture)
			}
			if floor := apigwrestTLSFloorOf(a); floor != tc.wantVer {
				t.Errorf("domain TLS floor for %q = %q, want %q", tc.policy, floor, tc.wantVer)
			}
		})
	}
}
