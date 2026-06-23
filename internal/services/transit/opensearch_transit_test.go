package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeOpensearchTransitClient is a hand-rolled opensearchTransitAPI for
// unit-testing the scanner's error propagation + classification without a live
// AWS client. listOut/listErr drive the (non-paginated) ListDomainNames call;
// descByName returns a per-domain DescribeDomain response keyed by name, and
// descErrByName forces a per-domain DescribeDomain failure.
type fakeOpensearchTransitClient struct {
	listOut       *opensearch.ListDomainNamesOutput
	listErr       error
	descByName    map[string]*opensearch.DescribeDomainOutput
	descErrByName map[string]error
	listCalls     int
	descCalls     int
}

func (f *fakeOpensearchTransitClient) ListDomainNames(ctx context.Context, in *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOut != nil {
		return f.listOut, nil
	}
	return &opensearch.ListDomainNamesOutput{}, nil
}

func (f *fakeOpensearchTransitClient) DescribeDomain(ctx context.Context, in *opensearch.DescribeDomainInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	f.descCalls++
	name := ""
	if in.DomainName != nil {
		name = *in.DomainName
	}
	if err, ok := f.descErrByName[name]; ok {
		return nil, err
	}
	if out, ok := f.descByName[name]; ok {
		return out, nil
	}
	return &opensearch.DescribeDomainOutput{}, nil
}

func opensearchtransitStrptr(s string) *string { return &s }
func opensearchtransitBoolptr(b bool) *bool    { return &b }

// opensearchtransitDomain builds a DescribeDomainOutput for a domain with the
// given endpoint options. enforceHTTPS nil means the field is absent.
func opensearchtransitDomain(name, policy string, enforceHTTPS *bool, certARN string) *opensearch.DescribeDomainOutput {
	deo := &opensearchtypes.DomainEndpointOptions{
		TLSSecurityPolicy: opensearchtypes.TLSSecurityPolicy(policy),
		EnforceHTTPS:      enforceHTTPS,
	}
	if certARN != "" {
		deo.CustomEndpointCertificateArn = opensearchtransitStrptr(certARN)
	}
	return &opensearch.DescribeDomainOutput{
		DomainStatus: &opensearchtypes.DomainStatus{
			DomainName:            opensearchtransitStrptr(name),
			DomainEndpointOptions: deo,
		},
	}
}

// opensearchtransitAssetByID returns the asset with the given ResourceID.
func opensearchtransitAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

func opensearchtransitPostureOf(a models.CryptoAsset) string {
	if a.Properties == nil {
		return ""
	}
	return a.Properties["posture"]
}

// TestOpensearchTransitListErrorPropagates verifies the incompleteness posture:
// a ListDomainNames failure (denied/throttled) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the cause — NOT a silent empty
// success.
func TestOpensearchTransitListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform es:ListDomainNames")
	client := &fakeOpensearchTransitClient{listErr: sentinel}
	resolver := newACMCertResolver(aws.Config{})
	_, err := OpenSearchTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListDomainNames fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListDomainNames failure, got: %v", err)
	}
}

// TestOpensearchTransitDescribeErrorSkipsButContinues verifies the per-domain
// error handling: a DescribeDomain failure on one domain is skipped (logged to
// stderr, no asset emitted for it) but does NOT abort the whole scan or fail —
// other domains still produce assets. This documents the established
// best-effort-per-resource behavior of this scanner.
func TestOpensearchTransitDescribeErrorSkipsButContinues(t *testing.T) {
	client := &fakeOpensearchTransitClient{
		listOut: &opensearch.ListDomainNamesOutput{
			DomainNames: []opensearchtypes.DomainInfo{
				{DomainName: opensearchtransitStrptr("dom-bad")},
				{DomainName: opensearchtransitStrptr("dom-good")},
			},
		},
		descErrByName: map[string]error{
			"dom-bad": errors.New("AccessDeniedException: not authorized to DescribeDomain"),
		},
		descByName: map[string]*opensearch.DescribeDomainOutput{
			"dom-good": opensearchtransitDomain("dom-good", "Policy-Min-TLS-1-2-2019-07", opensearchtransitBoolptr(true), ""),
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := OpenSearchTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if _, ok := opensearchtransitAssetByID(assets, "dom-bad"); ok {
		t.Errorf("dom-bad failed DescribeDomain and must not produce an asset")
	}
	if _, ok := opensearchtransitAssetByID(assets, "dom-good"); !ok {
		t.Errorf("dom-good must still produce an asset despite a sibling DescribeDomain error; got %d assets", len(assets))
	}
}

// TestOpensearchTransitClassification covers the honesty posture for this
// transit scanner: TLS version/floor is mapped correctly per real
// TLSSecurityPolicy enum values, and (critically) a domain that permits
// plaintext (EnforceHTTPS=false) is reported as no-encryption — NOT clean
// classical TLS — regardless of its configured policy floor.
func TestOpensearchTransitClassification(t *testing.T) {
	cases := []struct {
		name         string
		policy       string
		enforceHTTPS *bool
		wantPosture  models.CryptoPosture
		wantTLSMin   string // "" means don't assert
	}{
		{
			name:         "tls12_enforced_is_classical_not_no_encryption",
			policy:       "Policy-Min-TLS-1-2-2019-07",
			enforceHTTPS: opensearchtransitBoolptr(true),
			wantPosture:  models.PostureNonPQCClassical,
			wantTLSMin:   "1.2",
		},
		{
			name:         "tls10_policy_is_legacy_tls",
			policy:       "Policy-Min-TLS-1-0-2019-07",
			enforceHTTPS: opensearchtransitBoolptr(true),
			wantPosture:  models.PostureLegacyTLS,
			wantTLSMin:   "1.0",
		},
		{
			name:         "pfs_policy_is_tls13_classical_not_pqc",
			policy:       "Policy-Min-TLS-1-2-PFS-2023-10",
			enforceHTTPS: opensearchtransitBoolptr(true),
			wantPosture:  models.PostureNonPQCClassical,
			wantTLSMin:   "1.3",
		},
		{
			// EnforceHTTPS=false: plaintext HTTP accepted regardless of the TLS
			// floor, so the endpoint is NOT encrypted-in-transit. Must NOT report
			// a clean classical-TLS verdict.
			name:         "enforce_https_false_is_no_encryption_not_clean_tls",
			policy:       "Policy-Min-TLS-1-2-2019-07",
			enforceHTTPS: opensearchtransitBoolptr(false),
			wantPosture:  models.PostureNoEncryption,
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeOpensearchTransitClient{
				listOut: &opensearch.ListDomainNamesOutput{
					DomainNames: []opensearchtypes.DomainInfo{
						{DomainName: opensearchtransitStrptr("dom")},
					},
				},
				descByName: map[string]*opensearch.DescribeDomainOutput{
					"dom": opensearchtransitDomain("dom", tc.policy, tc.enforceHTTPS, ""),
				},
			}
			assets, err := OpenSearchTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			a, ok := opensearchtransitAssetByID(assets, "dom")
			if !ok {
				t.Fatalf("expected an asset for domain 'dom'; got %d assets", len(assets))
			}
			if got := opensearchtransitPostureOf(a); got != string(tc.wantPosture) {
				t.Errorf("posture: want %q, got %q", tc.wantPosture, got)
			}
			if tc.wantTLSMin != "" {
				if a.CryptoProps.ProtocolProperties == nil {
					t.Fatalf("expected protocol properties carrying a TLS floor")
				}
				if got := a.CryptoProps.ProtocolProperties.TLSMinVersion; got != tc.wantTLSMin {
					t.Errorf("TLSMinVersion: want %q, got %q", tc.wantTLSMin, got)
				}
			}
		})
	}
}
