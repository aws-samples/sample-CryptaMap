package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	osttypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeOpenSearchClient is a hand-rolled openSearchAPI for unit-testing the
// scanner's domain enumeration + per-domain describe error handling + posture
// classification without a live AWS client. listOut/listErr drive
// ListDomainNames; describeByName maps a domain name to a DescribeDomain output,
// and describeErrByName forces a per-domain DescribeDomain failure.
type fakeOpenSearchClient struct {
	listOut         *opensearch.ListDomainNamesOutput
	listErr         error
	describeByName  map[string]*opensearch.DescribeDomainOutput
	describeErrByNm map[string]error
}

func (f *fakeOpenSearchClient) ListDomainNames(ctx context.Context, in *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listOut != nil {
		return f.listOut, nil
	}
	return &opensearch.ListDomainNamesOutput{}, nil
}

func (f *fakeOpenSearchClient) DescribeDomain(ctx context.Context, in *opensearch.DescribeDomainInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error) {
	name := ""
	if in.DomainName != nil {
		name = *in.DomainName
	}
	if f.describeErrByNm != nil {
		if err, ok := f.describeErrByNm[name]; ok {
			return nil, err
		}
	}
	if f.describeByName != nil {
		if out, ok := f.describeByName[name]; ok {
			return out, nil
		}
	}
	return &opensearch.DescribeDomainOutput{}, nil
}

func osStrptr(s string) *string { return &s }
func osBoolptr(b bool) *bool    { return &b }

// encDomainOut builds a DescribeDomain output for a domain whose
// EncryptionAtRestOptions are Enabled (optionally with a CMK KmsKeyId).
func encDomainOut(name, kmsKeyID string) *opensearch.DescribeDomainOutput {
	opts := &osttypes.EncryptionAtRestOptions{Enabled: osBoolptr(true)}
	if kmsKeyID != "" {
		opts.KmsKeyId = osStrptr(kmsKeyID)
	}
	return &opensearch.DescribeDomainOutput{
		DomainStatus: &osttypes.DomainStatus{
			DomainName:              osStrptr(name),
			EncryptionAtRestOptions: opts,
		},
	}
}

// unencDomainOut builds a DescribeDomain output for a domain whose
// EncryptionAtRestOptions are explicitly disabled (genuinely off).
func unencDomainOut(name string) *opensearch.DescribeDomainOutput {
	return &opensearch.DescribeDomainOutput{
		DomainStatus: &osttypes.DomainStatus{
			DomainName:              osStrptr(name),
			EncryptionAtRestOptions: &osttypes.EncryptionAtRestOptions{Enabled: osBoolptr(false)},
		},
	}
}

func osAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

func osPosture(a models.CryptoAsset) string {
	if p, ok := a.Properties["posture"]; ok {
		return p
	}
	return ""
}

// TestOpenSearchScanEnumeratesAllDomains verifies that every domain returned by
// ListDomainNames is described and emitted as an asset — i.e. no domain is
// silently dropped during enumeration. (OpenSearch ListDomainNames is not
// SDK-paginated; it returns all domains in one call, so the regression guard
// here is "describe + emit each listed domain", the multi-resource analogue of
// the apigw pagination guard.)
func TestOpenSearchScanEnumeratesAllDomains(t *testing.T) {
	client := &fakeOpenSearchClient{
		listOut: &opensearch.ListDomainNamesOutput{
			DomainNames: []osttypes.DomainInfo{
				{DomainName: osStrptr("domain-a")},
				{DomainName: osStrptr("domain-b")},
			},
		},
		describeByName: map[string]*opensearch.DescribeDomainOutput{
			"domain-a": encDomainOut("domain-a", ""),
			"domain-b": encDomainOut("domain-b", ""),
		},
	}
	assets, err := OpenSearchScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	for _, want := range []string{"domain-a", "domain-b"} {
		if _, ok := osAssetByID(assets, want); !ok {
			t.Errorf("expected listed domain %q to appear as an asset; assets=%v", want, assets)
		}
	}
	if len(assets) != 2 {
		t.Errorf("expected exactly 2 assets, got %d", len(assets))
	}
}

// TestOpenSearchScanListErrorPropagates verifies the incompleteness contract: a
// ListDomainNames failure (denied / throttled) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the cause — NOT a silent
// empty success.
func TestOpenSearchScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform es:ListDomainNames")
	client := &fakeOpenSearchClient{listErr: sentinel}
	_, err := OpenSearchScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListDomainNames fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListDomainNames failure, got: %v", err)
	}
}

// TestOpenSearchScanDescribeErrorYieldsUnknown verifies the per-resource honesty
// fix: a DescribeDomain failure on one domain must NOT silently drop it (a false
// all-clear by omission) and must NOT default to NoEncryption (a false alarm).
// The domain must surface as a PostureUnknown asset carrying an explanatory note,
// while sibling domains still classify normally.
func TestOpenSearchScanDescribeErrorYieldsUnknown(t *testing.T) {
	client := &fakeOpenSearchClient{
		listOut: &opensearch.ListDomainNamesOutput{
			DomainNames: []osttypes.DomainInfo{
				{DomainName: osStrptr("ok-domain")},
				{DomainName: osStrptr("denied-domain")},
			},
		},
		describeByName: map[string]*opensearch.DescribeDomainOutput{
			"ok-domain": encDomainOut("ok-domain", ""),
		},
		describeErrByNm: map[string]error{
			"denied-domain": errors.New("AccessDeniedException: not authorized to perform es:DescribeDomain"),
		},
	}
	assets, err := OpenSearchScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-domain DescribeDomain error must NOT fail the whole scan; got: %v", err)
	}
	denied, ok := osAssetByID(assets, "denied-domain")
	if !ok {
		t.Fatal("expected the describe-failed domain to be emitted (not silently dropped) as a PostureUnknown asset")
	}
	if got := osPosture(denied); got != string(models.PostureUnknown) {
		t.Errorf("expected describe-failed domain posture %q, got %q (must not default to NoEncryption)", models.PostureUnknown, got)
	}
	if note, _ := denied.Properties["note"]; note == "" {
		t.Errorf("expected an explanatory note on the undetermined domain, got empty")
	}
	// Sibling domain must still classify correctly.
	okAsset, ok := osAssetByID(assets, "ok-domain")
	if !ok {
		t.Fatal("expected the describable sibling domain to still appear as an asset")
	}
	if got := osPosture(okAsset); got != string(models.PostureSymmetricOnly) {
		t.Errorf("expected encrypted sibling posture %q, got %q", models.PostureSymmetricOnly, got)
	}
}

// TestOpenSearchScanPostureMapping verifies the at-rest honesty mapping:
//   - EncryptionAtRestOptions Enabled -> SymmetricOnly (AES), NEVER NoEncryption.
//   - EncryptionAtRestOptions explicitly disabled (opt-in SSE genuinely off) ->
//     NoEncryption only when truly off.
//
// OpenSearch encryption-at-rest is opt-in (not always-on), so a disabled domain
// is a genuine NoEncryption, not a false alarm.
func TestOpenSearchScanPostureMapping(t *testing.T) {
	client := &fakeOpenSearchClient{
		listOut: &opensearch.ListDomainNamesOutput{
			DomainNames: []osttypes.DomainInfo{
				{DomainName: osStrptr("encrypted")},
				{DomainName: osStrptr("plaintext")},
			},
		},
		describeByName: map[string]*opensearch.DescribeDomainOutput{
			"encrypted": encDomainOut("encrypted", "arn:aws:kms:us-east-1:111122223333:key/abc"),
			"plaintext": unencDomainOut("plaintext"),
		},
	}
	assets, err := OpenSearchScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	enc, ok := osAssetByID(assets, "encrypted")
	if !ok {
		t.Fatal("expected encrypted domain asset")
	}
	if got := osPosture(enc); got != string(models.PostureSymmetricOnly) {
		t.Errorf("encrypted domain: expected posture %q (AES at-rest, never NoEncryption), got %q", models.PostureSymmetricOnly, got)
	}

	plain, ok := osAssetByID(assets, "plaintext")
	if !ok {
		t.Fatal("expected plaintext domain asset")
	}
	if got := osPosture(plain); got != string(models.PostureNoEncryption) {
		t.Errorf("genuinely-disabled domain: expected posture %q, got %q", models.PostureNoEncryption, got)
	}
}
