package certmgmt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeCloudfrontKeyGroupsClient is a hand-rolled cloudfrontKeyGroupsAPI for
// unit-testing the scanner's Marker pagination + error propagation without a
// live AWS client. pages is returned page-by-page (each call consumes the next
// page) with the NextMarker wired so the scanner loops through every page; err
// forces a ListPublicKeys failure.
type fakeCloudfrontKeyGroupsClient struct {
	pages []*cloudfront.ListPublicKeysOutput
	calls int
	err   error
}

func (f *fakeCloudfrontKeyGroupsClient) ListPublicKeys(ctx context.Context, in *cloudfront.ListPublicKeysInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListPublicKeysOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &cloudfront.ListPublicKeysOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func cloudfrontkeygroupsStrptr(s string) *string { return &s }

// cloudfrontkeygroupsAssetByID indexes assets by ResourceID for assertions.
func cloudfrontkeygroupsAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// cloudfrontkeygroupsRSAPEM generates a real PKIX-encoded RSA public key PEM so
// the scanner's parsePublicKeyAlgo path produces "RSA" + a real bit size,
// exercising the honesty posture (classical RSA, never PQC/no-encryption).
func cloudfrontkeygroupsRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestCloudfrontKeyGroupsScanPaginates verifies the ListPublicKeys Marker loop:
// a fake that returns 2 pages (NextMarker on page 1) must yield BOTH pages'
// public keys as assets. Without the pagination loop, only page 1 survives.
func TestCloudfrontKeyGroupsScanPaginates(t *testing.T) {
	pem := cloudfrontkeygroupsRSAPEM(t)
	client := &fakeCloudfrontKeyGroupsClient{
		pages: []*cloudfront.ListPublicKeysOutput{
			{
				PublicKeyList: &cftypes.PublicKeyList{
					Items: []cftypes.PublicKeySummary{
						{Id: cloudfrontkeygroupsStrptr("pk-page1"), Name: cloudfrontkeygroupsStrptr("k1"), EncodedKey: cloudfrontkeygroupsStrptr(pem)},
					},
					NextMarker: cloudfrontkeygroupsStrptr("marker-page2"),
				},
			},
			{
				PublicKeyList: &cftypes.PublicKeyList{
					Items: []cftypes.PublicKeySummary{
						{Id: cloudfrontkeygroupsStrptr("pk-page2"), Name: cloudfrontkeygroupsStrptr("k2"), EncodedKey: cloudfrontkeygroupsStrptr(pem)},
					},
					// no NextMarker -> last page
				},
			},
		},
	}
	assets, err := CloudFrontKeyGroupsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListPublicKeys to be called 2 times (paginated), got %d", client.calls)
	}
	byID := cloudfrontkeygroupsAssetByID(assets)
	for _, want := range []string{"pk-page1", "pk-page2"} {
		if _, ok := byID[want]; !ok {
			t.Errorf("expected public key %q from a paginated page to appear as an asset; got %v", want, assets)
		}
	}
}

// TestCloudfrontKeyGroupsScanErrorPropagates verifies the incompleteness
// posture: a ListPublicKeys failure (denied/throttled) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestCloudfrontKeyGroupsScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDenied: not authorized to perform cloudfront:ListPublicKeys")
	client := &fakeCloudfrontKeyGroupsClient{err: sentinel}
	assets, err := CloudFrontKeyGroupsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListPublicKeys fails, got nil (silent empty success); assets=%v", assets)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListPublicKeys failure, got: %v", err)
	}
}

// TestCloudfrontKeyGroupsHonestyRSA verifies the domain honesty posture: a
// customer-uploaded RSA verification key is a quantum-vulnerable classical
// signature key -> posture MUST be NonPQCClassical (a migration target), the
// algorithm recorded as "RSA" with a real key size, and the asset is a
// signature material (never marked as having no encryption / never PQC-safe).
func TestCloudfrontKeyGroupsHonestyRSA(t *testing.T) {
	pem := cloudfrontkeygroupsRSAPEM(t)
	client := &fakeCloudfrontKeyGroupsClient{
		pages: []*cloudfront.ListPublicKeysOutput{
			{
				PublicKeyList: &cftypes.PublicKeyList{
					Items: []cftypes.PublicKeySummary{
						{Id: cloudfrontkeygroupsStrptr("pk-rsa"), Name: cloudfrontkeygroupsStrptr("signer"), EncodedKey: cloudfrontkeygroupsStrptr(pem)},
					},
				},
			},
		},
	}
	assets, err := CloudFrontKeyGroupsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := cloudfrontkeygroupsAssetByID(assets)
	a, ok := byID["pk-rsa"]
	if !ok {
		t.Fatalf("expected asset for pk-rsa; got %v", assets)
	}
	if a.Properties["posture"] != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q (classical quantum-vulnerable, never safe/PQC), got %q", models.PostureNonPQCClassical, a.Properties["posture"])
	}
	if a.Properties["algorithm"] != "RSA" {
		t.Errorf("expected algorithm RSA recorded from parsed PEM, got %q", a.Properties["algorithm"])
	}
	if a.Properties["posture"] == "" {
		t.Error("expected a non-empty posture; an empty/no-encryption posture would be a false-safe verdict for an asymmetric key")
	}
	if a.CryptoProps.AlgorithmProperties == nil {
		t.Fatal("expected AlgorithmProperties to be populated")
	}
	if a.CryptoProps.AlgorithmProperties.Primitive != models.PrimitiveSignature {
		t.Errorf("expected primitive %q (verification key is a signature primitive), got %q", models.PrimitiveSignature, a.CryptoProps.AlgorithmProperties.Primitive)
	}
	if a.CryptoProps.AlgorithmProperties.NistQuantumSecurityLevel != 0 {
		t.Errorf("expected NIST quantum security level 0 (classical RSA offers no PQ security), got %d", a.CryptoProps.AlgorithmProperties.NistQuantumSecurityLevel)
	}
	if a.CryptoProps.AlgorithmProperties.KeySizeBits != 2048 {
		t.Errorf("expected real RSA key size 2048 from parsed PEM, got %d", a.CryptoProps.AlgorithmProperties.KeySizeBits)
	}
}

// TestCloudfrontKeyGroupsUnparsablePEMNotSafe verifies a key whose PEM cannot be
// parsed is NOT silently dropped and NOT treated as safe: it still becomes an
// asset with a classical (unparsed) label, key size 0, and NonPQCClassical
// posture — honest about uncertainty rather than a false all-clear.
func TestCloudfrontKeyGroupsUnparsablePEMNotSafe(t *testing.T) {
	client := &fakeCloudfrontKeyGroupsClient{
		pages: []*cloudfront.ListPublicKeysOutput{
			{
				PublicKeyList: &cftypes.PublicKeyList{
					Items: []cftypes.PublicKeySummary{
						{Id: cloudfrontkeygroupsStrptr("pk-garbage"), Name: cloudfrontkeygroupsStrptr("bad"), EncodedKey: cloudfrontkeygroupsStrptr("not-a-pem")},
					},
				},
			},
		},
	}
	assets, err := CloudFrontKeyGroupsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := cloudfrontkeygroupsAssetByID(assets)
	a, ok := byID["pk-garbage"]
	if !ok {
		t.Fatalf("expected unparsable key to still be inventoried (no silent drop); got %v", assets)
	}
	if a.Properties["posture"] != string(models.PostureNonPQCClassical) {
		t.Errorf("expected NonPQCClassical posture for unparsable key (never a clean/safe verdict), got %q", a.Properties["posture"])
	}
	if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.KeySizeBits != 0 {
		t.Errorf("expected key size 0 for unparsable PEM (honest unknown), got %+v", a.CryptoProps.AlgorithmProperties)
	}
}
