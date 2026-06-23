package certmgmt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	ratypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRolesAnywhereClient is a hand-rolled rolesAnywhereAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; listErr forces a
// ListTrustAnchors failure on the first call.
type fakeRolesAnywhereClient struct {
	rolesanywherePages []*rolesanywhere.ListTrustAnchorsOutput
	rolesanywhereCalls int
	rolesanywhereErr   error
}

func (f *fakeRolesAnywhereClient) ListTrustAnchors(ctx context.Context, in *rolesanywhere.ListTrustAnchorsInput, optFns ...func(*rolesanywhere.Options)) (*rolesanywhere.ListTrustAnchorsOutput, error) {
	if f.rolesanywhereErr != nil {
		return nil, f.rolesanywhereErr
	}
	if f.rolesanywhereCalls >= len(f.rolesanywherePages) {
		return &rolesanywhere.ListTrustAnchorsOutput{}, nil
	}
	out := f.rolesanywherePages[f.rolesanywhereCalls]
	f.rolesanywhereCalls++
	return out, nil
}

func rolesanywhereStrptr(s string) *string { return &s }
func rolesanywhereBoolptr(b bool) *bool    { return &b }

// rolesanywhereAssetByID indexes scan output by ResourceID for assertion.
func rolesanywhereAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// rolesanywhereRSACertPEM mints a real self-signed RSA certificate PEM so the
// CERTIFICATE_BUNDLE parse path exercises actual crypto/x509 decoding and yields
// a deterministic, observed NonPQCClassical posture (not a fabricated default).
func rolesanywhereRSACertPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rolesanywhere-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func rolesanywhereTA(arn, name string, source *ratypes.Source) ratypes.TrustAnchorDetail {
	return ratypes.TrustAnchorDetail{
		TrustAnchorArn: rolesanywhereStrptr(arn),
		Name:           rolesanywhereStrptr(name),
		Enabled:        rolesanywhereBoolptr(true),
		Source:         source,
	}
}

// TestRolesAnywhereScanPaginates verifies the ListTrustAnchors NextToken loop: a
// fake returning 2 pages (NextToken on page 1) must yield BOTH pages' anchors as
// assets. Without the pagination loop only the first page's anchor survives.
func TestRolesAnywhereScanPaginates(t *testing.T) {
	pem1 := rolesanywhereRSACertPEM(t)
	client := &fakeRolesAnywhereClient{
		rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
			{
				TrustAnchors: []ratypes.TrustAnchorDetail{
					rolesanywhereTA("arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-page1", "ta-page1", &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeCertificateBundle,
						SourceData: &ratypes.SourceDataMemberX509CertificateData{Value: pem1},
					}),
				},
				NextToken: rolesanywhereStrptr("tok-page2"),
			},
			{
				TrustAnchors: []ratypes.TrustAnchorDetail{
					rolesanywhereTA("arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-page2", "ta-page2", &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeSelfSignedRepository,
					}),
				},
				// no NextToken -> last page
			},
		},
	}

	assets, err := RolesAnywhereScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.rolesanywhereCalls; c != 2 {
		t.Errorf("expected ListTrustAnchors to be called 2 times (paginated), got %d", c)
	}
	got := rolesanywhereAssetByID(assets)
	for _, want := range []string{
		"arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-page1",
		"arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-page2",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected anchor %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestRolesAnywhereScanListErrorPropagates verifies the incompleteness decision: a
// ListTrustAnchors failure (denied/throttled) must make the scan VISIBLY incomplete
// by returning a non-nil error — NOT a silent empty success.
func TestRolesAnywhereScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rolesanywhere:ListTrustAnchors")
	client := &fakeRolesAnywhereClient{rolesanywhereErr: sentinel}

	assets, err := RolesAnywhereScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListTrustAnchors fails, got nil (silent empty success); assets=%v", assets)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListTrustAnchors failure, got: %v", err)
	}
}

// TestRolesAnywhereScanHonestyPosture is the domain honesty check for a CERTIFICATE
// scanner:
//   - CERTIFICATE_BUNDLE with a real RSA CA PEM -> OBSERVED NonPQCClassical
//     (classical, quantum-vulnerable). It must NEVER be reported as no-encryption.
//   - AWS_ACM_PCA (sourceData carries only the CA ARN, not the key algo) -> Unknown,
//     cross-linked to the acmpca asset; never a fabricated safe/classical posture.
//   - SELF_SIGNED_REPOSITORY / empty PEM -> Unknown (we did not read a key, so we do
//     not guess).
func TestRolesAnywhereScanHonestyPosture(t *testing.T) {
	rsaPEM := rolesanywhereRSACertPEM(t)
	const (
		bundleARN = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-bundle"
		pcaARN    = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-pca"
		selfARN   = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-self"
		caArn     = "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/abc"
	)
	client := &fakeRolesAnywhereClient{
		rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
			{
				TrustAnchors: []ratypes.TrustAnchorDetail{
					rolesanywhereTA(bundleARN, "bundle", &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeCertificateBundle,
						SourceData: &ratypes.SourceDataMemberX509CertificateData{Value: rsaPEM},
					}),
					rolesanywhereTA(pcaARN, "pca", &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeAwsAcmPca,
						SourceData: &ratypes.SourceDataMemberAcmPcaArn{Value: caArn},
					}),
					rolesanywhereTA(selfARN, "self", &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeSelfSignedRepository,
					}),
				},
			},
		},
	}

	assets, err := RolesAnywhereScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	by := rolesanywhereAssetByID(assets)

	// 1. Real RSA CA bundle -> observed NonPQCClassical, NEVER no-encryption.
	bundle, ok := by[bundleARN]
	if !ok {
		t.Fatalf("bundle anchor missing from assets: %v", by)
	}
	if p := bundle.Properties["posture"]; p != string(models.PostureNonPQCClassical) {
		t.Errorf("CERTIFICATE_BUNDLE RSA CA: posture = %q, want %q (classical, never no-encryption)", p, models.PostureNonPQCClassical)
	}
	if bundle.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Errorf("a parsed RSA CA certificate must never be classified no-encryption")
	}
	if bundle.Properties["publicKeyAlgorithm"] != "RSA" {
		t.Errorf("expected parsed publicKeyAlgorithm RSA, got %q", bundle.Properties["publicKeyAlgorithm"])
	}

	// 2. AWS_ACM_PCA -> Unknown (key algo not in sourceData), cross-linked.
	pca, ok := by[pcaARN]
	if !ok {
		t.Fatalf("pca anchor missing from assets: %v", by)
	}
	if p := pca.Properties["posture"]; p != string(models.PostureUnknown) {
		t.Errorf("AWS_ACM_PCA: posture = %q, want %q (algo not exposed -> do not guess)", p, models.PostureUnknown)
	}
	if pca.Properties["acmPcaArn"] != caArn {
		t.Errorf("AWS_ACM_PCA anchor must cross-link the CA ARN, got %q", pca.Properties["acmPcaArn"])
	}

	// 3. SELF_SIGNED_REPOSITORY / no PEM -> Unknown, never fabricated.
	self, ok := by[selfARN]
	if !ok {
		t.Fatalf("self-signed anchor missing from assets: %v", by)
	}
	if p := self.Properties["posture"]; p != string(models.PostureUnknown) {
		t.Errorf("SELF_SIGNED_REPOSITORY: posture = %q, want %q (no PEM parsed -> Unknown)", p, models.PostureUnknown)
	}
}
