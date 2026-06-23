package certmgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeACMPCAClient is a hand-rolled acmpcaAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so
// the scanner loops through every page; listErr forces a top-level failure.
type fakeACMPCAClient struct {
	acmpcaPages []*acmpca.ListCertificateAuthoritiesOutput
	acmpcaCalls int
	acmpcaErr   error
}

func (f *fakeACMPCAClient) ListCertificateAuthorities(ctx context.Context, in *acmpca.ListCertificateAuthoritiesInput, optFns ...func(*acmpca.Options)) (*acmpca.ListCertificateAuthoritiesOutput, error) {
	if f.acmpcaErr != nil {
		return nil, f.acmpcaErr
	}
	if f.acmpcaCalls >= len(f.acmpcaPages) {
		return &acmpca.ListCertificateAuthoritiesOutput{}, nil
	}
	out := f.acmpcaPages[f.acmpcaCalls]
	f.acmpcaCalls++
	return out, nil
}

func acmpcaStrptr(s string) *string { return &s }

// acmpcaCA builds a CA list entry with a given ARN + key algorithm.
func acmpcaCA(arn, keyAlgo string) acmpcatypes.CertificateAuthority {
	return acmpcatypes.CertificateAuthority{
		Arn:    acmpcaStrptr(arn),
		Status: acmpcatypes.CertificateAuthorityStatusActive,
		CertificateAuthorityConfiguration: &acmpcatypes.CertificateAuthorityConfiguration{
			KeyAlgorithm:     acmpcatypes.KeyAlgorithm(keyAlgo),
			SigningAlgorithm: acmpcatypes.SigningAlgorithmSha256withrsa,
		},
	}
}

// acmpcaPostureByID indexes the posture property of returned assets by resourceID.
func acmpcaPostureByID(assets []models.CryptoAsset) map[string]string {
	m := map[string]string{}
	for _, a := range assets {
		m[a.ResourceID] = a.Properties["posture"]
	}
	return m
}

// TestACMPCAScanPaginates verifies the ListCertificateAuthorities NextToken loop:
// a fake that returns 2 pages (NextToken on page 1) must yield BOTH pages' CAs as
// assets. Without the pagination loop, only the first page's CA survives.
func TestACMPCAScanPaginates(t *testing.T) {
	client := &fakeACMPCAClient{
		acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
			{
				CertificateAuthorities: []acmpcatypes.CertificateAuthority{acmpcaCA("arn:ca-page1", "RSA_2048")},
				NextToken:              acmpcaStrptr("tok-page2"),
			},
			{
				CertificateAuthorities: []acmpcatypes.CertificateAuthority{acmpcaCA("arn:ca-page2", "RSA_2048")},
				// no NextToken -> last page
			},
		},
	}
	assets, err := ACMPCAScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.acmpcaCalls; c != 2 {
		t.Errorf("expected ListCertificateAuthorities to be called 2 times (paginated), got %d", c)
	}
	got := acmpcaPostureByID(assets)
	for _, want := range []string{"arn:ca-page1", "arn:ca-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected CA %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestACMPCAScanListErrorPropagates verifies the incompleteness posture: a
// ListCertificateAuthorities failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestACMPCAScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform acm-pca:ListCertificateAuthorities")
	client := &fakeACMPCAClient{acmpcaErr: sentinel}
	_, err := ACMPCAScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListCertificateAuthorities fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListCertificateAuthorities failure, got: %v", err)
	}
}

// TestACMPCAScanPostureHonesty asserts the certificate-domain honesty posture:
// classical RSA/EC keys -> NonPQCClassical (a CA always has a key, so it must
// NEVER be reported as no-encryption); a PURE post-quantum ML-DSA signing key ->
// PQCReady (NOT hybrid, since ML-DSA performs no key exchange).
func TestACMPCAScanPostureHonesty(t *testing.T) {
	cases := []struct {
		acmpcaName    string
		acmpcaKeyAlgo string
		acmpcaWant    models.CryptoPosture
	}{
		{"rsa-classical", "RSA_2048", models.PostureNonPQCClassical},
		{"ec-classical", "EC_prime256v1", models.PostureNonPQCClassical},
		{"mldsa-pqc", "ML_DSA_65", models.PosturePQCReady},
		// An unknown/unmapped algorithm must still be a classical key posture,
		// never silently dropped or reported as having no encryption.
		{"unknown-algo", "SM2", models.PostureNonPQCClassical},
	}
	for _, tc := range cases {
		t.Run(tc.acmpcaName, func(t *testing.T) {
			client := &fakeACMPCAClient{
				acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
					{CertificateAuthorities: []acmpcatypes.CertificateAuthority{acmpcaCA("arn:"+tc.acmpcaName, tc.acmpcaKeyAlgo)}},
				},
			}
			assets, err := ACMPCAScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			if len(assets) != 1 {
				t.Fatalf("expected exactly 1 asset (CA never silently dropped), got %d", len(assets))
			}
			got := assets[0].Properties["posture"]
			if got != string(tc.acmpcaWant) {
				t.Errorf("key algo %q: expected posture %q, got %q", tc.acmpcaKeyAlgo, tc.acmpcaWant, got)
			}
			if got == "" || got == string(models.PostureNoEncryption) {
				t.Errorf("key algo %q: a CA always has a signing key and must never be no-encryption; got %q", tc.acmpcaKeyAlgo, got)
			}
		})
	}
}

// TestACMPCAScanSkipsNilArn verifies a CA with a nil ARN is skipped (cannot form a
// stable resource identity) without aborting the whole scan or dropping siblings.
func TestACMPCAScanSkipsNilArn(t *testing.T) {
	client := &fakeACMPCAClient{
		acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
			{CertificateAuthorities: []acmpcatypes.CertificateAuthority{
				{Arn: nil, Status: acmpcatypes.CertificateAuthorityStatusActive},
				acmpcaCA("arn:ca-valid", "RSA_2048"),
			}},
		},
	}
	assets, err := ACMPCAScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil-ARN CA skipped, valid sibling kept), got %d", len(assets))
	}
	if assets[0].ResourceID != "arn:ca-valid" {
		t.Errorf("expected the valid CA to survive, got resourceID %q", assets[0].ResourceID)
	}
}
