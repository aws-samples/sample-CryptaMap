package certmgmt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeIoTCertsClient is a hand-rolled iotCertsAPI for unit-testing the scanner's
// Marker pagination + per-cert DescribeCertificate handling without a live AWS
// client. listPages is returned page-by-page (each call consumes the next page)
// and the NextMarker is wired so the scanner loops through every page; listErr
// forces a ListCertificates failure. describePem / describeErr drive
// DescribeCertificate keyed by certificate ID so per-cert parse/error handling
// can be exercised.
type fakeIoTCertsClient struct {
	listPages   []*iot.ListCertificatesOutput
	listCalls   int
	listErr     error
	describePem map[string]string
	describeErr map[string]error
}

func (f *fakeIoTCertsClient) ListCertificates(ctx context.Context, in *iot.ListCertificatesInput, optFns ...func(*iot.Options)) (*iot.ListCertificatesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &iot.ListCertificatesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeIoTCertsClient) DescribeCertificate(ctx context.Context, in *iot.DescribeCertificateInput, optFns ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error) {
	id := ""
	if in.CertificateId != nil {
		id = *in.CertificateId
	}
	if f.describeErr != nil {
		if e, ok := f.describeErr[id]; ok {
			return nil, e
		}
	}
	pemBody := ""
	if f.describePem != nil {
		pemBody = f.describePem[id]
	}
	return &iot.DescribeCertificateOutput{
		CertificateDescription: &iottypes.CertificateDescription{
			CertificateArn: iotCertsStrptr("arn:" + id),
			CertificateId:  iotCertsStrptr(id),
			CertificatePem: iotCertsStrptr(pemBody),
		},
	}, nil
}

func iotCertsStrptr(s string) *string { return &s }

// iotCertsRSAPEM builds a real self-signed RSA leaf so the scanner's
// crypto/x509 parse path classifies it NonPQCClassical (RSA is quantum-vulnerable).
func iotCertsRSAPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return iotCertsSelfSigned(t, key, &key.PublicKey)
}

// iotCertsECDSAPEM builds a real self-signed ECDSA P-256 leaf -> NonPQCClassical.
func iotCertsECDSAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	return iotCertsSelfSigned(t, key, &key.PublicKey)
}

func iotCertsSelfSigned(t *testing.T, priv interface{}, pub interface{}) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "iotcerts-test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// iotCertsAssetByID returns the asset with the matching ResourceID, or nil.
func iotCertsAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// iotCertsPostureOf returns the recorded posture property of an asset.
func iotCertsPostureOf(a *models.CryptoAsset) models.CryptoPosture {
	if a == nil || a.Properties == nil {
		return ""
	}
	return models.CryptoPosture(a.Properties["posture"])
}

// TestIoTCertsScanPaginates verifies the ListCertificates Marker loop: a fake
// that returns 2 pages (NextMarker on page 1) must yield BOTH pages' certs as
// assets. Without the pagination loop, only the first page's cert survives.
func TestIoTCertsScanPaginates(t *testing.T) {
	rsaPem := iotCertsRSAPEM(t)
	client := &fakeIoTCertsClient{
		listPages: []*iot.ListCertificatesOutput{
			{
				Certificates: []iottypes.Certificate{{
					CertificateArn: iotCertsStrptr("arn:cert-page1"),
					CertificateId:  iotCertsStrptr("cert-page1"),
					Status:         iottypes.CertificateStatusActive,
				}},
				NextMarker: iotCertsStrptr("marker-page2"),
			},
			{
				Certificates: []iottypes.Certificate{{
					CertificateArn: iotCertsStrptr("arn:cert-page2"),
					CertificateId:  iotCertsStrptr("cert-page2"),
					Status:         iottypes.CertificateStatusActive,
				}},
				// no NextMarker -> last page
			},
		},
		describePem: map[string]string{
			"cert-page1": rsaPem,
			"cert-page2": rsaPem,
		},
	}
	assets, err := IoTCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListCertificates to be called 2 times (paginated), got %d", client.listCalls)
	}
	for _, want := range []string{"arn:cert-page1", "arn:cert-page2"} {
		if iotCertsAssetByID(assets, want) == nil {
			t.Errorf("expected cert %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestIoTCertsScanListErrorPropagates verifies the incompleteness decision: a
// ListCertificates failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestIoTCertsScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform iot:ListCertificates")
	client := &fakeIoTCertsClient{listErr: sentinel}
	_, err := IoTCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListCertificates fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListCertificates failure, got: %v", err)
	}
}

// TestIoTCertsScanDescribeErrorDoesNotDropCert verifies that a per-certificate
// DescribeCertificate failure does NOT abort the scan or silently drop the cert:
// unlike the ACM scanner (which skips), the IoT scanner deliberately STILL emits
// the cert — with PostureUnknown — so a leaf we could not read is visible and
// honestly unclassified, never disguised as a confident classical cert. The
// healthy sibling in the same page is also emitted.
func TestIoTCertsScanDescribeErrorDoesNotDropCert(t *testing.T) {
	rsaPem := iotCertsRSAPEM(t)
	client := &fakeIoTCertsClient{
		listPages: []*iot.ListCertificatesOutput{
			{
				Certificates: []iottypes.Certificate{
					{CertificateArn: iotCertsStrptr("arn:cert-bad"), CertificateId: iotCertsStrptr("cert-bad")},
					{CertificateArn: iotCertsStrptr("arn:cert-good"), CertificateId: iotCertsStrptr("cert-good")},
				},
			},
		},
		describeErr: map[string]error{
			"cert-bad": errors.New("ThrottlingException"),
		},
		describePem: map[string]string{
			"cert-good": rsaPem,
		},
	}
	assets, err := IoTCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	bad := iotCertsAssetByID(assets, "arn:cert-bad")
	if bad == nil {
		t.Fatal("cert whose DescribeCertificate failed must STILL be emitted (visible, not silently dropped)")
	}
	if got := iotCertsPostureOf(bad); got != models.PostureUnknown {
		t.Errorf("cert with failed DescribeCertificate: expected posture %q (honest), got %q", models.PostureUnknown, got)
	}
	if iotCertsAssetByID(assets, "arn:cert-good") == nil {
		t.Error("expected healthy cert to still be emitted alongside the failed sibling")
	}
}

// TestIoTCertsScanPostureHonesty asserts the certificate-domain honesty posture:
//   - a real classical RSA leaf -> NonPQCClassical (NEVER NoEncryption: a cert
//     always carries a signing key; the question is quantum-resistance).
//   - a real classical ECDSA leaf -> NonPQCClassical likewise.
//   - an unparseable / unrecognized PEM -> Unknown (NEVER a clean classical
//     all-clear that could hide an unmodeled PQC or weak algorithm).
func TestIoTCertsScanPostureHonesty(t *testing.T) {
	client := &fakeIoTCertsClient{
		listPages: []*iot.ListCertificatesOutput{
			{
				Certificates: []iottypes.Certificate{
					{CertificateArn: iotCertsStrptr("arn:cert-rsa"), CertificateId: iotCertsStrptr("cert-rsa")},
					{CertificateArn: iotCertsStrptr("arn:cert-ec"), CertificateId: iotCertsStrptr("cert-ec")},
					{CertificateArn: iotCertsStrptr("arn:cert-mystery"), CertificateId: iotCertsStrptr("cert-mystery")},
				},
			},
		},
		describePem: map[string]string{
			"cert-rsa": iotCertsRSAPEM(t),
			"cert-ec":  iotCertsECDSAPEM(t),
			// A garbage PEM body the x509 parser cannot decode -> the parser leaves
			// posture Unknown (the same fall-through a real future ML-DSA leaf with an
			// unrecognized OID would take). It must NOT be assumed classical.
			"cert-mystery": "-----BEGIN CERTIFICATE-----\nbm90LWEtcmVhbC1jZXJ0\n-----END CERTIFICATE-----\n",
		},
	}
	assets, err := IoTCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	for _, want := range []string{"arn:cert-rsa", "arn:cert-ec"} {
		a := iotCertsAssetByID(assets, want)
		if a == nil {
			t.Fatalf("expected classical cert %q to be emitted", want)
		}
		if got := iotCertsPostureOf(a); got != models.PostureNonPQCClassical {
			t.Errorf("classical cert %q: expected posture %q, got %q", want, models.PostureNonPQCClassical, got)
		}
		if got := iotCertsPostureOf(a); got == models.PostureNoEncryption {
			t.Errorf("a certificate must NEVER be classified NoEncryption; a cert always carries a signing key")
		}
	}

	mystery := iotCertsAssetByID(assets, "arn:cert-mystery")
	if mystery == nil {
		t.Fatal("expected the unparseable-PEM cert to be emitted as an asset (not silently dropped)")
	}
	if got := iotCertsPostureOf(mystery); got != models.PostureUnknown {
		t.Errorf("unparseable/unrecognized leaf: expected posture %q (no false all-clear), got %q", models.PostureUnknown, got)
	}
}
