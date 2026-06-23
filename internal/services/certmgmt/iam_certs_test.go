package certmgmt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// iamCertsStrptr is a local *string helper (prefixed to avoid colliding with
// other scanners' test helpers sharing the certmgmt package).
func iamCertsStrptr(s string) *string { return &s }

// iamCertsClassicalPEM is a REAL self-signed RSA-2048 / SHA256-RSA X.509
// certificate (generated offline, no live AWS). parseCertPEM must extract a
// classical signature/public-key algorithm from it and the scanner must stamp
// PostureNonPQCClassical — proving the honesty posture is driven by an actual
// parse, not a blanket assumption.
const iamCertsClassicalPEM = `-----BEGIN CERTIFICATE-----
MIICrzCCAZegAwIBAgIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExBpYW1j
ZXJ0cy5leGFtcGxlMB4XDTI2MDYxNjExNDgzMVoXDTI2MDYxNzExNDgzMVowGzEZ
MBcGA1UEAxMQaWFtY2VydHMuZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAMIHhMcUnjIevrx8Q/zCDYjy7DEenpjPAAG+ZdN719oEboHd0gK7
pTBgD4KHyocfcAiV6SPFwDhq5ur9Bdu83ZWnJq2c0roiXASRDxry1+dGsmLE7QHh
26qnw7jho5BBMW3L5OaqAfDDmKXdjk8mQGahaiG4M/tM3rLCzUqq7+qtfzFx8/2Z
JpbOEQ/AFAO2A2ztxCT7sJMD2w13D4AspuqNjH1jUqe0hyixmQKZlcwGLAQY0ZTC
TOe2DxY/bVw1YIvPQ7+5h36qpyQyPZThMCMeYHOWS2jWlSc941HrDi5S0yF0cXNl
ZeJbvu69Vec/9hr0j9GM946C9+KvewBssWcCAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAHvRc8QoUhssJfVnpiyB9dmcDWEhaFQzl1QQKT9l32rXUc1qJ+zl5JKGP/PuK
MLNJU9slJspYFdtfHhIec12iiPRQKuyc90FwtUwaa6wyRnuexpk5+eWUkmnjZYwp
YyD8S64KakkXU6zyikjhYmmfv2zdDE+LOzhLO5tAL3SqCaFjHgoNqJZV5pJ5ZniG
fQ75Gfpvv07kLWTYZmsoHbzm3qLhWf5X3h27j6FTooZoYLcXDfgF9FgcFD2ovLeN
Hgj85C67hlH4sur9YvHfsOwJHKzkcwxbj5qStlfii3n+y1+1SmyU+j4u2iL1PAx3
5Hr6vXSyKL5xenFpz6VkU5ffig==
-----END CERTIFICATE-----`

// fakeIAMCertsClient is a hand-rolled iamCertsAPI for unit-testing the scanner's
// pagination + per-cert PEM parsing + error propagation without a live AWS
// client. listPages is returned page-by-page (each call consumes the next page)
// with Marker/IsTruncated wired so the scanner loops through every page; listErr
// forces a ListServerCertificates failure; getBodies maps a server-cert name to
// its PEM body, and getErrs maps a name to a GetServerCertificate error.
type fakeIAMCertsClient struct {
	listPages []*iam.ListServerCertificatesOutput
	listCalls int
	listErr   error

	getBodies map[string]string
	getErrs   map[string]error
	getCalls  int
}

func (f *fakeIAMCertsClient) ListServerCertificates(ctx context.Context, in *iam.ListServerCertificatesInput, optFns ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &iam.ListServerCertificatesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeIAMCertsClient) GetServerCertificate(ctx context.Context, in *iam.GetServerCertificateInput, optFns ...func(*iam.Options)) (*iam.GetServerCertificateOutput, error) {
	f.getCalls++
	name := ""
	if in != nil && in.ServerCertificateName != nil {
		name = *in.ServerCertificateName
	}
	if f.getErrs != nil {
		if err, ok := f.getErrs[name]; ok {
			return nil, err
		}
	}
	body, ok := f.getBodies[name]
	if !ok {
		return &iam.GetServerCertificateOutput{}, nil
	}
	return &iam.GetServerCertificateOutput{
		ServerCertificate: &iamtypes.ServerCertificate{
			CertificateBody: iamCertsStrptr(body),
		},
	}, nil
}

func iamCertsMeta(name, arn string) iamtypes.ServerCertificateMetadata {
	return iamtypes.ServerCertificateMetadata{
		ServerCertificateName: iamCertsStrptr(name),
		Arn:                   iamCertsStrptr(arn),
		UploadDate:            iamCertsTimePtr(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)),
		Expiration:            iamCertsTimePtr(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)),
	}
}

func iamCertsTimePtr(t time.Time) *time.Time { return &t }

func iamCertsAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestIAMCertsScanPaginates verifies the ListServerCertificates Marker/IsTruncated
// loop: a fake returning 2 pages (IsTruncated+Marker on page 1) must yield BOTH
// pages' certs as assets. Without the pagination loop, only the first page's cert
// survives — silently dropping certs in dense accounts.
func TestIAMCertsScanPaginates(t *testing.T) {
	client := &fakeIAMCertsClient{
		listPages: []*iam.ListServerCertificatesOutput{
			{
				ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					iamCertsMeta("cert-page1", "arn:aws:iam::111122223333:server-certificate/cert-page1"),
				},
				IsTruncated: true,
				Marker:      iamCertsStrptr("marker-page2"),
			},
			{
				ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					iamCertsMeta("cert-page2", "arn:aws:iam::111122223333:server-certificate/cert-page2"),
				},
				// IsTruncated false -> last page
			},
		},
		getBodies: map[string]string{
			"cert-page1": iamCertsClassicalPEM,
			"cert-page2": iamCertsClassicalPEM,
		},
	}

	assets, err := IAMCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListServerCertificates to be called 2 times (paginated), got %d", client.listCalls)
	}
	for _, want := range []string{
		"arn:aws:iam::111122223333:server-certificate/cert-page1",
		"arn:aws:iam::111122223333:server-certificate/cert-page2",
	} {
		if _, ok := iamCertsAssetByID(assets, want); !ok {
			t.Errorf("expected cert %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestIAMCertsScanListErrorPropagates verifies the incompleteness contract: a
// ListServerCertificates failure (denied/throttled) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the cause — NOT a silent empty
// success that would look like "no IAM certs, all clear".
func TestIAMCertsScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform iam:ListServerCertificates")
	client := &fakeIAMCertsClient{listErr: sentinel}

	assets, err := IAMCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListServerCertificates fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListServerCertificates failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a hard List failure, got %d", len(assets))
	}
}

// TestIAMCertsScanClassicalCertPosture verifies the cert-domain honesty posture:
// a REAL classical RSA leaf parses to a classical signature algorithm and the
// asset is stamped PostureNonPQCClassical with an OBSERVED source (never a
// no-encryption verdict — a cert always carries a key/signature). It also asserts
// the parsed signature/public-key algorithm is recorded, proving posture is
// driven by an actual parse rather than a blanket assumption.
func TestIAMCertsScanClassicalCertPosture(t *testing.T) {
	client := &fakeIAMCertsClient{
		listPages: []*iam.ListServerCertificatesOutput{
			{
				ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					iamCertsMeta("classical", "arn:aws:iam::111122223333:server-certificate/classical"),
				},
			},
		},
		getBodies: map[string]string{"classical": iamCertsClassicalPEM},
	}

	assets, err := IAMCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := iamCertsAssetByID(assets, "arn:aws:iam::111122223333:server-certificate/classical")
	if !ok {
		t.Fatal("expected the classical cert to appear as an asset")
	}
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected posture %q for a parsed classical RSA cert, got %q", models.PostureNonPQCClassical, got)
	}
	if got := a.Properties["posture"]; got == string(models.PostureNoEncryption) {
		t.Errorf("a certificate must never be classified NoEncryption; got %q", got)
	}
	if got := a.Properties["source"]; got != "observed" {
		t.Errorf("expected a parsed classical verdict to be source=observed, got %q", got)
	}
	if a.CryptoProps.CertificateProperties == nil || a.CryptoProps.CertificateProperties.SignatureAlgorithmRef == "" {
		t.Errorf("expected the parsed signature algorithm to be recorded on a classical cert; props=%+v", a.CryptoProps.CertificateProperties)
	}
	if a.Properties["publicKeyAlgorithm"] == "" {
		t.Errorf("expected the parsed public-key algorithm to be recorded on a classical cert")
	}
}

// TestIAMCertsScanUnparseableCertIsUnknown verifies the false-safe guard: when the
// cert PEM cannot be parsed (bogus body, or a genuine PQC leaf with an
// unrecognized OID), the scanner must NOT fabricate a confident classical label —
// it records PostureUnknown (honest). The asset is still emitted, never silently
// dropped.
func TestIAMCertsScanUnparseableCertIsUnknown(t *testing.T) {
	client := &fakeIAMCertsClient{
		listPages: []*iam.ListServerCertificatesOutput{
			{
				ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					iamCertsMeta("opaque", "arn:aws:iam::111122223333:server-certificate/opaque"),
				},
			},
		},
		getBodies: map[string]string{"opaque": "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----"},
	}

	assets, err := IAMCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := iamCertsAssetByID(assets, "arn:aws:iam::111122223333:server-certificate/opaque")
	if !ok {
		t.Fatal("an unparseable cert must still be emitted as an asset, not silently dropped")
	}
	if got := a.Properties["posture"]; got != string(models.PostureUnknown) {
		t.Errorf("expected posture Unknown for an unparseable cert (no fabricated classical), got %q", got)
	}
}

// TestIAMCertsScanGetCertErrorNotSilentDrop verifies a per-cert
// GetServerCertificate failure does not silently drop the resource: the cert is
// still emitted (from its List metadata) and, with no parsed algorithm, carries
// the honest PostureUnknown rather than vanishing or being labeled classical.
func TestIAMCertsScanGetCertErrorNotSilentDrop(t *testing.T) {
	client := &fakeIAMCertsClient{
		listPages: []*iam.ListServerCertificatesOutput{
			{
				ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					iamCertsMeta("denied-get", "arn:aws:iam::111122223333:server-certificate/denied-get"),
				},
			},
		},
		getErrs: map[string]error{"denied-get": errors.New("AccessDenied: iam:GetServerCertificate")},
	}

	assets, err := IAMCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := iamCertsAssetByID(assets, "arn:aws:iam::111122223333:server-certificate/denied-get")
	if !ok {
		t.Fatal("a cert whose GetServerCertificate failed must still be emitted from List metadata, not dropped")
	}
	if got := a.Properties["posture"]; got != string(models.PostureUnknown) {
		t.Errorf("expected posture Unknown when the cert PEM could not be fetched, got %q", got)
	}
}
