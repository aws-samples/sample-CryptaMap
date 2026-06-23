package certmgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeACMClient is a hand-rolled acmAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. listPages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; listErr forces a
// ListCertificates failure. describeOut/describeErr drive DescribeCertificate
// keyed by certificate ARN so per-cert error handling can be exercised.
type fakeACMClient struct {
	listPages   []*acm.ListCertificatesOutput
	listCalls   int
	listErr     error
	describeOut map[string]*acm.DescribeCertificateOutput
	describeErr map[string]error
}

func (f *fakeACMClient) ListCertificates(ctx context.Context, in *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &acm.ListCertificatesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeACMClient) DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	arn := ""
	if in.CertificateArn != nil {
		arn = *in.CertificateArn
	}
	if f.describeErr != nil {
		if e, ok := f.describeErr[arn]; ok {
			return nil, e
		}
	}
	if f.describeOut != nil {
		if o, ok := f.describeOut[arn]; ok {
			return o, nil
		}
	}
	return &acm.DescribeCertificateOutput{}, nil
}

func acmStrptr(s string) *string { return &s }

// acmDescribeFor builds a DescribeCertificate response with the given key
// algorithm so tests can assert posture classification.
func acmDescribeFor(arn, keyAlgo string) *acm.DescribeCertificateOutput {
	return &acm.DescribeCertificateOutput{
		Certificate: &acmtypes.CertificateDetail{
			CertificateArn:     acmStrptr(arn),
			KeyAlgorithm:       acmtypes.KeyAlgorithm(keyAlgo),
			SignatureAlgorithm: acmStrptr("SHA256WITHRSA"),
			DomainName:         acmStrptr("example.com"),
		},
	}
}

// acmAssetByID returns the asset with the matching ResourceID, or nil.
func acmAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// acmPostureOf returns the recorded posture property of an asset.
func acmPostureOf(a *models.CryptoAsset) models.CryptoPosture {
	if a == nil || a.Properties == nil {
		return ""
	}
	return models.CryptoPosture(a.Properties["posture"])
}

// TestACMScanPaginates verifies the ListCertificates NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' certificates as
// assets. Without the pagination loop, only the first page's cert survives.
func TestACMScanPaginates(t *testing.T) {
	client := &fakeACMClient{
		listPages: []*acm.ListCertificatesOutput{
			{
				CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: acmStrptr("arn:cert-page1")}},
				NextToken:              acmStrptr("tok-page2"),
			},
			{
				CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: acmStrptr("arn:cert-page2")}},
				// no NextToken -> last page
			},
		},
		describeOut: map[string]*acm.DescribeCertificateOutput{
			"arn:cert-page1": acmDescribeFor("arn:cert-page1", "RSA_2048"),
			"arn:cert-page2": acmDescribeFor("arn:cert-page2", "RSA_2048"),
		},
	}
	assets, err := ACMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListCertificates to be called 2 times (paginated), got %d", client.listCalls)
	}
	for _, want := range []string{"arn:cert-page1", "arn:cert-page2"} {
		if acmAssetByID(assets, want) == nil {
			t.Errorf("expected cert %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestACMScanListErrorPropagates verifies the incompleteness decision: a
// ListCertificates failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestACMScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform acm:ListCertificates")
	client := &fakeACMClient{listErr: sentinel}
	_, err := ACMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListCertificates fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListCertificates failure, got: %v", err)
	}
}

// TestACMScanDescribeErrorDoesNotAbortScan verifies that a per-certificate
// DescribeCertificate failure does NOT abort the whole scan or silently corrupt
// it: the bad cert is skipped (logged to stderr) while the healthy certs in the
// same page are still emitted. This is a deliberate per-resource continue, not a
// silent drop of the entire scan.
func TestACMScanDescribeErrorDoesNotAbortScan(t *testing.T) {
	client := &fakeACMClient{
		listPages: []*acm.ListCertificatesOutput{
			{
				CertificateSummaryList: []acmtypes.CertificateSummary{
					{CertificateArn: acmStrptr("arn:cert-bad")},
					{CertificateArn: acmStrptr("arn:cert-good")},
				},
			},
		},
		describeErr: map[string]error{
			"arn:cert-bad": errors.New("ThrottlingException"),
		},
		describeOut: map[string]*acm.DescribeCertificateOutput{
			"arn:cert-good": acmDescribeFor("arn:cert-good", "RSA_2048"),
		},
	}
	assets, err := ACMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if acmAssetByID(assets, "arn:cert-good") == nil {
		t.Error("expected healthy cert to still be emitted despite sibling DescribeCertificate failure")
	}
	if acmAssetByID(assets, "arn:cert-bad") != nil {
		t.Error("cert whose DescribeCertificate failed should be skipped, not emitted with bogus data")
	}
}

// TestACMScanPostureHonesty asserts the certificate-domain honesty posture:
//   - a classical RSA cert -> NonPQCClassical (NEVER NoEncryption: a cert always
//     carries a signing key; the question is quantum-resistance, not presence).
//   - an unrecognized/future key algorithm -> Unknown (NEVER a clean classical
//     all-clear that could hide an unmodeled PQC or weak algorithm).
func TestACMScanPostureHonesty(t *testing.T) {
	client := &fakeACMClient{
		listPages: []*acm.ListCertificatesOutput{
			{
				CertificateSummaryList: []acmtypes.CertificateSummary{
					{CertificateArn: acmStrptr("arn:cert-rsa")},
					{CertificateArn: acmStrptr("arn:cert-mystery")},
				},
			},
		},
		describeOut: map[string]*acm.DescribeCertificateOutput{
			"arn:cert-rsa":     acmDescribeFor("arn:cert-rsa", "RSA_2048"),
			"arn:cert-mystery": acmDescribeFor("arn:cert-mystery", "FUTURE_PQC_ALGO_9000"),
		},
	}
	assets, err := ACMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	rsa := acmAssetByID(assets, "arn:cert-rsa")
	if rsa == nil {
		t.Fatal("expected the RSA cert to be emitted as an asset")
	}
	if got := acmPostureOf(rsa); got != models.PostureNonPQCClassical {
		t.Errorf("classical RSA cert: expected posture %q, got %q", models.PostureNonPQCClassical, got)
	}
	if got := acmPostureOf(rsa); got == models.PostureNoEncryption {
		t.Errorf("a certificate must NEVER be classified NoEncryption; a cert always carries a signing key")
	}

	mystery := acmAssetByID(assets, "arn:cert-mystery")
	if mystery == nil {
		t.Fatal("expected the unknown-algorithm cert to be emitted as an asset (not silently dropped)")
	}
	if got := acmPostureOf(mystery); got != models.PostureUnknown {
		t.Errorf("unrecognized key algorithm: expected posture %q (no false all-clear), got %q", models.PostureUnknown, got)
	}
}
