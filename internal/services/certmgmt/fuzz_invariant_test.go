package certmgmt

// fuzz_invariant_test.go is the ADVERSARIAL property/invariant test for the
// certificate-domain scanner cores PLUS a Go-native fuzz target for the
// parseCertPEM parser. See the datarest sibling for the cross-package rationale.
//
// Scanner cores covered (Scanner{}.scan(ctx, fakeClient, acct, region)) with the
// hostile shapes (top-level List error / per-resource Describe error / nil-empty
// output / empty page). Invariants: no panic; top-level error propagates with
// nil/empty assets; every emitted asset has a 7-enum posture + non-empty Service;
// no asset from a FAILED read carries a confident no-encryption / symmetric-only
// verdict.
//
// The cert domain has an important honesty nuance the test encodes: a classical
// cert/signing service whose per-resource detail read FAILS may still emit a
// NonPQCClassical asset (the algorithm family is implied by the platform), which
// is NOT a fabricated all-clear — it is the conservative quantum-vulnerable
// verdict. What it must NEVER do on a failed read is claim no-encryption,
// symmetric-only, or (the real danger) a PQC-safe verdict. parseCertPEM's fuzz
// target guards exactly that last point against arbitrary garbage bytes.

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/signer"

	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	signertypes "github.com/aws/aws-sdk-go-v2/service/signer/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

var certValidPostures = map[models.CryptoPosture]bool{
	models.PostureNoEncryption:    true,
	models.PostureLegacyTLS:       true,
	models.PostureNonPQCClassical: true,
	models.PostureSymmetricOnly:   true,
	models.PosturePQCHybrid:       true,
	models.PosturePQCReady:        true,
	models.PostureUnknown:         true,
}

func certAssertHonest(t *testing.T, scanner string, assets []models.CryptoAsset, fromFailedRead bool) {
	t.Helper()
	for i, a := range assets {
		if a.Service == "" {
			t.Errorf("[%s] asset #%d has empty Service (escapes the registry)", scanner, i)
		}
		p := models.CryptoPosture(a.Properties["posture"])
		if !certValidPostures[p] {
			t.Errorf("[%s] asset #%d has posture %q outside the 7-value enum", scanner, i, p)
		}
		if fromFailedRead && (p == models.PostureNoEncryption || p == models.PostureSymmetricOnly) {
			t.Errorf("[%s] asset #%d produced a confident %q verdict on a FAILED read (fabricated verdict); note=%q",
				scanner, i, p, a.Properties["note"])
		}
		// The cert-domain extra guard: a failed read must NEVER fabricate a
		// PQC-safe verdict (the regulator-facing worst case — claiming a customer
		// is quantum-ready when the read failed).
		if fromFailedRead && (p == models.PosturePQCHybrid || p == models.PosturePQCReady) {
			t.Errorf("[%s] asset #%d produced a PQC-SAFE verdict %q on a FAILED read (fabricated all-clear)", scanner, i, p)
		}
	}
}

func certRunCase(t *testing.T, scanner, scenario string, wantErr, fromFailedRead bool, fn func() ([]models.CryptoAsset, error)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("[%s/%s] PANIC on hostile input: %v", scanner, scenario, r)
		}
	}()
	assets, err := fn()
	if wantErr {
		if err == nil {
			t.Errorf("[%s/%s] expected a propagated error, got nil (silent empty success)", scanner, scenario)
		}
		if len(assets) != 0 {
			t.Errorf("[%s/%s] expected no assets on a top-level read error, got %d", scanner, scenario, len(assets))
		}
	}
	certAssertHonest(t, scanner, assets, fromFailedRead)
}

var certErrHostile = errors.New("AccessDeniedException: hostile-fuzz denied read")

// acm: ListCertificates + DescribeCertificate.
type fuzzACMClient struct{ errTop, errResource bool }

func (f *fuzzACMClient) ListCertificates(ctx context.Context, in *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	if f.errTop {
		return nil, certErrHostile
	}
	if f.errResource {
		arn := "arn:aws:acm:us-east-1:111122223333:certificate/abcd"
		return &acm.ListCertificatesOutput{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: &arn}}}, nil
	}
	return &acm.ListCertificatesOutput{}, nil
}
func (f *fuzzACMClient) DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	if f.errResource {
		return nil, certErrHostile
	}
	return &acm.DescribeCertificateOutput{}, nil // nil Certificate -> skipped
}

// acmpca: ListCertificateAuthorities.
type fuzzACMPCAClient struct{ errTop bool }

func (f *fuzzACMPCAClient) ListCertificateAuthorities(ctx context.Context, in *acmpca.ListCertificateAuthoritiesInput, _ ...func(*acmpca.Options)) (*acmpca.ListCertificateAuthoritiesOutput, error) {
	if f.errTop {
		return nil, certErrHostile
	}
	return &acmpca.ListCertificateAuthoritiesOutput{}, nil
}

// signer: ListSigningProfiles + GetSigningProfile.
type fuzzSignerClient struct{ errTop, errResource bool }

func (f *fuzzSignerClient) ListSigningProfiles(ctx context.Context, in *signer.ListSigningProfilesInput, _ ...func(*signer.Options)) (*signer.ListSigningProfilesOutput, error) {
	if f.errTop {
		return nil, certErrHostile
	}
	if f.errResource {
		name := "profile1"
		return &signer.ListSigningProfilesOutput{Profiles: []signertypes.SigningProfile{{ProfileName: &name}}}, nil
	}
	return &signer.ListSigningProfilesOutput{}, nil
}
func (f *fuzzSignerClient) GetSigningProfile(ctx context.Context, in *signer.GetSigningProfileInput, _ ...func(*signer.Options)) (*signer.GetSigningProfileOutput, error) {
	if f.errResource {
		return nil, certErrHostile
	}
	return &signer.GetSigningProfileOutput{}, nil
}

// TestFuzzCertScannerInvariants drives the cert-domain cores with hostile inputs.
func TestFuzzCertScannerInvariants(t *testing.T) {
	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	t.Run("topLevelError_propagates", func(t *testing.T) {
		certRunCase(t, "acm", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return ACMScanner{}.scan(ctx, &fuzzACMClient{errTop: true}, acct, region)
		})
		certRunCase(t, "acmpca", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return ACMPCAScanner{}.scan(ctx, &fuzzACMPCAClient{errTop: true}, acct, region)
		})
		certRunCase(t, "signer", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return SignerScanner{}.scan(ctx, &fuzzSignerClient{errTop: true}, acct, region)
		})
	})

	t.Run("perResourceError_neverFabricatesVerdict", func(t *testing.T) {
		// acm DROPS a cert whose DescribeCertificate fails (continue); the property
		// guarded is that no EMITTED cert is a fabricated verdict and no panic.
		certRunCase(t, "acm", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return ACMScanner{}.scan(ctx, &fuzzACMClient{errResource: true}, acct, region)
		})
		// signer emits a conservative NonPQCClassical asset even when
		// GetSigningProfile fails (classical platform); must NOT be no-enc/symmetric/PQC.
		certRunCase(t, "signer", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return SignerScanner{}.scan(ctx, &fuzzSignerClient{errResource: true}, acct, region)
		})
	})

	t.Run("emptyAndNilOutput_noPanic", func(t *testing.T) {
		certRunCase(t, "acm", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return ACMScanner{}.scan(ctx, &fuzzACMClient{}, acct, region)
		})
		certRunCase(t, "acmpca", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return ACMPCAScanner{}.scan(ctx, &fuzzACMPCAClient{}, acct, region)
		})
		certRunCase(t, "signer", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return SignerScanner{}.scan(ctx, &fuzzSignerClient{}, acct, region)
		})
	})
}

// FuzzParseCertPEM is a Go-native fuzz target for the cert-body parser shared by
// the iot_certs / iam_certs scanners. parseCertPEM takes attacker-influenced
// bytes (a PEM body fetched from IoT/IAM) and must NEVER panic and NEVER return a
// fabricated PQC-safe verdict on garbage: any input that does not parse to a
// recognized classical key must classify as PostureUnknown (or, for a real
// classical key, NonPQCClassical) — never pqc-hybrid / pqc-ready, and never a
// non-enum posture. Seed with representative hostile bodies; the fuzzer mutates.
func FuzzParseCertPEM(f *testing.F) {
	seeds := []string{
		"",
		"not a pem at all",
		"-----BEGIN CERTIFICATE-----\nbm90IGJhc2U2NA==\n-----END CERTIFICATE-----",
		"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
		"\x00\x01\x02\x03\xff\xfe",
		"-----BEGIN CERTIFICATE-----\n" + // truncated/garbage DER
			"MIIBkTCB+wIJAKZ\n-----END CERTIFICATE-----",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	valid := map[models.CryptoPosture]bool{
		models.PostureNoEncryption:    true,
		models.PostureLegacyTLS:       true,
		models.PostureNonPQCClassical: true,
		models.PostureSymmetricOnly:   true,
		models.PosturePQCHybrid:       true,
		models.PosturePQCReady:        true,
		models.PostureUnknown:         true,
	}

	f.Fuzz(func(t *testing.T, pemBody string) {
		// Must not panic (the fuzz harness fails the run if it does).
		res := parseCertPEM(pemBody)

		// Posture must always be in the 7-value enum.
		if !valid[res.Posture] {
			t.Fatalf("parseCertPEM returned out-of-enum posture %q for input %q", res.Posture, pemBody)
		}

		// The honesty invariant: arbitrary / unparseable bytes must NEVER be
		// classified as PQC-safe. parseCertPEM only ever returns Unknown or
		// NonPQCClassical (for a recognized RSA/ECDSA/Ed25519 key) — a pqc-hybrid /
		// pqc-ready verdict from this parser would be a fabricated all-clear.
		if res.Posture == models.PosturePQCHybrid || res.Posture == models.PosturePQCReady {
			t.Fatalf("parseCertPEM fabricated a PQC-safe verdict %q from input %q", res.Posture, pemBody)
		}

		// If a classical posture was asserted, it must rest on a real recognized
		// public-key algorithm + populated algo props — never a bare guess.
		if res.Posture == models.PostureNonPQCClassical {
			if res.PubKeyAlgo == "" || res.AlgoProps == nil {
				t.Fatalf("parseCertPEM asserted NonPQCClassical without a recognized key (PubKeyAlgo=%q, AlgoProps=%v) for input %q",
					res.PubKeyAlgo, res.AlgoProps, pemBody)
			}
		}
	})
}
