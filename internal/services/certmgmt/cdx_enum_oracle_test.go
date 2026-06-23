package certmgmt

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/signer"
	signertypes "github.com/aws/aws-sdk-go-v2/service/signer/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestCertMgmtScanners_SDKEnumOracle_CBOMSchemaConformance is a contract-driven
// enum-coverage test. For every AWS SDK enum field a certmgmt scanner reads, it
// drives the REAL scan() core once per enum member — iterating AWS's OWN
// authoritative value set via the generated EnumType("").Values() method (so the
// SDK, not a hand-maintained list, is the oracle) — and asserts the scanner
// produces a CycloneDX 1.7 schema-VALID CBOM for EACH member.
//
// A panic OR a schema-validation failure for ANY real AWS enum value is a REAL
// BUG (e.g. an empty-string algorithm token, or a signature/key value that
// produces a CDX component the schema rejects). Values are NOT softened or
// skipped: a failing value is left FAILING and the failure message captures the
// enum type + exact value + jsonschema error.
//
// Free-string fields (no SDK enum) that still feed the CBOM — notably ACM's
// CertificateDetail.SignatureAlgorithm (Type: String per the ACM API reference,
// https://docs.aws.amazon.com/acm/latest/APIReference/API_CertificateDetail.html)
// — are covered with a curated, documented slice rather than .Values().
func TestCertMgmtScanners_SDKEnumOracle_CBOMSchemaConformance(t *testing.T) {
	// Same schema-availability guard the existing conformance test uses: a
	// trivial valid doc must pass, else the vendored schema is absent -> skip
	// rather than false-fail.
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	const (
		acct   = "111122223333"
		region = "us-east-1"
	)

	// validateAssets asserts the scan did not error, produced at least one asset,
	// and that the resulting CBOM is CycloneDX 1.7 schema-valid. label identifies
	// the enum type + value under test so a failure points straight at the input.
	validateAssets := func(t *testing.T, label string, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: scan returned error: %v", label, err)
		}
		if len(assets) == 0 {
			t.Fatalf("%s: expected at least one asset, got none", label)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("%s: CBOM failed CycloneDX 1.7 schema validation: %v", label, verr)
		}
	}

	// ---------------------------------------------------------------------
	// ACM
	// ---------------------------------------------------------------------

	// acm.CertificateDetail.KeyAlgorithm — SDK enum acmtypes.KeyAlgorithm.
	// Drives string(det.KeyAlgorithm) -> acmAlgorithmProps / acmPosture and the
	// "keyAlgorithm" property. Iterate AWS's own value set.
	t.Run("acm/KeyAlgorithm", func(t *testing.T) {
		for _, v := range acmtypes.KeyAlgorithm("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				const arn = "arn:aws:acm:us-east-1:111122223333:certificate/abc"
				client := &fakeACMClient{
					listPages: []*acm.ListCertificatesOutput{
						{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: acmStrptr(arn)}}},
					},
					describeOut: map[string]*acm.DescribeCertificateOutput{
						arn: {
							Certificate: &acmtypes.CertificateDetail{
								CertificateArn:     acmStrptr(arn),
								KeyAlgorithm:       v, // <-- enum member under test
								SignatureAlgorithm: acmStrptr("SHA256WITHRSA"),
								Status:             acmtypes.CertificateStatusIssued,
								DomainName:         acmStrptr("example.com"),
							},
						},
					},
				}
				assets, err := ACMScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "acmtypes.KeyAlgorithm="+string(v), assets, err)
			})
		}
	})

	// acm.CertificateDetail.Status — SDK enum acmtypes.CertificateStatus.
	// Drives the "status" property. Hold KeyAlgorithm at a fixed valid value.
	t.Run("acm/CertificateStatus", func(t *testing.T) {
		for _, v := range acmtypes.CertificateStatus("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				const arn = "arn:aws:acm:us-east-1:111122223333:certificate/abc"
				client := &fakeACMClient{
					listPages: []*acm.ListCertificatesOutput{
						{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: acmStrptr(arn)}}},
					},
					describeOut: map[string]*acm.DescribeCertificateOutput{
						arn: {
							Certificate: &acmtypes.CertificateDetail{
								CertificateArn:     acmStrptr(arn),
								KeyAlgorithm:       acmtypes.KeyAlgorithmRsa2048,
								SignatureAlgorithm: acmStrptr("SHA256WITHRSA"),
								Status:             v, // <-- enum member under test
								DomainName:         acmStrptr("example.com"),
							},
						},
					},
				}
				assets, err := ACMScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "acmtypes.CertificateStatus="+string(v), assets, err)
			})
		}
	})

	// acm.CertificateDetail.SignatureAlgorithm is a FREE STRING (the ACM API
	// reference lists it as Type: String with no enumerated valid values), and it
	// flows directly into CertificateProperties.SignatureAlgorithmRef in the CBOM.
	// There is no .Values() oracle, so cover the documented ACM signing-algorithm
	// set as a curated slice. (RSA/ECDSA families with SHA-256/384/512 — the
	// algorithms ACM uses to sign issued certificates.) An empty/garbage ref that
	// the schema rejects would be a REAL bug here.
	t.Run("acm/SignatureAlgorithm_curated", func(t *testing.T) {
		acmSignatureAlgorithms := []string{
			"SHA256WITHRSA",
			"SHA384WITHRSA",
			"SHA512WITHRSA",
			"SHA256WITHECDSA",
			"SHA384WITHECDSA",
			"SHA512WITHECDSA",
		}
		for _, sig := range acmSignatureAlgorithms {
			sig := sig
			t.Run(sig, func(t *testing.T) {
				const arn = "arn:aws:acm:us-east-1:111122223333:certificate/abc"
				client := &fakeACMClient{
					listPages: []*acm.ListCertificatesOutput{
						{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: acmStrptr(arn)}}},
					},
					describeOut: map[string]*acm.DescribeCertificateOutput{
						arn: {
							Certificate: &acmtypes.CertificateDetail{
								CertificateArn:     acmStrptr(arn),
								KeyAlgorithm:       acmtypes.KeyAlgorithmRsa2048,
								SignatureAlgorithm: acmStrptr(sig), // <-- curated value under test
								Status:             acmtypes.CertificateStatusIssued,
								DomainName:         acmStrptr("example.com"),
							},
						},
					},
				}
				assets, err := ACMScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "acm SignatureAlgorithm="+sig, assets, err)
			})
		}
	})

	// ---------------------------------------------------------------------
	// ACM PCA
	// ---------------------------------------------------------------------

	// acmpca CertificateAuthorityConfiguration.KeyAlgorithm — SDK enum
	// acmpcatypes.KeyAlgorithm. Drives string(...KeyAlgorithm) -> acmpcaPosture /
	// acmpcaAlgorithmProps + the "keyAlgorithm" property. Iterate AWS's value set.
	t.Run("acmpca/KeyAlgorithm", func(t *testing.T) {
		for _, v := range acmpcatypes.KeyAlgorithm("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				ca := acmpcatypes.CertificateAuthority{
					Arn:    acmpcaStrptr("arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/ca-1"),
					Status: acmpcatypes.CertificateAuthorityStatusActive,
					CertificateAuthorityConfiguration: &acmpcatypes.CertificateAuthorityConfiguration{
						KeyAlgorithm:     v, // <-- enum member under test
						SigningAlgorithm: acmpcatypes.SigningAlgorithmSha256withrsa,
					},
				}
				client := &fakeACMPCAClient{
					acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
						{CertificateAuthorities: []acmpcatypes.CertificateAuthority{ca}},
					},
				}
				assets, err := ACMPCAScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "acmpcatypes.KeyAlgorithm="+string(v), assets, err)
			})
		}
	})

	// acmpca CertificateAuthorityConfiguration.SigningAlgorithm — SDK enum
	// acmpcatypes.SigningAlgorithm. Drives string(...SigningAlgorithm) ->
	// SignatureAlgorithmRef (a CycloneDX refType) + the "signingAlgorithm"
	// property. Hold KeyAlgorithm at a fixed valid value; iterate AWS's value set.
	t.Run("acmpca/SigningAlgorithm", func(t *testing.T) {
		for _, v := range acmpcatypes.SigningAlgorithm("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				ca := acmpcatypes.CertificateAuthority{
					Arn:    acmpcaStrptr("arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/ca-1"),
					Status: acmpcatypes.CertificateAuthorityStatusActive,
					CertificateAuthorityConfiguration: &acmpcatypes.CertificateAuthorityConfiguration{
						KeyAlgorithm:     acmpcatypes.KeyAlgorithmRsa2048,
						SigningAlgorithm: v, // <-- enum member under test
					},
				}
				client := &fakeACMPCAClient{
					acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
						{CertificateAuthorities: []acmpcatypes.CertificateAuthority{ca}},
					},
				}
				assets, err := ACMPCAScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "acmpcatypes.SigningAlgorithm="+string(v), assets, err)
			})
		}
	})

	// ---------------------------------------------------------------------
	// Signer
	// ---------------------------------------------------------------------

	// signer SigningConfigurationOverrides.EncryptionAlgorithm — SDK enum
	// signertypes.EncryptionAlgorithm. Drives string(sc.EncryptionAlgorithm) ->
	// signatureAlgorithmRef + AlgorithmName + the "signatureAlgorithm" property.
	// Iterate AWS's own value set.
	t.Run("signer/EncryptionAlgorithm", func(t *testing.T) {
		for _, v := range signertypes.EncryptionAlgorithm("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				const name = "prof"
				client := &fakeSignerClient{
					listPages: []*signer.ListSigningProfilesOutput{
						{Profiles: []signertypes.SigningProfile{
							{ProfileName: signerStrptr(name), Arn: signerStrptr("arn:aws:signer:us-east-1:111122223333:/signing-profiles/" + name)},
						}},
					},
					getOverrides: map[string]signertypes.EncryptionAlgorithm{
						name: v, // <-- enum member under test
					},
				}
				assets, err := SignerScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "signertypes.EncryptionAlgorithm="+string(v), assets, err)
			})
		}
	})

	// signer SigningConfigurationOverrides.HashAlgorithm — SDK enum
	// signertypes.HashAlgorithm. The fakeSignerClient always pairs the overrides'
	// EncryptionAlgorithm with HashAlgorithmSha256; to iterate HashAlgorithm's own
	// value set we drive the scan with each hash member while holding the
	// encryption algorithm fixed, asserting the CBOM stays schema-valid (the
	// hashAlgorithm flows to the "hashAlgorithm" property).
	t.Run("signer/HashAlgorithm", func(t *testing.T) {
		for _, h := range signertypes.HashAlgorithm("").Values() {
			h := h
			t.Run(string(h), func(t *testing.T) {
				const name = "prof"
				client := &fakeSignerHashClient{
					arn:      "arn:aws:signer:us-east-1:111122223333:/signing-profiles/" + name,
					name:     name,
					encAlgo:  signertypes.EncryptionAlgorithmRsa,
					hashAlgo: h, // <-- enum member under test
				}
				assets, err := SignerScanner{}.scan(context.Background(), client, acct, region)
				validateAssets(t, "signertypes.HashAlgorithm="+string(h), assets, err)
			})
		}
	})
}

// fakeSignerHashClient is a minimal signerAPI that returns exactly one profile
// and lets the test pin BOTH the EncryptionAlgorithm and HashAlgorithm overrides
// — the shared fakeSignerClient hard-codes HashAlgorithmSha256, so it cannot
// iterate HashAlgorithm's value set. Kept local to this enum-oracle test.
type fakeSignerHashClient struct {
	arn      string
	name     string
	listCall int
	encAlgo  signertypes.EncryptionAlgorithm
	hashAlgo signertypes.HashAlgorithm
}

func (f *fakeSignerHashClient) ListSigningProfiles(ctx context.Context, in *signer.ListSigningProfilesInput, optFns ...func(*signer.Options)) (*signer.ListSigningProfilesOutput, error) {
	if f.listCall >= 1 {
		return &signer.ListSigningProfilesOutput{}, nil
	}
	f.listCall++
	return &signer.ListSigningProfilesOutput{
		Profiles: []signertypes.SigningProfile{
			{ProfileName: signerStrptr(f.name), Arn: signerStrptr(f.arn)},
		},
	}, nil
}

func (f *fakeSignerHashClient) GetSigningProfile(ctx context.Context, in *signer.GetSigningProfileInput, optFns ...func(*signer.Options)) (*signer.GetSigningProfileOutput, error) {
	return &signer.GetSigningProfileOutput{
		Overrides: &signertypes.SigningPlatformOverrides{
			SigningConfiguration: &signertypes.SigningConfigurationOverrides{
				EncryptionAlgorithm: f.encAlgo,
				HashAlgorithm:       f.hashAlgo,
			},
		},
	}, nil
}
