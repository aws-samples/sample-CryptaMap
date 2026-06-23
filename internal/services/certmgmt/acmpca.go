package certmgmt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// The AWS Private CA supported-cryptographic-algorithms guarantee that backs the
// acmpca posture mapping below is the doc-fact "certmgmt/acmpca/supported-key-algos"
// (internal/pqc knowledge); a universal capability guarantee.

// ACMPCAScanner discovers AWS Private Certificate Authority CAs.
type ACMPCAScanner struct{}

// Name returns the canonical scanner identifier.
func (ACMPCAScanner) Name() string { return "acmpca" }

// Category returns the primary category for this scanner.
func (ACMPCAScanner) Category() models.Category { return models.CategoryCertificate }

// acmpcaPosture maps an ACMPCA KeyAlgorithm enum string to a CryptoPosture.
//
// ML-DSA (FIPS 204) is a PURE post-quantum SIGNATURE algorithm — it is NOT a
// classical+PQC hybrid and performs NO key exchange, so a CA whose key is
// ML_DSA_44/65/87 is pqc-ready, not pqc-hybrid. There is no ML_KEM key
// algorithm for a CA (a CA key signs, it does not encapsulate), so that branch
// is dead and removed. RSA / EC keys are classical; SM2 and any other value
// fall through to the classical default.
func acmpcaPosture(keyAlgo string) models.CryptoPosture {
	a := strings.ToUpper(keyAlgo)
	a = strings.ReplaceAll(a, "-", "_")
	switch {
	case strings.Contains(a, "ML_DSA"):
		return models.PosturePQCReady
	case strings.HasPrefix(a, "RSA"), strings.HasPrefix(a, "EC_"):
		return models.PostureNonPQCClassical
	}
	return models.PostureNonPQCClassical
}

// acmpcaAlgorithmProps builds an AlgorithmProperties block for an ACMPCA
// KeyAlgorithm enum string from the doc-sourced cipher table (curve / key size /
// security levels are not returned by the PCA API). Mirrors acm.go's
// acmAlgorithmProps(). Returns nil for an empty/unknown algorithm.
func acmpcaAlgorithmProps(keyAlgo string) *models.AlgorithmProperties {
	if keyAlgo == "" {
		return nil
	}
	p, ok := pqc.ACMKeyAlgorithmProfile(keyAlgo)
	if !ok {
		return nil
	}
	return &models.AlgorithmProperties{
		Primitive:                models.PrimitiveSignature,
		AlgorithmName:            p.AlgorithmName,
		KeySizeBits:              p.KeySizeBits,
		Curve:                    p.Curve,
		ClassicalSecurityLevel:   p.ClassicalSecurityLevel,
		NistQuantumSecurityLevel: p.NistQuantumSecurityLevel,
	}
}

// acmpcaAPI is the minimal slice of the acmpca client this scanner uses.
// ListCertificateAuthorities is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping CAs in accounts with
// many authorities. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *acmpca.Client
// satisfies it).
type acmpcaAPI interface {
	ListCertificateAuthorities(ctx context.Context, in *acmpca.ListCertificateAuthoritiesInput, optFns ...func(*acmpca.Options)) (*acmpca.ListCertificateAuthoritiesOutput, error)
}

// Scan lists all ACMPCA Certificate Authorities and emits one asset per CA.
// Pagination via NextToken; capped at 1000 items.
func (s ACMPCAScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := acmpca.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListCertificateAuthorities and
// classifies each CA into a CryptoAsset. A ListCertificateAuthorities error is NOT
// swallowed — it is returned so the engine records this scanner as errored, keeping
// a denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s ACMPCAScanner) scan(ctx context.Context, client acmpcaAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	const maxItems = 1000
	var nextToken *string
	for {
		out, err := client.ListCertificateAuthorities(ctx, &acmpca.ListCertificateAuthoritiesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("acmpca ListCertificateAuthorities: %w", err)
		}
		for _, ca := range out.CertificateAuthorities {
			if ca.Arn == nil {
				continue
			}
			keyAlgo := ""
			sigAlgo := ""
			subject := ""
			if ca.CertificateAuthorityConfiguration != nil {
				keyAlgo = string(ca.CertificateAuthorityConfiguration.KeyAlgorithm)
				// SigningAlgorithm is in the SAME ListCertificateAuthorities
				// response (CertificateAuthorityConfiguration.SigningAlgorithm) —
				// no extra Describe call needed — and is the true certificate
				// signature algorithm, distinct from the key algorithm.
				sigAlgo = string(ca.CertificateAuthorityConfiguration.SigningAlgorithm)
				if ca.CertificateAuthorityConfiguration.Subject != nil && ca.CertificateAuthorityConfiguration.Subject.CommonName != nil {
					subject = *ca.CertificateAuthorityConfiguration.Subject.CommonName
				}
			}
			var nb, na time.Time
			if ca.NotBefore != nil {
				nb = *ca.NotBefore
			}
			if ca.NotAfter != nil {
				na = *ca.NotAfter
			}
			id := *ca.Arn
			// SignatureAlgorithmRef holds the real signing algorithm; the key
			// algorithm stays in the keyAlgorithm property only.
			props := services.CertProps(subject, subject, sigAlgo, nb, na)
			if ap := acmpcaAlgorithmProps(keyAlgo); ap != nil {
				props.AlgorithmProperties = ap
			}
			a := services.NewAsset("acmpca", models.CategoryCertificate, accountID, region, id, "AWS::ACMPCA::CertificateAuthority", props)
			a.Properties["keyAlgorithm"] = keyAlgo
			if sigAlgo != "" {
				a.Properties["signingAlgorithm"] = sigAlgo
			}
			a.Properties["status"] = string(ca.Status)
			services.PostureProperty(&a, acmpcaPosture(keyAlgo))
			// The posture mapping is a universal AWS Private CA capability
			// guarantee (ML-DSA = pure PQC signature; RSA/EC = classical),
			// sourced from the supported-algorithms doc.
			services.StampDocFactKeyed(&a, "certmgmt/acmpca/supported-key-algos")
			assets = append(assets, a)
			if len(assets) >= maxItems {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
