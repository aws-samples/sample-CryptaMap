// Package certmgmt scans certificate management services.
package certmgmt

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ACMScanner discovers AWS Certificate Manager certificates.
type ACMScanner struct{}

// Name returns the canonical scanner identifier.
func (ACMScanner) Name() string { return "acm" }

// Category returns the primary category for this scanner.
func (ACMScanner) Category() models.Category { return models.CategoryCertificate }

// acmPosture maps an ACM key algorithm string to a CryptoPosture.
//
// ACM-issued certificates use only RSA/ECDSA key algorithms today, so the ML-DSA
// branch is effectively unreachable; it is kept defensively. If a PQC cert key
// ever appears, ML-DSA (FIPS 204) is a PURE post-quantum signature -> PQCReady,
// NOT PQCHybrid (a hybrid KEX). There is no ML-KEM cert key algorithm (a cert key
// signs, it does not encapsulate), so that branch is removed. Matches acmpcaPosture.
func acmPosture(keyAlgo string) models.CryptoPosture {
	a := strings.ToUpper(keyAlgo)
	a = strings.ReplaceAll(a, "-", "_")
	switch {
	case strings.Contains(a, "ML_DSA"):
		return models.PosturePQCReady
	case strings.HasPrefix(a, "RSA"), strings.HasPrefix(a, "EC_"), strings.HasPrefix(a, "ECDSA"):
		return models.PostureNonPQCClassical
	}
	// An unrecognized key algorithm (incl. a future AWS PQC key type) must not be
	// silently labeled classical — that would be a false all-clear. Report unknown.
	return models.PostureUnknown
}

// acmAlgorithmProps builds an AlgorithmProperties block for an ACM KeyAlgorithm
// enum string using the doc-sourced cipher table (curve/key-size/name/security
// levels are NOT returned by the ACM API). Returns nil for an empty/unknown
// algorithm so the cert block stays clean.
func acmAlgorithmProps(keyAlgo string) *models.AlgorithmProperties {
	if keyAlgo == "" {
		return nil
	}
	p, ok := pqc.ACMKeyAlgorithmProfile(keyAlgo)
	if !ok {
		return nil
	}
	prim := models.PrimitiveSignature
	return &models.AlgorithmProperties{
		Primitive:                prim,
		AlgorithmName:            p.AlgorithmName,
		KeySizeBits:              p.KeySizeBits,
		Curve:                    p.Curve,
		ClassicalSecurityLevel:   p.ClassicalSecurityLevel,
		NistQuantumSecurityLevel: p.NistQuantumSecurityLevel,
	}
}

// acmAPI is the minimal slice of the acm client this scanner uses.
// ListCertificates is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping certs in dense accounts.
// Defining it as an interface keeps the pagination + error propagation logic
// unit-testable with a fake (the concrete *acm.Client satisfies it).
type acmAPI interface {
	ListCertificates(ctx context.Context, in *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

// Scan lists all ACM certificates in the configured region and emits one CryptoAsset per certificate.
// Pagination via NextToken; capped at 1000 items as a safety bound.
func (s ACMScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := acm.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListCertificates and classifies
// each certificate into a CryptoAsset. A top-level ListCertificates error is NOT
// swallowed — it is returned so the engine records this scanner as errored
// (which surfaces in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s ACMScanner) scan(ctx context.Context, client acmAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("acm ListCertificates: %w", err)
		}
		for _, c := range out.CertificateSummaryList {
			if c.CertificateArn == nil {
				continue
			}
			d, derr := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: c.CertificateArn})
			if derr != nil {
				fmt.Fprintf(os.Stderr, "acm DescribeCertificate %s: %v\n", *c.CertificateArn, derr)
				continue
			}
			det := d.Certificate
			if det == nil {
				continue
			}
			sig := ""
			if det.SignatureAlgorithm != nil {
				sig = *det.SignatureAlgorithm
			}
			keyAlgo := string(det.KeyAlgorithm)
			subject := ""
			if det.Subject != nil {
				subject = *det.Subject
			}
			issuer := ""
			if det.Issuer != nil {
				issuer = *det.Issuer
			}
			var nb, na time.Time
			if det.NotBefore != nil {
				nb = *det.NotBefore
			}
			if det.NotAfter != nil {
				na = *det.NotAfter
			}
			id := *c.CertificateArn
			props := services.CertProps(subject, issuer, sig, nb, na)
			// Attach a doc-sourced algorithm block so Curve / Key size / Algorithm
			// (DASH today) fill in the cert detail panel.
			if ap := acmAlgorithmProps(keyAlgo); ap != nil {
				props.AlgorithmProperties = ap
			}
			a := services.NewAsset("acm", models.CategoryCertificate, accountID, region, id, "AWS::CertificateManager::Certificate", props)
			a.Properties["keyAlgorithm"] = keyAlgo

			// Additional fields from the SAME DescribeCertificate response.
			if det.DomainName != nil && *det.DomainName != "" {
				a.Properties["domainName"] = *det.DomainName
			}
			if len(det.SubjectAlternativeNames) > 0 {
				a.Properties["subjectAlternativeNames"] = strings.Join(det.SubjectAlternativeNames, ",")
			}
			if st := string(det.Status); st != "" {
				a.Properties["status"] = st
			}
			if tp := string(det.Type); tp != "" {
				a.Properties["type"] = tp
			}
			if re := string(det.RenewalEligibility); re != "" {
				a.Properties["renewalEligibility"] = re
			}
			if len(det.InUseBy) > 0 {
				// "which resources use this cert" — the requested datum.
				a.Properties["inUseBy"] = strings.Join(det.InUseBy, ",")
			}
			if det.CertificateAuthorityArn != nil && *det.CertificateAuthorityArn != "" {
				a.Properties["certificateAuthorityArn"] = *det.CertificateAuthorityArn
			}
			if det.Serial != nil && *det.Serial != "" {
				a.Properties["serial"] = *det.Serial
			}

			services.PostureProperty(&a, acmPosture(keyAlgo))
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
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
