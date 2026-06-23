package certmgmt

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appstream"
	asTypes "github.com/aws/aws-sdk-go-v2/service/appstream/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// AppStreamCertAuthScanner inventories AWS AppStream 2.0 certificate-based
// authentication on directory configurations.
//
// ADVERSARIAL FLIP — this is NOT an at-rest encryption surface. AppStream's
// at-rest data (home folders, app settings) delegates to S3 and EBS, which are
// scanned by their own scanners; classifying AppStream as "encryption off" would
// be wrong. The crypto surface UNIQUE to AppStream here is the workforce-VDI
// TRUST ANCHOR: certificate-based authentication gates SAML-federated users onto
// AD-domain-joined streaming instances using X.509 CLIENT certificates issued by
// an ACM Private CA. That CA mints classical X.509 (RSA/ECDSA) certificates whose
// signatures are quantum-vulnerable under Shor's algorithm, so every directory
// config with cert-based auth ENABLED is a NonPQCClassical migration target —
// never a no-encryption finding (this is auth/cert custody, not encryption).
//
// The CA's OWN key algorithm is classified separately by the acmpca scanner via
// the CertificateAuthorityArn recorded here; this scanner records only THAT
// cert-based auth is enforced and whether AD-password fallback is still allowed.
//
// passwordFallbackAllowed is true for Status=ENABLED (users may fall back to AD
// password if cert auth fails) and false for ENABLED_NO_DIRECTORY_LOGIN_FALLBACK
// (cert-only — a strictly stronger but still classical posture). A DISABLED
// config means cert-based auth is not in force; we emit it as an informational
// asset (NOT no-encryption) so the surface is accounted for without fabricating
// either an alarm or an all-clear.
type AppStreamCertAuthScanner struct{}

// Name returns the canonical scanner identifier.
func (AppStreamCertAuthScanner) Name() string { return "appstream_certauth" }

// Category returns the primary category for this scanner.
func (AppStreamCertAuthScanner) Category() models.Category { return models.CategoryCertificate }

// classifyAppStreamCertAuth maps a directory config's
// CertificateBasedAuthProperties to a fully classified CryptoAsset. It is the
// SINGLE source of truth for AppStream cert-based-auth posture: pure (no AWS
// client, no context), driven only by the SDK type + the resource coordinates,
// so the table test can exercise every status branch directly.
//
// Honesty contract baked in here:
//   - cba == nil means there is NO cert-based-auth block to assert anything
//     about, so it returns ok=false and Scan SKIPS the directory entirely. It
//     NEVER fabricates a no-encryption finding for an absent block.
//   - Every status (ENABLED / ENABLED_NO_DIRECTORY_LOGIN_FALLBACK / DISABLED /
//     any future value) maps to a CERTIFICATE asset, never an encryption
//     posture. ENABLED states are NonPQCClassical (classical X.509 trust in
//     force). A DISABLED config is recorded informationally as NonPQCClassical
//     for inventory — never PostureNoEncryption, because this surface is
//     auth/cert custody, not at-rest encryption.
func classifyAppStreamCertAuth(accountID, region, dirName string, cba *asTypes.CertificateBasedAuthProperties) (models.CryptoAsset, bool) {
	// No cert-based auth block at all: nothing to assert about this trust
	// surface. Signal skip rather than emit a misleading asset.
	if cba == nil {
		return models.CryptoAsset{}, false
	}
	status := cba.Status

	// classical X.509 client-cert trust → certificate asset, never encryption.
	// signatureAlgorithmRef is left empty: the AppStream API does not expose the
	// client cert's signature algorithm, and "X.509 client certificate" is a
	// format description, not a signature-algorithm token. The X.509 format is
	// recorded via CertificateProperties.CertificateFormat (set by CertProps).
	props := services.CertProps(dirName, "", "", time.Time{}, time.Time{})
	if props.CertificateProperties != nil {
		props.CertificateProperties.SubjectName = dirName
	}

	a := services.NewAsset("appstream_certauth", models.CategoryCertificate, accountID, region, dirName, "AWS::AppStream::DirectoryConfig", props)
	services.PostureProperty(&a, models.PostureNonPQCClassical)
	services.StampObserved(&a, "high")

	a.Properties["certBasedAuthStatus"] = string(status)
	if cba.CertificateAuthorityArn != nil && *cba.CertificateAuthorityArn != "" {
		a.Properties["certificateAuthorityArn"] = *cba.CertificateAuthorityArn
	}

	switch status {
	case asTypes.CertificateBasedAuthStatusEnabled:
		a.Properties["passwordFallbackAllowed"] = "true"
		a.Properties["note"] = "AppStream certificate-based authentication is ENABLED: workforce VDI access is gated on classical X.509 client certificates issued by an ACM Private CA (quantum-vulnerable RSA/ECDSA; the CA key is classified by the acmpca scanner). AD-password fallback is allowed."
	case asTypes.CertificateBasedAuthStatusEnabledNoDirectoryLoginFallback:
		a.Properties["passwordFallbackAllowed"] = "false"
		a.Properties["note"] = "AppStream certificate-based authentication is ENABLED (cert-only, no AD-password fallback): workforce VDI access requires classical X.509 client certificates issued by an ACM Private CA (quantum-vulnerable RSA/ECDSA; the CA key is classified by the acmpca scanner)."
	default: // DISABLED (or any future unknown value)
		a.Properties["passwordFallbackAllowed"] = "true"
		a.Properties["note"] = "AppStream certificate-based authentication is configured but DISABLED on this directory; classical X.509 client-cert trust is not currently enforced. Recorded for inventory only (this is auth/cert custody, not at-rest encryption)."
	}
	return a, true
}

// Scan lists directory configurations and inspects each one's
// CertificateBasedAuthProperties. DescribeDirectoryConfigs returns the full
// config inline (no per-resource Describe needed), so there is no inner fan-out.
func (s AppStreamCertAuthScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := appstream.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region

	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeDirectoryConfigs(ctx, &appstream.DescribeDirectoryConfigsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("appstream DescribeDirectoryConfigs: %w", err)
		}
		for i := range out.DirectoryConfigs {
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
			dc := out.DirectoryConfigs[i]
			if dc.DirectoryName == nil {
				continue
			}
			a, ok := classifyAppStreamCertAuth(accountID, region, *dc.DirectoryName, dc.CertificateBasedAuthProperties)
			if !ok {
				continue
			}
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
