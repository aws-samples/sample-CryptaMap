package certmgmt

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	ratypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// The IAM Roles Anywhere trust-model fact is the doc-fact
// "certmgmt/rolesanywhere/trust-model-signature-validation" (internal/pqc
// knowledge). Its "Signature validation" section documents that validation uses
// "the signature validation algorithm required by the key type of the certificate,
// for example RSA or ECDSA" — it does NOT document any universal ML-DSA /
// post-quantum floor. It therefore backs only the per-source provenance note for
// why an anchor's algo is Unknown here, never a fabricated safe posture.
//
// Verified live 2026-06-09:
//
//	https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html
//	https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_Source.html
//	https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_SourceData.html

// RolesAnywhereScanner discovers IAM Roles Anywhere trust anchors — the PKI roots
// that authenticate non-AWS workloads via X.509 certificates. CERTIFICATE category
// (mirrors iam_certs.go / acmpca.go).
//
// Crypto-classification provenance (spine rule: never fabricate a safe posture):
//   - CERTIFICATE_BUNDLE -> ListTrustAnchors inlines the CA PEM in
//     source.sourceData (x509CertificateData). We PARSE it with parseCertPEM, so
//     posture is OBSERVED: RSA/ECDSA/Ed25519 -> NonPQCClassical; an unrecognized
//     OID (e.g. a real ML-DSA CA cert crypto/x509 cannot decode) -> Unknown.
//   - AWS_ACM_PCA -> source.sourceData carries only the CA ARN (acmPcaArn), NOT
//     the key algorithm. We cross-link the ARN and leave posture Unknown; the
//     acmpca asset is the source of truth for that CA's posture.
//   - SELF_SIGNED_REPOSITORY / unknown union member -> Unknown.
type RolesAnywhereScanner struct{}

// Name returns the canonical scanner identifier.
func (RolesAnywhereScanner) Name() string { return "rolesanywhere" }

// Category returns the primary category for this scanner.
func (RolesAnywhereScanner) Category() models.Category { return models.CategoryCertificate }

// rolesAnywhereAPI is the minimal slice of the rolesanywhere client this scanner
// uses. ListTrustAnchors is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping trust anchors in
// accounts with many of them. Defining it as an interface keeps the pagination +
// error propagation logic unit-testable with a fake (the concrete
// *rolesanywhere.Client satisfies it).
type rolesAnywhereAPI interface {
	ListTrustAnchors(ctx context.Context, in *rolesanywhere.ListTrustAnchorsInput, optFns ...func(*rolesanywhere.Options)) (*rolesanywhere.ListTrustAnchorsOutput, error)
}

// Scan lists all IAM Roles Anywhere trust anchors and emits one asset per anchor.
// Pagination via nextToken; capped at services.MaxAssetsPerScanner. No per-anchor
// Get is needed: ListTrustAnchors already returns the full source union.
func (s RolesAnywhereScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := rolesanywhere.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListTrustAnchors and classifies each
// trust anchor into a CryptoAsset. A ListTrustAnchors error is NOT swallowed — it
// is returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s RolesAnywhereScanner) scan(ctx context.Context, client rolesAnywhereAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListTrustAnchors(ctx, &rolesanywhere.ListTrustAnchorsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("rolesanywhere ListTrustAnchors: %w", err)
		}
		for _, ta := range out.TrustAnchors {
			if ta.TrustAnchorArn == nil {
				continue
			}
			id := *ta.TrustAnchorArn

			name := ""
			if ta.Name != nil {
				name = *ta.Name
			}
			enabled := false
			if ta.Enabled != nil {
				enabled = *ta.Enabled
			}

			sourceType := ""
			acmPcaArn := ""
			pemBody := ""
			if ta.Source != nil {
				sourceType = string(ta.Source.SourceType)
				// SourceData is a smithy UNION (only one member set).
				switch sd := ta.Source.SourceData.(type) {
				case *ratypes.SourceDataMemberAcmPcaArn:
					acmPcaArn = sd.Value
				case *ratypes.SourceDataMemberX509CertificateData:
					pemBody = sd.Value
				}
			}

			// parseCertPEM returns PostureUnknown on empty/unparseable input, so a
			// non-bundle anchor (empty pemBody) yields Unknown — never a fabricated
			// posture.
			parsed := parseCertPEM(pemBody)

			// Subject/issuer/validity are not exposed by ListTrustAnchors, so they
			// stay empty rather than being invented.
			props := services.CertProps(name, "", parsed.SigAlgo, time.Time{}, time.Time{})
			if parsed.AlgoProps != nil {
				props.AlgorithmProperties = parsed.AlgoProps
			}

			a := services.NewAsset("rolesanywhere", models.CategoryCertificate, accountID, region, id, "AWS::RolesAnywhere::TrustAnchor", props)
			a.Properties["trustAnchorName"] = name
			a.Properties["enabled"] = boolStr(enabled)
			if sourceType != "" {
				a.Properties["sourceType"] = sourceType
			}
			if ta.TrustAnchorId != nil {
				a.Properties["trustAnchorId"] = *ta.TrustAnchorId
			}
			if parsed.PubKeyAlgo != "" {
				a.Properties["publicKeyAlgorithm"] = parsed.PubKeyAlgo
			}
			if acmPcaArn != "" {
				// Cross-link to the acmpca asset that owns this CA's real key algo.
				a.Properties["acmPcaArn"] = acmPcaArn
			}

			switch {
			case parsed.Posture == models.PostureNonPQCClassical:
				// Observed from the real parsed CERTIFICATE_BUNDLE PEM.
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				services.StampObserved(&a, "high")
			default:
				// Unrecognized-OID bundle, AWS_ACM_PCA, or SELF_SIGNED_REPOSITORY:
				// do NOT guess. Record Unknown; stamp the trust-model doc as the
				// basis for *why* it is Unknown, at low confidence.
				services.PostureProperty(&a, models.PostureUnknown)
				services.StampDocFactKeyed(&a, "certmgmt/rolesanywhere/trust-model-signature-validation")
			}

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

// boolStr renders a bool as the canonical "true"/"false" property string.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
