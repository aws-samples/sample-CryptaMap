package certmgmt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CloudFrontKeyGroupsScanner inventories CloudFront public keys (used to verify
// signed URLs / signed cookies and for field-level encryption). These are
// customer-uploaded asymmetric verification keys — classical RSA/ECDSA, both
// quantum-vulnerable -> NonPQCClassical (a quantum-migration target). The PEM is
// parsed to record the real algorithm and key size.
type CloudFrontKeyGroupsScanner struct{}

// Name returns the canonical scanner identifier.
func (CloudFrontKeyGroupsScanner) Name() string { return "cloudfront_keygroups" }

// Category returns the primary category for this scanner.
func (CloudFrontKeyGroupsScanner) Category() models.Category { return models.CategoryCertificate }

// cloudfrontKeyGroupsAPI is the minimal slice of the cloudfront client this
// scanner uses. ListPublicKeys is Marker-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping public keys in
// accounts with many of them. Defining it as an interface keeps the pagination +
// error propagation logic unit-testable with a fake (the concrete
// *cloudfront.Client satisfies it).
type cloudfrontKeyGroupsAPI interface {
	ListPublicKeys(ctx context.Context, in *cloudfront.ListPublicKeysInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListPublicKeysOutput, error)
}

// Scan paginates ListPublicKeys (the PEM is on the summary, no detail call).
func (s CloudFrontKeyGroupsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cloudfront.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListPublicKeys via Marker and
// classifies each public key into a CryptoAsset. A ListPublicKeys error is NOT
// swallowed — it is returned so the engine records this scanner as errored
// (surfaced in coverage), keeping a denied/throttled scan VISIBLY incomplete
// rather than a clean-looking empty success.
func (s CloudFrontKeyGroupsScanner) scan(ctx context.Context, client cloudfrontKeyGroupsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListPublicKeys(ctx, &cloudfront.ListPublicKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("cloudfront ListPublicKeys: %w", err)
		}
		if out.PublicKeyList == nil {
			break
		}
		for _, pk := range out.PublicKeyList.Items {
			if pk.Id == nil {
				continue
			}
			id := *pk.Id
			algoName, keyBits := "traditional public key", 0
			if pk.EncodedKey != nil {
				algoName, keyBits = parsePublicKeyAlgo(*pk.EncodedKey)
			}
			props := services.KeyMaterialProps("public-key", models.StateActive, keyBits, algoName)
			if props.AlgorithmProperties == nil {
				props.AlgorithmProperties = &models.AlgorithmProperties{}
			}
			props.AlgorithmProperties.Primitive = models.PrimitiveSignature
			props.AlgorithmProperties.AlgorithmName = algoName
			props.AlgorithmProperties.KeySizeBits = keyBits
			props.AlgorithmProperties.NistQuantumSecurityLevel = 0
			if pk.CreatedTime != nil && props.RelatedCryptoMaterialProperties != nil {
				props.RelatedCryptoMaterialProperties.CreationDate = pk.CreatedTime.UTC()
			}

			a := services.NewAsset("cloudfront_keygroups", models.CategoryCertificate, accountID, region, id, "AWS::CloudFront::PublicKey", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampObserved(&a, "high")
			if pk.Name != nil {
				a.Properties["publicKeyName"] = *pk.Name
			}
			a.Properties["algorithm"] = algoName
			if pk.CreatedTime != nil {
				a.Properties["createdTime"] = pk.CreatedTime.UTC().Format(time.RFC3339)
			}
			a.Properties["note"] = "CloudFront signed-URL/cookie verification key: traditional RSA/ECDSA (quantum-vulnerable signature); no PQC option."
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.PublicKeyList.NextMarker == nil || *out.PublicKeyList.NextMarker == "" {
			break
		}
		marker = out.PublicKeyList.NextMarker
	}
	return assets, nil
}

// parsePublicKeyAlgo parses a PEM-encoded public key and returns its algorithm
// label + key size in bits. Returns a generic label on parse failure (the key is
// still classical — never treated as PQC/safe).
func parsePublicKeyAlgo(encodedKeyPEM string) (string, int) {
	block, _ := pem.Decode([]byte(encodedKeyPEM))
	if block == nil {
		return "traditional public key (unparsed)", 0
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "traditional public key (unparsed)", 0
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		bits := 0
		if k.Curve != nil && k.Curve.Params() != nil {
			bits = k.Curve.Params().BitSize
		}
		return "ECDSA", bits
	default:
		return "traditional public key", 0
	}
}
