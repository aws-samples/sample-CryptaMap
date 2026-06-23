package keymgmt

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// KMSCustomKeyStoreScanner inventories AWS KMS custom key stores (CloudHSM-backed
// and external XKS). A custom key store is a key-CUSTODY backend, not a key
// itself: KMS keys created in a CloudHSM key store are symmetric-only (the HSM
// holds non-extractable AES-256), and external key stores delegate key material to
// a customer-operated external key manager. Either way the KMS-facing keys are
// symmetric -> SymmetricOnly; the entry is recorded for custody/inventory with its
// type and connection state.
type KMSCustomKeyStoreScanner struct{}

// Name returns the canonical scanner identifier.
func (KMSCustomKeyStoreScanner) Name() string { return "kms_custom_key_store" }

// Category returns the primary category for this scanner.
func (KMSCustomKeyStoreScanner) Category() models.Category { return models.CategoryKeyManagement }

// kmsCustomKeyStoreAPI is the minimal slice of the kms client this scanner uses.
// DescribeCustomKeyStores is Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping key stores in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *kms.Client satisfies it).
type kmsCustomKeyStoreAPI interface {
	DescribeCustomKeyStores(ctx context.Context, in *kms.DescribeCustomKeyStoresInput, optFns ...func(*kms.Options)) (*kms.DescribeCustomKeyStoresOutput, error)
}

// Scan paginates DescribeCustomKeyStores (the entry is both list and detail).
func (s KMSCustomKeyStoreScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeCustomKeyStores via Marker
// and classifies each key store. A DescribeCustomKeyStores error is NOT swallowed
// — it is returned so the engine records this scanner as errored (visible in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s KMSCustomKeyStoreScanner) scan(ctx context.Context, client kmsCustomKeyStoreAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeCustomKeyStores(ctx, &kms.DescribeCustomKeyStoresInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("kms DescribeCustomKeyStores: %w", err)
		}
		for _, e := range out.CustomKeyStores {
			if e.CustomKeyStoreId == nil {
				continue
			}
			id := *e.CustomKeyStoreId
			// Both custom-key-store types front SYMMETRIC AES keys to KMS callers.
			props := services.KeyMaterialProps("secret-key", models.StateActive, 256, "SYMMETRIC_DEFAULT")
			if props.AlgorithmProperties == nil {
				props.AlgorithmProperties = &models.AlgorithmProperties{}
			}
			props.AlgorithmProperties.Primitive = models.PrimitiveAE
			props.AlgorithmProperties.AlgorithmName = "AES-256"
			props.AlgorithmProperties.KeySizeBits = 256
			props.AlgorithmProperties.ClassicalSecurityLevel = 256
			props.AlgorithmProperties.NistQuantumSecurityLevel = pqc.SymmetricNISTCategory(256) // AES-256 anchors NIST Category 5

			a := services.NewAsset("kms_custom_key_store", models.CategoryKeyManagement, accountID, region, id, "AWS::KMS::CustomKeyStore", props)
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampObserved(&a, "high")
			if e.CustomKeyStoreName != nil {
				a.Properties["customKeyStoreName"] = *e.CustomKeyStoreName
			}
			if e.CustomKeyStoreType != "" {
				a.Properties["customKeyStoreType"] = string(e.CustomKeyStoreType)
			}
			if e.ConnectionState != "" {
				a.Properties["connectionState"] = string(e.ConnectionState)
			}
			if e.CloudHsmClusterId != nil && *e.CloudHsmClusterId != "" {
				a.Properties["cloudHsmClusterId"] = *e.CloudHsmClusterId
			}
			if e.CustomKeyStoreType == kmstypes.CustomKeyStoreTypeExternalKeyStore {
				a.Properties["note"] = "External (XKS) key store: KMS keys are symmetric AES, with key material held in a customer-operated external key manager (custody is external to AWS)."
			}
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
