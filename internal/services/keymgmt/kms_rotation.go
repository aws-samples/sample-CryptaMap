package keymgmt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// KMSRotationScanner reports rotation status for KMS keys.
type KMSRotationScanner struct{}

// Name returns the canonical scanner identifier.
func (KMSRotationScanner) Name() string { return "kms_rotation" }

// Category returns the primary category for this scanner.
func (KMSRotationScanner) Category() models.Category { return models.CategoryKeyManagement }

// kmsRotationAPI is the minimal slice of the kms client this scanner uses.
// ListKeys is Marker-paginated, so the scanner must loop; a single call returns
// only the first page, silently dropping keys in dense accounts. Defining it as
// an interface keeps the pagination + per-key error handling unit-testable with
// a fake (the concrete *kms.Client satisfies it).
type kmsRotationAPI interface {
	ListKeys(ctx context.Context, in *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// Scan lists KMS keys, then queries rotation status and multi-region flag for each.
// Pagination via Marker; capped at services.MaxAssetsPerScanner items.
func (s KMSRotationScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListKeys via Marker, then per key
// reads DescribeKey metadata (which decides classification AND rotation
// applicability) and — only when applicable — GetKeyRotationStatus. A top-level
// ListKeys error is NOT swallowed (returned so the scan is visibly incomplete);
// a per-key DescribeKey/GetKeyRotationStatus error is logged and the key still
// emitted with best-effort metadata (never silently dropped).
func (s KMSRotationScanner) scan(ctx context.Context, client kmsRotationAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("kms ListKeys: %w", err)
		}
		// Cap the per-page key batch to the remaining per-scanner budget before the
		// per-key DescribeKey/GetKeyRotationStatus fan so we never exceed the cap and
		// always warn loudly (never silently stop) when truncating.
		keys := out.Keys
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(keys) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			keys = keys[:remaining]
		}
		for _, k := range keys {
			if k.KeyId == nil {
				continue
			}
			id := *k.KeyId

			// DescribeKey FIRST: the spec/usage/origin/custom-key-store decide both
			// classification AND whether rotation status is even applicable, so we must
			// read the metadata before deciding to call GetKeyRotationStatus.
			multiRegion := false
			keySpec := "kms-managed"
			keyUsage := ""
			origin := ""
			customKeyStore := false
			size := 0
			d, derr := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
			if derr != nil {
				fmt.Fprintf(os.Stderr, "kms DescribeKey %s: %v\n", id, derr)
			} else if d.KeyMetadata != nil {
				if d.KeyMetadata.MultiRegion != nil {
					multiRegion = *d.KeyMetadata.MultiRegion
				}
				if string(d.KeyMetadata.KeySpec) != "" {
					keySpec = string(d.KeyMetadata.KeySpec)
					size = kmsKeySize(keySpec)
				}
				keyUsage = string(d.KeyMetadata.KeyUsage)
				origin = string(d.KeyMetadata.Origin)
				if d.KeyMetadata.CustomKeyStoreId != nil && *d.KeyMetadata.CustomKeyStoreId != "" {
					customKeyStore = true
				}
			}

			// Automatic key rotation is supported ONLY on symmetric-default KMS keys
			// with AWS_KMS origin and no custom key store (AWS docs, see docURL below).
			// For asymmetric / HMAC / imported (EXTERNAL) / custom-key-store keys it can
			// never report enabled, so emitting rotationEnabled=false there conflates
			// "inapplicable" with "off". Only call GetKeyRotationStatus when applicable.
			rotationApplicable := keySpec == "SYMMETRIC_DEFAULT" && origin == "AWS_KMS" && !customKeyStore
			rotationEnabled := false
			rotationPeriodDays := ""
			nextRotationDate := ""
			onDemandStart := ""
			var nextRotation *time.Time
			if rotationApplicable {
				rotation, rerr := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
				if rerr != nil {
					fmt.Fprintf(os.Stderr, "kms GetKeyRotationStatus %s: %v\n", id, rerr)
				} else {
					rotationEnabled = rotation.KeyRotationEnabled
					// Additive fields from the SAME GetKeyRotationStatus call.
					if rotation.RotationPeriodInDays != nil {
						rotationPeriodDays = fmt.Sprintf("%d", *rotation.RotationPeriodInDays)
					}
					if rotation.NextRotationDate != nil {
						nextRotationDate = rotation.NextRotationDate.UTC().Format("2006-01-02")
						t := *rotation.NextRotationDate
						nextRotation = &t
					}
					if rotation.OnDemandRotationStartDate != nil {
						onDemandStart = rotation.OnDemandRotationStartDate.UTC().Format("2006-01-02")
					}
				}
			}

			// Material type reflects the real key usage+spec (asymmetric -> private-key,
			// symmetric/HMAC -> secret-key) instead of a flat 'secret-key'.
			props := services.KeyMaterialProps(kmsMaterialType(keyUsage, keySpec), models.StateActive, size, keySpec)
			// NextRotationDate fills the otherwise-DASH 'Updated' field.
			if rcm := props.RelatedCryptoMaterialProperties; rcm != nil && nextRotation != nil {
				rcm.UpdateDate = *nextRotation
			}

			a := services.NewAsset("kms_rotation", models.CategoryKeyManagement, accountID, region, id, "AWS::KMS::Key", props)
			a.Properties["multiRegion"] = fmt.Sprintf("%t", multiRegion)
			a.Properties["keySpec"] = keySpec
			if keyUsage != "" {
				a.Properties["keyUsage"] = keyUsage
			}
			if origin != "" {
				a.Properties["origin"] = origin
			}
			if rotationApplicable {
				a.Properties["rotationApplicable"] = "true"
				a.Properties["rotationEnabled"] = fmt.Sprintf("%t", rotationEnabled)
				if rotationPeriodDays != "" {
					a.Properties["rotationPeriodDays"] = rotationPeriodDays
				}
				if nextRotationDate != "" {
					a.Properties["nextRotationDate"] = nextRotationDate
				}
				if onDemandStart != "" {
					a.Properties["onDemandRotationStartDate"] = onDemandStart
				}
				a.Properties["note"] = "automatic rotation applies only to symmetric-default KMS keys (AWS docs)"
			} else {
				// Inapplicable: do NOT emit a misleading rotationEnabled=false.
				a.Properties["rotationApplicable"] = "false"
				a.Properties["rotationEnabled"] = "inapplicable"
				a.Properties["note"] = "automatic rotation applies only to symmetric-default KMS keys (AWS docs); inapplicable to asymmetric/HMAC/imported/custom-key-store keys"
			}
			// Posture comes from the real KeySpec: asymmetric RSA/ECC/SM2 ->
			// NonPQCClassical (quantum-vulnerable), ML_DSA_* -> PQCReady (pure PQC
			// signature), symmetric/HMAC -> SymmetricOnly. The prior flat
			// PostureSymmetricOnly false-safed every asymmetric customer-managed key as
			// quantum-resistant.
			services.PostureProperty(&a, kmsSpecPosture(keySpec))
			// Posture is driven by a live DescribeKey observation.
			services.StampObserved(&a, "high")
			// The rotation-inapplicability sub-claim rests on a universal AWS-doc
			// guarantee; cite it (url + date only) without clobbering the observed
			// source set just above. Sourced from the loaded knowledge by key.
			if !rotationApplicable {
				services.StampDocFactSubclaimKeyed(&a, "keymgmt/kms_rotation/rotation-inapplicable")
			}
			assets = append(assets, a)
		}
		if !out.Truncated || out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
