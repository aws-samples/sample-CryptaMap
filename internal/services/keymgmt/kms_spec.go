// Package keymgmt scans AWS key-management services.
package keymgmt

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// KMSSpecScanner inspects KMS key specs (algorithm, usage, origin).
type KMSSpecScanner struct{}

// Name returns the canonical scanner identifier.
func (KMSSpecScanner) Name() string { return "kms_spec" }

// Category returns the primary category for this scanner.
func (KMSSpecScanner) Category() models.Category { return models.CategoryKeyManagement }

// kmsSpecPosture maps a KMS KeySpec string to a CryptoPosture.
//
// ML-DSA (FIPS 204) is a PURE post-quantum SIGNATURE algorithm — it performs no
// key exchange and is not a classical+PQC hybrid, so an ML_DSA_* key spec is
// PQCReady (pure PQC), NOT PQCHybrid (which denotes a hybrid KEX like
// X25519+ML-KEM). KMS exposes NO ML-KEM key spec (the only PQC KMS key type is
// ML-DSA for signing), so there is no ML_KEM branch here. This matches
// acmpcaPosture, which already classifies ML-DSA as PQCReady.
func kmsSpecPosture(keySpec string) models.CryptoPosture {
	a := strings.ToUpper(keySpec)
	a = strings.ReplaceAll(a, "-", "_")
	switch {
	case strings.Contains(a, "ML_DSA"):
		return models.PosturePQCReady
	case strings.HasPrefix(a, "RSA_"), strings.HasPrefix(a, "ECC_"), strings.HasPrefix(a, "SM2"):
		return models.PostureNonPQCClassical
	case strings.HasPrefix(a, "SYMMETRIC"), strings.HasPrefix(a, "HMAC"):
		return models.PostureSymmetricOnly
	}
	// Unknown / future KeySpec: classify Unknown, NOT symmetric-only. Defaulting an
	// unrecognized spec to symmetric-only would FALSE-SAFE a new asymmetric/quantum-
	// vulnerable spec as quantum-resistant; Unknown is the conservative posture.
	return models.PostureUnknown
}

// kmsAlgorithmName maps a KMS KeySpec to a friendly algorithm name for display
// (the Algorithm row), so the UI never shows a bare primitive code. Symmetric
// default is AES-256-GCM; HMAC and the asymmetric specs echo their spec name
// (already human-readable, e.g. RSA_2048, ECC_NIST_P256, ML_DSA_65).
func kmsAlgorithmName(keySpec string) string {
	a := strings.ToUpper(strings.ReplaceAll(keySpec, "-", "_"))
	switch {
	case a == "":
		return ""
	case strings.HasPrefix(a, "SYMMETRIC"):
		return "AES-256-GCM"
	default:
		// RSA_*, ECC_*, HMAC_*, ML_DSA_*, SM2 — the spec string is already a
		// readable algorithm identifier.
		return keySpec
	}
}

// kmsKeySize returns the key size in bits for a spec, preferring the
// doc-sourced cipher table (internal/pqc) and falling back to a parse.
func kmsKeySize(keySpec string) int {
	if p, ok := pqc.KMSKeySpecProfile(keySpec); ok && p.KeySizeBits > 0 {
		return p.KeySizeBits
	}
	a := strings.ToUpper(keySpec)
	switch {
	case strings.Contains(a, "RSA_4096"):
		return 4096
	case strings.Contains(a, "RSA_3072"):
		return 3072
	case strings.Contains(a, "RSA_2048"):
		return 2048
	case strings.Contains(a, "ECC_NIST_P256"), strings.Contains(a, "ECC_SECG_P256"):
		return 256
	case strings.Contains(a, "ECC_NIST_P384"):
		return 384
	case strings.Contains(a, "ECC_NIST_P521"):
		return 521
	case strings.Contains(a, "HMAC_512"):
		return 512
	case strings.Contains(a, "HMAC_384"):
		return 384
	case strings.Contains(a, "HMAC_256"):
		return 256
	case strings.Contains(a, "HMAC_224"):
		return 224
	case strings.Contains(a, "SYMMETRIC"):
		return 256
	}
	return 0
}

// kmsMaterialType maps a key's usage + spec to a CycloneDX related-crypto
// material type, instead of hard-coding 'secret-key' for every key. Symmetric
// (SYMMETRIC_DEFAULT) and HMAC keys are secret-key; asymmetric keys (RSA/ECC/
// ML-DSA, SIGN_VERIFY or ENCRYPT_DECRYPT or key-agreement) are private-key.
func kmsMaterialType(keyUsage, keySpec string) string {
	spec := strings.ToUpper(strings.ReplaceAll(keySpec, "-", "_"))
	switch {
	case strings.HasPrefix(spec, "SYMMETRIC"), strings.HasPrefix(spec, "HMAC"):
		return "secret-key"
	case spec == "":
		return "secret-key"
	default:
		// RSA_*, ECC_*, SM2, ML_DSA_* are asymmetric key pairs; the KMS-held
		// half is the private key.
		return "private-key"
	}
}

// kmsCryptoState maps a KMS KeyState enum to a CycloneDX CryptoState, replacing
// the prior hard-coded StateActive.
func kmsCryptoState(state kmstypes.KeyState) models.CryptoState {
	switch state {
	case kmstypes.KeyStateEnabled:
		return models.StateActive
	case kmstypes.KeyStateDisabled, kmstypes.KeyStateUnavailable, kmstypes.KeyStatePendingImport:
		return models.StateSuspended
	case kmstypes.KeyStatePendingDeletion, kmstypes.KeyStatePendingReplicaDeletion:
		return models.StateDestroyed
	default:
		return models.StateUnknown
	}
}

// kmsSpecAPI is the minimal slice of the kms client this scanner uses. ListKeys
// is Marker-paginated (a single call returns only the first page, silently
// dropping keys in dense accounts) and DescribeKey is fanned out per key.
// Defining it as an interface keeps the pagination + per-key error handling
// unit-testable with a fake (the concrete *kms.Client satisfies it).
type kmsSpecAPI interface {
	ListKeys(ctx context.Context, in *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Scan lists all KMS keys and emits one asset per key with spec/usage/origin metadata.
// Pagination via Marker; capped at 1000 items.
func (s KMSSpecScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListKeys via Marker and fans out
// DescribeKey per key, classifying each into a CryptoAsset. A top-level ListKeys
// error is NOT swallowed — it is returned so the engine records this scanner as
// errored, keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s KMSSpecScanner) scan(ctx context.Context, client kmsSpecAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("kms ListKeys: %w", err)
		}
		// Cap the per-page key batch to the remaining per-scanner budget before the
		// concurrent fan-out so we never launch more than the cap's worth of
		// DescribeKey goroutines.
		keys := out.Keys
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(keys) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			keys = keys[:remaining]
		}
		// DescribeKey per key concurrently (bounded, order-preserving). A nil KeyId,
		// a DescribeKey error, or nil metadata drops the key (mirrors the old
		// per-key `continue`).
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, keys,
			func(ctx context.Context, k kmstypes.KeyListEntry) (models.CryptoAsset, bool) {
				if k.KeyId == nil {
					return models.CryptoAsset{}, false
				}
				d, derr := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "kms DescribeKey %s: %v\n", *k.KeyId, derr)
					return models.CryptoAsset{}, false
				}
				meta := d.KeyMetadata
				if meta == nil {
					return models.CryptoAsset{}, false
				}
				id := *k.KeyId
				keySpec := string(meta.KeySpec)
				keyUsage := string(meta.KeyUsage)
				origin := string(meta.Origin)

				// Material type + lifecycle state derived from the metadata we used
				// to discard (was hard-coded secret-key / active).
				matType := kmsMaterialType(keyUsage, keySpec)
				state := kmsCryptoState(meta.KeyState)
				props := services.KeyMaterialProps(matType, state, kmsKeySize(keySpec), keySpec)

				// Fill Created / Expires from KeyMetadata (DASH today).
				if rcm := props.RelatedCryptoMaterialProperties; rcm != nil {
					if meta.CreationDate != nil {
						rcm.CreationDate = *meta.CreationDate
					}
					if meta.ValidTo != nil {
						rcm.ExpirationDate = *meta.ValidTo
					}
				}

				a := services.NewAsset("kms_spec", models.CategoryKeyManagement, accountID, region, id, "AWS::KMS::Key", props)
				a.Properties["keySpec"] = keySpec
				// Also emit kmsKeySpec — the prop the dashboard detail panel reads for
				// the "KMS key spec" row (keySpec alone was never surfaced there) — and
				// a friendly algorithmName so the Algorithm row shows e.g. "AES-256-GCM"
				// instead of a raw primitive code.
				a.Properties["kmsKeySpec"] = keySpec
				if an := kmsAlgorithmName(keySpec); an != "" {
					a.Properties["algorithmName"] = an
				}
				a.Properties["keyUsage"] = keyUsage
				a.Properties["origin"] = origin
				a.Properties["keyManager"] = string(meta.KeyManager)
				a.Properties["keyState"] = string(meta.KeyState)
				if meta.MultiRegion != nil {
					a.Properties["multiRegion"] = fmt.Sprintf("%t", *meta.MultiRegion)
				}
				if meta.Description != nil && *meta.Description != "" {
					a.Properties["description"] = *meta.Description
				}
				if len(meta.SigningAlgorithms) > 0 {
					a.Properties["signingAlgorithms"] = joinSpecs(meta.SigningAlgorithms)
				}
				if len(meta.EncryptionAlgorithms) > 0 {
					a.Properties["encryptionAlgorithms"] = joinSpecs(meta.EncryptionAlgorithms)
				}
				if meta.CustomKeyStoreId != nil && *meta.CustomKeyStoreId != "" {
					a.Properties["customKeyStoreId"] = *meta.CustomKeyStoreId
				}
				if meta.CloudHsmClusterId != nil && *meta.CloudHsmClusterId != "" {
					a.Properties["cloudHsmClusterId"] = *meta.CloudHsmClusterId
				}
				services.PostureProperty(&a, kmsSpecPosture(keySpec))
				return a, true
			})
		assets = append(assets, page...)
		if !out.Truncated || out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}

// joinSpecs renders a slice of KMS algorithm-spec enum values to a comma list.
func joinSpecs[T ~string](specs []T) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		parts = append(parts, string(s))
	}
	return strings.Join(parts, ",")
}
