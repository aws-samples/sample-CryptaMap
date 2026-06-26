// Package keymgmt scans AWS key-management services.
package keymgmt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	pctypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
	"github.com/aws/smithy-go"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// PaymentCryptographyScanner inspects AWS Payment Cryptography keys (the payment-HSM
// key store: TDES/AES symmetric and RSA/ECC asymmetric payment keys).
//
// PROVENANCE (web-verified 2026-06-09):
//   - SDK module: github.com/aws/aws-sdk-go-v2/service/paymentcryptography
//     (the CONTROL plane — key management — NOT paymentcryptographydata, which is
//     the data plane that performs encrypt/decrypt/PIN ops). Client constructor
//     paymentcryptography.NewFromConfig(cfg).
//     https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/paymentcryptography
//   - ListKeys returns []KeySummary with KeyAttributes INLINE (KeyAlgorithm,
//     KeyClass, KeyUsage), plus Enabled/Exportable/KeyArn/KeyState. Pagination via
//     NextToken (response) / NextToken+MaxResults (request).
//     https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ListKeys.html
//   - GetKey adds the per-key fields NOT in the summary: KeyOrigin
//     (EXTERNAL|AWS_PAYMENT_CRYPTOGRAPHY) and CreateTimestamp. We fan GetKey out
//     per key (MapConcurrent) to capture provenance/origin for the CBOM.
//     https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_GetKey.html
//   - KeyAlgorithm valid values (verified verbatim): TDES_2KEY, TDES_3KEY, AES_128,
//     AES_192, AES_256, HMAC_SHA224/256/384/512, RSA_2048/3072/4096,
//     ECC_NIST_P256/P384/P521.
//     https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_KeyAttributes.html
//
// PQC CLASSIFICATION (the critical precision point):
// Payment Cryptography announced HYBRID POST-QUANTUM TLS for connections to its
// service ENDPOINT. Per the AWS user guide: "All service endpoints support TLS
// 1.2—1.3 and hybrid post-quantum TLS" and "AWS Payment Cryptography also supports
// a hybrid post-quantum key exchange option for the Transport Layer Security (TLS)
// network encryption protocol ... when you connect to AWS Payment Cryptography API
// endpoints."
// https://docs.aws.amazon.com/payment-cryptography/latest/userguide/data-protection.html
// That is a TRANSPORT property of the API endpoint, NOT a property of the stored
// keys. The KEYS this scanner inventories are classical payment-HSM keys: AES/TDES
// symmetric, RSA/ECC asymmetric. There is NO ML-KEM/ML-DSA KeyAlgorithm. So we
// NEVER mark a key PQC just because the endpoint negotiates PQ-TLS — posture is
// derived solely from the key's own KeyAlgorithm.
type PaymentCryptographyScanner struct{}

// paymentCryptographyAPI is the minimal slice of the paymentcryptography client
// this scanner uses. ListKeys is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping keys in dense
// accounts. GetKey is fanned out per key for KeyOrigin + CreateTimestamp.
// Defining it as an interface keeps the pagination + error propagation +
// classification logic unit-testable with a fake (the concrete
// *paymentcryptography.Client satisfies it).
type paymentCryptographyAPI interface {
	ListKeys(ctx context.Context, in *paymentcryptography.ListKeysInput, optFns ...func(*paymentcryptography.Options)) (*paymentcryptography.ListKeysOutput, error)
	GetKey(ctx context.Context, in *paymentcryptography.GetKeyInput, optFns ...func(*paymentcryptography.Options)) (*paymentcryptography.GetKeyOutput, error)
}

// Name returns the canonical scanner identifier.
func (PaymentCryptographyScanner) Name() string { return "paymentcryptography" }

// Category returns the primary category for this scanner.
func (PaymentCryptographyScanner) Category() models.Category { return models.CategoryKeyManagement }

// payAlgoPosture maps a Payment Cryptography KeyAlgorithm to a CryptoPosture
// (mirrors kmsSpecPosture). It classifies the KEY's own algorithm — endpoint
// PQ-TLS is never considered here.
//
//   - AES_*               -> PostureSymmetricOnly  (AES is quantum-resistant-grade symmetric)
//   - TDES_*              -> PostureSymmetricOnly  (3DES is SYMMETRIC, so it is Grover-
//     class, NOT Shor-class — it is NOT a post-quantum migration target and must not
//     be counted as quantum-vulnerable in the PQC KPI. It IS a weak/legacy classical
//     cipher (64-bit block, ~112-bit strength, NIST-sunset), surfaced via the
//     separate "weakCipher" annotation + remediation note in Scan — classical hygiene,
//     not a quantum risk. Labeling it NonPQCClassical (defined as RSA/ECDHE asymmetric)
//     was a FALSE-ALARM that polluted the PQC denominator.)
//   - HMAC_*              -> PostureSymmetricOnly  (keyed-hash MAC, symmetric, quantum-resistant-grade)
//   - RSA_* / ECC_*       -> PostureNonPQCClassical (asymmetric, quantum-vulnerable)
//   - unknown / future    -> PostureUnknown         (never guess a safe posture)
func payAlgoPosture(keyAlgo pctypes.KeyAlgorithm) models.CryptoPosture {
	a := strings.ToUpper(strings.ReplaceAll(string(keyAlgo), "-", "_"))
	switch {
	case strings.HasPrefix(a, "AES_"):
		return models.PostureSymmetricOnly
	case strings.HasPrefix(a, "HMAC"):
		return models.PostureSymmetricOnly
	case strings.HasPrefix(a, "TDES_"):
		// 3DES is symmetric -> Grover-class, not a quantum (Shor) migration target.
		// Symmetric-only keeps it out of the PQC-vulnerable denominator; the
		// weakCipher annotation (set in Scan) carries the legacy-cipher concern.
		return models.PostureSymmetricOnly
	case strings.HasPrefix(a, "RSA_"), strings.HasPrefix(a, "ECC_"):
		return models.PostureNonPQCClassical
	}
	// Unknown / future KeyAlgorithm: classify Unknown, NOT symmetric-only.
	// Defaulting an unrecognized algorithm to a safe posture would FALSE-SAFE a new
	// asymmetric/quantum-vulnerable algorithm as quantum-resistant.
	return models.PostureUnknown
}

// payAlgorithmName maps a Payment Cryptography KeyAlgorithm to a friendly display
// label for the Algorithm row (mirrors kmsAlgorithmName) so the UI never shows a
// bare enum code. TDES is rendered as 3DES with the variant in parentheses to make
// the weak-legacy status legible.
func payAlgorithmName(keyAlgo pctypes.KeyAlgorithm) string {
	switch keyAlgo {
	case pctypes.KeyAlgorithmTdes2key:
		return "3DES (TDES 2-key)"
	case pctypes.KeyAlgorithmTdes3key:
		return "3DES (TDES 3-key)"
	case pctypes.KeyAlgorithmAes128:
		return "AES-128"
	case pctypes.KeyAlgorithmAes192:
		return "AES-192"
	case pctypes.KeyAlgorithmAes256:
		return "AES-256"
	case pctypes.KeyAlgorithmHmacSha224:
		return "HMAC-SHA-224"
	case pctypes.KeyAlgorithmHmacSha256:
		return "HMAC-SHA-256"
	case pctypes.KeyAlgorithmHmacSha384:
		return "HMAC-SHA-384"
	case pctypes.KeyAlgorithmHmacSha512:
		return "HMAC-SHA-512"
	case pctypes.KeyAlgorithmRsa2048:
		return "RSA-2048"
	case pctypes.KeyAlgorithmRsa3072:
		return "RSA-3072"
	case pctypes.KeyAlgorithmRsa4096:
		return "RSA-4096"
	case pctypes.KeyAlgorithmEccNistP256:
		return "ECC NIST P-256"
	case pctypes.KeyAlgorithmEccNistP384:
		return "ECC NIST P-384"
	case pctypes.KeyAlgorithmEccNistP521:
		return "ECC NIST P-521"
	case "":
		return ""
	default:
		// Unknown / future algorithm: echo the raw enum (already an identifier)
		// rather than fabricate a friendly name.
		return string(keyAlgo)
	}
}

// payKeySize returns the key size in bits for a KeyAlgorithm. For TDES we report
// the NOMINAL key length (2KEY=128, 3KEY=192) as keyed material, not the lower
// effective security; the weak-cipher signal is carried by the posture/notes.
func payKeySize(keyAlgo pctypes.KeyAlgorithm) int {
	switch keyAlgo {
	case pctypes.KeyAlgorithmTdes2key:
		return 128 // two 56-bit DES keys, stored as 128 bits with parity
	case pctypes.KeyAlgorithmTdes3key:
		return 192 // three 56-bit DES keys, stored as 192 bits with parity
	case pctypes.KeyAlgorithmAes128:
		return 128
	case pctypes.KeyAlgorithmAes192:
		return 192
	case pctypes.KeyAlgorithmAes256, pctypes.KeyAlgorithmHmacSha256:
		return 256
	case pctypes.KeyAlgorithmHmacSha224:
		return 224
	case pctypes.KeyAlgorithmHmacSha384:
		return 384
	case pctypes.KeyAlgorithmHmacSha512, pctypes.KeyAlgorithmEccNistP521:
		// HMAC-SHA-512 -> 512; ECC P-521 -> 521 (handled below to differ from 512).
		if keyAlgo == pctypes.KeyAlgorithmEccNistP521 {
			return 521
		}
		return 512
	case pctypes.KeyAlgorithmRsa2048:
		return 2048
	case pctypes.KeyAlgorithmRsa3072:
		return 3072
	case pctypes.KeyAlgorithmRsa4096:
		return 4096
	case pctypes.KeyAlgorithmEccNistP256:
		return 256
	case pctypes.KeyAlgorithmEccNistP384:
		return 384
	}
	return 0
}

// payMaterialType maps a KeyClass to a CycloneDX related-crypto material type.
// SYMMETRIC_KEY -> secret-key; ASYMMETRIC_KEY_PAIR/PRIVATE_KEY -> private-key;
// PUBLIC_KEY -> public-key.
func payMaterialType(keyClass pctypes.KeyClass) string {
	switch keyClass {
	case pctypes.KeyClassSymmetricKey:
		return "secret-key"
	case pctypes.KeyClassPublicKey:
		return "public-key"
	case pctypes.KeyClassAsymmetricKeyPair, pctypes.KeyClassPrivateKey:
		return "private-key"
	}
	return "secret-key"
}

// payCryptoState maps a Payment Cryptography KeyState to a CycloneDX CryptoState.
// CREATE_COMPLETE + Enabled is Active; DELETE_PENDING/COMPLETE are Destroyed; an
// in-progress create is Pre-activation -> Suspended (not yet usable).
func payCryptoState(state pctypes.KeyState, enabled bool) models.CryptoState {
	switch state {
	case pctypes.KeyStateCreateComplete:
		if enabled {
			return models.StateActive
		}
		return models.StateSuspended
	case pctypes.KeyStateCreateInProgress:
		return models.StateSuspended
	case pctypes.KeyStateDeletePending, pctypes.KeyStateDeleteComplete:
		return models.StateDestroyed
	}
	return models.StateUnknown
}

// isServiceUnavailableInRegion reports whether err indicates Payment Cryptography
// is not usable in this (account, region): an endpoint that does not resolve (the
// service is regional, not in every region) or AccessDenied (no opt-in / no
// permission to the regional service). These are "service not in use here"
// signals, not scan failures, so the caller skips gracefully (zero assets, nil
// error) — mirroring the timestream not-subscribed / qldb retired-endpoint skips.
// Genuine throttling/validation errors do NOT match and still surface.
func isServiceUnavailableInRegion(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException", "UnrecognizedClientException":
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "could not resolve endpoint") ||
		strings.Contains(msg, "AccessDeniedException") ||
		strings.Contains(msg, "not a valid Region")
}

// Scan lists all AWS Payment Cryptography keys and emits one asset per key with
// algorithm/class/usage/origin metadata. Pagination via NextToken; per-key GetKey
// fan-out (MapConcurrent) enriches each summary with KeyOrigin + CreateTimestamp.
// Capped at services.MaxAssetsPerScanner; graceful skip if the service is not
// available in the region.
func (s PaymentCryptographyScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := paymentcryptography.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListKeys, fans GetKey out per key,
// and classifies each into a CryptoAsset. A ListKeys error that signals the
// service is simply not available in this region is a graceful skip (zero assets,
// nil error); any other ListKeys error is propagated so a denied/throttled scan
// is VISIBLY incomplete rather than a clean-looking empty success. A per-key
// GetKey failure drops only the enrichment, never the asset.
func (s PaymentCryptographyScanner) scan(ctx context.Context, client paymentCryptographyAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListKeys(ctx, &paymentcryptography.ListKeysInput{NextToken: nextToken})
		if err != nil {
			// Payment Cryptography is a REGIONAL, opt-in service not present in
			// every region. Treat endpoint/AccessDenied "not available here"
			// signals as a graceful skip (no assets, no error) so they do not flag
			// the whole (account,region) shard as errored. Genuine errors surface.
			if isServiceUnavailableInRegion(err) {
				fmt.Fprintf(os.Stderr, "paymentcryptography: not available in %s, skipping: %v\n", region, err)
				return []models.CryptoAsset{}, nil
			}
			return nil, fmt.Errorf("paymentcryptography ListKeys: %w", err)
		}

		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out so we never launch more than the cap's worth of
		// GetKey goroutines.
		keys := out.Keys
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(keys) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			keys = keys[:remaining]
		}

		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, keys,
			func(ctx context.Context, k pctypes.KeySummary) (models.CryptoAsset, bool) {
				if k.KeyArn == nil {
					return models.CryptoAsset{}, false
				}
				id := *k.KeyArn

				// KeyAttributes are returned INLINE by ListKeys — algorithm/class/
				// usage are already in hand for classification.
				var keyAlgo pctypes.KeyAlgorithm
				var keyClass pctypes.KeyClass
				var keyUsage pctypes.KeyUsage
				if k.KeyAttributes != nil {
					keyAlgo = k.KeyAttributes.KeyAlgorithm
					keyClass = k.KeyAttributes.KeyClass
					keyUsage = k.KeyAttributes.KeyUsage
				}
				enabled := k.Enabled != nil && *k.Enabled
				exportable := k.Exportable != nil && *k.Exportable

				// GetKey adds KeyOrigin + CreateTimestamp (NOT in the summary).
				// ReadOnlyAccess grants payment-cryptography:GetKey; a per-key
				// failure drops only the enrichment, never the asset.
				var origin pctypes.KeyOrigin
				var created, deletePending = (*time.Time)(nil), (*time.Time)(nil)
				gout, gerr := client.GetKey(ctx, &paymentcryptography.GetKeyInput{KeyIdentifier: k.KeyArn})
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "paymentcryptography GetKey %s: %v\n", id, gerr)
				} else if gout.Key != nil {
					origin = gout.Key.KeyOrigin
					created = gout.Key.CreateTimestamp
					deletePending = gout.Key.DeletePendingTimestamp
					// Prefer the authoritative GetKey attributes if present.
					if gout.Key.KeyAttributes != nil {
						keyAlgo = gout.Key.KeyAttributes.KeyAlgorithm
						keyClass = gout.Key.KeyAttributes.KeyClass
						keyUsage = gout.Key.KeyAttributes.KeyUsage
					}
					enabled = gout.Key.Enabled != nil && *gout.Key.Enabled
					exportable = gout.Key.Exportable != nil && *gout.Key.Exportable
				}

				matType := payMaterialType(keyClass)
				state := payCryptoState(k.KeyState, enabled)
				props := services.KeyMaterialProps(matType, state, payKeySize(keyAlgo), string(keyAlgo))
				if rcm := props.RelatedCryptoMaterialProperties; rcm != nil {
					if created != nil {
						rcm.CreationDate = *created
					}
					if deletePending != nil {
						rcm.ExpirationDate = *deletePending
					}
				}

				a := services.NewAsset("paymentcryptography", models.CategoryKeyManagement, accountID, region, id, "AWS::PaymentCryptography::Key", props)
				a.Properties["keyAlgorithm"] = string(keyAlgo)
				if an := payAlgorithmName(keyAlgo); an != "" {
					a.Properties["algorithmName"] = an
				}
				a.Properties["keyState"] = string(k.KeyState)
				a.Properties["keyClass"] = string(keyClass)
				a.Properties["keyUsage"] = string(keyUsage)
				a.Properties["exportable"] = fmt.Sprintf("%t", exportable)
				if origin != "" {
					a.Properties["keyOrigin"] = string(origin)
				}
				if k.KeyCheckValue != nil && *k.KeyCheckValue != "" {
					a.Properties["keyCheckValue"] = *k.KeyCheckValue
				}
				// TDES is symmetric but WEAK/legacy — annotate so a reviewer is not
				// misled by "symmetric" into thinking it is AES-grade.
				if strings.HasPrefix(strings.ToUpper(string(keyAlgo)), "TDES_") {
					a.Properties["weakCipher"] = "3DES (TDES) is a legacy/deprecated symmetric cipher (64-bit block, ~112-bit effective strength); migrate to AES."
				}

				posture := payAlgoPosture(keyAlgo)
				services.PostureProperty(&a, posture)
				// Posture rests on the key's own observed KeyAlgorithm (a live API
				// fact). Unknown/empty algorithm is not a confident classification.
				if posture != models.PostureUnknown && keyAlgo != "" {
					services.StampObserved(&a, "high")
				}
				return a, true
			})
		assets = append(assets, page...)

		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
