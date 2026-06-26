package keymgmt

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// The UNIVERSAL guarantee that every AWS-managed KMS key (alias prefix
// "alias/aws/", reserved per the KMS concepts doc) is a symmetric encryption key
// — AWS KMS auto-rotates AWS-managed keys yearly and rotation is supported ONLY
// on symmetric encryption keys, so an AWS-managed key can never be asymmetric —
// is the doc-fact "keymgmt/kms_usage/aws-managed-symmetric-only" (internal/pqc
// knowledge). It lets us classify an alias/aws/* whose target key is not yet
// lazily provisioned (no TargetKeyId, so DescribeKey can't resolve it) as
// SymmetricOnly instead of a permission-gap-masquerading Unknown.

// isAWSManagedAlias reports whether an alias name is the reserved AWS-managed
// form "alias/aws/<service>". The reserved prefix is the literal lowercase
// "alias/aws/" and KMS alias names are CASE SENSITIVE, so the match must be
// case-sensitive: a case-insensitive check let a legitimate customer alias such
// as "alias/AWS/foo" (whose target key may be asymmetric) be treated as an
// AWS-managed symmetric-only key — a FALSE-SAFE. Only the exact reserved prefix,
// which customers cannot create, qualifies for the symmetric-only guarantee.
func isAWSManagedAlias(aliasName string) bool {
	return strings.HasPrefix(aliasName, "alias/aws/")
}

// KMSUsageScanner enumerates KMS aliases to surface key usage scope.
type KMSUsageScanner struct{}

// Name returns the canonical scanner identifier.
func (KMSUsageScanner) Name() string { return "kms_usage" }

// Category returns the primary category for this scanner.
func (KMSUsageScanner) Category() models.Category { return models.CategoryKeyManagement }

// kmsUsageAPI is the minimal slice of the kms client this scanner uses.
// ListAliases is Marker-paginated and each alias does one DescribeKey to resolve
// the target key's spec; defining it as an interface keeps the pagination +
// target-resolution logic unit-testable with a fake (the concrete *kms.Client
// satisfies it).
type kmsUsageAPI interface {
	ListAliases(ctx context.Context, in *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Scan lists all KMS aliases. One asset per alias mapping is emitted; alias->key target is
// recorded as a property. Less granular than kms_spec; useful for usage tracking.
// Pagination via Marker; capped at 1000 items.
func (s KMSUsageScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListAliases, resolves each alias's
// target-key spec via DescribeKey, and classifies posture. A ListAliases error is
// returned (not swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s KMSUsageScanner) scan(ctx context.Context, client kmsUsageAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListAliases(ctx, &kms.ListAliasesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("kms ListAliases: %w", err)
		}
		// Cap the per-page alias batch to the remaining per-scanner budget before
		// the concurrent fan-out (each alias does one DescribeKey).
		aliases := out.Aliases
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(aliases) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			aliases = aliases[:remaining]
		}
		// Resolve each alias's target-key spec concurrently (bounded, order-
		// preserving). A nil AliasName drops the entry; an alias is always emitted
		// otherwise (PostureUnknown when the target can't be described).
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, aliases,
			func(ctx context.Context, al kmstypes.AliasListEntry) (models.CryptoAsset, bool) {
				if al.AliasName == nil {
					return models.CryptoAsset{}, false
				}
				id := *al.AliasName
				target := ""
				if al.TargetKeyId != nil {
					target = *al.TargetKeyId
				}
				// relatedCryptoMaterialProperties.type is an ENUM. A KMS alias is a
				// pointer/mapping to a key, not key material itself → the valid member
				// is "other". The "alias" semantics are carried by cryptamap:materialType
				// + scope=alias-mapping below.
				props := services.KeyMaterialProps("other", models.StateActive, 0, target)
				a := services.NewAsset("kms_usage", models.CategoryKeyManagement, accountID, region, id, "AWS::KMS::Alias", props)
				a.Properties["materialType"] = "alias"
				a.Properties["aliasName"] = id
				if target != "" {
					a.Properties["targetKeyId"] = target
				}
				a.Properties["scope"] = "alias-mapping"

				// An alias is a pointer; its TRUE posture is the TARGET KEY's spec.
				// Hardcoding symmetric-only was a FALSE-SAFE: an alias targeting an
				// RSA/ECC asymmetric key (e.g. a signing/encryption CMK) would be shown
				// quantum-resistant. Resolve the target key's KeySpec via DescribeKey and
				// classify with the same kmsSpecPosture used by kms_spec. On failure,
				// fall back to PostureUnknown (NOT a safe posture) so we never assert a
				// false quantum-resistant state.
				posture := models.PostureUnknown
				resolved := false
				if target != "" {
					if d, derr := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &target}); derr != nil {
						fmt.Fprintf(os.Stderr, "kms_usage DescribeKey %s: %v\n", target, derr)
					} else if d.KeyMetadata != nil {
						keySpec := string(d.KeyMetadata.KeySpec)
						a.Properties["targetKeySpec"] = keySpec
						// Mirror the full target context that kms_spec emits, so the alias
						// asset carries usage/state/origin (e.g. signing vs encryption CMK)
						// from the SAME already-fetched KeyMetadata (no extra API call).
						a.Properties["targetKeyUsage"] = string(d.KeyMetadata.KeyUsage)
						a.Properties["targetKeyState"] = string(d.KeyMetadata.KeyState)
						a.Properties["targetOrigin"] = string(d.KeyMetadata.Origin)
						a.Properties["targetKeyManager"] = string(d.KeyMetadata.KeyManager)
						posture = kmsSpecPosture(keySpec)
						resolved = true
					}
				}
				// Data-completeness: an AWS-managed alias (reserved "alias/aws/" prefix)
				// whose target key DescribeKey could not resolve — almost always because
				// the key is LAZILY provisioned and not created until first use, so the
				// alias carries no TargetKeyId — is NOT genuinely unknown. AWS-managed keys
				// are always auto-rotated yearly, and automatic rotation is supported ONLY
				// on symmetric encryption keys, so an AWS-managed key can never be
				// asymmetric. Apply that universal guarantee instead of leaving a
				// permission/timing gap masquerading as Unknown. Stamped as an AWS-doc
				// fact so its provenance (guarantee, not observation) is auditable.
				if !resolved && isAWSManagedAlias(id) {
					posture = models.PostureSymmetricOnly
					a.Properties["targetKeyManager"] = "AWS"
					a.Properties["awsManagedKeyGuarantee"] = "symmetric-only"
					services.StampDocFactKeyed(&a, "keymgmt/kms_usage/aws-managed-symmetric-only")
				}
				services.PostureProperty(&a, posture)
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
