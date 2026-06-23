package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kendra"
	kentypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// KendraScanner inventories Amazon Kendra indexes for at-rest encryption. Kendra
// indexes hold the searchable corpus behind RAG / KYC / enterprise-search
// workloads, so the index store is a sensitive data-at-rest surface.
//
// ALWAYS-ENCRYPTED (Type-C, no per-resource toggle): Amazon Kendra encrypts every
// index at rest with AES-256 (symmetric) and encryption CANNOT be disabled — it
// uses an AWS-owned, AWS-managed, or customer-managed KMS key
// (https://docs.aws.amazon.com/kendra/latest/dg/encryption-at-rest.html). The only
// per-resource choice is WHICH key: DescribeIndex's
// ServerSideEncryptionConfiguration.KmsKeyId is populated for a customer/managed
// CMK and ABSENT when the AWS-owned default key is used. So posture is
// unconditionally SymmetricOnly; an absent KmsKeyId is the AWS-owned default
// (no customer key custody), NEVER a no-encryption finding — labelling an
// always-encrypted RAG/KYC corpus as "encryption off" would be a false alarm, and
// labelling the AWS-owned-key case as a clean all-clear would hide the lack of
// customer key custody. Kendra rejects asymmetric keys, so the at-rest envelope is
// symmetric AES-256 (quantum-resistant), a SymmetricOnly inventory item rather than
// a quantum-migration target. (Kendra is GA in ap-south-1/Mumbai.)
type KendraScanner struct{}

// kendraOwnedKeySentinel is the kmsKeyId value recorded when an index uses the
// AWS-owned default key (DescribeIndex returns no ServerSideEncryptionConfiguration
// or an empty KmsKeyId). It is still AES-256 at rest, but there is NO customer key
// custody — so it is neither a no-encryption finding nor a clean all-clear.
const kendraOwnedKeySentinel = "AWS_OWNED_KMS_KEY"

// kendraKeyTier inspects a Kendra index's ServerSideEncryptionConfiguration and
// returns the kmsKeyId to record. It is a pure, SDK-types-only, client-free helper
// so the key-tier classification can be unit-tested without a Kendra client.
//
// Kendra ALWAYS encrypts at rest with AES-256 (symmetric, no disable toggle), so
// this helper only selects the key TIER, never the posture (posture is
// unconditionally SymmetricOnly in Scan). A populated KmsKeyId is a
// customer/AWS-managed CMK; a nil config or empty KmsKeyId is the AWS-owned default
// key (kendraOwnedKeySentinel) — NOT no-encryption and NOT a clean all-clear.
func kendraKeyTier(sse *kentypes.ServerSideEncryptionConfiguration) string {
	if sse != nil && sse.KmsKeyId != nil && *sse.KmsKeyId != "" {
		return *sse.KmsKeyId
	}
	return kendraOwnedKeySentinel
}

// kendraAPI is the minimal slice of the kendra client this scanner uses.
// ListIndices is NextToken-paginated; defining it as an interface keeps the
// pagination + per-index key-tier classification unit-testable with a fake (the
// concrete *kendra.Client satisfies it).
type kendraAPI interface {
	ListIndices(ctx context.Context, in *kendra.ListIndicesInput, optFns ...func(*kendra.Options)) (*kendra.ListIndicesOutput, error)
	DescribeIndex(ctx context.Context, in *kendra.DescribeIndexInput, optFns ...func(*kendra.Options)) (*kendra.DescribeIndexOutput, error)
}

// Name returns the canonical service identifier.
func (KendraScanner) Name() string { return "kendra" }

// Category returns the primary CryptaMap category.
func (KendraScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists indexes (NextToken cursor), then DescribeIndex(Id) for each to read
// ServerSideEncryptionConfiguration.KmsKeyId. Every index is SymmetricOnly per the
// universal AWS-doc at-rest guarantee; the KMS key id only records the key tier.
func (s KendraScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kendra.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListIndices and classifies each
// index's at-rest key tier via DescribeIndex. A ListIndices error is returned
// (not swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s KendraScanner) scan(ctx context.Context, client kendraAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListIndices(ctx, &kendra.ListIndicesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("kendra ListIndices: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out, so a pathological region never launches more than the
		// cap's worth of goroutines.
		summaries := out.IndexConfigurationSummaryItems
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(summaries) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			summaries = summaries[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, summaries,
			func(ctx context.Context, sum kentypes.IndexConfigurationSummary) (models.CryptoAsset, bool) {
				if sum.Id == nil || *sum.Id == "" {
					return models.CryptoAsset{}, false
				}
				id := *sum.Id

				desc, derr := client.DescribeIndex(ctx, &kendra.DescribeIndexInput{Id: &id})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "kendra:%s DescribeIndex: %v\n", id, derr)
					return models.CryptoAsset{}, false
				}

				// Kendra always encrypts at rest with AES-256 (universal AWS-doc
				// guarantee, no disable toggle), so posture is unconditionally
				// SymmetricOnly.
				a := services.NewAsset("kendra", models.CategoryDataAtRest, accountID, region, id, "AWS::Kendra::Index", services.AESAtRest())
				services.PostureProperty(&a, models.PostureSymmetricOnly)
				services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/kendra/latest/dg/encryption-at-rest.html", "2026-06-15")

				// Key tier: a populated KmsKeyId is a customer/AWS-managed CMK; its
				// absence is the AWS-owned default key (still AES-256, but no customer
				// key custody — not a clean all-clear and not no-encryption).
				a.Properties["kmsKeyId"] = kendraKeyTier(desc.ServerSideEncryptionConfiguration)

				// Evidence only — never used to downgrade posture (there is no at-rest
				// disabled state; CREATING/UPDATING/FAILED are lifecycle states, not a
				// no-encryption signal).
				if sum.Status != "" {
					a.Properties["status"] = string(sum.Status)
				}
				if sum.Edition != "" {
					a.Properties["edition"] = string(sum.Edition)
				}
				if sum.Name != nil && *sum.Name != "" {
					a.Properties["indexName"] = *sum.Name
				}
				a.Properties["note"] = "Amazon Kendra always encrypts index data at rest with AES-256 (symmetric, cannot be disabled); an absent KmsKeyId means the AWS-owned default key (no customer key custody), not no-encryption."
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
