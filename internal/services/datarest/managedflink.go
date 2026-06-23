package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2"
	kav2types "github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ManagedFlinkScanner inventories Amazon Managed Service for Apache Flink
// applications (SDK module kinesisanalyticsv2) for their at-rest encryption of
// durable application state (checkpoints/snapshots/savepoints).
//
// Always-on, never an "encryption off" finding: managed Flink ALWAYS encrypts
// durable application state at rest with AES-256 — there is no per-application
// toggle to disable it — so every application is SymmetricOnly, NEVER
// NoEncryption. (Reporting one of these as no-encryption would be a regulator
// honesty violation.) AES-256 is symmetric and quantum-resistant, so this is a
// key-custody question, not a quantum-migration target.
//
// Key tier IS API-readable (verified against the kinesisanalyticsv2 SDK): the
// DescribeApplication ApplicationDetail exposes
// ApplicationConfigurationDescription.ApplicationEncryptionConfigurationDescription
// with a KeyType enum (AWS_OWNED_KEY | CUSTOMER_MANAGED_KEY) and a KeyId. When
// the block is present we record the observed tier; when it is absent (older
// applications / accounts predating the encryption-config surface, or a Studio
// notebook that returns no encryption description) the service still encrypts
// with an AWS-owned key — so we fall back to kmsKeyId="AWS_OWNED_KMS_KEY" and
// StampDocFact the universal always-encrypted guarantee. An AWS-owned default is
// "no customer key custody", not a clean all-clear and not no-encryption.
type ManagedFlinkScanner struct{}

// managedFlinkAPI is the minimal slice of the kinesisanalyticsv2 client this
// scanner uses. ListApplications is NextToken-paginated; defining it as an
// interface keeps the pagination + key-tier classification unit-testable with a
// fake (the concrete *kinesisanalyticsv2.Client satisfies it).
type managedFlinkAPI interface {
	ListApplications(ctx context.Context, in *kinesisanalyticsv2.ListApplicationsInput, optFns ...func(*kinesisanalyticsv2.Options)) (*kinesisanalyticsv2.ListApplicationsOutput, error)
	DescribeApplication(ctx context.Context, in *kinesisanalyticsv2.DescribeApplicationInput, optFns ...func(*kinesisanalyticsv2.Options)) (*kinesisanalyticsv2.DescribeApplicationOutput, error)
}

// Name returns the canonical service identifier.
func (ManagedFlinkScanner) Name() string { return "managed_flink" }

// Category returns the primary CryptaMap category.
func (ManagedFlinkScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists applications (NextToken cursor), then DescribeApplication for each
// to read its at-rest encryption configuration. Every application is emitted as
// SymmetricOnly (always-encrypted AES-256 at rest); the encryption-config
// description distinguishes the key tier — a CUSTOMER_MANAGED_KEY with a KeyId
// vs the AWS-owned default key.
func (s ManagedFlinkScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kinesisanalyticsv2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListApplications and classifies each
// application's at-rest key tier via DescribeApplication. A ListApplications error
// is returned (not swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s ManagedFlinkScanner) scan(ctx context.Context, client managedFlinkAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListApplications(ctx, &kinesisanalyticsv2.ListApplicationsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("kinesisanalyticsv2 ListApplications: %w", err)
		}
		summaries := out.ApplicationSummaries
		// Cap the page to the remaining per-scanner budget BEFORE the concurrent
		// fan-out so a pathological region never launches more than the cap's worth
		// of goroutines.
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(summaries) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			summaries = summaries[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, summaries,
			func(ctx context.Context, sum kav2types.ApplicationSummary) (models.CryptoAsset, bool) {
				if sum.ApplicationName == nil {
					return models.CryptoAsset{}, false
				}
				name := *sum.ApplicationName

				desc, derr := client.DescribeApplication(ctx, &kinesisanalyticsv2.DescribeApplicationInput{ApplicationName: &name})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "managed_flink:%s DescribeApplication: %v\n", name, derr)
					return models.CryptoAsset{}, false
				}

				// Managed Flink always encrypts durable application state at rest with
				// AES-256 (universal AWS-doc guarantee), so posture is unconditionally
				// SymmetricOnly. There is no at-rest DISABLED state to downgrade it.
				a := services.NewAsset("managed_flink", models.CategoryDataAtRest, accountID, region, name, "AWS::KinesisAnalyticsV2::Application", services.AESAtRest())
				services.PostureProperty(&a, models.PostureSymmetricOnly)
				services.StampDocFact(&a, "high",
					"https://docs.aws.amazon.com/managed-flink/latest/java/key-management-flink.html",
					"2026-06-15")

				if d := desc.ApplicationDetail; d != nil {
					a.Properties["applicationStatus"] = string(d.ApplicationStatus)
					if d.ApplicationMode != "" {
						a.Properties["applicationMode"] = string(d.ApplicationMode)
					}
					a.Properties["runtimeEnvironment"] = string(d.RuntimeEnvironment)
				}

				// Key tier from the encryption-config description. classifyFlinkKeyTier
				// is the single source of truth for the at-rest key-custody mapping
				// (observed CMK / AWS-owned vs the absent-block AWS-owned default).
				kt := classifyFlinkKeyTier(encConfigDesc(desc))
				if kt.keyTypeProp != "" {
					a.Properties["keyType"] = kt.keyTypeProp
				}
				if kt.observed {
					services.StampObserved(&a, "high")
				}
				if kt.note != "" {
					a.Properties["note"] = kt.note
				}
				a.Properties["kmsKeyId"] = kt.kmsKeyID
				a.Properties["keyTier"] = kt.keyTier
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

// flinkKeyTier is the pure, AWS-client-free result of classifying a managed
// Flink application's at-rest KEY CUSTODY from its encryption-config description.
// The at-rest POSTURE is NOT part of this tuple: managed Flink is unconditionally
// SymmetricOnly (always-encrypted AES-256 at rest), so the posture is set by Scan
// independently and is never downgraded by key tier. This tuple only resolves the
// key custody — observed customer CMK vs observed AWS-owned vs the absent-block
// AWS-owned default — which is the lever an auditor cares about. None of these
// branches is a clean all-clear: an AWS-owned/managed key means no customer key
// custody, not "encryption verified safe".
type flinkKeyTier struct {
	kmsKeyID    string // resolved key id, or the "AWS_OWNED_KMS_KEY" sentinel
	keyTier     string // "customer-managed" | "aws-owned" | "aws-managed-default"
	keyTypeProp string // observed KeyType enum string, "" when no block was returned
	note        string // honesty note for the absent-block AWS-owned default, else ""
	observed    bool   // true when the tier came from a live API field (StampObserved)
}

// classifyFlinkKeyTier maps a DescribeApplication
// ApplicationEncryptionConfigurationDescription to the at-rest key custody. It is
// pure (no AWS client, no context) so the key-custody mapping is unit-testable.
//
//   - CUSTOMER_MANAGED_KEY -> customer-managed, kmsKeyId = the CMK id, observed.
//   - AWS_OWNED_KEY        -> aws-owned, observed; kmsKeyId = the returned id if any,
//     else the AWS_OWNED_KMS_KEY sentinel.
//   - nil block (older apps / Studio notebooks returning no encryption description)
//     -> the AWS-owned DEFAULT: kmsKeyId = AWS_OWNED_KMS_KEY sentinel, NOT observed,
//     with the honesty note that the service still encrypts (AES-256) but there is
//     no customer key custody. A nil block NEVER degrades to no-encryption and is
//     never reported as a clean all-clear.
func classifyFlinkKeyTier(cd *kav2types.ApplicationEncryptionConfigurationDescription) flinkKeyTier {
	if cd == nil {
		return flinkKeyTier{
			kmsKeyID: "AWS_OWNED_KMS_KEY",
			keyTier:  "aws-managed-default",
			note:     "Managed Service for Apache Flink always encrypts durable application state (checkpoints/snapshots) at rest with AES-256; no per-application encryption-config was returned, so the at-rest key is the AWS-owned default (no customer key custody).",
		}
	}
	kt := flinkKeyTier{
		kmsKeyID:    "AWS_OWNED_KMS_KEY",
		keyTier:     "aws-managed-default",
		keyTypeProp: string(cd.KeyType),
	}
	switch cd.KeyType {
	case kav2types.KeyTypeCustomerManagedKey:
		kt.keyTier = "customer-managed"
		if cd.KeyId != nil && *cd.KeyId != "" {
			kt.kmsKeyID = *cd.KeyId
		}
		kt.observed = true
	case kav2types.KeyTypeAwsOwnedKey:
		kt.keyTier = "aws-owned"
		if cd.KeyId != nil && *cd.KeyId != "" {
			kt.kmsKeyID = *cd.KeyId
		}
		kt.observed = true
	}
	return kt
}

// encConfigDesc returns the application's at-rest encryption-config description
// from a DescribeApplication output, or nil when the application, its
// configuration description, or the encryption block is absent.
func encConfigDesc(desc *kinesisanalyticsv2.DescribeApplicationOutput) *kav2types.ApplicationEncryptionConfigurationDescription {
	if desc == nil || desc.ApplicationDetail == nil || desc.ApplicationDetail.ApplicationConfigurationDescription == nil {
		return nil
	}
	return desc.ApplicationDetail.ApplicationConfigurationDescription.ApplicationEncryptionConfigurationDescription
}
