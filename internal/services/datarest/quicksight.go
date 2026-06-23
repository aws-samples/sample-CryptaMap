package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	qstypes "github.com/aws/aws-sdk-go-v2/service/quicksight/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// quickSightDocURL / quickSightAsOf back the universal AWS-doc guarantee that
// QuickSight always encrypts stored data at rest with AES-256.
const (
	quickSightResourceType = "AWS::QuickSight::KeyRegistration"
	quickSightDocURL       = "https://docs.aws.amazon.com/quicksight/latest/user/data-encryption-at-rest.html"
	quickSightAsOf         = "2026-06-15"
)

// classifyQuickSightKeyRegistration is the PURE classification core of the
// QuickSight scanner: given the account's key registration (the slice returned
// by DescribeKeyRegistration) plus the account/region used to build ARNs, it
// returns the fully-classified at-rest assets. It takes only the SDK types
// slice (no client, no context) so the table test can drive every branch.
//
// HONESTY CONTRACT (always-encrypted, NEVER no-encryption): QuickSight stored
// data is ALWAYS AES-256 at rest with no "disable encryption" surface, so posture
// is unconditionally PostureSymmetricOnly. An empty/nil registration is the
// AWS-managed default key (no customer key custody), NOT a no-encryption finding
// and NOT a clean all-clear.
func classifyQuickSightKeyRegistration(keyRegistration []qstypes.RegisteredCustomerManagedKey, accountID, region string) []models.CryptoAsset {
	assets := []models.CryptoAsset{}

	// No customer-managed key registered -> AWS-managed default key. Still AES-256
	// at rest, just no customer key custody. One account-level asset.
	if len(keyRegistration) == 0 {
		resourceID := fmt.Sprintf("%s/%s", accountID, region)
		a := services.NewAsset("quicksight", models.CategoryDataAtRest, accountID, region, resourceID, quickSightResourceType, services.AESAtRest())
		services.PostureProperty(&a, models.PostureSymmetricOnly)
		services.StampDocFact(&a, "high", quickSightDocURL, quickSightAsOf)
		a.Properties["kmsKeyId"] = "AWS_MANAGED_DEFAULT"
		a.Properties["keyTier"] = "aws-managed-default"
		a.Properties["note"] = "No customer managed key registered for QuickSight; data at rest is encrypted with an AWS-managed default KMS key (AES-256). Always-encrypted — no customer key custody, but not a no-encryption finding."
		assets = append(assets, a)
		return assets
	}

	// One or more registered customer-managed keys. Emit one asset per key so the
	// CBOM records each CMK's ARN and which one is the account default.
	for i, k := range keyRegistration {
		keyArn := ""
		if k.KeyArn != nil {
			keyArn = *k.KeyArn
		}
		// resourceID is the CMK ARN when present, else a stable per-index fallback
		// so distinct registrations do not collide on the same bom-ref.
		resourceID := keyArn
		if resourceID == "" {
			resourceID = fmt.Sprintf("%s/%s/cmk-%d", accountID, region, i)
		}
		a := services.NewAsset("quicksight", models.CategoryDataAtRest, accountID, region, resourceID, quickSightResourceType, services.AESAtRest())
		services.PostureProperty(&a, models.PostureSymmetricOnly)
		services.StampDocFact(&a, "high", quickSightDocURL, quickSightAsOf)
		if keyArn != "" {
			a.Properties["kmsKeyId"] = keyArn
		}
		a.Properties["keyTier"] = "customer-managed"
		if k.DefaultKey {
			a.Properties["defaultKey"] = "true"
		}
		a.Properties["note"] = "QuickSight data at rest is encrypted with a customer managed KMS key (AES-256). Customer holds key custody."
		assets = append(assets, a)
	}
	return assets
}

// QuickSightScanner inspects an Amazon QuickSight account's at-rest key
// registration (SPICE datasets and other stored QuickSight data are always
// encrypted at rest with AES-256).
//
// HONESTY CONTRACT (always-encrypted, NEVER no-encryption): QuickSight has no
// "disable encryption" surface — stored data is ALWAYS AES-256 at rest. The only
// customer-visible lever is WHICH symmetric key wraps it. So posture is
// unconditionally SymmetricOnly here; the key tier is the distinguishing
// evidence, and an empty/absent registration is the AWS-managed default key, NOT
// a no-encryption finding (that would be a false alarm against an always-encrypted
// service).
//
// Two tiers:
//   - One or more RegisteredCustomerManagedKey entries -> the account encrypts
//     QuickSight data with customer-managed CMK(s). We emit one asset per
//     registered key, recording its ARN + whether it is the default key.
//   - No registered keys -> QuickSight uses an AWS-managed default key (still
//     AES-256 at rest). We emit a single account-level asset with
//     kmsKeyId=AWS_MANAGED_DEFAULT — "no customer key custody", which is NOT a
//     clean all-clear, but is also NOT no-encryption.
//
// This is account+region scoped (one DescribeKeyRegistration call), not a long
// resource list, so no pagination / inner fan-out is needed.
type QuickSightScanner struct{}

// quickSightAPI is the minimal slice of the quicksight client this scanner uses.
// Defining it as an interface keeps the single-call read + key-registration
// classification unit-testable with a fake (the concrete *quicksight.Client
// satisfies it).
type quickSightAPI interface {
	DescribeKeyRegistration(ctx context.Context, in *quicksight.DescribeKeyRegistrationInput, optFns ...func(*quicksight.Options)) (*quicksight.DescribeKeyRegistrationOutput, error)
}

// Name returns the canonical service identifier.
func (QuickSightScanner) Name() string { return "quicksight" }

// Category returns the primary CryptaMap category.
func (QuickSightScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan reads the account's QuickSight key registration. The "always encrypts at
// rest with AES-256" guarantee is a UNIVERSAL AWS-doc fact (no per-resource
// toggle exposes it), so it is stamped via services.StampDocFact rather than a
// live observation.
func (s QuickSightScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := quicksight.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it reads the account's QuickSight key
// registration and classifies the at-rest key tier.
func (s QuickSightScanner) scan(ctx context.Context, client quickSightAPI, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.DescribeKeyRegistration(ctx, &quicksight.DescribeKeyRegistrationInput{
		AwsAccountId: &accountID,
	})
	if err != nil {
		return nil, fmt.Errorf("quicksight DescribeKeyRegistration: %w", err)
	}

	return classifyQuickSightKeyRegistration(out.KeyRegistration, accountID, region), nil
}
