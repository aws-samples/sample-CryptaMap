package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	cptypes "github.com/aws/aws-sdk-go-v2/service/customerprofiles/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CustomerProfilesScanner inspects Amazon Connect Customer Profiles domains for
// their at-rest encryption key. A Customer Profiles domain is the consolidated
// container for contact-center customer PII (profiles, objects, identity-resolution
// output), so its at-rest key custody is squarely in regulatory scope.
//
// CMK-vs-AWS-managed CLASSIFIER (not a pass/fail toggle): Customer Profiles ALWAYS
// encrypts data at rest with AES-256 — there is no "off" state — so this is NEVER a
// no-encryption finding and posture is unconditionally SymmetricOnly. What varies is
// KEY CUSTODY, read from GetDomain.DefaultEncryptionKey:
//
//   - DefaultEncryptionKey SET   -> a customer-supplied KMS CMK (customer key custody);
//     kmsKeyId = the key ARN.
//   - DefaultEncryptionKey EMPTY/ABSENT -> AWS-managed default key. CRITICAL: the field
//     is Required:No (min length 0) and the AWS doc states it falls back to "an AWS
//     managed key ... when no specific type of encryption key is specified". An empty
//     value is therefore NOT a clean Type-A all-clear (no customer key custody) and is
//     ALSO NOT no-encryption — it is recorded as kmsKeyId=AWS_MANAGED_DEFAULT with an
//     explicit "no customer key custody" note (HONESTY CONTRACT).
//
// Either way the cipher is symmetric AES-256 (quantum-resistant), so the posture is
// SymmetricOnly; only the key-custody evidence differs.
type CustomerProfilesScanner struct{}

// customerProfilesAPI is the minimal slice of the customerprofiles client this
// scanner uses. ListDomains is NextToken-paginated; defining it as an interface
// keeps the pagination + per-domain key-custody classification unit-testable with
// a fake (the concrete *customerprofiles.Client satisfies it).
type customerProfilesAPI interface {
	ListDomains(ctx context.Context, in *customerprofiles.ListDomainsInput, optFns ...func(*customerprofiles.Options)) (*customerprofiles.ListDomainsOutput, error)
	GetDomain(ctx context.Context, in *customerprofiles.GetDomainInput, optFns ...func(*customerprofiles.Options)) (*customerprofiles.GetDomainOutput, error)
}

// cpKeyCustody is the pure, SDK-free classification of a Customer Profiles
// domain's at-rest KEY CUSTODY from GetDomain.DefaultEncryptionKey. It is the
// SINGLE source of truth driven by both Scan and the unit test.
//
// The cipher is ALWAYS AES-256 (SymmetricOnly) regardless of custody — this
// function never returns no-encryption — so it classifies only the key tier:
//
//   - defaultEncryptionKey SET (non-empty)  -> customer-supplied KMS CMK; the
//     returned kmsKeyId is that ARN, keyTier "customer-cmk", no note.
//   - defaultEncryptionKey nil OR ""        -> AWS-managed default key (the field
//     is Required:No). kmsKeyId "AWS_MANAGED_DEFAULT", keyTier "aws-managed-default",
//     and an explicit "no customer key custody — not a clean all-clear" note.
//
// HONESTY CONTRACT: the empty/nil branch is NEVER a clean Type-A all-clear and is
// NEVER no-encryption; it carries the no-custody note so it cannot be mistaken for
// a customer-controlled key.
func cpKeyCustody(defaultEncryptionKey *string) (kmsKeyID, keyTier, note string) {
	if defaultEncryptionKey != nil && *defaultEncryptionKey != "" {
		// Customer-supplied KMS CMK — customer key custody.
		return *defaultEncryptionKey, "customer-cmk", ""
	}
	// Empty/absent: AWS-managed default key. Encrypted, but NO customer key
	// custody — never report this as a clean all-clear, never as no-encryption.
	return "AWS_MANAGED_DEFAULT", "aws-managed-default",
		"Customer Profiles domain has no customer-supplied encryption key; data at rest is encrypted with an AWS-managed default key (AES-256). No customer key custody — not a clean all-clear."
}

// Name returns the canonical service identifier.
func (CustomerProfilesScanner) Name() string { return "connect_customer_profiles" }

// Category returns the primary CryptaMap category.
func (CustomerProfilesScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists domains (NextToken cursor), then GetDomain for each to read its
// DefaultEncryptionKey and classify key custody. The always-AES-256-at-rest
// guarantee is an AWS-doc universal fact (no per-resource toggle), so it is stamped
// via StampDocFact rather than inferred from any observable disable switch.
func (s CustomerProfilesScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := customerprofiles.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListDomains and classifies each
// domain's at-rest key custody via GetDomain. A ListDomains error is returned
// (not swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s CustomerProfilesScanner) scan(ctx context.Context, client customerProfilesAPI, accountID, region string) ([]models.CryptoAsset, error) {
	const docURL = "https://docs.aws.amazon.com/customerprofiles/latest/APIReference/API_GetDomain.html"

	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListDomains(ctx, &customerprofiles.ListDomainsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("customerprofiles ListDomains: %w", err)
		}
		items := out.Items
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(items) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			items = items[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, items,
			func(ctx context.Context, item cptypes.ListDomainItem) (models.CryptoAsset, bool) {
				if item.DomainName == nil || *item.DomainName == "" {
					return models.CryptoAsset{}, false
				}
				name := *item.DomainName
				desc, derr := client.GetDomain(ctx, &customerprofiles.GetDomainInput{DomainName: &name})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "customerprofiles:%s GetDomain: %v\n", name, derr)
					// The domain is known to exist (it was in ListDomains) but its
					// encryption detail could not be read — keep it as PostureUnknown
					// rather than silently dropping it (HONESTY CONTRACT: never an
					// all-clear by omission, never a no-encryption false alarm).
					a := services.NewAsset("connect_customer_profiles", models.CategoryDataAtRest, accountID, region, name, "AWS::CustomerProfiles::Domain", services.UnknownAtRest())
					services.PostureProperty(&a, models.PostureUnknown)
					a.Properties["note"] = "Could not read domain encryption (detail call failed); at-rest key custody undetermined."
					return a, true
				}

				// Customer Profiles always encrypts at rest with AES-256 (no disable
				// switch), so posture is unconditionally SymmetricOnly; we only
				// classify KEY CUSTODY from DefaultEncryptionKey.
				a := services.NewAsset("connect_customer_profiles", models.CategoryDataAtRest, accountID, region, name, "AWS::CustomerProfiles::Domain", services.AESAtRest())
				services.PostureProperty(&a, models.PostureSymmetricOnly)
				services.StampDocFact(&a, "high", docURL, "2026-06-15")

				kmsKeyID, keyTier, note := cpKeyCustody(desc.DefaultEncryptionKey)
				a.Properties["kmsKeyId"] = kmsKeyID
				a.Properties["keyTier"] = keyTier
				if note != "" {
					a.Properties["note"] = note
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
