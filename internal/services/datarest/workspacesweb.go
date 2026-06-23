package datarest

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/workspacesweb"
	wswtypes "github.com/aws/aws-sdk-go-v2/service/workspacesweb/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// WorkSpacesWebScanner inventories Amazon WorkSpaces Web (Amazon WorkSpaces
// Secure Browser) portals for their at-rest encryption posture.
//
// WorkSpaces Secure Browser is a BYOD clean-room browser-access boundary: all
// customer data persisted by the service (browser policy statements, usernames,
// logging, IP addresses, etc.) is encrypted at rest. Per the AWS doc guarantee
// ("Encryption at rest is configured by default and all customer data ... is
// encrypted using AWS KMS"), encryption is ALWAYS on — there is no per-resource
// toggle that turns it off. By default the portal is encrypted with an AWS-owned
// key; a symmetric customer-managed CMK can be supplied at resource creation and,
// once set, can never be removed or changed.
//
// This makes WorkSpaces Web a Type-A always-encrypted at-rest surface: posture is
// unconditionally SymmetricOnly (AES-256 KMS envelope), NEVER NoEncryption. The
// CustomerManagedKey field only distinguishes the KEY TIER:
//   - CustomerManagedKey set  -> customer holds key custody (their CMK)
//   - CustomerManagedKey absent -> AWS-owned default key (no customer key custody)
//
// An absent CMK is recorded as kmsKeyId=AWS_OWNED_KMS_KEY (keyTier=aws-owned-default):
// that is "no customer key custody", NOT a clean all-clear and NOT no-encryption.
// Labeling an always-encrypted service as no-encryption would be a false alarm and
// violate the regulator-tool honesty contract.
type WorkSpacesWebScanner struct{}

// workSpacesWebAPI is the minimal slice of the workspacesweb client this scanner
// uses. ListPortals is NextToken-paginated; defining it as an interface keeps the
// pagination + per-portal key-tier classification unit-testable with a fake (the
// concrete *workspacesweb.Client satisfies it).
type workSpacesWebAPI interface {
	ListPortals(ctx context.Context, in *workspacesweb.ListPortalsInput, optFns ...func(*workspacesweb.Options)) (*workspacesweb.ListPortalsOutput, error)
	GetPortal(ctx context.Context, in *workspacesweb.GetPortalInput, optFns ...func(*workspacesweb.Options)) (*workspacesweb.GetPortalOutput, error)
}

// Name returns the canonical service identifier.
func (WorkSpacesWebScanner) Name() string { return "workspaces_web" }

// Category returns the primary CryptaMap category.
func (WorkSpacesWebScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists portals (NextToken pagination), then GetPortal for each to read its
// CustomerManagedKey. Every portal is emitted SymmetricOnly (always-encrypted),
// with the key tier driven solely by the presence of a customer-managed key.
func (s WorkSpacesWebScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := workspacesweb.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListPortals and classifies each
// portal's at-rest key tier via GetPortal. A ListPortals error is returned (not
// swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s WorkSpacesWebScanner) scan(ctx context.Context, client workSpacesWebAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListPortals(ctx, &workspacesweb.ListPortalsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("workspacesweb ListPortals: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out, so a pathological region never launches more than the
		// cap's worth of goroutines.
		portals := out.Portals
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(portals) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			portals = portals[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, portals,
			func(ctx context.Context, p wswtypes.PortalSummary) (models.CryptoAsset, bool) {
				if p.PortalArn == nil || *p.PortalArn == "" {
					return models.CryptoAsset{}, false
				}
				portalArn := *p.PortalArn

				// GetPortal returns the full portal including CustomerManagedKey and
				// AdditionalEncryptionContext, which the summary does not carry.
				gp, gerr := client.GetPortal(ctx, &workspacesweb.GetPortalInput{PortalArn: &portalArn})
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "workspacesweb:%s GetPortal: %v\n", portalArn, gerr)
					return models.CryptoAsset{}, false
				}

				// WorkSpaces Web always encrypts at rest with an AES-256 KMS envelope
				// (universal AWS-doc guarantee; no per-resource disable), so posture is
				// unconditionally SymmetricOnly.
				a := services.NewAssetWithARN(portalArn, "workspaces_web", models.CategoryDataAtRest, accountID, region, portalArn, "AWS::WorkSpacesWeb::Portal", services.AESAtRest())
				services.PostureProperty(&a, models.PostureSymmetricOnly)
				services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/workspaces-web/latest/adminguide/encryption-rest.html", "2026-06-15")

				// Key tier classification (pure, single source of truth — see
				// classifyWorkSpacesWebKeyTier). A populated CustomerManagedKey means
				// the customer holds key custody; its absence (or a nil portal) is the
				// AWS-owned default key (still AES-256, NEVER no-encryption).
				kmsKey, keyTier, note := classifyWorkSpacesWebKeyTier(gp.Portal)
				if portal := gp.Portal; portal != nil {
					if portal.DisplayName != nil && *portal.DisplayName != "" {
						a.Properties["displayName"] = *portal.DisplayName
					}
					if portal.PortalStatus != "" {
						a.Properties["portalStatus"] = string(portal.PortalStatus)
					}
					if portal.AuthenticationType != "" {
						a.Properties["authenticationType"] = string(portal.AuthenticationType)
					}
					if len(portal.AdditionalEncryptionContext) > 0 {
						a.Properties["additionalEncryptionContext"] = encodeEncryptionContext(portal.AdditionalEncryptionContext)
					}
				}
				a.Properties["kmsKeyId"] = kmsKey
				a.Properties["keyTier"] = keyTier
				a.Properties["note"] = note
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

// classifyWorkSpacesWebKeyTier is the PURE classification core of the scanner: it
// maps a portal's CustomerManagedKey to the (kmsKeyId, keyTier, note) the asset
// records. It takes the concrete SDK *wswtypes.Portal (no client, no context) so
// the table test can drive every branch directly.
//
// WorkSpaces Secure Browser is a Type-A always-encrypted at-rest surface (AES-256
// KMS envelope, no per-resource disable), so the POSTURE is unconditionally
// SymmetricOnly and is NOT decided here — this helper only selects the KEY TIER:
//   - CustomerManagedKey set        -> customer key custody (their CMK)
//   - CustomerManagedKey absent/empty, or portal nil -> AWS-owned default key
//
// A nil portal (e.g. an empty GetPortal response) degrades to the AWS-owned
// default branch, NEVER a crash and NEVER a no-encryption / clean all-clear. The
// AWS-owned-default note explicitly says "no customer key custody" so the default
// is never mistaken for a clean all-clear.
func classifyWorkSpacesWebKeyTier(portal *wswtypes.Portal) (kmsKeyID, keyTier, note string) {
	kmsKeyID = "AWS_OWNED_KMS_KEY"
	keyTier = "aws-owned-default"
	note = "WorkSpaces Secure Browser always encrypts customer data at rest; this portal uses the AWS-owned default KMS key (no customer key custody), not a customer-managed CMK."
	if portal != nil && portal.CustomerManagedKey != nil && *portal.CustomerManagedKey != "" {
		kmsKeyID = *portal.CustomerManagedKey
		keyTier = "customer-managed"
		note = "WorkSpaces Secure Browser always encrypts customer data at rest; this portal uses a customer-managed CMK (symmetric AES-256 KMS envelope)."
	}
	return kmsKeyID, keyTier, note
}

// encodeEncryptionContext renders the portal's additional KMS encryption context
// as a stable, deterministically-ordered k=v list for evidence (map iteration
// order is otherwise nondeterministic, which would churn the CBOM diff).
func encodeEncryptionContext(ctxMap map[string]string) string {
	keys := make([]string, 0, len(ctxMap))
	for k := range ctxMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+ctxMap[k])
	}
	return strings.Join(parts, ",")
}
