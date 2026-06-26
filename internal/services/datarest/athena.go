package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// AthenaScanner inspects Athena workgroups for query-result encryption.
//
// IMPORTANT (opt-in, Type-B): Athena query-result encryption is NOT on by
// default. A workgroup with no ResultConfiguration.EncryptionConfiguration writes
// UNENCRYPTED query results to S3 — so an absent config is a GENUINE no-encryption
// finding, never a false all-clear. The built-in "primary" workgroup (where most
// ad-hoc queries run) is the most common offender. When encryption IS configured
// it is S3-backed symmetric AES-256 (SSE_S3 / SSE_KMS / CSE_KMS) — all
// SymmetricOnly; there is no asymmetric/PQC surface here.
type AthenaScanner struct{}

// Name returns the canonical service identifier.
func (AthenaScanner) Name() string { return "athena" }

// Category returns the primary CryptaMap category.
func (AthenaScanner) Category() models.Category { return models.CategoryDataAtRest }

// athenaAPI is the minimal slice of the athena client this scanner uses.
// ListWorkGroups is NextToken-paginated (a single call returns only the first
// page, silently dropping workgroups in dense accounts) and GetWorkGroup is
// called per-workgroup. Defining it as an interface keeps the pagination +
// per-resource error handling unit-testable with a fake (the concrete
// *athena.Client satisfies it).
type athenaAPI interface {
	ListWorkGroups(ctx context.Context, in *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error)
	GetWorkGroup(ctx context.Context, in *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error)
}

// Scan lists workgroups, then GetWorkGroup for each to read its result-encryption
// configuration (ListWorkGroups returns only summaries).
func (s AthenaScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := athena.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListWorkGroups and GetWorkGroup-s
// each summary to classify result-encryption posture. A top-level ListWorkGroups
// error is propagated (the scan is visibly incomplete, not a clean empty
// success); a per-workgroup GetWorkGroup error does NOT drop the workgroup but
// records it as PostureUnknown with a note (so a read failure is neither a false
// all-clear by omission nor a fabricated NoEncryption false alarm).
func (s AthenaScanner) scan(ctx context.Context, client athenaAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("athena ListWorkGroups: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget before the
		// concurrent GetWorkGroup fan-out.
		wgs := out.WorkGroups
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(wgs) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			wgs = wgs[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, wgs,
			func(ctx context.Context, wg athenatypes.WorkGroupSummary) (models.CryptoAsset, bool) {
				if wg.Name == nil {
					return models.CryptoAsset{}, false
				}
				name := *wg.Name
				desc, derr := client.GetWorkGroup(ctx, &athena.GetWorkGroupInput{WorkGroup: &name})
				if derr != nil {
					// Do NOT drop the workgroup: emit a PostureUnknown asset with a
					// note so a read failure never reads as a clean all-clear by
					// omission (and never as a fabricated NoEncryption false alarm).
					fmt.Fprintf(os.Stderr, "athena:%s GetWorkGroup: %v\n", name, derr)
					a := services.NewAsset("athena", models.CategoryDataAtRest, accountID, region, name, "AWS::Athena::WorkGroup", services.UnknownAtRest())
					services.PostureProperty(&a, models.PostureUnknown)
					a.Properties["note"] = "Could not read workgroup configuration; result-encryption state undetermined."
					return a, true
				}

				// Walk the nil-able config chain to the result-encryption block.
				var enc *athenatypes.EncryptionConfiguration
				enforce := ""
				if desc.WorkGroup != nil && desc.WorkGroup.Configuration != nil {
					c := desc.WorkGroup.Configuration
					if c.EnforceWorkGroupConfiguration != nil {
						enforce = fmt.Sprintf("%t", *c.EnforceWorkGroupConfiguration)
					}
					if c.ResultConfiguration != nil {
						enc = c.ResultConfiguration.EncryptionConfiguration
					}
				}

				posture := models.PostureNoEncryption
				props := services.NoEncryption()
				sseOption := ""
				kmsKey := ""
				if enc != nil {
					sseOption = string(enc.EncryptionOption)
					if enc.KmsKey != nil {
						kmsKey = *enc.KmsKey
					}
					switch enc.EncryptionOption {
					case athenatypes.EncryptionOptionSseS3,
						athenatypes.EncryptionOptionSseKms,
						athenatypes.EncryptionOptionCseKms:
						// All three are AES-256 symmetric (S3-managed, KMS envelope, or
						// client-side KMS) — quantum-resistant at rest.
						posture = models.PostureSymmetricOnly
						props = services.AESAtRest()
					}
				}

				a := services.NewAsset("athena", models.CategoryDataAtRest, accountID, region, name, "AWS::Athena::WorkGroup", props)
				services.PostureProperty(&a, posture)
				if sseOption != "" {
					a.Properties["sseAlgorithm"] = sseOption
				}
				if kmsKey != "" {
					a.Properties["kmsKeyId"] = kmsKey
				}
				if enforce != "" {
					a.Properties["enforceWorkGroupConfiguration"] = enforce
				}
				if posture == models.PostureNoEncryption {
					a.Properties["note"] = "Athena result encryption is opt-in and not configured on this workgroup; query results are written unencrypted to S3."
				} else if enforce == "false" {
					// Per-query client settings can override; workgroup-level posture
					// is reported but confidence is weaker.
					a.Properties["note"] = "Workgroup does not enforce its configuration; individual queries may override the result-encryption setting."
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
