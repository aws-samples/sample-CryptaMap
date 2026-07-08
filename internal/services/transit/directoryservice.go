package transit

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	dstypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
	"github.com/aws/smithy-go"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// DirectoryServiceScanner inspects AWS Directory Service directories for LDAPS
// (LDAP-over-TLS) enablement.
//
// LDAPS is OPT-IN and off by default. The API exposes only whether client-side
// LDAPS is enabled (not the cert material). So: LDAPS Enabled -> NonPQCClassical
// (TLS with a classical RSA/ECDSA cert + KEX; encrypted but quantum-vulnerable);
// LDAPS Disabled -> NoEncryption for the LDAP channel (a genuine finding);
// unsupported (e.g. SimpleAD, where the client-LDAPS API does not apply) ->
// Unknown, never a false all-clear.
type DirectoryServiceScanner struct{}

// Name returns the canonical service identifier.
func (DirectoryServiceScanner) Name() string { return "directoryservice" }

// Category returns the primary CryptaMap category.
func (DirectoryServiceScanner) Category() models.Category { return models.CategoryDataInTransit }

// directoryServiceAPI is the minimal slice of the directoryservice client this
// scanner uses. DescribeDirectories is NextToken-paginated, so the scanner must
// loop; a single call returns only the first page, silently dropping directories
// in accounts with many of them. Defining it as an interface keeps the
// pagination + error propagation logic unit-testable with a fake (the concrete
// *directoryservice.Client satisfies it).
type directoryServiceAPI interface {
	DescribeDirectories(ctx context.Context, in *directoryservice.DescribeDirectoriesInput, optFns ...func(*directoryservice.Options)) (*directoryservice.DescribeDirectoriesOutput, error)
	DescribeLDAPSSettings(ctx context.Context, in *directoryservice.DescribeLDAPSSettingsInput, optFns ...func(*directoryservice.Options)) (*directoryservice.DescribeLDAPSSettingsOutput, error)
}

// Scan enumerates directories, then DescribeLDAPSSettings per directory.
func (s DirectoryServiceScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := directoryservice.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeDirectories and, per
// directory, resolves LDAPS posture. A DescribeDirectories error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success. A per-directory DescribeLDAPSSettings failure does NOT drop the
// directory: it stays an Unknown asset with a note (UnsupportedOperationException
// -> NotApplicable), never a false all-clear.
func (s DirectoryServiceScanner) scan(ctx context.Context, client directoryServiceAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		// Pass DirectoryIds nil (omit) to enumerate all directories.
		out, err := client.DescribeDirectories(ctx, &directoryservice.DescribeDirectoriesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("directoryservice DescribeDirectories: %w", err)
		}
		for _, dir := range out.DirectoryDescriptions {
			if dir.DirectoryId == nil {
				continue
			}
			id := *dir.DirectoryId

			posture := models.PostureUnknown
			ldapsStatus := "Unknown"
			observed := false
			props := services.TLSProtocolPropsDoc("", "directory-ldaps", "low",
				"https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_ldap.html")

			lout, lerr := client.DescribeLDAPSSettings(ctx, &directoryservice.DescribeLDAPSSettingsInput{
				DirectoryId: dir.DirectoryId, Type: dstypes.LDAPSTypeClient,
			})
			if lerr != nil {
				// UnsupportedOperationException (e.g. SimpleAD) -> LDAPS not applicable,
				// keep Unknown (not Disabled, not safe).
				var apiErr smithy.APIError
				if errors.As(lerr, &apiErr) && apiErr.ErrorCode() == "UnsupportedOperationException" {
					ldapsStatus = "NotApplicable"
				} else {
					fmt.Fprintf(os.Stderr, "directoryservice DescribeLDAPSSettings %s: %v\n", id, lerr)
				}
			} else if len(lout.LDAPSSettingsInfo) > 0 {
				// DescribeLDAPSSettings can return multiple rows (one per region
				// for Multi-Region MicrosoftAD). Classify from the WEAKEST row:
				// any Disabled region means plaintext LDAP is accepted somewhere,
				// so reading only row[0] could report another region's Enabled
				// state as the directory-wide verdict.
				for _, row := range lout.LDAPSSettingsInfo {
					st := row.LDAPSStatus
					switch st {
					case dstypes.LDAPSStatusEnabled:
						// A real per-region LDAPS status read.
						observed = true
						if posture != models.PostureNoEncryption {
							// LDAPS on: classical TLS — encrypted but quantum-vulnerable.
							posture = models.PostureNonPQCClassical
							ldapsStatus = string(st)
							// This verdict is OBSERVED (a live LDAPS status read), so the
							// protocol block must NOT claim source=aws-doc. Replace the
							// doc-fact seed props (initialized for the Unknown/fallback
							// path) with the plain observed block so the block's
							// provenance agrees with the StampObserved stamp below.
							props = services.TLSProtocolProps("", "directory-ldaps")
						}
					case dstypes.LDAPSStatusDisabled:
						// LDAP channel not encrypted in at least one region — the
						// weakest state wins. A real per-region LDAPS status read.
						observed = true
						posture = models.PostureNoEncryption
						props = services.NoEncryption()
						ldapsStatus = string(st)
					default:
						if ldapsStatus == "Unknown" {
							ldapsStatus = string(st)
						}
					}
				}
			}

			a := services.NewAsset("directoryservice", models.CategoryDataInTransit, accountID, region, id, "AWS::DirectoryService::MicrosoftAD", props)
			services.PostureProperty(&a, posture)
			// Enabled/Disabled are real per-region LDAPS status reads (observed);
			// the Unknown/NotApplicable/SimpleAD fallbacks rest only on the LDAPS
			// admin-guide doc. Stamp accordingly so an observed verdict is not
			// laundered as a doc-fact and vice versa.
			if observed {
				services.StampObserved(&a, "high")
			} else {
				services.StampDocFact(&a, "low",
					"https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_enable_ldap.html", "")
			}
			a.Properties["ldapsStatus"] = ldapsStatus
			if dir.Type != "" {
				a.Properties["directoryType"] = string(dir.Type)
			}
			if dir.Name != nil {
				a.Properties["directoryName"] = *dir.Name
			}
			switch posture {
			case models.PostureNoEncryption:
				a.Properties["note"] = "Client-side LDAPS is disabled; LDAP traffic to this directory is not encrypted in transit."
			case models.PostureUnknown:
				a.Properties["note"] = "LDAPS state is not exposed for this directory type (e.g. SimpleAD); transit encryption could not be determined from the API."
			}
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
