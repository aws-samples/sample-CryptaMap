package transit

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type TransferFamilyScanner struct{}

func (TransferFamilyScanner) Name() string              { return "transferfamily" }
func (TransferFamilyScanner) Category() models.Category { return models.CategoryDataInTransit }

// transferPolicyYearRe extracts the 4-digit year stamped into a Transfer Family
// security-policy name (e.g. TransferSecurityPolicy-2025-03 -> 2025).
var transferPolicyYearRe = regexp.MustCompile(`20\d{2}`)

// postureFromTransferPolicyName classifies a Transfer Family server from its
// security-policy NAME alone. This is the FALLBACK used only when
// DescribeSecurityPolicy is unavailable (e.g. AccessDenied), so the authoritative
// KEX-based classification cannot run.
//
// Per AWS, every Transfer Family security policy issued from 2025 onward includes
// post-quantum hybrid key exchange — even though "pq" does NOT appear in the name
// (only the deprecated experimental policies spell out "pq"). So:
//   - a name containing "pq" (experimental PQ-SSH) -> PQCHybrid;
//   - any 2025-or-later dated policy -> PQCHybrid;
//   - a recognized older dated policy -> classical;
//   - anything else (including an unread/empty name) -> Unknown.
//
// Unknown — not a default "classical" — is the honest verdict for a name we cannot
// place: defaulting to classical was a FALSE-SAFE that mislabeled a current PQ
// policy whose details we could not read.
func postureFromTransferPolicyName(policy string) (models.CryptoPosture, string) {
	pl := strings.ToLower(policy)
	switch {
	case strings.Contains(pl, "1-0"):
		// Defensive: no current Transfer policy name carries a "1-0" TLS-1.0 token,
		// but if one ever does, treat it as legacy.
		return models.PostureLegacyTLS, "1.0"
	case strings.Contains(pl, "pq"):
		return models.PosturePQCHybrid, "1.2"
	case transferPolicyYear(pl) >= 2025:
		return models.PosturePQCHybrid, "1.2"
	case strings.Contains(pl, "2018-11"), strings.Contains(pl, "2020-06"),
		strings.Contains(pl, "2022-03"), strings.Contains(pl, "2023-05"):
		return models.PostureNonPQCClassical, "1.2"
	default:
		return models.PostureUnknown, "1.2"
	}
}

// transferPolicyYear returns the year stamped in a policy name, or 0 if none.
func transferPolicyYear(pl string) int {
	if m := transferPolicyYearRe.FindString(pl); m != "" {
		y, _ := strconv.Atoi(m)
		return y
	}
	return 0
}

// transferAPI is the minimal slice of the transfer client this scanner uses.
// ListServers is NextToken-paginated, so the scanner must loop; a single call
// returns only the first page, silently dropping servers in dense accounts.
// Defining it as an interface keeps the pagination + error propagation logic
// unit-testable with a fake (the concrete *transfer.Client satisfies it).
type transferAPI interface {
	ListServers(ctx context.Context, in *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error)
	DescribeServer(ctx context.Context, in *transfer.DescribeServerInput, optFns ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error)
	DescribeSecurityPolicy(ctx context.Context, in *transfer.DescribeSecurityPolicyInput, optFns ...func(*transfer.Options)) (*transfer.DescribeSecurityPolicyOutput, error)
}

func (s TransferFamilyScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := transfer.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListServers and, per server,
// classifies the security policy into a CryptoAsset. A ListServers error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success. Per-server DescribeServer / DescribeSecurityPolicy errors are
// non-fatal (logged to stderr) and fall back to the policy-name-only path, so a
// server is never silently dropped.
func (s TransferFamilyScanner) scan(ctx context.Context, client transferAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListServers(ctx, &transfer.ListServersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("transferfamily ListServers: %w", err)
		}
		for _, srv := range out.Servers {
			if srv.ServerId == nil {
				continue
			}
			d, derr := client.DescribeServer(ctx, &transfer.DescribeServerInput{ServerId: srv.ServerId})
			policy := ""
			// Default to Unknown, not classical: a server whose policy we cannot place
			// must not be asserted non-PQ (the current 2025 PQ policies carry no "pq"
			// in the name, so a classical default was a false-safe).
			posture := models.PostureUnknown
			ver := "1.2"
			if derr == nil && d.Server != nil && d.Server.SecurityPolicyName != nil {
				policy = *d.Server.SecurityPolicyName
				posture, ver = postureFromTransferPolicyName(policy)
			} else if derr != nil {
				fmt.Fprintf(os.Stderr, "transferfamily DescribeServer %s: %v\n", *srv.ServerId, derr)
			}

			// Default props from the policy-name-only path (backward compatible).
			props := services.TLSProtocolProps(ver, policy)
			var fipsStr string

			// Deepen: pull the actual SSH/TLS algorithm lists from the security
			// policy so per-algorithm detail and an ML-KEM-based PQC posture are
			// observed rather than guessed from the policy name. On error (e.g.
			// AccessDenied for transfer:DescribeSecurityPolicy) fall back to the
			// policy-name-only behavior above — additive and backward compatible.
			if policy != "" {
				dp, perr := client.DescribeSecurityPolicy(ctx, &transfer.DescribeSecurityPolicyInput{
					SecurityPolicyName: &policy,
				})
				if perr != nil {
					fmt.Fprintf(os.Stderr, "transferfamily DescribeSecurityPolicy %s: %v\n", policy, perr)
				} else if dp.SecurityPolicy != nil {
					sp := dp.SecurityPolicy
					props = classifyTransferPolicy(sp.SshKexs, sp.SshCiphers, sp.SshMacs, sp.TlsCiphers)
					// Prefer observed KEX posture when KEX data is present.
					if p := postureFromTransferKexs(sp.SshKexs); p != models.CryptoPosture("") {
						posture = p
					}
					if sp.Fips != nil {
						if *sp.Fips {
							fipsStr = "true"
						} else {
							fipsStr = "false"
						}
					}
				}
			}

			a := services.NewAsset("transferfamily", models.CategoryDataInTransit, accountID, region, *srv.ServerId, "AWS::Transfer::Server", props)
			services.PostureProperty(&a, posture)
			if policy != "" {
				a.Properties["securityPolicy"] = policy
			}
			if fipsStr != "" {
				a.Properties["fips"] = fipsStr
			}
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
