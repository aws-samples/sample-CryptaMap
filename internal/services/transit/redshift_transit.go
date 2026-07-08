package transit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type RedshiftTransitScanner struct{}

func (RedshiftTransitScanner) Name() string              { return "redshift_transit" }
func (RedshiftTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// redshiftTransitAPI is the minimal slice of the redshift client this scanner
// uses. Both calls are Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping clusters/parameters in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation + SSL-enforcement logic unit-testable with a fake (the concrete
// *redshift.Client satisfies it). DescribeClusterParameters requires the
// redshift:DescribeClusterParameters IAM read action.
type redshiftTransitAPI interface {
	DescribeClusters(ctx context.Context, in *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error)
	DescribeClusterParameters(ctx context.Context, in *redshift.DescribeClusterParametersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error)
}

func (s RedshiftTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := redshift.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates DescribeClusters via Marker and
// classifies each cluster into a CryptoAsset. A DescribeClusters error is NOT
// swallowed — it is returned so the engine records this scanner as errored
// (which surfaces in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s RedshiftTransitScanner) scan(ctx context.Context, client redshiftTransitAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	// Cache require_ssl enforcement per parameter group so that many clusters
	// sharing a group cost a single DescribeClusterParameters call.
	pgCache := map[string]sslEnforcement{}
	var marker *string
	for {
		out, err := client.DescribeClusters(ctx, &redshift.DescribeClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("redshift_transit DescribeClusters: %w", err)
		}
		for _, c := range out.Clusters {
			if c.ClusterIdentifier == nil {
				continue
			}
			// Redshift exposes NO default per-cluster server-cert identifier and
			// no API returns the negotiated TLS version, so we do not fabricate a
			// "1.2"/"redshift-tls" observation — the version is left unknown. The
			// only server-cert data available is the CUSTOM-domain cert (ARN +
			// expiry), present only when a custom domain is configured; read it
			// when present.
			props := services.TLSProtocolPropsDetailed("", "redshift-tls", "", "", 0, false)
			a := services.NewAsset("redshift_transit", models.CategoryDataInTransit, accountID, region, *c.ClusterIdentifier, "AWS::Redshift::Cluster", props)

			// Redshift clusters ALWAYS offer TLS, but offering it is not the same
			// as enforcing it: unless the cluster parameter group sets
			// require_ssl=true (which DEFAULTS to false), the cluster STILL
			// accepts plaintext connections. Reporting such a cluster as clean
			// classical TLS is a false all-clear, so we resolve the enforcement
			// state from the attached cluster parameter group(s) via
			// DescribeClusterParameters and downgrade the posture when TLS is
			// merely available, not enforced — the same tri-state as rds_transit.
			enf := redshiftSSLEnforcement(ctx, client, c.ClusterParameterGroups, pgCache)
			a.Properties["sslEnforcement"] = string(enf)
			switch enf {
			case sslEnforced:
				// require_ssl=true: plaintext refused; classical TLS enforced.
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				services.StampObserved(&a, "high")
			case sslNotEnforced:
				// TLS offered but plaintext still accepted — a mixed posture, not
				// a clean classical-TLS all-clear. legacy-tls is the closest
				// weakened-transit signal (provably NOT fully-enforced TLS).
				services.PostureProperty(&a, models.PostureLegacyTLS)
				a.Properties["note"] = "Redshift cluster offers TLS but does not enforce it (require_ssl is false in the cluster parameter group — the Redshift default); plaintext connections are still accepted."
				services.StampObserved(&a, "high")
			default:
				// Enforcement could not be read (no parameter group resolvable or
				// a DescribeClusterParameters failure): TLS is available but
				// enforcement is unproven. Report Unknown rather than asserting
				// either a clean all-clear or a false alarm.
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "Redshift cluster offers TLS, but SSL enforcement (require_ssl) could not be read from the cluster parameter group via DescribeClusterParameters."
			}

			if c.CustomDomainName != nil && *c.CustomDomainName != "" {
				a.Properties["customDomainName"] = *c.CustomDomainName
			}
			if c.CustomDomainCertificateArn != nil && *c.CustomDomainCertificateArn != "" {
				a.Properties["customDomainCertificateArn"] = *c.CustomDomainCertificateArn
				services.StampObserved(&a, "high")
				// Resolve the custom-domain ACM cert for signature algorithm + key size.
				resolveACMCert(ctx, certResolver, *c.CustomDomainCertificateArn, &a)
			}
			if c.CustomDomainCertificateExpiryDate != nil {
				a.Properties["customDomainCertificateExpiry"] = c.CustomDomainCertificateExpiryDate.UTC().Format(time.RFC3339)
			}
			assets = append(assets, a)
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return assets, nil
}

// redshiftSSLEnforcement resolves whether TLS is ENFORCED for a cluster by
// inspecting its cluster parameter group(s) for require_ssl. Results per group
// are memoised in cache. Returns sslUnknown when no group is resolvable or the
// parameters could not be read so a missing signal never becomes a fabricated
// all-clear.
func redshiftSSLEnforcement(ctx context.Context, client redshiftTransitAPI, groups []redshifttypes.ClusterParameterGroupStatus, cache map[string]sslEnforcement) sslEnforcement {
	if len(groups) == 0 {
		return sslUnknown
	}
	result := sslUnknown
	for _, g := range groups {
		if g.ParameterGroupName == nil || *g.ParameterGroupName == "" {
			continue
		}
		name := *g.ParameterGroupName
		enf, ok := cache[name]
		if !ok {
			enf = describeRedshiftGroupRequireSSL(ctx, client, name)
			cache[name] = enf
		}
		switch enf {
		case sslEnforced:
			// Any group that enforces TLS is decisive.
			return sslEnforced
		case sslNotEnforced:
			result = sslNotEnforced
		}
	}
	return result
}

// describeRedshiftGroupRequireSSL paginates DescribeClusterParameters for one
// cluster parameter group and reports the TLS-enforcement state derived from
// require_ssl (documented default: false — plaintext accepted). A read failure
// logs to stderr and yields sslUnknown (never a fabricated posture).
func describeRedshiftGroupRequireSSL(ctx context.Context, client redshiftTransitAPI, name string) sslEnforcement {
	result := sslUnknown
	var marker *string
	for {
		out, err := client.DescribeClusterParameters(ctx, &redshift.DescribeClusterParametersInput{
			ParameterGroupName: aws.String(name),
			Marker:             marker,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "redshift_transit DescribeClusterParameters(%s): %v\n", name, err)
			return sslUnknown
		}
		for _, p := range out.Parameters {
			if p.ParameterName == nil || !strings.EqualFold(*p.ParameterName, "require_ssl") {
				continue
			}
			val := ""
			if p.ParameterValue != nil {
				val = strings.ToLower(strings.TrimSpace(*p.ParameterValue))
			}
			if val == "true" || val == "1" || val == "on" {
				return sslEnforced
			}
			// Explicitly false, or present but unset (Redshift's documented
			// default is false): plaintext accepted.
			result = sslNotEnforced
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return result
}
