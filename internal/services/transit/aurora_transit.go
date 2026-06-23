package transit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type AuroraTransitScanner struct{}

func (AuroraTransitScanner) Name() string              { return "aurora_transit" }
func (AuroraTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// auroraTransitRDSAPI is the minimal slice of the rds client this scanner uses.
// Both calls are Marker-paginated, so the scanner must loop; a single call
// returns only the first page, silently dropping clusters/parameters in dense
// accounts. Defining it as an interface keeps pagination + error-propagation
// logic unit-testable with a fake (the concrete *rds.Client satisfies it).
type auroraTransitRDSAPI interface {
	DescribeDBClusters(ctx context.Context, in *rds.DescribeDBClustersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
	DescribeDBClusterParameters(ctx context.Context, in *rds.DescribeDBClusterParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClusterParametersOutput, error)
}

func (s AuroraTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := rds.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeDBClusters, classifies each
// Aurora cluster's transit posture (cert key family + enforce-TLS toggle), and is
// driven by the auroraTransitRDSAPI interface so a fake can exercise pagination
// and error paths without a live AWS client. A DescribeDBClusters error is NOT
// swallowed — it is propagated so a denied/throttled scan stays VISIBLY
// incomplete rather than a clean-looking empty success.
func (s AuroraTransitScanner) scan(ctx context.Context, client auroraTransitRDSAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	// Cache enforce-TLS lookups by cluster parameter-group name so a group
	// shared across many clusters is read once per region.
	enforceCache := map[string]dbSSLEnforcement{}
	var marker *string
	for {
		out, err := client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("aurora_transit DescribeDBClusters: %w", err)
		}
		for _, c := range out.DBClusters {
			if c.DBClusterIdentifier == nil || c.Engine == nil {
				continue
			}
			if !strings.HasPrefix(strings.ToLower(*c.Engine), "aurora") {
				continue
			}
			// Read CertificateDetails (CAIdentifier + ValidTill) already returned
			// by DescribeDBClusters. The CA id encodes the leaf cert key family
			// (RSA-2048 vs ECDSA-P384 vs RSA-4096). The negotiated TLS version is
			// not exposed by any API, so the version is left unknown rather than
			// asserting a fabricated "1.2"/"aurora-tls" as observed.
			caID := ""
			var validTill *time.Time
			if c.CertificateDetails != nil {
				if c.CertificateDetails.CAIdentifier != nil {
					caID = *c.CertificateDetails.CAIdentifier
				}
				validTill = c.CertificateDetails.ValidTill
			}
			sigAlgo, keyBits := dbCertKeyFamily(caID)
			props := services.TLSProtocolPropsDetailed("", "aurora-tls", "", sigAlgo, keyBits, false)
			a := services.NewAsset("aurora_transit", models.CategoryDataInTransit, accountID, region, *c.DBClusterIdentifier, "AWS::RDS::DBCluster", props)
			if caID != "" {
				a.Properties["ca_identifier"] = caID
				services.StampObserved(&a, "high")
			}
			if validTill != nil {
				a.Properties["cert_valid_till"] = validTill.UTC().Format(time.RFC3339)
			}

			// TLS being AVAILABLE is not the same as TLS being REQUIRED: unless
			// the cluster parameter group sets require_secure_transport=1
			// (Aurora-MySQL) or rds.force_ssl=1 (Aurora-PostgreSQL), clients may
			// still connect in plaintext. Inspect the toggle and downgrade the
			// posture when enforcement is absent. A param-group read failure
			// leaves enforcement "unknown" so we never fabricate an all-clear or
			// an alarm.
			enforce := auroraSSLEnforcement(ctx, client, c.DBClusterParameterGroup, enforceCache)
			a.Properties["tls_enforcement"] = string(enforce)
			switch enforce {
			case dbSSLEnforced:
				services.PostureProperty(&a, models.PostureNonPQCClassical)
			case dbSSLNotEnforced:
				// TLS available but not required: plaintext connections are
				// permitted. legacy-tls is the closest weakened-transit posture
				// (there is no PostureMixed constant).
				services.PostureProperty(&a, models.PostureLegacyTLS)
				a.Properties["note"] = "TLS available but not enforced (require_secure_transport/rds.force_ssl not set); plaintext client connections permitted"
			default:
				// Enforcement undetermined (param group unreadable/absent). Do
				// not assert a clean classical all-clear off an unverified toggle.
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "TLS enforcement state could not be determined from the cluster parameter group"
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

// auroraSSLEnforcement resolves whether the given cluster parameter group forces
// TLS, caching by group name. A nil group name or any describe error yields
// dbSSLUnknown so an unreadable toggle never becomes a fabricated verdict.
func auroraSSLEnforcement(ctx context.Context, client auroraTransitRDSAPI, groupName *string, cache map[string]dbSSLEnforcement) dbSSLEnforcement {
	if groupName == nil || *groupName == "" {
		return dbSSLUnknown
	}
	if cached, ok := cache[*groupName]; ok {
		return cached
	}
	params := map[string]string{}
	var marker *string
	for {
		page, err := client.DescribeDBClusterParameters(ctx, &rds.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: groupName,
			Marker:                      marker,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "aurora_transit DescribeDBClusterParameters(%s): %v\n", *groupName, err)
			cache[*groupName] = dbSSLUnknown
			return dbSSLUnknown
		}
		for _, p := range page.Parameters {
			if p.ParameterName == nil {
				continue
			}
			val := ""
			if p.ParameterValue != nil {
				val = *p.ParameterValue
			}
			params[*p.ParameterName] = val
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}
	enforce := classifyDBSSLEnforcement(params)
	cache[*groupName] = enforce
	return enforce
}
