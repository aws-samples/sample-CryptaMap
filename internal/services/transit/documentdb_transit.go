package transit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdb"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type DocumentDBTransitScanner struct{}

func (DocumentDBTransitScanner) Name() string              { return "documentdb_transit" }
func (DocumentDBTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// docdbTransitAPI is the minimal slice of the docdb client this scanner uses.
// DescribeDBClusters, DescribeDBInstances, and DescribeDBClusterParameters are
// all Marker-paginated, so the scanner must loop; a single call returns only the
// first page, silently dropping clusters/instances/parameters in dense accounts.
// Defining it as an interface keeps the pagination + error-propagation logic
// unit-testable with a fake (the concrete *docdb.Client satisfies it).
type docdbTransitAPI interface {
	DescribeDBClusters(ctx context.Context, in *docdb.DescribeDBClustersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClustersOutput, error)
	DescribeDBInstances(ctx context.Context, in *docdb.DescribeDBInstancesInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBInstancesOutput, error)
	DescribeDBClusterParameters(ctx context.Context, in *docdb.DescribeDBClusterParametersInput, optFns ...func(*docdb.Options)) (*docdb.DescribeDBClusterParametersOutput, error)
}

func (s DocumentDBTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := docdb.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeDBClusters and classifies
// each cluster's in-transit-encryption posture. A DescribeDBClusters error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success.
func (s DocumentDBTransitScanner) scan(ctx context.Context, client docdbTransitAPI, accountID, region string) ([]models.CryptoAsset, error) {
	// The server CA-certificate identifier + details live on the DocDB
	// DBInstance, NOT the DBCluster, so build a cluster -> (caID, validTill)
	// map from DescribeDBInstances first and join it onto each cluster below. A
	// describe failure leaves the cert unknown rather than fabricating one.
	clusterCert := docdbClusterCerts(ctx, client)

	// Cache the tls-parameter enforcement state per cluster parameter group so
	// that many clusters sharing a group cost a single DescribeDBClusterParameters
	// call.
	pgCache := map[string]docdbTLSEnforcement{}

	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("documentdb_transit DescribeDBClusters: %w", err)
		}
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(out.DBClusters) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			out.DBClusters = out.DBClusters[:remaining]
		}
		for _, c := range out.DBClusters {
			if c.DBClusterIdentifier == nil {
				continue
			}
			// Join the CA-cert info discovered from the cluster's instances. The
			// CA id encodes the leaf cert key family. The negotiated TLS version
			// is not exposed by any API, so it is left unknown rather than
			// asserting a fabricated "1.2" as observed.
			cert := clusterCert[*c.DBClusterIdentifier]
			sigAlgo, keyBits := dbCertKeyFamily(cert.caID)
			props := services.TLSProtocolPropsDetailed("", "documentdb-tls", "", sigAlgo, keyBits, false)
			a := services.NewAsset("documentdb_transit", models.CategoryDataInTransit, accountID, region, *c.DBClusterIdentifier, "AWS::DocDB::DBCluster", props)

			// DocumentDB enables TLS by default, but in-transit encryption is
			// managed by the "tls" parameter in the cluster's cluster parameter
			// group and CAN be disabled (tls=disabled), in which case the cluster
			// accepts plaintext connections. Reporting such a cluster as clean
			// classical TLS is a false all-clear, so we resolve the tls parameter
			// from the attached cluster parameter group and downgrade the posture
			// to no-encryption when TLS is explicitly disabled. An enforcing value
			// or an unreadable parameter never fabricates an all-clear or alarm.
			enf := clusterTLSEnforcement(ctx, client, c.DBClusterParameterGroup, pgCache)
			a.Properties["tlsEnforcement"] = string(enf)
			switch enf {
			case docdbTLSDisabled:
				// tls=disabled: the cluster does NOT accept secure connections.
				services.PostureProperty(&a, models.PostureNoEncryption)
				a.Properties["note"] = "DocumentDB cluster parameter group sets tls=disabled; the cluster does not accept secure connections and traffic is not encrypted in transit."
				services.StampDocFactKeyed(&a, "transit/documentdb_transit/security-encryption-ssl")
			case docdbTLSEnforced:
				// tls=enabled/tls1.2+/tls1.3+/fips-140-3 (or an immutable default
				// cluster parameter group, which cannot have had tls changed):
				// only secure connections are accepted.
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				services.StampDocFactKeyed(&a, "transit/documentdb_transit/security-encryption-ssl")
			default:
				// The tls parameter could not be read (no parameter group
				// resolvable or a DescribeDBClusterParameters failure): TLS is
				// enabled by default but the enforcement state is unproven. Report
				// Unknown rather than asserting either a clean all-clear or a false
				// alarm.
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "DocumentDB in-transit encryption (the tls cluster parameter) could not be determined from the cluster parameter group; enforcement state is undetermined."
			}

			if cert.caID != "" {
				a.Properties["ca_identifier"] = cert.caID
				services.StampObserved(&a, "high")
			}
			if cert.validTill != nil {
				a.Properties["cert_valid_till"] = cert.validTill.UTC().Format(time.RFC3339)
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

// docdbClusterCert holds the server-cert facts joined from a cluster's instances.
type docdbClusterCert struct {
	caID      string
	validTill *time.Time
}

// docdbClusterCerts paginates DescribeDBInstances and returns a map from
// DBClusterIdentifier to one member instance's CA-certificate id + validity (the
// server CA cert is consistent across a cluster's instances). On any describe
// error it returns whatever was collected so the cluster pass still runs with
// the cert left unknown.
func docdbClusterCerts(ctx context.Context, client docdbTransitAPI) map[string]docdbClusterCert {
	out := map[string]docdbClusterCert{}
	var marker *string
	for {
		page, err := client.DescribeDBInstances(ctx, &docdb.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			fmt.Fprintf(os.Stderr, "documentdb_transit DescribeDBInstances: %v\n", err)
			return out
		}
		for _, ins := range page.DBInstances {
			if ins.DBClusterIdentifier == nil {
				continue
			}
			if _, ok := out[*ins.DBClusterIdentifier]; ok {
				continue
			}
			c := docdbClusterCert{}
			if ins.CACertificateIdentifier != nil {
				c.caID = *ins.CACertificateIdentifier
			}
			if ins.CertificateDetails != nil {
				if c.caID == "" && ins.CertificateDetails.CAIdentifier != nil {
					c.caID = *ins.CertificateDetails.CAIdentifier
				}
				c.validTill = ins.CertificateDetails.ValidTill
			}
			out[*ins.DBClusterIdentifier] = c
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}
	return out
}

// docdbTLSEnforcement records whether a DocumentDB cluster enforces TLS (refuses
// plaintext), has TLS explicitly disabled (plaintext accepted), or could not be
// determined.
type docdbTLSEnforcement string

const (
	docdbTLSEnforced docdbTLSEnforcement = "enforced" // tls=enabled/tls1.2+/tls1.3+/fips-140-3 (or immutable default group)
	docdbTLSDisabled docdbTLSEnforcement = "disabled" // tls=disabled (plaintext accepted)
	docdbTLSUnknown  docdbTLSEnforcement = "unknown"  // not resolvable / API error
)

// clusterTLSEnforcement resolves whether TLS is enforced for a cluster by
// inspecting the tls parameter of its cluster parameter group. The default
// cluster parameter group is immutable (its tls value cannot be changed), so a
// cluster on a default group is reported as enforced without an extra call.
// Results per group are memoised in cache. Returns docdbTLSUnknown when no group
// is resolvable so a missing signal never becomes a fabricated all-clear.
func clusterTLSEnforcement(ctx context.Context, client docdbTransitAPI, group *string, cache map[string]docdbTLSEnforcement) docdbTLSEnforcement {
	if group == nil || *group == "" {
		return docdbTLSUnknown
	}
	name := *group
	if strings.HasPrefix(strings.ToLower(name), "default.") {
		// Default cluster parameter groups are immutable: tls cannot have been
		// changed from its enabled default.
		return docdbTLSEnforced
	}
	if enf, ok := cache[name]; ok {
		return enf
	}
	enf := describeGroupTLSEnforcement(ctx, client, name)
	cache[name] = enf
	return enf
}

// describeGroupTLSEnforcement paginates DescribeDBClusterParameters for one
// cluster parameter group and reports the TLS-enforcement state derived from the
// tls parameter. A read failure logs to stderr and yields docdbTLSUnknown (never
// a fabricated posture).
func describeGroupTLSEnforcement(ctx context.Context, client docdbTransitAPI, name string) docdbTLSEnforcement {
	result := docdbTLSUnknown
	var marker *string
	for {
		out, err := client.DescribeDBClusterParameters(ctx, &docdb.DescribeDBClusterParametersInput{
			DBClusterParameterGroupName: aws.String(name),
			Marker:                      marker,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "documentdb_transit DescribeDBClusterParameters(%s): %v\n", name, err)
			return docdbTLSUnknown
		}
		for _, p := range out.Parameters {
			if p.ParameterName == nil || strings.ToLower(*p.ParameterName) != "tls" {
				continue
			}
			val := ""
			if p.ParameterValue != nil {
				val = strings.ToLower(strings.TrimSpace(*p.ParameterValue))
			}
			switch val {
			case "disabled":
				return docdbTLSDisabled
			case "enabled", "fips-140-3", "tls1.2+", "tls1.3+":
				result = docdbTLSEnforced
			default:
				// Parameter exposed but empty/unrecognised value: leave the
				// enforcement state undetermined rather than guessing.
			}
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return result
}
