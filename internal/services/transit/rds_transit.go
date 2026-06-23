package transit

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type RDSTransitScanner struct{}

func (RDSTransitScanner) Name() string              { return "rds_transit" }
func (RDSTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// rdsTransitAPI is the minimal slice of the rds client this scanner uses. Both
// calls are Marker-paginated, so the scanner must loop; a single call returns
// only the first page, silently dropping instances/parameters in dense
// accounts. Defining it as an interface keeps the pagination + error
// propagation + SSL-enforcement logic unit-testable with a fake (the concrete
// *rds.Client satisfies it).
type rdsTransitAPI interface {
	DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBParameters(ctx context.Context, in *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error)
}

func (s RDSTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := rds.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeDBInstances and classifies
// each instance into a CryptoAsset. A DescribeDBInstances error is NOT swallowed
// — it is returned so the engine records this scanner as errored (visibly
// incomplete) rather than a clean-looking empty success.
func (s RDSTransitScanner) scan(ctx context.Context, client rdsTransitAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	// Cache force_ssl/require_secure_transport enforcement per parameter group so
	// that many instances sharing a group cost a single DescribeDBParameters call.
	pgCache := map[string]sslEnforcement{}
	var marker *string
	for {
		out, err := client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("rds_transit DescribeDBInstances: %w", err)
		}
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(out.DBInstances) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			out.DBInstances = out.DBInstances[:remaining]
		}
		for _, ins := range out.DBInstances {
			if ins.DBInstanceIdentifier == nil {
				continue
			}
			// Read the server CA-certificate identifier + details that
			// DescribeDBInstances already returns. The CA id encodes the leaf
			// cert key family (rds-ca-rsa2048 vs rds-ca-ecc384 vs rds-ca-rsa4096)
			// — a genuine PQ-relevant signal. The negotiated TLS version/cipher
			// is NOT exposed by any API, so we leave the version unknown rather
			// than asserting a fabricated "1.2"/"rds-tls" as observed.
			caID := ""
			if ins.CACertificateIdentifier != nil {
				caID = *ins.CACertificateIdentifier
			}
			if ins.CertificateDetails != nil && ins.CertificateDetails.CAIdentifier != nil && caID == "" {
				caID = *ins.CertificateDetails.CAIdentifier
			}
			sigAlgo, keyBits := dbCertKeyFamily(caID)
			props := services.TLSProtocolPropsDetailed("", "rds-tls", "", sigAlgo, keyBits, false)
			a := services.NewAsset("rds_transit", models.CategoryDataInTransit, accountID, region, *ins.DBInstanceIdentifier, "AWS::RDS::DBInstance", props)

			// RDS instances ALWAYS offer TLS, but offering it is not the same as
			// enforcing it: unless the engine parameter group sets
			// rds.force_ssl=1 (MySQL/MariaDB) or require_secure_transport=ON
			// (PostgreSQL/MySQL), the database STILL accepts plaintext
			// connections. Reporting such an instance as clean classical TLS is
			// a false all-clear, so we resolve the enforcement state from the
			// attached DB parameter group and downgrade the posture when TLS is
			// merely available, not enforced.
			enf := instanceSSLEnforcement(ctx, client, ins.DBParameterGroups, pgCache)
			a.Properties["sslEnforcement"] = string(enf)
			if ins.Engine != nil && *ins.Engine != "" {
				a.Properties["engine"] = *ins.Engine
			}
			switch enf {
			case sslEnforced:
				// force_ssl/require_secure_transport on: plaintext refused.
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				services.StampObserved(&a, "high")
			case sslNotEnforced:
				// TLS offered but plaintext still accepted — a mixed posture, not
				// a clean classical-TLS all-clear. legacy-tls is the closest
				// weakened-transit signal (provably NOT fully-enforced TLS).
				services.PostureProperty(&a, models.PostureLegacyTLS)
				a.Properties["note"] = "RDS instance offers TLS but does not enforce it (rds.force_ssl/require_secure_transport not set in the parameter group); plaintext connections are still accepted."
				services.StampObserved(&a, "high")
			default:
				// enforcement could not be read (no parameter group resolvable,
				// unsupported engine, or a DescribeDBParameters failure): TLS is
				// available but enforcement is unproven. Report Unknown rather
				// than asserting either a clean all-clear or a false alarm.
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "RDS instance offers TLS, but SSL enforcement (rds.force_ssl/require_secure_transport) could not be determined from the parameter group."
			}

			if caID != "" {
				a.Properties["ca_identifier"] = caID
				services.StampObserved(&a, "high")
			}
			if ins.CertificateDetails != nil && ins.CertificateDetails.ValidTill != nil {
				a.Properties["cert_valid_till"] = ins.CertificateDetails.ValidTill.UTC().Format(time.RFC3339)
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

// sslEnforcement records whether an RDS instance forces TLS (refuses plaintext),
// allows plaintext, or could not be determined.
type sslEnforcement string

const (
	sslEnforced    sslEnforcement = "enforced"     // rds.force_ssl=1 / require_secure_transport=ON
	sslNotEnforced sslEnforcement = "not-enforced" // parameter present but off (plaintext accepted)
	sslUnknown     sslEnforcement = "unknown"      // not resolvable / unsupported engine / API error
)

// instanceSSLEnforcement resolves whether TLS is ENFORCED for an instance by
// inspecting its DB parameter group(s) for rds.force_ssl (MySQL/MariaDB) and
// require_secure_transport (PostgreSQL/MySQL). Results per group are memoised in
// cache. Returns sslUnknown when no group is resolvable or the relevant
// parameter is absent so a missing signal never becomes a fabricated all-clear.
func instanceSSLEnforcement(ctx context.Context, client rdsTransitAPI, groups []rdstypes.DBParameterGroupStatus, cache map[string]sslEnforcement) sslEnforcement {
	if len(groups) == 0 {
		return sslUnknown
	}
	result := sslUnknown
	for _, g := range groups {
		if g.DBParameterGroupName == nil || *g.DBParameterGroupName == "" {
			continue
		}
		name := *g.DBParameterGroupName
		enf, ok := cache[name]
		if !ok {
			enf = describeGroupSSLEnforcement(ctx, client, name)
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

// describeGroupSSLEnforcement paginates DescribeDBParameters for one parameter
// group and reports the TLS-enforcement state derived from rds.force_ssl and
// require_secure_transport. A read failure logs to stderr and yields sslUnknown
// (never a fabricated posture).
func describeGroupSSLEnforcement(ctx context.Context, client rdsTransitAPI, name string) sslEnforcement {
	result := sslUnknown
	var marker *string
	for {
		out, err := client.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
			DBParameterGroupName: aws.String(name),
			Marker:               marker,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "rds_transit DescribeDBParameters(%s): %v\n", name, err)
			return sslUnknown
		}
		for _, p := range out.Parameters {
			if p.ParameterName == nil {
				continue
			}
			pn := strings.ToLower(*p.ParameterName)
			if pn != "rds.force_ssl" && pn != "require_secure_transport" {
				continue
			}
			val := ""
			if p.ParameterValue != nil {
				val = strings.ToLower(strings.TrimSpace(*p.ParameterValue))
			}
			if val == "" {
				// Parameter exposed but unset: enforcement not configured.
				if result == sslUnknown {
					result = sslNotEnforced
				}
				continue
			}
			if val == "1" || val == "on" || val == "true" {
				return sslEnforced
			}
			// Explicitly off (0/off/false): plaintext accepted.
			result = sslNotEnforced
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return result
}
