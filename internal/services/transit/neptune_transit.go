package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/neptune"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type NeptuneTransitScanner struct{}

func (NeptuneTransitScanner) Name() string              { return "neptune_transit" }
func (NeptuneTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// neptuneTransitAPI is the minimal slice of the neptune client this scanner
// uses. Both calls are Marker-paginated, so the scanner must loop; a single call
// returns only the first page, silently dropping clusters/instances in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *neptune.Client satisfies it).
type neptuneTransitAPI interface {
	DescribeDBClusters(ctx context.Context, in *neptune.DescribeDBClustersInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error)
	DescribeDBInstances(ctx context.Context, in *neptune.DescribeDBInstancesInput, optFns ...func(*neptune.Options)) (*neptune.DescribeDBInstancesOutput, error)
}

func (s NeptuneTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := neptune.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it builds the cluster -> CA-cert-id map, then
// paginates DescribeDBClusters and classifies each cluster into a CryptoAsset. A
// DescribeDBClusters error is NOT swallowed — it is returned so the engine
// records this scanner as errored, keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s NeptuneTransitScanner) scan(ctx context.Context, client neptuneTransitAPI, accountID, region string) ([]models.CryptoAsset, error) {
	// The CA-certificate identifier lives on the Neptune DBInstance, NOT the
	// DBCluster, so build a cluster -> CA-cert-id map from DescribeDBInstances
	// first and join it onto each cluster below. A describe failure leaves the
	// cert unknown rather than fabricating one.
	clusterCA := neptuneClusterCACerts(ctx, client)

	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeDBClusters(ctx, &neptune.DescribeDBClustersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("neptune_transit DescribeDBClusters: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// append loop so an unbounded cluster list cannot blow past the cap.
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
			// Join the CA-cert id discovered from the cluster's instances. The
			// CA id encodes the leaf cert key family; the negotiated TLS version
			// is not exposed by any API, so it is left unknown.
			caID := clusterCA[*c.DBClusterIdentifier]
			sigAlgo, keyBits := dbCertKeyFamily(caID)
			props := services.TLSProtocolPropsDetailed("", "neptune-tls", "", sigAlgo, keyBits, false)
			a := services.NewAsset("neptune_transit", models.CategoryDataInTransit, accountID, region, *c.DBClusterIdentifier, "AWS::Neptune::DBCluster", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			if caID != "" {
				a.Properties["ca_identifier"] = caID
			}
			// Neptune only allows SSL connections through HTTPS to any instance or
			// cluster endpoint (plaintext is not accepted), and engine version
			// 1.0.4.0+ only supports HTTPS requests. That TLS-enforcement guarantee
			// is the PRIMARY basis for the transit verdict and is not exposed by any
			// per-resource API, so it is stamped as an aws-doc fact LAST (the
			// observed CA-cert key family above is a secondary detail and must not
			// clobber the doc-fact source). The cipher family is classical
			// (non-PQC), so the PostureNonPQCClassical above remains correct.
			services.StampDocFactKeyed(&a, "transit/neptune_transit/ssl-https-only")
			assets = append(assets, a)
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return assets, nil
}

// neptuneClusterCACerts paginates DescribeDBInstances and returns a map from
// DBClusterIdentifier to the CA-certificate identifier of one of its member
// instances (the server CA cert is consistent across a cluster's instances). On
// any describe error it returns whatever was collected so the cluster pass still
// runs with the cert left unknown.
func neptuneClusterCACerts(ctx context.Context, client neptuneTransitAPI) map[string]string {
	out := map[string]string{}
	var marker *string
	for {
		page, err := client.DescribeDBInstances(ctx, &neptune.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			fmt.Fprintf(os.Stderr, "neptune_transit DescribeDBInstances: %v\n", err)
			return out
		}
		for _, ins := range page.DBInstances {
			if ins.DBClusterIdentifier == nil || ins.CACertificateIdentifier == nil {
				continue
			}
			if _, ok := out[*ins.DBClusterIdentifier]; !ok {
				out[*ins.DBClusterIdentifier] = *ins.CACertificateIdentifier
			}
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}
	return out
}
