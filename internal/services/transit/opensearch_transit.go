package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type OpenSearchTransitScanner struct{}

func (OpenSearchTransitScanner) Name() string              { return "opensearch_transit" }
func (OpenSearchTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// opensearchTransitAPI is the minimal slice of the opensearch client this
// scanner uses. ListDomainNames is not paginated (the API returns all domains
// in one shot, no NextToken), and DescribeDomain is called once per domain.
// Defining it as an interface keeps the error-propagation + classification
// logic unit-testable with a fake (the concrete *opensearch.Client satisfies
// it), with no live AWS.
type opensearchTransitAPI interface {
	ListDomainNames(ctx context.Context, in *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomain(ctx context.Context, in *opensearch.DescribeDomainInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error)
}

func (s OpenSearchTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := opensearch.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it lists OpenSearch domains, describes each, and
// classifies it into a CryptoAsset. A ListDomainNames error is NOT swallowed — it
// is returned so the engine records this scanner as errored (keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success). A per-domain DescribeDomain error is logged and skipped (byte-for-byte
// the prior behavior).
func (s OpenSearchTransitScanner) scan(ctx context.Context, client opensearchTransitAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	listOut, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("opensearch_transit ListDomainNames: %w", err)
	}
	assets := []models.CryptoAsset{}
	for _, d := range listOut.DomainNames {
		if d.DomainName == nil {
			continue
		}
		desc, derr := client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: d.DomainName})
		if derr != nil {
			fmt.Fprintf(os.Stderr, "opensearch_transit DescribeDomain %s: %v\n", *d.DomainName, derr)
			continue
		}
		ver := "1.2"
		posture := models.PostureNonPQCClassical
		policy := ""
		enforceHTTPSStr := ""
		certARN := ""
		plaintextAllowed := false
		note := ""
		if desc.DomainStatus != nil && desc.DomainStatus.DomainEndpointOptions != nil {
			deo := desc.DomainStatus.DomainEndpointOptions
			policy = string(deo.TLSSecurityPolicy)
			// Deepen: match the REAL TLSSecurityPolicy enum values (the previous
			// "1-2-pq" substring matched no real policy and produced a bogus
			// PQC-hybrid flag). None of these policies are post-quantum.
			ver, posture, _ = classifyOpenSearchTLSPolicy(policy)
			if deo.EnforceHTTPS != nil {
				if *deo.EnforceHTTPS {
					enforceHTTPSStr = "true"
				} else {
					enforceHTTPSStr = "false"
				}
			}
			// EnforceHTTPS=false means the endpoint accepts plaintext HTTP
			// regardless of the TLSSecurityPolicy floor, so a domain that permits
			// plaintext must NOT be reported as clean classical TLS (mirrors MSK's
			// TLS_PLAINTEXT and elasticache's "preferred" mixed-mode handling).
			plaintextAllowed, note = openSearchEnforceHTTPSOverride(deo.EnforceHTTPS)
			// A custom endpoint binds a customer ACM cert (default AWS-managed
			// endpoint cert is not resolvable). Only present when a custom endpoint
			// is configured.
			if deo.CustomEndpointCertificateArn != nil && *deo.CustomEndpointCertificateArn != "" {
				certARN = *deo.CustomEndpointCertificateArn
			}
		}
		props := services.TLSProtocolProps(ver, policy)
		// The TLSSecurityPolicy enum is itself the documented TLS floor.
		if props.ProtocolProperties != nil && ver != "" {
			props.ProtocolProperties.TLSMinVersion = ver
		}
		if plaintextAllowed {
			// EnforceHTTPS is disabled: plaintext is accepted regardless of the
			// configured TLS policy, so the endpoint is not encrypted-in-transit.
			props = services.NoEncryption()
			posture = models.PostureNoEncryption
		}
		a := services.NewAsset("opensearch_transit", models.CategoryDataInTransit, accountID, region, *d.DomainName, "AWS::OpenSearchService::Domain", props)
		services.PostureProperty(&a, posture)
		if note != "" {
			a.Properties["note"] = note
		}
		if enforceHTTPSStr != "" {
			a.Properties["enforceHttps"] = enforceHTTPSStr
		}
		if certARN != "" {
			a.Properties["certificateArn"] = certARN
			resolveACMCert(ctx, certResolver, certARN, &a)
		}
		assets = append(assets, a)
	}
	return assets, nil
}
