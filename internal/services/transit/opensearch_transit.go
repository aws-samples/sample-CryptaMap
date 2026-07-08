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
		// Honest defaults: when DomainEndpointOptions (or a recognizable
		// TLSSecurityPolicy) is absent, the TLS floor/posture cannot be proven
		// from the API data actually read — report Unknown with a note rather
		// than fabricating a "1.2 classical" verdict.
		minVer := ""
		maxVer := ""
		posture := models.PostureUnknown
		policy := ""
		enforceHTTPSStr := ""
		certARN := ""
		plaintextAllowed := false
		note := "DescribeDomain returned no readable DomainEndpointOptions.TLSSecurityPolicy; the domain's TLS floor and posture could not be determined."
		if desc.DomainStatus != nil && desc.DomainStatus.DomainEndpointOptions != nil {
			deo := desc.DomainStatus.DomainEndpointOptions
			policy = string(deo.TLSSecurityPolicy)
			// Deepen: match the REAL TLSSecurityPolicy enum values (the previous
			// "1-2-pq" substring matched no real policy and produced a bogus
			// PQC-hybrid flag). None of these policies are post-quantum. Floor
			// and ceiling come back separately: a floor-1.2 policy that merely
			// permits up to 1.3 must report TLSMinVersion=1.2, never 1.3.
			minVer, maxVer, posture, _ = classifyOpenSearchTLSPolicy(policy)
			if posture == models.PostureUnknown {
				note = fmt.Sprintf("OpenSearch TLSSecurityPolicy %q is not a recognized enum value; the TLS floor and posture could not be determined from it.", policy)
			} else {
				note = ""
			}
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
			// The plaintext note takes precedence over an unrecognized-policy
			// note (no-encryption is the more severe, and proven, verdict).
			if pt, ptNote := openSearchEnforceHTTPSOverride(deo.EnforceHTTPS); pt {
				plaintextAllowed, note = pt, ptNote
			}
			// A custom endpoint binds a customer ACM cert (default AWS-managed
			// endpoint cert is not resolvable). Only present when a custom endpoint
			// is configured.
			if deo.CustomEndpointCertificateArn != nil && *deo.CustomEndpointCertificateArn != "" {
				certARN = *deo.CustomEndpointCertificateArn
			}
		}
		// Version carries the policy's CEILING (highest permitted version);
		// TLSMinVersion carries the FLOOR. Both are set only when proven from
		// the recognized TLSSecurityPolicy enum value — never guessed.
		props := services.TLSProtocolProps(maxVer, policy)
		if props.ProtocolProperties != nil && minVer != "" {
			props.ProtocolProperties.TLSMinVersion = minVer
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
