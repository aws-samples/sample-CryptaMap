package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// OpenSearchScanner inspects OpenSearch domains for at-rest encryption.
type OpenSearchScanner struct{}

// Name returns the canonical service identifier.
func (OpenSearchScanner) Name() string { return "opensearch" }

// Category returns the primary CryptaMap category.
func (OpenSearchScanner) Category() models.Category { return models.CategoryDataAtRest }

// openSearchAPI is the minimal slice of the opensearch client this scanner uses.
// ListDomainNames is not paginated by the SDK (it returns all domains in one
// call), but DescribeDomain is invoked per domain, so its error handling is the
// load-bearing behavior. Defining the dependency as an interface keeps the
// per-domain error propagation + posture classification unit-testable with a
// hand-rolled fake (the concrete *opensearch.Client satisfies it).
type openSearchAPI interface {
	ListDomainNames(ctx context.Context, in *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomain(ctx context.Context, in *opensearch.DescribeDomainInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainOutput, error)
}

// Scan lists domains, then describes each to read EncryptionAtRestOptions.
func (s OpenSearchScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := opensearch.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it lists domains and describes each to classify
// at-rest posture. A top-level ListDomainNames error is propagated (a denied /
// throttled scan stays VISIBLY incomplete, not a clean empty success). A
// per-domain DescribeDomain error is NOT swallowed and does NOT default to
// NoEncryption — it yields a PostureUnknown asset with a note so the undetermined
// state is honest.
func (s OpenSearchScanner) scan(ctx context.Context, client openSearchAPI, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("opensearch ListDomainNames: %w", err)
	}
	assets := make([]models.CryptoAsset, 0, len(out.DomainNames))
	for _, d := range out.DomainNames {
		if d.DomainName == nil {
			continue
		}
		name := *d.DomainName
		desc, derr := client.DescribeDomain(ctx, &opensearch.DescribeDomainInput{DomainName: d.DomainName})
		if derr != nil {
			// HONESTY CONTRACT: do NOT silently drop the domain (a false all-clear by
			// omission) and do NOT default to NoEncryption (a false alarm). The at-rest
			// state is genuinely undetermined, so emit a PostureUnknown asset with a note.
			fmt.Fprintf(os.Stderr, "opensearch:%s DescribeDomain: %v\n", name, derr)
			a := services.NewAsset("opensearch", models.CategoryDataAtRest, accountID, region, name, "AWS::OpenSearchService::Domain", services.UnknownAtRest())
			services.PostureProperty(&a, models.PostureUnknown)
			a.Properties["note"] = "Could not read OpenSearch domain encryption configuration (DescribeDomain failed); at-rest state undetermined."
			assets = append(assets, a)
			continue
		}
		posture := models.PostureNoEncryption
		props := services.NoEncryption()
		if desc.DomainStatus != nil && desc.DomainStatus.EncryptionAtRestOptions != nil &&
			desc.DomainStatus.EncryptionAtRestOptions.Enabled != nil &&
			*desc.DomainStatus.EncryptionAtRestOptions.Enabled {
			posture = models.PostureSymmetricOnly
			props = services.AESAtRest()
		}
		a := services.NewAsset("opensearch", models.CategoryDataAtRest, accountID, region, name, "AWS::OpenSearchService::Domain", props)
		services.PostureProperty(&a, posture)
		assets = append(assets, a)
	}
	return assets, nil
}
