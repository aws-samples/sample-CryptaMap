package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SageMakerScanner inspects SageMaker domains for KMS encryption of EFS volumes.
type SageMakerScanner struct{}

// sageMakerAPI is the minimal slice of the sagemaker client this scanner uses.
// ListDomains is NextToken-paginated (so the scanner must loop; a single call
// returns only the first page, silently dropping domains in dense accounts) and
// DescribeDomain carries the per-domain KMS key. Defining it as an interface keeps
// the pagination + error-propagation + key-tier logic unit-testable with a fake
// (the concrete *sagemaker.Client satisfies it).
type sageMakerAPI interface {
	ListDomains(ctx context.Context, in *sagemaker.ListDomainsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListDomainsOutput, error)
	DescribeDomain(ctx context.Context, in *sagemaker.DescribeDomainInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeDomainOutput, error)
}

// Name returns the canonical service identifier.
func (SageMakerScanner) Name() string { return "sagemaker" }

// Category returns the primary CryptaMap category.
func (SageMakerScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan paginates ListDomains, then DescribeDomain for the KMS key.
func (s SageMakerScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := sagemaker.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListDomains and, per domain,
// DescribeDomain to read the KMS key tier. A ListDomains error is NOT swallowed —
// it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success. A per-domain DescribeDomain error does NOT silently drop the domain nor
// emit a clean AWS-owned-key default (a false-safe): the domain is known to exist
// (it was in ListDomains) but its key custody is undetermined, so it is recorded as
// PostureUnknown with a note (HONESTY CONTRACT: never an all-clear by omission).
func (s SageMakerScanner) scan(ctx context.Context, client sageMakerAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListDomains(ctx, &sagemaker.ListDomainsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("sagemaker ListDomains: %w", err)
		}
		for _, d := range out.Domains {
			if d.DomainId == nil {
				continue
			}
			id := *d.DomainId
			desc, derr := client.DescribeDomain(ctx, &sagemaker.DescribeDomainInput{DomainId: d.DomainId})
			if derr != nil {
				fmt.Fprintf(os.Stderr, "sagemaker:%s DescribeDomain: %v\n", id, derr)
				// The domain is known to exist (it was in ListDomains) but its
				// encryption detail could not be read — keep it as PostureUnknown
				// rather than silently dropping it or emitting a clean AWS-owned-key
				// default (HONESTY CONTRACT: never an all-clear by omission, never a
				// no-encryption false alarm).
				a := services.NewAsset("sagemaker", models.CategoryDataAtRest, accountID, region, id, "AWS::SageMaker::Domain", services.UnknownAtRest())
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "Could not read domain encryption (DescribeDomain failed); at-rest key custody undetermined."
				assets = append(assets, a)
				continue
			}
			// A SageMaker Domain's EFS volume is always encrypted at rest — with an
			// AWS-managed key by default, or a customer-managed key when specified — so
			// posture is unconditionally SymmetricOnly. An empty KmsKeyId means the
			// AWS-managed default key, NOT no-encryption.
			kmsKey := "AWS_OWNED_KMS_KEY"
			if desc.KmsKeyId != nil && *desc.KmsKeyId != "" {
				kmsKey = *desc.KmsKeyId
			}
			a := services.NewAsset("sagemaker", models.CategoryDataAtRest, accountID, region, id, "AWS::SageMaker::Domain", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/sagemaker/at-rest-aes256")
			a.Properties["kmsKeyId"] = kmsKey
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
