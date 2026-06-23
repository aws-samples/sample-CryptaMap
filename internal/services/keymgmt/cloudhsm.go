package keymgmt

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CloudHSMScanner discovers CloudHSMv2 clusters.
type CloudHSMScanner struct{}

// Name returns the canonical scanner identifier.
func (CloudHSMScanner) Name() string { return "cloudhsm" }

// Category returns the primary category for this scanner.
func (CloudHSMScanner) Category() models.Category { return models.CategoryKeyManagement }

// cloudHSMv2API is the minimal slice of the cloudhsmv2 client this scanner uses.
// DescribeClusters is NextToken-paginated, so the scanner must loop; a single call
// returns only the first page, silently dropping clusters in dense accounts.
// Defining it as an interface keeps the pagination + error-propagation logic
// unit-testable with a fake (the concrete *cloudhsmv2.Client satisfies it).
type cloudHSMv2API interface {
	DescribeClusters(ctx context.Context, in *cloudhsmv2.DescribeClustersInput, optFns ...func(*cloudhsmv2.Options)) (*cloudhsmv2.DescribeClustersOutput, error)
}

// Scan lists CloudHSMv2 clusters and emits one asset per cluster.
// Pagination via NextToken; capped at services.MaxAssetsPerScanner items.
func (s CloudHSMScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cloudhsmv2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeClusters and classifies each
// cluster into a CryptoAsset. A DescribeClusters error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s CloudHSMScanner) scan(ctx context.Context, client cloudHSMv2API, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeClusters(ctx, &cloudhsmv2.DescribeClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("cloudhsmv2 DescribeClusters: %w", err)
		}
		// Cap the per-page cluster batch to the remaining per-scanner budget before
		// appending so we never exceed the cap and surface truncation honestly.
		clusters := out.Clusters
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(clusters) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			clusters = clusters[:remaining]
		}
		for _, c := range clusters {
			if c.ClusterId == nil {
				continue
			}
			id := *c.ClusterId
			hsmType := ""
			if c.HsmType != nil {
				hsmType = *c.HsmType
			}
			// CycloneDX relatedCryptoMaterialProperties.type is an ENUM; an HSM cluster
			// is a key-storage container → the valid member is "key". The descriptive
			// "hsm-cluster" label is preserved as cryptamap:materialType below.
			props := services.KeyMaterialProps("key", models.StateActive, 0, hsmType)
			a := services.NewAsset("cloudhsm", models.CategoryKeyManagement, accountID, region, id, "AWS::CloudHSM::Cluster", props)
			a.Properties["materialType"] = "hsm-cluster"
			a.Properties["hsmType"] = hsmType
			a.Properties["state"] = string(c.State)
			// Mode (FIPS | NON_FIPS) is the single most crypto-relevant cluster
			// property and is immutable after creation: in FIPS mode only FIPS-validated
			// keys/algorithms can be used (AWS docs). Capture it as the authoritative
			// FIPS fact, plus cert presence and creation time from the SAME
			// DescribeClusters response (no extra API call).
			if c.Mode != "" {
				a.Properties["mode"] = string(c.Mode)
			}
			a.Properties["certificatesPresent"] = strconv.FormatBool(c.Certificates != nil)
			if c.CreateTimestamp != nil {
				a.Properties["createTimestamp"] = c.CreateTimestamp.UTC().Format(time.RFC3339)
			}
			// CloudHSM exposes a closed PKCS#11 mechanism/key-type set (AES/3DES/RSA/
			// ECDSA + classical hashes only — no ML-KEM/ML-DSA/SLH-DSA), so any
			// asymmetric key in the cluster is classical/quantum-vulnerable. This is a
			// UNIVERSAL guarantee (exhaustive supported-algorithm enumeration), not an
			// overridable default; keep PostureNonPQCClassical and cite the doc.
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "keymgmt/cloudhsm/pkcs11-classical-only")
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
