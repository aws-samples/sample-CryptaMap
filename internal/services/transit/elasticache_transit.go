package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type ElastiCacheTransitScanner struct{}

func (ElastiCacheTransitScanner) Name() string              { return "elasticache_transit" }
func (ElastiCacheTransitScanner) Category() models.Category { return models.CategoryDataInTransit }

// elasticacheTransitAPI is the minimal slice of the elasticache client this
// scanner uses. DescribeReplicationGroups is Marker-paginated, so the scanner
// must loop; a single call returns only the first page, silently dropping
// replication groups in dense accounts. Defining it as an interface keeps the
// pagination + error-propagation logic unit-testable with a fake (the concrete
// *elasticache.Client satisfies it).
type elasticacheTransitAPI interface {
	DescribeReplicationGroups(ctx context.Context, in *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error)
}

func (s ElastiCacheTransitScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := elasticache.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeReplicationGroups and
// classifies each group's transit-encryption posture. A DescribeReplicationGroups
// error is NOT swallowed — it is returned so the engine records this scanner as
// errored (which surfaces in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s ElastiCacheTransitScanner) scan(ctx context.Context, client elasticacheTransitAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("elasticache_transit DescribeReplicationGroups: %w", err)
		}
		for _, rg := range out.ReplicationGroups {
			if rg.ReplicationGroupId == nil {
				continue
			}
			// Read the encryption MODE (preferred/required) alongside the bool.
			// DescribeReplicationGroups already returns both fields — no extra
			// API call. The mode determines whether plaintext is still accepted:
			// "required" enforces TLS (drops unencrypted connections) while
			// "preferred" is a mixed mode that ALSO accepts plaintext, so a
			// preferred group must NOT be reported as clean classical TLS.
			enabled := rg.TransitEncryptionEnabled != nil && *rg.TransitEncryptionEnabled
			mode := string(rg.TransitEncryptionMode)
			posture := models.PostureNoEncryption
			docFact := false
			switch {
			case !enabled:
				posture = models.PostureNoEncryption
			case mode == "required":
				// TLS enforced — plaintext refused.
				posture = models.PostureNonPQCClassical
				docFact = true
			case mode == "preferred":
				// Mixed mode: TLS offered but plaintext still accepted. There is
				// no PostureMixed constant; legacy-tls is the closest weakened-
				// transit signal (it is provably NOT fully-enforced TLS).
				posture = models.PostureLegacyTLS
				docFact = true
			default:
				// enabled==true but no mode reported: TLS is on, enforcement
				// unknown. Keep classical without asserting "required".
				posture = models.PostureNonPQCClassical
			}
			// Do NOT hardcode a TLS 1.2 floor: the 1.2 minimum applies only to
			// Valkey 7.2+ / Redis OSS 6+ (and only from 2026-04-28); older engines may
			// still negotiate TLS 1.0/1.1. ReplicationGroup exposes Engine but not the
			// engine VERSION (that needs DescribeCacheClusters), so we cannot prove the
			// floor per group — leave the version UNSET rather than asserting a
			// fabricated "1.2" (which was a false-safe for legacy engines). The
			// mode-derived posture above is unaffected.
			props := services.TLSProtocolProps("", "AWS-managed")
			a := services.NewAsset("elasticache_transit", models.CategoryDataInTransit, accountID, region, *rg.ReplicationGroupId, "AWS::ElastiCache::ReplicationGroup", props)
			services.PostureProperty(&a, posture)
			if mode != "" {
				a.Properties["transitEncryptionMode"] = mode
			}
			if rg.Engine != nil && *rg.Engine != "" {
				a.Properties["engine"] = *rg.Engine
			}
			// The preferred/required plaintext-acceptance semantics are a
			// universal AWS-doc guarantee, not an observed cipher.
			if docFact {
				services.StampDocFactKeyed(&a, "transit/elasticache_transit/in-transit-encryption-enable")
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
