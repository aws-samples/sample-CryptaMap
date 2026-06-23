package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// IoTCoreScanner reports the IoT Core data-plane TLS posture. The authoritative
// TLS posture lives on the account's DOMAIN CONFIGURATIONS (their TlsConfig
// SecurityPolicy), not on individual Things — a Thing is a device-registry
// record with no TLS negotiation data. We therefore read each domain
// configuration's real security policy and emit one
// AWS::IoT::DomainConfiguration asset per config, plus the implicit
// "iot:Data-ATS" endpoint, and keep Things only as an inventory count (capped at
// 50) WITHOUT attaching a fabricated TLS classification to them.
type IoTCoreScanner struct{}

func (IoTCoreScanner) Name() string              { return "iotcore" }
func (IoTCoreScanner) Category() models.Category { return models.CategoryDataInTransit }

// iotCoreAPI is the minimal slice of the iot client this scanner uses.
// ListDomainConfigurations and ListThings are Marker/MaxResults-paginated, so the
// scanner must loop; a single call returns only the first page, silently dropping
// domain configurations/Things in dense accounts. Defining it as an interface
// keeps the pagination + error propagation logic unit-testable with a fake (the
// concrete *iot.Client satisfies it).
type iotCoreAPI interface {
	ListDomainConfigurations(ctx context.Context, in *iot.ListDomainConfigurationsInput, optFns ...func(*iot.Options)) (*iot.ListDomainConfigurationsOutput, error)
	DescribeDomainConfiguration(ctx context.Context, in *iot.DescribeDomainConfigurationInput, optFns ...func(*iot.Options)) (*iot.DescribeDomainConfigurationOutput, error)
	ListThings(ctx context.Context, in *iot.ListThingsInput, optFns ...func(*iot.Options)) (*iot.ListThingsOutput, error)
}

func (s IoTCoreScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := iot.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListDomainConfigurations and
// ListThings, describes each domain configuration's real TLS security policy, and
// classifies the result. Behavior mirrors the original Scan exactly — a
// ListDomainConfigurations error breaks the loop (the data endpoint + Things are
// still attempted), and a ListThings error is surfaced only when nothing else was
// found, so domain-config assets are never dropped by a Things failure.
func (s IoTCoreScanner) scan(ctx context.Context, client iotCoreAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}

	// Domain configurations carry the real TLS security policy. Paginate
	// ListDomainConfigurations (Marker/NextMarker) and describe each one.
	seen := map[string]bool{}
	var marker *string
	for {
		out, err := client.ListDomainConfigurations(ctx, &iot.ListDomainConfigurationsInput{Marker: marker})
		if err != nil {
			fmt.Fprintf(os.Stderr, "iotcore ListDomainConfigurations: %v\n", err)
			break
		}
		for _, dc := range out.DomainConfigurations {
			if dc.DomainConfigurationName == nil {
				continue
			}
			seen[*dc.DomainConfigurationName] = true
			if a, ok := s.describeDomainConfig(ctx, client, accountID, region, *dc.DomainConfigurationName); ok {
				assets = append(assets, a)
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}

	// Also describe the implicit data endpoint config "iot:Data-ATS" to capture
	// the real ATS posture when it is not already in the list above.
	if !seen["iot:Data-ATS"] {
		if a, ok := s.describeDomainConfig(ctx, client, accountID, region, "iot:Data-ATS"); ok {
			assets = append(assets, a)
		}
	}

	// Things: keep an inventory baseline (capped at 50) but do NOT attach a TLS
	// classification — a Thing is not a TLS endpoint.
	max := int32(50)
	tout, err := client.ListThings(ctx, &iot.ListThingsInput{MaxResults: &max})
	if err != nil {
		// Domain-config assets are the primary signal; a ListThings failure
		// should not drop them. Surface the error only when nothing was found.
		if len(assets) == 0 {
			return nil, fmt.Errorf("iotcore ListThings: %w", err)
		}
		fmt.Fprintf(os.Stderr, "iotcore ListThings: %v\n", err)
		return assets, nil
	}
	for _, t := range tout.Things {
		if t.ThingName == nil {
			continue
		}
		// Inventory-only: empty protocol block, no fabricated posture.
		a := services.NewAsset("iotcore", models.CategoryDataInTransit, accountID, region, *t.ThingName, "AWS::IoT::Thing", models.CryptoProperties{AssetType: models.AssetTypeProtocol})
		a.Properties["inventory"] = "true"
		assets = append(assets, a)
	}
	return assets, nil
}

// describeDomainConfig reads one domain configuration's TlsConfig.SecurityPolicy
// and builds an AWS::IoT::DomainConfiguration asset classified from the REAL
// policy. Returns (asset, false) when the config cannot be described.
func (s IoTCoreScanner) describeDomainConfig(ctx context.Context, client iotCoreAPI, accountID, region, name string) (models.CryptoAsset, bool) {
	out, err := client.DescribeDomainConfiguration(ctx, &iot.DescribeDomainConfigurationInput{DomainConfigurationName: &name})
	if err != nil {
		fmt.Fprintf(os.Stderr, "iotcore DescribeDomainConfiguration %s: %v\n", name, err)
		return models.CryptoAsset{}, false
	}

	policy := ""
	if out.TlsConfig != nil && out.TlsConfig.SecurityPolicy != nil {
		policy = *out.TlsConfig.SecurityPolicy
	}

	ver, posture := classifyIoTSecurityPolicy(policy)
	observed := policy != ""
	if !observed {
		// No policy returned: fall back to the AWS-doc default for NEW domain
		// configurations (IoTSecurityPolicy_TLS13_1_2_2022_10 => TLS 1.3). This
		// is an overridable default for existing configs, so it is tagged
		// aws-doc / low confidence rather than asserted as observed.
		ver = "1.3"
		posture = models.PostureNonPQCClassical
	}

	suite := policy
	if suite == "" {
		suite = "iot-tls"
	}
	props := services.TLSProtocolProps(ver, suite)
	// The IoT SecurityPolicy enum is itself the documented TLS floor (empty when
	// the policy is unknown so no floor is fabricated).
	if props.ProtocolProperties != nil && ver != "" {
		props.ProtocolProperties.TLSMinVersion = ver
	}
	a := services.NewAsset("iotcore", models.CategoryDataInTransit, accountID, region, name, "AWS::IoT::DomainConfiguration", props)
	services.PostureProperty(&a, posture)
	if out.DomainName != nil {
		a.Properties["domainName"] = *out.DomainName
	}
	if string(out.ServiceType) != "" {
		a.Properties["serviceType"] = string(out.ServiceType)
	}
	if observed {
		a.Properties["securityPolicy"] = policy
		services.StampObserved(&a, "high")
	} else {
		services.StampDocFactKeyed(&a, "transit/iotcore/iot-endpoints-tls-config")
	}
	return a, true
}
