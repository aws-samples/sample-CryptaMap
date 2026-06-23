package transit

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	apigwv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestTransitScanners_EnumOracleCBOMConformance is a CONTRACT test: for every
// AWS SDK enum field a transit scanner reads, it iterates AWS's OWN authoritative
// value set — the generated EnumType("").Values() method — and asserts the
// scanner produces a schema-valid CycloneDX 1.7 CBOM for EACH enum member. The
// SDK's enums.go is the oracle; if AWS adds a new TLS security policy or a new
// client-broker mode in a future SDK bump, this test automatically covers it and
// fails LOUDLY if that value yields a panic or a schema-invalid asset (e.g. an
// unexpected protocol-version string, an empty cipherSuite name, a bad
// relatedCryptoMaterial enum). A failure here is a REAL output bug, not a test
// defect — do not soften or skip values to make it pass.
//
// Fields with a free-string SDK type (no generated enum) are covered against the
// AWS-documented value set as a curated slice, clearly marked.
//
// Fully offline: every subtest reuses the package's existing hand-rolled fakes.
// context.Background(), account "111122223333", region "us-east-1".
func TestTransitScanners_EnumOracleCBOMConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping enum-oracle conformance: %v", err)
	}

	const acct, region = "111122223333", "us-east-1"

	// validate is the shared assertion: scan must not panic, must succeed, yield
	// >=1 asset, and its CBOM must pass CycloneDX 1.7 schema validation. The
	// failure message carries the enum type + value so a regression points
	// straight at the offending AWS value.
	validate := func(t *testing.T, enumType, value string, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("scan for %s=%q returned error: %v", enumType, value, err)
		}
		if len(assets) == 0 {
			t.Fatalf("scan for %s=%q produced zero assets (expected >=1)", enumType, value)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("CBOM failed CycloneDX 1.7 schema validation for %s=%q: %v", enumType, value, verr)
		}
	}

	// ------------------------------------------------------------------
	// apigw REST: apigatewaytypes.SecurityPolicy on the custom DomainName.
	// Drives secPolicyToVersion -> TLSProtocolPropsDetailed (the richest
	// path: PQ-hybrid policies emit a KeyExchangeGroup + PQCHybrid flag).
	// ------------------------------------------------------------------
	t.Run("apigw_rest/SecurityPolicy", func(t *testing.T) {
		vals := apigwtypes.SecurityPolicy("").Values()
		if len(vals) == 0 {
			t.Fatal("apigatewaytypes.SecurityPolicy().Values() is empty; SDK contract changed")
		}
		for _, v := range vals {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeAPIGWRestClient{
					domainsPages: []*apigw.GetDomainNamesOutput{
						{Items: []apigwtypes.DomainName{{
							DomainName:     apigwrestStrptr("dom.example.com"),
							SecurityPolicy: v,
						}}},
					},
				}
				assets, err := APIGWRestScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
				validate(t, "apigateway.SecurityPolicy", string(v), assets, err)
			})
		}
	})

	// ------------------------------------------------------------------
	// apigw HTTP: apigatewayv2types.SecurityPolicy on the HTTP-API custom
	// DomainNameConfiguration. The apigwv2 fake serves a single domainsOut.
	// ------------------------------------------------------------------
	t.Run("apigw_http/SecurityPolicy", func(t *testing.T) {
		vals := apigwv2types.SecurityPolicy("").Values()
		if len(vals) == 0 {
			t.Fatal("apigatewayv2types.SecurityPolicy().Values() is empty; SDK contract changed")
		}
		for _, v := range vals {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeAPIGWHTTPClient{
					domainsOut: &apigwv2.GetDomainNamesOutput{
						Items: []apigwv2types.DomainName{{
							DomainName: strptr("dom.example.com"),
							DomainNameConfigurations: []apigwv2types.DomainNameConfiguration{
								{SecurityPolicy: v},
							},
						}},
					},
				}
				assets, err := APIGWHTTPScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
				validate(t, "apigatewayv2.SecurityPolicy", string(v), assets, err)
			})
		}
	})

	// ------------------------------------------------------------------
	// opensearch: opensearchtypes.TLSSecurityPolicy on the domain endpoint
	// options. EnforceHTTPS is held true so each policy drives the real
	// classifyOpenSearchTLSPolicy floor -> TLSProtocolProps path.
	// ------------------------------------------------------------------
	t.Run("opensearch_transit/TLSSecurityPolicy", func(t *testing.T) {
		vals := opensearchtypes.TLSSecurityPolicy("").Values()
		if len(vals) == 0 {
			t.Fatal("opensearchtypes.TLSSecurityPolicy().Values() is empty; SDK contract changed")
		}
		for _, v := range vals {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeOpensearchTransitClient{
					listOut: &opensearch.ListDomainNamesOutput{
						DomainNames: []opensearchtypes.DomainInfo{
							{DomainName: opensearchtransitStrptr("dom")},
						},
					},
					descByName: map[string]*opensearch.DescribeDomainOutput{
						"dom": opensearchtransitDomain("dom", string(v), opensearchtransitBoolptr(true), ""),
					},
				}
				assets, err := OpenSearchTransitScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
				validate(t, "opensearch.TLSSecurityPolicy", string(v), assets, err)
			})
		}
	})

	// ------------------------------------------------------------------
	// msk: kafkatypes.ClientBroker on the provisioned cluster's
	// EncryptionInTransit. TLS / TLS_PLAINTEXT / PLAINTEXT each drive a
	// different posture + (for the no-encryption case) NoEncryption() props.
	// InCluster held true to fix the other field.
	// ------------------------------------------------------------------
	t.Run("msk_transit/ClientBroker", func(t *testing.T) {
		vals := kafkatypes.ClientBroker("").Values()
		if len(vals) == 0 {
			t.Fatal("kafkatypes.ClientBroker().Values() is empty; SDK contract changed")
		}
		for _, v := range vals {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeMSKTransitClient{
					clustersPages: []*kafka.ListClustersV2Output{
						{ClusterInfoList: []kafkatypes.Cluster{
							msktransitProvisionedCluster("cluster-"+string(v), string(v), msktransitBoolptr(true)),
						}},
					},
				}
				assets, err := MSKTransitScanner{}.scan(context.Background(), client, acct, region)
				validate(t, "kafka.ClientBroker", string(v), assets, err)
			})
		}
	})

	// ------------------------------------------------------------------
	// iot: the IoT Core domain-configuration TlsConfig.SecurityPolicy is a
	// FREE STRING in the SDK (*string, no generated enum type), so there is
	// no Values() oracle. Cover the AWS-documented IoT Core security-policy
	// set as a curated slice (the documented predefined names) plus the
	// empty/doc-default path. Source:
	// https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html
	// If AWS adds a policy here, this list must be extended manually.
	// ------------------------------------------------------------------
	t.Run("iotcore/SecurityPolicy_curated", func(t *testing.T) {
		// Documented IoT Core predefined TLS security policies. These are the
		// values DescribeDomainConfiguration returns in TlsConfig.SecurityPolicy.
		iotPolicies := []string{
			"",                                    // no TlsConfig -> doc-default (TLS 1.3) path
			"IoTSecurityPolicy_TLS13_1_2_2022_10", // TLS 1.3 floor
			"IoTSecurityPolicy_TLS12_1_2_2022_10", // TLS 1.2 floor
			"IoTSecurityPolicy_TLS12_1_0_2022_10", // TLS 1.2 (legacy cipher-set vintage, not TLS 1.0)
			"IoTSecurityPolicy_TLS12_1_2_2019_07", // older TLS 1.2 policy
			"IoTSecurityPolicy_TLS12_1_0_2019_07", // older legacy-vintage TLS 1.2 policy
		}
		for _, p := range iotPolicies {
			p := p
			name := p
			if name == "" {
				name = "no_policy_doc_default"
			}
			t.Run(name, func(t *testing.T) {
				client := &fakeIoTCoreClient{
					dcPages: []*iot.ListDomainConfigurationsOutput{{}},
					describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
						"iot:Data-ATS": iotcoreDCPolicy(p),
					},
					thingsOut: &iot.ListThingsOutput{},
				}
				assets, err := IoTCoreScanner{}.scan(context.Background(), client, acct, region)
				validate(t, "iot.SecurityPolicy(curated)", p, assets, err)
			})
		}
	})

	// ------------------------------------------------------------------
	// vpn: the EC2 Site-to-Site VPN tunnel phase1/phase2 encryption,
	// integrity, DH-group, and IKE-version fields are SDK STRUCTS holding a
	// *string Value (Phase1EncryptionAlgorithmsListValue etc.), NOT generated
	// enums — there is no Values() oracle. Cover the AWS-documented value sets
	// as curated slices. Source:
	// https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html
	// If AWS adds an algorithm here, these lists must be extended manually.
	// ------------------------------------------------------------------
	t.Run("vpn/tunnel_algorithms_curated", func(t *testing.T) {
		// Documented Site-to-Site VPN tunnel option values.
		phase1Enc := []string{"AES128", "AES256", "AES128-GCM-16", "AES256-GCM-16"}
		phase2Enc := phase1Enc
		integrity := []string{"SHA1", "SHA2-256", "SHA2-384", "SHA2-512"}
		dhGroups := []int32{2, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		ikeVersions := []string{"ikev1", "ikev2"}

		runVPN := func(t *testing.T, label, value string, tunnel ec2types.TunnelOption) {
			client := &fakeVPNEC2Client{
				out: &ec2.DescribeVpnConnectionsOutput{
					VpnConnections: []ec2types.VpnConnection{{
						VpnConnectionId: vpnStrptr("vpn-" + value),
						Options: &ec2types.VpnConnectionOptions{
							TunnelOptions: []ec2types.TunnelOption{tunnel},
						},
					}},
				},
			}
			assets, err := VPNScanner{}.scan(context.Background(), client, acct, region)
			validate(t, label, value, assets, err)
		}

		t.Run("phase1Enc", func(t *testing.T) {
			for _, e := range phase1Enc {
				e := e
				t.Run(e, func(t *testing.T) {
					runVPN(t, "vpn.phase1Enc(curated)", e, vpnTunnel(e, "AES256-GCM-16", "SHA2-256", "SHA2-256", 20, "ikev2"))
				})
			}
		})
		t.Run("phase2Enc", func(t *testing.T) {
			for _, e := range phase2Enc {
				e := e
				t.Run(e, func(t *testing.T) {
					runVPN(t, "vpn.phase2Enc(curated)", e, vpnTunnel("AES256-GCM-16", e, "SHA2-256", "SHA2-256", 20, "ikev2"))
				})
			}
		})
		t.Run("integrity", func(t *testing.T) {
			for _, i := range integrity {
				i := i
				t.Run(i, func(t *testing.T) {
					runVPN(t, "vpn.integrity(curated)", i, vpnTunnel("AES256-GCM-16", "AES256-GCM-16", i, i, 20, "ikev2"))
				})
			}
		})
		t.Run("dhGroup", func(t *testing.T) {
			for _, g := range dhGroups {
				g := g
				t.Run("group", func(t *testing.T) {
					runVPN(t, "vpn.dhGroup(curated)", "group", vpnTunnel("AES256-GCM-16", "AES256-GCM-16", "SHA2-256", "SHA2-256", g, "ikev2"))
				})
			}
		})
		t.Run("ikeVersion", func(t *testing.T) {
			for _, k := range ikeVersions {
				k := k
				t.Run(k, func(t *testing.T) {
					runVPN(t, "vpn.ikeVersion(curated)", k, vpnTunnel("AES256-GCM-16", "AES256-GCM-16", "SHA2-256", "SHA2-256", 20, k))
				})
			}
		})
	})
}
