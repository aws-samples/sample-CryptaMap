package transit

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigw "github.com/aws/aws-sdk-go-v2/service/apigateway"
	apigwtypes "github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	apigwv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	apigwv2types "github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	amtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	appsynctypes "github.com/aws/aws-sdk-go-v2/service/appsync/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	dctypes "github.com/aws/aws-sdk-go-v2/service/directconnect/types"
	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	dstypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	gatypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	opensearchtypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vltypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestTransitScanners_CBOMSchemaConformance drives the REAL scan() core of every
// transit scanner that has a separable offline seam (plus the pure classify
// helpers) through the official CycloneDX 1.7 schema validator. This is the
// highest-risk package for schema-shape bugs because it is protocol-heavy
// (TLS/SSH/IPsec — cipherSuites, ikev2TransformTypes, protocolProperties.type),
// so each subtest produces >=1 real asset and asserts the emitted CBOM validates.
//
// NO live AWS account is touched: every subtest reuses the package's existing
// hand-rolled fakes / pure helpers. A schema FAILURE here is a REAL output bug.
func TestTransitScanners_CBOMSchemaConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	const acct, region = "111122223333", "us-east-1"

	// validate is the shared assertion: scan must succeed, yield >=1 asset, and
	// its CBOM must pass CycloneDX 1.7 schema validation.
	validate := func(t *testing.T, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(assets) == 0 {
			t.Fatal("expected at least one asset")
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("CBOM failed CycloneDX 1.7 schema validation: %v", verr)
		}
	}

	// ---------------------------------------------------------------------
	// Group 1: scanners with a separable scan() + existing fake.
	// ---------------------------------------------------------------------

	t.Run("alb", func(t *testing.T) {
		client := &fakeALBClient{
			lbPages: []*elbv2.DescribeLoadBalancersOutput{
				{LoadBalancers: []elbv2types.LoadBalancer{albAppLB("alb-1")}},
			},
			listeners: map[string]*elbv2.DescribeListenersOutput{
				"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/alb-1": {
					Listeners: []elbv2types.Listener{{Port: albI32(443), SslPolicy: albStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
				},
			},
		}
		assets, err := ALBScanner{}.scan(context.Background(), client, nil, acct, region)
		validate(t, assets, err)
	})

	t.Run("nlb", func(t *testing.T) {
		client := &fakeNLBClient{
			lbPages: []*elbv2.DescribeLoadBalancersOutput{
				{LoadBalancers: []elbv2types.LoadBalancer{nlbNetLB("nlb-1")}},
			},
			listeners: map[string]*elbv2.DescribeListenersOutput{
				"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-1": {
					Listeners: []elbv2types.Listener{{Port: nlbI32(443), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
				},
			},
		}
		assets, err := NLBScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("classicelb", func(t *testing.T) {
		client := &fakeClassicELBClient{
			classicelbPages: []*elb.DescribeLoadBalancersOutput{
				{
					LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
						{
							LoadBalancerName:     classicelbStrptr("lb-1"),
							ListenerDescriptions: []elbtypes.ListenerDescription{classicelbListener("HTTPS", 443, "", "ELBSecurityPolicy-2016-08")},
						},
					},
				},
			},
		}
		assets, err := ClassicELBScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("apigw_http", func(t *testing.T) {
		client := &fakeAPIGWHTTPClient{
			apisPages: []*apigwv2.GetApisOutput{
				{Items: []apigwv2types.Api{{ApiId: strptr("api-1")}}},
			},
		}
		assets, err := APIGWHTTPScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("apigw_rest", func(t *testing.T) {
		client := &fakeAPIGWRestClient{
			apisPages: []*apigw.GetRestApisOutput{
				{Items: []apigwtypes.RestApi{{Id: apigwrestStrptr("rest-1")}}},
			},
		}
		assets, err := APIGWRestScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("clientvpn", func(t *testing.T) {
		client := &fakeClientVPNEC2Client{
			clientvpnPages: []*ec2.DescribeClientVpnEndpointsOutput{
				{ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{ClientVpnEndpointId: clientvpnStrptr("cvpn-endpoint-1")},
				}},
			},
		}
		assets, err := ClientVPNScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("vpclattice", func(t *testing.T) {
		client := &fakeVPCLatticeClient{
			servicesPages: []*vpclattice.ListServicesOutput{
				{Items: []vltypes.ServiceSummary{{Id: vpclatticeStrptr("svc-1")}}},
			},
			listenersByService: map[string][]*vpclattice.ListListenersOutput{
				"svc-1": {
					{Items: []vltypes.ListenerSummary{
						{Arn: vpclatticeStrptr("arn:l:svc1-listener1"), Protocol: vltypes.ListenerProtocolHttps},
					}},
				},
			},
		}
		assets, err := VPCLatticeScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("appmesh", func(t *testing.T) {
		client := &fakeAppMeshClient{
			meshPages: []*appmesh.ListMeshesOutput{
				{Meshes: []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-1")}}},
			},
			vnPages: []*appmesh.ListVirtualNodesOutput{
				{VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: appmeshStrptr("vn-a")}}},
			},
			describeByNode: map[string]*appmesh.DescribeVirtualNodeOutput{
				"vn-a": appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeStrict}),
			},
		}
		assets, err := AppMeshScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("appsync", func(t *testing.T) {
		client := &fakeAppSyncClient{
			pages: []*appsync.ListGraphqlApisOutput{
				{GraphqlApis: []appsynctypes.GraphqlApi{{ApiId: appsyncStrptr("api-1")}}},
			},
		}
		assets, err := AppSyncScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("aurora_transit", func(t *testing.T) {
		client := &auroratransitFakeRDS{
			clusterPages: []*rds.DescribeDBClustersOutput{
				{
					DBClusters: []rdstypes.DBCluster{{
						DBClusterIdentifier: auroratransitStrptr("aurora-page1"),
						Engine:              auroratransitStrptr("aurora-mysql"),
					}},
				},
			},
		}
		assets, err := AuroraTransitScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("rds_transit", func(t *testing.T) {
		client := &fakeRDSTransitClient{
			instancePages: []*rds.DescribeDBInstancesOutput{
				{DBInstances: []rdstypes.DBInstance{{
					DBInstanceIdentifier: rdstransitStrptr("db-enforced"),
					DBParameterGroups:    []rdstypes.DBParameterGroupStatus{rdstransitParamGroup("pg-enforced")},
				}}},
			},
			paramsByGroup: map[string][]rdstypes.Parameter{
				"pg-enforced": {rdstransitForceSSLParam("1")},
			},
		}
		assets, err := RDSTransitScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("documentdb_transit", func(t *testing.T) {
		client := &fakeDocumentDBTransitClient{
			clusterPages: []*docdb.DescribeDBClustersOutput{{
				DBClusters: []docdbtypes.DBCluster{{
					DBClusterIdentifier:     documentdbtransitStrptr("cluster-default"),
					DBClusterParameterGroup: documentdbtransitStrptr("default.docdb5.0"),
				}},
			}},
		}
		assets, err := DocumentDBTransitScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("neptune_transit", func(t *testing.T) {
		client := &fakeNeptuneTransitClient{
			clustersPages: []*neptune.DescribeDBClustersOutput{
				{DBClusters: []neptunetypes.DBCluster{{DBClusterIdentifier: neptunetransitStrptr("neptune-secured")}}},
			},
			instancesPages: []*neptune.DescribeDBInstancesOutput{
				{
					DBInstances: []neptunetypes.DBInstance{{
						DBClusterIdentifier:     neptunetransitStrptr("neptune-secured"),
						CACertificateIdentifier: neptunetransitStrptr("rds-ca-ecc256-g1"),
					}},
				},
			},
		}
		assets, err := NeptuneTransitScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("elasticache_transit", func(t *testing.T) {
		client := &fakeElasticacheTransitClient{
			groupPages: []*elasticache.DescribeReplicationGroupsOutput{
				{
					ReplicationGroups: []elasticachetypes.ReplicationGroup{
						{
							ReplicationGroupId:       elasticachetransitStrptr("rg-required"),
							TransitEncryptionEnabled: elasticachetransitBoolptr(true),
							TransitEncryptionMode:    elasticachetypes.TransitEncryptionModeRequired,
							Engine:                   elasticachetransitStrptr("redis"),
						},
					},
				},
			},
		}
		assets, err := ElastiCacheTransitScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("redshift_transit", func(t *testing.T) {
		client := &fakeRedshiftTransitClient{
			pages: []*redshift.DescribeClustersOutput{
				{Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("plain-cluster")}}},
			},
		}
		assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("opensearch_transit", func(t *testing.T) {
		client := &fakeOpensearchTransitClient{
			listOut: &opensearch.ListDomainNamesOutput{
				DomainNames: []opensearchtypes.DomainInfo{
					{DomainName: opensearchtransitStrptr("dom")},
				},
			},
			descByName: map[string]*opensearch.DescribeDomainOutput{
				"dom": opensearchtransitDomain("dom", "Policy-Min-TLS-1-2-2019-07", opensearchtransitBoolptr(true), ""),
			},
		}
		assets, err := OpenSearchTransitScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("msk_transit", func(t *testing.T) {
		client := &fakeMSKTransitClient{
			clustersPages: []*kafka.ListClustersV2Output{
				{
					ClusterInfoList: []kafkatypes.Cluster{
						msktransitProvisionedCluster("tls-only", "TLS", msktransitBoolptr(true)),
					},
				},
			},
		}
		assets, err := MSKTransitScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("directconnect", func(t *testing.T) {
		client := &fakeDirectConnectClient{
			out: &directconnect.DescribeConnectionsOutput{
				Connections: []dctypes.Connection{
					{ConnectionId: directconnectStrptr("dxcon-aaa"), EncryptionMode: directconnectStrptr("must_encrypt")},
				},
			},
		}
		assets, err := DirectConnectScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("directoryservice", func(t *testing.T) {
		client := &directoryserviceFakeClient{
			dirPages: []*directoryservice.DescribeDirectoriesOutput{
				{
					DirectoryDescriptions: []dstypes.DirectoryDescription{
						{DirectoryId: directoryserviceStrptr("d-enabled"), Type: dstypes.DirectoryTypeMicrosoftAd},
					},
				},
			},
			ldapsByID: map[string]directoryserviceLDAPSResult{
				"d-enabled": {status: dstypes.LDAPSStatusEnabled, hasRow: true},
			},
		}
		assets, err := DirectoryServiceScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("ecs", func(t *testing.T) {
		const arn = "arn:aws:ecs:us-east-1:111122223333:cluster/prod"
		client := &fakeECSClient{
			ecsPages: []*ecs.ListClustersOutput{
				{ClusterArns: []string{arn}},
			},
		}
		assets, err := ECSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("eks", func(t *testing.T) {
		client := &fakeEKSClient{
			eksListPages: []*eks.ListClustersOutput{
				{Clusters: []string{"prod-cluster"}},
			},
		}
		assets, err := EKSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("lambda", func(t *testing.T) {
		client := &fakeLambdaListClient{
			functionsPages: []*lambda.ListFunctionsOutput{
				{Functions: []lambdatypes.FunctionConfiguration{{FunctionName: lambdaStrptr("fn-honest")}}},
			},
		}
		assets, err := LambdaScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("iotcore", func(t *testing.T) {
		client := &fakeIoTCoreClient{
			dcPages: []*iot.ListDomainConfigurationsOutput{
				{DomainConfigurations: []iottypes.DomainConfigurationSummary{
					{DomainConfigurationName: iotcoreStrptr("dc-keep")},
				}},
			},
			describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
				"dc-keep":      iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
				"iot:Data-ATS": iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
			},
			thingsOut: &iot.ListThingsOutput{},
		}
		assets, err := IoTCoreScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("transferfamily", func(t *testing.T) {
		const policy = "TransferSecurityPolicy-2025-03"
		client := &fakeTransferClient{
			listPages: []*transfer.ListServersOutput{
				{Servers: []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-pq")}}},
			},
			describeServers: map[string]*transfer.DescribeServerOutput{
				"s-pq": transferfamilyServerWithPolicy("s-pq", policy),
			},
			describePolicies: map[string]*transfer.DescribeSecurityPolicyOutput{
				policy: {
					SecurityPolicy: &transfertypes.DescribedSecurityPolicy{
						SecurityPolicyName: transferfamilyStrptr(policy),
						SshKexs:            []string{"mlkem768x25519-sha256", "ecdh-sha2-nistp256"},
						SshCiphers:         []string{"aes256-gcm@openssh.com"},
						SshMacs:            []string{"hmac-sha2-256"},
						Fips:               transferfamilyBoolptr(false),
					},
				},
			},
		}
		assets, err := TransferFamilyScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("cloudfront", func(t *testing.T) {
		// Happy-path distribution with a known TLS-1.2 floor and the default
		// CloudFront cert (no ACM ARN), so no cert resolver call is needed.
		client := &fakeCloudFrontClient{
			pages: []*cloudfront.ListDistributionsOutput{
				{DistributionList: &cftypes.DistributionList{
					Items: []cftypes.DistributionSummary{
						{
							Id: cloudfrontConfStrptr("E1DISTRIBUTION"),
							ViewerCertificate: &cftypes.ViewerCertificate{
								MinimumProtocolVersion: cftypes.MinimumProtocolVersionTLSv122021,
							},
						},
					},
				}},
			},
		}
		assets, err := CloudFrontScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		validate(t, assets, err)
	})

	t.Run("globalaccelerator", func(t *testing.T) {
		const accelARN = "arn:aws:globalaccelerator::111122223333:accelerator/abcd"
		client := &fakeGlobalAcceleratorClient{
			accelPages: []*globalaccelerator.ListAcceleratorsOutput{
				{Accelerators: []gatypes.Accelerator{{AcceleratorArn: gaConfStrptr(accelARN)}}},
			},
			listenersByAccel: map[string]*globalaccelerator.ListListenersOutput{
				accelARN: {Listeners: []gatypes.Listener{
					{ListenerArn: gaConfStrptr(accelARN + "/listener/l1"), Protocol: gatypes.ProtocolTcp},
				}},
			},
		}
		assets, err := GlobalAcceleratorScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	t.Run("vpn", func(t *testing.T) {
		client := &fakeVPNEC2Client{
			out: &ec2.DescribeVpnConnectionsOutput{
				VpnConnections: []ec2types.VpnConnection{
					{
						VpnConnectionId: vpnStrptr("vpn-observed"),
						Options: &ec2types.VpnConnectionOptions{
							TunnelOptions: []ec2types.TunnelOption{
								vpnTunnel("AES256-GCM-16", "AES256-GCM-16", "SHA2-512", "SHA2-512", 21, "ikev2"),
							},
						},
					},
				},
			},
		}
		assets, err := VPNScanner{}.scan(context.Background(), client, acct, region)
		validate(t, assets, err)
	})

	// ---------------------------------------------------------------------
	// Group 2: pure classify helpers wrapped in a full asset. This is the
	// protocol-shape hot path — ikev2TransformTypes, ssh/ipsec/tls
	// cipherSuites (algorithms vs identifiers vs name-only), protocol type
	// enum — where CycloneDX-shape bugs live, independent of any SDK plumbing.
	// ---------------------------------------------------------------------

	wrap := func(props models.CryptoProperties) []models.CryptoAsset {
		a := services.NewAsset("transit-classify", models.CategoryDataInTransit, acct, region, "res-1", "AWS::Test::Resource", props)
		return []models.CryptoAsset{a}
	}

	t.Run("classify_vpn_tunnel_ipsec_ikev2", func(t *testing.T) {
		// Exercises ikev2TransformTypes + ipsec cipherSuites[].algorithms + DH KEX label.
		props := classifyVPNTunnel(
			[]string{"AES256-GCM-16"},
			[]string{"AES256-GCM-16"},
			[]string{"SHA2-256"},
			[]string{"SHA2-512"},
			[]int32{20, 21},
			[]string{"ikev2"},
		)
		validate(t, wrap(props), nil)
	})

	t.Run("classify_transfer_policy_ssh", func(t *testing.T) {
		// Exercises ssh protocol type + ssh-kex/ssh-ciphers/ssh-macs/tls-ciphers
		// cipherSuites[].algorithms + PQCHybrid flag.
		props := classifyTransferPolicy(
			[]string{"mlkem768x25519-sha256", "ecdh-sha2-nistp256"},
			[]string{"aes256-gcm@openssh.com"},
			[]string{"hmac-sha2-256"},
			[]string{"TLS_AES_128_GCM_SHA256"},
		)
		validate(t, wrap(props), nil)
	})

	t.Run("classify_msk_transit_tls", func(t *testing.T) {
		// Exercises tls protocol with a name-only cipherSuite (no algorithms array).
		b := true
		_, _, _, props, _, _ := classifyMSKTransit("TLS", &b)
		validate(t, wrap(props), nil)
	})

	t.Run("classify_ssl_policy_tls_pq", func(t *testing.T) {
		// Exercises tls cipherSuites: name-only (policy label), algorithms
		// (tls-ciphers), AND identifiers (ssl-protocols version labels), plus the
		// PQ-hybrid KeyExchangeGroup path. This is the richest tls protocol block.
		sp := elbv2types.SslPolicy{
			Name:         awsString("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"),
			SslProtocols: []string{"TLSv1.2", "TLSv1.3"},
			Ciphers: []elbv2types.Cipher{
				{Name: awsString("TLS_AES_128_GCM_SHA256"), Priority: awsI32(1)},
				{Name: awsString("ECDHE-RSA-AES128-GCM-SHA256"), Priority: awsI32(2)},
			},
		}
		res := classifySSLPolicy(sp, "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09")
		validate(t, wrap(res.props), nil)
	})
}

func awsString(s string) *string { return &s }
func awsI32(i int32) *int32      { return &i }

func cloudfrontConfStrptr(s string) *string { return &s }
func gaConfStrptr(s string) *string         { return &s }

// fakeCloudFrontClient is a hand-rolled cloudFrontAPI returning canned
// ListDistributions pages page-by-page (each call consumes the next page).
type fakeCloudFrontClient struct {
	pages []*cloudfront.ListDistributionsOutput
	calls int
}

func (f *fakeCloudFrontClient) ListDistributions(ctx context.Context, in *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if f.calls >= len(f.pages) {
		return &cloudfront.ListDistributionsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

// fakeGlobalAcceleratorClient is a hand-rolled globalAcceleratorAPI: it returns
// canned ListAccelerators pages and, per accelerator ARN, a canned
// ListListeners output.
type fakeGlobalAcceleratorClient struct {
	accelPages       []*globalaccelerator.ListAcceleratorsOutput
	accelCalls       int
	listenersByAccel map[string]*globalaccelerator.ListListenersOutput
}

func (f *fakeGlobalAcceleratorClient) ListAccelerators(ctx context.Context, in *globalaccelerator.ListAcceleratorsInput, optFns ...func(*globalaccelerator.Options)) (*globalaccelerator.ListAcceleratorsOutput, error) {
	if f.accelCalls >= len(f.accelPages) {
		return &globalaccelerator.ListAcceleratorsOutput{}, nil
	}
	out := f.accelPages[f.accelCalls]
	f.accelCalls++
	return out, nil
}

func (f *fakeGlobalAcceleratorClient) ListListeners(ctx context.Context, in *globalaccelerator.ListListenersInput, optFns ...func(*globalaccelerator.Options)) (*globalaccelerator.ListListenersOutput, error) {
	if in.AcceleratorArn != nil {
		if out, ok := f.listenersByAccel[*in.AcceleratorArn]; ok {
			return out, nil
		}
	}
	return &globalaccelerator.ListListenersOutput{}, nil
}
