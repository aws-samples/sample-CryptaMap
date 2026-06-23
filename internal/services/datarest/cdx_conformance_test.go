package datarest

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	cptypes "github.com/aws/aws-sdk-go-v2/service/customerprofiles/types"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	docdbtypes "github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/docdbelastic"
	deltypes "github.com/aws/aws-sdk-go-v2/service/docdbelastic/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/emrserverless"
	emrsltypes "github.com/aws/aws-sdk-go-v2/service/emrserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kendra"
	kentypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2"
	kav2types "github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	memorydbtypes "github.com/aws/aws-sdk-go-v2/service/memorydb/types"
	mgntypes "github.com/aws/aws-sdk-go-v2/service/mgn/types"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	mqtypes "github.com/aws/aws-sdk-go-v2/service/mq/types"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	neptunetypes "github.com/aws/aws-sdk-go-v2/service/neptune/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	osttypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/aws/aws-sdk-go-v2/service/opensearchserverless"
	osstypes "github.com/aws/aws-sdk-go-v2/service/opensearchserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/qldb"
	qldbtypes "github.com/aws/aws-sdk-go-v2/service/qldb/types"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	qstypes "github.com/aws/aws-sdk-go-v2/service/quicksight/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	sagemakertypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secmtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/storagegateway"
	sgtypes "github.com/aws/aws-sdk-go-v2/service/storagegateway/types"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"
	tstypes "github.com/aws/aws-sdk-go-v2/service/timestreamwrite/types"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/workspacesweb"
	wswtypes "github.com/aws/aws-sdk-go-v2/service/workspacesweb/types"
	xraytypes "github.com/aws/aws-sdk-go-v2/service/xray/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestDatarestScanners_CBOMSchemaConformance drives the REAL scan() core of every
// datarest scanner that exposes a separable offline seam (a lowercase
// scan(ctx, fakeClient, account, region)) with a representative HAPPY-PATH input
// returning >=1 asset, then validates the emitted CBOM against the vendored
// official CycloneDX 1.7 schema via output.ValidateAssetsCBOM.
//
// This is the offline conformance net: it proves each scanner's actual output —
// not a hand-built approximation — is schema-valid WITHOUT a live AWS account. A
// schema-validation failure here is a REAL output bug (e.g. an invalid enum
// member or wrong object/array shape in the CBOM), not a test defect.
//
// Scanners WITHOUT a separable offline seam are listed in the package-level
// comment at the bottom of this file as "not offline-testable" with reasons.
func TestDatarestScanners_CBOMSchemaConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	const acct, region = "111122223333", "us-east-1"

	// validate runs the scanner output through the CDX 1.7 schema and fails the
	// subtest (NOT silently) on any schema violation — that is the whole point.
	validate := func(t *testing.T, name string, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s scan: %v", name, err)
		}
		if len(assets) == 0 {
			t.Fatalf("%s: expected at least one asset for happy-path conformance", name)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("%s CBOM failed CycloneDX 1.7 schema validation: %v", name, verr)
		}
	}

	t.Run("amazonmq", func(t *testing.T) {
		client := &fakeAmazonMQClient{
			listPages: []*mq.ListBrokersOutput{
				{BrokerSummaries: []mqtypes.BrokerSummary{{BrokerId: mqSP("b-cmk"), BrokerName: mqSP("withcmk")}}},
			},
			describeByID: map[string]*mq.DescribeBrokerOutput{
				"b-cmk": {EngineType: mqtypes.EngineTypeActivemq},
			},
		}
		assets, err := AmazonMQScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "amazonmq", assets, err)
	})

	t.Run("athena", func(t *testing.T) {
		client := &fakeAthenaClient{
			listPages: []*athena.ListWorkGroupsOutput{
				{WorkGroups: wgSummaries("wg-ok")},
			},
			getWorkGroups: map[string]*athena.GetWorkGroupOutput{
				"wg-ok": wgWithEncryption("wg-ok", athenatypes.EncryptionOptionSseKms, "arn:aws:kms:us-east-1:111122223333:key/abc", true),
			},
		}
		assets, err := AthenaScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "athena", assets, err)
	})

	t.Run("backup", func(t *testing.T) {
		client := &fakeBackupClient{
			listPages: []*backup.ListBackupVaultsOutput{
				{BackupVaultList: []backuptypes.BackupVaultListMember{vault("vault-cmk"), vault("vault-default")}},
			},
			describeKeyFor: map[string]string{
				"vault-cmk": "arn:aws:kms:us-east-1:111122223333:key/cmk-1234",
			},
		}
		assets, err := BackupScanner{}.scan(context.Background(), client, &fakeBackupKMS{}, acct, region)
		validate(t, "backup", assets, err)
	})

	t.Run("cloudwatchlogs", func(t *testing.T) {
		client := &fakeCWLogsClient{
			pages: []*cloudwatchlogs.DescribeLogGroupsOutput{
				{LogGroups: []cwltypes.LogGroup{
					{LogGroupName: cwStrptr("/with/cmk"), KmsKeyId: cwStrptr("arn:aws:kms:us-east-1:111122223333:key/abcd-1234")},
					{LogGroupName: cwStrptr("/no/cmk")},
				}},
			},
		}
		assets, err := CloudWatchLogsScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "cloudwatchlogs", assets, err)
	})

	t.Run("dax", func(t *testing.T) {
		client := &fakeDAXClient{
			pages: []*dax.DescribeClustersOutput{
				{Clusters: []daxtypes.Cluster{
					{
						ClusterName:    sp("clu-encrypted"),
						ClusterArn:     sp("arn:aws:dax:us-east-1:111122223333:cache/clu-encrypted"),
						SSEDescription: &daxtypes.SSEDescription{Status: daxtypes.SSEStatusEnabled},
					},
				}},
			},
		}
		assets, err := DAXScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "dax", assets, err)
	})

	t.Run("dms", func(t *testing.T) {
		client := &fakeDMSClient{
			pages: []*databasemigrationservice.DescribeReplicationInstancesOutput{
				{ReplicationInstances: []dmstypes.ReplicationInstance{
					{ReplicationInstanceIdentifier: dmsStrptr("ri-1"), KmsKeyId: dmsStrptr("arn:aws:kms:us-east-1:111122223333:key/abcd-1234-ef56")},
				}},
			},
		}
		assets, err := DMSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "dms", assets, err)
	})

	t.Run("documentdb", func(t *testing.T) {
		client := &fakeDocDBClient{
			pages: []*docdb.DescribeDBClustersOutput{
				{DBClusters: []docdbtypes.DBCluster{
					{DBClusterIdentifier: docdbStr("encrypted-cmk"), StorageEncrypted: docdbBool(true), KmsKeyId: docdbStr("arn:aws:kms:us-east-1:111122223333:key/abcd-1234")},
				}},
			},
		}
		assets, err := DocumentDBScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "documentdb", assets, err)
	})

	t.Run("dynamodb", func(t *testing.T) {
		client := &fakeDynamoDBClient{
			listPages: []*dynamodb.ListTablesOutput{
				{TableNames: []string{"with-cmk"}},
			},
			describe: map[string]*dynamodb.DescribeTableOutput{
				"with-cmk": {Table: &ddbtypes.TableDescription{
					SSEDescription: &ddbtypes.SSEDescription{
						KMSMasterKeyArn: ddbStrptr("arn:aws:kms:us-east-1:111122223333:key/abcd-cmk"),
						SSEType:         ddbtypes.SSETypeKms,
						Status:          ddbtypes.SSEStatusEnabled,
					},
				}},
			},
		}
		assets, err := DynamoDBScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "dynamodb", assets, err)
	})

	t.Run("ebs", func(t *testing.T) {
		client := &fakeEBSClient{
			volPages: []*ec2.DescribeVolumesOutput{
				{Volumes: []ec2types.Volume{{
					VolumeId:  strptr("vol-enc"),
					Encrypted: boolptr(true),
					KmsKeyId:  strptr("arn:aws:kms:us-east-1:111122223333:key/abc"),
				}}},
			},
			keyByID: map[string]string{
				"arn:aws:kms:us-east-1:111122223333:key/abc": "SYMMETRIC_DEFAULT",
			},
		}
		assets, err := EBSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "ebs", assets, err)
	})

	t.Run("efs", func(t *testing.T) {
		client := &fakeEFSClient{
			pages: []*efs.DescribeFileSystemsOutput{
				{FileSystems: []efstypes.FileSystemDescription{
					{FileSystemId: sptr("fs-cmk"), Encrypted: bptr(true), KmsKeyId: sptr("arn:aws:kms:us-east-1:111122223333:key/abcd-1234")},
				}},
			},
		}
		assets, err := EFSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "efs", assets, err)
	})

	t.Run("elasticache", func(t *testing.T) {
		client := &fakeElastiCacheClient{
			pages: []*elasticache.DescribeReplicationGroupsOutput{
				{ReplicationGroups: []ectypes.ReplicationGroup{
					{ReplicationGroupId: ecStr("rg-cmk"), AtRestEncryptionEnabled: ecBool(true), KmsKeyId: ecStr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
				}},
			},
		}
		assets, err := ElastiCacheScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "elasticache", assets, err)
	})

	t.Run("emr", func(t *testing.T) {
		client := &fakeEMRClient{
			listPages: []*emr.ListSecurityConfigurationsOutput{
				{SecurityConfigurations: scSummaries("sc-ok")},
			},
			describeBodies: map[string]string{
				"sc-ok": `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":false}}`,
			},
		}
		assets, err := EMRScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "emr", assets, err)
	})

	t.Run("emrserverless", func(t *testing.T) {
		client := &fakeEMRServerlessClient{
			pages: []*emrserverless.ListApplicationsOutput{
				{Applications: []emrsltypes.ApplicationSummary{
					{Arn: emrsp("arn:aws:emr-serverless:us-east-1:111122223333:/applications/app-1"), Name: emrsp("analytics")},
				}},
			},
		}
		assets, err := EMRServerlessScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "emrserverless", assets, err)
	})

	t.Run("firehose", func(t *testing.T) {
		client := &fakeFirehoseClient{
			listPages: []*firehose.ListDeliveryStreamsOutput{
				{
					DeliveryStreamNames:    []string{"stream-enabled"},
					HasMoreDeliveryStreams: awssdk.Bool(false),
				},
			},
			describeByName: map[string]*firehose.DescribeDeliveryStreamOutput{
				"stream-enabled": enabledDescribe("stream-enabled", "CUSTOMER_MANAGED_CMK", "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"),
			},
		}
		assets, err := FirehoseScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "firehose", assets, err)
	})

	t.Run("fsx", func(t *testing.T) {
		client := &fakeFSxClient{
			pages: []*fsx.DescribeFileSystemsOutput{
				{FileSystems: []fsxtypes.FileSystem{
					{FileSystemId: fsxStrptr("fs-cmk"), KmsKeyId: fsxStrptr("arn:aws:kms:us-east-1:111122223333:key/abc")},
				}},
			},
		}
		assets, err := FSxScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "fsx", assets, err)
	})

	t.Run("glue", func(t *testing.T) {
		client := &fakeGlueClient{
			settings: &gluetypes.DataCatalogEncryptionSettings{
				EncryptionAtRest: &gluetypes.EncryptionAtRest{
					CatalogEncryptionMode: gluetypes.CatalogEncryptionModeSsekms,
					SseAwsKmsKeyId:        strptr("arn:aws:kms:us-east-1:111122223333:key/abc-123"),
				},
			},
		}
		assets, err := GlueScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "glue", assets, err)
	})

	t.Run("kinesis", func(t *testing.T) {
		client := &fakeKinesisClient{
			listPages: []*kinesis.ListStreamsOutput{
				{StreamNames: []string{"stream-kms"}, HasMoreStreams: kinBptr(false)},
			},
			summaries: map[string]*kinesis.DescribeStreamSummaryOutput{
				"stream-kms": kmsSummary(),
			},
		}
		assets, err := KinesisScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "kinesis", assets, err)
	})

	t.Run("lightsail", func(t *testing.T) {
		client := &fakeLightsailClient{
			pages: []*lightsail.GetInstancesOutput{
				{Instances: []lightsailtypes.Instance{{Name: lsStrptr("inst-1")}}},
			},
		}
		assets, err := LightsailScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "lightsail", assets, err)
	})

	t.Run("memorydb", func(t *testing.T) {
		client := &fakeMemoryDBClient{
			pages: []*memorydb.DescribeClustersOutput{
				{Clusters: []memorydbtypes.Cluster{
					{Name: memdbStrptr("cluster-cmk"), KmsKeyId: memdbStrptr("arn:aws:kms:us-east-1:111122223333:key/abcd-cmk")},
				}},
			},
		}
		assets, err := MemoryDBScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "memorydb", assets, err)
	})

	t.Run("msk", func(t *testing.T) {
		client := &fakeMSKClient{
			pages: []*kafka.ListClustersV2Output{
				{ClusterInfoList: []kafkatypes.Cluster{
					mskProvisionedCluster("with-cmk", "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"),
				}},
			},
		}
		assets, err := MSKScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "msk", assets, err)
	})

	t.Run("neptune", func(t *testing.T) {
		client := &fakeNeptuneClient{
			pages: []*neptune.DescribeDBClustersOutput{
				{DBClusters: []neptunetypes.DBCluster{
					{DBClusterIdentifier: neptuneStr("encrypted-cmk"), StorageEncrypted: neptuneBool(true), KmsKeyId: neptuneStr("arn:aws:kms:us-east-1:111122223333:key/abcd-1234")},
				}},
			},
		}
		assets, err := NeptuneScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "neptune", assets, err)
	})

	t.Run("opensearch", func(t *testing.T) {
		client := &fakeOpenSearchClient{
			listOut: &opensearch.ListDomainNamesOutput{
				DomainNames: []osttypes.DomainInfo{
					{DomainName: osStrptr("encrypted")},
				},
			},
			describeByName: map[string]*opensearch.DescribeDomainOutput{
				"encrypted": encDomainOut("encrypted", "arn:aws:kms:us-east-1:111122223333:key/abc"),
			},
		}
		assets, err := OpenSearchScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "opensearch", assets, err)
	})

	t.Run("opensearchserverless", func(t *testing.T) {
		client := &fakeOSSClient{
			listPages: []*opensearchserverless.ListCollectionsOutput{
				{CollectionSummaries: []osstypes.CollectionSummary{
					{Name: ossStrptr("coll-1"), Arn: ossStrptr("arn:aws:aoss:us-east-1:111122223333:collection/c1")},
				}},
			},
		}
		assets, err := OpenSearchServerlessScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "opensearchserverless", assets, err)
	})

	t.Run("rds", func(t *testing.T) {
		client := &fakeRDSClient{
			pages: []*rds.DescribeDBInstancesOutput{
				{DBInstances: []rdstypes.DBInstance{
					{DBInstanceIdentifier: rdsStrptr("db-1"), StorageEncrypted: rdsBoolptr(true), KmsKeyId: rdsStrptr("arn:aws:kms:us-east-1:111122223333:key/abc")},
				}},
			},
		}
		assets, err := RDSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "rds", assets, err)
	})

	t.Run("redshift", func(t *testing.T) {
		client := &fakeRedshiftClient{
			pages: []*redshift.DescribeClustersOutput{
				{Clusters: []redshifttypes.Cluster{
					{ClusterIdentifier: rsStr("cluster-1"), Encrypted: rsBool(true), KmsKeyId: rsStr("arn:aws:kms:us-east-1:111122223333:key/abc")},
				}},
			},
		}
		assets, err := RedshiftScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "redshift", assets, err)
	})

	t.Run("redshiftserverless", func(t *testing.T) {
		client := &fakeRedshiftServerlessClient{
			nsPages: []*redshiftserverless.ListNamespacesOutput{
				{Namespaces: []rsstypes.Namespace{
					{NamespaceName: strptr("ns-1"), NamespaceArn: strptr("arn:aws:redshift-serverless:us-east-1:111122223333:namespace/ns-1")},
				}},
			},
		}
		assets, err := RedshiftServerlessScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "redshiftserverless", assets, err)
	})

	t.Run("sagemaker", func(t *testing.T) {
		cmkARN := "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456"
		client := &fakeSageMakerClient{
			listPages: []*sagemaker.ListDomainsOutput{
				{Domains: []sagemakertypes.DomainDetails{{DomainId: smSP("d-1")}}},
			},
			describeByID: map[string]*sagemaker.DescribeDomainOutput{
				"d-1": {KmsKeyId: &cmkARN},
			},
		}
		assets, err := SageMakerScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "sagemaker", assets, err)
	})

	t.Run("secretsmanager", func(t *testing.T) {
		client := &fakeSecretsManagerClient{
			pages: []*secretsmanager.ListSecretsOutput{
				{SecretList: []secmtypes.SecretListEntry{
					{Name: smstrptr("cmk-secret"), KmsKeyId: smstrptr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
				}},
			},
		}
		assets, err := SecretsManagerScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "secretsmanager", assets, err)
	})

	t.Run("sqs", func(t *testing.T) {
		const q1 = "https://sqs.us-east-1.amazonaws.com/111122223333/queue-1"
		client := &fakeSQSClient{
			listPages: []*sqs.ListQueuesOutput{
				{QueueUrls: []string{q1}},
			},
			attrsByURL: map[string]map[string]string{
				q1: {"KmsMasterKeyId": "arn:aws:kms:us-east-1:111122223333:key/abc-123"},
			},
		}
		assets, err := SQSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "sqs", assets, err)
	})

	t.Run("ssm", func(t *testing.T) {
		client := &fakeSSMClient{
			pages: []*ssm.DescribeParametersOutput{
				{Parameters: []ssmtypes.ParameterMetadata{
					{Name: ssmstrptr("secure-cmk"), Type: ssmtypes.ParameterTypeSecureString, KeyId: ssmstrptr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
				}},
			},
		}
		assets, err := SSMScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "ssm", assets, err)
	})

	t.Run("storagegateway", func(t *testing.T) {
		client := &fakeStorageGatewayClient{
			gatewaysPages: []*storagegateway.ListGatewaysOutput{
				{Gateways: []sgtypes.GatewayInfo{{GatewayARN: sgPtr("arn:gw:1")}}},
			},
			fileSharesPages: []*storagegateway.ListFileSharesOutput{
				{FileShareInfoList: []sgtypes.FileShareInfo{
					{FileShareARN: sgPtr("arn:nfs:cmk"), FileShareType: sgtypes.FileShareTypeNfs},
				}},
			},
			nfsByARN: map[string]sgtypes.NFSFileShareInfo{
				"arn:nfs:cmk": {FileShareARN: sgPtr("arn:nfs:cmk"), EncryptionType: sgtypes.EncryptionTypeSseKms, KMSKey: sgPtr("arn:aws:kms:us-east-1:111122223333:key/cmk-1")},
			},
		}
		assets, err := StorageGatewayScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "storagegateway", assets, err)
	})

	t.Run("timestream", func(t *testing.T) {
		client := &fakeTimestreamClient{
			pages: []*timestreamwrite.ListDatabasesOutput{
				{Databases: []tstypes.Database{
					{DatabaseName: tsstr("db-cmk"), KmsKeyId: tsstr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
				}},
			},
		}
		assets, err := TimestreamScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "timestream", assets, err)
	})

	t.Run("workspaces", func(t *testing.T) {
		client := &fakeWorkSpacesClient{
			pages: []*workspaces.DescribeWorkspacesOutput{
				{Workspaces: []workspacestypes.Workspace{
					{
						WorkspaceId:                 wsStrptr("ws-1"),
						RootVolumeEncryptionEnabled: wsBoolptr(true),
						UserVolumeEncryptionEnabled: wsBoolptr(false),
						VolumeEncryptionKey:         wsStrptr("arn:aws:kms:us-east-1:111122223333:key/abc"),
					},
				}},
			},
		}
		assets, err := WorkSpacesScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "workspaces", assets, err)
	})

	// ---------------------------------------------------------------------
	// Newly-seamed scanners (added with the offline scan() refactor). Each
	// drives the REAL scan() core via a hand-rolled fake returning a
	// representative happy-path response, then validates the emitted CBOM.
	// ---------------------------------------------------------------------

	t.Run("s3", func(t *testing.T) {
		const b = "my-bucket"
		client := &fakeS3Client{
			buckets: []s3types.Bucket{{Name: cseStr(b), BucketRegion: cseStr(region)}},
			enc: map[string]*s3.GetBucketEncryptionOutput{
				b: {ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
					Rules: []s3types.ServerSideEncryptionRule{{
						ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
							SSEAlgorithm:   s3types.ServerSideEncryptionAwsKms,
							KMSMasterKeyID: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
						},
						BucketKeyEnabled: cseBool(true),
					}},
				}},
			},
		}
		assets, err := S3Scanner{}.scan(context.Background(), client, fakeS3KMS{}, acct, region)
		validate(t, "s3", assets, err)
	})

	t.Run("sns", func(t *testing.T) {
		const arn = "arn:aws:sns:us-east-1:111122223333:my-topic"
		client := &fakeSNSClient{
			topics: []string{arn},
			attrs: map[string]map[string]string{
				arn: {"KmsMasterKeyId": "arn:aws:kms:us-east-1:111122223333:key/abc"},
			},
		}
		assets, err := SNSScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "sns", assets, err)
	})

	t.Run("xray", func(t *testing.T) {
		client := &fakeXRayClient{cfg: &xraytypes.EncryptionConfig{
			Type:   xraytypes.EncryptionTypeKms,
			KeyId:  cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
			Status: xraytypes.EncryptionStatusActive,
		}}
		assets, err := XRayScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "xray", assets, err)
	})

	t.Run("codebuild", func(t *testing.T) {
		client := &fakeCodeBuildClient{
			names: []string{"proj-1"},
			projects: []cbtypes.Project{{
				Name:          cseStr("proj-1"),
				Arn:           cseStr("arn:aws:codebuild:us-east-1:111122223333:project/proj-1"),
				EncryptionKey: cseStr("arn:aws:kms:us-east-1:111122223333:key/cmk-1"),
			}},
		}
		assets, err := CodeBuildScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "codebuild", assets, err)
	})

	t.Run("eventbridge", func(t *testing.T) {
		client := &fakeEventBridgeClient{
			buses: []ebtypes.EventBus{{Name: cseStr("default"), Arn: cseStr("arn:aws:events:us-east-1:111122223333:event-bus/default")}},
			describe: map[string]*eventbridge.DescribeEventBusOutput{
				"default": {KmsKeyIdentifier: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc")},
			},
		}
		assets, err := EventBridgeScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "eventbridge", assets, err)
	})

	t.Run("kendra", func(t *testing.T) {
		client := &fakeKendraClient{
			summaries: []kentypes.IndexConfigurationSummary{{Id: cseStr("idx-1"), Name: cseStr("idx"), Status: kentypes.IndexStatusActive, Edition: kentypes.IndexEditionEnterpriseEdition}},
			describe: map[string]*kendra.DescribeIndexOutput{
				"idx-1": {ServerSideEncryptionConfiguration: &kentypes.ServerSideEncryptionConfiguration{KmsKeyId: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc")}},
			},
		}
		assets, err := KendraScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "kendra", assets, err)
	})

	t.Run("keyspaces", func(t *testing.T) {
		client := &fakeKeyspacesClient{
			keyspaces: []kstypes.KeyspaceSummary{{KeyspaceName: cseStr("myks")}},
			tables: map[string][]kstypes.TableSummary{
				"myks": {{TableName: cseStr("mytable")}},
			},
			getTable: map[string]*keyspaces.GetTableOutput{
				"myks/mytable": {EncryptionSpecification: &kstypes.EncryptionSpecification{
					Type:             kstypes.EncryptionTypeCustomerManagedKmsKey,
					KmsKeyIdentifier: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
				}},
			},
		}
		assets, err := KeyspacesScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "keyspaces", assets, err)
	})

	t.Run("managed_flink", func(t *testing.T) {
		client := &fakeManagedFlinkClient{
			summaries: []kav2types.ApplicationSummary{{ApplicationName: cseStr("app-1"), ApplicationStatus: kav2types.ApplicationStatusRunning}},
			describe: map[string]*kinesisanalyticsv2.DescribeApplicationOutput{
				"app-1": {ApplicationDetail: &kav2types.ApplicationDetail{
					ApplicationStatus:  kav2types.ApplicationStatusRunning,
					RuntimeEnvironment: kav2types.RuntimeEnvironmentFlink118,
					ApplicationConfigurationDescription: &kav2types.ApplicationConfigurationDescription{
						ApplicationEncryptionConfigurationDescription: &kav2types.ApplicationEncryptionConfigurationDescription{
							KeyType: kav2types.KeyTypeCustomerManagedKey,
							KeyId:   cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
						},
					},
				}},
			},
		}
		assets, err := ManagedFlinkScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "managed_flink", assets, err)
	})

	t.Run("qldb", func(t *testing.T) {
		client := &fakeQLDBClient{
			ledgers: []qldbtypes.LedgerSummary{{Name: cseStr("ledger-1")}},
			describe: map[string]*qldb.DescribeLedgerOutput{
				"ledger-1": {EncryptionDescription: &qldbtypes.LedgerEncryptionDescription{KmsKeyArn: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc")}},
			},
		}
		assets, err := QLDBScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "qldb", assets, err)
	})

	t.Run("quicksight", func(t *testing.T) {
		client := &fakeQuickSightClient{out: &quicksight.DescribeKeyRegistrationOutput{
			KeyRegistration: []qstypes.RegisteredCustomerManagedKey{
				{KeyArn: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"), DefaultKey: true},
			},
		}}
		assets, err := QuickSightScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "quicksight", assets, err)
	})

	t.Run("stepfunctions", func(t *testing.T) {
		const arn = "arn:aws:states:us-east-1:111122223333:stateMachine:sm-1"
		client := &fakeStepFunctionsClient{
			items: []sfntypes.StateMachineListItem{{StateMachineArn: cseStr(arn), Name: cseStr("sm-1"), Type: sfntypes.StateMachineTypeStandard}},
			describe: map[string]*sfn.DescribeStateMachineOutput{
				arn: {EncryptionConfiguration: &sfntypes.EncryptionConfiguration{
					Type:     sfntypes.EncryptionTypeCustomerManagedKmsKey,
					KmsKeyId: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
				}},
			},
		}
		assets, err := StepFunctionsScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "stepfunctions", assets, err)
	})

	t.Run("workspaces_web", func(t *testing.T) {
		const arn = "arn:aws:workspaces-web:us-east-1:111122223333:portal/p-1"
		client := &fakeWorkSpacesWebClient{
			portals: []wswtypes.PortalSummary{{PortalArn: cseStr(arn)}},
			getByARN: map[string]*workspacesweb.GetPortalOutput{
				arn: {Portal: &wswtypes.Portal{
					PortalArn:          cseStr(arn),
					DisplayName:        cseStr("portal"),
					PortalStatus:       wswtypes.PortalStatusActive,
					CustomerManagedKey: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
				}},
			},
		}
		assets, err := WorkSpacesWebScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "workspaces_web", assets, err)
	})

	t.Run("connect_customer_profiles", func(t *testing.T) {
		client := &fakeCustomerProfilesClient{
			items: []cptypes.ListDomainItem{{DomainName: cseStr("dom-1")}},
			getByDom: map[string]*customerprofiles.GetDomainOutput{
				"dom-1": {DefaultEncryptionKey: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc")},
			},
		}
		assets, err := CustomerProfilesScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "connect_customer_profiles", assets, err)
	})

	t.Run("documentdb_elastic", func(t *testing.T) {
		const arn = "arn:aws:docdb-elastic:us-east-1:111122223333:cluster/c-1"
		client := &fakeDocDBElasticClient{
			clusters: []deltypes.ClusterInList{{ClusterArn: cseStr(arn), ClusterName: cseStr("c-1")}},
			getByARN: map[string]*docdbelastic.GetClusterOutput{
				arn: {Cluster: &deltypes.Cluster{KmsKeyId: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc")}},
			},
		}
		assets, err := DocumentDBElasticScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "documentdb_elastic", assets, err)
	})

	t.Run("mgn", func(t *testing.T) {
		client := &fakeMGNClient{
			items: []mgntypes.ReplicationConfigurationTemplate{{
				ReplicationConfigurationTemplateID: cseStr("rct-1"),
				EbsEncryption:                      mgntypes.ReplicationConfigurationEbsEncryptionCustom,
				EbsEncryptionKeyArn:                cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
			}},
		}
		assets, err := MGNScanner{}.scan(context.Background(), client, acct, region)
		validate(t, "mgn", assets, err)
	})
}

// cseStr / cseBool are local pointer helpers for the newly-seamed conformance
// subtests (cse = conformance seam), kept distinct from the older sptr/strptr
// helpers to avoid any redeclaration across the package's test files.
func cseStr(s string) *string { return &s }
func cseBool(b bool) *bool    { return &b }

// Scanners in internal/services/datarest that are NOT covered by the offline
// CBOM-conformance net above, and why:
//
//   - bedrock : no single-interface scan() seam — Scan() fans out to per-feature
//               helpers (scanCustomModels/scanAgents/scanKnowledgeBases/
//               scanGuardrails) that each take the CONCRETE *bedrock.Client and
//               *bedrockagent.Client (two different clients, four List/Get method
//               sets), not one fakeable interface. Seaming it would require either
//               a 8+-method combined interface or per-family seams — a larger
//               change than a pure shim — so it is intentionally left for a
//               dedicated follow-up. Its PURE classification core
//               (classifyBedrockKeyTier / newBedrockAsset) is already unit-tested
//               in bedrock_test.go, and every family emits the same AESAtRest()
//               algorithm-asset shape the other 15 datarest conformance subtests
//               prove schema-valid.
//
// All other datarest scanners now expose a lowercase scan(ctx, fakeClient,
// account, region) seam and ARE covered above (codebuild, connect_customer_profiles,
// documentdb_elastic, eventbridge, kendra, keyspaces, managed_flink, mgn, qldb,
// quicksight, s3, sns, stepfunctions, workspaces_web, xray).
