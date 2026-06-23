package datarest

// cdx_adversarial_test.go — "Edge #2": drive the REAL scan() core of every seamed
// datarest scanner with HOSTILE / EDGE-CASE SDK responses that real AWS can return
// but the happy-path fakes never exercise, and assert TWO robustness invariants for
// every covered scanner:
//
//	(i)  the scanner NEVER panics (recover-wrapper turns a panic into a test
//	     failure with the triggering scenario + stack), and
//	(ii) whatever assets it returns, output.ValidateAssetsCBOM(assets) is nil —
//	     the emitted CBOM is CycloneDX 1.7 schema-valid EVEN ON GARBAGE INPUT.
//
// A panic OR a schema-validation failure here is a REAL ROBUSTNESS BUG (a
// dereferenced nil pointer; a raw AWS enum string — mode/type/state/status —
// copied into a CBOM enum field without mapping, which a future/unknown enum
// value breaks). The test is intentionally NOT softened: it leaves the failure
// visible so the source can be fixed.
//
// The adversarial shapes fed to each fake (adapted per SDK shape):
//   - nil top-level output / empty resource list,
//   - a resource with ALL pointer fields nil,
//   - a resource with an UNKNOWN enum value AWS could add later ("FUTURE_MODE"),
//   - empty strings where names/ARNs are expected,
//   - an extremely long (10k-char) string in a name/id,
//   - unexpected combos (encryption struct present but all sub-fields empty).
//
// It reuses each scanner's EXISTING fake (same package) — only the canned outputs
// are hostile. Breadth over depth: many scanners, a few sharp cases each.

import (
	"context"
	"strings"
	"testing"

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
	fhtypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	fsxtypes "github.com/aws/aws-sdk-go-v2/service/fsx/types"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"
	"github.com/aws/aws-sdk-go-v2/service/kendra"
	kentypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2"
	kav2types "github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2/types"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/aws/aws-sdk-go-v2/service/memorydb"
	memorydbtypes "github.com/aws/aws-sdk-go-v2/service/memorydb/types"
	mgntypes "github.com/aws/aws-sdk-go-v2/service/mgn/types"
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

// advStr returns a pointer to s (local helper, avoids redeclaration with the
// per-scanner pointer helpers already in the package's other test files).
func advStr(s string) *string { return &s }
func advBool(b bool) *bool    { return &b }

// longStr is a 10k-character hostile name/id/ARN.
var longStr = strings.Repeat("A", 10000)

// futureEnum is an enum value AWS could add in the future that no current
// mapper recognizes — the canonical "unknown enum" adversarial input.
const futureEnum = "FUTURE_MODE_2099"

// runAdversarial drives one scanner core (fn) under a panic guard and asserts
// the two robustness invariants. A panic OR a schema violation is reported as a
// REAL ROBUSTNESS BUG and FAILS the subtest — never softened.
func runAdversarial(t *testing.T, scanner, scenario string, fn func() ([]models.CryptoAsset, error)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ROBUSTNESS BUG [%s/%s]: scanner PANICKED on adversarial input: %v", scanner, scenario, r)
		}
	}()
	assets, err := fn()
	// An error is an acceptable (honest) outcome on hostile input; we only
	// require no-panic and schema-validity of whatever assets ARE returned.
	_ = err
	if len(assets) == 0 {
		return // nothing emitted -> trivially schema-valid, nothing to check
	}
	if verr := output.ValidateAssetsCBOM(assets); verr != nil {
		t.Errorf("ROBUSTNESS BUG [%s/%s]: emitted CBOM FAILED CycloneDX 1.7 schema validation on adversarial input: %v",
			scanner, scenario, verr)
	}
}

// TestDatarestScanners_AdversarialInput is the Edge-#2 robustness net.
func TestDatarestScanners_AdversarialInput(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping adversarial conformance: %v", err)
	}
	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	// ---- dynamodb: unknown SSEType enum + all-nil description ----
	t.Run("dynamodb", func(t *testing.T) {
		runAdversarial(t, "dynamodb", "unknownSSEType+longName", func() ([]models.CryptoAsset, error) {
			c := &fakeDynamoDBClient{
				listPages: []*dynamodb.ListTablesOutput{{TableNames: []string{longStr, ""}}},
				describe: map[string]*dynamodb.DescribeTableOutput{
					longStr: {Table: &ddbtypes.TableDescription{
						SSEDescription: &ddbtypes.SSEDescription{
							SSEType: ddbtypes.SSEType(futureEnum),
							Status:  ddbtypes.SSEStatus(futureEnum),
						},
					}},
					"": {Table: nil}, // all-nil description
				},
			}
			return DynamoDBScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- dax: unknown SSEStatus + all-nil cluster ----
	t.Run("dax", func(t *testing.T) {
		runAdversarial(t, "dax", "unknownStatus+nilCluster", func() ([]models.CryptoAsset, error) {
			c := &fakeDAXClient{
				pages: []*dax.DescribeClustersOutput{{Clusters: []daxtypes.Cluster{
					{ClusterName: advStr(longStr), ClusterArn: advStr(""), SSEDescription: &daxtypes.SSEDescription{Status: daxtypes.SSEStatus(futureEnum)}},
					{}, // all-nil pointer fields
				}}},
			}
			return DAXScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- athena: unknown EncryptionOption + empty workgroup ----
	t.Run("athena", func(t *testing.T) {
		runAdversarial(t, "athena", "unknownEncOption", func() ([]models.CryptoAsset, error) {
			c := &fakeAthenaClient{
				listPages: []*athena.ListWorkGroupsOutput{{WorkGroups: []athenatypes.WorkGroupSummary{{Name: advStr("wg-x")}, {}}}},
				getWorkGroups: map[string]*athena.GetWorkGroupOutput{
					"wg-x": {WorkGroup: &athenatypes.WorkGroup{
						Name: advStr("wg-x"),
						Configuration: &athenatypes.WorkGroupConfiguration{
							ResultConfiguration: &athenatypes.ResultConfiguration{
								EncryptionConfiguration: &athenatypes.EncryptionConfiguration{
									EncryptionOption: athenatypes.EncryptionOption(futureEnum),
									KmsKey:           advStr(""),
								},
							},
						},
					}},
				},
			}
			return AthenaScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- stepfunctions: unknown EncryptionType + nil EncryptionConfiguration ----
	t.Run("stepfunctions", func(t *testing.T) {
		runAdversarial(t, "stepfunctions", "unknownEncType+nilCfg", func() ([]models.CryptoAsset, error) {
			const arn = "arn:aws:states:us-east-1:111122223333:stateMachine:sm-x"
			c := &fakeStepFunctionsClient{
				items: []sfntypes.StateMachineListItem{
					{StateMachineArn: advStr(arn), Name: advStr(longStr), Type: sfntypes.StateMachineType(futureEnum)},
					{StateMachineArn: nil}, // nil ARN -> dropped
				},
				describe: map[string]*sfn.DescribeStateMachineOutput{
					arn: {EncryptionConfiguration: &sfntypes.EncryptionConfiguration{
						Type:     sfntypes.EncryptionType(futureEnum),
						KmsKeyId: advStr(""),
					}},
				},
			}
			return StepFunctionsScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- mgn: unknown EbsEncryption enum + empty key ----
	t.Run("mgn", func(t *testing.T) {
		runAdversarial(t, "mgn", "unknownEbsEnc", func() ([]models.CryptoAsset, error) {
			c := &fakeMGNClient{
				items: []mgntypes.ReplicationConfigurationTemplate{
					{ReplicationConfigurationTemplateID: advStr(longStr), EbsEncryption: mgntypes.ReplicationConfigurationEbsEncryption(futureEnum), EbsEncryptionKeyArn: advStr("")},
					{}, // all-nil
				},
			}
			return MGNScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- managed_flink: unknown KeyType + empty config ----
	t.Run("managed_flink", func(t *testing.T) {
		runAdversarial(t, "managed_flink", "unknownKeyType+emptyDetail", func() ([]models.CryptoAsset, error) {
			c := &fakeManagedFlinkClient{
				summaries: []kav2types.ApplicationSummary{{ApplicationName: advStr("app-x"), ApplicationStatus: kav2types.ApplicationStatus(futureEnum)}, {}},
				describe: map[string]*kinesisanalyticsv2.DescribeApplicationOutput{
					"app-x": {ApplicationDetail: &kav2types.ApplicationDetail{
						ApplicationStatus:  kav2types.ApplicationStatus(futureEnum),
						RuntimeEnvironment: kav2types.RuntimeEnvironment(futureEnum),
						ApplicationConfigurationDescription: &kav2types.ApplicationConfigurationDescription{
							ApplicationEncryptionConfigurationDescription: &kav2types.ApplicationEncryptionConfigurationDescription{
								KeyType: kav2types.KeyType(futureEnum),
								KeyId:   advStr(""),
							},
						},
					}},
				},
			}
			return ManagedFlinkScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- keyspaces: unknown EncryptionType + nil table summary ----
	t.Run("keyspaces", func(t *testing.T) {
		runAdversarial(t, "keyspaces", "unknownEncType", func() ([]models.CryptoAsset, error) {
			c := &fakeKeyspacesClient{
				keyspaces: []kstypes.KeyspaceSummary{{KeyspaceName: advStr("ks-x")}, {}},
				tables: map[string][]kstypes.TableSummary{
					"ks-x": {{TableName: advStr(longStr)}, {}},
				},
				getTable: map[string]*keyspaces.GetTableOutput{
					"ks-x/" + longStr: {EncryptionSpecification: &kstypes.EncryptionSpecification{
						Type:             kstypes.EncryptionType(futureEnum),
						KmsKeyIdentifier: advStr(""),
					}},
				},
			}
			return KeyspacesScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- storagegateway: unknown EncryptionType + nil ARNs ----
	t.Run("storagegateway", func(t *testing.T) {
		runAdversarial(t, "storagegateway", "unknownEncType+nilARN", func() ([]models.CryptoAsset, error) {
			c := &fakeStorageGatewayClient{
				gatewaysPages: []*storagegateway.ListGatewaysOutput{{Gateways: []sgtypes.GatewayInfo{{GatewayARN: advStr("arn:gw:x")}, {}}}},
				fileSharesPages: []*storagegateway.ListFileSharesOutput{{FileShareInfoList: []sgtypes.FileShareInfo{
					{FileShareARN: advStr("arn:nfs:x"), FileShareType: sgtypes.FileShareType(futureEnum)},
					{}, // nil ARN
				}}},
				nfsByARN: map[string]sgtypes.NFSFileShareInfo{
					"arn:nfs:x": {FileShareARN: advStr("arn:nfs:x"), EncryptionType: sgtypes.EncryptionType(futureEnum), KMSKey: advStr("")},
				},
			}
			return StorageGatewayScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- xray: unknown EncryptionType + unknown Status + nil config ----
	t.Run("xray", func(t *testing.T) {
		runAdversarial(t, "xray", "unknownType+nilCfg", func() ([]models.CryptoAsset, error) {
			c := &fakeXRayClient{cfg: &xraytypes.EncryptionConfig{
				Type:   xraytypes.EncryptionType(futureEnum),
				Status: xraytypes.EncryptionStatus(futureEnum),
				KeyId:  advStr(""),
			}}
			return XRayScanner{}.scan(ctx, c, acct, region)
		})
		runAdversarial(t, "xray", "nilConfig", func() ([]models.CryptoAsset, error) {
			return XRayScanner{}.scan(ctx, &fakeXRayClient{cfg: nil}, acct, region)
		})
	})

	// ---- ssm: unknown ParameterType + empty key ----
	t.Run("ssm", func(t *testing.T) {
		runAdversarial(t, "ssm", "unknownParamType", func() ([]models.CryptoAsset, error) {
			c := &fakeSSMClient{
				pages: []*ssm.DescribeParametersOutput{{Parameters: []ssmtypes.ParameterMetadata{
					{Name: advStr(longStr), Type: ssmtypes.ParameterType(futureEnum), KeyId: advStr("")},
					{}, // all-nil
				}}},
			}
			return SSMScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- s3: encryption struct present, all sub-fields empty + unknown algo ----
	t.Run("s3", func(t *testing.T) {
		runAdversarial(t, "s3", "emptyEncRule+unknownAlgo", func() ([]models.CryptoAsset, error) {
			const b = "bkt-x"
			c := &fakeS3Client{
				buckets: []s3types.Bucket{{Name: advStr(b), BucketRegion: advStr(region)}, {}},
				enc: map[string]*s3.GetBucketEncryptionOutput{
					b: {ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
						Rules: []s3types.ServerSideEncryptionRule{
							{}, // empty rule
							{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
								SSEAlgorithm:   s3types.ServerSideEncryption(futureEnum),
								KMSMasterKeyID: advStr(""),
							}},
						},
					}},
				},
			}
			return S3Scanner{}.scan(ctx, c, fakeS3KMS{}, acct, region)
		})
	})

	// ---- firehose: unknown KeyType + empty stream name ----
	t.Run("firehose", func(t *testing.T) {
		runAdversarial(t, "firehose", "unknownKeyType", func() ([]models.CryptoAsset, error) {
			c := &fakeFirehoseClient{
				listPages: []*firehose.ListDeliveryStreamsOutput{{DeliveryStreamNames: []string{"s-x", ""}, HasMoreDeliveryStreams: advBool(false)}},
				describeByName: map[string]*firehose.DescribeDeliveryStreamOutput{
					"s-x": {DeliveryStreamDescription: &fhtypes.DeliveryStreamDescription{
						DeliveryStreamName: advStr(longStr),
						DeliveryStreamARN:  advStr(""),
						DeliveryStreamEncryptionConfiguration: &fhtypes.DeliveryStreamEncryptionConfiguration{
							KeyType: fhtypes.KeyType(futureEnum),
							Status:  fhtypes.DeliveryStreamEncryptionStatus(futureEnum),
						},
					}},
				},
			}
			return FirehoseScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- glue: encryption-at-rest present, unknown mode, empty key ----
	t.Run("glue", func(t *testing.T) {
		runAdversarial(t, "glue", "unknownCatalogMode", func() ([]models.CryptoAsset, error) {
			c := &fakeGlueClient{
				settings: &gluetypes.DataCatalogEncryptionSettings{
					EncryptionAtRest: &gluetypes.EncryptionAtRest{
						CatalogEncryptionMode: gluetypes.CatalogEncryptionMode(futureEnum),
						SseAwsKmsKeyId:        advStr(""),
					},
				},
			}
			return GlueScanner{}.scan(ctx, c, acct, region)
		})
		runAdversarial(t, "glue", "nilSettings", func() ([]models.CryptoAsset, error) {
			return GlueScanner{}.scan(ctx, &fakeGlueClient{settings: nil}, acct, region)
		})
	})

	// ---- ebs: unknown KMS keyspec + all-nil volume ----
	t.Run("ebs", func(t *testing.T) {
		runAdversarial(t, "ebs", "unknownKeySpec+nilVol", func() ([]models.CryptoAsset, error) {
			c := &fakeEBSClient{
				volPages: []*ec2.DescribeVolumesOutput{{Volumes: []ec2types.Volume{
					{VolumeId: advStr(longStr), Encrypted: advBool(true), KmsKeyId: advStr("arn:k:x")},
					{}, // all-nil
				}}},
				keyByID: map[string]string{"arn:k:x": futureEnum},
			}
			return EBSScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- the "list of resources, nil/empty pointer fields" family ----
	t.Run("rds", func(t *testing.T) {
		runAdversarial(t, "rds", "nilFields+longID", func() ([]models.CryptoAsset, error) {
			c := &fakeRDSClient{pages: []*rds.DescribeDBInstancesOutput{{DBInstances: []rdstypes.DBInstance{
				{DBInstanceIdentifier: advStr(longStr)}, {},
			}}}}
			return RDSScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("neptune", func(t *testing.T) {
		runAdversarial(t, "neptune", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeNeptuneClient{pages: []*neptune.DescribeDBClustersOutput{{DBClusters: []neptunetypes.DBCluster{
				{DBClusterIdentifier: advStr("")}, {},
			}}}}
			return NeptuneScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("documentdb", func(t *testing.T) {
		runAdversarial(t, "documentdb", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeDocDBClient{pages: []*docdb.DescribeDBClustersOutput{{DBClusters: []docdbtypes.DBCluster{
				{DBClusterIdentifier: advStr(longStr), StorageEncrypted: advBool(true)}, {},
			}}}}
			return DocumentDBScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("redshift", func(t *testing.T) {
		runAdversarial(t, "redshift", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeRedshiftClient{pages: []*redshift.DescribeClustersOutput{{Clusters: []redshifttypes.Cluster{
				{ClusterIdentifier: advStr("")}, {},
			}}}}
			return RedshiftScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("elasticache", func(t *testing.T) {
		runAdversarial(t, "elasticache", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeElastiCacheClient{pages: []*elasticache.DescribeReplicationGroupsOutput{{ReplicationGroups: []ectypes.ReplicationGroup{
				{ReplicationGroupId: advStr(longStr), AtRestEncryptionEnabled: advBool(true)}, {},
			}}}}
			return ElastiCacheScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("efs", func(t *testing.T) {
		runAdversarial(t, "efs", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeEFSClient{pages: []*efs.DescribeFileSystemsOutput{{FileSystems: []efstypes.FileSystemDescription{
				{FileSystemId: advStr(""), Encrypted: advBool(true)}, {},
			}}}}
			return EFSScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("fsx", func(t *testing.T) {
		runAdversarial(t, "fsx", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeFSxClient{pages: []*fsx.DescribeFileSystemsOutput{{FileSystems: []fsxtypes.FileSystem{
				{FileSystemId: advStr(longStr)}, {},
			}}}}
			return FSxScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("dms", func(t *testing.T) {
		runAdversarial(t, "dms", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeDMSClient{pages: []*databasemigrationservice.DescribeReplicationInstancesOutput{{ReplicationInstances: []dmstypes.ReplicationInstance{
				{ReplicationInstanceIdentifier: advStr("")}, {},
			}}}}
			return DMSScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("memorydb", func(t *testing.T) {
		runAdversarial(t, "memorydb", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeMemoryDBClient{pages: []*memorydb.DescribeClustersOutput{{Clusters: []memorydbtypes.Cluster{
				{Name: advStr(longStr)}, {},
			}}}}
			return MemoryDBScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("timestream", func(t *testing.T) {
		runAdversarial(t, "timestream", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeTimestreamClient{pages: []*timestreamwrite.ListDatabasesOutput{{Databases: []tstypes.Database{
				{DatabaseName: advStr("")}, {},
			}}}}
			return TimestreamScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("cloudwatchlogs", func(t *testing.T) {
		runAdversarial(t, "cloudwatchlogs", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeCWLogsClient{pages: []*cloudwatchlogs.DescribeLogGroupsOutput{{LogGroups: []cwltypes.LogGroup{
				{LogGroupName: advStr(longStr), KmsKeyId: advStr("")}, {},
			}}}}
			return CloudWatchLogsScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("secretsmanager", func(t *testing.T) {
		runAdversarial(t, "secretsmanager", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeSecretsManagerClient{pages: []*secretsmanager.ListSecretsOutput{{SecretList: []secmtypes.SecretListEntry{
				{Name: advStr(""), KmsKeyId: advStr("")}, {},
			}}}}
			return SecretsManagerScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("workspaces", func(t *testing.T) {
		runAdversarial(t, "workspaces", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeWorkSpacesClient{pages: []*workspaces.DescribeWorkspacesOutput{{Workspaces: []workspacestypes.Workspace{
				{WorkspaceId: advStr(longStr), RootVolumeEncryptionEnabled: advBool(true)}, {},
			}}}}
			return WorkSpacesScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("lightsail", func(t *testing.T) {
		runAdversarial(t, "lightsail", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeLightsailClient{pages: []*lightsail.GetInstancesOutput{{Instances: []lightsailtypes.Instance{
				{Name: advStr("")}, {},
			}}}}
			return LightsailScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- list+describe families with nil/empty + long strings ----
	t.Run("backup", func(t *testing.T) {
		runAdversarial(t, "backup", "nilVaultFields", func() ([]models.CryptoAsset, error) {
			c := &fakeBackupClient{
				listPages: []*backup.ListBackupVaultsOutput{{BackupVaultList: []backuptypes.BackupVaultListMember{
					{BackupVaultName: advStr(longStr)}, {},
				}}},
			}
			return BackupScanner{}.scan(ctx, c, &fakeBackupKMS{}, acct, region)
		})
	})
	t.Run("msk", func(t *testing.T) {
		runAdversarial(t, "msk", "nilClusterFields", func() ([]models.CryptoAsset, error) {
			c := &fakeMSKClient{pages: []*kafka.ListClustersV2Output{{ClusterInfoList: []kafkatypes.Cluster{
				{ClusterName: advStr(longStr), ClusterType: kafkatypes.ClusterType(futureEnum)}, {},
			}}}}
			return MSKScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("opensearch", func(t *testing.T) {
		runAdversarial(t, "opensearch", "nilDomain", func() ([]models.CryptoAsset, error) {
			c := &fakeOpenSearchClient{
				listOut: &opensearch.ListDomainNamesOutput{DomainNames: []osttypes.DomainInfo{{DomainName: advStr("d-x")}, {}}},
				describeByName: map[string]*opensearch.DescribeDomainOutput{
					"d-x": {DomainStatus: nil}, // nil status
				},
			}
			return OpenSearchScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("opensearchserverless", func(t *testing.T) {
		runAdversarial(t, "opensearchserverless", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeOSSClient{listPages: []*opensearchserverless.ListCollectionsOutput{{CollectionSummaries: []osstypes.CollectionSummary{
				{Name: advStr(longStr), Arn: advStr("")}, {},
			}}}}
			return OpenSearchServerlessScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("redshiftserverless", func(t *testing.T) {
		// FINDING (left failing intentionally): two namespaces on the SAME page that
		// both resolve to an empty resource id (nil/empty NamespaceArn AND empty
		// NamespaceName) produce two BYTE-IDENTICAL CBOM components — same empty-ARN
		// BomRef, same props — which violates CycloneDX 1.7 components/uniqueItems.
		// Root cause: redshiftserverless.go:64-80 derives id="" from empty fields and
		// always appends an asset, and internal/output/cyclonedx.go buildCBOM
		// (~line 96-170) appends one component per asset WITHOUT deduplicating by
		// bom-ref. This is a systemic gap shared by every simple list-scanner whenever
		// two list entries collapse to the same id (e.g. a degraded/partial AWS List
		// response, or duplicate entries across paginated boundaries). The CBOM
		// builder must dedup components by bom-ref (or scanners must skip empty-id
		// resources). See the parent-agent report.
		runAdversarial(t, "redshiftserverless", "twoEmptyIdNamespaces_uniqueItems", func() ([]models.CryptoAsset, error) {
			c := &fakeRedshiftServerlessClient{nsPages: []*redshiftserverless.ListNamespacesOutput{{Namespaces: []rsstypes.Namespace{
				{NamespaceName: advStr(""), NamespaceArn: advStr("")}, {},
			}}}}
			return RedshiftServerlessScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("sagemaker", func(t *testing.T) {
		runAdversarial(t, "sagemaker", "nilDomainFields", func() ([]models.CryptoAsset, error) {
			c := &fakeSageMakerClient{
				listPages: []*sagemaker.ListDomainsOutput{{Domains: []sagemakertypes.DomainDetails{{DomainId: advStr("d-x")}, {}}}},
				describeByID: map[string]*sagemaker.DescribeDomainOutput{
					"d-x": {KmsKeyId: advStr("")}, // empty key
				},
			}
			return SageMakerScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("eventbridge", func(t *testing.T) {
		runAdversarial(t, "eventbridge", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeEventBridgeClient{
				buses: []ebtypes.EventBus{{Name: advStr(longStr), Arn: advStr("")}, {}},
				describe: map[string]*eventbridge.DescribeEventBusOutput{
					longStr: {KmsKeyIdentifier: advStr("")},
				},
			}
			return EventBridgeScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("kendra", func(t *testing.T) {
		runAdversarial(t, "kendra", "unknownStatus+nilSSE", func() ([]models.CryptoAsset, error) {
			c := &fakeKendraClient{
				summaries: []kentypes.IndexConfigurationSummary{
					{Id: advStr("i-x"), Name: advStr(longStr), Status: kentypes.IndexStatus(futureEnum), Edition: kentypes.IndexEdition(futureEnum)}, {},
				},
				describe: map[string]*kendra.DescribeIndexOutput{
					"i-x": {ServerSideEncryptionConfiguration: nil},
				},
			}
			return KendraScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("qldb", func(t *testing.T) {
		runAdversarial(t, "qldb", "nilEncDesc", func() ([]models.CryptoAsset, error) {
			c := &fakeQLDBClient{
				ledgers: []qldbtypes.LedgerSummary{{Name: advStr(longStr)}, {}},
				describe: map[string]*qldb.DescribeLedgerOutput{
					longStr: {EncryptionDescription: nil},
				},
			}
			return QLDBScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("quicksight", func(t *testing.T) {
		runAdversarial(t, "quicksight", "emptyKeyReg", func() ([]models.CryptoAsset, error) {
			c := &fakeQuickSightClient{out: &quicksight.DescribeKeyRegistrationOutput{
				KeyRegistration: []qstypes.RegisteredCustomerManagedKey{{KeyArn: advStr("")}, {}},
			}}
			return QuickSightScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("workspaces_web", func(t *testing.T) {
		runAdversarial(t, "workspaces_web", "unknownStatus+nilPortal", func() ([]models.CryptoAsset, error) {
			const arn = "arn:aws:workspaces-web:us-east-1:111122223333:portal/p-x"
			c := &fakeWorkSpacesWebClient{
				portals: []wswtypes.PortalSummary{{PortalArn: advStr(arn)}, {}},
				getByARN: map[string]*workspacesweb.GetPortalOutput{
					arn: {Portal: &wswtypes.Portal{PortalArn: advStr(arn), DisplayName: advStr(longStr), PortalStatus: wswtypes.PortalStatus(futureEnum), CustomerManagedKey: advStr("")}},
				},
			}
			return WorkSpacesWebScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("connect_customer_profiles", func(t *testing.T) {
		runAdversarial(t, "connect_customer_profiles", "nilKey", func() ([]models.CryptoAsset, error) {
			c := &fakeCustomerProfilesClient{
				items: []cptypes.ListDomainItem{{DomainName: advStr(longStr)}, {}},
				getByDom: map[string]*customerprofiles.GetDomainOutput{
					longStr: {DefaultEncryptionKey: advStr("")},
				},
			}
			return CustomerProfilesScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("documentdb_elastic", func(t *testing.T) {
		runAdversarial(t, "documentdb_elastic", "nilCluster", func() ([]models.CryptoAsset, error) {
			const arn = "arn:aws:docdb-elastic:us-east-1:111122223333:cluster/c-x"
			c := &fakeDocDBElasticClient{
				clusters: []deltypes.ClusterInList{{ClusterArn: advStr(arn), ClusterName: advStr(longStr)}, {}},
				getByARN: map[string]*docdbelastic.GetClusterOutput{
					arn: {Cluster: nil}, // nil cluster
				},
			}
			return DocumentDBElasticScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("codebuild", func(t *testing.T) {
		runAdversarial(t, "codebuild", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeCodeBuildClient{
				names:    []string{"p-x", ""},
				projects: []cbtypes.Project{{Name: advStr(longStr), Arn: advStr(""), EncryptionKey: advStr("")}, {}},
			}
			return CodeBuildScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("emr", func(t *testing.T) {
		runAdversarial(t, "emr", "garbageJSON", func() ([]models.CryptoAsset, error) {
			c := &fakeEMRClient{
				listPages: []*emr.ListSecurityConfigurationsOutput{{SecurityConfigurations: scSummaries("sc-x")}},
				describeBodies: map[string]string{
					"sc-x": `{"EncryptionConfiguration":{"EnableAtRestEncryption":"not-a-bool"}}`, // malformed JSON shape
				},
			}
			return EMRScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("emrserverless", func(t *testing.T) {
		runAdversarial(t, "emrserverless", "nilFields", func() ([]models.CryptoAsset, error) {
			c := &fakeEMRServerlessClient{pages: []*emrserverless.ListApplicationsOutput{{Applications: []emrsltypes.ApplicationSummary{
				{Arn: advStr(""), Name: advStr(longStr)}, {},
			}}}}
			return EMRServerlessScanner{}.scan(ctx, c, acct, region)
		})
	})
	t.Run("sns", func(t *testing.T) {
		runAdversarial(t, "sns", "emptyAttrs", func() ([]models.CryptoAsset, error) {
			const arn = "arn:aws:sns:us-east-1:111122223333:t-x"
			c := &fakeSNSClient{topics: []string{arn, ""}, attrs: map[string]map[string]string{arn: {}}}
			return SNSScanner{}.scan(ctx, c, acct, region)
		})
	})
}
