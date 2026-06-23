package datarest

// Hand-rolled fake clients for the newly-seamed datarest scanners, used by the
// CBOM-schema-conformance subtests in cdx_conformance_test.go. Each fake returns a
// single representative HAPPY-PATH page so the scanner's real scan() core emits >=1
// asset, whose CBOM is then validated against the vendored CycloneDX 1.7 schema.
//
// These fakes implement the unexported xxxAPI interfaces declared next to each
// scanner; the concrete *svc.Client also satisfies them in production.

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/customerprofiles"
	cptypes "github.com/aws/aws-sdk-go-v2/service/customerprofiles/types"
	"github.com/aws/aws-sdk-go-v2/service/docdbelastic"
	deltypes "github.com/aws/aws-sdk-go-v2/service/docdbelastic/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kendra"
	kentypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2"
	kav2types "github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/mgn"
	mgntypes "github.com/aws/aws-sdk-go-v2/service/mgn/types"
	"github.com/aws/aws-sdk-go-v2/service/qldb"
	qldbtypes "github.com/aws/aws-sdk-go-v2/service/qldb/types"
	"github.com/aws/aws-sdk-go-v2/service/quicksight"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/workspacesweb"
	wswtypes "github.com/aws/aws-sdk-go-v2/service/workspacesweb/types"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	xraytypes "github.com/aws/aws-sdk-go-v2/service/xray/types"
)

// --- s3 ---

type fakeS3Client struct {
	buckets []s3types.Bucket
	enc     map[string]*s3.GetBucketEncryptionOutput
}

func (f *fakeS3Client) ListBuckets(ctx context.Context, in *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeS3Client) GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, _ ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if in.Bucket != nil {
		if out, ok := f.enc[*in.Bucket]; ok {
			return out, nil
		}
	}
	return &s3.GetBucketEncryptionOutput{}, nil
}

type fakeS3KMS struct{}

func (fakeS3KMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeySpec: kmstypes.KeySpecSymmetricDefault}}, nil
}

// --- sns ---

type fakeSNSClient struct {
	topics []string // ARNs
	attrs  map[string]map[string]string
}

func (f *fakeSNSClient) ListTopics(ctx context.Context, in *sns.ListTopicsInput, _ ...func(*sns.Options)) (*sns.ListTopicsOutput, error) {
	out := &sns.ListTopicsOutput{}
	for i := range f.topics {
		arn := f.topics[i]
		out.Topics = append(out.Topics, snstypes.Topic{TopicArn: &arn})
	}
	return out, nil
}

func (f *fakeSNSClient) GetTopicAttributes(ctx context.Context, in *sns.GetTopicAttributesInput, _ ...func(*sns.Options)) (*sns.GetTopicAttributesOutput, error) {
	if in.TopicArn != nil {
		if a, ok := f.attrs[*in.TopicArn]; ok {
			return &sns.GetTopicAttributesOutput{Attributes: a}, nil
		}
	}
	return &sns.GetTopicAttributesOutput{}, nil
}

// --- xray ---

type fakeXRayClient struct {
	cfg *xraytypes.EncryptionConfig
}

func (f *fakeXRayClient) GetEncryptionConfig(ctx context.Context, in *xray.GetEncryptionConfigInput, _ ...func(*xray.Options)) (*xray.GetEncryptionConfigOutput, error) {
	return &xray.GetEncryptionConfigOutput{EncryptionConfig: f.cfg}, nil
}

// --- codebuild ---

type fakeCodeBuildClient struct {
	names    []string
	projects []cbtypes.Project
}

func (f *fakeCodeBuildClient) ListProjects(ctx context.Context, in *codebuild.ListProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	return &codebuild.ListProjectsOutput{Projects: f.names}, nil
}

func (f *fakeCodeBuildClient) BatchGetProjects(ctx context.Context, in *codebuild.BatchGetProjectsInput, _ ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	return &codebuild.BatchGetProjectsOutput{Projects: f.projects}, nil
}

// --- eventbridge ---

type fakeEventBridgeClient struct {
	buses    []ebtypes.EventBus
	describe map[string]*eventbridge.DescribeEventBusOutput
}

func (f *fakeEventBridgeClient) ListEventBuses(ctx context.Context, in *eventbridge.ListEventBusesInput, _ ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
	return &eventbridge.ListEventBusesOutput{EventBuses: f.buses}, nil
}

func (f *fakeEventBridgeClient) DescribeEventBus(ctx context.Context, in *eventbridge.DescribeEventBusInput, _ ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error) {
	if in.Name != nil {
		if out, ok := f.describe[*in.Name]; ok {
			return out, nil
		}
	}
	return &eventbridge.DescribeEventBusOutput{}, nil
}

// --- kendra ---

type fakeKendraClient struct {
	summaries []kentypes.IndexConfigurationSummary
	describe  map[string]*kendra.DescribeIndexOutput
}

func (f *fakeKendraClient) ListIndices(ctx context.Context, in *kendra.ListIndicesInput, _ ...func(*kendra.Options)) (*kendra.ListIndicesOutput, error) {
	return &kendra.ListIndicesOutput{IndexConfigurationSummaryItems: f.summaries}, nil
}

func (f *fakeKendraClient) DescribeIndex(ctx context.Context, in *kendra.DescribeIndexInput, _ ...func(*kendra.Options)) (*kendra.DescribeIndexOutput, error) {
	if in.Id != nil {
		if out, ok := f.describe[*in.Id]; ok {
			return out, nil
		}
	}
	return &kendra.DescribeIndexOutput{}, nil
}

// --- keyspaces ---

type fakeKeyspacesClient struct {
	keyspaces []kstypes.KeyspaceSummary
	tables    map[string][]kstypes.TableSummary // keyspace -> tables
	getTable  map[string]*keyspaces.GetTableOutput
}

func (f *fakeKeyspacesClient) ListKeyspaces(ctx context.Context, in *keyspaces.ListKeyspacesInput, _ ...func(*keyspaces.Options)) (*keyspaces.ListKeyspacesOutput, error) {
	return &keyspaces.ListKeyspacesOutput{Keyspaces: f.keyspaces}, nil
}

func (f *fakeKeyspacesClient) ListTables(ctx context.Context, in *keyspaces.ListTablesInput, _ ...func(*keyspaces.Options)) (*keyspaces.ListTablesOutput, error) {
	if in.KeyspaceName != nil {
		return &keyspaces.ListTablesOutput{Tables: f.tables[*in.KeyspaceName]}, nil
	}
	return &keyspaces.ListTablesOutput{}, nil
}

func (f *fakeKeyspacesClient) GetTable(ctx context.Context, in *keyspaces.GetTableInput, _ ...func(*keyspaces.Options)) (*keyspaces.GetTableOutput, error) {
	if in.KeyspaceName != nil && in.TableName != nil {
		if out, ok := f.getTable[*in.KeyspaceName+"/"+*in.TableName]; ok {
			return out, nil
		}
	}
	return &keyspaces.GetTableOutput{}, nil
}

// --- managed_flink ---

type fakeManagedFlinkClient struct {
	summaries []kav2types.ApplicationSummary
	describe  map[string]*kinesisanalyticsv2.DescribeApplicationOutput
}

func (f *fakeManagedFlinkClient) ListApplications(ctx context.Context, in *kinesisanalyticsv2.ListApplicationsInput, _ ...func(*kinesisanalyticsv2.Options)) (*kinesisanalyticsv2.ListApplicationsOutput, error) {
	return &kinesisanalyticsv2.ListApplicationsOutput{ApplicationSummaries: f.summaries}, nil
}

func (f *fakeManagedFlinkClient) DescribeApplication(ctx context.Context, in *kinesisanalyticsv2.DescribeApplicationInput, _ ...func(*kinesisanalyticsv2.Options)) (*kinesisanalyticsv2.DescribeApplicationOutput, error) {
	if in.ApplicationName != nil {
		if out, ok := f.describe[*in.ApplicationName]; ok {
			return out, nil
		}
	}
	return &kinesisanalyticsv2.DescribeApplicationOutput{}, nil
}

// --- qldb ---

type fakeQLDBClient struct {
	ledgers  []qldbtypes.LedgerSummary
	describe map[string]*qldb.DescribeLedgerOutput
}

func (f *fakeQLDBClient) ListLedgers(ctx context.Context, in *qldb.ListLedgersInput, _ ...func(*qldb.Options)) (*qldb.ListLedgersOutput, error) {
	return &qldb.ListLedgersOutput{Ledgers: f.ledgers}, nil
}

func (f *fakeQLDBClient) DescribeLedger(ctx context.Context, in *qldb.DescribeLedgerInput, _ ...func(*qldb.Options)) (*qldb.DescribeLedgerOutput, error) {
	if in.Name != nil {
		if out, ok := f.describe[*in.Name]; ok {
			return out, nil
		}
	}
	return &qldb.DescribeLedgerOutput{}, nil
}

// --- quicksight ---

type fakeQuickSightClient struct {
	out *quicksight.DescribeKeyRegistrationOutput
}

func (f *fakeQuickSightClient) DescribeKeyRegistration(ctx context.Context, in *quicksight.DescribeKeyRegistrationInput, _ ...func(*quicksight.Options)) (*quicksight.DescribeKeyRegistrationOutput, error) {
	if f.out != nil {
		return f.out, nil
	}
	return &quicksight.DescribeKeyRegistrationOutput{}, nil
}

// --- stepfunctions ---

type fakeStepFunctionsClient struct {
	items    []sfntypes.StateMachineListItem
	describe map[string]*sfn.DescribeStateMachineOutput
}

func (f *fakeStepFunctionsClient) ListStateMachines(ctx context.Context, in *sfn.ListStateMachinesInput, _ ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	return &sfn.ListStateMachinesOutput{StateMachines: f.items}, nil
}

func (f *fakeStepFunctionsClient) DescribeStateMachine(ctx context.Context, in *sfn.DescribeStateMachineInput, _ ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
	if in.StateMachineArn != nil {
		if out, ok := f.describe[*in.StateMachineArn]; ok {
			return out, nil
		}
	}
	return &sfn.DescribeStateMachineOutput{}, nil
}

// --- workspaces_web ---

type fakeWorkSpacesWebClient struct {
	portals  []wswtypes.PortalSummary
	getByARN map[string]*workspacesweb.GetPortalOutput
}

func (f *fakeWorkSpacesWebClient) ListPortals(ctx context.Context, in *workspacesweb.ListPortalsInput, _ ...func(*workspacesweb.Options)) (*workspacesweb.ListPortalsOutput, error) {
	return &workspacesweb.ListPortalsOutput{Portals: f.portals}, nil
}

func (f *fakeWorkSpacesWebClient) GetPortal(ctx context.Context, in *workspacesweb.GetPortalInput, _ ...func(*workspacesweb.Options)) (*workspacesweb.GetPortalOutput, error) {
	if in.PortalArn != nil {
		if out, ok := f.getByARN[*in.PortalArn]; ok {
			return out, nil
		}
	}
	return &workspacesweb.GetPortalOutput{}, nil
}

// --- connect_customer_profiles ---

type fakeCustomerProfilesClient struct {
	items    []cptypes.ListDomainItem
	getByDom map[string]*customerprofiles.GetDomainOutput
}

func (f *fakeCustomerProfilesClient) ListDomains(ctx context.Context, in *customerprofiles.ListDomainsInput, _ ...func(*customerprofiles.Options)) (*customerprofiles.ListDomainsOutput, error) {
	return &customerprofiles.ListDomainsOutput{Items: f.items}, nil
}

func (f *fakeCustomerProfilesClient) GetDomain(ctx context.Context, in *customerprofiles.GetDomainInput, _ ...func(*customerprofiles.Options)) (*customerprofiles.GetDomainOutput, error) {
	if in.DomainName != nil {
		if out, ok := f.getByDom[*in.DomainName]; ok {
			return out, nil
		}
	}
	return &customerprofiles.GetDomainOutput{}, nil
}

// --- documentdb_elastic ---

type fakeDocDBElasticClient struct {
	clusters []deltypes.ClusterInList
	getByARN map[string]*docdbelastic.GetClusterOutput
}

func (f *fakeDocDBElasticClient) ListClusters(ctx context.Context, in *docdbelastic.ListClustersInput, _ ...func(*docdbelastic.Options)) (*docdbelastic.ListClustersOutput, error) {
	return &docdbelastic.ListClustersOutput{Clusters: f.clusters}, nil
}

func (f *fakeDocDBElasticClient) GetCluster(ctx context.Context, in *docdbelastic.GetClusterInput, _ ...func(*docdbelastic.Options)) (*docdbelastic.GetClusterOutput, error) {
	if in.ClusterArn != nil {
		if out, ok := f.getByARN[*in.ClusterArn]; ok {
			return out, nil
		}
	}
	return &docdbelastic.GetClusterOutput{}, nil
}

// --- mgn ---

type fakeMGNClient struct {
	items []mgntypes.ReplicationConfigurationTemplate
}

func (f *fakeMGNClient) DescribeReplicationConfigurationTemplates(ctx context.Context, in *mgn.DescribeReplicationConfigurationTemplatesInput, _ ...func(*mgn.Options)) (*mgn.DescribeReplicationConfigurationTemplatesOutput, error) {
	return &mgn.DescribeReplicationConfigurationTemplatesOutput{Items: f.items}, nil
}
