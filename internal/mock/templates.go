// Package mock generates realistic synthetic crypto findings for end-to-end
// testing without AWS API access. Distributions follow the spec: 5% CRITICAL,
// 15% HIGH, 65% MEDIUM, 15% INFORMATIONAL.
package mock

import "github.com/aws-samples/cryptamap/pkg/models"

// Template describes how to render a synthetic asset for one service.
type Template struct {
	Service      string
	Category     models.Category
	ResourceType string
	NamePattern  string // e.g. "my-bucket-%d"

	// Posture distribution sums to 100. Defaults below are spec-aligned.
	PctNoEncryption    int
	PctLegacyTLS       int
	PctNonPQCClassical int
	PctPQCHybrid       int
	PctSymmetricOnly   int
}

// Defaults: 5% CRIT, 15% HIGH, 65% MED, 15% INFO.
var defaultDistribution = struct {
	NoEnc, Legacy, NonPQC, Hybrid, Sym int
}{NoEnc: 5, Legacy: 15, NonPQC: 65, Hybrid: 5, Sym: 10}

// Templates returns one Template per supported service identifier.
func Templates() []Template {
	dist := defaultDistribution
	atRest := []struct {
		svc, rtype, pat string
	}{
		{"s3", "AWS::S3::Bucket", "bucket-%d"},
		{"ebs", "AWS::EC2::Volume", "vol-%08x"},
		{"rds", "AWS::RDS::DBInstance", "rds-instance-%d"},
		{"dynamodb", "AWS::DynamoDB::Table", "ddb-table-%d"},
		{"redshift", "AWS::Redshift::Cluster", "redshift-cluster-%d"},
		{"elasticache", "AWS::ElastiCache::CacheCluster", "elasticache-%d"},
		{"documentdb", "AWS::DocDB::DBCluster", "docdb-cluster-%d"},
		{"neptune", "AWS::Neptune::DBCluster", "neptune-cluster-%d"},
		{"opensearch", "AWS::OpenSearchService::Domain", "opensearch-%d"},
		{"efs", "AWS::EFS::FileSystem", "fs-%08x"},
		{"fsx", "AWS::FSx::FileSystem", "fsx-fs-%d"},
		{"backup", "AWS::Backup::BackupVault", "backup-vault-%d"},
		{"glue", "AWS::Glue::DataCatalog", "glue-catalog-%d"},
		{"msk", "AWS::MSK::Cluster", "msk-cluster-%d"},
		{"sqs", "AWS::SQS::Queue", "sqs-%d"},
		{"sns", "AWS::SNS::Topic", "sns-topic-%d"},
		{"kinesis", "AWS::Kinesis::Stream", "kinesis-stream-%d"},
		{"secretsmanager", "AWS::SecretsManager::Secret", "secret-%d"},
		{"ssm", "AWS::SSM::Parameter", "ssm-param-%d"},
		{"cloudwatchlogs", "AWS::Logs::LogGroup", "log-group-%d"},
		{"sagemaker", "AWS::SageMaker::Domain", "sm-domain-%d"},
		{"workspaces", "AWS::WorkSpaces::Workspace", "ws-%d"},
		{"lightsail", "AWS::Lightsail::Instance", "lightsail-%d"},
		{"dms", "AWS::DMS::ReplicationInstance", "dms-rep-%d"},
		{"timestream", "AWS::Timestream::Database", "ts-db-%d"},
		{"qldb", "AWS::QLDB::Ledger", "qldb-ledger-%d"},
		{"keyspaces", "AWS::Cassandra::Keyspace", "keyspace-%d"},
		{"memorydb", "AWS::MemoryDB::Cluster", "memdb-cluster-%d"},
		// --- previously-uncovered data-at-rest scanners ---
		{"athena", "AWS::Athena::WorkGroup", "athena-wg-%d"},
		{"firehose", "AWS::KinesisFirehose::DeliveryStream", "firehose-%d"},
		{"emr", "AWS::EMR::SecurityConfiguration", "emr-secconf-%d"},
		{"emr_serverless", "AWS::EMRServerless::Application", "emr-sl-app-%d"},
		{"amazonmq", "AWS::AmazonMQ::Broker", "mq-broker-%d"},
		{"dax", "AWS::DAX::Cluster", "dax-cluster-%d"},
		{"redshiftserverless", "AWS::RedshiftServerless::Namespace", "rs-sl-ns-%d"},
		{"documentdb_elastic", "AWS::DocDBElastic::Cluster", "docdb-elastic-%d"},
		{"storagegateway", "AWS::StorageGateway::Gateway", "sgw-gateway-%d"},
		{"opensearch_serverless", "AWS::OpenSearchServerless::Collection", "aoss-collection-%d"},
		{"bedrock", "AWS::Bedrock::CustomModel", "bedrock-model-%d"},
		{"quicksight", "AWS::QuickSight::KeyRegistration", "quicksight-keyreg-%d"},
		{"managed_flink", "AWS::KinesisAnalyticsV2::Application", "flink-app-%d"},
		{"eventbridge", "AWS::Events::EventBus", "eventbus-%d"},
		{"stepfunctions", "AWS::StepFunctions::StateMachine", "sfn-statemachine-%d"},
		{"connect_customer_profiles", "AWS::CustomerProfiles::Domain", "profiles-domain-%d"},
		{"workspaces_web", "AWS::WorkSpacesWeb::Portal", "wsweb-portal-%d"},
		{"codebuild", "AWS::CodeBuild::Project", "codebuild-project-%d"},
		{"xray", "AWS::XRay::EncryptionConfig", "xray-encconfig-%d"},
		{"mgn", "AWS::MGN::ReplicationConfigurationTemplate", "mgn-rct-%d"},
		{"kendra", "AWS::Kendra::Index", "kendra-index-%d"},
	}
	transit := []struct {
		svc, rtype, pat string
	}{
		{"alb", "AWS::ElasticLoadBalancingV2::LoadBalancer", "alb-%d"},
		{"nlb", "AWS::ElasticLoadBalancingV2::LoadBalancer", "nlb-%d"},
		{"apigw_rest", "AWS::ApiGateway::RestApi", "apigw-rest-%d"},
		{"apigw_http", "AWS::ApiGatewayV2::Api", "apigw-http-%d"},
		{"cloudfront", "AWS::CloudFront::Distribution", "cf-dist-%d"},
		{"elasticache_transit", "AWS::ElastiCache::CacheCluster", "elasticache-tls-%d"},
		{"documentdb_transit", "AWS::DocDB::DBCluster", "docdb-tls-%d"},
		{"rds_transit", "AWS::RDS::DBInstance", "rds-tls-%d"},
		{"aurora_transit", "AWS::RDS::DBCluster", "aurora-tls-%d"},
		{"opensearch_transit", "AWS::OpenSearchService::Domain", "os-tls-%d"},
		{"msk_transit", "AWS::MSK::Cluster", "msk-tls-%d"},
		{"redshift_transit", "AWS::Redshift::Cluster", "rs-tls-%d"},
		{"neptune_transit", "AWS::Neptune::DBCluster", "neptune-tls-%d"},
		{"eks", "AWS::EKS::Cluster", "eks-%d"},
		{"ecs", "AWS::ECS::Cluster", "ecs-%d"},
		{"lambda", "AWS::Lambda::Function", "lambda-%d"},
		{"appsync", "AWS::AppSync::GraphQLApi", "appsync-%d"},
		{"iotcore", "AWS::IoT::Thing", "iot-%d"},
		{"transferfamily", "AWS::Transfer::Server", "transfer-%d"},
		{"vpn", "AWS::EC2::VPNConnection", "vpn-%08x"},
		{"directconnect", "AWS::DirectConnect::Connection", "dx-%d"},
		{"globalaccelerator", "AWS::GlobalAccelerator::Accelerator", "ga-%d"},
		// --- previously-uncovered data-in-transit scanners ---
		// appmesh: STRICT/PERMISSIVE TLS nodes are encrypted in transit — the mock
		// MUST give it a TLS spread (NOT no-encryption), mirroring the honesty
		// contract that an encrypted mesh node is never mislabeled no-encryption.
		{"appmesh", "AWS::AppMesh::VirtualNode", "appmesh-vnode-%d"},
		{"classicelb", "AWS::ElasticLoadBalancing::LoadBalancer", "classic-elb-%d"},
		{"clientvpn", "AWS::EC2::ClientVpnEndpoint", "cvpn-endpoint-%d"},
		{"directoryservice", "AWS::DirectoryService::MicrosoftAD", "ds-ad-%d"},
		{"vpclattice", "AWS::VpcLattice::Listener", "lattice-listener-%d"},
	}
	cert := []struct {
		svc, rtype, pat string
	}{
		{"acm", "AWS::CertificateManager::Certificate", "acm-cert-%d"},
		{"acmpca", "AWS::ACMPCA::CertificateAuthority", "acm-pca-%d"},
		{"iam_certs", "AWS::IAM::ServerCertificate", "iam-cert-%d"},
		{"cloudfront_certs", "AWS::CloudFront::Distribution", "cf-cert-%d"},
		{"iot_certs", "AWS::IoT::Certificate", "iot-cert-%d"},
		// --- previously-uncovered certificate / signing scanners ---
		{"signer", "AWS::Signer::SigningProfile", "signer-profile-%d"},
		{"rolesanywhere", "AWS::RolesAnywhere::TrustAnchor", "rolesanywhere-ta-%d"},
		{"ses_dkim", "AWS::SES::EmailIdentity", "ses-identity-%d"},
		{"appstream_certauth", "AWS::AppStream::DirectoryConfig", "appstream-dircfg-%d"},
		{"cloudfront_keygroups", "AWS::CloudFront::PublicKey", "cf-pubkey-%d"},
	}
	key := []struct {
		svc, rtype, pat string
	}{
		// The real registry has NO scanner named "kms"; it splits into three KMS
		// scanners (spec/usage/rotation). Use the actual Name() values so every
		// registered scanner has a template and none is orphaned.
		{"kms_spec", "AWS::KMS::Key", "kms-key-%d"},
		{"kms_usage", "AWS::KMS::Alias", "kms-alias-%d"},
		{"kms_rotation", "AWS::KMS::Key", "kms-rot-key-%d"},
		{"kms_custom_key_store", "AWS::KMS::CustomKeyStore", "kms-cks-%d"},
		{"cloudhsm", "AWS::CloudHSM::Cluster", "hsm-cluster-%d"},
		// --- previously-uncovered key-management scanners ---
		{"cognito", "AWS::Cognito::UserPool", "cognito-pool-%d"},
		{"ec2keypairs", "AWS::EC2::KeyPair", "ec2-keypair-%d"},
		{"paymentcryptography", "AWS::PaymentCryptography::Key", "paycrypto-key-%d"},
		{"secrets_rotation", "AWS::SecretsManager::Secret", "secret-rot-%d"},
		// cloudtrail_evidence lives in the runtime package but its Category() is
		// KeyManagement; group it here for a consistent posture distribution.
		{"cloudtrail_evidence", "AWS::CloudTrail::RuntimeEvidence", "ct-evidence-%d"},
	}
	sdk := []struct {
		svc, rtype, pat string
	}{
		{"lambda_runtime", "AWS::Lambda::Function", "lambda-rt-%d"},
		{"container_images", "AWS::ECR::Repository", "ecr-%d"},
		{"ec2_ssm", "AWS::EC2::Instance", "i-%08x"},
	}

	out := make([]Template, 0, 64)
	for _, e := range atRest {
		out = append(out, Template{Service: e.svc, Category: models.CategoryDataAtRest, ResourceType: e.rtype, NamePattern: e.pat,
			PctNoEncryption: dist.NoEnc, PctLegacyTLS: 0, PctNonPQCClassical: 0, PctPQCHybrid: 0, PctSymmetricOnly: 100 - dist.NoEnc})
	}
	for _, e := range transit {
		out = append(out, Template{Service: e.svc, Category: models.CategoryDataInTransit, ResourceType: e.rtype, NamePattern: e.pat,
			PctNoEncryption: 0, PctLegacyTLS: dist.Legacy, PctNonPQCClassical: dist.NonPQC, PctPQCHybrid: dist.Hybrid + dist.Sym, PctSymmetricOnly: 0,
		})
	}
	for _, e := range cert {
		out = append(out, Template{Service: e.svc, Category: models.CategoryCertificate, ResourceType: e.rtype, NamePattern: e.pat,
			PctNoEncryption: 0, PctLegacyTLS: 0, PctNonPQCClassical: 80, PctPQCHybrid: 5, PctSymmetricOnly: 15,
		})
	}
	for _, e := range key {
		out = append(out, Template{Service: e.svc, Category: models.CategoryKeyManagement, ResourceType: e.rtype, NamePattern: e.pat,
			PctNoEncryption: 0, PctLegacyTLS: 0, PctNonPQCClassical: 70, PctPQCHybrid: 10, PctSymmetricOnly: 20,
		})
	}
	for _, e := range sdk {
		out = append(out, Template{Service: e.svc, Category: models.CategorySDKLibrary, ResourceType: e.rtype, NamePattern: e.pat,
			PctNoEncryption: 0, PctLegacyTLS: 0, PctNonPQCClassical: 75, PctPQCHybrid: 5, PctSymmetricOnly: 20,
		})
	}
	return out
}
