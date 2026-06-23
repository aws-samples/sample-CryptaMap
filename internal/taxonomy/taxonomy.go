// Package taxonomy maps every registered scanner Name() to friendly metadata
// (DisplayName, AWSCategory, CryptoFunction, SubAspect) so internal scanner IDs
// like kms_spec/kms_rotation never leak to UI/CBOM. It provides Lookup with a
// safe fallback for unknown names.
//
// This package is intentionally dependency-free (only strings/sort) so it can be
// imported by output code without dragging in the AWS SDK or creating an import
// cycle with internal/scanner.
package taxonomy

import (
	"sort"
	"strings"
)

// Entry is the friendly taxonomy metadata for one scanner Name().
type Entry struct {
	ScannerName    string `json:"scannerName"`    // internal Name() e.g. "kms_spec"
	DisplayName    string `json:"displayName"`    // e.g. "AWS KMS"
	AWSCategory    string `json:"awsCategory"`    // e.g. "Security, Identity & Compliance"
	CryptoFunction string `json:"cryptoFunction"` // data-at-rest|data-in-transit|key-management|certificates-pki|sdk-library
	SubAspect      string `json:"subAspect"`      // e.g. "key-spec"
}

// CryptoFunction string consts (stable wire vocabulary, distinct from
// models.Category so the *_transit variants can carry data-in-transit while
// sharing a DisplayName with their at-rest counterparts).
const (
	FuncDataAtRest      = "data-at-rest"
	FuncDataInTransit   = "data-in-transit"
	FuncKeyManagement   = "key-management"
	FuncCertificatesPKI = "certificates-pki"
	FuncSDKLibrary      = "sdk-library"
)

// registry maps scanner Name() -> friendly Entry. One literal entry per scanner
// in the full scanner list (99 entries — must match the count registered in
// cmd/cryptamap/register*.go; guarded by
// internal/scanner.TestRegistryResolvesToTaxonomy). Built as a package-level
// composite literal so there is no init ordering risk.
var registry = map[string]Entry{
	// --- data-at-rest (28) ---
	"s3":             {ScannerName: "s3", DisplayName: "Amazon S3", AWSCategory: "Storage", CryptoFunction: FuncDataAtRest, SubAspect: "bucket-encryption"},
	"ebs":            {ScannerName: "ebs", DisplayName: "Amazon EBS", AWSCategory: "Storage", CryptoFunction: FuncDataAtRest, SubAspect: "volume-encryption"},
	"rds":            {ScannerName: "rds", DisplayName: "Amazon RDS", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "storage-encryption"},
	"dynamodb":       {ScannerName: "dynamodb", DisplayName: "Amazon DynamoDB", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "table-encryption"},
	"redshift":       {ScannerName: "redshift", DisplayName: "Amazon Redshift", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "cluster-encryption"},
	"elasticache":    {ScannerName: "elasticache", DisplayName: "Amazon ElastiCache", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "at-rest-encryption"},
	"documentdb":     {ScannerName: "documentdb", DisplayName: "Amazon DocumentDB", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "storage-encryption"},
	"neptune":        {ScannerName: "neptune", DisplayName: "Amazon Neptune", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "storage-encryption"},
	"opensearch":     {ScannerName: "opensearch", DisplayName: "Amazon OpenSearch Service", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "domain-encryption"},
	"efs":            {ScannerName: "efs", DisplayName: "Amazon EFS", AWSCategory: "Storage", CryptoFunction: FuncDataAtRest, SubAspect: "filesystem-encryption"},
	"fsx":            {ScannerName: "fsx", DisplayName: "Amazon FSx", AWSCategory: "Storage", CryptoFunction: FuncDataAtRest, SubAspect: "filesystem-encryption"},
	"backup":         {ScannerName: "backup", DisplayName: "AWS Backup", AWSCategory: "Storage", CryptoFunction: FuncDataAtRest, SubAspect: "vault-encryption"},
	"glue":           {ScannerName: "glue", DisplayName: "AWS Glue", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "security-config-encryption"},
	"msk":            {ScannerName: "msk", DisplayName: "Amazon MSK", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "at-rest-encryption"},
	"sqs":            {ScannerName: "sqs", DisplayName: "Amazon SQS", AWSCategory: "Application Integration", CryptoFunction: FuncDataAtRest, SubAspect: "queue-encryption"},
	"sns":            {ScannerName: "sns", DisplayName: "Amazon SNS", AWSCategory: "Application Integration", CryptoFunction: FuncDataAtRest, SubAspect: "topic-encryption"},
	"kinesis":        {ScannerName: "kinesis", DisplayName: "Amazon Kinesis Data Streams", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "stream-encryption"},
	"secretsmanager": {ScannerName: "secretsmanager", DisplayName: "AWS Secrets Manager", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncDataAtRest, SubAspect: "secret-encryption"},
	"ssm":            {ScannerName: "ssm", DisplayName: "AWS Systems Manager Parameter Store", AWSCategory: "Management & Governance", CryptoFunction: FuncDataAtRest, SubAspect: "parameter-encryption"},
	"cloudwatchlogs": {ScannerName: "cloudwatchlogs", DisplayName: "Amazon CloudWatch Logs", AWSCategory: "Management & Governance", CryptoFunction: FuncDataAtRest, SubAspect: "log-group-encryption"},
	"sagemaker":      {ScannerName: "sagemaker", DisplayName: "Amazon SageMaker", AWSCategory: "Machine Learning", CryptoFunction: FuncDataAtRest, SubAspect: "volume-encryption"},
	"workspaces":     {ScannerName: "workspaces", DisplayName: "Amazon WorkSpaces", AWSCategory: "End User Computing", CryptoFunction: FuncDataAtRest, SubAspect: "volume-encryption"},
	"lightsail":      {ScannerName: "lightsail", DisplayName: "Amazon Lightsail", AWSCategory: "Compute", CryptoFunction: FuncDataAtRest, SubAspect: "disk-encryption"},
	"dms":            {ScannerName: "dms", DisplayName: "AWS Database Migration Service", AWSCategory: "Migration & Transfer", CryptoFunction: FuncDataAtRest, SubAspect: "endpoint-encryption"},
	"timestream":     {ScannerName: "timestream", DisplayName: "Amazon Timestream", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "table-encryption"},
	"qldb":           {ScannerName: "qldb", DisplayName: "Amazon QLDB", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "ledger-encryption"},
	"keyspaces":      {ScannerName: "keyspaces", DisplayName: "Amazon Keyspaces", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "table-encryption"},
	"memorydb":       {ScannerName: "memorydb", DisplayName: "Amazon MemoryDB", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "at-rest-encryption"},

	// --- data-at-rest (added: 10 scanners that previously fell back to "Other") ---
	"emr":                   {ScannerName: "emr", DisplayName: "Amazon EMR", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "security-config-encryption"},
	"emr_serverless":        {ScannerName: "emr_serverless", DisplayName: "Amazon EMR Serverless", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "application-encryption"},
	"dax":                   {ScannerName: "dax", DisplayName: "Amazon DynamoDB Accelerator (DAX)", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "cluster-encryption"},
	"firehose":              {ScannerName: "firehose", DisplayName: "Amazon Data Firehose", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "delivery-stream-encryption"},
	"athena":                {ScannerName: "athena", DisplayName: "Amazon Athena", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "workgroup-encryption"},
	"amazonmq":              {ScannerName: "amazonmq", DisplayName: "Amazon MQ", AWSCategory: "Application Integration", CryptoFunction: FuncDataAtRest, SubAspect: "broker-encryption"},
	"storagegateway":        {ScannerName: "storagegateway", DisplayName: "AWS Storage Gateway", AWSCategory: "Storage", CryptoFunction: FuncDataAtRest, SubAspect: "gateway-encryption"},
	"documentdb_elastic":    {ScannerName: "documentdb_elastic", DisplayName: "Amazon DocumentDB Elastic Clusters", AWSCategory: "Database", CryptoFunction: FuncDataAtRest, SubAspect: "cluster-encryption"},
	"opensearch_serverless": {ScannerName: "opensearch_serverless", DisplayName: "Amazon OpenSearch Serverless", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "collection-encryption"},
	"redshiftserverless":    {ScannerName: "redshiftserverless", DisplayName: "Amazon Redshift Serverless", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "namespace-encryption"},

	// --- data-at-rest (added 2026-06-15: 11 scanners promoted to v1 by the skipped-services audit) ---
	"bedrock":                   {ScannerName: "bedrock", DisplayName: "Amazon Bedrock", AWSCategory: "Machine Learning", CryptoFunction: FuncDataAtRest, SubAspect: "model-cmk-encryption"},
	"quicksight":                {ScannerName: "quicksight", DisplayName: "Amazon QuickSight", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "key-registration-encryption"},
	"managed_flink":             {ScannerName: "managed_flink", DisplayName: "Amazon Managed Service for Apache Flink", AWSCategory: "Analytics", CryptoFunction: FuncDataAtRest, SubAspect: "application-state-encryption"},
	"eventbridge":               {ScannerName: "eventbridge", DisplayName: "Amazon EventBridge", AWSCategory: "Application Integration", CryptoFunction: FuncDataAtRest, SubAspect: "event-bus-encryption"},
	"stepfunctions":             {ScannerName: "stepfunctions", DisplayName: "AWS Step Functions", AWSCategory: "Application Integration", CryptoFunction: FuncDataAtRest, SubAspect: "state-machine-encryption"},
	"connect_customer_profiles": {ScannerName: "connect_customer_profiles", DisplayName: "Amazon Connect Customer Profiles", AWSCategory: "Customer Engagement", CryptoFunction: FuncDataAtRest, SubAspect: "domain-encryption"},
	"workspaces_web":            {ScannerName: "workspaces_web", DisplayName: "Amazon WorkSpaces Secure Browser", AWSCategory: "End User Computing", CryptoFunction: FuncDataAtRest, SubAspect: "portal-encryption"},
	"codebuild":                 {ScannerName: "codebuild", DisplayName: "AWS CodeBuild", AWSCategory: "Developer Tools", CryptoFunction: FuncDataAtRest, SubAspect: "artifact-encryption"},
	"xray":                      {ScannerName: "xray", DisplayName: "AWS X-Ray", AWSCategory: "Developer Tools", CryptoFunction: FuncDataAtRest, SubAspect: "trace-encryption"},
	"mgn":                       {ScannerName: "mgn", DisplayName: "AWS Application Migration Service", AWSCategory: "Migration & Transfer", CryptoFunction: FuncDataAtRest, SubAspect: "replication-volume-encryption"},
	"kendra":                    {ScannerName: "kendra", DisplayName: "Amazon Kendra", AWSCategory: "Machine Learning", CryptoFunction: FuncDataAtRest, SubAspect: "index-encryption"},

	// --- data-in-transit (22) ---
	"alb":                 {ScannerName: "alb", DisplayName: "Application Load Balancer", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "listener-tls"},
	"nlb":                 {ScannerName: "nlb", DisplayName: "Network Load Balancer", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "listener-tls"},
	"apigw_rest":          {ScannerName: "apigw_rest", DisplayName: "Amazon API Gateway (REST)", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "security-policy-tls"},
	"apigw_http":          {ScannerName: "apigw_http", DisplayName: "Amazon API Gateway (HTTP)", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "security-policy-tls"},
	"cloudfront":          {ScannerName: "cloudfront", DisplayName: "Amazon CloudFront", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "viewer-tls"},
	"elasticache_transit": {ScannerName: "elasticache_transit", DisplayName: "Amazon ElastiCache", AWSCategory: "Database", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-encryption"},
	"documentdb_transit":  {ScannerName: "documentdb_transit", DisplayName: "Amazon DocumentDB", AWSCategory: "Database", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-tls"},
	"rds_transit":         {ScannerName: "rds_transit", DisplayName: "Amazon RDS", AWSCategory: "Database", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-tls"},
	"aurora_transit":      {ScannerName: "aurora_transit", DisplayName: "Amazon Aurora", AWSCategory: "Database", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-tls"},
	"opensearch_transit":  {ScannerName: "opensearch_transit", DisplayName: "Amazon OpenSearch Service", AWSCategory: "Analytics", CryptoFunction: FuncDataInTransit, SubAspect: "node-to-node-tls"},
	"msk_transit":         {ScannerName: "msk_transit", DisplayName: "Amazon MSK", AWSCategory: "Analytics", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-tls"},
	"redshift_transit":    {ScannerName: "redshift_transit", DisplayName: "Amazon Redshift", AWSCategory: "Analytics", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-tls"},
	"neptune_transit":     {ScannerName: "neptune_transit", DisplayName: "Amazon Neptune", AWSCategory: "Database", CryptoFunction: FuncDataInTransit, SubAspect: "in-transit-tls"},
	"eks":                 {ScannerName: "eks", DisplayName: "Amazon EKS", AWSCategory: "Compute", CryptoFunction: FuncDataInTransit, SubAspect: "endpoint-tls"},
	"ecs":                 {ScannerName: "ecs", DisplayName: "Amazon ECS", AWSCategory: "Compute", CryptoFunction: FuncDataInTransit, SubAspect: "service-tls"},
	"lambda":              {ScannerName: "lambda", DisplayName: "AWS Lambda", AWSCategory: "Compute", CryptoFunction: FuncDataInTransit, SubAspect: "url-tls"},
	"appsync":             {ScannerName: "appsync", DisplayName: "AWS AppSync", AWSCategory: "Application Integration", CryptoFunction: FuncDataInTransit, SubAspect: "endpoint-tls"},
	"iotcore":             {ScannerName: "iotcore", DisplayName: "AWS IoT Core", AWSCategory: "Internet of Things", CryptoFunction: FuncDataInTransit, SubAspect: "mqtt-tls"},
	"transferfamily":      {ScannerName: "transferfamily", DisplayName: "AWS Transfer Family", AWSCategory: "Migration & Transfer", CryptoFunction: FuncDataInTransit, SubAspect: "endpoint-tls"},
	"vpn":                 {ScannerName: "vpn", DisplayName: "AWS Site-to-Site VPN", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "ipsec-ike"},
	"directconnect":       {ScannerName: "directconnect", DisplayName: "AWS Direct Connect", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "macsec"},
	"globalaccelerator":   {ScannerName: "globalaccelerator", DisplayName: "AWS Global Accelerator", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "listener-tls"},

	// --- data-in-transit (added: 5 scanners that previously fell back to "Other") ---
	"clientvpn":        {ScannerName: "clientvpn", DisplayName: "AWS Client VPN", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "endpoint-tls"},
	"vpclattice":       {ScannerName: "vpclattice", DisplayName: "Amazon VPC Lattice", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "listener-tls"},
	"classicelb":       {ScannerName: "classicelb", DisplayName: "Classic Load Balancer", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "listener-tls"},
	"appmesh":          {ScannerName: "appmesh", DisplayName: "AWS App Mesh", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncDataInTransit, SubAspect: "virtual-node-tls"},
	"directoryservice": {ScannerName: "directoryservice", DisplayName: "AWS Directory Service", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncDataInTransit, SubAspect: "ldap-tls"},

	// --- certificates-pki (6) ---
	"acm":              {ScannerName: "acm", DisplayName: "AWS Certificate Manager", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncCertificatesPKI, SubAspect: "public-certificate"},
	"acmpca":           {ScannerName: "acmpca", DisplayName: "AWS Private CA", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncCertificatesPKI, SubAspect: "private-ca"},
	"iam_certs":        {ScannerName: "iam_certs", DisplayName: "AWS IAM Server Certificates", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncCertificatesPKI, SubAspect: "server-certificate"},
	"cloudfront_certs": {ScannerName: "cloudfront_certs", DisplayName: "Amazon CloudFront Custom Certificates", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncCertificatesPKI, SubAspect: "viewer-certificate"},
	"iot_certs":        {ScannerName: "iot_certs", DisplayName: "AWS IoT Core Device Certificates", AWSCategory: "Internet of Things", CryptoFunction: FuncCertificatesPKI, SubAspect: "device-certificate"},
	"rolesanywhere":    {ScannerName: "rolesanywhere", DisplayName: "AWS IAM Roles Anywhere", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncCertificatesPKI, SubAspect: "trust-anchor"},

	// --- certificates-pki (added: 2 scanners that previously fell back to "Other") ---
	"signer":               {ScannerName: "signer", DisplayName: "AWS Signer", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncCertificatesPKI, SubAspect: "signing-profile"},
	"cloudfront_keygroups": {ScannerName: "cloudfront_keygroups", DisplayName: "Amazon CloudFront Key Groups", AWSCategory: "Networking & Content Delivery", CryptoFunction: FuncCertificatesPKI, SubAspect: "signed-url-public-key"},

	// --- certificates-pki (added 2026-06-15: 2 signing/cert surfaces promoted to v1) ---
	"ses_dkim":           {ScannerName: "ses_dkim", DisplayName: "Amazon SES (DKIM Signing)", AWSCategory: "Customer Engagement", CryptoFunction: FuncCertificatesPKI, SubAspect: "dkim-signing"},
	"appstream_certauth": {ScannerName: "appstream_certauth", DisplayName: "Amazon AppStream 2.0 (Certificate-Based Auth)", AWSCategory: "End User Computing", CryptoFunction: FuncCertificatesPKI, SubAspect: "certificate-based-auth"},

	// --- key-management (6) ---
	"kms_spec":            {ScannerName: "kms_spec", DisplayName: "AWS KMS", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "key-spec"},
	"kms_usage":           {ScannerName: "kms_usage", DisplayName: "AWS KMS", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "key-usage"},
	"kms_rotation":        {ScannerName: "kms_rotation", DisplayName: "AWS KMS", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "key-rotation"},
	"cloudhsm":            {ScannerName: "cloudhsm", DisplayName: "AWS CloudHSM", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "hsm-cluster"},
	"secrets_rotation":    {ScannerName: "secrets_rotation", DisplayName: "AWS Secrets Manager", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "secret-rotation"},
	"paymentcryptography": {ScannerName: "paymentcryptography", DisplayName: "AWS Payment Cryptography", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "payment-key"},

	// --- key-management (added: 3 scanners that previously fell back to "Other") ---
	"cognito":              {ScannerName: "cognito", DisplayName: "Amazon Cognito", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "user-pool-signing-key"},
	"ec2keypairs":          {ScannerName: "ec2keypairs", DisplayName: "Amazon EC2 Key Pairs", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "key-pair"},
	"kms_custom_key_store": {ScannerName: "kms_custom_key_store", DisplayName: "AWS KMS Custom Key Stores", AWSCategory: "Security, Identity & Compliance", CryptoFunction: FuncKeyManagement, SubAspect: "custom-key-store"},

	// --- sdk-library (3) ---
	"lambda_runtime":   {ScannerName: "lambda_runtime", DisplayName: "AWS Lambda", AWSCategory: "Compute", CryptoFunction: FuncSDKLibrary, SubAspect: "runtime-sdk-version"},
	"container_images": {ScannerName: "container_images", DisplayName: "Amazon ECS/EKS Container Images", AWSCategory: "Compute", CryptoFunction: FuncSDKLibrary, SubAspect: "image-sdk-version"},
	"ec2_ssm":          {ScannerName: "ec2_ssm", DisplayName: "Amazon EC2 (via SSM Inventory)", AWSCategory: "Compute", CryptoFunction: FuncSDKLibrary, SubAspect: "instance-sdk-inventory"},

	// --- runtime-evidence (1) ---
	"cloudtrail_evidence": {ScannerName: "cloudtrail_evidence", DisplayName: "AWS CloudTrail (runtime crypto evidence)", AWSCategory: "Management & Governance", CryptoFunction: FuncKeyManagement, SubAspect: "runtime-evidence"},
}

// aliases maps short / non-scanner service identifiers (used by the mock
// generator and some UI surfaces) onto a canonical registered scanner Name() so
// they still resolve to a friendly Entry. This is intentionally NOT part of the
// registry so the registry count invariant is preserved; it only widens Lookup's
// input domain without adding new friendly metadata.
var aliases = map[string]string{
	"kms": "kms_spec", // mock emits Service:"kms"; collapse to the KMS family head
}

// Lookup returns the friendly Entry for a scanner Name(). When the name is not
// registered directly, it is resolved through the alias table; if it is still
// unknown, it returns a safe fallback (DisplayName humanized from the name,
// AWSCategory "Other", empty CryptoFunction/SubAspect) and ok=false. It never
// panics.
func Lookup(name string) (Entry, bool) {
	if e, ok := registry[name]; ok {
		return e, true
	}
	if canon, ok := aliases[name]; ok {
		if e, ok := registry[canon]; ok {
			return e, true
		}
	}
	return Entry{ScannerName: name, DisplayName: humanize(name), AWSCategory: "Other"}, false
}

// MustLookup is the convenience form used by output code; it always returns an
// Entry (the safe fallback when the name is not registered).
func MustLookup(name string) Entry {
	e, _ := Lookup(name)
	return e
}

// All returns every registered Entry sorted by ScannerName, for tests and UI
// enumeration.
func All() []Entry {
	out := make([]Entry, 0, len(registry))
	for _, e := range registry {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScannerName < out[j].ScannerName })
	return out
}

// humanize turns "kms_spec" -> "Kms Spec" as a last-resort display fallback only
// (real names come from the registry).
func humanize(name string) string {
	return strings.Title(strings.ReplaceAll(name, "_", " "))
}
