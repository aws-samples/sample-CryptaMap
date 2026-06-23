package taxonomy

import "testing"

// fullScannerList is a hand-maintained copy of the 99 registered scanner Name()
// values. It is kept here (rather than importing internal/scanner) so this unit
// test does not pull in the AWS SDK. TestAllScannersCovered guards the registry
// against this list. The cross-check that this mirror stays in lockstep with the
// real registry lives in internal/scanner (TestRegistryResolvesToTaxonomy), which
// can import the live scanner structs.
var fullScannerList = []string{
	// data-at-rest
	"s3", "ebs", "rds", "dynamodb", "redshift", "elasticache", "documentdb",
	"neptune", "opensearch", "efs", "fsx", "backup", "glue", "msk", "sqs",
	"sns", "kinesis", "secretsmanager", "ssm", "cloudwatchlogs", "sagemaker",
	"workspaces", "lightsail", "dms", "timestream", "qldb", "keyspaces", "memorydb",
	"emr", "emr_serverless", "dax", "firehose", "athena", "amazonmq",
	"storagegateway", "documentdb_elastic", "opensearch_serverless", "redshiftserverless",
	// data-at-rest (2026-06-15 coverage-expansion: 11 promoted scanners)
	"bedrock", "quicksight", "managed_flink", "eventbridge", "stepfunctions",
	"connect_customer_profiles", "workspaces_web", "codebuild", "xray", "mgn", "kendra",
	// data-in-transit
	"alb", "nlb", "apigw_rest", "apigw_http", "cloudfront", "elasticache_transit",
	"documentdb_transit", "rds_transit", "aurora_transit", "opensearch_transit",
	"msk_transit", "redshift_transit", "neptune_transit", "eks", "ecs", "lambda",
	"appsync", "iotcore", "transferfamily", "vpn", "directconnect", "globalaccelerator",
	"clientvpn", "vpclattice", "classicelb", "appmesh", "directoryservice",
	// certificates-pki
	"acm", "acmpca", "iam_certs", "cloudfront_certs", "iot_certs", "rolesanywhere",
	"signer", "cloudfront_keygroups",
	// certificates-pki (2026-06-15 coverage-expansion: 2 promoted scanners)
	"ses_dkim", "appstream_certauth",
	// key-management
	"kms_spec", "kms_usage", "kms_rotation", "cloudhsm", "secrets_rotation",
	"paymentcryptography", "cognito", "ec2keypairs", "kms_custom_key_store",
	// sdk-library
	"lambda_runtime", "container_images", "ec2_ssm",
	// runtime-evidence
	"cloudtrail_evidence",
}

// TestAllScannersCovered asserts every registered scanner Name() resolves to an
// Entry with non-empty DisplayName, AWSCategory and CryptoFunction.
func TestAllScannersCovered(t *testing.T) {
	for _, name := range fullScannerList {
		e, ok := Lookup(name)
		if !ok {
			t.Errorf("scanner %q: Lookup ok=false, expected a registered entry", name)
			continue
		}
		if e.DisplayName == "" {
			t.Errorf("scanner %q: empty DisplayName", name)
		}
		if e.AWSCategory == "" {
			t.Errorf("scanner %q: empty AWSCategory", name)
		}
		if e.CryptoFunction == "" {
			t.Errorf("scanner %q: empty CryptoFunction", name)
		}
		if e.ScannerName != name {
			t.Errorf("scanner %q: Entry.ScannerName=%q, want %q", name, e.ScannerName, name)
		}
	}
}

// TestNoEmptyDisplayName asserts no registered entry maps to an empty DisplayName.
func TestNoEmptyDisplayName(t *testing.T) {
	for _, e := range All() {
		if e.DisplayName == "" {
			t.Errorf("scanner %q maps to an empty DisplayName", e.ScannerName)
		}
	}
}

// TestKMSSharedDisplayName asserts the KMS variants collapse to one friendly
// DisplayName so internal IDs (kms_spec/kms_rotation/kms_usage) never leak.
func TestKMSSharedDisplayName(t *testing.T) {
	spec := MustLookup("kms_spec")
	rotation := MustLookup("kms_rotation")
	if spec.DisplayName != "AWS KMS" {
		t.Errorf("kms_spec DisplayName=%q, want %q", spec.DisplayName, "AWS KMS")
	}
	if rotation.DisplayName != "AWS KMS" {
		t.Errorf("kms_rotation DisplayName=%q, want %q", rotation.DisplayName, "AWS KMS")
	}
	if spec.SubAspect == rotation.SubAspect {
		t.Errorf("kms_spec and kms_rotation should have distinct SubAspect, both=%q", spec.SubAspect)
	}
}

// TestAliasResolution asserts short / non-scanner service identifiers used by
// the mock generator (e.g. "kms") resolve to a registered friendly Entry so the
// internal scanner ID never leaks even when the caller passes the short name.
func TestAliasResolution(t *testing.T) {
	e, ok := Lookup("kms")
	if !ok {
		t.Fatalf("Lookup(kms) ok=false, want true via alias")
	}
	if e.DisplayName != "AWS KMS" {
		t.Errorf("alias kms DisplayName=%q, want %q", e.DisplayName, "AWS KMS")
	}
	if e.CryptoFunction != FuncKeyManagement {
		t.Errorf("alias kms CryptoFunction=%q, want %q", e.CryptoFunction, FuncKeyManagement)
	}
}

// TestLookupFallback asserts an unknown name returns the safe fallback rather
// than panicking: ok=false, non-empty DisplayName, AWSCategory=="Other".
func TestLookupFallback(t *testing.T) {
	e, ok := Lookup("does_not_exist")
	if ok {
		t.Fatalf("Lookup(does_not_exist) ok=true, want false")
	}
	if e.DisplayName == "" {
		t.Errorf("fallback DisplayName is empty, want humanized name")
	}
	if e.AWSCategory != "Other" {
		t.Errorf("fallback AWSCategory=%q, want %q", e.AWSCategory, "Other")
	}
	if e.ScannerName != "does_not_exist" {
		t.Errorf("fallback ScannerName=%q, want %q", e.ScannerName, "does_not_exist")
	}
	// MustLookup must also return the fallback (never panic) for unknown names.
	if got := MustLookup("does_not_exist").DisplayName; got == "" {
		t.Errorf("MustLookup fallback DisplayName is empty")
	}
}

// TestCount asserts the registry holds exactly 99 entries — one per scanner
// registered in cmd/cryptamap/register*.go (data-at-rest 49, data-in-transit 27,
// certificates-pki 10, key-management 9, sdk-library 3, runtime-evidence 1). The
// authoritative cross-check against the live registry is
// internal/scanner.TestRegistryResolvesToTaxonomy.
func TestCount(t *testing.T) {
	if got := len(All()); got != 99 {
		t.Errorf("len(All())=%d, want 99", got)
	}
	if got := len(fullScannerList); got != 99 {
		t.Errorf("len(fullScannerList)=%d, want 99", got)
	}
}
