package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	smithymw "github.com/aws/smithy-go/middleware"

	"github.com/aws-samples/cryptamap/internal/services/certmgmt"
	"github.com/aws-samples/cryptamap/internal/services/datarest"
	"github.com/aws-samples/cryptamap/internal/services/keymgmt"
	"github.com/aws-samples/cryptamap/internal/services/runtime"
	"github.com/aws-samples/cryptamap/internal/services/sdkpqc"
	"github.com/aws-samples/cryptamap/internal/services/transit"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
)

// testRegistry builds a Registry wired with the exact same scanner set as
// cmd/cryptamap/register*.go. The wiring lives in package main (which a test
// cannot import), so it is mirrored here; the count + per-name checks below fail
// loudly if the two drift apart. internal/services/* does NOT import
// internal/scanner, so importing the concrete scanners from this package is
// cycle-free.
func testRegistry() *Registry {
	r := NewRegistry()

	// certificate management (8)
	r.Register(certmgmt.ACMScanner{})
	r.Register(certmgmt.ACMPCAScanner{})
	r.Register(certmgmt.IAMCertsScanner{})
	r.Register(certmgmt.CloudFrontCertsScanner{})
	r.Register(certmgmt.IoTCertsScanner{})
	r.Register(certmgmt.RolesAnywhereScanner{})
	r.Register(certmgmt.SignerScanner{})
	r.Register(certmgmt.CloudFrontKeyGroupsScanner{})
	r.Register(certmgmt.SESDKIMScanner{})
	r.Register(certmgmt.AppStreamCertAuthScanner{})

	// key management (9)
	r.Register(keymgmt.KMSSpecScanner{})
	r.Register(keymgmt.KMSUsageScanner{})
	r.Register(keymgmt.KMSRotationScanner{})
	r.Register(keymgmt.CloudHSMScanner{})
	r.Register(keymgmt.SecretsRotationScanner{})
	r.Register(keymgmt.PaymentCryptographyScanner{})
	r.Register(keymgmt.CognitoScanner{})
	r.Register(keymgmt.EC2KeyPairsScanner{})
	r.Register(keymgmt.KMSCustomKeyStoreScanner{})

	// sdk / library PQC (3)
	r.Register(sdkpqc.LambdaRuntimeScanner{})
	r.Register(sdkpqc.ContainerImagesScanner{})
	r.Register(sdkpqc.EC2SSMScanner{})

	// data at rest (38)
	r.Register(datarest.S3Scanner{})
	r.Register(datarest.EBSScanner{})
	r.Register(datarest.RDSScanner{})
	r.Register(datarest.DynamoDBScanner{})
	r.Register(datarest.RedshiftScanner{})
	r.Register(datarest.ElastiCacheScanner{})
	r.Register(datarest.DocumentDBScanner{})
	r.Register(datarest.NeptuneScanner{})
	r.Register(datarest.OpenSearchScanner{})
	r.Register(datarest.EFSScanner{})
	r.Register(datarest.FSxScanner{})
	r.Register(datarest.BackupScanner{})
	r.Register(datarest.GlueScanner{})
	r.Register(datarest.MSKScanner{})
	r.Register(datarest.SQSScanner{})
	r.Register(datarest.SNSScanner{})
	r.Register(datarest.KinesisScanner{})
	r.Register(datarest.SecretsManagerScanner{})
	r.Register(datarest.SSMScanner{})
	r.Register(datarest.CloudWatchLogsScanner{})
	r.Register(datarest.SageMakerScanner{})
	r.Register(datarest.WorkSpacesScanner{})
	r.Register(datarest.LightsailScanner{})
	r.Register(datarest.DMSScanner{})
	r.Register(datarest.TimestreamScanner{})
	r.Register(datarest.QLDBScanner{})
	r.Register(datarest.KeyspacesScanner{})
	r.Register(datarest.MemoryDBScanner{})
	r.Register(datarest.AthenaScanner{})
	r.Register(datarest.FirehoseScanner{})
	r.Register(datarest.EMRScanner{})
	r.Register(datarest.AmazonMQScanner{})
	r.Register(datarest.DAXScanner{})
	r.Register(datarest.RedshiftServerlessScanner{})
	r.Register(datarest.DocumentDBElasticScanner{})
	r.Register(datarest.StorageGatewayScanner{})
	r.Register(datarest.OpenSearchServerlessScanner{})
	r.Register(datarest.EMRServerlessScanner{})
	r.Register(datarest.BedrockScanner{})
	r.Register(datarest.QuickSightScanner{})
	r.Register(datarest.ManagedFlinkScanner{})
	r.Register(datarest.EventBridgeScanner{})
	r.Register(datarest.StepFunctionsScanner{})
	r.Register(datarest.CustomerProfilesScanner{})
	r.Register(datarest.WorkSpacesWebScanner{})
	r.Register(datarest.CodeBuildScanner{})
	r.Register(datarest.XRayScanner{})
	r.Register(datarest.MGNScanner{})
	r.Register(datarest.KendraScanner{})

	// data in transit (27)
	r.Register(transit.ALBScanner{})
	r.Register(transit.NLBScanner{})
	r.Register(transit.APIGWRestScanner{})
	r.Register(transit.APIGWHTTPScanner{})
	r.Register(transit.CloudFrontScanner{})
	r.Register(transit.ElastiCacheTransitScanner{})
	r.Register(transit.DocumentDBTransitScanner{})
	r.Register(transit.RDSTransitScanner{})
	r.Register(transit.AuroraTransitScanner{})
	r.Register(transit.OpenSearchTransitScanner{})
	r.Register(transit.MSKTransitScanner{})
	r.Register(transit.RedshiftTransitScanner{})
	r.Register(transit.NeptuneTransitScanner{})
	r.Register(transit.EKSScanner{})
	r.Register(transit.ECSScanner{})
	r.Register(transit.LambdaScanner{})
	r.Register(transit.AppSyncScanner{})
	r.Register(transit.IoTCoreScanner{})
	r.Register(transit.TransferFamilyScanner{})
	r.Register(transit.VPNScanner{})
	r.Register(transit.DirectConnectScanner{})
	r.Register(transit.GlobalAcceleratorScanner{})
	r.Register(transit.ClientVPNScanner{})
	r.Register(transit.VPCLatticeScanner{})
	r.Register(transit.ClassicELBScanner{})
	r.Register(transit.AppMeshScanner{})
	r.Register(transit.DirectoryServiceScanner{})

	// runtime evidence (1)
	r.Register(runtime.CloudTrailEvidenceScanner{})

	return r
}

// readVerbPrefixes are the operation-name prefixes the read-only contract allows.
// CryptaMap is report-only/read-only: every AWS SDK operation it issues must be a
// non-mutating read. smithy operation names are the model shape names (e.g.
// "DescribeKeyPairs", "GetCallerIdentity", "ListKeys"), so a prefix check on the
// operation name is a faithful read/write discriminator.
var readVerbPrefixes = []string{
	"Describe", "List", "Get", "BatchGet", "Lookup", "Select", "Search", "Scan",
}

func isReadOperation(op string) bool {
	for _, p := range readVerbPrefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
	}
	return false
}

// errReadOnlyGuard short-circuits the SDK request after the guard has inspected
// the operation name, so the test never performs real network I/O.
var errReadOnlyGuard = errors.New("read-only-guard: request short-circuited after inspection")

// readOnlyGuardConfig returns an aws.Config whose Finalize-step middleware records
// every SDK operation name and fails the test if any operation is not a read. The
// middleware runs before the request is sent and returns errReadOnlyGuard, so no
// AWS call leaves the process. This genuinely catches a future mutating SDK call
// from any scanner exercised through this config: the guard sees the operation
// name of every request the scanner attempts.
func readOnlyGuardConfig(t *testing.T, seen *[]string) aws.Config {
	t.Helper()
	guard := smithymw.FinalizeMiddlewareFunc(
		"cryptamap-readonly-guard",
		func(ctx context.Context, in smithymw.FinalizeInput, _ smithymw.FinalizeHandler) (smithymw.FinalizeOutput, smithymw.Metadata, error) {
			op := smithymw.GetOperationName(ctx)
			*seen = append(*seen, op)
			if !isReadOperation(op) {
				t.Errorf("read-only violation: scanner issued non-read operation %q", op)
			}
			// Short-circuit: do not call next, so the request is never sent.
			return smithymw.FinalizeOutput{}, smithymw.Metadata{}, errReadOnlyGuard
		},
	)
	return aws.Config{
		Region: "us-east-1",
		APIOptions: []func(*smithymw.Stack) error{
			func(s *smithymw.Stack) error {
				return s.Finalize.Add(guard, smithymw.Before)
			},
		},
	}
}

// TestScannerReadOnlyMiddleware (a) asserts the read-only contract: a
// representative scanner driven through a guarded aws.Config issues only read
// operations. The guard is a Finalize-step middleware that inspects every SDK
// operation name and fails on any non-read verb, then short-circuits so no real
// AWS call is made.
//
// COVERAGE SCOPE: this exercises one representative scanner path
// (EC2KeyPairsScanner, which also triggers the shared services.AccountID STS
// GetCallerIdentity call) rather than every scanner — running all 86 scanners
// against a live middleware harness is far heavier and most are gated behind
// pagination/list calls that the short-circuit truncates. The guard is generic:
// pointed at any scanner it would catch a mutating call. The registry↔taxonomy
// and coverage tests below cover the full set.
func TestScannerReadOnlyMiddleware(t *testing.T) {
	var seen []string
	cfg := readOnlyGuardConfig(t, &seen)

	// EC2KeyPairsScanner.Scan first resolves the account via STS GetCallerIdentity
	// then calls EC2 DescribeKeyPairs — both reads. The guard short-circuits each
	// request, so Scan returns an error wrapping errReadOnlyGuard; that is the
	// expected, network-free outcome.
	_, err := keymgmt.EC2KeyPairsScanner{}.Scan(context.Background(), cfg)
	if err != nil && !errors.Is(err, errReadOnlyGuard) {
		// A non-guard error (e.g. credential resolution) is acceptable as long as
		// the guard still observed only read operations; we assert on `seen`.
		t.Logf("scan returned non-guard error (acceptable): %v", err)
	}

	if len(seen) == 0 {
		t.Fatalf("read-only guard observed no SDK operations; the middleware was not exercised")
	}
	// Sanity: confirm the guard actually saw the expected read verbs.
	sawDescribe := false
	for _, op := range seen {
		if !isReadOperation(op) {
			t.Errorf("non-read operation slipped through: %q", op)
		}
		if strings.HasPrefix(op, "Describe") {
			sawDescribe = true
		}
	}
	if !sawDescribe {
		t.Errorf("expected at least one Describe* operation, saw %v", seen)
	}
}

// TestNonReadOperationDetected proves the read-verb discriminator (the heart of
// the guard) actually rejects mutating verbs — so the guard in
// TestScannerReadOnlyMiddleware would fail the build if a scanner ever issued a
// write. Without this, a buggy isReadOperation that returns true for everything
// would let writes slip by silently.
func TestNonReadOperationDetected(t *testing.T) {
	reads := []string{"DescribeKeyPairs", "ListKeys", "GetCallerIdentity", "BatchGetItem", "LookupEvents", "SelectObjectContent", "Scan", "SearchResources"}
	for _, op := range reads {
		if !isReadOperation(op) {
			t.Errorf("isReadOperation(%q) = false, want true (read verb)", op)
		}
	}
	writes := []string{"PutObject", "CreateKey", "DeleteBucket", "ModifyInstanceAttribute", "UpdateTable", "TerminateInstances", "AttachRolePolicy", "EnableKeyRotation"}
	for _, op := range writes {
		if isReadOperation(op) {
			t.Errorf("isReadOperation(%q) = true, want false (mutating verb must be rejected)", op)
		}
	}
}

// TestCoverageReconciliation (b) asserts every registered scanner Name() appears
// in the engine's per-service report after a run — no scanner is silently absent
// from the coverage summary. The run uses the read-only guard config, so each
// scanner errors out network-free; Engine.Run still emits one ServiceScanReport
// per registered scanner regardless of per-scanner outcome.
func TestCoverageReconciliation(t *testing.T) {
	reg := testRegistry()
	// Single-attempt, no backoff: scanners fail fast under the guard.
	e := NewEngine(reg, nil, EngineOptions{MaxRetries: 0, MaxGoroutines: 8, ToolVersion: "test"})

	var seen []string // collected for the read-only guard side-effect only
	cfg := readOnlyGuardConfig(t, &seen)

	res := e.Run(context.Background(), cfg, "000000000000")

	reported := make(map[string]bool, len(res.ServiceStats))
	for _, s := range res.ServiceStats {
		reported[s.Service] = true
	}
	for _, name := range reg.Names() {
		if !reported[name] {
			t.Errorf("scanner %q registered but absent from engine ServiceStats coverage", name)
		}
	}
	if got, want := len(res.ServiceStats), reg.Len(); got != want {
		t.Errorf("engine reported %d service stats, want %d (one per registered scanner)", got, want)
	}
	if res.Summary.ServiceCount != reg.Len() {
		t.Errorf("summary ServiceCount=%d, want %d", res.Summary.ServiceCount, reg.Len())
	}
}

// TestRegistryResolvesToTaxonomy (c) asserts every registered scanner Name()
// resolves to a real taxonomy Entry with AWSCategory != "Other". This FAILS
// before the taxonomy entries for the ~20 newly-registered scanners are added
// (they fall back to AWSCategory:"Other" with an empty CryptoFunction) and PASSES
// once they are present, guaranteeing no scanner leaks an "Other"/humanized label
// into CBOM/PQCC/dashboard. It also cross-checks the taxonomy mirror count.
func TestRegistryResolvesToTaxonomy(t *testing.T) {
	reg := testRegistry()
	names := reg.Names()

	for _, name := range names {
		e, ok := taxonomy.Lookup(name)
		if !ok {
			t.Errorf("scanner %q: taxonomy.Lookup ok=false (no Entry); falls back to AWSCategory:%q", name, e.AWSCategory)
			continue
		}
		if e.AWSCategory == "Other" {
			t.Errorf("scanner %q: AWSCategory=%q (fallback), want a real category", name, e.AWSCategory)
		}
		if e.AWSCategory == "" {
			t.Errorf("scanner %q: empty AWSCategory", name)
		}
		if e.DisplayName == "" {
			t.Errorf("scanner %q: empty DisplayName", name)
		}
		if e.CryptoFunction == "" {
			t.Errorf("scanner %q: empty CryptoFunction", name)
		}
	}

	// The taxonomy.All() registry and the live scanner registry must be the same
	// size: no orphan taxonomy entries and no unregistered taxonomy gaps.
	if got, want := len(taxonomy.All()), reg.Len(); got != want {
		t.Errorf("taxonomy.All()=%d entries, live registry=%d scanners; they must match", got, want)
	}
}
