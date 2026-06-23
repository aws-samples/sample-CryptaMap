package mock

import (
	"testing"

	"github.com/aws-samples/cryptamap/internal/services/certmgmt"
	"github.com/aws-samples/cryptamap/internal/services/datarest"
	"github.com/aws-samples/cryptamap/internal/services/keymgmt"
	"github.com/aws-samples/cryptamap/internal/services/runtime"
	"github.com/aws-samples/cryptamap/internal/services/sdkpqc"
	"github.com/aws-samples/cryptamap/internal/services/transit"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// named is the minimal slice of scanner.ServiceScanner this test needs. It is
// declared locally (rather than importing internal/scanner) because
// internal/scanner imports internal/mock via mock_engine.go, so importing the
// scanner package back into a mock test would create an import cycle. Every
// concrete scanner satisfies this interface, so the registered set can be
// enumerated cycle-free by importing only the internal/services/* packages
// (which import neither internal/mock nor internal/scanner).
type named interface{ Name() string }

// liveScanners returns the EXACT registered scanner set, mirroring
// cmd/cryptamap/register*.go and internal/scanner/registry_test.go's testRegistry.
// Package main cannot be imported from a test, so the wiring is mirrored here.
//
// This is intentionally the LIVE concrete-scanner set (not a hand-typed name
// list): if a new scanner is registered in cmd but a mock Template is forgotten,
// this slice grows but Templates() does not, and TestMockCoverageNoDrift fails.
func liveScanners() []named {
	return []named{
		// certificate management
		certmgmt.ACMScanner{},
		certmgmt.ACMPCAScanner{},
		certmgmt.IAMCertsScanner{},
		certmgmt.CloudFrontCertsScanner{},
		certmgmt.IoTCertsScanner{},
		certmgmt.RolesAnywhereScanner{},
		certmgmt.SignerScanner{},
		certmgmt.CloudFrontKeyGroupsScanner{},
		certmgmt.SESDKIMScanner{},
		certmgmt.AppStreamCertAuthScanner{},

		// key management
		keymgmt.KMSSpecScanner{},
		keymgmt.KMSUsageScanner{},
		keymgmt.KMSRotationScanner{},
		keymgmt.CloudHSMScanner{},
		keymgmt.SecretsRotationScanner{},
		keymgmt.PaymentCryptographyScanner{},
		keymgmt.CognitoScanner{},
		keymgmt.EC2KeyPairsScanner{},
		keymgmt.KMSCustomKeyStoreScanner{},

		// sdk / library PQC
		sdkpqc.LambdaRuntimeScanner{},
		sdkpqc.ContainerImagesScanner{},
		sdkpqc.EC2SSMScanner{},

		// data at rest
		datarest.S3Scanner{},
		datarest.EBSScanner{},
		datarest.RDSScanner{},
		datarest.DynamoDBScanner{},
		datarest.RedshiftScanner{},
		datarest.ElastiCacheScanner{},
		datarest.DocumentDBScanner{},
		datarest.NeptuneScanner{},
		datarest.OpenSearchScanner{},
		datarest.EFSScanner{},
		datarest.FSxScanner{},
		datarest.BackupScanner{},
		datarest.GlueScanner{},
		datarest.MSKScanner{},
		datarest.SQSScanner{},
		datarest.SNSScanner{},
		datarest.KinesisScanner{},
		datarest.SecretsManagerScanner{},
		datarest.SSMScanner{},
		datarest.CloudWatchLogsScanner{},
		datarest.SageMakerScanner{},
		datarest.WorkSpacesScanner{},
		datarest.LightsailScanner{},
		datarest.DMSScanner{},
		datarest.TimestreamScanner{},
		datarest.QLDBScanner{},
		datarest.KeyspacesScanner{},
		datarest.MemoryDBScanner{},
		datarest.AthenaScanner{},
		datarest.FirehoseScanner{},
		datarest.EMRScanner{},
		datarest.AmazonMQScanner{},
		datarest.DAXScanner{},
		datarest.RedshiftServerlessScanner{},
		datarest.DocumentDBElasticScanner{},
		datarest.StorageGatewayScanner{},
		datarest.OpenSearchServerlessScanner{},
		datarest.EMRServerlessScanner{},
		datarest.BedrockScanner{},
		datarest.QuickSightScanner{},
		datarest.ManagedFlinkScanner{},
		datarest.EventBridgeScanner{},
		datarest.StepFunctionsScanner{},
		datarest.CustomerProfilesScanner{},
		datarest.WorkSpacesWebScanner{},
		datarest.CodeBuildScanner{},
		datarest.XRayScanner{},
		datarest.MGNScanner{},
		datarest.KendraScanner{},

		// data in transit
		transit.ALBScanner{},
		transit.NLBScanner{},
		transit.APIGWRestScanner{},
		transit.APIGWHTTPScanner{},
		transit.CloudFrontScanner{},
		transit.ElastiCacheTransitScanner{},
		transit.DocumentDBTransitScanner{},
		transit.RDSTransitScanner{},
		transit.AuroraTransitScanner{},
		transit.OpenSearchTransitScanner{},
		transit.MSKTransitScanner{},
		transit.RedshiftTransitScanner{},
		transit.NeptuneTransitScanner{},
		transit.EKSScanner{},
		transit.ECSScanner{},
		transit.LambdaScanner{},
		transit.AppSyncScanner{},
		transit.IoTCoreScanner{},
		transit.TransferFamilyScanner{},
		transit.VPNScanner{},
		transit.DirectConnectScanner{},
		transit.GlobalAcceleratorScanner{},
		transit.ClientVPNScanner{},
		transit.VPCLatticeScanner{},
		transit.ClassicELBScanner{},
		transit.AppMeshScanner{},
		transit.DirectoryServiceScanner{},

		// runtime evidence
		runtime.CloudTrailEvidenceScanner{},
	}
}

// liveScannerNames returns the deduplicated Name() set of every registered
// scanner, failing on any duplicate (which would mask a missing scanner).
func liveScannerNames(t *testing.T) map[string]bool {
	t.Helper()
	names := make(map[string]bool)
	for _, s := range liveScanners() {
		n := s.Name()
		if n == "" {
			t.Errorf("scanner %T returned empty Name()", s)
		}
		if names[n] {
			t.Errorf("duplicate registered scanner Name() %q", n)
		}
		names[n] = true
	}
	return names
}

// templateByService indexes Templates() by Service for O(1) lookup and asserts
// there are no duplicate Service entries in the template set (a duplicate would
// silently double-generate one service and could mask a missing one).
func templateByService(t *testing.T) map[string]Template {
	t.Helper()
	idx := make(map[string]Template)
	for _, tpl := range Templates() {
		if _, dup := idx[tpl.Service]; dup {
			t.Errorf("duplicate mock Template for service %q", tpl.Service)
		}
		idx[tpl.Service] = tpl
	}
	return idx
}

// TestMockCoverageNoDrift is the drift guard: every registered scanner Name()
// MUST have a corresponding mock Template. Before this test existed, Templates()
// covered only ~60 of the 99 registered scanners, so --mock and every mock-driven
// e2e silently skipped 39 services. This test FAILS the build the moment mock
// coverage drops below 100%, so it can never silently drift again.
func TestMockCoverageNoDrift(t *testing.T) {
	names := liveScannerNames(t)
	tmpls := templateByService(t)

	missing := make([]string, 0)
	for name := range names {
		if _, ok := tmpls[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("MOCK COVERAGE DRIFT: %d/%d registered scanners have NO mock Template: %v\n"+
			"Add a Template{Service:<Name()>, ...} for each in internal/mock/templates.go.",
			len(missing), len(names), missing)
	}

	// 100%% coverage means at least one template per scanner.
	if len(tmpls) < len(names) {
		t.Errorf("mock has %d distinct service templates but %d scanners are registered; coverage must be >=100%%",
			len(tmpls), len(names))
	}
}

// TestMockNoOrphanTemplates guards the reverse direction: a Template whose
// Service matches NO registered scanner generates assets for a service that
// cannot exist in a real scan (e.g. the old stale "kms" template, which never
// had a scanner — the real ones are kms_spec/kms_usage/kms_rotation). Such
// orphans pollute mock output and hide the fact that a real scanner is missing
// a template, so they are an error.
func TestMockNoOrphanTemplates(t *testing.T) {
	registered := liveScannerNames(t)

	for _, tpl := range Templates() {
		if !registered[tpl.Service] {
			t.Errorf("orphan mock Template: service %q has no registered scanner Name(); "+
				"remove it or correct it to a real scanner identifier", tpl.Service)
		}
	}
}

// TestMockTemplatesWellFormed asserts each Template is internally valid: a known
// Category, a non-empty ResourceType/NamePattern, and a posture distribution that
// does not OVER-commit (sum <= 100; the residual rolls to PostureUnknown in
// PostureFor). This keeps the synthetic data honest — a malformed distribution
// (e.g. summing >100) would make later buckets unreachable.
func TestMockTemplatesWellFormed(t *testing.T) {
	validCat := map[models.Category]bool{
		models.CategoryDataAtRest:    true,
		models.CategoryDataInTransit: true,
		models.CategoryCertificate:   true,
		models.CategoryKeyManagement: true,
		models.CategorySDKLibrary:    true,
	}
	for _, tpl := range Templates() {
		if !validCat[tpl.Category] {
			t.Errorf("template %q: unknown Category %q", tpl.Service, tpl.Category)
		}
		if tpl.ResourceType == "" {
			t.Errorf("template %q: empty ResourceType", tpl.Service)
		}
		if tpl.NamePattern == "" {
			t.Errorf("template %q: empty NamePattern", tpl.Service)
		}
		sum := tpl.PctNoEncryption + tpl.PctLegacyTLS + tpl.PctNonPQCClassical +
			tpl.PctPQCHybrid + tpl.PctSymmetricOnly
		if sum < 0 || sum > 100 {
			t.Errorf("template %q: posture distribution sums to %d, want 0..100", tpl.Service, sum)
		}
	}
}
