package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/aws-samples/cryptamap/internal/merge"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// compileCDXSchema compiles the official CycloneDX 1.7 JSON Schema bundled at
// testdata/schemas/, skipping the test if the schema is not present. Shared by the
// single-scan and merged-org-artifact validation tests.
func compileCDXSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	schemaPath := filepath.Join(repoRoot, "testdata", "schemas", "cdx-bom-1.7.schema.json")

	if _, err := os.Stat(schemaPath); err != nil {
		// CI sets CRYPTAMAP_REQUIRE_SCHEMA=1 so a missing vendored bundle is a hard
		// failure rather than a silent skip — otherwise CI could stay green while
		// never validating CBOM schema conformance. The schema is committed under
		// testdata/schemas/, so an absence in CI means a broken checkout/vendor and
		// MUST fail. Locally (no env var) we keep the graceful skip.
		if os.Getenv("CRYPTAMAP_REQUIRE_SCHEMA") == "1" {
			t.Fatalf("schema not present at %s; CRYPTAMAP_REQUIRE_SCHEMA=1 forbids skipping (run scripts/fetch-schema.sh to vendor it)", schemaPath)
		}
		t.Skipf("schema not present at %s; skipping (run scripts/fetch-schema.sh, or set CRYPTAMAP_REQUIRE_SCHEMA=1 to require it)", schemaPath)
	}

	compiler := jsonschema.NewCompiler()
	addLocal := func(uri, local string) {
		f, err := os.Open(filepath.Join(repoRoot, "testdata", "schemas", local))
		if err != nil {
			t.Fatalf("open %s: %v", local, err)
		}
		t.Cleanup(func() { f.Close() })
		if err := compiler.AddResource(uri, f); err != nil {
			t.Fatalf("AddResource %s: %v", uri, err)
		}
	}
	addLocal("http://cyclonedx.org/schema/bom-1.7.schema.json", "cdx-bom-1.7.schema.json")
	addLocal("http://cyclonedx.org/schema/spdx.schema.json", "spdx.schema.json")
	addLocal("http://cyclonedx.org/schema/jsf-0.82.schema.json", "jsf-0.82.schema.json")
	addLocal("http://cyclonedx.org/schema/cryptography-defs.schema.json", "cryptography-defs.schema.json")
	schema, err := compiler.Compile("http://cyclonedx.org/schema/bom-1.7.schema.json")
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return schema
}

// validateCBOM marshals the BOM and validates it against the compiled schema.
func validateCBOM(t *testing.T, schema *jsonschema.Schema, bom CDXBOM) {
	t.Helper()
	raw, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal CBOM: %v", err)
	}
	var any interface{}
	if err := json.Unmarshal(raw, &any); err != nil {
		t.Fatalf("unmarshal CBOM: %v", err)
	}
	if err := schema.Validate(any); err != nil {
		t.Fatalf("CycloneDX 1.7 validation failed: %v", err)
	}
}

// TestCycloneDXSchemaValidation validates a generated CBOM against the
// official CycloneDX 1.7 JSON Schema bundled at testdata/schemas/cdx-bom-1.7.schema.json.
// The sample scan deliberately includes the live shapes that previously failed
// validation: a TLS protocol component carrying the non-schema ProtocolProperties
// Source field, and a Lambda-style component with empty CryptoProperties{}.
func TestCycloneDXSchemaValidation(t *testing.T) {
	schema := compileCDXSchema(t)
	validateCBOM(t, schema, buildCBOM(sampleScan(t)))
}

// TestCycloneDXSchemaValidationMerged validates the MERGED org-artifact path:
// it merges multiple per-account shards (each carrying the TLS-Source and empty-
// Lambda shapes) into a single org envelope and validates the merged CBOM against
// the schema, so the org-wide artifact is guaranteed schema-valid too.
func TestCycloneDXSchemaValidationMerged(t *testing.T) {
	schema := compileCDXSchema(t)

	shardA := sampleScan(t)
	shardA.AccountID = "111111111111"
	shardB := sampleScan(t)
	shardB.AccountID = "222222222222"
	// Distinct BomRefs per shard so the merge keeps every component (the dedup
	// keys on BomRef); sampleScan already uses fresh UUID BomRefs per call.

	res := merge.Merge([]models.ScanResult{shardA, shardB}, "999999999999")
	validateCBOM(t, schema, buildCBOM(res.Merged))
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	return f
}

// findComponent returns the first component whose bom-ref or name contains sub.
func findComponentByService(t *testing.T, bom CDXBOM, service string) CDXComponent {
	t.Helper()
	for _, c := range bom.Components {
		for _, p := range c.Properties {
			if p.Name == "cryptamap:service" && p.Value == service {
				return c
			}
		}
	}
	t.Fatalf("no component with cryptamap:service=%q", service)
	return CDXComponent{}
}

func propValue(c CDXComponent, name string) (string, bool) {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}

// TestFriendlyTaxonomyProperties asserts each component carries the friendly
// taxonomy as cryptamap: properties and that the component Name uses the friendly
// DisplayName (not the raw scanner ID). It also asserts the raw service ID is
// still present for traceability.
func TestFriendlyTaxonomyProperties(t *testing.T) {
	bom := buildCBOM(sampleScan(t))

	kms := findComponentByService(t, bom, "kms")
	if got, _ := propValue(kms, "cryptamap:displayName"); got != "AWS KMS" {
		t.Errorf("kms cryptamap:displayName=%q, want %q", got, "AWS KMS")
	}
	if got, _ := propValue(kms, "cryptamap:awsCategory"); got != "Security, Identity & Compliance" {
		t.Errorf("kms cryptamap:awsCategory=%q, want %q", got, "Security, Identity & Compliance")
	}
	if got, _ := propValue(kms, "cryptamap:cryptoFunction"); got != "key-management" {
		t.Errorf("kms cryptamap:cryptoFunction=%q, want %q", got, "key-management")
	}
	if got, _ := propValue(kms, "cryptamap:subAspect"); got == "" {
		t.Errorf("kms cryptamap:subAspect empty, want non-empty")
	}
	// Component Name must use the friendly DisplayName, never the scanner ID.
	if want := "AWS KMS — kms-key-0"; kms.Name != want {
		t.Errorf("kms component Name=%q, want %q", kms.Name, want)
	}
	// Raw service ID retained for traceability.
	if got, _ := propValue(kms, "cryptamap:service"); got != "kms" {
		t.Errorf("kms cryptamap:service=%q, want %q", got, "kms")
	}

	alb := findComponentByService(t, bom, "alb")
	if got, _ := propValue(alb, "cryptamap:displayName"); got != "Application Load Balancer" {
		t.Errorf("alb cryptamap:displayName=%q, want %q", got, "Application Load Balancer")
	}
	if got, _ := propValue(alb, "cryptamap:cryptoFunction"); got != "data-in-transit" {
		t.Errorf("alb cryptamap:cryptoFunction=%q, want %q", got, "data-in-transit")
	}
}

// TestKnowledgeProvenanceMetadata asserts every CBOM records the active PQC-
// knowledge freshness/provenance as knowledge: namespaced metadata properties
// (so the dashboard freshness badge + air-gapped/downstream consumers can read
// how fresh the knowledge was at scan time). Guards against a future change
// silently dropping the provenance block.
func TestKnowledgeProvenanceMetadata(t *testing.T) {
	bom := buildCBOM(sampleScan(t))

	metaProp := func(name string) (string, bool) {
		for _, p := range bom.Metadata.Properties {
			if p.Name == name {
				return p.Value, true
			}
		}
		return "", false
	}

	// The seven always-present knowledge: keys must all be set and non-empty.
	for _, key := range []string{
		"knowledge:source", "knowledge:version", "knowledge:asOf",
		"knowledge:minAsOf", "knowledge:maxAsOf", "knowledge:factCount", "knowledge:digest",
	} {
		v, ok := metaProp(key)
		if !ok {
			t.Errorf("CBOM metadata missing %q", key)
			continue
		}
		if v == "" {
			t.Errorf("CBOM metadata %q is empty", key)
		}
	}

	// source must be the embedded baseline in a test binary with no override env.
	if v, _ := metaProp("knowledge:source"); v != "embedded" {
		t.Errorf("knowledge:source=%q, want embedded (no override set in test)", v)
	}
	// digest must look like the sha256-prefixed knowledge digest.
	if v, _ := metaProp("knowledge:digest"); !strings.HasPrefix(v, "sha256:") {
		t.Errorf("knowledge:digest=%q, want sha256: prefix", v)
	}
	// factCount must be a positive integer.
	if v, _ := metaProp("knowledge:factCount"); v == "0" || v == "" {
		t.Errorf("knowledge:factCount=%q, want a positive count", v)
	}
}

// TestDeeperCryptoDetailProperties asserts the additive deeper-detail fields are
// emitted as flat cryptamap: properties (since the CDX schema forbids them inside
// cryptoProperties) AND that they are NOT present inside the marshaled
// cryptoProperties sub-objects.
func TestDeeperCryptoDetailProperties(t *testing.T) {
	bom := buildCBOM(sampleScan(t))

	kms := findComponentByService(t, bom, "kms")
	if got, _ := propValue(kms, "cryptamap:algorithmName"); got != "AES-256-GCM" {
		t.Errorf("kms cryptamap:algorithmName=%q, want %q", got, "AES-256-GCM")
	}
	if got, _ := propValue(kms, "cryptamap:keySizeBits"); got != "256" {
		t.Errorf("kms cryptamap:keySizeBits=%q, want %q", got, "256")
	}
	if got, _ := propValue(kms, "cryptamap:kmsKeySpec"); got != "SYMMETRIC_DEFAULT" {
		t.Errorf("kms cryptamap:kmsKeySpec=%q, want %q", got, "SYMMETRIC_DEFAULT")
	}
	// Canonical CycloneDX fields must remain inside cryptoProperties.
	if kms.CryptoProperties == nil || kms.CryptoProperties.AlgorithmProperties == nil {
		t.Fatalf("kms cryptoProperties.algorithmProperties missing")
	}
	if kms.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "256" {
		t.Errorf("kms parameterSetIdentifier lost during sanitize")
	}
	// The non-schema custom fields must be stripped from the marshaled struct.
	if kms.CryptoProperties.AlgorithmProperties.KMSKeySpec != "" {
		t.Errorf("kms KMSKeySpec leaked into cryptoProperties (schema-forbidden)")
	}
	if kms.CryptoProperties.AlgorithmProperties.AlgorithmName != "" {
		t.Errorf("kms AlgorithmName leaked into cryptoProperties (schema-forbidden)")
	}
	if kms.CryptoProperties.AlgorithmProperties.KeySizeBits != 0 {
		t.Errorf("kms KeySizeBits leaked into cryptoProperties (schema-forbidden)")
	}

	alb := findComponentByService(t, bom, "alb")
	if got, _ := propValue(alb, "cryptamap:keyExchangeGroup"); got != "X25519MLKEM768" {
		t.Errorf("alb cryptamap:keyExchangeGroup=%q, want %q", got, "X25519MLKEM768")
	}
	if got, _ := propValue(alb, "cryptamap:pqcHybrid"); got != "true" {
		t.Errorf("alb cryptamap:pqcHybrid=%q, want %q", got, "true")
	}
	if got, _ := propValue(alb, "cryptamap:certSignatureAlgorithm"); got != "sha256WithRSAEncryption" {
		t.Errorf("alb cryptamap:certSignatureAlgorithm=%q, want %q", got, "sha256WithRSAEncryption")
	}
	if got, _ := propValue(alb, "cryptamap:certKeySizeBits"); got != "2048" {
		t.Errorf("alb cryptamap:certKeySizeBits=%q, want %q", got, "2048")
	}
	// Canonical protocol fields preserved; custom fields stripped from struct.
	if alb.CryptoProperties == nil || alb.CryptoProperties.ProtocolProperties == nil {
		t.Fatalf("alb cryptoProperties.protocolProperties missing")
	}
	if alb.CryptoProperties.ProtocolProperties.Version != "1.3" {
		t.Errorf("alb protocol version lost during sanitize")
	}
	if alb.CryptoProperties.ProtocolProperties.KeyExchangeGroup != "" {
		t.Errorf("alb KeyExchangeGroup leaked into cryptoProperties (schema-forbidden)")
	}
	if alb.CryptoProperties.ProtocolProperties.PQCHybrid {
		t.Errorf("alb PQCHybrid leaked into cryptoProperties (schema-forbidden)")
	}
}

// TestSanitizeDoesNotMutateInput asserts buildCBOM does not mutate the caller's
// asset cryptoProperties (sanitize works on a copy).
func TestSanitizeDoesNotMutateInput(t *testing.T) {
	scan := sampleScan(t)
	// Find the kms asset in the input and snapshot its custom field.
	var idx = -1
	for i, a := range scan.Assets {
		if a.Service == "kms" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("kms asset not found in sample scan")
	}
	_ = buildCBOM(scan)
	if scan.Assets[idx].CryptoProps.AlgorithmProperties.KMSKeySpec != "SYMMETRIC_DEFAULT" {
		t.Errorf("buildCBOM mutated the input asset's KMSKeySpec")
	}
}

func sampleScan(t *testing.T) models.ScanResult {
	t.Helper()
	now := time.Now().UTC()
	return models.ScanResult{
		ScanID:      uuid.NewString(),
		AccountID:   "123456789012",
		Region:      "ap-south-1",
		StartedAt:   now.Add(-time.Second),
		CompletedAt: now,
		Mode:        "test",
		ToolVersion: "1.0.0",
		Assets: []models.CryptoAsset{
			{
				BomRef:       "crypto-" + uuid.NewString(),
				Name:         "test-bucket",
				Service:      "s3",
				Category:     models.CategoryDataAtRest,
				AccountID:    "123456789012",
				Region:       "ap-south-1",
				ResourceID:   "test-bucket",
				ResourceType: "AWS::S3::Bucket",
				DiscoveredAt: now,
				CryptoProps: models.CryptoProperties{
					AssetType: models.AssetTypeAlgorithm,
					AlgorithmProperties: &models.AlgorithmProperties{
						Primitive:                models.PrimitiveAE,
						Mode:                     "gcm",
						ParameterSetIdentifier:   "256",
						ClassicalSecurityLevel:   256,
						NistQuantumSecurityLevel: 5, // AES-256 anchors NIST Category 5
					},
				},
			},
			// KMS at-rest asset carrying the deeper algorithm detail (algorithmName,
			// keySizeBits, kmsKeySpec) so the schema test exercises sanitizeForCDX.
			{
				BomRef:       "crypto-" + uuid.NewString(),
				Name:         "kms-key-0",
				Service:      "kms",
				Category:     models.CategoryKeyManagement,
				AccountID:    "123456789012",
				Region:       "ap-south-1",
				ResourceID:   "kms-key-0",
				ResourceType: "AWS::KMS::Key",
				DiscoveredAt: now,
				CryptoProps: models.CryptoProperties{
					AssetType: models.AssetTypeAlgorithm,
					AlgorithmProperties: &models.AlgorithmProperties{
						Primitive:                models.PrimitiveAE,
						Mode:                     "gcm",
						ParameterSetIdentifier:   "256",
						ClassicalSecurityLevel:   256,
						NistQuantumSecurityLevel: 5, // AES-256 anchors NIST Category 5
						AlgorithmName:            "AES-256-GCM",
						KeySizeBits:              256,
						KMSKeySpec:               "SYMMETRIC_DEFAULT",
					},
				},
			},
			// TLS in-transit asset carrying the deeper protocol detail (keyExchangeGroup,
			// pqcHybrid, certSignatureAlgorithm, certKeySizeBits).
			{
				BomRef:       "crypto-" + uuid.NewString(),
				Name:         "alb-0",
				Service:      "alb",
				Category:     models.CategoryDataInTransit,
				AccountID:    "123456789012",
				Region:       "ap-south-1",
				ResourceID:   "alb-0",
				ResourceType: "AWS::ElasticLoadBalancingV2::LoadBalancer",
				DiscoveredAt: now,
				CryptoProps: models.CryptoProperties{
					AssetType: models.AssetTypeProtocol,
					ProtocolProperties: &models.ProtocolProperties{
						Type:    "tls",
						Version: "1.3",
						CipherSuites: []models.CipherSuite{{
							Name:       "TLS_AES_256_GCM_SHA384",
							Algorithms: []string{"TLS_AES_256_GCM_SHA384"},
						}},
						KeyExchangeGroup:       "X25519MLKEM768",
						PQCHybrid:              true,
						CertSignatureAlgorithm: "sha256WithRSAEncryption",
						CertKeySizeBits:        2048,
						// Source is the non-schema provenance field the live TLS scanners
						// set. protocolProperties is additionalProperties:false in CDX 1.7,
						// so it MUST be stripped by sanitizeForCDX or the CBOM fails schema
						// validation (the provenance survives as cryptamap:source).
						Source: "observed",
					},
				},
			},
			// Lambda-style asset: the runtime scanner exposes no observable crypto, so
			// it emits an EMPTY models.CryptoProperties{} (assetType==""). The CDX 1.7
			// cryptoProperties node REQUIRES a non-empty assetType enum, so buildCBOM
			// must OMIT the cryptoProperties object entirely here (the posture stays
			// 'unknown' via the component's cryptamap:* properties) — otherwise the
			// emitted {assetType:""} is schema-invalid.
			{
				BomRef:       "crypto-" + uuid.NewString(),
				Name:         "fn-0",
				Service:      "lambda_runtime",
				Category:     models.CategorySDKLibrary,
				AccountID:    "123456789012",
				Region:       "ap-south-1",
				ResourceID:   "fn-0",
				ResourceType: "AWS::Lambda::Function",
				DiscoveredAt: now,
				CryptoProps:  models.CryptoProperties{},
				Properties: map[string]string{
					"posture":      "unknown",
					"functionName": "fn-0",
					"runtime":      "provided.al2023",
				},
			},
		},
	}
}
