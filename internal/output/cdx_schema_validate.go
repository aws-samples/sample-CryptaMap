package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// This file provides a REUSABLE CycloneDX 1.7 schema validator so that any
// package's tests (e.g. the per-scanner conformance tests under
// internal/services/**) can validate the CBOM their real scan() output produces
// — not just internal/output's own tests. The bundled schema is the single
// vendored source of truth at testdata/schemas/, located relative to this
// source file via runtime.Caller so the resolution works from any caller package.

var (
	cdxSchemaOnce sync.Once
	cdxSchema     *jsonschema.Schema
	cdxSchemaErr  error
)

// schemaDir returns testdata/schemas relative to THIS source file (repo-root/
// internal/output/cdx_schema_validate.go -> repo-root/testdata/schemas).
func schemaDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "schemas")
}

// compileVendoredCDXSchema compiles the bundled CycloneDX 1.7 schema (+ its
// external $ref companions) once. Returns an error if the vendored bundle is
// missing so callers can decide whether to skip or fail.
func compileVendoredCDXSchema() (*jsonschema.Schema, error) {
	cdxSchemaOnce.Do(func() {
		dir := schemaDir()
		if _, err := os.Stat(filepath.Join(dir, "cdx-bom-1.7.schema.json")); err != nil {
			cdxSchemaErr = fmt.Errorf("vendored CDX 1.7 schema not found at %s: %w", dir, err)
			return
		}
		c := jsonschema.NewCompiler()
		add := func(uri, local string) bool {
			f, err := os.Open(filepath.Join(dir, local))
			if err != nil {
				cdxSchemaErr = fmt.Errorf("open %s: %w", local, err)
				return false
			}
			defer f.Close()
			if err := c.AddResource(uri, f); err != nil {
				cdxSchemaErr = fmt.Errorf("add %s: %w", local, err)
				return false
			}
			return true
		}
		if add("http://cyclonedx.org/schema/bom-1.7.schema.json", "cdx-bom-1.7.schema.json") &&
			add("http://cyclonedx.org/schema/spdx.schema.json", "spdx.schema.json") &&
			add("http://cyclonedx.org/schema/jsf-0.82.schema.json", "jsf-0.82.schema.json") &&
			add("http://cyclonedx.org/schema/cryptography-defs.schema.json", "cryptography-defs.schema.json") {
			cdxSchema, cdxSchemaErr = c.Compile("http://cyclonedx.org/schema/bom-1.7.schema.json")
		}
	})
	return cdxSchema, cdxSchemaErr
}

// ValidateCBOMBytes validates raw CBOM JSON against the vendored official
// CycloneDX 1.7 schema. Returns nil when valid; a descriptive error otherwise
// (including when the vendored schema bundle is absent). Reusable from any
// package's tests as the single CBOM-conformance entry point.
func ValidateCBOMBytes(raw []byte) error {
	schema, err := compileVendoredCDXSchema()
	if err != nil {
		return err
	}
	var doc interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("unmarshal CBOM: %w", err)
	}
	return schema.Validate(doc)
}

// ValidateAssetsCBOM builds a CBOM from the given assets (as one scan shard) and
// validates it against the vendored CycloneDX 1.7 schema. This is the convenient
// seam for per-scanner conformance tests: feed a scanner's real scan() output and
// assert the emitted CBOM is schema-valid.
func ValidateAssetsCBOM(assets []models.CryptoAsset) error {
	raw, err := AsBytes(models.ScanResult{
		ScanID:    "conformance",
		AccountID: "111111111111",
		Region:    "ap-south-1",
		Mode:      "test",
		Assets:    assets,
	})
	if err != nil {
		return fmt.Errorf("AsBytes: %w", err)
	}
	return ValidateCBOMBytes(raw)
}
