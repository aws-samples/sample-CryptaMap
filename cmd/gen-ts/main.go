// Command gen-ts is CryptaMap's single-source-of-truth TypeScript type
// generator. It reflects the canonical Go wire structs (pkg/models,
// internal/roadmap, internal/output) and the verified enum vocabularies
// (pkg/models, internal/pqc) and emits dashboard/src/types/generated.ts.
//
// It is deterministic, stdlib-only, and fully offline: it imports the
// first-party packages directly (already in the module graph) and reflects
// their exported structs, so any field rename, retag, add or removal in Go
// surfaces as a diff in generated.ts. CI runs `make generate-types` and
// `git diff --exit-code` to fail the build if the checked-in file is stale.
//
// Reflection is used for STRUCT SHAPE (field names taken verbatim from the
// json tag, optionality from `omitempty`/pointer/slice/map, types from the Go
// kind) so the struct surface can never silently drift. ENUM VOCABULARIES are
// listed explicitly from the Go consts (reflection cannot enumerate a string
// type's const members) and are guarded by enumGuard() which fails the
// generator if the named enum types ever stop being plain `string`.
package main

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/roadmap"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// outFile is the generated TS target. The hand-written index.ts/roadmap.ts
// re-export from it so all existing dashboard imports keep working.
const outFile = "dashboard/src/types/generated.ts"

// tsEnum is a named string-literal union emitted to TS. Members are the
// authoritative wire strings from the Go consts.
type tsEnum struct {
	Name    string
	Doc     string
	Members []string
	// goType is the Go type whose underlying kind is asserted to be string,
	// so a future change away from `string` fails generation loudly.
	goType reflect.Type
}

// tsStruct is one Go struct to reflect into a TS interface.
type tsStruct struct {
	Name string // TS interface name
	Doc  string
	rt   reflect.Type
}

func main() {
	enums := []tsEnum{
		{
			Name:    "Severity",
			Doc:     "Canonical severity (pkg/models/finding.go Severity).",
			goType:  reflect.TypeOf(models.Severity("")),
			Members: []string{string(models.SeverityCritical), string(models.SeverityHigh), string(models.SeverityMedium), string(models.SeverityInformational)},
		},
		{
			Name:    "CryptoPosture",
			Doc:     "Encryption posture (pkg/models/finding.go CryptoPosture).",
			goType:  reflect.TypeOf(models.CryptoPosture("")),
			Members: []string{string(models.PostureNoEncryption), string(models.PostureLegacyTLS), string(models.PostureNonPQCClassical), string(models.PostureSymmetricOnly), string(models.PosturePQCHybrid), string(models.PosturePQCReady), string(models.PostureUnknown)},
		},
		{
			Name:    "Category",
			Doc:     "Asset surface category (pkg/models/asset.go Category).",
			goType:  reflect.TypeOf(models.Category("")),
			Members: []string{string(models.CategoryDataAtRest), string(models.CategoryDataInTransit), string(models.CategoryCertificate), string(models.CategoryKeyManagement), string(models.CategorySDKLibrary)},
		},
		{
			Name:    "AssetType",
			Doc:     "CycloneDX 1.7 cryptoProperties.assetType (pkg/models/asset.go AssetType).",
			goType:  reflect.TypeOf(models.AssetType("")),
			Members: []string{string(models.AssetTypeAlgorithm), string(models.AssetTypeCertificate), string(models.AssetTypeProtocol), string(models.AssetTypeRelatedMaterial)},
		},
		{
			Name:    "AlgorithmPrimitive",
			Doc:     "CycloneDX 1.7 algorithmProperties.primitive (pkg/models/asset.go AlgorithmPrimitive).",
			goType:  reflect.TypeOf(models.AlgorithmPrimitive("")),
			Members: []string{string(models.PrimitiveAE), string(models.PrimitiveBlockCipher), string(models.PrimitiveKEM), string(models.PrimitiveSignature), string(models.PrimitiveHash), string(models.PrimitiveKeyAgree), string(models.PrimitiveKDF), string(models.PrimitiveMAC)},
		},
		{
			Name:    "CryptoState",
			Doc:     "Material lifecycle state (pkg/models/asset.go CryptoState).",
			goType:  reflect.TypeOf(models.CryptoState("")),
			Members: []string{string(models.StateActive), string(models.StateSuspended), string(models.StateDestroyed), string(models.StateUnknown)},
		},
		{
			Name:    "PQCStatus",
			Doc:     "PQC readiness status (internal/pqc/matrix.go PQCStatus).",
			goType:  reflect.TypeOf(pqc.PQCStatus("")),
			Members: []string{string(pqc.StatusAvailable), string(pqc.StatusHybridTLSOnly), string(pqc.StatusNotYet), string(pqc.StatusNotApplicable), string(pqc.StatusNotEncrypted)},
		},
		{
			Name:    "UpgradeEase",
			Doc:     "Effort to enable PQC (internal/pqc/matrix.go UpgradeEase).",
			goType:  reflect.TypeOf(pqc.UpgradeEase("")),
			Members: []string{string(pqc.EaseOneFlip), string(pqc.EaseConfigChange), string(pqc.EaseAppChange), string(pqc.EaseAWSManagedAuto), string(pqc.EaseNoneAvailable)},
		},
		{
			Name:    "Confidence",
			Doc:     "Matrix verification confidence (internal/pqc/matrix.go Confidence).",
			goType:  reflect.TypeOf(pqc.Confidence("")),
			Members: []string{string(pqc.ConfHigh), string(pqc.ConfMedium), string(pqc.ConfLow)},
		},
		{
			Name:    "SymmetricStrength",
			Doc:     "Symmetric-cipher strength tier (internal/pqc/primitives.go SymmetricStrength). Additive to PQCStatus.",
			goType:  reflect.TypeOf(pqc.SymmetricStrength("")),
			Members: []string{string(pqc.StrengthSafe), string(pqc.StrengthReview), string(pqc.StrengthWeak), string(pqc.StrengthUnconfirmed)},
		},
		{
			Name:    "ComplianceStatus",
			Doc:     "ComplianceMapping.status vocabulary (pkg/models/finding.go ComplianceMapping).",
			goType:  reflect.TypeOf(""), // not a named Go type; literal vocabulary
			Members: []string{"compliant", "non-compliant", "partial", "informational"},
		},
	}

	// enumTypeOverride maps a Go named string type to the TS enum name to use
	// for fields of that type, so e.g. a field `Severity models.Severity`
	// emits `severity: Severity` instead of `string`.
	enumTypeOverride := map[string]string{
		"models.Severity":           "Severity",
		"models.CryptoPosture":      "CryptoPosture",
		"models.Category":           "Category",
		"models.AssetType":          "AssetType",
		"models.AlgorithmPrimitive": "AlgorithmPrimitive",
		"models.CryptoState":        "CryptoState",
		"pqc.PQCStatus":             "PQCStatus",
		"pqc.UpgradeEase":           "UpgradeEase",
		"pqc.Confidence":            "Confidence",
		"pqc.SymmetricStrength":     "SymmetricStrength",
	}

	structs := []tsStruct{
		// pkg/models — scan/finding surface
		{Name: "MoscaScore", Doc: "pkg/models/finding.go MoscaScore.", rt: reflect.TypeOf(models.MoscaScore{})},
		{Name: "ComplianceMapping", Doc: "pkg/models/finding.go ComplianceMapping.", rt: reflect.TypeOf(models.ComplianceMapping{})},
		{Name: "Finding", Doc: "pkg/models/finding.go Finding.", rt: reflect.TypeOf(models.Finding{})},
		{Name: "ScanSummary", Doc: "pkg/models/scan.go ScanSummary.", rt: reflect.TypeOf(models.ScanSummary{})},
		{Name: "ServiceScanReport", Doc: "pkg/models/scan.go ServiceScanReport.", rt: reflect.TypeOf(models.ServiceScanReport{})},
		{Name: "ScanResult", Doc: "pkg/models/scan.go ScanResult.", rt: reflect.TypeOf(models.ScanResult{})},
		{Name: "MultiScanResult", Doc: "pkg/models/scan.go MultiScanResult.", rt: reflect.TypeOf(models.MultiScanResult{})},
		// pkg/models — CBOM cryptoProperties surface
		{Name: "AlgorithmProperties", Doc: "pkg/models/asset.go AlgorithmProperties.", rt: reflect.TypeOf(models.AlgorithmProperties{})},
		{Name: "CertificateProperties", Doc: "pkg/models/asset.go CertificateProperties.", rt: reflect.TypeOf(models.CertificateProperties{})},
		{Name: "CipherSuite", Doc: "pkg/models/asset.go CipherSuite.", rt: reflect.TypeOf(models.CipherSuite{})},
		{Name: "ProtocolProperties", Doc: "pkg/models/asset.go ProtocolProperties.", rt: reflect.TypeOf(models.ProtocolProperties{})},
		{Name: "RelatedCryptoMaterialProperties", Doc: "pkg/models/asset.go RelatedCryptoMaterialProperties.", rt: reflect.TypeOf(models.RelatedCryptoMaterialProperties{})},
		{Name: "CryptoProperties", Doc: "pkg/models/asset.go CryptoProperties.", rt: reflect.TypeOf(models.CryptoProperties{})},
		{Name: "CryptoAsset", Doc: "pkg/models/asset.go CryptoAsset (raw discovered asset record).", rt: reflect.TypeOf(models.CryptoAsset{})},
		// internal/output — CycloneDX CBOM wire shapes
		{Name: "CDXTool", Doc: "internal/output/cyclonedx.go CDXTool.", rt: reflect.TypeOf(output.CDXTool{})},
		{Name: "CDXMetaComp", Doc: "internal/output/cyclonedx.go CDXMetaComp.", rt: reflect.TypeOf(output.CDXMetaComp{})},
		{Name: "CDXProperty", Doc: "internal/output/cyclonedx.go CDXProperty.", rt: reflect.TypeOf(output.CDXProperty{})},
		{Name: "CDXMetadata", Doc: "internal/output/cyclonedx.go CDXMetadata.", rt: reflect.TypeOf(output.CDXMetadata{})},
		{Name: "CDXComponent", Doc: "internal/output/cyclonedx.go CDXComponent.", rt: reflect.TypeOf(output.CDXComponent{})},
		{Name: "CDXBOM", Doc: "internal/output/cyclonedx.go CDXBOM (top-level CycloneDX 1.7 CBOM).", rt: reflect.TypeOf(output.CDXBOM{})},
		// internal/roadmap — roadmap surface
		{Name: "RoadmapItem", Doc: "internal/roadmap/roadmap.go RoadmapItem.", rt: reflect.TypeOf(roadmap.RoadmapItem{})},
		{Name: "ServiceRollup", Doc: "internal/roadmap/roadmap.go ServiceRollup.", rt: reflect.TypeOf(roadmap.ServiceRollup{})},
		{Name: "AccountRollup", Doc: "internal/roadmap/roadmap.go AccountRollup.", rt: reflect.TypeOf(roadmap.AccountRollup{})},
		{Name: "Roadmap", Doc: "internal/roadmap/roadmap.go Roadmap (top-level roadmap envelope).", rt: reflect.TypeOf(roadmap.Roadmap{})},
	}

	// fieldTypeOverride narrows specific struct fields whose Go type is a plain
	// `string` but whose wire vocabulary is a known closed set, keyed by
	// "GoStructName.jsonKey". This keeps the union authoritative + generated
	// rather than hand-edited downstream.
	fieldTypeOverride := map[string]string{
		"ComplianceMapping.status": "ComplianceStatus",
	}

	g := &gen{enumTypeOverride: enumTypeOverride, fieldTypeOverride: fieldTypeOverride}
	for _, e := range enums {
		g.enumGuard(e)
	}

	var b bytes.Buffer
	writeHeader(&b)
	for _, e := range enums {
		g.writeEnum(&b, e)
	}
	for _, s := range structs {
		g.writeStruct(&b, s)
	}
	if len(g.errs) > 0 {
		fmt.Fprintln(os.Stderr, "gen-ts: type model assertions failed:")
		for _, e := range g.errs {
			fmt.Fprintln(os.Stderr, "  - "+e)
		}
		os.Exit(1)
	}

	out := b.Bytes()
	if err := os.WriteFile(outFile, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-ts: write %s: %v\n", outFile, err)
		os.Exit(1)
	}
	fmt.Printf("gen-ts: wrote %s (%d enums, %d interfaces)\n", outFile, len(enums), len(structs))
}

type gen struct {
	enumTypeOverride  map[string]string
	fieldTypeOverride map[string]string
	errs              []string
}

// enumGuard fails generation if a named enum type stops being a plain string.
func (g *gen) enumGuard(e tsEnum) {
	if e.goType == nil {
		return
	}
	if e.goType.Kind() != reflect.String {
		g.errs = append(g.errs, fmt.Sprintf("enum %s: backing Go type %s is %s, expected string", e.Name, e.goType.String(), e.goType.Kind()))
	}
}

func writeHeader(b *bytes.Buffer) {
	// Canonical Go-style "Code generated ... DO NOT EDIT." header so tooling
	// (and humans) recognize the file as generated.
	fmt.Fprintf(b, "// Code generated by gen-ts; DO NOT EDIT.\n")
	fmt.Fprintf(b, "//\n")
	fmt.Fprintf(b, "// Single source of truth: the Go wire structs in pkg/models, internal/roadmap,\n")
	fmt.Fprintf(b, "// internal/output and the enum vocabularies in pkg/models + internal/pqc.\n")
	fmt.Fprintf(b, "// Regenerate with `make generate-types` (runs `go run ./cmd/gen-ts`). CI fails\n")
	fmt.Fprintf(b, "// if this file is stale (regenerate + git diff --exit-code).\n")
	fmt.Fprintf(b, "//\n")
	fmt.Fprintf(b, "// Field names are the Go json tags verbatim; `?` optionality mirrors\n")
	fmt.Fprintf(b, "// json `omitempty` / pointer / slice / map fields.\n")
	fmt.Fprintf(b, "\n")
	// No timestamp emitted: output stays deterministic for git diff --exit-code.
}

func (g *gen) writeEnum(b *bytes.Buffer, e tsEnum) {
	if e.Doc != "" {
		fmt.Fprintf(b, "/** %s */\n", e.Doc)
	}
	parts := make([]string, len(e.Members))
	for i, m := range e.Members {
		parts[i] = "'" + m + "'"
	}
	fmt.Fprintf(b, "export type %s = %s;\n\n", e.Name, strings.Join(parts, " | "))
}

func (g *gen) writeStruct(b *bytes.Buffer, s tsStruct) {
	if s.Doc != "" {
		fmt.Fprintf(b, "/** %s */\n", s.Doc)
	}
	fmt.Fprintf(b, "export interface %s {\n", s.Name)
	for i := 0; i < s.rt.NumField(); i++ {
		f := s.rt.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts := parseJSONTag(tag, f.Name)
		optional := hasOpt(opts, "omitempty") || isPointer(f.Type)
		tsType := g.tsType(f.Type)
		if ov, ok := g.fieldTypeOverride[s.rt.Name()+"."+name]; ok {
			tsType = ov
		}
		q := ""
		if optional {
			q = "?"
		}
		// Quote keys that are not valid bare TS identifiers (e.g. bom-ref).
		key := name
		if !isIdent(name) {
			key = "'" + name + "'"
		}
		fmt.Fprintf(b, "  %s%s: %s;\n", key, q, tsType)
	}
	fmt.Fprintf(b, "}\n\n")
}

// tsType maps a Go reflect.Type to a TS type expression.
func (g *gen) tsType(t reflect.Type) string {
	// Named enum override (before deref) for value-typed enums.
	if ts, ok := g.enumTypeOverride[shortName(t)]; ok {
		return ts
	}
	switch t.Kind() {
	case reflect.Ptr:
		return g.tsType(t.Elem())
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return g.tsType(t.Elem()) + "[]"
	case reflect.Map:
		return fmt.Sprintf("Record<%s, %s>", g.tsType(t.Key()), g.tsType(t.Elem()))
	case reflect.Struct:
		// time.Time serializes to an RFC3339 string.
		if t.PkgPath() == "time" && t.Name() == "Time" {
			return "string"
		}
		// Reference a sibling generated interface by its TS name.
		return t.Name()
	case reflect.Interface:
		return "unknown"
	default:
		g.errs = append(g.errs, fmt.Sprintf("unhandled Go kind %s for type %s", t.Kind(), t.String()))
		return "unknown"
	}
}

// shortName returns pkg.Type for named types (e.g. models.Severity), deref'ing
// pointers, so it can be matched against enumTypeOverride.
func shortName(t reflect.Type) string {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Name() == "" || t.PkgPath() == "" {
		return ""
	}
	pp := t.PkgPath()
	short := pp[strings.LastIndex(pp, "/")+1:]
	return short + "." + t.Name()
}

func parseJSONTag(tag, fallback string) (name string, opts []string) {
	if tag == "" {
		return fallback, nil
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = fallback
	}
	return name, parts[1:]
}

func hasOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

func isPointer(t reflect.Type) bool { return t.Kind() == reflect.Ptr }

// isIdent reports whether s is a valid bare TS/JS identifier (so it needs no
// quoting as an object key).
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if i > 0 {
			ok = ok || (r >= '0' && r <= '9')
		}
		if !ok {
			return false
		}
	}
	return true
}
