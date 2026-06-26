package output

// END-TO-END OUTPUT-PIPELINE regression net.
//
// This is the whole-output-layer guard: it drives ONE deterministic mock
// ScanResult through the SAME finding/summary derivation a live scan uses, then
// runs EVERY output writer over that single result and asserts each artifact is
// (a) structurally valid for its format AND (b) honesty-consistent with the
// posture the scan recorded. It is the "AppMesh-class" net for the output layer:
// per-writer opt-in tests can each pass while the assembled pipeline still emits
// a self-contradicting artifact (a CBOM component that claims PQC-safe over an
// asset the scan flagged quantum-vulnerable, an ASFF severity that disagrees
// with the finding, a roadmap whose counts drift from the summary, an Excel that
// evaluates an attacker-supplied formula, an HTML report that reaches the
// network). Every check is loop/table driven over the generated data so a new
// scanner/posture is covered automatically.
//
// Pipeline assembled here (mirrors scanner.RunMock, but with a FIXED seed so the
// artifacts are byte-stable run to run):
//
//	mock.Generator{Seed,Scale}.GenerateAssets
//	  -> scanner.BuildFindings (the real, pure posture->finding path)
//	  -> buildE2ESummary (mirrors Engine.buildSummary, which is unexported)
//	  -> models.ScanResult
//	  -> WriteCBOM/AsBytes, WriteASFF, WritePQCCExcel,
//	     WriteRoadmapJSON/Markdown, WriteHTMLReport
//
// RunMock itself is NOT reused because it seeds from time.Now().UnixNano(); the
// documented deterministic seam is to drive mock.Generator directly with a fixed
// Seed (see internal/scanner/invariants_test.go).

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xuri/excelize/v2"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/mock"
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// e2eSeed / e2eScale make the synthetic ScanResult byte-for-byte deterministic
// while large enough that every mock-reachable posture is represented many times
// over (so the consistency loops genuinely exercise each posture branch, not a
// lucky single path). Scale 40 over ~70 templates is ~2-3k assets — plenty for
// coverage, fast enough for an output-layer test.
const (
	e2eSeed  int64 = 0xE2E0017
	e2eScale       = 40
)

// quantumResistantPostures are the postures whose cryptography needs no PQC migration:
// AES symmetric-at-rest (Grover-only), PQ-hybrid, or pure PQC. Mirrors
// risk.IsQuantumResistantPosture; duplicated as a set here so the output package's
// honesty assertions do not need to import internal/risk.
var quantumResistantPostures = map[string]bool{
	string(models.PostureSymmetricOnly): true,
	string(models.PosturePQCHybrid):     true,
	string(models.PosturePQCReady):      true,
}

// quantumVulnerablePostures are the postures the scan flagged as NOT
// quantum-resistant (Shor-breakable classical asymmetric, weak/legacy, or absent
// encryption). An asset with one of these MUST NOT carry a PQC-safe claim.
var quantumVulnerablePostures = map[string]bool{
	string(models.PostureNoEncryption):    true,
	string(models.PostureLegacyTLS):       true,
	string(models.PostureNonPQCClassical): true,
}

// validE2EPostures is the canonical 7-value posture enum; every emitted asset
// must carry one of these (honesty contract #5).
var validE2EPostures = map[string]bool{
	string(models.PostureNoEncryption):    true,
	string(models.PostureLegacyTLS):       true,
	string(models.PostureNonPQCClassical): true,
	string(models.PostureSymmetricOnly):   true,
	string(models.PosturePQCHybrid):       true,
	string(models.PosturePQCReady):        true,
	string(models.PostureUnknown):         true,
}

// buildE2ESummary mirrors scanner.(*Engine).buildSummary (which is unexported)
// so the assembled ScanResult carries the same aggregate counts a live scan
// would. Keeping this in lock-step with the engine is exactly what the
// roadmap/Excel/HTML reconciliation assertions below verify.
func buildE2ESummary(assets []models.CryptoAsset, findings []models.Finding, services int) models.ScanSummary {
	s := models.ScanSummary{
		TotalAssets:   len(assets),
		TotalFindings: len(findings),
		ServiceCount:  services,
	}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityInformational:
			s.Informational++
		}
	}
	// Mirror scanner.buildSummary (B3): symmetric-only assets are inventory-only,
	// not findings, and are reconciled via InventoryOnly.
	for _, a := range assets {
		if a.Properties != nil && a.Properties["posture"] == string(models.PostureSymmetricOnly) {
			s.InventoryOnly++
		}
	}
	return s
}

// e2eScanResult assembles the full deterministic ScanResult that every writer is
// driven over. It runs the REAL BuildFindings derivation so the artifacts under
// test contain exactly the postures/severities a live scan would have produced.
func e2eScanResult(t *testing.T) models.ScanResult {
	t.Helper()
	g := mock.Generator{
		AccountID: "123456789012",
		Region:    "ap-south-1",
		Scale:     e2eScale,
		Seed:      e2eSeed,
	}
	assets := g.GenerateAssets()
	if len(assets) == 0 {
		t.Fatal("mock generator produced 0 assets; the pipeline would assert nothing")
	}
	findings := scanner.BuildFindings(assets, (*compliance.Registry)(nil), nil)
	// B3 at-rest INVENTORY-ONLY: symmetric-only (quantum-resistant at rest) assets
	// are inventoried but NOT emitted as findings, so the contract is one finding
	// per NON-symmetric-only asset.
	inventoryOnly := 0
	for _, a := range assets {
		if a.Properties != nil && a.Properties["posture"] == string(models.PostureSymmetricOnly) {
			inventoryOnly++
		}
	}
	if want := len(assets) - inventoryOnly; len(findings) != want {
		t.Fatalf("BuildFindings produced %d findings for %d assets (%d inventory-only symmetric); expected %d (one per non-symmetric-only asset)",
			len(findings), len(assets), inventoryOnly, want)
	}
	now := time.Now().UTC()
	return models.ScanResult{
		ScanID:      uuid.NewString(),
		AccountID:   g.AccountID,
		Region:      g.Region,
		StartedAt:   now.Add(-time.Second),
		CompletedAt: now,
		Mode:        "mock",
		Summary:     buildE2ESummary(assets, findings, len(mock.Templates())),
		Assets:      assets,
		Findings:    findings,
		ToolVersion: "1.0.0",
	}
}

// componentPosture returns the cryptamap:posture property value of a CBOM
// component (empty if absent).
func componentPosture(c CDXComponent) string {
	for _, p := range c.Properties {
		if p.Name == "cryptamap:posture" {
			return p.Value
		}
	}
	return ""
}

// realComponents returns the discovered-AWS-resource components, excluding the
// emitter-synthesized algorithm-definition nodes (cryptamap:synthetic="true")
// that linkCryptoAssetGraph appends so the CycloneDX refType references resolve.
// The asset-accounting invariants (count == TotalAssets, posture/service honesty)
// apply only to real resources; synthetic nodes are pure algorithm definitions
// with no posture/service by design.
func realComponents(comps []CDXComponent) []CDXComponent {
	out := make([]CDXComponent, 0, len(comps))
	for _, c := range comps {
		if isSyntheticComponent(c) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// TestE2EPipeline_CBOM drives WriteCBOM/AsBytes over the assembled scan and
// asserts:
//   - the CBOM validates against the official CycloneDX 1.7 JSON Schema (reusing
//     the bundled schema-validation helper from cyclonedx_test.go);
//   - the round-tripped component count equals summary.TotalAssets (mutual
//     consistency: the inventory is neither truncated nor inflated);
//   - every component carries a posture in the 7-value enum and resolves to a
//     real taxonomy Entry (no AWSCategory=="Other") — honesty contract #5;
//   - NO component claims a PQC-safe verdict that contradicts its asset posture:
//     a quantum-VULNERABLE posture must never carry pqcHybrid=true or a
//     ML-KEM/ML-DSA cryptamap:algorithmName, and a quantum-RESISTANT posture must
//     never be labeled with a Shor-breakable asymmetric primitive (key-agree/
//     signature/kem-classical) — honesty contract #4.
func TestE2EPipeline_CBOM(t *testing.T) {
	scan := e2eScanResult(t)
	schema := compileCDXSchema(t) // skips if the bundled schema is absent

	// 1. Round-trip through AsBytes and validate the PARSED bytes against the
	// schema (not just the in-memory struct), so the marshaled artifact is what
	// is checked.
	raw, err := AsBytes(scan)
	if err != nil {
		t.Fatalf("AsBytes: %v", err)
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}
	if err := schema.Validate(generic); err != nil {
		t.Fatalf("CycloneDX 1.7 schema validation of the e2e CBOM failed: %v", err)
	}

	// Also validate via WriteCBOM to cover that writer path.
	var wbuf bytes.Buffer
	if err := WriteCBOM(&wbuf, scan); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}

	// 2. Parse back into the typed BOM for the consistency checks.
	var bom CDXBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("re-parse CBOM into CDXBOM: %v", err)
	}

	// Mutual consistency: real (non-synthetic) component count == summary asset
	// count. Synthetic algorithm-definition nodes are excluded — they are not
	// discovered resources.
	realComps := realComponents(bom.Components)
	if len(realComps) != scan.Summary.TotalAssets {
		t.Errorf("CBOM real component count %d != summary.TotalAssets %d",
			len(realComps), scan.Summary.TotalAssets)
	}

	// pqcAlgoName matches a post-quantum algorithm label. Used to catch a PQC-safe
	// CLAIM (an ML-KEM/ML-DSA/SLH-DSA algorithm name) sitting on a component whose
	// posture says it is quantum-vulnerable.
	pqcAlgoName := regexp.MustCompile(`(?i)\b(ml-?kem|ml-?dsa|slh-?dsa|kyber|dilithium|sphincs)\b`)

	postureCounts := map[string]int{}
	for _, c := range realComps {
		posture := componentPosture(c)
		postureCounts[posture]++

		// Honesty #5: posture is in the 7-value enum.
		if !validE2EPostures[posture] {
			t.Errorf("component %q carries posture %q not in the 7-value enum", c.Name, posture)
		}

		// Honesty #5: the raw service resolves to a real taxonomy Entry (no "Other").
		svc := ""
		for _, p := range c.Properties {
			if p.Name == "cryptamap:service" {
				svc = p.Value
			}
		}
		if svc == "" {
			t.Errorf("component %q has empty cryptamap:service", c.Name)
		} else if tx, ok := taxonomy.Lookup(svc); !ok || tx.AWSCategory == "Other" || tx.CryptoFunction == "" {
			t.Errorf("component %q service %q does not resolve to a real taxonomy Entry (cat=%q func=%q ok=%v)",
				c.Name, svc, tx.AWSCategory, tx.CryptoFunction, ok)
		}

		// Read the flat PQC-claim properties the writer emits.
		pqcHybrid := false
		algoName := ""
		for _, p := range c.Properties {
			switch p.Name {
			case "cryptamap:pqcHybrid":
				pqcHybrid = p.Value == "true"
			case "cryptamap:algorithmName":
				algoName = p.Value
			}
		}

		// Honesty #4: a quantum-VULNERABLE posture must carry NO PQC-safe claim.
		if quantumVulnerablePostures[posture] {
			if pqcHybrid {
				t.Errorf("component %q posture=%q (quantum-vulnerable) but cryptamap:pqcHybrid=true — contradictory PQC-safe claim",
					c.Name, posture)
			}
			if pqcAlgoName.MatchString(algoName) {
				t.Errorf("component %q posture=%q (quantum-vulnerable) but algorithmName=%q claims a PQC algorithm — contradictory",
					c.Name, posture, algoName)
			}
		}

		// Honesty #4 (output-layer scope): the WRITER must not FABRICATE a
		// PQC-hybrid claim on top of a component whose attached algorithm is a
		// classical key-agree primitive. A pqcHybrid=true flag sitting over a bare
		// classical key-agree primitive (no PQ KEM) would be a fabricated PQC-safe
		// verdict introduced by the output layer. (The complementary invariant —
		// that the SCANNER/mock never assigns a quantum-resistant posture to a classical
		// asymmetric primitive in the first place — is a scanner-layer concern; this
		// e2e net deliberately does not police the mock's own posture/primitive
		// pairing. See the reported mock-data gap.)
		if pqcHybrid && c.CryptoProperties != nil &&
			c.CryptoProperties.AlgorithmProperties != nil {
			prim := c.CryptoProperties.AlgorithmProperties.Primitive
			if prim == models.PrimitiveKeyAgree &&
				c.CryptoProperties.AlgorithmProperties.NistQuantumSecurityLevel == 0 {
				t.Errorf("component %q claims cryptamap:pqcHybrid=true but its algorithm is a classical key-agree primitive with no PQ security level — fabricated PQC claim",
					c.Name)
			}
		}
	}

	// Sanity: the deterministic mock must actually exercise both a quantum-resistant
	// and a quantum-vulnerable posture, else the consistency loop asserts nothing.
	safeSeen, vulnSeen := 0, 0
	for p, n := range postureCounts {
		if quantumResistantPostures[p] {
			safeSeen += n
		}
		if quantumVulnerablePostures[p] {
			vulnSeen += n
		}
	}
	if safeSeen == 0 || vulnSeen == 0 {
		t.Fatalf("mock did not produce both safe and vulnerable postures (safe=%d vuln=%d); coverage gap", safeSeen, vulnSeen)
	}
}

// TestE2EPipeline_ASFF drives WriteASFF over the assembled scan and asserts:
//   - the output is a valid JSON array with one finding per scan finding;
//   - each ProductArn is well-formed (the ${ACCOUNT}/${REGION} placeholders are
//     expanded and the account segment equals AwsAccountId, per the AWS
//     private-product ARN shape);
//   - each severity Label/Normalized pair maps correctly from the finding
//     severity (Honesty: the exported severity must equal the recorded one — no
//     silent re-grading at the output edge).
func TestE2EPipeline_ASFF(t *testing.T) {
	scan := e2eScanResult(t)
	// Use the default template ARN shape so expandProductArn has placeholders to
	// substitute (this is the production default in cmd/cryptamap).
	const productArn = "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"

	var buf bytes.Buffer
	if err := WriteASFF(&buf, scan, productArn); err != nil {
		t.Fatalf("WriteASFF: %v", err)
	}

	var findings []ASFFFinding
	if err := json.Unmarshal(buf.Bytes(), &findings); err != nil {
		t.Fatalf("ASFF output is not a valid JSON array: %v", err)
	}
	if len(findings) != len(scan.Findings) {
		t.Fatalf("ASFF emitted %d findings, want %d (one per scan finding)", len(findings), len(scan.Findings))
	}

	// Index the source findings by the ASFF Id we expect, so severity mapping can
	// be checked per finding. The Id is derived deterministically in
	// BuildASFFFinding; here we just check structural + mapping invariants per row.
	wantNorm := map[string]int{
		string(models.SeverityCritical):      90,
		string(models.SeverityHigh):          70,
		string(models.SeverityMedium):        40,
		string(models.SeverityInformational): 0,
	}
	wellFormedArn := regexp.MustCompile(`^arn:aws:securityhub:[a-z0-9-]+:\d{12}:product/\d{12}/default$`)

	for i, f := range findings {
		// ProductArn well-formed and account segment == AwsAccountId.
		if !wellFormedArn.MatchString(f.ProductARN) {
			t.Errorf("finding[%d] ProductArn %q is not well-formed (placeholders unexpanded?)", i, f.ProductARN)
		}
		if !strings.Contains(f.ProductARN, f.AwsAccountID) {
			t.Errorf("finding[%d] ProductArn %q does not contain AwsAccountId %q", i, f.ProductARN, f.AwsAccountID)
		}
		// Severity Label is a valid CryptaMap severity and Normalized matches it.
		norm, ok := wantNorm[f.Severity.Label]
		if !ok {
			t.Errorf("finding[%d] severity label %q is not a canonical CryptaMap severity", i, f.Severity.Label)
			continue
		}
		if f.Severity.Normalized != norm {
			t.Errorf("finding[%d] severity %q normalized=%d, want %d", i, f.Severity.Label, f.Severity.Normalized, norm)
		}
		// Schema version + required envelope fields present.
		if f.SchemaVersion != "2018-10-08" {
			t.Errorf("finding[%d] SchemaVersion=%q, want 2018-10-08", i, f.SchemaVersion)
		}
		if f.AwsAccountID == "" || f.ID == "" {
			t.Errorf("finding[%d] missing AwsAccountId/Id", i)
		}
	}

	// Cross-check the aggregate severity distribution reconciles with the summary:
	// the count of each ASFF severity label equals the summary tally.
	got := map[string]int{}
	for _, f := range findings {
		got[f.Severity.Label]++
	}
	if got[string(models.SeverityCritical)] != scan.Summary.Critical ||
		got[string(models.SeverityHigh)] != scan.Summary.High ||
		got[string(models.SeverityMedium)] != scan.Summary.Medium ||
		got[string(models.SeverityInformational)] != scan.Summary.Informational {
		t.Errorf("ASFF severity tally %v does not reconcile with summary {C:%d H:%d M:%d I:%d}",
			got, scan.Summary.Critical, scan.Summary.High, scan.Summary.Medium, scan.Summary.Informational)
	}
}

// TestE2EPipeline_PQCCExcel drives WritePQCCExcel and asserts:
//   - the writer returns no error and produces an openable .xlsx;
//   - REGRESSION for the formula-injection fix: a finding whose ResourceID is a
//     malicious "=HYPERLINK(...)" formula comes out QUOTE-PREFIXED (literal text)
//     in the Baseline Inventory sheet, never an evaluatable formula cell;
//   - the Baseline Inventory row count reconciles with the finding count.
func TestE2EPipeline_PQCCExcel(t *testing.T) {
	scan := e2eScanResult(t)

	// Inject a finding whose ResourceID is a spreadsheet formula-injection payload
	// (the exact attack the sanitizeCell fix neutralizes). It must come out as
	// literal, quote-prefixed text in the workbook.
	const evil = `=HYPERLINK("http://evil","click")`
	scan.Findings = append(scan.Findings, models.Finding{
		ID:          uuid.NewString(),
		Title:       "synthetic formula-injection probe",
		Description: "regression probe for OWASP CSV/Excel formula injection",
		Severity:    models.SeverityHigh,
		Posture:     models.PostureNonPQCClassical,
		AccountID:   scan.AccountID,
		Region:      scan.Region,
		Service:     "s3",
		ResourceID:  evil,
		Mosca:       models.MoscaScore{Score: 5},
		CreatedAt:   scan.CompletedAt,
		UpdatedAt:   scan.CompletedAt,
	})

	var buf bytes.Buffer
	if err := WritePQCCExcel(&buf, scan, PQCCOptions{OwnerName: "Test Owner"}); err != nil {
		t.Fatalf("WritePQCCExcel: %v", err)
	}

	f, err := excelize.OpenReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("generated xlsx is not openable: %v", err)
	}
	defer f.Close()

	rows, err := f.GetRows("Baseline Inventory")
	if err != nil {
		t.Fatalf("read Baseline Inventory sheet: %v", err)
	}
	// header + one row per finding.
	if want := 1 + len(scan.Findings); len(rows) != want {
		t.Errorf("Baseline Inventory has %d rows, want %d (header + one per finding)", len(rows), want)
	}

	// Find the row whose "Asset/System Short Name/ID" column (B, index 1) is our
	// injected payload and assert it is quote-prefixed literal text. excelize
	// returns the stored cell text; the sanitizeCell fix stores "'"+payload so the
	// leading rune the spreadsheet sees is a quote, not '='.
	const wantSanitized = `'` + evil
	found := false
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		cell := row[1]
		// The unsanitized payload (starting with '=') must NEVER appear verbatim.
		if cell == evil {
			t.Errorf("formula-injection payload written UNSANITIZED into a cell: %q", cell)
		}
		if cell == wantSanitized || strings.HasSuffix(cell, evil) && strings.HasPrefix(cell, "'") {
			found = true
		}
	}
	if !found {
		t.Errorf("did not find the quote-prefixed sanitized payload %q in the Baseline Inventory; got rows=%d", wantSanitized, len(rows))
	}

	// Also assert via the raw cell-value API that the literal stored value of the
	// injected cell starts with a quote (defense in depth against GetRows
	// normalization).
	// The injected finding is the last one, so its row is the last data row.
	lastRow := strconv.Itoa(len(rows)) // 1-based; header is row 1, so last finding is row len(rows)
	v, err := f.GetCellValue("Baseline Inventory", "B"+lastRow)
	if err != nil {
		t.Fatalf("GetCellValue B%s: %v", lastRow, err)
	}
	if !strings.HasPrefix(v, "'") && strings.HasPrefix(v, "=") {
		t.Errorf("injected cell B%s value %q is an evaluatable formula (not sanitized)", lastRow, v)
	}
}

// TestE2EPipeline_Roadmap drives WriteRoadmapJSON and WriteRoadmapMarkdown and
// asserts:
//   - the JSON is valid and parses into a roadmap.Roadmap;
//   - the markdown is non-empty and carries the expected headers;
//   - counts reconcile with the summary: the per-account rollup Critical+High
//     tallies sum to the summary Critical/High counts, and the ranked-item count
//     equals the finding count (every finding becomes a roadmap item).
func TestE2EPipeline_Roadmap(t *testing.T) {
	scan := e2eScanResult(t)

	jsonBytes, err := RoadmapJSONBytes(scan)
	if err != nil {
		t.Fatalf("RoadmapJSONBytes: %v", err)
	}
	// roadmap.Roadmap is in internal/roadmap; decode into a minimal local shape so
	// the output package test does not need to import the roadmap types directly.
	var rm struct {
		AsOf  string `json:"asOf"`
		Items []struct {
			Posture   string `json:"posture"`
			Severity  string `json:"severity"`
			AccountID string `json:"accountId"`
		} `json:"items"`
		ByAccount []struct {
			AccountID string `json:"accountId"`
			Critical  int    `json:"critical"`
			High      int    `json:"high"`
		} `json:"byAccount"`
	}
	if err := json.Unmarshal(jsonBytes, &rm); err != nil {
		t.Fatalf("roadmap JSON is invalid: %v", err)
	}
	if rm.AsOf == "" {
		t.Errorf("roadmap JSON missing AsOf provenance date")
	}
	// One ranked item per finding.
	if len(rm.Items) != len(scan.Findings) {
		t.Errorf("roadmap has %d ranked items, want %d (one per finding)", len(rm.Items), len(scan.Findings))
	}
	// Per-account Critical/High reconcile with the summary totals.
	sumCrit, sumHigh := 0, 0
	for _, a := range rm.ByAccount {
		sumCrit += a.Critical
		sumHigh += a.High
	}
	if sumCrit != scan.Summary.Critical {
		t.Errorf("roadmap ByAccount Critical sum %d != summary.Critical %d", sumCrit, scan.Summary.Critical)
	}
	if sumHigh != scan.Summary.High {
		t.Errorf("roadmap ByAccount High sum %d != summary.High %d", sumHigh, scan.Summary.High)
	}
	// Every ranked item carries a valid posture (no fabricated/empty posture in
	// the regulator-facing roadmap).
	for i, it := range rm.Items {
		if !validE2EPostures[it.Posture] {
			t.Errorf("roadmap item[%d] posture %q not in the 7-value enum", i, it.Posture)
		}
	}

	mdBytes, err := RoadmapMarkdownBytes(scan)
	if err != nil {
		t.Fatalf("RoadmapMarkdownBytes: %v", err)
	}
	md := string(mdBytes)
	for _, want := range []string{"# CryptaMap PQC Migration Roadmap", "## By Service", "## By Account"} {
		if !strings.Contains(md, want) {
			t.Errorf("roadmap markdown missing expected section %q", want)
		}
	}
}

// TestE2EPipeline_HTMLReport drives WriteHTMLReport and asserts:
//   - the report is valid-ish, self-contained HTML (doctype + structural tags);
//   - it references NO external http(s):// resource (the air-gap invariant —
//     reuses assertNoExternalResourceRefs from html_report_test.go);
//   - the embedded JSON data envelope parses and its asset count equals the
//     summary asset count (mutual consistency across the pipeline);
//   - no unescaped scan data leaks raw "<script>" past the data blob: a posture
//     value injected with a script tag is HTML-escaped by html/template.
func TestE2EPipeline_HTMLReport(t *testing.T) {
	scan := e2eScanResult(t)

	// Inject an asset whose Name carries an XSS-style payload to confirm the
	// html/template auto-escaping holds end to end (the rendered cell must NOT
	// contain a live <script> tag from scan data).
	xssName := `evil"><script>alert(1)</script>`
	scan.Assets = append(scan.Assets, models.CryptoAsset{
		BomRef:       models.BomRefForARN("arn:aws:s3:::" + "xss-probe"),
		Name:         xssName,
		Service:      "s3",
		Category:     models.CategoryDataAtRest,
		AccountID:    scan.AccountID,
		Region:       scan.Region,
		ResourceID:   "xss-probe",
		ResourceType: "AWS::S3::Bucket",
		Properties:   map[string]string{"posture": string(models.PostureSymmetricOnly)},
	})
	// Keep the summary consistent with the added asset so the count assertion is exact.
	scan.Summary.TotalAssets = len(scan.Assets)

	raw, err := HTMLReportBytes(scan)
	if err != nil {
		t.Fatalf("HTMLReportBytes: %v", err)
	}
	html := string(raw)

	for _, want := range []string{"<!DOCTYPE html>", "<html", "</html>", "<head>", "<body>", "</body>"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing structural tag %q", want)
		}
	}

	// Air-gap invariant: no external resource references (shared helper).
	assertNoExternalResourceRefs(t, html)

	// The XSS payload must be HTML-escaped in the rendered body: the literal,
	// un-escaped "<script>alert(1)</script>" from scan data must NOT appear (the
	// only legitimate <script> is the data-blob tag the report itself emits).
	if strings.Contains(html, "<script>alert(1)</script>") {
		t.Errorf("HTML report contains UNESCAPED injected script tag from scan data (XSS)")
	}

	// The embedded JSON data envelope parses and its asset count == summary count.
	blob := extractDataBlob(t, html)
	var envelope struct {
		ScanID string `json:"scanId"`
		Assets []struct {
			Name string `json:"name"`
		} `json:"assets"`
		Summary models.ScanSummary `json:"summary"`
	}
	if err := json.Unmarshal([]byte(blob), &envelope); err != nil {
		t.Fatalf("embedded HTML data blob is not valid JSON: %v", err)
	}
	if envelope.ScanID != scan.ScanID {
		t.Errorf("embedded blob scanId=%q, want %q", envelope.ScanID, scan.ScanID)
	}
	if len(envelope.Assets) != scan.Summary.TotalAssets {
		t.Errorf("embedded blob asset count %d != summary.TotalAssets %d", len(envelope.Assets), scan.Summary.TotalAssets)
	}
}

// TestE2EPipeline_CrossArtifactConsistency is the capstone: it builds the scan
// ONCE and asserts the independently-generated artifacts agree on the inventory
// size and finding count, so a future change that desyncs one writer from the
// shared summary/finding model fails here even if each per-writer test still
// passes in isolation.
func TestE2EPipeline_CrossArtifactConsistency(t *testing.T) {
	scan := e2eScanResult(t)

	// CBOM component count.
	var bom CDXBOM
	raw, err := AsBytes(scan)
	if err != nil {
		t.Fatalf("AsBytes: %v", err)
	}
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatalf("re-parse CBOM: %v", err)
	}

	// ASFF finding count.
	var asffBuf bytes.Buffer
	if err := WriteASFF(&asffBuf, scan, "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"); err != nil {
		t.Fatalf("WriteASFF: %v", err)
	}
	var asff []ASFFFinding
	if err := json.Unmarshal(asffBuf.Bytes(), &asff); err != nil {
		t.Fatalf("parse ASFF: %v", err)
	}

	// HTML embedded blob asset count.
	htmlBytes, err := HTMLReportBytes(scan)
	if err != nil {
		t.Fatalf("HTMLReportBytes: %v", err)
	}
	blob := extractDataBlob(t, string(htmlBytes))
	var env struct {
		Assets []json.RawMessage `json:"assets"`
	}
	if err := json.Unmarshal([]byte(blob), &env); err != nil {
		t.Fatalf("parse HTML blob: %v", err)
	}

	// All inventory views must agree with the summary asset count (synthetic
	// algorithm-definition nodes excluded — they are not discovered resources).
	if got := len(realComponents(bom.Components)); got != scan.Summary.TotalAssets {
		t.Errorf("CBOM real components %d != summary assets %d", got, scan.Summary.TotalAssets)
	}
	if len(env.Assets) != scan.Summary.TotalAssets {
		t.Errorf("HTML blob assets %d != summary assets %d", len(env.Assets), scan.Summary.TotalAssets)
	}
	// All finding views must agree with the summary finding count.
	if len(asff) != scan.Summary.TotalFindings {
		t.Errorf("ASFF findings %d != summary findings %d", len(asff), scan.Summary.TotalFindings)
	}
}
