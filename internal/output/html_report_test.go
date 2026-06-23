package output

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// htmlSampleScan builds a ScanResult with assets AND findings so the HTML report
// exercises both the asset table and the roadmap table. sampleScan (in
// cyclonedx_test.go) carries no findings, so we use a local helper here.
func htmlSampleScan() models.ScanResult {
	now := time.Now().UTC()
	bom := "crypto-" + uuid.NewString()
	return models.ScanResult{
		ScanID:      "scan-html-1",
		AccountID:   "123456789012",
		Region:      "ap-south-1",
		StartedAt:   now.Add(-time.Second),
		CompletedAt: now,
		Mode:        "test",
		ToolVersion: "1.0.0",
		Summary: models.ScanSummary{
			TotalAssets:   1,
			TotalFindings: 1,
			High:          1,
			ServiceCount:  1,
		},
		Assets: []models.CryptoAsset{
			{
				BomRef:       bom,
				Name:         "rds-transit-db",
				Service:      "rds_transit",
				Category:     models.CategoryDataInTransit,
				AccountID:    "123456789012",
				Region:       "ap-south-1",
				ResourceID:   "rds-transit-db",
				ResourceType: "AWS::RDS::DBInstance",
				DiscoveredAt: now,
				CryptoProps: models.CryptoProperties{
					AssetType: models.AssetTypeProtocol,
					ProtocolProperties: &models.ProtocolProperties{
						Type:             "tls",
						Version:          "1.2",
						KeyExchangeGroup: "secp256r1",
					},
				},
			},
		},
		Findings: []models.Finding{
			{
				ID:          "f-rds-1",
				Title:       "RDS transit uses classical TLS key exchange",
				Description: "Connection uses ECDHE secp256r1 without ML-KEM hybrid.",
				Severity:    models.SeverityHigh,
				Posture:     models.PostureNonPQCClassical,
				AccountID:   "123456789012",
				Region:      "ap-south-1",
				Service:     "rds_transit",
				ResourceID:  "rds-transit-db",
				AssetBomRef: bom,
				Mosca:       models.MoscaScore{X: 7, Y: 2, Z: 1, Score: 8},
			},
		},
	}
}

// TestHTMLReportSelfContained asserts the report is valid-ish HTML, inlines the
// machine-readable data blob, renders the asset + roadmap rows, and references
// NO external http(s):// resource (the air-gap / file:// invariant).
func TestHTMLReportSelfContained(t *testing.T) {
	scan := htmlSampleScan()
	raw, err := HTMLReportBytes(scan)
	if err != nil {
		t.Fatalf("HTMLReportBytes: %v", err)
	}
	html := string(raw)

	// 1. Valid-ish HTML: doctype + the structural tags.
	for _, want := range []string{"<!DOCTYPE html>", "<html", "</html>", "<head>", "<body>", "</body>"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing expected HTML structure %q", want)
		}
	}

	// 2. The inlined data blob is present and is a parseable JSON envelope.
	const blobOpen = `<script id="cryptamap-data" type="application/json">`
	if !strings.Contains(html, blobOpen) {
		t.Fatalf("report missing inlined data blob script tag %q", blobOpen)
	}
	blob := extractDataBlob(t, html)
	var envelope htmlReport
	if err := json.Unmarshal([]byte(blob), &envelope); err != nil {
		t.Fatalf("inlined data blob is not valid JSON: %v\nblob:\n%s", err, blob)
	}
	if envelope.ScanID != scan.ScanID {
		t.Errorf("blob scanId=%q, want %q", envelope.ScanID, scan.ScanID)
	}
	if len(envelope.Assets) != 1 {
		t.Errorf("blob assets=%d, want 1", len(envelope.Assets))
	}
	if len(envelope.Roadmap) != 1 {
		t.Errorf("blob roadmap items=%d, want 1", len(envelope.Roadmap))
	}

	// 3. The rendered tables contain the asset + roadmap rows (friendly display
	// name, not the raw scanner id leaking as the visible cell).
	for _, want := range []string{"rds-transit-db", "AWS::RDS::DBInstance", "non-pqc-classical", "HIGH"} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing expected cell content %q", want)
		}
	}

	// 4. The air-gap invariant: NO external http(s):// resource references. We
	// scan the whole document (including the embedded JSON blob may legitimately
	// carry a SourceURL citation, so we only forbid http(s) inside HTML resource
	// attributes — src=, href=, url(...) — not anywhere in the file).
	assertNoExternalResourceRefs(t, html)
}

// TestHTMLReportEmptyScan asserts an empty scan still produces a valid,
// self-contained page (no panic, no external refs, both empty-state messages).
func TestHTMLReportEmptyScan(t *testing.T) {
	scan := models.ScanResult{
		ScanID:      "scan-empty",
		AccountID:   "000000000000",
		Region:      "ap-south-1",
		Mode:        "test",
		ToolVersion: "1.0.0",
		CompletedAt: time.Now().UTC(),
	}
	raw, err := HTMLReportBytes(scan)
	if err != nil {
		t.Fatalf("HTMLReportBytes (empty): %v", err)
	}
	html := string(raw)
	if !strings.Contains(html, "<!DOCTYPE html>") || !strings.Contains(html, "</html>") {
		t.Fatalf("empty report is not valid-ish HTML")
	}
	if !strings.Contains(html, "No cryptographic assets discovered") {
		t.Errorf("empty report missing empty-asset message")
	}
	if !strings.Contains(html, "No roadmap items") {
		t.Errorf("empty report missing empty-roadmap message")
	}
	assertNoExternalResourceRefs(t, html)
}

// extractDataBlob returns the JSON text inside the inlined data <script>.
func extractDataBlob(t *testing.T, html string) string {
	t.Helper()
	const open = `<script id="cryptamap-data" type="application/json">`
	i := strings.Index(html, open)
	if i < 0 {
		t.Fatalf("data blob open tag not found")
	}
	rest := html[i+len(open):]
	j := strings.Index(rest, "</script>")
	if j < 0 {
		t.Fatalf("data blob close tag not found")
	}
	return strings.TrimSpace(rest[:j])
}

// externalResourceRef matches a resource-loading attribute (src/href) or a CSS
// url() that points at an absolute http(s):// URL — i.e. something that would
// make the file reach out to the network when opened. A SourceURL citation
// rendered as visible text is NOT a resource ref and is allowed.
var externalResourceRef = regexp.MustCompile(`(?i)(src|href)\s*=\s*["']https?://|url\(\s*['"]?https?://`)

// assertNoExternalResourceRefs fails if the HTML loads any external (http/https)
// stylesheet, script, font, or image — the offline / air-gapped invariant.
func assertNoExternalResourceRefs(t *testing.T, html string) {
	t.Helper()
	if m := externalResourceRef.FindString(html); m != "" {
		t.Errorf("report references an external resource (breaks offline invariant): %q", m)
	}
}
