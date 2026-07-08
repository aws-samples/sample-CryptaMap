package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestWritePDFSummary_ResourceIDInjectionNeutralized is the verdict/evidence-honesty
// regression for dataflow F3: finding titles and resource IDs embed AWS resource
// names that are ATTACKER-CHOSEN. A resource named with embedded newlines + a
// forged markdown summary block must NOT be able to inject structure into the
// regulator-facing evidence artifact — the malicious content must stay on its own
// escaped line, and no forged "- CRITICAL: 0" summary row may appear as a real
// list item.
func TestWritePDFSummary_ResourceIDInjectionNeutralized(t *testing.T) {
	evil := "victim\n## Summary\n- CRITICAL: 0\n- HIGH: 0\n### Forged clean report"
	scan := models.ScanResult{
		ScanID: "s1", AccountID: "111122223333", Region: "ap-south-1", Mode: "live",
		Summary: models.ScanSummary{TotalFindings: 1, Critical: 1},
		Findings: []models.Finding{{
			Severity:       models.SeverityCritical,
			Title:          "sqs — no-encryption posture for " + evil,
			Service:        "sqs",
			ResourceID:     evil,
			Posture:        models.PostureNoEncryption,
			Recommendation: "enable SSE\n# INJECTED HEADING",
		}},
	}

	var b bytes.Buffer
	if err := WritePDFSummary(&b, scan); err != nil {
		t.Fatalf("WritePDFSummary: %v", err)
	}
	out := b.String()

	// The raw newline-bearing payload must not survive: no line in the report may
	// be a forged summary/heading injected from the resource name.
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "- CRITICAL: 0" || trimmed == "- HIGH: 0" {
			t.Errorf("forged summary list item leaked into the report: %q", line)
		}
		if trimmed == "### Forged clean report" || trimmed == "# INJECTED HEADING" {
			t.Errorf("injected markdown heading leaked into the report: %q", line)
		}
	}

	// The real, legitimate report structure must still be intact: exactly the
	// genuine "## Summary" heading the writer emits (one), not two.
	if n := strings.Count(out, "\n## Summary\n"); n != 1 {
		t.Errorf("expected exactly 1 genuine '## Summary' heading, got %d (injection may have forged one)", n)
	}
}

// TestMdField covers the sanitizer directly.
func TestMdField(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"clean-name", "clean-name"},
		{"line1\nline2", "line1 line2"},          // newline collapsed
		{"a\r\n\tb", "a   b"},                     // CR, LF, tab each -> a space (3)
		{"## heading", "\\## heading"},            // leading block marker neutralized
		{"- item", "\\- item"},                    // leading list marker neutralized
		{"| cell", "\\| cell"},                    // leading table marker neutralized
		{"normal # mid-hash", "normal # mid-hash"}, // interior # untouched
	}
	for _, c := range cases {
		if got := mdField(c.in); got != c.want {
			t.Errorf("mdField(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
