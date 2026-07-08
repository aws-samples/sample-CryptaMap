package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// mdField sanitizes a scanner-derived string for safe interpolation into the
// single-line markdown fields of the report below. Several of these values embed
// AWS resource identifiers that are ATTACKER-CHOSEN (queue/table/bucket names,
// folded into f.Title / f.ResourceID), so writing them raw let a resource named
// with embedded newlines + markdown (e.g. "x\n## Summary\n- CRITICAL: 0") forge
// sections in the regulator-facing evidence artifact. This collapses any CR/LF
// and other control characters to a single space so a value can never break out
// of its line, and neutralizes a leading markdown block marker (#, -, *, >, |, `)
// so it cannot start a heading/list/table/quote/code row. It is deliberately
// conservative (readability over fidelity) for an evidence summary; the CBOM and
// html/template report remain the structured, fully-escaped artifacts.
func mdField(s string) string {
	if s == "" {
		return s
	}
	// Collapse every control char (incl. \r, \n, \t) to a space.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r < 0x20) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	// Neutralize a leading markdown block marker so the value cannot start a new
	// structural element on its line.
	if out != "" && strings.ContainsRune("#-*>|`", rune(out[0])) {
		out = "\\" + out
	}
	return out
}

// WritePDFSummary writes a minimal text-format "PDF" summary. The CLI ships a
// markdown-style report rather than a binary PDF to avoid a heavy CGO dep on
// maroto; the dashboard's html2pdf can render the current view to a
// human-readable PDF. Neither is the regulator deliverable — the CycloneDX CBOM
// is the machine-readable artifact; these are human-readable summaries.
//
// This keeps the binary statically-linked while still providing a CLI summary
// artefact that can be checked into evidence repos. All scanner-derived fields
// interpolated below are passed through mdField, because finding titles and
// resource IDs embed attacker-choosable AWS resource names (markdown-injection
// vector into the evidence artifact).
func WritePDFSummary(dst io.Writer, scan models.ScanResult) error {
	// Route all writes through errWriter so a mid-stream failure (full disk,
	// closed pipe) after the first line is propagated instead of swallowed.
	ew := &errWriter{w: dst}
	var w io.Writer = ew
	fmt.Fprintf(w, "# CryptaMap Scan Report\n\n")
	fmt.Fprintf(w, "- Scan ID: %s\n", scan.ScanID)
	fmt.Fprintf(w, "- Account: %s\n", scan.AccountID)
	fmt.Fprintf(w, "- Region: %s\n", scan.Region)
	fmt.Fprintf(w, "- Mode: %s\n", scan.Mode)
	fmt.Fprintf(w, "- Started: %s\n", scan.StartedAt.UTC())
	fmt.Fprintf(w, "- Completed: %s\n\n", scan.CompletedAt.UTC())
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "- Total assets: %d\n", scan.Summary.TotalAssets)
	fmt.Fprintf(w, "- Total findings: %d\n", scan.Summary.TotalFindings)
	fmt.Fprintf(w, "- CRITICAL: %d\n", scan.Summary.Critical)
	fmt.Fprintf(w, "- HIGH:     %d\n", scan.Summary.High)
	fmt.Fprintf(w, "- MEDIUM:   %d\n", scan.Summary.Medium)
	fmt.Fprintf(w, "- INFO:     %d\n\n", scan.Summary.Informational)
	fmt.Fprintf(w, "## Findings (top 50)\n\n")
	for i, f := range scan.Findings {
		if i >= 50 {
			fmt.Fprintf(w, "... and %d more\n", len(scan.Findings)-50)
			break
		}
		fmt.Fprintf(w, "### %d. [%s] %s\n", i+1, f.Severity, mdField(f.Title))
		fmt.Fprintf(w, "- Service: %s | Resource: %s\n", mdField(f.Service), mdField(f.ResourceID))
		fmt.Fprintf(w, "- Posture: %s | Mosca: %d (X+Y-Z)\n", mdField(string(f.Posture)), f.Mosca.Score)
		fmt.Fprintf(w, "- Recommendation: %s\n\n", mdField(f.Recommendation))
	}
	return ew.err
}
