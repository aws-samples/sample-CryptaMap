package output

import (
	"fmt"
	"io"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// WritePDFSummary writes a minimal text-format "PDF" summary. The CLI ships a
// markdown-style report rather than a binary PDF to avoid a heavy CGO dep on
// maroto; the dashboard's html2pdf produces the regulator-grade PDF.
//
// This keeps the binary statically-linked while still providing a CLI summary
// artefact that can be checked into evidence repos.
func WritePDFSummary(w io.Writer, scan models.ScanResult) error {
	if _, err := fmt.Fprintf(w, "# CryptaMap Scan Report\n\n"); err != nil {
		return err
	}
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
		fmt.Fprintf(w, "### %d. [%s] %s\n", i+1, f.Severity, f.Title)
		fmt.Fprintf(w, "- Service: %s | Resource: %s\n", f.Service, f.ResourceID)
		fmt.Fprintf(w, "- Posture: %s | Mosca: %d (X+Y-Z)\n", f.Posture, f.Mosca.Score)
		fmt.Fprintf(w, "- Recommendation: %s\n\n", f.Recommendation)
	}
	return nil
}
