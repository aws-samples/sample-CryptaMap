package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/aws-samples/cryptamap/internal/roadmap"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// defaultRoadmapTopN is the number of "do these first" items rendered in the
// concise markdown report. The full ranked list always lives in roadmap.json.
const defaultRoadmapTopN = 25

// WriteRoadmapJSON builds the PQC migration roadmap from scan and writes it as
// indented JSON. It mirrors the existing writer pattern (io.Writer first arg)
// and uses only stdlib encoding/json, so it adds no new dependency.
func WriteRoadmapJSON(w io.Writer, scan models.ScanResult) error {
	return writeRoadmapJSON(w, roadmap.Build(scan))
}

// writeRoadmapJSON renders an already-built roadmap as indented JSON. Callers
// that emit multiple roadmap artifacts in one run should call roadmap.Build
// once and reuse the result instead of rebuilding over the full asset set.
func writeRoadmapJSON(w io.Writer, rm roadmap.Roadmap) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rm)
}

// WriteRoadmapMarkdown writes the concise human-readable roadmap report with the
// default top-N (25) "do these first" items.
func WriteRoadmapMarkdown(w io.Writer, scan models.ScanResult) error {
	return WriteRoadmapMarkdownTopN(w, scan, defaultRoadmapTopN)
}

// WriteRoadmapJSONAndMarkdown builds the roadmap once and renders both the JSON
// and the default-topN markdown artifacts from that single result, avoiding the
// repeated full-asset-set roadmap.Build that calling WriteRoadmapJSON and
// WriteRoadmapMarkdown separately would incur. Output bytes are identical to
// invoking the two writers individually.
func WriteRoadmapJSONAndMarkdown(jsonW, mdW io.Writer, scan models.ScanResult) error {
	rm := roadmap.Build(scan)
	if err := writeRoadmapJSON(jsonW, rm); err != nil {
		return err
	}
	return writeRoadmapMarkdownTopN(mdW, rm, defaultRoadmapTopN)
}

// WriteRoadmapMarkdownTopN writes a concise, hand-rolled markdown report (no
// templating/markdown library, matching pdf_writer.go's static-link invariant):
// a header with the verification AsOf date and the source envelope, a
// "Top N — Do These First" table (rank, displayName, account/region, posture,
// Mosca, quick-win, recommended AWS action + cited source URL), followed by the
// per-service and per-account roll-up tables.
func WriteRoadmapMarkdownTopN(w io.Writer, scan models.ScanResult, topN int) error {
	return writeRoadmapMarkdownTopN(w, roadmap.Build(scan), topN)
}

// writeRoadmapMarkdownTopN renders an already-built roadmap as markdown. Callers
// that emit multiple roadmap artifacts in one run should call roadmap.Build
// once and reuse the result instead of rebuilding over the full asset set.
func writeRoadmapMarkdownTopN(w io.Writer, rm roadmap.Roadmap, topN int) error {
	if topN <= 0 {
		topN = defaultRoadmapTopN
	}

	if _, err := fmt.Fprintf(w, "# CryptaMap PQC Migration Roadmap\n\n"); err != nil {
		return err
	}
	fmt.Fprintf(w, "Ranked \"upgrade these to PQC first\" list, derived from web-verified AWS\n")
	fmt.Fprintf(w, "post-quantum support (as of **%s**) cross-referenced with each finding's\n", rm.AsOf)
	fmt.Fprintf(w, "Mosca's-Theorem urgency, cryptographic posture, and harvest-now-decrypt-later\n")
	fmt.Fprintf(w, "exposure.\n\n")
	fmt.Fprintf(w, "- Generated from: `%s`\n", rm.GeneratedFrom)
	fmt.Fprintf(w, "- Total ranked items: %d\n", len(rm.Items))
	fmt.Fprintf(w, "- Verification as-of: %s\n\n", rm.AsOf)

	// Top-N "do these first" table.
	n := topN
	if n > len(rm.Items) {
		n = len(rm.Items)
	}
	fmt.Fprintf(w, "## Top %d — Do These First\n\n", n)
	fmt.Fprintf(w, "| Rank | Score | Service | Account / Region | Posture | Mosca | PQC Status | Ease | Quick Win | Recommended AWS action | Source |\n")
	fmt.Fprintf(w, "|---:|---:|---|---|---|---:|---|---|:---:|---|---|\n")
	for i := 0; i < n; i++ {
		it := rm.Items[i]
		quick := ""
		if it.QuickWin {
			quick = "yes"
		}
		fmt.Fprintf(w, "| %d | %.2f | %s | %s / %s | %s | %d | %s | %s | %s | %s | %s |\n",
			it.Rank,
			it.PriorityScore,
			mdCell(it.DisplayName),
			mdCell(it.AccountID),
			mdCell(it.Region),
			mdCell(string(it.Posture)),
			it.Mosca.Score,
			mdCell(string(it.PQCStatus)),
			mdCell(string(it.UpgradeEase)),
			quick,
			mdCell(it.RecommendedAction),
			mdCell(it.SourceURL),
		)
	}
	fmt.Fprintf(w, "\n")

	// Per-service roll-up.
	fmt.Fprintf(w, "## By Service\n\n")
	fmt.Fprintf(w, "| Service | Display Name | Items | Max Priority | Sum Priority | Quick Wins | PQC Status |\n")
	fmt.Fprintf(w, "|---|---|---:|---:|---:|---:|---|\n")
	for _, s := range rm.ByService {
		fmt.Fprintf(w, "| %s | %s | %d | %.2f | %.2f | %d | %s |\n",
			mdCell(s.Service), mdCell(s.DisplayName), s.Items, s.MaxPriority, s.SumPriority, s.QuickWins, mdCell(string(s.PQCStatus)))
	}
	fmt.Fprintf(w, "\n")

	// Per-account roll-up.
	fmt.Fprintf(w, "## By Account\n\n")
	fmt.Fprintf(w, "| Account | Items | Max Priority | Sum Priority | Critical | High |\n")
	fmt.Fprintf(w, "|---|---:|---:|---:|---:|---:|\n")
	for _, a := range rm.ByAccount {
		fmt.Fprintf(w, "| %s | %d | %.2f | %.2f | %d | %d |\n",
			mdCell(a.AccountID), a.Items, a.MaxPriority, a.SumPriority, a.Critical, a.High)
	}
	fmt.Fprintf(w, "\n")

	return nil
}

// mdCell sanitizes a value for a markdown table cell: it escapes pipes and
// collapses newlines so a multi-line howToEnable string does not break the
// table layout.
func mdCell(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case '|':
			out = append(out, '\\', '|')
		case '\n', '\r':
			out = append(out, ' ')
		default:
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "-"
	}
	return string(out)
}

// RoadmapJSONBytes returns the roadmap JSON as a byte slice (test helper,
// mirrors cyclonedx.AsBytes).
func RoadmapJSONBytes(scan models.ScanResult) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteRoadmapJSON(&buf, scan); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RoadmapMarkdownBytes returns the roadmap markdown as a byte slice (test
// helper).
func RoadmapMarkdownBytes(scan models.ScanResult) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteRoadmapMarkdown(&buf, scan); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
