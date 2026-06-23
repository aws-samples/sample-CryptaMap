package output

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"time"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/roadmap"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// WriteHTMLReport emits ONE fully self-contained, offline HTML report for a
// ScanResult. The file opens directly from file:// with no network access: all
// CSS and JS are inlined and the report carries NO http(s):// references to
// stylesheets, scripts, fonts, or images. The posture summary, asset table, and
// PQC migration roadmap are rendered as static HTML AND embedded verbatim as a
// machine-readable <script type="application/json"> blob, so the file doubles as
// regulator-readable offline evidence and a re-parseable data envelope.
//
// It is dependency-free beyond the standard library (html/template) and the
// existing internal models/roadmap/pqc packages, mirroring the writer pattern of
// roadmap_writer.go / pdf_writer.go (io.Writer first arg, no CGO, no heavy dep),
// so the binary stays statically linked.
//
// SIGNING: this writer deliberately does NOT embed a signer. For air-gapped BFSI
// evidence the .html is signed OUT OF BAND with a detached signature, which is
// offline-verifiable and does not perturb the report bytes:
//
//	# minisign (recommended for air-gapped: tiny, no PKI):
//	minisign -Sm report.html               # -> report.html.minisig
//	minisign -Vm report.html -p signer.pub # offline verify, no network
//
//	# or cosign in keyed (non-keyless) mode, also fully offline:
//	cosign sign-blob --key cosign.key report.html --output-signature report.html.sig
//	cosign verify-blob --key cosign.pub --signature report.html.sig report.html
//
// The detached .minisig/.sig sits next to report.html in the evidence bundle;
// verification needs only the public key and never reaches out to the network.
func WriteHTMLReport(w io.Writer, scan models.ScanResult) error {
	data := buildHTMLReport(scan)
	// Marshal the embedded data envelope first; html/template's "js" / safe-JSON
	// escaping inside a <script> block is handled below via template.JS so the
	// blob round-trips byte-for-byte for downstream re-parsers.
	blob, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	view := htmlView{
		Report:   data,
		DataJSON: template.JS(blob),
	}
	return htmlReportTemplate.Execute(w, view)
}

// HTMLReportBytes returns the rendered HTML report as a byte slice (test helper,
// mirrors RoadmapMarkdownBytes / cyclonedx.AsBytes).
func HTMLReportBytes(scan models.ScanResult) ([]byte, error) {
	var buf bytes.Buffer
	if err := WriteHTMLReport(&buf, scan); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// htmlReport is the self-describing data envelope inlined into the report. It is
// a flattened, presentation-oriented projection of the scan + roadmap so the
// embedded JSON blob is directly consumable without re-running the ranker.
type htmlReport struct {
	ScanID      string                `json:"scanId"`
	AccountID   string                `json:"accountId"`
	Region      string                `json:"region"`
	Mode        string                `json:"mode"`
	ToolVersion string                `json:"toolVersion"`
	GeneratedAt string                `json:"generatedAt"`
	StartedAt   string                `json:"startedAt"`
	CompletedAt string                `json:"completedAt"`
	Summary     models.ScanSummary    `json:"summary"`
	Knowledge   htmlKnowledge         `json:"knowledge"`
	Assets      []htmlAsset           `json:"assets"`
	Roadmap     []roadmap.RoadmapItem `json:"roadmap"`
}

// htmlKnowledge is the PQC-knowledge freshness/provenance headline shown so a
// regulator can see HOW FRESH the post-quantum facts were at scan time.
type htmlKnowledge struct {
	Source           string `json:"source"`
	KnowledgeVersion string `json:"knowledgeVersion"`
	AsOf             string `json:"asOf"`
	MinAsOf          string `json:"minAsOf"`
	FactCount        int    `json:"factCount"`
	Digest           string `json:"digest"`
}

// htmlAsset is the flattened per-asset row rendered in the asset table.
type htmlAsset struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Service      string `json:"service"`
	Category     string `json:"category"`
	AccountID    string `json:"accountId"`
	Region       string `json:"region"`
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType,omitempty"`
}

// htmlView is the template execution context: the data envelope plus its already
// JSON-marshaled bytes (as template.JS so html/template emits them verbatim
// inside the <script type="application/json"> block).
type htmlView struct {
	Report   htmlReport
	DataJSON template.JS
}

// buildHTMLReport projects a ScanResult (and the roadmap derived from it) into
// the flat htmlReport envelope. It performs NO I/O and is fully deterministic
// given the scan, so the writer is unit-testable.
func buildHTMLReport(scan models.ScanResult) htmlReport {
	rm := roadmap.Build(scan)

	prov := pqc.KnowledgeProvenanceInfo()
	rep := htmlReport{
		ScanID:      scan.ScanID,
		AccountID:   scan.AccountID,
		Region:      scan.Region,
		Mode:        scan.Mode,
		ToolVersion: scan.ToolVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		StartedAt:   scan.StartedAt.UTC().Format(time.RFC3339),
		CompletedAt: scan.CompletedAt.UTC().Format(time.RFC3339),
		Summary:     scan.Summary,
		Knowledge: htmlKnowledge{
			Source:           string(prov.Source),
			KnowledgeVersion: prov.KnowledgeVersion,
			AsOf:             prov.AsOf,
			MinAsOf:          prov.MinAsOf,
			FactCount:        prov.FactCount,
			Digest:           prov.Digest,
		},
		Assets:  make([]htmlAsset, 0, len(scan.Assets)),
		Roadmap: rm.Items,
	}
	for _, a := range scan.Assets {
		// Friendly taxonomy DisplayName so internal scanner IDs (e.g. kms_spec)
		// never leak into the regulator-facing table, mirroring cyclonedx.go.
		tx := taxonomy.MustLookup(a.Service)
		rep.Assets = append(rep.Assets, htmlAsset{
			Name:         a.Name,
			DisplayName:  tx.DisplayName,
			Service:      a.Service,
			Category:     string(a.Category),
			AccountID:    a.AccountID,
			Region:       a.Region,
			ResourceID:   a.ResourceID,
			ResourceType: a.ResourceType,
		})
	}
	return rep
}

// htmlReportTemplate is the single self-contained page. All CSS/JS is inline; it
// references NO external (http/https) resources so it renders fully offline from
// file://. The {{.DataJSON}} blob is the machine-readable evidence envelope.
var htmlReportTemplate = template.Must(template.New("htmlReport").Parse(htmlReportHTML))

const htmlReportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="CryptaMap {{.Report.ToolVersion}}">
<title>CryptaMap PQC Posture Report — {{.Report.AccountID}} / {{.Report.Region}}</title>
<style>
:root{--bg:#0f1117;--card:#1a1d29;--fg:#e6e8ef;--muted:#9aa3b2;--line:#2a2f3e;
--crit:#ef4444;--high:#f59e0b;--med:#eab308;--info:#22c55e;--accent:#60a5fa;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:24px 28px;border-bottom:1px solid var(--line);background:var(--card)}
h1{margin:0 0 4px;font-size:20px}
h2{font-size:16px;margin:28px 0 10px}
.sub{color:var(--muted);font-size:13px}
main{padding:20px 28px;max-width:1200px;margin:0 auto}
.meta{display:flex;flex-wrap:wrap;gap:6px 24px;margin-top:10px;color:var(--muted);font-size:12px}
.meta b{color:var(--fg);font-weight:600}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:8px 0 4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:120px}
.card .n{font-size:24px;font-weight:700}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.crit .n{color:var(--crit)} .card.high .n{color:var(--high)}
.card.med .n{color:var(--med)} .card.info .n{color:var(--info)}
table{width:100%;border-collapse:collapse;margin:6px 0 18px;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
tr:hover td{background:rgba(96,165,250,.06)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--line)}
.sev-CRITICAL{color:var(--crit);border-color:var(--crit)}
.sev-HIGH{color:var(--high);border-color:var(--high)}
.sev-MEDIUM{color:var(--med);border-color:var(--med)}
.sev-INFORMATIONAL{color:var(--info);border-color:var(--info)}
a{color:var(--accent)}
.prov{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 16px;font-size:12px;color:var(--muted)}
.prov code{color:var(--fg)}
footer{padding:18px 28px;color:var(--muted);font-size:12px;border-top:1px solid var(--line)}
.empty{color:var(--muted);font-style:italic;padding:8px 0}
</style>
</head>
<body>
<header>
<h1>CryptaMap — Post-Quantum Cryptographic Posture</h1>
<div class="sub">Offline, self-contained evidence report. Renders without any network access.</div>
<div class="meta">
<span><b>Account:</b> {{.Report.AccountID}}</span>
<span><b>Region:</b> {{.Report.Region}}</span>
<span><b>Mode:</b> {{.Report.Mode}}</span>
<span><b>Scan ID:</b> {{.Report.ScanID}}</span>
<span><b>Tool:</b> CryptaMap {{.Report.ToolVersion}}</span>
<span><b>Completed:</b> {{.Report.CompletedAt}}</span>
<span><b>Generated:</b> {{.Report.GeneratedAt}}</span>
</div>
</header>
<main>

<h2>Posture summary</h2>
<div class="cards">
<div class="card"><div class="n">{{.Report.Summary.TotalAssets}}</div><div class="l">Assets</div></div>
<div class="card"><div class="n">{{.Report.Summary.TotalFindings}}</div><div class="l">Findings</div></div>
<div class="card crit"><div class="n">{{.Report.Summary.Critical}}</div><div class="l">Critical</div></div>
<div class="card high"><div class="n">{{.Report.Summary.High}}</div><div class="l">High</div></div>
<div class="card med"><div class="n">{{.Report.Summary.Medium}}</div><div class="l">Medium</div></div>
<div class="card info"><div class="n">{{.Report.Summary.Informational}}</div><div class="l">Info</div></div>
</div>

<h2>PQC knowledge provenance</h2>
<div class="prov">
Post-quantum support facts as of <code>{{.Report.Knowledge.AsOf}}</code>
(source <code>{{.Report.Knowledge.Source}}</code>, version <code>{{.Report.Knowledge.KnowledgeVersion}}</code>,
weakest-link freshness <code>{{.Report.Knowledge.MinAsOf}}</code>,
{{.Report.Knowledge.FactCount}} facts, digest <code>{{.Report.Knowledge.Digest}}</code>).
</div>

<h2>Discovered cryptographic assets ({{len .Report.Assets}})</h2>
{{if .Report.Assets}}
<table>
<thead><tr><th>Service</th><th>Name</th><th>Category</th><th>Account</th><th>Region</th><th>Resource</th><th>Type</th></tr></thead>
<tbody>
{{range .Report.Assets}}
<tr>
<td>{{.DisplayName}}</td>
<td>{{.Name}}</td>
<td>{{.Category}}</td>
<td>{{.AccountID}}</td>
<td>{{.Region}}</td>
<td>{{.ResourceID}}</td>
<td>{{.ResourceType}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}<div class="empty">No cryptographic assets discovered in this scan.</div>{{end}}

<h2>PQC migration roadmap ({{len .Report.Roadmap}})</h2>
{{if .Report.Roadmap}}
<table>
<thead><tr><th class="num">Rank</th><th class="num">Score</th><th>Service</th><th>Account / Region</th><th>Posture</th><th>Severity</th><th class="num">Mosca</th><th>PQC status</th><th>Recommended action</th></tr></thead>
<tbody>
{{range .Report.Roadmap}}
<tr>
<td class="num">{{.Rank}}</td>
<td class="num">{{printf "%.2f" .PriorityScore}}</td>
<td>{{.DisplayName}}</td>
<td>{{.AccountID}} / {{.Region}}</td>
<td><span class="badge sev-{{.Severity}}">{{.Posture}}</span></td>
<td>{{.Severity}}</td>
<td class="num">{{.Mosca.Score}}</td>
<td>{{.PQCStatus}}</td>
<td>{{.RecommendedAction}}{{if .SourceURL}} <span class="sub">[{{.SourceURL}}]</span>{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}<div class="empty">No roadmap items (no findings).</div>{{end}}

</main>
<footer>
Generated by CryptaMap {{.Report.ToolVersion}}. This single file is fully self-contained and
references no external resources. The machine-readable evidence envelope is embedded below as
<code>&lt;script id="cryptamap-data" type="application/json"&gt;</code>. Sign it out of band with a
detached signature (minisign / cosign) for offline-verifiable, air-gapped evidence.
</footer>
<script id="cryptamap-data" type="application/json">
{{.DataJSON}}
</script>
</body>
</html>
`
