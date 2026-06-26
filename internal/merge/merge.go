// Package merge implements a pure, deterministic org-wide merge/dedup engine
// that collapses N per-region/per-account scan shards (models.ScanResult) into a
// single merged models.ScanResult envelope, so every existing writer (CycloneDX,
// PQCC, ASFF, roadmap) can render it unchanged.
//
// The package is intentionally dependency-light: it imports only the standard
// library and pkg/models. It performs NO I/O and makes NO AWS SDK calls, which
// makes Merge fully unit-testable and free of any cyclic-import / SDK-pull-in
// risk (it deliberately does not import internal/scanner; the summary recompute
// is a free function mirroring scanner.Engine.buildSummary).
package merge

import (
	"sort"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// Source ranks the detection source for precedence. On a duplicate BomRef the
// higher Source wins. It is read from the additive convention
// asset.Properties["source"]; when absent it is inferred from scan.Mode.
//
// No current scanner sets Properties["source"], so today every asset falls back
// to the Mode-derived baseline and behavior is well defined. Future
// probe/SDK scanners can set the property to win precedence.
type Source int

const (
	SourceUnknown Source = iota
	SourceTagging
	SourceConfig
	SourceTargetedSDK
	SourceActiveProbe
)

// Sentinel identity values for the merged envelope. Per-asset and per-finding
// AccountID/Region are preserved on every merged record so downstream artifacts
// retain true provenance even though the envelope itself uses sentinels.
const (
	SentinelAccount = "org"
	SentinelRegion  = "multi"
	MergedMode      = "merged"
	// MockMergedMode marks a merge whose shards were ALL mock scans, so synthetic
	// data is never mislabeled as a real org scan downstream (the dashboard treats
	// mode="mock" as demo data). A merge with any real shard stays MergedMode.
	MockMergedMode = "mock"
)

// Coverage is one (account,region) shard descriptor for the merged envelope.
type Coverage struct {
	AccountID   string    `json:"accountId"`
	Region      string    `json:"region"`
	Mode        string    `json:"mode"`
	Assets      int       `json:"assets"`
	Findings    int       `json:"findings"`
	StartedAt   time.Time `json:"startedAt"`
	CompletedAt time.Time `json:"completedAt"`
	Errored     bool      `json:"errored"` // any ServiceScanReport in the shard had Errors
}

// Result is the merged envelope: the single merged ScanResult (for existing
// writers), the per-shard coverage list, and the source MultiScanResult for
// org provenance.
type Result struct {
	Merged   models.ScanResult      `json:"merged"`
	Coverage []Coverage             `json:"coverage"`
	Multi    models.MultiScanResult `json:"multi"`
}

// Merge is the pure entrypoint. orchestratorAccountID is the management/caller
// account recorded on the MultiScanResult envelope. Merge(nil, ...) returns a
// zero-value-safe Result.
func Merge(scans []models.ScanResult, orchestratorAccountID string) Result {
	// Reimplemented on top of the streaming Merger so there is a SINGLE dedup code
	// path shared with the hierarchical/streaming merge. keepShards=true preserves
	// the exact batch contract (Multi.Scans retains the verbatim shards, as the
	// existing tests assert). Output is byte-identical to the previous batch
	// implementation for the same input order (proven in streaming_test.go).
	m := NewMerger(orchestratorAccountID, true)
	for _, scan := range scans {
		m.Add(scan)
	}
	return m.Finish()
}

// sourceOf extracts Source from an asset. It reads the additive convention
// asset.Properties["source"]; when absent it infers from scanMode
// ("live" -> SourceConfig baseline, "mock" -> SourceTagging baseline,
// other/empty -> SourceUnknown).
func sourceOf(a models.CryptoAsset, scanMode string) Source {
	if a.Properties != nil {
		switch a.Properties["source"] {
		case "active-probe":
			return SourceActiveProbe
		case "targeted-sdk":
			return SourceTargetedSDK
		case "config":
			return SourceConfig
		case "tagging":
			return SourceTagging
		}
	}
	switch scanMode {
	case "live":
		return SourceConfig
	case "mock":
		return SourceTagging
	default:
		return SourceUnknown
	}
}

// assetCandidate carries the dedup metadata alongside an asset so collisions
// can be resolved deterministically.
type assetCandidate struct {
	asset  models.CryptoAsset
	source Source
}

// dedupAssets keys on a.BomRef (models.BomRefForARN). On collision it keeps the
// higher Source; ties are broken by richer asset (more Properties keys), then
// later DiscoveredAt, then lexicographically smaller ResourceARN. Returns
// assets sorted by BomRef for deterministic output.
func dedupAssets(scans []models.ScanResult) []models.CryptoAsset {
	best := make(map[string]assetCandidate)
	for _, scan := range scans {
		for _, a := range scan.Assets {
			key := a.BomRef
			cand := assetCandidate{asset: a, source: sourceOf(a, scan.Mode)}
			existing, ok := best[key]
			if !ok || preferAsset(cand, existing) {
				best[key] = cand
			}
		}
	}
	out := make([]models.CryptoAsset, 0, len(best))
	for _, c := range best {
		out = append(out, c.asset)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].BomRef < out[j].BomRef
	})
	return out
}

// preferAsset reports whether cand should replace existing for the same BomRef.
func preferAsset(cand, existing assetCandidate) bool {
	if cand.source != existing.source {
		return cand.source > existing.source
	}
	cp, ep := len(cand.asset.Properties), len(existing.asset.Properties)
	if cp != ep {
		return cp > ep
	}
	if !cand.asset.DiscoveredAt.Equal(existing.asset.DiscoveredAt) {
		return cand.asset.DiscoveredAt.After(existing.asset.DiscoveredAt)
	}
	return cand.asset.ResourceARN < existing.asset.ResourceARN
}

// findingKey builds the dedup key for a finding. It keys on
// (AssetBomRef + Service + Posture); findings with an empty AssetBomRef fall
// back to keying on (ResourceARN + Service + Posture).
func findingKey(f models.Finding) string {
	ref := f.AssetBomRef
	if ref == "" {
		ref = f.ResourceARN
	}
	return ref + "\x00" + f.Service + "\x00" + string(f.Posture)
}

// dedupFindings unions findings keyed by findingKey, keeping the finding with
// the highest models.NormalizedSeverity. The kept finding carries its own Mosca
// and Compliance (no field-level blending). Sorted by
// (NormalizedSeverity desc, Service asc, ResourceID asc).
func dedupFindings(scans []models.ScanResult) []models.Finding {
	best := make(map[string]models.Finding)
	for _, scan := range scans {
		for _, f := range scan.Findings {
			key := findingKey(f)
			existing, ok := best[key]
			if !ok || models.NormalizedSeverity(f.Severity) > models.NormalizedSeverity(existing.Severity) {
				best[key] = f
			}
		}
	}
	out := make([]models.Finding, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		si, sj := models.NormalizedSeverity(out[i].Severity), models.NormalizedSeverity(out[j].Severity)
		if si != sj {
			return si > sj
		}
		if out[i].Service != out[j].Service {
			return out[i].Service < out[j].Service
		}
		if out[i].ResourceID != out[j].ResourceID {
			return out[i].ResourceID < out[j].ResourceID
		}
		// Total tiebreakers for deterministic order (see streaming.go sortedFindings).
		if out[i].AccountID != out[j].AccountID {
			return out[i].AccountID < out[j].AccountID
		}
		if out[i].Region != out[j].Region {
			return out[i].Region < out[j].Region
		}
		return out[i].ResourceARN < out[j].ResourceARN
	})
	return out
}

// buildSummary recomputes ScanSummary from the merged assets+findings, mirroring
// scanner.Engine.buildSummary's severity switch exactly. ServiceCount is the
// count of distinct Service values across the merged assets.
func buildSummary(assets []models.CryptoAsset, findings []models.Finding) models.ScanSummary {
	s := models.ScanSummary{
		TotalAssets:   len(assets),
		TotalFindings: len(findings),
	}
	services := make(map[string]struct{})
	for _, a := range assets {
		services[a.Service] = struct{}{}
	}
	s.ServiceCount = len(services)
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
	// Mirror scanner.buildSummary (B3): reconcile the inventory-only count
	// (quantum-resistant-at-rest symmetric AES-256, PostureSymmetricOnly) from the
	// merged assets so the assets removed from the finding stream do not vanish.
	for _, a := range assets {
		if a.Properties != nil && a.Properties["posture"] == string(models.PostureSymmetricOnly) {
			s.InventoryOnly++
		}
	}
	return s
}

// unionServiceStats sums AssetCount and DurationMS per Service across shards and
// concatenates each shard's Errors, so ServiceScanReport observability survives
// the merge. Output is sorted by Service for determinism.
func unionServiceStats(scans []models.ScanResult) []models.ServiceScanReport {
	agg := make(map[string]*models.ServiceScanReport)
	order := make([]string, 0)
	for _, scan := range scans {
		for _, st := range scan.ServiceStats {
			cur, ok := agg[st.Service]
			if !ok {
				cur = &models.ServiceScanReport{Service: st.Service}
				agg[st.Service] = cur
				order = append(order, st.Service)
			}
			cur.AssetCount += st.AssetCount
			cur.DurationMS += st.DurationMS
			cur.Errors = append(cur.Errors, st.Errors...)
		}
	}
	if len(order) == 0 {
		return nil
	}
	sort.Strings(order)
	out := make([]models.ServiceScanReport, 0, len(order))
	for _, svc := range order {
		out = append(out, *agg[svc])
	}
	return out
}

// buildCoverage returns one Coverage row per input shard, preserving input order.
func buildCoverage(scans []models.ScanResult) []Coverage {
	out := make([]Coverage, 0, len(scans))
	for _, scan := range scans {
		out = append(out, Coverage{
			AccountID:   scan.AccountID,
			Region:      scan.Region,
			Mode:        scan.Mode,
			Assets:      len(scan.Assets),
			Findings:    len(scan.Findings),
			StartedAt:   scan.StartedAt,
			CompletedAt: scan.CompletedAt,
			Errored:     shardErrored(scan),
		})
	}
	return out
}

// shardErrored reports whether any ServiceScanReport in the shard has Errors.
func shardErrored(scan models.ScanResult) bool {
	for _, st := range scan.ServiceStats {
		if len(st.Errors) > 0 {
			return true
		}
	}
	return false
}

// buildMulti reuses models.MultiScanResult as the org-provenance envelope. The
// verbatim shards are preserved; it is NOT fed to single-ScanResult writers.
func buildMulti(scans []models.ScanResult, orchestratorAccountID string, startedAt, completedAt time.Time) models.MultiScanResult {
	accounts := make(map[string]struct{})
	regions := make(map[string]struct{})
	for _, scan := range scans {
		accounts[scan.AccountID] = struct{}{}
		regions[scan.Region] = struct{}{}
	}
	return models.MultiScanResult{
		OrchestratorAccountID: orchestratorAccountID,
		StartedAt:             startedAt,
		CompletedAt:           completedAt,
		Scans:                 scans,
		TotalAccounts:         len(accounts),
		TotalRegions:          len(regions),
	}
}

// timeBounds returns min(StartedAt) and max(CompletedAt) across shards, ignoring
// zero-value timestamps when a non-zero one is available.
func timeBounds(scans []models.ScanResult) (time.Time, time.Time) {
	var startedAt, completedAt time.Time
	for _, scan := range scans {
		if !scan.StartedAt.IsZero() {
			if startedAt.IsZero() || scan.StartedAt.Before(startedAt) {
				startedAt = scan.StartedAt
			}
		}
		if scan.CompletedAt.After(completedAt) {
			completedAt = scan.CompletedAt
		}
	}
	return startedAt, completedAt
}

// firstToolVersion returns the first non-empty ToolVersion across shards.
func firstToolVersion(scans []models.ScanResult) string {
	for _, scan := range scans {
		if scan.ToolVersion != "" {
			return scan.ToolVersion
		}
	}
	return ""
}

// firstNonEmptyScanID returns the first non-empty ScanID across shards. Tests
// assert on counts, not ScanID, so reusing the first shard's ID keeps output
// deterministic without pulling in a uuid dependency.
func firstNonEmptyScanID(scans []models.ScanResult) string {
	for _, scan := range scans {
		if scan.ScanID != "" {
			return scan.ScanID
		}
	}
	return ""
}
