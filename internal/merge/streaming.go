package merge

import (
	"sort"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// Merger is a memory-bounded, streaming equivalent of Merge. Callers fold shards
// in one at a time with Add and can DISCARD each models.ScanResult immediately
// afterward — the Merger retains only the DEDUPED working set (asset/finding maps
// keyed by BomRef/findingKey) plus small per-shard summaries, never the sum of
// all raw shards. Finish() then renders the merged Result.
//
// This is the primitive behind the hierarchical merge: a per-account merge folds
// that account's region shards; the final merge folds each per-account merged
// object. Peak memory is bounded by the number of DISTINCT resources, not by the
// number of shards × their size — which is what removes the org-merge OOM cliff
// (see docs/SCALING.md §2).
//
// Add MUST be called in a deterministic order (callers sort shards by
// account/region first) so tie-breaks that depend on first-seen resolve
// identically to batch Merge. With the same input order, NewMerger().Add(...).
// Finish() produces byte-identical output to Merge(...) — proven by the
// equivalence tests in streaming_test.go. Merge itself is reimplemented on top of
// Merger so there is a single dedup code path.
type Merger struct {
	assets   map[string]assetCandidate
	findings map[string]models.Finding

	// Order-preserving accumulators mirroring the batch helpers.
	statsAgg   map[string]*models.ServiceScanReport
	statsOrder []string
	coverage   []Coverage
	multiScans []models.ScanResult // retained ONLY when keepShards is set

	accounts map[string]struct{}
	regions  map[string]struct{}

	startedAt    time.Time
	completedAt  time.Time
	toolVersion  string
	firstScanID  string
	orchestrator string
	keepShards   bool
	shardCount   int
	// allMock stays true only while every shard added so far was a mock scan, so
	// a merge of synthetic shards is honestly reported as mode="mock" rather than
	// "merged" (which the dashboard would otherwise treat as a real org scan).
	allMock bool
}

// NewMerger returns an empty streaming Merger. orchestratorAccountID is recorded
// on the MultiScanResult envelope. keepShards controls whether the verbatim
// per-shard ScanResults are retained in Multi.Scans: pass false on the
// memory-critical Lambda merge path (nothing downstream reads Multi.Scans — see
// docs/SCALING.md §4.1); pass true to preserve the exact batch-Merge contract
// (the batch Merge wrapper uses true).
func NewMerger(orchestratorAccountID string, keepShards bool) *Merger {
	return &Merger{
		assets:       make(map[string]assetCandidate),
		findings:     make(map[string]models.Finding),
		statsAgg:     make(map[string]*models.ServiceScanReport),
		accounts:     make(map[string]struct{}),
		regions:      make(map[string]struct{}),
		orchestrator: orchestratorAccountID,
		keepShards:   keepShards,
		allMock:      true, // flips false on the first non-mock shard (see Add)
	}
}

// Add folds one shard into the working set. The shard may be discarded by the
// caller after Add returns (unless keepShards is true, in which case the Merger
// retains a reference for Multi.Scans). Mirrors the per-element loops of
// dedupAssets/dedupFindings/unionServiceStats/buildCoverage/buildMulti exactly.
func (m *Merger) Add(scan models.ScanResult) {
	m.shardCount++
	if scan.Mode != "mock" {
		m.allMock = false // any non-mock shard makes the merge a real merge
	}

	// Assets (dedupAssets semantics).
	for _, a := range scan.Assets {
		cand := assetCandidate{asset: a, source: sourceOf(a, scan.Mode)}
		if existing, ok := m.assets[a.BomRef]; !ok || preferAsset(cand, existing) {
			m.assets[a.BomRef] = cand
		}
	}

	// Findings (dedupFindings semantics: highest NormalizedSeverity wins, first
	// seen on a tie).
	for _, f := range scan.Findings {
		key := findingKey(f)
		if existing, ok := m.findings[key]; !ok || models.NormalizedSeverity(f.Severity) > models.NormalizedSeverity(existing.Severity) {
			m.findings[key] = f
		}
	}

	// ServiceStats union (unionServiceStats semantics).
	for _, st := range scan.ServiceStats {
		cur, ok := m.statsAgg[st.Service]
		if !ok {
			cur = &models.ServiceScanReport{Service: st.Service}
			m.statsAgg[st.Service] = cur
			m.statsOrder = append(m.statsOrder, st.Service)
		}
		cur.AssetCount += st.AssetCount
		cur.DurationMS += st.DurationMS
		cur.Errors = append(cur.Errors, st.Errors...)
	}

	// Coverage (buildCoverage semantics — one row per shard, input order).
	m.coverage = append(m.coverage, Coverage{
		AccountID:   scan.AccountID,
		Region:      scan.Region,
		Mode:        scan.Mode,
		Assets:      len(scan.Assets),
		Findings:    len(scan.Findings),
		StartedAt:   scan.StartedAt,
		CompletedAt: scan.CompletedAt,
		Errored:     shardErrored(scan),
	})

	// Multi envelope accounting (buildMulti semantics).
	m.accounts[scan.AccountID] = struct{}{}
	m.regions[scan.Region] = struct{}{}

	// timeBounds semantics.
	if !scan.StartedAt.IsZero() && (m.startedAt.IsZero() || scan.StartedAt.Before(m.startedAt)) {
		m.startedAt = scan.StartedAt
	}
	if scan.CompletedAt.After(m.completedAt) {
		m.completedAt = scan.CompletedAt
	}
	// firstToolVersion / firstNonEmptyScanID semantics (first non-empty wins).
	if m.toolVersion == "" && scan.ToolVersion != "" {
		m.toolVersion = scan.ToolVersion
	}
	if m.firstScanID == "" && scan.ScanID != "" {
		m.firstScanID = scan.ScanID
	}

	if m.keepShards {
		m.multiScans = append(m.multiScans, scan)
	}
}

// AddPreMerged folds a per-account intermediate result (tier 1 of the
// hierarchical merge) into the working set, carrying through its REAL per-shard
// coverage rows instead of synthesizing one sentinel row from the merged
// envelope. This is the key difference from Add for the final tier: a tier-1
// object's own AccountID is the sentinel "org" and its unioned ServiceStats look
// errored, so treating it as a single raw shard (via Add) would corrupt the
// coverage/summary rollup (succeeded/failed/perAccount). The asset/finding/stats
// dedup is identical to Add — only the coverage source differs.
//
// coverage is the tier-1 object's res.Coverage (the genuine (account,region)
// rows). assets/findings/serviceStats come from the tier-1 res.Merged.
func (m *Merger) AddPreMerged(merged models.ScanResult, coverage []Coverage) {
	m.shardCount++
	if merged.Mode != "mock" {
		m.allMock = false
	}

	for _, a := range merged.Assets {
		cand := assetCandidate{asset: a, source: sourceOf(a, merged.Mode)}
		if existing, ok := m.assets[a.BomRef]; !ok || preferAsset(cand, existing) {
			m.assets[a.BomRef] = cand
		}
	}
	for _, f := range merged.Findings {
		key := findingKey(f)
		if existing, ok := m.findings[key]; !ok || models.NormalizedSeverity(f.Severity) > models.NormalizedSeverity(existing.Severity) {
			m.findings[key] = f
		}
	}
	for _, st := range merged.ServiceStats {
		cur, ok := m.statsAgg[st.Service]
		if !ok {
			cur = &models.ServiceScanReport{Service: st.Service}
			m.statsAgg[st.Service] = cur
			m.statsOrder = append(m.statsOrder, st.Service)
		}
		cur.AssetCount += st.AssetCount
		cur.DurationMS += st.DurationMS
		cur.Errors = append(cur.Errors, st.Errors...)
	}

	// Carry the REAL coverage rows through, and derive Multi accounting + time
	// bounds from them (not from the sentinel envelope) so account/region counts
	// and succeeded/failed are correct.
	for _, c := range coverage {
		m.coverage = append(m.coverage, c)
		m.accounts[c.AccountID] = struct{}{}
		m.regions[c.Region] = struct{}{}
		if !c.StartedAt.IsZero() && (m.startedAt.IsZero() || c.StartedAt.Before(m.startedAt)) {
			m.startedAt = c.StartedAt
		}
		if c.CompletedAt.After(m.completedAt) {
			m.completedAt = c.CompletedAt
		}
	}
	if m.toolVersion == "" && merged.ToolVersion != "" {
		m.toolVersion = merged.ToolVersion
	}
	if m.firstScanID == "" && merged.ScanID != "" {
		m.firstScanID = merged.ScanID
	}
}

// mergedMode reports the merged-result Mode: "mock" when every shard folded in
// was a mock scan (so the merged artifact is honestly synthetic), else "merged".
// A merge with no shards is "merged" (handled in Finish's empty branch).
func (m *Merger) mergedMode() string {
	if m.allMock {
		return MockMergedMode
	}
	return MergedMode
}

// Finish renders the merged Result from the accumulated working set. After
// Finish the Merger should not be reused. An empty Merger (no Add calls) returns
// the same zero-value-safe Result as Merge(nil, ...).
func (m *Merger) Finish() Result {
	if m.shardCount == 0 {
		return Result{
			Merged: models.ScanResult{
				AccountID: SentinelAccount,
				Region:    SentinelRegion,
				Mode:      MergedMode,
			},
			Coverage: []Coverage{},
			Multi: models.MultiScanResult{
				OrchestratorAccountID: m.orchestrator,
				Scans:                 []models.ScanResult{},
			},
		}
	}

	mergedAssets := m.sortedAssets()
	mergedFindings := m.sortedFindings()
	summary := buildSummary(mergedAssets, mergedFindings)
	stats := m.sortedStats()

	merged := models.ScanResult{
		ScanID:       m.firstScanID,
		AccountID:    SentinelAccount,
		Region:       SentinelRegion,
		StartedAt:    m.startedAt,
		CompletedAt:  m.completedAt,
		Mode:         m.mergedMode(),
		Summary:      summary,
		Assets:       mergedAssets,
		Findings:     mergedFindings,
		ServiceStats: stats,
		ToolVersion:  m.toolVersion,
	}

	scans := m.multiScans
	if scans == nil {
		// keepShards=false: Multi carries accounting only, no verbatim shards.
		scans = []models.ScanResult{}
	}
	multi := models.MultiScanResult{
		OrchestratorAccountID: m.orchestrator,
		StartedAt:             m.startedAt,
		CompletedAt:           m.completedAt,
		Scans:                 scans,
		TotalAccounts:         len(m.accounts),
		TotalRegions:          len(m.regions),
	}

	return Result{Merged: merged, Coverage: m.coverage, Multi: multi}
}

// sortedAssets mirrors dedupAssets' final sort (by BomRef).
func (m *Merger) sortedAssets() []models.CryptoAsset {
	out := make([]models.CryptoAsset, 0, len(m.assets))
	for _, c := range m.assets {
		out = append(out, c.asset)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BomRef < out[j].BomRef })
	return out
}

// sortedFindings mirrors dedupFindings' final sort
// (NormalizedSeverity desc, Service asc, ResourceID asc).
func (m *Merger) sortedFindings() []models.Finding {
	out := make([]models.Finding, 0, len(m.findings))
	for _, f := range m.findings {
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
		// Total tiebreakers so the order is fully deterministic regardless of map
		// iteration order. Without these, an org with many same-(severity,service,
		// resourceId) findings across accounts (e.g. "bucket-0" in every account)
		// sorts non-deterministically (Go sort.Slice is not stable), making batch
		// and streaming merges — and even two runs of either — disagree on order.
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

// sortedStats mirrors unionServiceStats' output (sorted by Service).
func (m *Merger) sortedStats() []models.ServiceScanReport {
	if len(m.statsOrder) == 0 {
		return nil
	}
	order := make([]string, len(m.statsOrder))
	copy(order, m.statsOrder)
	sort.Strings(order)
	out := make([]models.ServiceScanReport, 0, len(order))
	for _, svc := range order {
		out = append(out, *m.statsAgg[svc])
	}
	return out
}
