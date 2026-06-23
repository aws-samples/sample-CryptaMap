package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/aws-samples/cryptamap/internal/merge"
	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// This file holds the PURE merge-from-raw core used by the Lambda merge-mode
// (lambda.go runMergeMode). It is intentionally UNTAGGED (no //go:build lambda)
// so the merge/render logic is unit-testable under the default
// `go build ./...` / `go test ./cmd/...` without the lambda runtime or any AWS
// SDK calls. The build-tagged runMergeMode is only the S3 list/get/put I/O
// front-end around these functions.

// mergedArtifactKeys are the S3 keys (relative to the results-bucket root, i.e.
// NOT including any S3Writer prefix) under which a merge run's outputs land.
// scans/latest/<runId>.* mirrors the existing Node MergeResultsFn layout
// (runId already carries the "run-" prefix), extended from the old counts-only
// summary to the full Go pipeline outputs.
type mergedArtifactKeys struct {
	CBOM     string
	Roadmap  string
	RoadmapM string
	Coverage string
	Summary  string
}

// mergedKeys returns the scans/latest/<runId>.* key set for a run (runId
// already carries the "run-" prefix; non-org scans pass an empty runId). An
// empty runId falls back to "_norun" so the keys remain well-formed (mirrors
// rawRunPrefix).
func mergedKeys(runID string) mergedArtifactKeys {
	if runID == "" {
		runID = "_norun"
	}
	base := fmt.Sprintf("scans/latest/%s", runID)
	return mergedArtifactKeys{
		CBOM:     base + ".cbom.json",
		Roadmap:  base + ".roadmap.json",
		RoadmapM: base + ".roadmap.md",
		Coverage: base + ".coverage.json",
		Summary:  base + ".json",
	}
}

// mergeSummary mirrors the shape the prior Node MergeResultsFn wrote to
// scans/latest/<runId>.json so dashboards/alerting that read the old
// counts summary keep working. perAccount aggregates findings/assets per
// member account (summing its regions).
type mergeSummary struct {
	RunID                  string                `json:"runId"`
	GeneratedAt            string                `json:"generatedAt"`
	AccountsRegionsScanned int                   `json:"accountsRegionsScanned"`
	Succeeded              int                   `json:"succeeded"`
	Failed                 int                   `json:"failed"`
	TotalFindings          int                   `json:"totalFindings"`
	TotalCritical          int                   `json:"totalCritical"`
	TotalAssets            int                   `json:"totalAssets"`
	PerAccount             []mergeSummaryAccount `json:"perAccount"`
	CBOMKey                string                `json:"cbomKey"`
	RoadmapKey             string                `json:"roadmapKey"`
	CoverageKey            string                `json:"coverageKey"`
	Coverage               []merge.Coverage      `json:"coverage"`
	// Completion barrier (SCALING.md §4.4): expected = seed-emitted shard count,
	// observed = shards that actually landed/merged. missing>0 / complete=false
	// flags silently-vanished or tolerated-failed shards so a decimated run never
	// reports a clean, smaller result. expectedShards<=0 means "unknown" (legacy
	// replay): complete=true, missing=0.
	ExpectedShards int  `json:"expectedShards"`
	ObservedShards int  `json:"observedShards"`
	MissingShards  int  `json:"missingShards"`
	Complete       bool `json:"complete"`
	// Per-account completion barrier (hierarchical merge tier 2): a tier-1
	// per-account merge can partially fail, leaving its scans/account-merged/
	// <runId>/<accountId>.json object missing or corrupt. The final tier records
	// every account whose per-account object failed to fetch/decode rather than
	// aborting (so one bad account never decimates the whole org merge) and
	// surfaces them here. ExpectedAccounts is the number of per-account objects the
	// final tier listed; MissingAccounts holds the account IDs that did not fold.
	// A non-empty MissingAccounts forces Complete=false so a decimated org report
	// is never reported as a clean success. Both are empty/0 on the raw-shard
	// fallback path (no per-account tier) and need not appear in the JSON then.
	ExpectedAccounts int      `json:"expectedAccounts,omitempty"`
	MissingAccounts  []string `json:"missingAccounts,omitempty"`
	// Incomplete is the LOUD top-level flag (the inverse of Complete) the
	// DECISION (loud-incomplete) requires: a decimated run must make its
	// incompleteness impossible to miss. It is redundant with Complete on purpose
	// — dashboards/CLIs that only look for a positive "incomplete" signal (banners,
	// alerts) get a stable boolean to key off without having to negate Complete.
	Incomplete bool `json:"incomplete"`
	// FailedShards is the STRUCTURED list of (account,region) tuples that did not
	// land cleanly in this run, each with the failure reason where known, so a
	// regulator-facing report (and the dashboard/CLI banner) can name exactly which
	// accounts/regions were dropped and why — never just a bare count. It folds
	// three classes of incompleteness:
	//   - errored shards: a shard that landed but had service-scan errors (its
	//     coverage row carries Errored=true) — region known, reason generic.
	//   - missing accounts: a tier-1 per-account merged object that failed to
	//     fetch/decode (region "*" — the whole account's regions are unaccounted),
	//     carrying the fetch/decode reason recorded by streamAccountMergedObjects.
	//   - vanished shards: the count gap (ExpectedShards-ObservedShards) when the
	//     seed fanned out more (account,region) shards than landed and we cannot
	//     attribute them to specific tuples (the seed passes a count, not a list);
	//     surfaced as a single synthetic row so the gap is never silent.
	// Empty on a clean, fully-reconciled run.
	FailedShards []failedShard `json:"failedShards,omitempty"`
	// Posture is the per-posture asset roll-up (mirrors the dashboard's
	// summarizePosture over CBOM components) so the Overview can render KPIs from
	// /summary without downloading the full CBOM.
	Posture mergeSummaryPosture `json:"posture"`
	// QuantumSafePct is stage2 / (stage1 + stage2) as a whole percent, mirroring
	// the dashboard summarizeMaturity headline (stage0 no-encryption + unknown are
	// EXCLUDED from the denominator). 0 when there are no encrypted assets.
	QuantumSafePct int `json:"quantumSafePct"`
}

// mergeSummaryPosture mirrors the dashboard PostureSummary: one count per
// cryptamap:posture bucket over the merged assets, with anything unrecognized
// folded into Unknown (matching the dashboard summarizePosture switch default).
type mergeSummaryPosture struct {
	NoEncryption    int `json:"noEncryption"`
	LegacyTLS       int `json:"legacyTLS"`
	NonPQCClassical int `json:"nonPQCClassical"`
	SymmetricOnly   int `json:"symmetricOnly"`
	PQCHybrid       int `json:"pqcHybrid"`
	PQCReady        int `json:"pqcReady"`
	Unknown         int `json:"unknown"`
}

// mergeSummaryAccount is one per-account roll-up row in the summary.
type mergeSummaryAccount struct {
	AccountID string `json:"accountId"`
	Regions   int    `json:"regions"`
	Findings  int    `json:"findings"`
	Critical  int    `json:"critical"`
	Assets    int    `json:"assets"`
}

// accountMergedObject is the per-account merge tier's (tier 1) output object,
// stored at scans/account-merged/<runId>/<accountId>.json. It pairs the deduped
// per-account ScanResult with that account's REAL (account,region) coverage rows,
// so the final tier (tier 2) can fold it via merge.Merger.AddPreMerged and
// preserve correct succeeded/failed/perAccount accounting (the merged envelope's
// own AccountID is the sentinel "org", which must NOT drive the summary).
type accountMergedObject struct {
	Merged   models.ScanResult `json:"merged"`
	Coverage []merge.Coverage  `json:"coverage"`
}

// mergeRawShards is the pure merge step. The raw shards already carry Assets AND
// Findings (uploaded verbatim by the scan branch), so unlike org-merge-files we
// do NOT re-parse CycloneDX or re-derive findings — this is strictly simpler and
// lossless. It reuses the exact pure funcs org_merge_files.go uses:
// output.SortScansByAccountRegion + merge.Merge(scans, merge.SentinelAccount).
func mergeRawShards(scans []models.ScanResult) merge.Result {
	output.SortScansByAccountRegion(scans)
	return merge.Merge(scans, merge.SentinelAccount)
}

// failedShard is one structured (account,region) tuple that did not land cleanly,
// with the failure reason where known. It is the per-tuple payload of the
// loud-incomplete report (mergeSummary.FailedShards) so a regulator-facing output
// — and the dashboard/CLI banner — can name exactly which account/region was
// dropped and why, never just a bare count. Region is "*" when the whole account
// is unaccounted (a missing per-account merged object covers all that account's
// regions at once).
type failedShard struct {
	AccountID string `json:"accountId"`
	Region    string `json:"region"`
	Reason    string `json:"reason"`
}

// missingAccount pairs a missing/corrupt per-account merged object's account ID
// with the fetch/decode reason recorded by streamAccountMergedObjects, so the
// loud-incomplete report can explain WHY the account folded short rather than just
// listing the ID.
type missingAccount struct {
	accountID string
	reason    string
}

// accountBarrier carries the per-account tier-2 completion signal from
// runMergeMode into the pure summary builder: the number of per-account merged
// objects the final tier listed, and the accounts whose object failed to
// fetch/decode (a partially-failed tier-1 merge), each with its failure reason.
// It is the zero value on the raw-shard fallback path (no per-account tier), which
// the summary treats as "no account barrier" rather than a spurious incomplete.
type accountBarrier struct {
	expectedAccounts int
	missingAccounts  []missingAccount
}

// accountIDs returns just the sorted account IDs of the barrier's missing
// accounts, for the legacy MissingAccounts []string field (kept for back-compat
// with existing consumers; the per-reason detail lives in FailedShards).
func (b accountBarrier) accountIDs() []string {
	if len(b.missingAccounts) == 0 {
		return nil
	}
	ids := make([]string, 0, len(b.missingAccounts))
	for _, m := range b.missingAccounts {
		ids = append(ids, m.accountID)
	}
	return ids
}

// buildMergeArtifacts renders the merged Result into the in-memory artifact set
// (CBOM, roadmap JSON, roadmap markdown, coverage JSON, summary JSON) keyed by
// their target S3 key, reusing output.WriteCBOM / WriteRoadmapJSON /
// WriteRoadmapMarkdown verbatim. Returned as a map so the caller (runMergeMode)
// is a thin upload loop. acctBarrier surfaces the per-account tier-2 completion
// signal (missing/partial per-account objects) into the summary.
func buildMergeArtifacts(res merge.Result, runID string, expectedShards int, acctBarrier accountBarrier) (map[string][]byte, mergedArtifactKeys, mergeSummary, error) {
	keys := mergedKeys(runID)
	out := make(map[string][]byte, 5)

	// Dashboard-compatible counts summary, including the loud-incomplete report.
	// Built first so it can be returned to the caller (runMergeMode) for the
	// incompleteness banner/log even on a later render error.
	summary := buildMergeSummary(res, runID, keys, expectedShards, acctBarrier)

	// Merged org-wide CBOM (CycloneDX), reusing output.WriteCBOM verbatim.
	var cbomBuf bytes.Buffer
	if err := output.WriteCBOM(&cbomBuf, res.Merged); err != nil {
		return nil, keys, summary, fmt.Errorf("write merged CBOM: %w", err)
	}
	out[keys.CBOM] = cbomBuf.Bytes()

	// Org-wide PQC roadmap (JSON + markdown). Build the roadmap once and render
	// both artifacts from it to avoid recomputing over the full asset set.
	var roadmapBuf, roadmapMDBuf bytes.Buffer
	if err := output.WriteRoadmapJSONAndMarkdown(&roadmapBuf, &roadmapMDBuf, res.Merged); err != nil {
		return nil, keys, summary, fmt.Errorf("write roadmap: %w", err)
	}
	out[keys.Roadmap] = roadmapBuf.Bytes()
	out[keys.RoadmapM] = roadmapMDBuf.Bytes()

	// Coverage matrix.
	covBytes, err := json.MarshalIndent(res.Coverage, "", "  ")
	if err != nil {
		return nil, keys, summary, fmt.Errorf("marshal coverage: %w", err)
	}
	out[keys.Coverage] = covBytes

	sumBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return nil, keys, summary, fmt.Errorf("marshal summary: %w", err)
	}
	out[keys.Summary] = sumBytes

	return out, keys, summary, nil
}

// buildMergeSummary rolls the merged Result up into the legacy summary shape.
// succeeded/failed are derived from the per-shard coverage Errored flag so the
// summary reflects partial-failure state the same way the dashboard expects.
func buildMergeSummary(res merge.Result, runID string, keys mergedArtifactKeys, expectedShards int, acctBarrier accountBarrier) mergeSummary {
	var succeeded, failed int
	// failedShards is the structured, named list of dropped/failed (account,region)
	// tuples that backs the loud-incomplete report. Errored shards are recorded
	// here as they are counted below; missing accounts and the vanished-shard count
	// gap are folded in after the reconciliation math.
	var failedShards []failedShard
	perAcct := map[string]*mergeSummaryAccount{}
	order := []string{}
	for _, c := range res.Coverage {
		if c.Errored {
			failed++
			failedShards = append(failedShards, failedShard{
				AccountID: c.AccountID,
				Region:    c.Region,
				Reason:    "shard completed with service-scan errors (partial coverage for this account/region)",
			})
		} else {
			succeeded++
		}
		// Coverage is per-shard, so Regions is the genuine count of (account,region)
		// shards that landed for this account (observability). Asset/finding COUNTS
		// must NOT be summed from coverage here: c.Assets/c.Findings are the RAW
		// pre-dedup per-shard counts, so a global resource (S3/CloudFront/IAM/...)
		// seen in N region shards would be counted N times, inflating the per-account
		// rollup so sum(perAccount.assets) > TotalAssets. The deduped per-account
		// counts are derived from the merged sets below instead.
		a, ok := perAcct[c.AccountID]
		if !ok {
			a = &mergeSummaryAccount{AccountID: c.AccountID}
			perAcct[c.AccountID] = a
			order = append(order, c.AccountID)
		}
		a.Regions++
	}
	// Per-account asset/finding/critical counts from the DEDUPED merged sets,
	// grouped by each record's real AccountID (preserved through the merge). This
	// makes sum(perAccount.assets) == TotalAssets and sum(perAccount.findings) ==
	// TotalFindings, reconciling the live /summary rollup with the deduped headline
	// AND with the dashboard's own mock/fallback derivation (summaryFromCBOM), which
	// counts deduped CBOM components. An account that only appears on assets/findings
	// (not coverage) or vice-versa is still represented.
	ensureAcct := func(id string) *mergeSummaryAccount {
		a, ok := perAcct[id]
		if !ok {
			a = &mergeSummaryAccount{AccountID: id}
			perAcct[id] = a
			order = append(order, id)
		}
		return a
	}
	for _, asset := range res.Merged.Assets {
		ensureAcct(asset.AccountID).Assets++
	}
	for _, f := range res.Merged.Findings {
		a := ensureAcct(f.AccountID)
		a.Findings++
		if f.Severity == models.SeverityCritical {
			a.Critical++
		}
	}
	per := make([]mergeSummaryAccount, 0, len(order))
	for _, id := range order {
		per = append(per, *perAcct[id])
	}

	generatedAt := ""
	if !res.Merged.CompletedAt.IsZero() {
		generatedAt = res.Merged.CompletedAt.UTC().Format("2006-01-02T15:04:05Z")
	}

	// Completion barrier: reconcile observed shards (the real (account,region)
	// coverage rows) against the seed-emitted expected count. expectedShards<=0
	// means "unknown" (legacy replay / manual invoke): report complete with no
	// gap rather than a bogus negative shortfall. observed may exceed expected if
	// a shard wrote >1 raw object; clamp missing at >=0.
	observed := len(res.Coverage)
	missing := 0
	complete := true
	if expectedShards > 0 {
		missing = expectedShards - observed
		if missing < 0 {
			missing = 0
		}
		complete = missing == 0
	}

	// Per-account barrier: a tier-1 per-account merge whose object failed to
	// fetch/decode was recorded (not aborted on) by runMergeMode and carried here.
	// Any such account decimates the org report, so it forces complete=false even
	// if the seed shard count happened to reconcile. Each missing account becomes a
	// structured failed-shard row with region "*" (its whole region set is
	// unaccounted) and the recorded fetch/decode reason.
	if len(acctBarrier.missingAccounts) > 0 {
		complete = false
		for _, ma := range acctBarrier.missingAccounts {
			reason := ma.reason
			if reason == "" {
				reason = "per-account merged object missing or corrupt"
			}
			failedShards = append(failedShards, failedShard{
				AccountID: ma.accountID,
				Region:    "*",
				Reason:    reason,
			})
		}
	}

	// Vanished shards: the seed fanned out more (account,region) shards than landed
	// and we cannot attribute the gap to specific tuples (the seed passes a count,
	// not a list). Record the gap as a single synthetic row keyed "*"/"*" so the
	// shortfall is named and impossible to miss, never a silent smaller result.
	if missing > 0 {
		failedShards = append(failedShards, failedShard{
			AccountID: "*",
			Region:    "*",
			Reason: fmt.Sprintf(
				"%d of %d expected scan shard(s) never landed (no result object found); specific account/region cannot be attributed from the seed shard count",
				missing, expectedShards),
		})
	}

	posture := summarizePostureCounts(res.Merged.Assets)

	return mergeSummary{
		RunID:                  runID,
		GeneratedAt:            generatedAt,
		AccountsRegionsScanned: len(res.Coverage),
		Succeeded:              succeeded,
		Failed:                 failed,
		TotalFindings:          res.Merged.Summary.TotalFindings,
		TotalCritical:          res.Merged.Summary.Critical,
		TotalAssets:            res.Merged.Summary.TotalAssets,
		PerAccount:             per,
		CBOMKey:                keys.CBOM,
		RoadmapKey:             keys.Roadmap,
		CoverageKey:            keys.Coverage,
		Coverage:               res.Coverage,
		ExpectedShards:         expectedShards,
		ObservedShards:         observed,
		MissingShards:          missing,
		Complete:               complete,
		Incomplete:             !complete,
		FailedShards:           failedShards,
		ExpectedAccounts:       acctBarrier.expectedAccounts,
		MissingAccounts:        acctBarrier.accountIDs(),
		Posture:                posture,
		QuantumSafePct:         quantumSafePct(posture),
	}
}

// summarizePostureCounts buckets the merged assets by their cryptamap:posture
// property (asset.Properties["posture"], the SAME value the CBOM writer stamps
// onto each component). It mirrors the dashboard summarizePosture so the /summary
// rollup and a client-side count over the CBOM agree; anything unrecognized
// (including a missing property) folds into Unknown.
func summarizePostureCounts(assets []models.CryptoAsset) mergeSummaryPosture {
	var p mergeSummaryPosture
	for _, a := range assets {
		switch models.CryptoPosture(a.Properties["posture"]) {
		case models.PostureNoEncryption:
			p.NoEncryption++
		case models.PostureLegacyTLS:
			p.LegacyTLS++
		case models.PostureNonPQCClassical:
			p.NonPQCClassical++
		case models.PostureSymmetricOnly:
			p.SymmetricOnly++
		case models.PosturePQCHybrid:
			p.PQCHybrid++
		case models.PosturePQCReady:
			p.PQCReady++
		default:
			p.Unknown++
		}
	}
	return p
}

// quantumSafePct mirrors the dashboard summarizeMaturity headline: the share of
// ENCRYPTED+classifiable assets that are quantum-safe, i.e. stage2 / (stage1 +
// stage2), rounded to a whole percent. Stage 0 (no-encryption) and unknown are
// excluded from the denominator.
func quantumSafePct(p mergeSummaryPosture) int {
	stage1Vulnerable := p.LegacyTLS + p.NonPQCClassical
	stage2QuantumSafe := p.SymmetricOnly + p.PQCHybrid + p.PQCReady
	encrypted := stage1Vulnerable + stage2QuantumSafe
	if encrypted == 0 {
		return 0
	}
	// Whole-percent rounding matching the dashboard's Math.round (round half up
	// for positive values), in integer math as (2*num + den) / (2*den).
	return (2*stage2QuantumSafe*100 + encrypted) / (2 * encrypted)
}
