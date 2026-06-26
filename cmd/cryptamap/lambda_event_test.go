package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func TestParseLambdaEventFanOut(t *testing.T) {
	raw := []byte(`{
		"mode": "lambda",
		"accountId": "111122223333",
		"region": "ap-south-1",
		"roleArn": "arn:aws:iam::111122223333:role/CryptaMapScannerRole",
		"externalId": "scanner-ext-id"
	}`)

	evt, err := parseLambdaEvent(raw)
	if err != nil {
		t.Fatalf("parseLambdaEvent: unexpected error: %v", err)
	}

	if got, want := evt.Mode, "lambda"; got != want {
		t.Errorf("Mode: got=%q want=%q", got, want)
	}
	if got, want := evt.AccountID, "111122223333"; got != want {
		t.Errorf("AccountID: got=%q want=%q", got, want)
	}
	if got, want := evt.Region, "ap-south-1"; got != want {
		t.Errorf("Region: got=%q want=%q", got, want)
	}
	if got, want := evt.RoleArn, "arn:aws:iam::111122223333:role/CryptaMapScannerRole"; got != want {
		t.Errorf("RoleArn: got=%q want=%q", got, want)
	}
	if got, want := evt.ExternalId, "scanner-ext-id"; got != want {
		t.Errorf("ExternalId: got=%q want=%q", got, want)
	}
	if evt.RoleSessionName != "" {
		t.Errorf("RoleSessionName: got=%q want empty", evt.RoleSessionName)
	}
}

func TestParseLambdaEventSingleAccount(t *testing.T) {
	// No roleArn/externalId -> preserves single-account fields only.
	raw := []byte(`{"mode":"lambda","accountId":"999988887777","region":"us-east-1"}`)

	evt, err := parseLambdaEvent(raw)
	if err != nil {
		t.Fatalf("parseLambdaEvent: unexpected error: %v", err)
	}
	if evt.RoleArn != "" {
		t.Errorf("RoleArn: got=%q want empty", evt.RoleArn)
	}
	if evt.ExternalId != "" {
		t.Errorf("ExternalId: got=%q want empty", evt.ExternalId)
	}
	if got, want := evt.AccountID, "999988887777"; got != want {
		t.Errorf("AccountID: got=%q want=%q", got, want)
	}
}

func TestParseLambdaEventMalformed(t *testing.T) {
	if _, err := parseLambdaEvent([]byte(`{not json`)); err == nil {
		t.Errorf("parseLambdaEvent: expected error for malformed JSON, got nil")
	}
}

func TestResolveScanRegion(t *testing.T) {
	tests := []struct {
		name        string
		evt         LambdaEvent
		fallbackCfg string
		want        string
	}{
		{
			name:        "explicit event region wins",
			evt:         LambdaEvent{Region: "ap-south-1"},
			fallbackCfg: "eu-west-1",
			want:        "ap-south-1",
		},
		{
			name:        "falls back to cfg region",
			evt:         LambdaEvent{},
			fallbackCfg: "eu-west-1",
			want:        "eu-west-1",
		},
		{
			name:        "final fallback us-east-1",
			evt:         LambdaEvent{},
			fallbackCfg: "",
			want:        "us-east-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveScanRegion(tc.evt, tc.fallbackCfg); got != tc.want {
				t.Errorf("resolveScanRegion: got=%q want=%q", got, tc.want)
			}
		})
	}
}

// TestParseLambdaEventMerge proves the terminal org-merge event contract:
// { mode:"lambda", merge:true, runId:"run-..." } sets Merge and RunID and does
// NOT set any scan-only field, so handle() takes the merge branch.
func TestParseLambdaEventMerge(t *testing.T) {
	raw := []byte(`{"mode":"lambda","merge":true,"runId":"run-20260604-abc123"}`)

	evt, err := parseLambdaEvent(raw)
	if err != nil {
		t.Fatalf("parseLambdaEvent: unexpected error: %v", err)
	}
	if !evt.Merge {
		t.Errorf("Merge: got=false want=true")
	}
	if got, want := evt.RunID, "run-20260604-abc123"; got != want {
		t.Errorf("RunID: got=%q want=%q", got, want)
	}
	if evt.RoleArn != "" || evt.AccountID != "" || evt.Region != "" {
		t.Errorf("merge event should carry no scan fields, got roleArn=%q accountId=%q region=%q",
			evt.RoleArn, evt.AccountID, evt.Region)
	}
}

// TestParseLambdaEventScanCarriesRunID proves a fan-out SCAN event threads the
// runId through (used to namespace the raw shard key) while Merge stays false.
func TestParseLambdaEventScanCarriesRunID(t *testing.T) {
	raw := []byte(`{"mode":"lambda","accountId":"111122223333","region":"ap-south-1","runId":"run-xyz","roleArn":"arn:aws:iam::111122223333:role/CryptaMapScannerRole"}`)

	evt, err := parseLambdaEvent(raw)
	if err != nil {
		t.Fatalf("parseLambdaEvent: unexpected error: %v", err)
	}
	if evt.Merge {
		t.Errorf("Merge: got=true want=false for a scan event")
	}
	if got, want := evt.RunID, "run-xyz"; got != want {
		t.Errorf("RunID: got=%q want=%q", got, want)
	}
}

// TestRawScanKey asserts the exact raw-shard key shape and the empty-runId
// fallback that keeps single-account scheduled scans out of any org-run prefix.
func TestRawScanKey(t *testing.T) {
	tests := []struct {
		name    string
		runID   string
		account string
		region  string
		scanID  string
		want    string
	}{
		{
			name:    "namespaced by runId",
			runID:   "run-abc",
			account: "111122223333",
			region:  "ap-south-1",
			scanID:  "scan-42",
			want:    "scans/raw/run-abc/111122223333-ap-south-1-scan-42.json",
		},
		{
			name:    "empty runId falls back to _norun namespace",
			runID:   "",
			account: "999988887777",
			region:  "us-east-1",
			scanID:  "scan-7",
			want:    "scans/raw/_norun/999988887777-us-east-1-scan-7.json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawScanKey(tc.runID, tc.account, tc.region, tc.scanID); got != tc.want {
				t.Errorf("rawScanKey: got=%q want=%q", got, tc.want)
			}
		})
	}
}

// TestRawRunPrefix asserts the list prefix used by the merge step (and that the
// empty-runId fallback matches the rawScanKey fallback so the two never diverge).
func TestRawRunPrefix(t *testing.T) {
	if got, want := rawRunPrefix("run-abc"), "scans/raw/run-abc/"; got != want {
		t.Errorf("rawRunPrefix(run-abc): got=%q want=%q", got, want)
	}
	if got, want := rawRunPrefix(""), "scans/raw/_norun/"; got != want {
		t.Errorf("rawRunPrefix(empty): got=%q want=%q", got, want)
	}
	// A raw key MUST live under its run prefix (so the merge ListObjectsV2 finds it).
	key := rawScanKey("run-abc", "111122223333", "ap-south-1", "scan-1")
	if !strings.HasPrefix(key, rawRunPrefix("run-abc")) {
		t.Errorf("rawScanKey %q does not live under rawRunPrefix %q", key, rawRunPrefix("run-abc"))
	}
}

// TestParseLambdaEventMergeAccount proves the per-account merge tier event parses
// with MergeAccount + accountId and stays distinct from a scan or final merge.
func TestParseLambdaEventMergeAccount(t *testing.T) {
	raw := []byte(`{"mode":"lambda","mergeAccount":true,"runId":"run-abc","accountId":"111122223333"}`)
	evt, err := parseLambdaEvent(raw)
	if err != nil {
		t.Fatalf("parseLambdaEvent: %v", err)
	}
	if !evt.MergeAccount {
		t.Errorf("MergeAccount: got=false want=true")
	}
	if evt.Merge {
		t.Errorf("Merge: got=true want=false (mergeAccount is a distinct tier)")
	}
	if got, want := evt.AccountID, "111122223333"; got != want {
		t.Errorf("AccountID: got=%q want=%q", got, want)
	}
}

// TestAccountMergeKeys asserts the hierarchical-merge key shapes and — critically
// — that accountRawPrefix actually captures a raw shard key for that account, so
// the per-account merge tier's ListObjectsV2 finds exactly that account's shards.
func TestAccountMergeKeys(t *testing.T) {
	// accountRawPrefix must be a prefix of every raw key for that (run, account).
	rawKey := rawScanKey("run-abc", "111122223333", "ap-south-1", "scan-1")
	pfx := accountRawPrefix("run-abc", "111122223333")
	if !strings.HasPrefix(rawKey, pfx) {
		t.Errorf("accountRawPrefix %q does not capture raw key %q", pfx, rawKey)
	}
	// It must NOT capture a different account's shard.
	otherKey := rawScanKey("run-abc", "999988887777", "ap-south-1", "scan-1")
	if strings.HasPrefix(otherKey, pfx) {
		t.Errorf("accountRawPrefix %q wrongly captures other-account key %q", pfx, otherKey)
	}
	// Per-account merged object lives under the account-merged prefix.
	mk := accountMergedKey("run-abc", "111122223333")
	if !strings.HasPrefix(mk, accountMergedPrefix("run-abc")) {
		t.Errorf("accountMergedKey %q not under accountMergedPrefix %q", mk, accountMergedPrefix("run-abc"))
	}
	if mk != "scans/account-merged/run-abc/111122223333.json" {
		t.Errorf("accountMergedKey: got=%q", mk)
	}
	// Empty-runId fallback stays consistent with the other prefixes (_norun).
	if got := accountMergedPrefix(""); got != "scans/account-merged/_norun/" {
		t.Errorf("accountMergedPrefix(empty): got=%q", got)
	}
}

// TestMergedKeys asserts the scans/latest/<runId>.* artifact key set (runId
// already carries the "run-" prefix, so there is exactly one "run-") and its
// empty-runId fallback.
func TestMergedKeys(t *testing.T) {
	keys := mergedKeys("run-abc")
	want := map[string]string{
		"CBOM":     "scans/latest/run-abc.cbom.json",
		"Roadmap":  "scans/latest/run-abc.roadmap.json",
		"RoadmapM": "scans/latest/run-abc.roadmap.md",
		"Coverage": "scans/latest/run-abc.coverage.json",
		"Summary":  "scans/latest/run-abc.json",
	}
	if keys.CBOM != want["CBOM"] {
		t.Errorf("CBOM: got=%q want=%q", keys.CBOM, want["CBOM"])
	}
	if keys.Roadmap != want["Roadmap"] {
		t.Errorf("Roadmap: got=%q want=%q", keys.Roadmap, want["Roadmap"])
	}
	if keys.RoadmapM != want["RoadmapM"] {
		t.Errorf("RoadmapM: got=%q want=%q", keys.RoadmapM, want["RoadmapM"])
	}
	if keys.Coverage != want["Coverage"] {
		t.Errorf("Coverage: got=%q want=%q", keys.Coverage, want["Coverage"])
	}
	if keys.Summary != want["Summary"] {
		t.Errorf("Summary: got=%q want=%q", keys.Summary, want["Summary"])
	}
	if got := mergedKeys("").CBOM; got != "scans/latest/_norun.cbom.json" {
		t.Errorf("mergedKeys(empty).CBOM: got=%q want=scans/latest/_norun.cbom.json", got)
	}
}

// mkRawShard builds a minimal raw ScanResult shard the way the scan branch
// uploads it: Assets AND Findings present (so the merge step does NOT re-derive).
func mkRawShard(account, region, arn string, sev models.Severity) models.ScanResult {
	ref := models.BomRefForARN(arn)
	return models.ScanResult{
		ScanID:    "scan-" + account + "-" + region,
		AccountID: account,
		Region:    region,
		Mode:      "live",
		Assets: []models.CryptoAsset{{
			BomRef: ref, Name: arn, Service: "kms", AccountID: account,
			Region: region, ResourceID: arn, ResourceARN: arn,
		}},
		Findings: []models.Finding{{
			ID: arn, Severity: sev, AccountID: account, Region: region,
			Service: "kms", ResourceID: arn, ResourceARN: arn, AssetBomRef: ref,
		}},
	}
}

// TestMergeFromRawPath exercises the pure merge-from-raw core (mergeRawShards +
// buildMergeArtifacts) that runMergeMode wraps with S3 I/O. It proves the raw
// shards (assets+findings already present) merge with NO finding re-derivation,
// dedup collapses a global-service ARN seen in two regions, and all five
// artifacts (CBOM/roadmap.json/roadmap.md/coverage.json/summary.json) are
// produced under the right keys with a findings-bearing summary.
func TestMergeFromRawPath(t *testing.T) {
	globalARN := "arn:aws:kms::111122223333:key/global-key"
	regionalARN := "arn:aws:kms:ap-south-1:111122223333:key/regional-key"

	scans := []models.ScanResult{
		mkRawShard("111122223333", "us-east-1", globalARN, models.SeverityCritical),
		mkRawShard("111122223333", "ap-south-1", globalARN, models.SeverityCritical), // duplicate ARN -> collapses
		mkRawShard("111122223333", "ap-south-1", regionalARN, models.SeverityHigh),   // distinct ARN -> kept
	}

	res := mergeRawShards(scans)
	if got := res.Merged.Summary.TotalAssets; got != 2 {
		t.Errorf("merged assets: got=%d want=2 (global ARN dedups across regions)", got)
	}
	if got := res.Merged.Summary.TotalFindings; got != 2 {
		t.Errorf("merged findings: got=%d want=2", got)
	}
	if got := res.Merged.Summary.Critical; got != 1 {
		t.Errorf("merged critical: got=%d want=1", got)
	}

	artifacts, keys, _, err := buildMergeArtifacts(res, "run-test", len(res.Coverage), accountBarrier{})
	if err != nil {
		t.Fatalf("buildMergeArtifacts: %v", err)
	}
	for _, k := range []string{keys.CBOM, keys.Roadmap, keys.RoadmapM, keys.Coverage, keys.Summary} {
		body, ok := artifacts[k]
		if !ok {
			t.Errorf("artifact missing for key %q", k)
			continue
		}
		if len(body) == 0 {
			t.Errorf("artifact %q is empty", k)
		}
	}
	if !strings.HasPrefix(keys.CBOM, "scans/latest/run-test") {
		t.Errorf("CBOM key %q not under scans/latest/run-test", keys.CBOM)
	}

	// The dashboard-compatible summary must carry the merged totals so consumers
	// reading the old counts shape keep working.
	var summary mergeSummary
	if err := json.Unmarshal(artifacts[keys.Summary], &summary); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if summary.RunID != "run-test" {
		t.Errorf("summary.RunID: got=%q want=run-test", summary.RunID)
	}
	if summary.TotalFindings != 2 || summary.TotalCritical != 1 || summary.TotalAssets != 2 {
		t.Errorf("summary totals: findings=%d critical=%d assets=%d want 2/1/2",
			summary.TotalFindings, summary.TotalCritical, summary.TotalAssets)
	}
	// 3 shards scanned -> coverage has 3 (account,region,arn) rows; the per-account
	// roll-up aggregates them under the single member account.
	if summary.AccountsRegionsScanned != 3 {
		t.Errorf("summary.AccountsRegionsScanned: got=%d want=3", summary.AccountsRegionsScanned)
	}
	if len(summary.PerAccount) != 1 || summary.PerAccount[0].AccountID != "111122223333" {
		t.Errorf("summary.PerAccount: got=%+v want single account 111122223333", summary.PerAccount)
	}
}

// TestPerAccountReconcilesToDedupedTotal is an Edge #5 numeric-integrity guard:
// the /summary perAccount rollup must reconcile to the DEDUPED org headline.
// Before the fix, buildMergeSummary summed RAW per-shard coverage counts, so a
// member account's reported asset/finding count was inflated by every global
// resource (S3/CloudFront/IAM/...) seen in more than one region shard — making
// sum(perAccount.assets) EXCEED summary.TotalAssets and disagree with the
// dashboard's own mock/fallback derivation (summaryFromCBOM), which counts
// deduped CBOM components. Each member account's counts must now be computed
// from the deduped merged sets (grouped by the asset/finding's real AccountID),
// so the per-account rollup sums exactly to the headline total.
func TestPerAccountReconcilesToDedupedTotal(t *testing.T) {
	globalARN := "arn:aws:s3:::org-global-bucket" // one true asset, in 3 regions
	regionalARN := "arn:aws:kms:ap-south-1:111122223333:key/regional"
	scans := []models.ScanResult{
		mkRawShard("111122223333", "us-east-1", globalARN, models.SeverityCritical),
		mkRawShard("111122223333", "us-west-2", globalARN, models.SeverityCritical),  // dup ARN -> collapses
		mkRawShard("111122223333", "ap-south-1", globalARN, models.SeverityCritical), // dup ARN -> collapses
		mkRawShard("111122223333", "ap-south-1", regionalARN, models.SeverityHigh),   // distinct
	}
	res := mergeRawShards(scans)
	keys := mergedKeys("run-recon")
	s := buildMergeSummary(res, "run-recon", keys, len(res.Coverage), accountBarrier{})

	// Headline is deduped: global bucket (1) + regional key (1) = 2.
	if s.TotalAssets != 2 || s.TotalFindings != 2 {
		t.Fatalf("deduped headline: assets=%d findings=%d, want 2/2", s.TotalAssets, s.TotalFindings)
	}
	// The per-account rollup must sum to the deduped headline, NOT the raw 4.
	var sumAssets, sumFindings int
	for _, a := range s.PerAccount {
		sumAssets += a.Assets
		sumFindings += a.Findings
	}
	if sumAssets != s.TotalAssets {
		t.Errorf("sum(perAccount.assets)=%d but TotalAssets=%d — per-account counts do not reconcile to the deduped headline (cross-region duplicates inflate the per-account count)", sumAssets, s.TotalAssets)
	}
	if sumFindings != s.TotalFindings {
		t.Errorf("sum(perAccount.findings)=%d but TotalFindings=%d — per-account finding counts do not reconcile to the deduped headline", sumFindings, s.TotalFindings)
	}
}

// TestPerAccountSumsAcrossAccounts proves the per-account rollup partitions the
// deduped org totals across multiple member accounts with no loss or double
// count: each distinct account's deduped assets/findings are attributed to that
// account, and the columns sum to the headline.
func TestPerAccountSumsAcrossAccounts(t *testing.T) {
	scans := []models.ScanResult{
		mkRawShard("111111111111", "us-east-1", "arn:aws:kms:us-east-1:111111111111:key/a", models.SeverityHigh),
		mkRawShard("111111111111", "us-west-2", "arn:aws:kms:us-west-2:111111111111:key/b", models.SeverityMedium),
		mkRawShard("222222222222", "us-east-1", "arn:aws:kms:us-east-1:222222222222:key/c", models.SeverityCritical),
	}
	res := mergeRawShards(scans)
	s := buildMergeSummary(res, "run-multi", mergedKeys("run-multi"), len(res.Coverage), accountBarrier{})

	if s.TotalAssets != 3 || s.TotalFindings != 3 {
		t.Fatalf("headline assets=%d findings=%d, want 3/3", s.TotalAssets, s.TotalFindings)
	}
	byAcct := map[string]mergeSummaryAccount{}
	var sumA, sumF int
	for _, a := range s.PerAccount {
		byAcct[a.AccountID] = a
		sumA += a.Assets
		sumF += a.Findings
	}
	if sumA != 3 || sumF != 3 {
		t.Errorf("per-account columns sum to assets=%d findings=%d, want 3/3", sumA, sumF)
	}
	if byAcct["111111111111"].Assets != 2 {
		t.Errorf("account 111: assets=%d, want 2", byAcct["111111111111"].Assets)
	}
	if byAcct["222222222222"].Assets != 1 {
		t.Errorf("account 222: assets=%d, want 1", byAcct["222222222222"].Assets)
	}
}

// TestMergeFromRawEmpty proves an empty raw-shard set still yields a well-formed
// (empty) merged envelope and all five artifacts, so a run with zero shards does
// not crash the merge step.
func TestMergeFromRawEmpty(t *testing.T) {
	res := mergeRawShards(nil)
	artifacts, keys, _, err := buildMergeArtifacts(res, "run-empty", 0, accountBarrier{})
	if err != nil {
		t.Fatalf("buildMergeArtifacts(empty): %v", err)
	}
	if got := res.Merged.Summary.TotalFindings; got != 0 {
		t.Errorf("empty merge findings: got=%d want=0", got)
	}
	for _, k := range []string{keys.CBOM, keys.Roadmap, keys.RoadmapM, keys.Coverage, keys.Summary} {
		if len(artifacts[k]) == 0 {
			t.Errorf("empty-run artifact %q missing/empty", k)
		}
	}
}

// TestParseLambdaEventMergeExpectedShards proves the completion-barrier field
// parses, and that a legacy merge event without it yields ExpectedShards=0.
func TestParseLambdaEventMergeExpectedShards(t *testing.T) {
	withE, err := parseLambdaEvent([]byte(`{"mode":"lambda","merge":true,"runId":"run-x","expectedShards":12}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !withE.Merge || withE.ExpectedShards != 12 {
		t.Errorf("merge=%v expectedShards=%d, want true/12", withE.Merge, withE.ExpectedShards)
	}
	legacy, _ := parseLambdaEvent([]byte(`{"mode":"lambda","merge":true,"runId":"run-x"}`))
	if legacy.ExpectedShards != 0 {
		t.Errorf("legacy expectedShards=%d, want 0 (unknown)", legacy.ExpectedShards)
	}
}

// TestMergeCompletionBarrier proves buildMergeSummary reconciles observed shards
// against the seed-emitted expected count: a shortfall sets missing>0/complete=
// false; a match sets complete=true; an unknown (0) expected never reports a
// bogus shortfall; observed>expected clamps missing at 0.
func TestMergeCompletionBarrier(t *testing.T) {
	// Build a merged Result with 2 coverage rows (2 observed shards).
	res := mergeRawShards([]models.ScanResult{
		mkRawShard("111111111111", "us-east-1", "arn:aws:s3:::a", models.SeverityInformational),
		mkRawShard("222222222222", "us-east-1", "arn:aws:s3:::b", models.SeverityInformational),
	})
	keys := mergedKeys("run-x")

	// expected=3, observed=2 -> missing 1, incomplete.
	s := buildMergeSummary(res, "run-x", keys, 3, accountBarrier{})
	if s.ObservedShards != 2 || s.ExpectedShards != 3 || s.MissingShards != 1 || s.Complete {
		t.Errorf("shortfall: observed=%d expected=%d missing=%d complete=%v, want 2/3/1/false", s.ObservedShards, s.ExpectedShards, s.MissingShards, s.Complete)
	}
	// expected=2 -> complete.
	if s := buildMergeSummary(res, "run-x", keys, 2, accountBarrier{}); s.MissingShards != 0 || !s.Complete {
		t.Errorf("match: missing=%d complete=%v, want 0/true", s.MissingShards, s.Complete)
	}
	// expected=0 (unknown/legacy) -> complete, no shortfall.
	if s := buildMergeSummary(res, "run-x", keys, 0, accountBarrier{}); s.MissingShards != 0 || !s.Complete {
		t.Errorf("unknown: missing=%d complete=%v, want 0/true (no bogus shortfall)", s.MissingShards, s.Complete)
	}
	// observed>expected -> clamp missing at 0.
	if s := buildMergeSummary(res, "run-x", keys, 1, accountBarrier{}); s.MissingShards != 0 {
		t.Errorf("over-count: missing=%d, want 0 (clamped)", s.MissingShards)
	}
}

// TestMergeAccountBarrier proves the per-account completion barrier (hierarchical
// merge tier 2): a partially-failed tier-1 per-account merge — recorded as a
// missing account by runMergeMode — forces the org summary incomplete and lists
// the specific missing accounts, even when the seed shard count happens to
// reconcile. An empty barrier (raw-shard fallback / all accounts folded) leaves
// the summary clean.
func TestMergeAccountBarrier(t *testing.T) {
	res := mergeRawShards([]models.ScanResult{
		mkRawShard("111111111111", "us-east-1", "arn:aws:s3:::a", models.SeverityInformational),
		mkRawShard("222222222222", "us-east-1", "arn:aws:s3:::b", models.SeverityInformational),
	})
	keys := mergedKeys("run-x")

	// A missing account forces incomplete and surfaces the specific account ID,
	// even though the shard count reconciles (expected=2, observed=2).
	barrier := accountBarrier{expectedAccounts: 3, missingAccounts: []missingAccount{
		{accountID: "333333333333", reason: "per-account merged object decode failed (corrupt/truncated): unexpected EOF"},
	}}
	s := buildMergeSummary(res, "run-x", keys, 2, barrier)
	if s.Complete || !s.Incomplete {
		t.Errorf("missing account must force complete=false/incomplete=true, got complete=%v incomplete=%v", s.Complete, s.Incomplete)
	}
	if s.ExpectedAccounts != 3 {
		t.Errorf("expectedAccounts: got=%d want=3", s.ExpectedAccounts)
	}
	if len(s.MissingAccounts) != 1 || s.MissingAccounts[0] != "333333333333" {
		t.Errorf("missingAccounts: got=%+v want [333333333333]", s.MissingAccounts)
	}
	// The structured failed-shard list must name the account (region "*" — the whole
	// account's regions are unaccounted) and carry the recorded reason.
	if len(s.FailedShards) != 1 {
		t.Fatalf("FailedShards: got=%+v want exactly 1 row", s.FailedShards)
	}
	if fs := s.FailedShards[0]; fs.AccountID != "333333333333" || fs.Region != "*" ||
		!strings.Contains(fs.Reason, "decode failed") {
		t.Errorf("FailedShards[0]: got=%+v want account=333333333333 region=* reason~decode failed", fs)
	}

	// Empty barrier (all per-account objects folded, or raw fallback) with a
	// matching shard count stays complete with no missing accounts reported.
	clean := buildMergeSummary(res, "run-x", keys, 2, accountBarrier{expectedAccounts: 2})
	if !clean.Complete || clean.Incomplete || len(clean.MissingAccounts) != 0 || len(clean.FailedShards) != 0 {
		t.Errorf("clean: complete=%v incomplete=%v missing=%+v failed=%+v, want true/false/empty/empty",
			clean.Complete, clean.Incomplete, clean.MissingAccounts, clean.FailedShards)
	}
}

// TestMergeFailedShardReport proves the loud-incomplete structured report
// (DECISION): the merged summary lists every dropped/failed (account,region)
// tuple with its reason, folding all three classes — errored shards (a shard that
// landed but had service errors), missing per-account objects, and the
// vanished-shard count gap — and sets the loud top-level Incomplete flag. A clean
// run carries no FailedShards and Incomplete=false.
func TestMergeFailedShardReport(t *testing.T) {
	// One clean shard + one errored shard (an injected service error), so the
	// coverage carries an Errored=true row for 222222222222/ap-south-1.
	clean := mkRawShard("111111111111", "us-east-1", "arn:aws:s3:::clean", models.SeverityInformational)
	errored := mkRawShard("222222222222", "ap-south-1", "arn:aws:s3:::bad", models.SeverityInformational)
	errored.ServiceStats = []models.ServiceScanReport{{
		Service: "s3",
		Errors:  []string{"AccessDenied: assume-role failed"},
	}}
	res := mergeRawShards([]models.ScanResult{clean, errored})
	keys := mergedKeys("run-f")

	// expectedShards=4 but only 2 landed -> a 2-shard vanished gap; plus the errored
	// shard; plus a missing per-account object. All three must appear, loudly.
	barrier := accountBarrier{expectedAccounts: 3, missingAccounts: []missingAccount{
		{accountID: "444444444444", reason: "per-account merged object fetch failed: NoSuchKey"},
	}}
	s := buildMergeSummary(res, "run-f", keys, 4, barrier)

	if !s.Incomplete || s.Complete {
		t.Fatalf("incomplete=%v complete=%v, want true/false", s.Incomplete, s.Complete)
	}
	if s.MissingShards != 2 {
		t.Errorf("MissingShards: got=%d want=2", s.MissingShards)
	}

	// Index the structured rows by account for assertion clarity.
	byAcct := map[string]failedShard{}
	for _, fs := range s.FailedShards {
		byAcct[fs.AccountID] = fs
	}
	if len(s.FailedShards) != 3 {
		t.Fatalf("FailedShards: got %d rows (%+v), want 3 (errored + missing-account + vanished-gap)", len(s.FailedShards), s.FailedShards)
	}
	// Errored shard: region known, reason names the partial coverage.
	if fs, ok := byAcct["222222222222"]; !ok || fs.Region != "ap-south-1" || !strings.Contains(fs.Reason, "service-scan errors") {
		t.Errorf("errored-shard row: got=%+v ok=%v", fs, ok)
	}
	// Missing per-account object: region "*", carries the recorded fetch reason.
	if fs, ok := byAcct["444444444444"]; !ok || fs.Region != "*" || !strings.Contains(fs.Reason, "fetch failed") {
		t.Errorf("missing-account row: got=%+v ok=%v", fs, ok)
	}
	// Vanished-shard gap: synthetic "*"/"*" row naming the count shortfall.
	if fs, ok := byAcct["*"]; !ok || fs.Region != "*" || !strings.Contains(fs.Reason, "never landed") {
		t.Errorf("vanished-gap row: got=%+v ok=%v", fs, ok)
	}

	// Clean run: no failed shards, not incomplete.
	cleanS := buildMergeSummary(mergeRawShards([]models.ScanResult{clean}), "run-f", keys, 1, accountBarrier{})
	if cleanS.Incomplete || len(cleanS.FailedShards) != 0 {
		t.Errorf("clean: incomplete=%v failed=%+v, want false/empty", cleanS.Incomplete, cleanS.FailedShards)
	}
}

// TestSummarizePostureCounts + TestHeadlineCallouts lock the /summary posture
// rollup: per-posture bucketing mirrors the dashboard, and the two honest headline
// callouts replace the retired single headline percentage — quantumVulnerablePct =
// (legacyTLS+nonPQCClassical)/classifiable (Unknown excluded), and pqcEndToEndPct =
// pqcReady/total (hybrid-with-classical-cert and symmetric-only EXCLUDED from the
// numerator; full asset total in the denominator).
func TestSummarizePostureCounts(t *testing.T) {
	mk := func(posture models.CryptoPosture) models.CryptoAsset {
		a := models.CryptoAsset{Properties: map[string]string{}}
		if posture != "" {
			a.Properties["posture"] = string(posture)
		}
		return a
	}
	assets := []models.CryptoAsset{
		mk(models.PostureNoEncryption),
		mk(models.PostureLegacyTLS),
		mk(models.PostureNonPQCClassical), mk(models.PostureNonPQCClassical),
		mk(models.PostureSymmetricOnly), mk(models.PostureSymmetricOnly), mk(models.PostureSymmetricOnly),
		mk(models.PosturePQCHybrid),
		mk(models.PosturePQCReady),
		mk(""), // missing -> unknown
	}
	p := summarizePostureCounts(assets)
	if p.NoEncryption != 1 || p.LegacyTLS != 1 || p.NonPQCClassical != 2 ||
		p.SymmetricOnly != 3 || p.PQCHybrid != 1 || p.PQCReady != 1 || p.Unknown != 1 {
		t.Errorf("posture counts = %+v", p)
	}
}

func TestHeadlineCallouts(t *testing.T) {
	// noenc(1) legacy(1) classical(2) sym(3) hybrid(1) ready(1) unknown(1).
	p := mergeSummaryPosture{
		NoEncryption: 1, LegacyTLS: 1, NonPQCClassical: 2,
		SymmetricOnly: 3, PQCHybrid: 1, PQCReady: 1, Unknown: 1,
	}
	// quantumVulnerablePct: vulnerable = legacy(1)+classical(2) = 3; classifiable =
	// all-but-unknown = 1+1+2+3+1+1 = 9; 3/9 = 33.33% -> round = 33.
	if got := quantumVulnerablePct(p); got != 33 {
		t.Errorf("quantumVulnerablePct = %d, want 33", got)
	}
	// pqcEndToEndPct: numerator = pqcReady(1) ONLY (hybrid + symmetric EXCLUDED);
	// denominator = full total incl. unknown = 10; 1/10 = 10%.
	if got := pqcEndToEndPct(p); got != 10 {
		t.Errorf("pqcEndToEndPct = %d, want 10", got)
	}
	// No classifiable / no assets -> 0, never a divide-by-zero.
	if got := quantumVulnerablePct(mergeSummaryPosture{Unknown: 5}); got != 0 {
		t.Errorf("quantumVulnerablePct(only unknown) = %d, want 0", got)
	}
	if got := pqcEndToEndPct(mergeSummaryPosture{}); got != 0 {
		t.Errorf("pqcEndToEndPct(empty) = %d, want 0", got)
	}
	// Hybrid must NEVER count as end-to-end PQC: all-hybrid org -> 0%.
	if got := pqcEndToEndPct(mergeSummaryPosture{PQCHybrid: 4}); got != 0 {
		t.Errorf("pqcEndToEndPct(all hybrid) = %d, want 0", got)
	}
}
