package merge

import (
	"fmt"
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// This file holds Edge #5 numeric/aggregate-integrity tests for the org-wide
// merge: property-style assertions that no real asset is dropped or
// double-counted, that the recomputed summary counts reconcile to the emitted
// sets, and that the merge-layer seams that feed the dashboard's per-account
// rollup behave as documented.

// -----------------------------------------------------------------------------
// 1. MERGE CORRECTNESS — no loss / no double-count over N overlapping shards.
// -----------------------------------------------------------------------------

// TestMergeNoLossNoDoubleCount is the core property test. It builds many shards
// across several accounts/regions where each account has both account-scoped
// resources (distinct ARNs, must all survive) AND a per-account "global"
// resource repeated in every region shard of that account (one true asset, must
// collapse to ONE). The merged asset count must equal the number of DISTINCT
// ARNs — never more (double-count) and never fewer (silent drop).
func TestMergeNoLossNoDoubleCount(t *testing.T) {
	accounts := []string{"111111111111", "222222222222", "333333333333"}
	regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
	const regionalPerShard = 4 // distinct regional resources per (account,region)

	distinct := map[string]struct{}{}
	var scans []models.ScanResult

	for _, acct := range accounts {
		// One account-global resource (region-less ARN) repeated in every region
		// shard — exactly the S3/CloudFront/IAM case the dedup must collapse.
		globalARN := fmt.Sprintf("arn:aws:s3:::bucket-%s", acct)
		distinct[globalARN] = struct{}{}

		for _, region := range regions {
			var assets []models.CryptoAsset
			// The repeated account-global asset (same ARN -> same BomRef in every region).
			assets = append(assets, mkAsset(globalARN, "s3", acct, region, nil))
			// Distinct regional assets, unique per (account,region,index).
			for i := 0; i < regionalPerShard; i++ {
				arn := fmt.Sprintf("arn:aws:kms:%s:%s:key/k%d", region, acct, i)
				distinct[arn] = struct{}{}
				assets = append(assets, mkAsset(arn, "kms_spec", acct, region, nil))
			}
			scans = append(scans, models.ScanResult{
				Mode: "live", AccountID: acct, Region: region, Assets: assets,
			})
		}
	}

	wantDistinct := len(distinct)

	got := Merge(scans, "999999999999")

	// No loss, no double-count: emitted asset slice length == distinct ARN count.
	if len(got.Merged.Assets) != wantDistinct {
		t.Fatalf("merged assets = %d, want %d distinct ARNs (loss or double-count)", len(got.Merged.Assets), wantDistinct)
	}
	// Every distinct ARN is present exactly once (no silent overwrite of a real
	// asset by a collision, no phantom duplicate).
	seen := map[string]int{}
	for _, a := range got.Merged.Assets {
		seen[a.ResourceARN]++
	}
	if len(seen) != wantDistinct {
		t.Fatalf("distinct emitted ARNs = %d, want %d", len(seen), wantDistinct)
	}
	for arn, n := range seen {
		if n != 1 {
			t.Errorf("ARN %s emitted %d times, want exactly 1", arn, n)
		}
	}
	for arn := range distinct {
		if seen[arn] != 1 {
			t.Errorf("distinct input ARN %s missing from merge (silent drop)", arn)
		}
	}
}

// TestMergeOrderInvariance proves merge output is independent of shard input
// order — a permutation of the same shards yields the same deduped asset count
// and the same set of ARNs (the dedup/sort is order-stable on counts).
func TestMergeOrderInvariance(t *testing.T) {
	a := "arn:aws:kms:us-east-1:111111111111:key/a"
	b := "arn:aws:kms:us-west-2:111111111111:key/b"
	g := "arn:aws:s3:::shared" // global, in both shards

	forward := []models.ScanResult{
		{Mode: "live", AccountID: "111111111111", Region: "us-east-1", Assets: []models.CryptoAsset{
			mkAsset(a, "kms_spec", "111111111111", "us-east-1", nil),
			mkAsset(g, "s3", "111111111111", "us-east-1", nil),
		}},
		{Mode: "live", AccountID: "111111111111", Region: "us-west-2", Assets: []models.CryptoAsset{
			mkAsset(b, "kms_spec", "111111111111", "us-west-2", nil),
			mkAsset(g, "s3", "111111111111", "us-west-2", nil),
		}},
	}
	reverse := []models.ScanResult{forward[1], forward[0]}

	gf := Merge(forward, "999999999999")
	gr := Merge(reverse, "999999999999")

	if gf.Merged.Summary.TotalAssets != 3 || gr.Merged.Summary.TotalAssets != 3 {
		t.Fatalf("totals differ by order: forward=%d reverse=%d, want 3 each (a,b,g)",
			gf.Merged.Summary.TotalAssets, gr.Merged.Summary.TotalAssets)
	}
	collect := func(r []models.CryptoAsset) []string {
		out := make([]string, len(r))
		for i, x := range r {
			out[i] = x.BomRef
		}
		return out
	}
	ff, rr := collect(gf.Merged.Assets), collect(gr.Merged.Assets)
	for i := range ff {
		if ff[i] != rr[i] {
			t.Errorf("merged asset order differs by input order at %d: %q vs %q", i, ff[i], rr[i])
		}
	}
}

// TestDuplicateAccountRegionShard proves that two shards with the SAME
// (account,region) and the SAME assets (e.g. a shard written twice, or a retry)
// do not double-count assets/findings, while each shard still gets its own
// coverage row (coverage is intentionally per-shard, not deduped).
func TestDuplicateAccountRegionShard(t *testing.T) {
	arn := "arn:aws:kms:us-east-1:111111111111:key/a"
	one := models.ScanResult{
		Mode: "live", AccountID: "111111111111", Region: "us-east-1",
		Assets:   []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", nil)},
		Findings: []models.Finding{mkFinding(arn, "kms_spec", models.PostureNonPQCClassical, models.SeverityMedium, 3)},
	}
	got := Merge([]models.ScanResult{one, one}, "999999999999")

	if got.Merged.Summary.TotalAssets != 1 {
		t.Errorf("duplicate shard double-counted assets: got %d, want 1", got.Merged.Summary.TotalAssets)
	}
	if got.Merged.Summary.TotalFindings != 1 {
		t.Errorf("duplicate shard double-counted findings: got %d, want 1", got.Merged.Summary.TotalFindings)
	}
	if len(got.Coverage) != 2 {
		t.Errorf("coverage rows = %d, want 2 (one per input shard, even if duplicate)", len(got.Coverage))
	}
}

// TestEmptyAndSupersetShards proves empty shards contribute nothing to the
// deduped sets, and a shard that is a strict superset of another collapses to
// the superset's distinct assets (no double-count of the shared subset).
func TestEmptyAndSupersetShards(t *testing.T) {
	a := "arn:aws:kms:us-east-1:111111111111:key/a"
	b := "arn:aws:kms:us-east-1:111111111111:key/b"
	c := "arn:aws:kms:us-east-1:111111111111:key/c"

	subset := models.ScanResult{Mode: "live", AccountID: "111111111111", Region: "us-east-1",
		Assets: []models.CryptoAsset{
			mkAsset(a, "kms_spec", "111111111111", "us-east-1", nil),
			mkAsset(b, "kms_spec", "111111111111", "us-east-1", nil),
		}}
	superset := models.ScanResult{Mode: "live", AccountID: "111111111111", Region: "us-east-1",
		Assets: []models.CryptoAsset{
			mkAsset(a, "kms_spec", "111111111111", "us-east-1", nil),
			mkAsset(b, "kms_spec", "111111111111", "us-east-1", nil),
			mkAsset(c, "kms_spec", "111111111111", "us-east-1", nil),
		}}
	empty := models.ScanResult{Mode: "live", AccountID: "222222222222", Region: "eu-west-1"}

	got := Merge([]models.ScanResult{empty, subset, superset, empty}, "999999999999")
	if got.Merged.Summary.TotalAssets != 3 {
		t.Errorf("empty+subset+superset = %d distinct assets, want 3 (a,b,c)", got.Merged.Summary.TotalAssets)
	}
	if len(got.Coverage) != 4 {
		t.Errorf("coverage rows = %d, want 4 (one per input shard incl. empties)", len(got.Coverage))
	}
}

// -----------------------------------------------------------------------------
// 2. COUNT INVARIANTS — recomputed summary reconciles to the emitted sets.
// -----------------------------------------------------------------------------

// TestSummaryReconcilesToEmittedSets is the headline invariant: after merge,
// Summary.TotalAssets == len(Merged.Assets), Summary.TotalFindings ==
// len(Merged.Findings), and the per-severity finding counts sum to
// TotalFindings (the recomputed denominator the dashboard divides by).
func TestSummaryReconcilesToEmittedSets(t *testing.T) {
	mkF := func(arn, svc string, p models.CryptoPosture, sev models.Severity) models.Finding {
		f := mkFinding(arn, svc, p, sev, 1)
		return f
	}
	scans := []models.ScanResult{
		{Mode: "live", AccountID: "111111111111", Region: "us-east-1",
			Assets: []models.CryptoAsset{
				mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil),
				mkAsset("arn:aws:rds:us-east-1:111111111111:db:d1", "rds_transit", "111111111111", "us-east-1", nil),
			},
			Findings: []models.Finding{
				mkF("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", models.PostureNonPQCClassical, models.SeverityMedium),
				mkF("arn:aws:rds:us-east-1:111111111111:db:d1", "rds_transit", models.PostureLegacyTLS, models.SeverityHigh),
			}},
		{Mode: "live", AccountID: "222222222222", Region: "eu-west-1",
			Assets: []models.CryptoAsset{
				mkAsset("arn:aws:rds:eu-west-1:222222222222:db:d2", "rds_transit", "222222222222", "eu-west-1", nil),
			},
			Findings: []models.Finding{
				mkF("arn:aws:rds:eu-west-1:222222222222:db:d2", "rds_transit", models.PostureNoEncryption, models.SeverityCritical),
			}},
	}

	got := Merge(scans, "999999999999")
	s := got.Merged.Summary

	if s.TotalAssets != len(got.Merged.Assets) {
		t.Errorf("Summary.TotalAssets=%d but emitted %d assets", s.TotalAssets, len(got.Merged.Assets))
	}
	if s.TotalFindings != len(got.Merged.Findings) {
		t.Errorf("Summary.TotalFindings=%d but emitted %d findings", s.TotalFindings, len(got.Merged.Findings))
	}
	// Per-severity counts must sum to TotalFindings (no finding falls outside the
	// four severity buckets the summary recomputes; the % maturity denominator and
	// severity KPIs all derive from these).
	if sum := s.Critical + s.High + s.Medium + s.Informational; sum != s.TotalFindings {
		t.Errorf("severity buckets sum to %d but TotalFindings=%d (a finding severity is unbucketed)", sum, s.TotalFindings)
	}
}

// TestSeverityBucketsCoverAllFindings asserts every emitted finding lands in
// exactly one of the four counted buckets — so the recomputed Summary never
// silently undercounts a finding whose Severity string is outside the switch.
func TestSeverityBucketsCoverAllFindings(t *testing.T) {
	severities := []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityInformational,
	}
	var findings []models.Finding
	for i, sev := range severities {
		arn := fmt.Sprintf("arn:aws:kms:us-east-1:111111111111:key/k%d", i)
		findings = append(findings, mkFinding(arn, "kms_spec", models.PostureNonPQCClassical, sev, 1))
	}
	got := Merge([]models.ScanResult{{Mode: "live", Findings: findings}}, "1")
	s := got.Merged.Summary
	if s.Critical+s.High+s.Medium+s.Informational != s.TotalFindings {
		t.Errorf("not every severity bucketed: c=%d h=%d m=%d i=%d total=%d",
			s.Critical, s.High, s.Medium, s.Informational, s.TotalFindings)
	}
	if s.TotalFindings != 4 {
		t.Errorf("TotalFindings=%d, want 4", s.TotalFindings)
	}
}

// -----------------------------------------------------------------------------
// 3. SEAM CONTRACT — per-shard coverage counts are RAW (pre-dedup), the merged
//    Summary is DEDUPED. This is the seam the cmd-layer /summary perAccount
//    rollup is built on. The test PINS the documented divergence so any future
//    change to either side is caught: a naive consumer that sums coverage to get
//    the org total would OVER-count whenever a global resource spans shards.
// -----------------------------------------------------------------------------

// TestCoverageRawVsMergedDeduped documents and locks the invariant gap: the
// sum of per-shard Coverage.Assets is the RAW pre-dedup count (a global resource
// seen in N region shards is counted N times), whereas Summary.TotalAssets is
// the DEDUPED count (counted once). The cmd-layer mergeSummary.perAccount rollup
// sums Coverage.Assets, so on the live merge path a member account's reported
// asset/finding count is inflated by its cross-region duplicates and does NOT
// reconcile to the deduped headline TotalAssets — unlike the dashboard's own
// mock/fallback derivation (summaryFromCBOM), which counts deduped components and
// DOES reconcile. See finding in the audit report.
func TestCoverageRawVsMergedDeduped(t *testing.T) {
	g := "arn:aws:s3:::global-bucket" // one true asset, in 3 region shards
	var scans []models.ScanResult
	for _, region := range []string{"us-east-1", "us-west-2", "eu-west-1"} {
		scans = append(scans, models.ScanResult{
			Mode: "live", AccountID: "111111111111", Region: region,
			Assets: []models.CryptoAsset{mkAsset(g, "s3", "111111111111", region, nil)},
		})
	}
	got := Merge(scans, "999999999999")

	// Deduped headline: the global bucket is ONE asset.
	if got.Merged.Summary.TotalAssets != 1 {
		t.Fatalf("deduped TotalAssets = %d, want 1 (global bucket is one asset)", got.Merged.Summary.TotalAssets)
	}
	// Raw coverage: summing per-shard counts gives the PRE-dedup total (3 here).
	var rawSum int
	for _, c := range got.Coverage {
		rawSum += c.Assets
	}
	if rawSum != 3 {
		t.Fatalf("raw coverage sum = %d, want 3 (one row per shard, each counts the bucket)", rawSum)
	}
	// The divergence is the whole point: raw per-account sum != deduped total
	// whenever a global resource spans shards. This is the documented mis-
	// aggregation in the cmd-layer /summary perAccount rollup.
	if rawSum == got.Merged.Summary.TotalAssets {
		t.Fatalf("expected raw coverage sum (%d) to DIVERGE from deduped total (%d) when a global resource spans shards; "+
			"if they now match, the perAccount rollup may have been fixed to dedup — update this test and the audit",
			rawSum, got.Merged.Summary.TotalAssets)
	}
}

// -----------------------------------------------------------------------------
// 4. CROSS-ACCOUNT COLLISION SAFETY — distinct accounts must never collide.
// -----------------------------------------------------------------------------

// TestCrossAccountNoCollision proves that account-scoped resources in different
// accounts (whose ARNs embed the account id) never collide on BomRef, so an
// asset in account A cannot silently overwrite a same-named asset in account B.
func TestCrossAccountNoCollision(t *testing.T) {
	scans := []models.ScanResult{
		{Mode: "live", AccountID: "111111111111", Region: "us-east-1", Assets: []models.CryptoAsset{
			mkAsset("arn:aws:kms:us-east-1:111111111111:key/shared-alias", "kms_spec", "111111111111", "us-east-1", nil),
		}},
		{Mode: "live", AccountID: "222222222222", Region: "us-east-1", Assets: []models.CryptoAsset{
			mkAsset("arn:aws:kms:us-east-1:222222222222:key/shared-alias", "kms_spec", "222222222222", "us-east-1", nil),
		}},
	}
	got := Merge(scans, "999999999999")
	if got.Merged.Summary.TotalAssets != 2 {
		t.Fatalf("two distinct-account resources collapsed to %d, want 2 (cross-account collision)", got.Merged.Summary.TotalAssets)
	}
	if got.Multi.TotalAccounts != 2 {
		t.Errorf("TotalAccounts = %d, want 2", got.Multi.TotalAccounts)
	}
}

// TestEmptyARNFindingCollision is a FOCUSED probe of the findingKey fallback. A
// finding with NEITHER an AssetBomRef NOR a ResourceARN keys on
// "" + Service + Posture. Two genuinely DIFFERENT resources (different
// ResourceID, even different accounts) that both lack an ARN and share
// (Service, Posture) collide on this key and one is silently dropped, keeping
// only the higher severity. This documents the (narrow) condition under which a
// real finding can be lost in the merge. It is currently only reachable if a
// scanner emits findings with empty AssetBomRef AND empty ResourceARN.
func TestEmptyARNFindingCollision(t *testing.T) {
	mkNoRef := func(resourceID, acct, svc string, sev models.Severity) models.Finding {
		return models.Finding{
			Service:    svc,
			Posture:    models.PostureNonPQCClassical,
			Severity:   sev,
			AccountID:  acct,
			ResourceID: resourceID,
			// AssetBomRef and ResourceARN intentionally empty.
		}
	}
	scans := []models.ScanResult{
		{Mode: "live", AccountID: "111111111111", Findings: []models.Finding{
			mkNoRef("resource-A", "111111111111", "somesvc", models.SeverityMedium),
		}},
		{Mode: "live", AccountID: "222222222222", Findings: []models.Finding{
			mkNoRef("resource-B", "222222222222", "somesvc", models.SeverityHigh),
		}},
	}
	got := Merge(scans, "999999999999")

	// Document the ACTUAL behavior: the two ARN-less findings collide and one is
	// dropped. If a fix later disambiguates them (e.g. keying on ResourceID or
	// AccountID in the fallback), this count becomes 2 and the test should be
	// updated to assert no-loss. We assert the current lossy behavior so the
	// regression is visible and intentional, not a surprise.
	if len(got.Merged.Findings) != 1 {
		t.Fatalf("ARN-less collision: got %d findings; behavior changed — "+
			"if the fallback key now includes ResourceID/AccountID this is a FIX, update the audit and assert 2",
			len(got.Merged.Findings))
	}
	// The surviving one is the higher severity (highest-severity-wins union).
	if got.Merged.Findings[0].Severity != models.SeverityHigh {
		t.Errorf("survivor severity = %q, want HIGH (highest-severity-wins)", got.Merged.Findings[0].Severity)
	}
}
