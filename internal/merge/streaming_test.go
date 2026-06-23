package merge

import (
	"reflect"
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// shard builds a small synthetic shard with deterministic content for the
// equivalence tests. region varies the ARN so cross-region duplicates of the
// same logical bucket collapse (region-less S3 ARN), exercising dedup.
func shard(account, region string, n int, mode string) models.ScanResult {
	assets := make([]models.CryptoAsset, 0, n)
	findings := make([]models.Finding, 0, n)
	for i := 0; i < n; i++ {
		// Region-less ARN: same i across regions => same BomRef => dedups.
		arn := "arn:aws:s3:::bucket-" + account + "-" + itoa(i)
		a := models.CryptoAsset{
			BomRef: models.BomRefForARN(arn), Name: "bucket-" + itoa(i), Service: "s3",
			Category: models.CategoryDataAtRest, AccountID: account, Region: region,
			ResourceID: "bucket-" + itoa(i), ResourceType: "AWS::S3::Bucket", ResourceARN: arn,
			Properties: map[string]string{"posture": string(models.PostureSymmetricOnly)},
		}
		assets = append(assets, a)
		findings = append(findings, models.Finding{
			ID: arn, Severity: models.SeverityInformational, Posture: models.PostureSymmetricOnly,
			AccountID: account, Region: region, Service: "s3", ResourceID: a.ResourceID,
			ResourceARN: arn, AssetBomRef: a.BomRef,
		})
	}
	return models.ScanResult{
		ScanID: account + "-" + region, AccountID: account, Region: region, Mode: mode,
		StartedAt: time.Unix(1700000000, 0).UTC(), CompletedAt: time.Unix(1700001000, 0).UTC(),
		Assets: assets, Findings: findings, ToolVersion: "1.0.0",
		ServiceStats: []models.ServiceScanReport{{Service: "s3", AssetCount: n, DurationMS: 10}},
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestStreamingEqualsBatch is the load-bearing guarantee: folding shards through
// the streaming Merger (one at a time, shards discardable) produces a Result
// identical to the batch Merge over the same shards in the same order. If these
// ever diverge, the hierarchical merge would silently disagree with the CLI/test
// path.
func TestStreamingEqualsBatch(t *testing.T) {
	scans := []models.ScanResult{
		shard("111111111111", "us-east-1", 5, "live"),
		shard("111111111111", "us-west-2", 5, "live"), // same buckets, diff region -> dedup
		shard("222222222222", "us-east-1", 3, "live"),
		shard("333333333333", "eu-west-1", 7, "live"),
	}

	batch := Merge(scans, "999999999999")

	m := NewMerger("999999999999", true) // keepShards=true to match batch contract
	for _, s := range scans {
		m.Add(s)
	}
	stream := m.Finish()

	if !reflect.DeepEqual(batch, stream) {
		t.Fatalf("streaming Result != batch Result\n batch.Summary=%+v\nstream.Summary=%+v",
			batch.Merged.Summary, stream.Merged.Summary)
	}
}

// TestStreamingKeepShardsFalseDropsVerbatim proves keepShards=false omits the
// Multi.Scans verbatim copy (the memory win) while keeping Merged identical and
// the Multi accounting (TotalAccounts/TotalRegions) intact.
func TestStreamingKeepShardsFalseDropsVerbatim(t *testing.T) {
	scans := []models.ScanResult{
		shard("111111111111", "us-east-1", 4, "live"),
		shard("222222222222", "us-east-1", 4, "live"),
	}
	withShards := Merge(scans, "org")

	m := NewMerger("org", false)
	for _, s := range scans {
		m.Add(s)
	}
	lean := m.Finish()

	// Merged payload must be identical regardless of keepShards.
	if !reflect.DeepEqual(withShards.Merged, lean.Merged) {
		t.Errorf("Merged differs between keepShards true/false")
	}
	if !reflect.DeepEqual(withShards.Coverage, lean.Coverage) {
		t.Errorf("Coverage differs between keepShards true/false")
	}
	// keepShards=false drops the verbatim shards but keeps the accounting.
	if len(lean.Multi.Scans) != 0 {
		t.Errorf("keepShards=false Multi.Scans = %d, want 0 (memory win)", len(lean.Multi.Scans))
	}
	if lean.Multi.TotalAccounts != 2 || lean.Multi.TotalRegions != 1 {
		t.Errorf("lean Multi totals accounts=%d regions=%d, want 2/1", lean.Multi.TotalAccounts, lean.Multi.TotalRegions)
	}
	if len(withShards.Multi.Scans) != 2 {
		t.Errorf("keepShards=true Multi.Scans = %d, want 2", len(withShards.Multi.Scans))
	}
}

// TestAddPreMergedPreservesCoverage is the regression test for the coverage bug:
// folding per-account merged objects via AddPreMerged must preserve the REAL
// (account,region) coverage rows, so the final summary's succeeded/failed/
// perAccount accounting is correct — NOT collapsed to one sentinel "org" row.
func TestAddPreMergedPreservesCoverage(t *testing.T) {
	// Two accounts, each merged from its own region shards (tier 1).
	acct1 := Merge([]models.ScanResult{
		shard("111111111111", "us-east-1", 3, "live"),
		shard("111111111111", "us-west-2", 3, "live"),
	}, "org")
	acct2 := Merge([]models.ScanResult{
		shard("222222222222", "ap-south-1", 4, "live"),
	}, "org")

	// Tier 2: fold the per-account objects WITH their real coverage.
	final := NewMerger("org", false)
	final.AddPreMerged(acct1.Merged, acct1.Coverage)
	final.AddPreMerged(acct2.Merged, acct2.Coverage)
	res := final.Finish()

	// Coverage must reflect the 3 ORIGINAL (account,region) shards, not 2 sentinel
	// per-account rows.
	if len(res.Coverage) != 3 {
		t.Fatalf("coverage rows = %d, want 3 real (account,region) shards", len(res.Coverage))
	}
	accts := map[string]int{}
	for _, c := range res.Coverage {
		if c.AccountID == SentinelAccount {
			t.Errorf("coverage row has sentinel AccountID %q — real account id was lost", c.AccountID)
		}
		accts[c.AccountID]++
	}
	if accts["111111111111"] != 2 || accts["222222222222"] != 1 {
		t.Errorf("per-account coverage rows = %v, want {111...:2, 222...:1}", accts)
	}
	// Multi accounting derives from the real rows.
	if res.Multi.TotalAccounts != 2 || res.Multi.TotalRegions != 3 {
		t.Errorf("Multi accounts=%d regions=%d, want 2/3", res.Multi.TotalAccounts, res.Multi.TotalRegions)
	}
	// Assets dedup correctly across tiers: acct1 = 3 distinct (region-less ARN
	// collapses its 2 regions), acct2 = 4 distinct -> 7 total.
	if res.Merged.Summary.TotalAssets != 7 {
		t.Errorf("TotalAssets = %d, want 7 (acct1=3 region-deduped + acct2=4)", res.Merged.Summary.TotalAssets)
	}
}

// TestStreamingHierarchicalEqualsFlat proves the HIERARCHICAL invariant: merging
// per-account intermediate results (each itself a streaming merge of that
// account's region shards) and then folding those intermediates through a final
// streaming merge yields the same deduped asset/finding SET as one flat merge of
// all original shards. (The envelope/coverage shape differs by construction — a
// two-tier merge's "shards" are the per-account objects — so we compare the
// merged asset/finding identities, which is what the CBOM/roadmap consume.)
func TestStreamingHierarchicalEqualsFlat(t *testing.T) {
	a1r1 := shard("111111111111", "us-east-1", 5, "live")
	a1r2 := shard("111111111111", "us-west-2", 5, "live")
	a2r1 := shard("222222222222", "us-east-1", 6, "live")
	a3r1 := shard("333333333333", "eu-west-1", 4, "live")

	flat := Merge([]models.ScanResult{a1r1, a1r2, a2r1, a3r1}, "org")

	// Tier 1: per-account merges.
	acct1 := Merge([]models.ScanResult{a1r1, a1r2}, "org").Merged
	acct2 := Merge([]models.ScanResult{a2r1}, "org").Merged
	acct3 := Merge([]models.ScanResult{a3r1}, "org").Merged
	// Tier 2: final streaming merge over the per-account merged objects.
	final := NewMerger("org", false)
	for _, acct := range []models.ScanResult{acct1, acct2, acct3} {
		final.Add(acct)
	}
	hier := final.Finish()

	if flat.Merged.Summary.TotalAssets != hier.Merged.Summary.TotalAssets {
		t.Errorf("hierarchical TotalAssets=%d != flat=%d", hier.Merged.Summary.TotalAssets, flat.Merged.Summary.TotalAssets)
	}
	if flat.Merged.Summary.TotalFindings != hier.Merged.Summary.TotalFindings {
		t.Errorf("hierarchical TotalFindings=%d != flat=%d", hier.Merged.Summary.TotalFindings, flat.Merged.Summary.TotalFindings)
	}
	// Asset identities (BomRefs) must match exactly.
	flatRefs := map[string]bool{}
	for _, a := range flat.Merged.Assets {
		flatRefs[a.BomRef] = true
	}
	for _, a := range hier.Merged.Assets {
		if !flatRefs[a.BomRef] {
			t.Errorf("hierarchical produced asset %s absent from flat merge", a.BomRef)
		}
		delete(flatRefs, a.BomRef)
	}
	if len(flatRefs) != 0 {
		t.Errorf("flat merge had %d assets the hierarchical merge dropped", len(flatRefs))
	}
}
