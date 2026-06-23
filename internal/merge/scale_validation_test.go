package merge

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// makeShard builds one synthetic (account,region) ScanResult with assetsPerShard
// assets + findings, mimicking the live density (per-asset CryptoProps + Properties).
func makeShard(account, region string, assetsPerShard int) models.ScanResult {
	assets := make([]models.CryptoAsset, 0, assetsPerShard)
	findings := make([]models.Finding, 0, assetsPerShard)
	for i := 0; i < assetsPerShard; i++ {
		arn := fmt.Sprintf("arn:aws:s3:::bucket-%s-%s-%d", account, region, i)
		a := models.CryptoAsset{
			BomRef:       models.BomRefForARN(arn),
			Name:         fmt.Sprintf("bucket-%d", i),
			Service:      "s3",
			Category:     models.CategoryDataAtRest,
			AccountID:    account,
			Region:       region,
			ResourceID:   fmt.Sprintf("bucket-%d", i),
			ResourceType: "AWS::S3::Bucket",
			ResourceARN:  arn,
			CryptoProps: models.CryptoProperties{
				AssetType: models.AssetTypeAlgorithm,
				AlgorithmProperties: &models.AlgorithmProperties{
					Primitive: models.PrimitiveAE, Mode: "gcm",
					ParameterSetIdentifier: "256", AlgorithmName: "AES-256-GCM", KeySizeBits: 256,
				},
			},
			Properties: map[string]string{"posture": string(models.PostureSymmetricOnly)},
		}
		assets = append(assets, a)
		findings = append(findings, models.Finding{
			ID: arn, Title: "s3 finding", Description: "synthetic finding for scale validation of the merge path",
			Severity: models.SeverityInformational, Posture: models.PostureSymmetricOnly,
			AccountID: account, Region: region, Service: "s3", ResourceID: a.ResourceID,
			ResourceARN: arn, AssetBomRef: a.BomRef,
		})
	}
	return models.ScanResult{
		ScanID: account + "-" + region, AccountID: account, Region: region, Mode: "live",
		Assets: assets, Findings: findings,
		Summary: models.ScanSummary{TotalAssets: assetsPerShard, TotalFindings: assetsPerShard},
	}
}

// TestMergeScaleProfile is a manual profiling harness (run with -run
// TestMergeScaleProfile -v). It is skipped by default so it never slows CI. It
// builds accounts x regions shards of assetsPerShard each and reports merge time
// + peak heap, to locate the in-memory merge ceiling that the redesign doc
// addresses. NOT an assertion test — a measurement.
func TestMergeScaleProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("scale profile skipped in -short")
	}
	t.Skip("manual profiling harness; remove this Skip to run locally")

	for _, p := range []struct{ accounts, regions, perShard int }{
		{50, 4, 2000},  // 200 shards x 2k = 400k assets
		{100, 5, 2000}, // 500 shards x 2k = 1M assets
		{300, 5, 2000}, // 1500 shards x 2k = 3M assets
	} {
		shards := make([]models.ScanResult, 0, p.accounts*p.regions)
		for a := 0; a < p.accounts; a++ {
			for r := 0; r < p.regions; r++ {
				shards = append(shards, makeShard(fmt.Sprintf("acct%04d", a), fmt.Sprintf("region-%d", r), p.perShard))
			}
		}
		var m0 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		start := time.Now()
		res := Merge(shards, "orchestrator")
		elapsed := time.Since(start)
		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)
		t.Logf("accounts=%d regions=%d perShard=%d shards=%d -> mergedAssets=%d mergedFindings=%d | merge=%s | heapAlloc Δ=%dMB sys=%dMB",
			p.accounts, p.regions, p.perShard, len(shards),
			res.Merged.Summary.TotalAssets, res.Merged.Summary.TotalFindings,
			elapsed.Round(time.Millisecond),
			(m1.HeapAlloc-m0.HeapAlloc)/1024/1024, m1.Sys/1024/1024)
	}
}

// TestStreamingVsBatchMemory measures the memory win of folding shards ONE AT A
// TIME (streaming, shard dropped after Add — what the Lambda merge now does) vs
// loading ALL shards into a slice before merging (the old downloadRawShards +
// Merge path). Each is measured in isolation (the other's data is released +
// GC'd first) for a fair peak. Run separately per mode via the MODE env var to
// avoid one mode's heap polluting the other's peak:
//
//	MODE=batch go test ./internal/merge -run TestStreamingVsBatchMemory -v
//	MODE=stream go test ./internal/merge -run TestStreamingVsBatchMemory -v
//
// HONEST NOTE: streaming bounds the "all raw shards resident simultaneously"
// term (~halving peak for mostly-distinct orgs, more when shards overlap/dedup).
// It does NOT make the merge O(1): the final deduped working set still scales
// with the count of DISTINCT resources. For an org with millions of genuinely
// distinct assets the deduped set itself is large — that is the residual term
// the design doc's /tmp- or DynamoDB-backed dedup option would address. This
// harness makes both terms visible rather than overclaiming.
func TestStreamingVsBatchMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("scale profile skipped in -short")
	}
	t.Skip("manual profiling harness; set MODE=batch|stream and remove this Skip")

	const accounts, regions, perShard = 300, 5, 2000
	const total = accounts * regions
	mode := "stream" // override via env in real runs

	gen := func(i int) models.ScanResult {
		a, r := i/regions, i%regions
		return makeShard(fmt.Sprintf("acct%04d", a), fmt.Sprintf("region-%d", r), perShard)
	}

	runtime.GC()
	var peak uint64
	sample := func() {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		if ms.Sys > peak {
			peak = ms.Sys
		}
	}

	var assets int
	if mode == "batch" {
		shards := make([]models.ScanResult, 0, total)
		for i := 0; i < total; i++ {
			shards = append(shards, gen(i))
			if i%100 == 0 {
				sample()
			}
		}
		res := Merge(shards, "org")
		sample()
		assets = res.Merged.Summary.TotalAssets
	} else {
		m := NewMerger("org", false)
		for i := 0; i < total; i++ {
			s := gen(i)
			m.Add(s)
			s = models.ScanResult{} // drop the shard immediately (streaming)
			if i%100 == 0 {
				sample()
			}
		}
		res := m.Finish()
		sample()
		assets = res.Merged.Summary.TotalAssets
	}
	t.Logf("MODE=%s shards=%d mergedAssets=%d | peak sys=%dMB", mode, total, assets, peak/1024/1024)
}
