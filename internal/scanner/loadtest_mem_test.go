package scanner

// Empirical per-shard memory + time scaling load test.
//
// This is NOT a normal unit test: it allocates hundreds of thousands of
// synthetic CryptoAssets and drives the REAL downstream shard path
// (BuildFindings -> buildSummary -> CBOM JSON marshal) to measure peak memory
// and wall time. It is gated behind the CRYPTAMAP_LOADTEST=1 env var so it never
// runs in normal CI (where it would burn minutes and gigabytes).
//
// Run it explicitly with:
//
//	CRYPTAMAP_LOADTEST=1 go test ./internal/scanner/ -run TestLoadScaling -v -timeout 20m
//
// Why this path mirrors a real shard (see internal/scanner/engine.go):
//   - engine.go:120,139 accumulate ALL assets into one allAssets slice.
//   - engine.go:147 (buildFindings -> BuildFindings) builds a parallel findings
//     slice of the same cardinality.
//   - engine.go:148 (buildSummary) walks both.
//   - the result is then JSON/CBOM-serialized (output.WriteCBOM / output.AsBytes),
//     which materializes a CDXBOM (a third full-cardinality slice of components)
//     PLUS the marshaled byte buffer.
//
// So peak heap is roughly: assets + findings + CDX components + the CBOM byte
// buffer. This test measures that peak empirically so the per-shard asset cap can
// be set from data instead of a guess, against the real Lambda limits
// (1024 MB memory, 15-min timeout — cdk scanner-stack.ts:43-44).

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// loadTestSizes are the per-shard asset counts to characterize. 500k is well
// beyond any realistic single-account/region shard, included to find the cliff.
var loadTestSizes = []int{10000, 50000, 100000, 250000, 500000}

// postureRotation cycles realistic postures so findings severity work and the
// compliance mapper both exercise their real branches (not one hot path).
var postureRotation = []models.CryptoPosture{
	models.PostureNoEncryption,
	models.PostureLegacyTLS,
	models.PostureNonPQCClassical,
	models.PostureSymmetricOnly,
	models.PosturePQCHybrid,
	models.PosturePQCReady,
	models.PostureUnknown,
}

// serviceRotation spreads assets across services so taxonomy lookup + the Mosca
// per-service score path are exercised, and so strings aren't all one interned
// constant.
var serviceRotation = []string{
	"s3", "kms", "acm", "elb", "cloudfront", "rds", "dynamodb", "ec2", "lambda", "iot",
}

// makeAsset synthesizes one realistic CryptoAsset. Every string varies with the
// index (via fmt.Sprintf) so the Go runtime cannot collapse them to a single
// interned pointer — this keeps the measured heap honest. The shape (number and
// size of fields/properties) mirrors the ~567-byte JSON footprint of a real
// asset from pkg/models.
func makeAsset(i int) models.CryptoAsset {
	posture := postureRotation[i%len(postureRotation)]
	service := serviceRotation[i%len(serviceRotation)]
	region := fmt.Sprintf("us-east-%d", (i%4)+1)
	resourceID := fmt.Sprintf("%s-resource-%08d", service, i)
	arn := fmt.Sprintf("arn:aws:%s:%s:1234567890%02d:resource/%s", service, region, i%100, resourceID)

	return models.CryptoAsset{
		BomRef:       models.BomRefForARN(arn),
		Name:         fmt.Sprintf("%s asset %08d", service, i),
		Description:  fmt.Sprintf("Synthetic load-test cryptographic asset number %08d for service %s in region %s", i, service, region),
		Service:      service,
		Category:     models.CategoryDataInTransit,
		AccountID:    fmt.Sprintf("1234567890%02d", i%100),
		Region:       region,
		ResourceID:   resourceID,
		ResourceARN:  arn,
		ResourceType: fmt.Sprintf("AWS::%s::Resource", service),
		CryptoProps: models.CryptoProperties{
			AssetType: models.AssetTypeProtocol,
			AlgorithmProperties: &models.AlgorithmProperties{
				Primitive:                models.PrimitiveKeyAgree,
				ParameterSetIdentifier:   fmt.Sprintf("param-%06d", i),
				Curve:                    "secp256r1",
				ClassicalSecurityLevel:   128,
				NistQuantumSecurityLevel: 0,
				KeySizeBits:              256,
				AlgorithmName:            "ECDHE-secp256r1",
			},
			ProtocolProperties: &models.ProtocolProperties{
				Type:                   "tls",
				Version:                "1.2",
				KeyExchangeGroup:       "secp256r1",
				CertSignatureAlgorithm: "sha256WithRSAEncryption",
				CertKeySizeBits:        2048,
				Source:                 "observed",
				TLSMinVersion:          "1.2",
			},
		},
		Tags: map[string]string{
			"env":   fmt.Sprintf("env-%d", i%3),
			"owner": fmt.Sprintf("team-%04d", i%1000),
		},
		DiscoveredAt: time.Now().UTC(),
		Properties: map[string]string{
			"posture":    string(posture),
			"source":     "load-test",
			"endpoint":   fmt.Sprintf("https://%s.example.aws/%08d", service, i),
			"policyName": fmt.Sprintf("ELBSecurityPolicy-%06d", i),
		},
	}
}

// TestLoadScaling empirically measures per-shard memory + time scaling.
//
// For each N it: synthesizes N assets, runs the real BuildFindings +
// buildSummary the engine uses, assembles a ScanResult, and CBOM-marshals it via
// output.AsBytes — reproducing the real shard's peak allocation. It forces a GC
// before reading post stats so HeapAlloc reflects live (retained) memory, and
// reports TotalAlloc (cumulative churn) and Sys (OS-reserved high-water mark) too.
func TestLoadScaling(t *testing.T) {
	if os.Getenv("CRYPTAMAP_LOADTEST") != "1" {
		t.Skip("set CRYPTAMAP_LOADTEST=1 to run the per-shard memory/time scaling load test")
	}

	// Use the real default compliance registry (nil enabled => all 9 frameworks)
	// + default Mosca params so the finding-generation work matches a live shard
	// exactly.
	comp := compliance.NewRegistry(nil)
	eng := NewEngine(NewRegistry(), comp, EngineOptions{ToolVersion: "loadtest"})

	const mib = 1024.0 * 1024.0

	t.Logf("Real Lambda shard limits: 1024 MB memory, 15-min timeout (cdk scanner-stack.ts:43-44)")
	t.Logf("Peak model: assets + parallel findings + CDX components + CBOM byte buffer (~2x asset set + serialized bytes)")
	t.Logf("%10s | %14s | %14s | %14s | %16s | %12s",
		"N", "HeapAlloc MB", "TotalAlloc MB", "Sys MB", "marshal bytes MB", "elapsed ms")
	t.Logf("%s", "-----------+----------------+----------------+----------------+------------------+-------------")

	for _, n := range loadTestSizes {
		heapMB, totalMB, sysMB, marshalMB, elapsedMS := runOneScale(t, eng, comp, n)
		t.Logf("%10d | %14.1f | %14.1f | %14.1f | %16.1f | %12d",
			n, heapMB/mib, totalMB/mib, sysMB/mib, marshalMB/mib, elapsedMS)
	}
}

// runOneScale drives one N through the full shard path and returns raw byte
// counts (caller divides for MB) plus elapsed milliseconds.
func runOneScale(t *testing.T, eng *Engine, comp *compliance.Registry, n int) (heap, total, sys, marshal float64, elapsedMS int64) {
	t.Helper()

	// Clean baseline: drop anything retained from the previous N before we read
	// the "before" stats, so deltas are attributable to this iteration.
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	start := time.Now()

	// 1. Synthesize N realistic assets (the allAssets accumulation, engine.go:120,139).
	assets := make([]models.CryptoAsset, 0, n)
	for i := 0; i < n; i++ {
		assets = append(assets, makeAsset(i))
	}

	// 2. Real downstream shard path: findings + summary (engine.go:147-148),
	//    using the engine's own (exported-equivalent) builders.
	findings := eng.buildFindings(assets)
	summary := eng.buildSummary(assets, findings, len(serviceRotation))

	// 3. Assemble the ScanResult exactly as Engine.Run does (engine.go:150).
	scan := models.ScanResult{
		ScanID:      "loadtest-scan",
		AccountID:   "123456789012",
		Region:      "us-east-1",
		StartedAt:   start,
		CompletedAt: time.Now().UTC(),
		Mode:        "live",
		Summary:     summary,
		Assets:      assets,
		Findings:    findings,
		ToolVersion: "loadtest",
	}

	// 4. CBOM-marshal — this materializes the CDX component slice + the byte
	//    buffer, the real serialization peak a shard pays before S3 upload.
	cbom, err := output.AsBytes(scan)
	if err != nil {
		t.Fatalf("N=%d: output.AsBytes failed: %v", n, err)
	}
	marshalLen := len(cbom)

	elapsed := time.Since(start)

	// Force GC so HeapAlloc reflects retained live memory at the post-marshal
	// point. We keep references (assets/findings/scan/cbom) alive across the
	// read via runtime.KeepAlive below so the measurement captures the genuine
	// simultaneous footprint, not a partially-collected one.
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	heap = float64(after.HeapAlloc)
	total = float64(after.TotalAlloc - before.TotalAlloc)
	sys = float64(after.Sys)
	marshal = float64(marshalLen)
	elapsedMS = elapsed.Milliseconds()

	// Keep the big allocations alive until AFTER we read the post stats, so the
	// compiler/GC cannot reclaim them early and understate peak retained memory.
	runtime.KeepAlive(assets)
	runtime.KeepAlive(findings)
	runtime.KeepAlive(scan)
	runtime.KeepAlive(cbom)

	return heap, total, sys, marshal, elapsedMS
}
