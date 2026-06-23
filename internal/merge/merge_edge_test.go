package merge

import (
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestMultiAccountDedupAndProvenance proves the headline org-wide behavior:
// the SAME ARN scanned in two different ACCOUNTS still keys on BomRef and
// collapses to one asset (BomRefForARN is account-agnostic), the kept asset's
// per-record provenance is preserved, and genuinely per-account distinct ARNs
// are unioned. This complements the single-account two-region case in
// merge_test.go.
func TestMultiAccountDedupAndProvenance(t *testing.T) {
	// A global resource ARN with no embedded account, the realistic collision
	// case across accounts (e.g. a shared/global ref or a re-scanned hub asset).
	sharedARN := "arn:aws:cloudfront::shared:distribution/E777"

	scans := []models.ScanResult{
		{
			Mode: "live", AccountID: "111111111111", Region: "us-east-1",
			Assets: []models.CryptoAsset{
				mkAsset(sharedARN, "cloudfront_certs", "111111111111", "us-east-1", nil),
				mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil),
			},
		},
		{
			Mode: "live", AccountID: "222222222222", Region: "us-east-1",
			Assets: []models.CryptoAsset{
				mkAsset(sharedARN, "cloudfront_certs", "222222222222", "us-east-1", nil),
				mkAsset("arn:aws:kms:us-east-1:222222222222:key/b", "kms_spec", "222222222222", "us-east-1", nil),
			},
		},
	}

	got := Merge(scans, "999999999999")

	// shared collapses to 1; the two account-specific KMS keys stay distinct => 3.
	if len(got.Merged.Assets) != 3 {
		t.Fatalf("merged assets = %d, want 3 (shared ARN collapses across accounts; 2 distinct KMS keys)", len(got.Merged.Assets))
	}
	if got.Merged.Summary.TotalAssets != 3 {
		t.Errorf("summary.TotalAssets = %d, want 3", got.Merged.Summary.TotalAssets)
	}
	// Two distinct services (cloudfront_certs, kms_spec).
	if got.Merged.Summary.ServiceCount != 2 {
		t.Errorf("summary.ServiceCount = %d, want 2", got.Merged.Summary.ServiceCount)
	}

	// The envelope uses sentinels, but every merged asset keeps a real account.
	for _, a := range got.Merged.Assets {
		if a.AccountID == SentinelAccount || a.AccountID == "" {
			t.Errorf("merged asset %s lost account provenance: %q", a.BomRef, a.AccountID)
		}
	}

	// Multi envelope counts two accounts, one region.
	if got.Multi.TotalAccounts != 2 {
		t.Errorf("Multi.TotalAccounts = %d, want 2", got.Multi.TotalAccounts)
	}
	if got.Multi.TotalRegions != 1 {
		t.Errorf("Multi.TotalRegions = %d, want 1", got.Multi.TotalRegions)
	}
}

// TestSourcePrecedenceFullLadder walks the complete precedence ladder pairwise
// (every higher source beats the next lower one) so a regression that reorders
// the Source constants is caught, regardless of shard order.
func TestSourcePrecedenceFullLadder(t *testing.T) {
	arn := "arn:aws:kms:us-east-1:111111111111:key/ladder"

	// Ordered weakest..strongest; each higher entry must win over each lower one.
	ladder := []string{"tagging", "config", "targeted-sdk", "active-probe"}

	for hi := 1; hi < len(ladder); hi++ {
		for lo := 0; lo < hi; lo++ {
			high, low := ladder[hi], ladder[lo]
			// Run both shard orders to prove order-independence.
			for _, order := range [][]string{{low, high}, {high, low}} {
				scans := []models.ScanResult{
					{Mode: "live", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": order[0]})}},
					{Mode: "live", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": order[1]})}},
				}
				got := Merge(scans, "999999999999")
				if len(got.Merged.Assets) != 1 {
					t.Fatalf("source %s vs %s order %v: want 1 deduped asset, got %d", high, low, order, len(got.Merged.Assets))
				}
				if got.Merged.Assets[0].Properties["source"] != high {
					t.Errorf("source %s vs %s order %v: kept %q, want %q", high, low, order, got.Merged.Assets[0].Properties["source"], high)
				}
			}
		}
	}
}

// TestPreferAssetTieBreaks exercises preferAsset's tie-break chain directly when
// the Source is equal: richer asset (more Properties) wins, then later
// DiscoveredAt, then lexicographically smaller ResourceARN.
func TestPreferAssetTieBreaks(t *testing.T) {
	t0 := time.Date(2026, 6, 3, 9, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 3, 10, 0, 0, 0, time.UTC)

	base := func(props map[string]string, discovered time.Time, arn string) assetCandidate {
		a := models.CryptoAsset{Properties: props, DiscoveredAt: discovered, ResourceARN: arn}
		return assetCandidate{asset: a, source: SourceConfig}
	}

	t.Run("richer asset wins on equal source", func(t *testing.T) {
		rich := base(map[string]string{"source": "config", "x": "1"}, t0, "arn:z")
		thin := base(map[string]string{"source": "config"}, t1, "arn:a")
		if !preferAsset(rich, thin) {
			t.Errorf("richer asset (more Properties) should win over thinner even with later time / smaller ARN on the other")
		}
		if preferAsset(thin, rich) {
			t.Errorf("thinner asset must not win over richer")
		}
	})

	t.Run("later DiscoveredAt wins when equal richness", func(t *testing.T) {
		early := base(map[string]string{"source": "config"}, t0, "arn:a")
		late := base(map[string]string{"source": "config"}, t1, "arn:z")
		if !preferAsset(late, early) {
			t.Errorf("later DiscoveredAt should win when source + richness are equal")
		}
	})

	t.Run("smaller ARN wins when richness + time equal", func(t *testing.T) {
		small := base(map[string]string{"source": "config"}, t0, "arn:aaa")
		large := base(map[string]string{"source": "config"}, t0, "arn:zzz")
		if !preferAsset(small, large) {
			t.Errorf("lexicographically smaller ResourceARN should win on full tie")
		}
		if preferAsset(large, small) {
			t.Errorf("larger ARN must not win on full tie (deterministic)")
		}
	})
}

// TestMixedModeBaseline proves the Mode-derived baseline is applied per-shard:
// a live-mode asset (baseline SourceConfig) beats a mock-mode asset (baseline
// SourceTagging) for the same BomRef when neither sets an explicit source.
func TestMixedModeBaseline(t *testing.T) {
	arn := "arn:aws:s3:::shared-bucket"
	scans := []models.ScanResult{
		{Mode: "mock", AccountID: "111111111111", Region: "us-east-1",
			Assets: []models.CryptoAsset{mkAsset(arn, "s3", "111111111111", "us-east-1", map[string]string{"k": "mock"})}},
		{Mode: "live", AccountID: "111111111111", Region: "us-east-1",
			Assets: []models.CryptoAsset{mkAsset(arn, "s3", "111111111111", "us-east-1", map[string]string{"k": "live"})}},
	}
	got := Merge(scans, "999999999999")
	if len(got.Merged.Assets) != 1 {
		t.Fatalf("want 1 deduped asset, got %d", len(got.Merged.Assets))
	}
	if got.Merged.Assets[0].Properties["k"] != "live" {
		t.Errorf("live-mode (SourceConfig baseline) should beat mock-mode (SourceTagging baseline); kept %q, want live", got.Merged.Assets[0].Properties["k"])
	}
}

// TestFindingKeyFallbackToARN proves findings with an empty AssetBomRef fall
// back to keying on ResourceARN, so two distinct unkeyed findings on different
// resources are NOT collapsed together (a real concern for findings emitted
// before an asset BomRef is assigned).
func TestFindingKeyFallbackToARN(t *testing.T) {
	mkBare := func(arn, svc string, sev models.Severity) models.Finding {
		return models.Finding{
			Service:     svc,
			Posture:     models.PostureNonPQCClassical,
			Severity:    sev,
			ResourceID:  arn,
			ResourceARN: arn,
			// AssetBomRef intentionally empty -> findingKey falls back to ResourceARN.
		}
	}

	t.Run("distinct ARNs not collapsed", func(t *testing.T) {
		scans := []models.ScanResult{
			{Mode: "live", Findings: []models.Finding{
				mkBare("arn:aws:rds:us-east-1:111111111111:db:one", "rds_transit", models.SeverityHigh),
				mkBare("arn:aws:rds:us-east-1:111111111111:db:two", "rds_transit", models.SeverityHigh),
			}},
		}
		got := Merge(scans, "999999999999")
		if len(got.Merged.Findings) != 2 {
			t.Fatalf("two distinct bare findings must stay 2, got %d", len(got.Merged.Findings))
		}
	})

	t.Run("same ARN collapses to highest severity", func(t *testing.T) {
		arn := "arn:aws:rds:us-east-1:111111111111:db:same"
		scans := []models.ScanResult{
			{Mode: "live", Findings: []models.Finding{mkBare(arn, "rds_transit", models.SeverityMedium)}},
			{Mode: "live", Findings: []models.Finding{mkBare(arn, "rds_transit", models.SeverityCritical)}},
		}
		got := Merge(scans, "999999999999")
		if len(got.Merged.Findings) != 1 {
			t.Fatalf("same bare ARN must collapse to 1, got %d", len(got.Merged.Findings))
		}
		if got.Merged.Findings[0].Severity != models.SeverityCritical {
			t.Errorf("collapsed bare finding severity = %q, want CRITICAL", got.Merged.Findings[0].Severity)
		}
	})
}

// TestCoverageErroredAcrossShards proves the per-shard errored flag and counts
// are independent per shard, and that input order is preserved even when a
// later shard errors and an earlier one does not.
func TestCoverageErroredAcrossShards(t *testing.T) {
	scans := []models.ScanResult{
		{
			Mode: "live", AccountID: "111111111111", Region: "us-east-1",
			Assets: []models.CryptoAsset{mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil)},
			ServiceStats: []models.ServiceScanReport{
				{Service: "kms_spec", AssetCount: 1}, // no errors
			},
		},
		{
			Mode: "live", AccountID: "222222222222", Region: "eu-west-1",
			ServiceStats: []models.ServiceScanReport{
				{Service: "kms_spec", AssetCount: 0, Errors: []string{"AccessDenied"}},
			},
		},
		{
			Mode: "live", AccountID: "333333333333", Region: "ap-south-1",
			Assets: []models.CryptoAsset{mkAsset("arn:aws:kms:ap-south-1:333333333333:key/c", "kms_spec", "333333333333", "ap-south-1", nil)},
			ServiceStats: []models.ServiceScanReport{
				{Service: "kms_spec", AssetCount: 1},
			},
		},
	}

	got := Merge(scans, "999999999999")

	if len(got.Coverage) != 3 {
		t.Fatalf("coverage rows = %d, want 3 (one per shard)", len(got.Coverage))
	}
	// Input order preserved.
	wantAccts := []string{"111111111111", "222222222222", "333333333333"}
	for i, want := range wantAccts {
		if got.Coverage[i].AccountID != want {
			t.Errorf("coverage[%d].AccountID = %q, want %q (input order must be preserved)", i, got.Coverage[i].AccountID, want)
		}
	}
	// Only the middle shard errored.
	if got.Coverage[0].Errored {
		t.Errorf("coverage[0].Errored = true, want false")
	}
	if !got.Coverage[1].Errored {
		t.Errorf("coverage[1].Errored = false, want true (AccessDenied)")
	}
	if got.Coverage[2].Errored {
		t.Errorf("coverage[2].Errored = true, want false")
	}
	// The errored shard scanned zero assets; that must not be hidden.
	if got.Coverage[1].Assets != 0 {
		t.Errorf("coverage[1].Assets = %d, want 0 (errored shard found nothing)", got.Coverage[1].Assets)
	}
}

// TestUnionServiceStatsNilSafe proves unionServiceStats returns nil (not an
// empty slice that would imply "scanned, zero services") when no shard carried
// any ServiceStats, and otherwise unions deterministically by service.
func TestUnionServiceStatsNilSafe(t *testing.T) {
	t.Run("no stats anywhere -> nil", func(t *testing.T) {
		scans := []models.ScanResult{
			{Mode: "live", Assets: []models.CryptoAsset{mkAsset("arn:aws:s3:::b", "s3", "1", "us-east-1", nil)}},
		}
		got := Merge(scans, "1")
		if got.Merged.ServiceStats != nil {
			t.Errorf("ServiceStats = %v, want nil when no shard carried stats", got.Merged.ServiceStats)
		}
	})

	t.Run("union sorted by service", func(t *testing.T) {
		scans := []models.ScanResult{
			{Mode: "live", ServiceStats: []models.ServiceScanReport{
				{Service: "s3", AssetCount: 2, DurationMS: 10},
				{Service: "kms_spec", AssetCount: 1, DurationMS: 5},
			}},
			{Mode: "live", ServiceStats: []models.ServiceScanReport{
				{Service: "s3", AssetCount: 3, DurationMS: 7},
			}},
		}
		got := Merge(scans, "1")
		if len(got.Merged.ServiceStats) != 2 {
			t.Fatalf("union stats = %d, want 2", len(got.Merged.ServiceStats))
		}
		// Sorted: kms_spec before s3.
		if got.Merged.ServiceStats[0].Service != "kms_spec" || got.Merged.ServiceStats[1].Service != "s3" {
			t.Errorf("union stats not sorted by service: %q, %q", got.Merged.ServiceStats[0].Service, got.Merged.ServiceStats[1].Service)
		}
		s3 := got.Merged.ServiceStats[1]
		if s3.AssetCount != 5 || s3.DurationMS != 17 {
			t.Errorf("s3 union AssetCount=%d DurationMS=%d, want 5/17", s3.AssetCount, s3.DurationMS)
		}
	})
}
