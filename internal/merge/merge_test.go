package merge

import (
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// mkAsset builds a CryptoAsset with a BomRef derived from arn (the real dedup
// key), mirroring how the scanner/mock paths populate it via BomRefForARN.
func mkAsset(arn, service, account, region string, props map[string]string) models.CryptoAsset {
	return models.CryptoAsset{
		BomRef:      models.BomRefForARN(arn),
		Name:        arn,
		Service:     service,
		AccountID:   account,
		Region:      region,
		ResourceID:  arn,
		ResourceARN: arn,
		Properties:  props,
	}
}

// mkFinding builds a Finding linked to an asset's BomRef.
func mkFinding(arn, service string, posture models.CryptoPosture, sev models.Severity, mosca int) models.Finding {
	return models.Finding{
		ID:          arn + "|" + service + "|" + string(posture),
		Service:     service,
		Posture:     posture,
		Severity:    sev,
		ResourceID:  arn,
		ResourceARN: arn,
		AssetBomRef: models.BomRefForARN(arn),
		Mosca:       models.MoscaScore{Score: mosca},
	}
}

// TestMergeDedupByBomRef proves the four core requirements in one table:
//   - two ScanResults sharing one ARN collapse to ONE asset (dedup by BomRef),
//   - distinct ARNs are unioned,
//   - summary counts are recomputed from the deduped sets,
//   - a global-service duplicate (same ARN in two region shards) collapses while
//     a genuinely regional resource (distinct ARNs) stays as two.
func TestMergeDedupByBomRef(t *testing.T) {
	globalARN := "arn:aws:cloudfront::111111111111:distribution/E123"

	tests := []struct {
		name           string
		scans          []models.ScanResult
		wantAssets     int
		wantFindings   int
		wantServiceCnt int
	}{
		{
			name: "same ARN in two regions collapses to one asset",
			scans: []models.ScanResult{
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset(globalARN, "cloudfront_certs", "111111111111", "us-east-1", nil)}},
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset(globalARN, "cloudfront_certs", "111111111111", "us-west-2", nil)}},
			},
			wantAssets:     1,
			wantServiceCnt: 1,
		},
		{
			name: "distinct ARNs are unioned",
			scans: []models.ScanResult{
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil)}},
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset("arn:aws:kms:us-west-2:111111111111:key/b", "kms_spec", "111111111111", "us-west-2", nil)}},
			},
			wantAssets:     2,
			wantServiceCnt: 1,
		},
		{
			name: "distinct services counted distinctly",
			scans: []models.ScanResult{
				{Mode: "live", Assets: []models.CryptoAsset{
					mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil),
					mkAsset("arn:aws:s3:::bucket-a", "s3_encryption", "111111111111", "us-east-1", nil),
				}},
			},
			wantAssets:     2,
			wantServiceCnt: 2,
		},
		{
			name: "duplicate ARN with a distinct ARN: one collapses, one unioned",
			scans: []models.ScanResult{
				{Mode: "live", Assets: []models.CryptoAsset{
					mkAsset(globalARN, "cloudfront_certs", "111111111111", "us-east-1", nil),
					mkAsset("arn:aws:rds:us-east-1:111111111111:db:prod", "rds_transit", "111111111111", "us-east-1", nil),
				}},
				{Mode: "live", Assets: []models.CryptoAsset{
					mkAsset(globalARN, "cloudfront_certs", "111111111111", "eu-west-1", nil),
				}},
			},
			wantAssets:     2, // global dup collapses to 1, rds is its own
			wantServiceCnt: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(tc.scans, "999999999999")
			if len(got.Merged.Assets) != tc.wantAssets {
				t.Fatalf("merged assets = %d, want %d", len(got.Merged.Assets), tc.wantAssets)
			}
			if got.Merged.Summary.TotalAssets != tc.wantAssets {
				t.Errorf("summary.TotalAssets = %d, want %d (must be recomputed from deduped set)", got.Merged.Summary.TotalAssets, tc.wantAssets)
			}
			if got.Merged.Summary.ServiceCount != tc.wantServiceCnt {
				t.Errorf("summary.ServiceCount = %d, want %d", got.Merged.Summary.ServiceCount, tc.wantServiceCnt)
			}
			// Assets must be sorted by BomRef for deterministic output.
			for i := 1; i < len(got.Merged.Assets); i++ {
				if got.Merged.Assets[i-1].BomRef > got.Merged.Assets[i].BomRef {
					t.Errorf("assets not sorted by BomRef at index %d", i)
				}
			}
		})
	}
}

// TestSourcePrecedence proves that on a BomRef collision the higher-ranked
// detection source wins, and that the absent-source Mode-derived baseline is
// applied deterministically.
func TestSourcePrecedence(t *testing.T) {
	arn := "arn:aws:kms:us-east-1:111111111111:key/shared"

	tests := []struct {
		name       string
		scans      []models.ScanResult
		wantSource string // expected Properties["source"] on the kept asset, "" if none
	}{
		{
			name: "active-probe beats config",
			scans: []models.ScanResult{
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": "config"})}},
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": "active-probe"})}},
			},
			wantSource: "active-probe",
		},
		{
			name: "active-probe beats config regardless of shard order",
			scans: []models.ScanResult{
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": "active-probe"})}},
				{Mode: "live", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": "config"})}},
			},
			wantSource: "active-probe",
		},
		{
			name: "targeted-sdk beats tagging",
			scans: []models.ScanResult{
				{Mode: "mock", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": "tagging"})}},
				{Mode: "mock", Assets: []models.CryptoAsset{mkAsset(arn, "kms_spec", "111111111111", "us-east-1", map[string]string{"source": "targeted-sdk"})}},
			},
			wantSource: "targeted-sdk",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(tc.scans, "999999999999")
			if len(got.Merged.Assets) != 1 {
				t.Fatalf("expected 1 deduped asset, got %d", len(got.Merged.Assets))
			}
			if got.Merged.Assets[0].Properties["source"] != tc.wantSource {
				t.Errorf("kept asset source = %q, want %q", got.Merged.Assets[0].Properties["source"], tc.wantSource)
			}
		})
	}
}

// TestSourceOfBaseline checks the Mode-derived baseline inference in isolation.
func TestSourceOfBaseline(t *testing.T) {
	tests := []struct {
		mode  string
		props map[string]string
		want  Source
	}{
		{"live", nil, SourceConfig},
		{"mock", nil, SourceTagging},
		{"", nil, SourceUnknown},
		{"weird", nil, SourceUnknown},
		{"live", map[string]string{"source": "active-probe"}, SourceActiveProbe},
		{"mock", map[string]string{"source": "targeted-sdk"}, SourceTargetedSDK},
		{"live", map[string]string{"source": "tagging"}, SourceTagging},
		{"mock", map[string]string{"source": "config"}, SourceConfig},
	}
	for _, tc := range tests {
		got := sourceOf(models.CryptoAsset{Properties: tc.props}, tc.mode)
		if got != tc.want {
			t.Errorf("sourceOf(mode=%q, props=%v) = %d, want %d", tc.mode, tc.props, got, tc.want)
		}
	}
}

// TestFindingUnionSeverity proves duplicate (bomref,service,posture) findings
// union to the highest NormalizedSeverity, and distinct keys are preserved.
func TestFindingUnionSeverity(t *testing.T) {
	arn := "arn:aws:rds:us-east-1:111111111111:db:prod"

	tests := []struct {
		name         string
		scans        []models.ScanResult
		wantFindings int
		wantTopSev   models.Severity
	}{
		{
			name: "same key keeps CRITICAL over MEDIUM",
			scans: []models.ScanResult{
				{Mode: "live", Findings: []models.Finding{mkFinding(arn, "rds_transit", models.PostureNonPQCClassical, models.SeverityMedium, 3)}},
				{Mode: "live", Findings: []models.Finding{mkFinding(arn, "rds_transit", models.PostureNonPQCClassical, models.SeverityCritical, 8)}},
			},
			wantFindings: 1,
			wantTopSev:   models.SeverityCritical,
		},
		{
			name: "same key keeps CRITICAL regardless of order",
			scans: []models.ScanResult{
				{Mode: "live", Findings: []models.Finding{mkFinding(arn, "rds_transit", models.PostureNonPQCClassical, models.SeverityCritical, 8)}},
				{Mode: "live", Findings: []models.Finding{mkFinding(arn, "rds_transit", models.PostureNonPQCClassical, models.SeverityMedium, 3)}},
			},
			wantFindings: 1,
			wantTopSev:   models.SeverityCritical,
		},
		{
			name: "distinct postures are NOT merged",
			scans: []models.ScanResult{
				{Mode: "live", Findings: []models.Finding{mkFinding(arn, "rds_transit", models.PostureNonPQCClassical, models.SeverityHigh, 5)}},
				{Mode: "live", Findings: []models.Finding{mkFinding(arn, "rds_transit", models.PostureLegacyTLS, models.SeverityCritical, 8)}},
			},
			wantFindings: 2,
			wantTopSev:   models.SeverityCritical,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(tc.scans, "999999999999")
			if len(got.Merged.Findings) != tc.wantFindings {
				t.Fatalf("merged findings = %d, want %d", len(got.Merged.Findings), tc.wantFindings)
			}
			if got.Merged.Summary.TotalFindings != tc.wantFindings {
				t.Errorf("summary.TotalFindings = %d, want %d", got.Merged.Summary.TotalFindings, tc.wantFindings)
			}
			// Findings sorted by NormalizedSeverity desc; first must be the top.
			if got.Merged.Findings[0].Severity != tc.wantTopSev {
				t.Errorf("top finding severity = %q, want %q", got.Merged.Findings[0].Severity, tc.wantTopSev)
			}
		})
	}
}

// TestSummaryRecomputed proves the recomputed severity counts roll up correctly
// across the deduped finding set.
func TestSummaryRecomputed(t *testing.T) {
	scans := []models.ScanResult{
		{
			Mode: "live",
			Findings: []models.Finding{
				mkFinding("arn:a", "kms_spec", models.PostureNonPQCClassical, models.SeverityCritical, 9),
				mkFinding("arn:b", "rds_transit", models.PostureLegacyTLS, models.SeverityHigh, 5),
			},
		},
		{
			Mode: "live",
			Findings: []models.Finding{
				mkFinding("arn:c", "s3_encryption", models.PostureSymmetricOnly, models.SeverityInformational, 0),
				mkFinding("arn:d", "alb_listener", models.PostureUnknown, models.SeverityMedium, 2),
				// duplicate of arn:a finding at lower severity -> must collapse, not double count
				mkFinding("arn:a", "kms_spec", models.PostureNonPQCClassical, models.SeverityMedium, 4),
			},
		},
	}
	got := Merge(scans, "999999999999")
	s := got.Merged.Summary
	if s.TotalFindings != 4 {
		t.Fatalf("TotalFindings = %d, want 4 (duplicate must collapse)", s.TotalFindings)
	}
	if s.Critical != 1 || s.High != 1 || s.Medium != 1 || s.Informational != 1 {
		t.Errorf("severity counts C/H/M/I = %d/%d/%d/%d, want 1/1/1/1", s.Critical, s.High, s.Medium, s.Informational)
	}
}

// TestCoverageAndSentinels proves the merged envelope uses sentinels, the
// coverage list has one row per shard with correct counts + Errored flags, and
// the time bounds are min/max across shards.
func TestCoverageAndSentinels(t *testing.T) {
	t0 := time.Date(2026, 6, 3, 10, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 3, 11, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 6, 3, 13, 0, 0, 0, time.UTC)

	scans := []models.ScanResult{
		{
			Mode: "live", AccountID: "111111111111", Region: "us-east-1",
			StartedAt: t1, CompletedAt: t2,
			Assets:   []models.CryptoAsset{mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil)},
			Findings: []models.Finding{mkFinding("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", models.PostureNonPQCClassical, models.SeverityHigh, 5)},
			ServiceStats: []models.ServiceScanReport{
				{Service: "kms_spec", AssetCount: 1, DurationMS: 100, Errors: []string{"throttled"}},
			},
		},
		{
			Mode: "live", AccountID: "222222222222", Region: "eu-west-1",
			StartedAt: t0, CompletedAt: t3,
			Assets: []models.CryptoAsset{mkAsset("arn:aws:kms:eu-west-1:222222222222:key/b", "kms_spec", "222222222222", "eu-west-1", nil)},
			ServiceStats: []models.ServiceScanReport{
				{Service: "kms_spec", AssetCount: 1, DurationMS: 50},
			},
		},
	}

	got := Merge(scans, "999999999999")

	if got.Merged.AccountID != SentinelAccount {
		t.Errorf("Merged.AccountID = %q, want %q", got.Merged.AccountID, SentinelAccount)
	}
	if got.Merged.Region != SentinelRegion {
		t.Errorf("Merged.Region = %q, want %q", got.Merged.Region, SentinelRegion)
	}
	if got.Merged.Mode != MergedMode {
		t.Errorf("Merged.Mode = %q, want %q", got.Merged.Mode, MergedMode)
	}
	if !got.Merged.StartedAt.Equal(t0) {
		t.Errorf("Merged.StartedAt = %v, want min %v", got.Merged.StartedAt, t0)
	}
	if !got.Merged.CompletedAt.Equal(t3) {
		t.Errorf("Merged.CompletedAt = %v, want max %v", got.Merged.CompletedAt, t3)
	}

	// Per-asset provenance preserved (assets are self-describing).
	for _, a := range got.Merged.Assets {
		if a.AccountID == SentinelAccount || a.Region == SentinelRegion {
			t.Errorf("merged asset %s lost provenance: account=%q region=%q", a.BomRef, a.AccountID, a.Region)
		}
	}

	// Coverage: one row per input shard, input order preserved.
	if len(got.Coverage) != 2 {
		t.Fatalf("coverage rows = %d, want 2", len(got.Coverage))
	}
	c0 := got.Coverage[0]
	if c0.AccountID != "111111111111" || c0.Region != "us-east-1" {
		t.Errorf("coverage[0] identity = %s/%s", c0.AccountID, c0.Region)
	}
	if c0.Assets != 1 || c0.Findings != 1 {
		t.Errorf("coverage[0] counts assets=%d findings=%d, want 1/1", c0.Assets, c0.Findings)
	}
	if !c0.Errored {
		t.Errorf("coverage[0].Errored = false, want true (shard had service errors)")
	}
	c1 := got.Coverage[1]
	if c1.Errored {
		t.Errorf("coverage[1].Errored = true, want false (no errors)")
	}

	// Service stats union: AssetCount and DurationMS summed, errors concatenated.
	if len(got.Merged.ServiceStats) != 1 {
		t.Fatalf("merged service stats = %d, want 1", len(got.Merged.ServiceStats))
	}
	st := got.Merged.ServiceStats[0]
	if st.AssetCount != 2 || st.DurationMS != 150 {
		t.Errorf("union stats AssetCount=%d DurationMS=%d, want 2/150", st.AssetCount, st.DurationMS)
	}
	if len(st.Errors) != 1 || st.Errors[0] != "throttled" {
		t.Errorf("union stats Errors = %v, want [throttled]", st.Errors)
	}

	// Multi provenance envelope.
	if got.Multi.OrchestratorAccountID != "999999999999" {
		t.Errorf("Multi.OrchestratorAccountID = %q, want 999999999999", got.Multi.OrchestratorAccountID)
	}
	if got.Multi.TotalAccounts != 2 || got.Multi.TotalRegions != 2 {
		t.Errorf("Multi totals accounts=%d regions=%d, want 2/2", got.Multi.TotalAccounts, got.Multi.TotalRegions)
	}
	if len(got.Multi.Scans) != 2 {
		t.Errorf("Multi.Scans = %d, want 2 (verbatim shards)", len(got.Multi.Scans))
	}
}

// TestMergeEmptyAndSingle proves Merge(nil, ...) is zero-value-safe and a single
// shard round-trips counts unchanged.
func TestMergeEmptyAndSingle(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		got := Merge(nil, "999999999999")
		if got.Merged.AccountID != SentinelAccount || got.Merged.Region != SentinelRegion || got.Merged.Mode != MergedMode {
			t.Errorf("empty merge envelope = %s/%s/%s, want %s/%s/%s",
				got.Merged.AccountID, got.Merged.Region, got.Merged.Mode,
				SentinelAccount, SentinelRegion, MergedMode)
		}
		if len(got.Merged.Assets) != 0 || len(got.Merged.Findings) != 0 {
			t.Errorf("empty merge should have no assets/findings, got %d/%d", len(got.Merged.Assets), len(got.Merged.Findings))
		}
		if got.Merged.Summary != (models.ScanSummary{}) {
			t.Errorf("empty merge summary should be zero, got %+v", got.Merged.Summary)
		}
		if len(got.Coverage) != 0 {
			t.Errorf("empty merge coverage should be empty, got %d", len(got.Coverage))
		}
		if got.Multi.OrchestratorAccountID != "999999999999" {
			t.Errorf("empty merge Multi orchestrator = %q, want 999999999999", got.Multi.OrchestratorAccountID)
		}
		if len(got.Multi.Scans) != 0 {
			t.Errorf("empty merge Multi.Scans = %d, want 0", len(got.Multi.Scans))
		}
	})

	t.Run("single shard round-trips counts", func(t *testing.T) {
		single := models.ScanResult{
			Mode: "live", AccountID: "111111111111", Region: "us-east-1",
			ToolVersion: "1.2.3",
			Assets: []models.CryptoAsset{
				mkAsset("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", "111111111111", "us-east-1", nil),
				mkAsset("arn:aws:s3:::bucket", "s3_encryption", "111111111111", "us-east-1", nil),
			},
			Findings: []models.Finding{
				mkFinding("arn:aws:kms:us-east-1:111111111111:key/a", "kms_spec", models.PostureNonPQCClassical, models.SeverityCritical, 9),
			},
		}
		got := Merge([]models.ScanResult{single}, "111111111111")
		if len(got.Merged.Assets) != 2 {
			t.Errorf("single-shard assets = %d, want 2", len(got.Merged.Assets))
		}
		if len(got.Merged.Findings) != 1 {
			t.Errorf("single-shard findings = %d, want 1", len(got.Merged.Findings))
		}
		if got.Merged.Summary.TotalAssets != 2 || got.Merged.Summary.TotalFindings != 1 {
			t.Errorf("single-shard summary = %+v, want 2 assets / 1 finding", got.Merged.Summary)
		}
		if got.Merged.Summary.Critical != 1 {
			t.Errorf("single-shard Critical = %d, want 1", got.Merged.Summary.Critical)
		}
		if got.Merged.Summary.ServiceCount != 2 {
			t.Errorf("single-shard ServiceCount = %d, want 2", got.Merged.Summary.ServiceCount)
		}
		if got.Merged.ToolVersion != "1.2.3" {
			t.Errorf("single-shard ToolVersion = %q, want 1.2.3 (first non-empty)", got.Merged.ToolVersion)
		}
		if len(got.Coverage) != 1 {
			t.Errorf("single-shard coverage rows = %d, want 1", len(got.Coverage))
		}
	})
}
