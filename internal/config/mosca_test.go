package config

import (
	"testing"

	"github.com/aws-samples/cryptamap/internal/risk"
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestMoscaOverrideParams_Mapping pins the YAML->risk field mapping and the
// zero-value rules of the converter.
func TestMoscaOverrideParams_Mapping(t *testing.T) {
	cfg := Default()

	// No overrides -> nil (engine uses built-in defaults).
	if got := cfg.MoscaOverrideParams(); got != nil {
		t.Fatalf("expected nil for empty overrides, got %v", got)
	}

	cfg.Risk.Mosca.Overrides = map[string]MoscaDefaults{
		// Full override: all three fields map X/Y/Z.
		"rds": {DataShelfLifeYears: 25, MigrationTimeYears: 4, ThreatTimelineYears: 5},
		// Partial override: unset fields fall back to the service's built-in
		// defaults (s3 default is X=7,Y=2,Z=3), not zero.
		"s3": {DataShelfLifeYears: 1},
		// Fully-zero override is meaningless and must be skipped entirely.
		"kms": {},
	}

	got := cfg.MoscaOverrideParams()
	if want := (risk.MoscaParams{X: 25, Y: 4, Z: 5}); got["rds"] != want {
		t.Errorf("rds: got %+v, want %+v", got["rds"], want)
	}
	if want := (risk.MoscaParams{X: 1, Y: 2, Z: 3}); got["s3"] != want {
		t.Errorf("s3 partial: got %+v, want %+v (unset fields keep service defaults)", got["s3"], want)
	}
	if _, ok := got["kms"]; ok {
		t.Errorf("kms: fully-zero override must be skipped, got %+v", got["kms"])
	}

	// Only fully-zero entries -> nil, same as no overrides at all.
	cfg.Risk.Mosca.Overrides = map[string]MoscaDefaults{"rds": {}}
	if got := cfg.MoscaOverrideParams(); got != nil {
		t.Fatalf("expected nil when every override is fully zero, got %v", got)
	}
}

// TestMoscaOverride_ChangesBuildFindingsSeverity is the end-to-end wiring test:
// an operator override of data_shelf_life_years for a service must change that
// service's Mosca score AND finding severity via scanner.BuildFindings,
// relative to the built-in defaults.
func TestMoscaOverride_ChangesBuildFindingsSeverity(t *testing.T) {
	asset := models.CryptoAsset{
		Service:    "rds",
		ResourceID: "db-1",
		Region:     "ap-south-1",
		Properties: map[string]string{"posture": string(models.PostureNonPQCClassical)},
	}

	// Baseline: rds defaults are X=10,Y=2,Z=3 -> Mosca 9 -> CRITICAL.
	base := scanner.BuildFindings([]models.CryptoAsset{asset}, nil, nil)
	if len(base) != 1 {
		t.Fatalf("expected 1 baseline finding, got %d", len(base))
	}
	if base[0].Mosca.Score != 9 || base[0].Severity != models.SeverityCritical {
		t.Fatalf("baseline: got score=%d severity=%s, want score=9 severity=%s",
			base[0].Mosca.Score, base[0].Severity, models.SeverityCritical)
	}

	// Operator override: data shelf-life 1y -> Mosca 1+2-3=0 -> Mosca severity
	// INFORMATIONAL, so the finding drops to the posture severity (MEDIUM).
	cfg := Default()
	cfg.Risk.Mosca.Overrides = map[string]MoscaDefaults{
		"rds": {DataShelfLifeYears: 1},
	}
	overridden := scanner.BuildFindings([]models.CryptoAsset{asset}, nil, cfg.MoscaOverrideParams())
	if len(overridden) != 1 {
		t.Fatalf("expected 1 overridden finding, got %d", len(overridden))
	}
	if overridden[0].Mosca.Score != 0 {
		t.Errorf("override: got Mosca score %d, want 0 (X=1,Y=2,Z=3)", overridden[0].Mosca.Score)
	}
	if overridden[0].Severity != models.SeverityMedium {
		t.Errorf("override: got severity %s, want %s (posture-derived, Mosca no longer escalates)",
			overridden[0].Severity, models.SeverityMedium)
	}
	if overridden[0].Severity == base[0].Severity {
		t.Errorf("override did not change severity: both %s", base[0].Severity)
	}
}
