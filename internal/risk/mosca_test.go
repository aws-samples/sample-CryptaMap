package risk

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func TestCalculate(t *testing.T) {
	cases := []struct {
		name string
		in   MoscaParams
		want int
	}{
		{"financial transaction (RDS-like)", MoscaParams{X: 10, Y: 2, Z: 3}, 9},
		{"customer PII (S3-like)", MoscaParams{X: 7, Y: 2, Z: 3}, 6},
		{"ephemeral session", MoscaParams{X: 1, Y: 1, Z: 3}, -1},
		{"certificate", MoscaParams{X: 5, Y: 1, Z: 3}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Calculate(tc.in)
			if got.Score != tc.want {
				t.Fatalf("got %d want %d", got.Score, tc.want)
			}
		})
	}
}

func TestSeverityFromMosca(t *testing.T) {
	cases := []struct {
		score int
		want  models.Severity
	}{
		{9, models.SeverityCritical},
		{7, models.SeverityCritical},
		{6, models.SeverityHigh},
		{4, models.SeverityHigh},
		{3, models.SeverityMedium},
		{1, models.SeverityMedium},
		{0, models.SeverityInformational},
		{-1, models.SeverityInformational},
	}
	for _, tc := range cases {
		if got := SeverityFromMosca(tc.score); got != tc.want {
			t.Errorf("score %d: got %s want %s", tc.score, got, tc.want)
		}
	}
}

func TestSeverityFromPosture(t *testing.T) {
	if SeverityFromPosture(models.PostureNoEncryption) != models.SeverityCritical {
		t.Error("no-encryption must be CRITICAL")
	}
	if SeverityFromPosture(models.PostureLegacyTLS) != models.SeverityHigh {
		t.Error("legacy-tls must be HIGH")
	}
	if SeverityFromPosture(models.PosturePQCHybrid) != models.SeverityInformational {
		t.Error("pqc-hybrid must be INFORMATIONAL")
	}
}

// TestDefaultParamsCalibratedRows closes the gap: the calibration table must
// actually be consulted — TestCalculate alone only verifies integer addition,
// so deleting the whole IndianBFSIDefaults map previously broke zero tests.
func TestDefaultParamsCalibratedRows(t *testing.T) {
	cases := map[string]MoscaParams{
		"rds":         {X: 10, Y: 2, Z: 3},
		"s3":          {X: 7, Y: 2, Z: 3},
		"elasticache": {X: 1, Y: 1, Z: 3},
		"acm":         {X: 5, Y: 1, Z: 3},
		"alb":         {X: 7, Y: 1, Z: 3},
		"cloudhsm":    {X: 7, Y: 2, Z: 3},
	}
	for svc, want := range cases {
		if got := DefaultParams(svc); got != want {
			t.Errorf("DefaultParams(%q) = %+v, want %+v", svc, got, want)
		}
	}
	// Unknown service falls back to the 5/1/3 baseline (score 3, MEDIUM floor).
	if got := DefaultParams("no-such-service"); got != (MoscaParams{X: 5, Y: 1, Z: 3}) {
		t.Errorf("DefaultParams fallback = %+v, want {5 1 3}", got)
	}
}

// TestCalculateForServiceOverridePrecedence pins the override path: an explicit
// override must beat the defaults table, and a nil map must be safe.
func TestCalculateForServiceOverridePrecedence(t *testing.T) {
	over := map[string]MoscaParams{"rds": {X: 15, Y: 3, Z: 3}}
	if got := CalculateForService("rds", over); got.Score != 15 {
		t.Errorf("override rds score = %d, want 15 (X+Y-Z)", got.Score)
	}
	if got := CalculateForService("rds", nil); got.Score != 9 {
		t.Errorf("default rds score = %d, want 9", got.Score)
	}
}
