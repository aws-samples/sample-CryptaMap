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
