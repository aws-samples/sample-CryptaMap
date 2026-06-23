package scanner

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// asset is a tiny helper to build a CryptoAsset carrying just the fields
// BuildFindings reads: Service and Properties["posture"].
func assetWithPosture(service string, posture models.CryptoPosture) models.CryptoAsset {
	return models.CryptoAsset{
		Service:    service,
		ResourceID: "r-" + service,
		Properties: map[string]string{"posture": string(posture)},
	}
}

// TestBuildFindings_QuantumSafePostureNotMoscaAlarmed pins the H1 fix: a
// quantum-SAFE posture (symmetric-only / pqc-hybrid / pqc-ready) on a
// high-shelf-life service whose Mosca score is CRITICAL must stay
// INFORMATIONAL — the posture-blind Mosca/HNDL urgency must NOT raise it.
//
// This fails on the old worse-of(posture, Mosca) logic, which would yield
// CRITICAL for an AES-256 (symmetric-only) RDS table because rds → Mosca 9.
func TestBuildFindings_QuantumSafePostureNotMoscaAlarmed(t *testing.T) {
	safePostures := []models.CryptoPosture{
		models.PostureSymmetricOnly,
		models.PosturePQCHybrid,
		models.PosturePQCReady,
	}
	// rds and dynamodb both default to X=10,Y=2,Z=3 → score 9 → CRITICAL.
	for _, service := range []string{"rds", "dynamodb"} {
		for _, p := range safePostures {
			a := assetWithPosture(service, p)
			findings := BuildFindings([]models.CryptoAsset{a}, nil, nil)
			if len(findings) != 1 {
				t.Fatalf("service=%s posture=%s: expected 1 finding, got %d", service, p, len(findings))
			}
			f := findings[0]
			// Sanity: the service really does produce a CRITICAL Mosca score,
			// otherwise this test would not be exercising the bump-suppression.
			if f.Mosca.Score < 7 {
				t.Fatalf("service=%s: expected CRITICAL Mosca score (>=7), got %d", service, f.Mosca.Score)
			}
			if f.Severity != models.SeverityInformational {
				t.Errorf("service=%s posture=%s: quantum-safe asset must be INFORMATIONAL, got %s",
					service, p, f.Severity)
			}
		}
	}
}

// TestBuildFindings_VulnerablePostureKeepsWorseOf confirms the fix does NOT
// regress the genuinely at-risk postures: on the same high-shelf-life service,
// no-encryption and non-pqc-classical assets still get their worse-of
// (posture, Mosca) severity — the Mosca CRITICAL urgency rightly applies.
func TestBuildFindings_VulnerablePostureKeepsWorseOf(t *testing.T) {
	cases := []struct {
		posture models.CryptoPosture
		want    models.Severity
	}{
		// posture=CRITICAL, Mosca=CRITICAL → CRITICAL.
		{models.PostureNoEncryption, models.SeverityCritical},
		// posture=MEDIUM, Mosca=CRITICAL → CRITICAL (Mosca/HNDL bump applies).
		{models.PostureNonPQCClassical, models.SeverityCritical},
		// posture=HIGH, Mosca=CRITICAL → CRITICAL.
		{models.PostureLegacyTLS, models.SeverityCritical},
	}
	for _, tc := range cases {
		a := assetWithPosture("rds", tc.posture)
		findings := BuildFindings([]models.CryptoAsset{a}, nil, nil)
		if len(findings) != 1 {
			t.Fatalf("posture=%s: expected 1 finding, got %d", tc.posture, len(findings))
		}
		if got := findings[0].Severity; got != tc.want {
			t.Errorf("posture=%s on rds: want %s (worse-of with Mosca CRITICAL), got %s",
				tc.posture, tc.want, got)
		}
	}
}
