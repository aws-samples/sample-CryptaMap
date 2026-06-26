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

// TestBuildFindings_QuantumResistantPostureNotMoscaAlarmed pins the H1 fix: a
// quantum-resistant non-at-rest posture (pqc-hybrid / pqc-ready) on a
// high-shelf-life service whose Mosca score is CRITICAL must stay
// INFORMATIONAL — the posture-blind Mosca/HNDL urgency must NOT raise it.
//
// This fails on the old worse-of(posture, Mosca) logic, which would yield
// CRITICAL because rds/dynamodb → Mosca 9.
//
// NOTE (B3): symmetric-only (quantum-resistant at rest, AES-256) is now
// INVENTORY-ONLY and is NOT emitted as a finding at all — that contract is
// asserted separately in TestBuildFindings_SymmetricOnlyIsInventoryNotFinding.
func TestBuildFindings_QuantumResistantPostureNotMoscaAlarmed(t *testing.T) {
	resistantPostures := []models.CryptoPosture{
		models.PosturePQCHybrid,
		models.PosturePQCReady,
	}
	// rds and dynamodb both default to X=10,Y=2,Z=3 → score 9 → CRITICAL.
	for _, service := range []string{"rds", "dynamodb"} {
		for _, p := range resistantPostures {
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
				t.Errorf("service=%s posture=%s: quantum-resistant asset must be INFORMATIONAL, got %s",
					service, p, f.Severity)
			}
		}
	}
}

// TestBuildFindings_SymmetricOnlyIsInventoryNotFinding pins the B3 at-rest
// INVENTORY-ONLY contract: a quantum-resistant-at-rest (symmetric AES-256,
// PostureSymmetricOnly) asset is recorded for inventory completeness but must
// produce ZERO findings — even on a high-shelf-life service whose Mosca score is
// CRITICAL. It is not a PQC-migration item, so it never enters the finding
// stream, never feeds a severity bucket, and never inflates the headline.
func TestBuildFindings_SymmetricOnlyIsInventoryNotFinding(t *testing.T) {
	// rds and dynamodb both default to X=10,Y=2,Z=3 → score 9 → CRITICAL, so a
	// regression that let symmetric-only through would be loudly visible.
	for _, service := range []string{"rds", "dynamodb"} {
		a := assetWithPosture(service, models.PostureSymmetricOnly)
		findings := BuildFindings([]models.CryptoAsset{a}, nil, nil)
		if len(findings) != 0 {
			t.Fatalf("service=%s symmetric-only: expected 0 findings (inventory-only), got %d", service, len(findings))
		}
	}

	// And reconcile the inventory count: a mix of one symmetric-only asset and
	// one genuinely vulnerable asset must yield exactly 1 finding (the vulnerable
	// one) and InventoryOnly=1 (the symmetric-only one), so the at-rest asset is
	// visibly reconciled, never silently dropped.
	e := &Engine{}
	assets := []models.CryptoAsset{
		assetWithPosture("rds", models.PostureSymmetricOnly),
		assetWithPosture("rds", models.PostureNoEncryption),
	}
	findings := BuildFindings(assets, nil, nil)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (the vulnerable asset), got %d", len(findings))
	}
	sum := e.buildSummary(assets, findings, 1)
	if sum.InventoryOnly != 1 {
		t.Errorf("expected InventoryOnly=1 (the symmetric-only asset), got %d", sum.InventoryOnly)
	}
	if sum.TotalFindings != 1 {
		t.Errorf("expected TotalFindings=1, got %d", sum.TotalFindings)
	}
	if sum.TotalAssets != 2 {
		t.Errorf("expected TotalAssets=2 (both still inventoried), got %d", sum.TotalAssets)
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
