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

// TestBuildFindings_DeterministicID pins the regulator-diff contract: the SAME
// asset scanned twice must yield the SAME Finding.ID, so finding artifacts diff
// cleanly across runs instead of churning a fresh uuid every scan. Two distinct
// assets must still get distinct ids, and a posture change on the same asset is
// a materially different finding record (distinct id). This test FAILS if the
// id is reverted to uuid.NewString() (which mints a fresh value every call).
func TestBuildFindings_DeterministicID(t *testing.T) {
	a := models.CryptoAsset{
		AccountID:  "111122223333",
		Region:     "us-east-1",
		Service:    "rds",
		ResourceID: "db-prod-1",
		Properties: map[string]string{"posture": string(models.PostureNoEncryption)},
	}

	run1 := BuildFindings([]models.CryptoAsset{a}, nil, nil)
	run2 := BuildFindings([]models.CryptoAsset{a}, nil, nil)
	if len(run1) != 1 || len(run2) != 1 {
		t.Fatalf("expected 1 finding per run, got %d and %d", len(run1), len(run2))
	}
	if run1[0].ID == "" {
		t.Fatal("Finding.ID must not be empty")
	}
	// The core mutation gate: identical input asset -> identical id across runs.
	if run1[0].ID != run2[0].ID {
		t.Errorf("same asset scanned twice must yield the SAME Finding.ID (deterministic), got %q vs %q",
			run1[0].ID, run2[0].ID)
	}

	// A different asset must not collide onto the same id.
	b := a
	b.ResourceID = "db-prod-2"
	other := BuildFindings([]models.CryptoAsset{b}, nil, nil)
	if other[0].ID == run1[0].ID {
		t.Errorf("distinct assets must have distinct Finding.IDs, both got %q", run1[0].ID)
	}

	// A posture change on the same asset is a materially different finding record.
	c := a
	c.Properties = map[string]string{"posture": string(models.PostureLegacyTLS)}
	postureChanged := BuildFindings([]models.CryptoAsset{c}, nil, nil)
	if postureChanged[0].ID == run1[0].ID {
		t.Errorf("a posture change must change the Finding.ID, both got %q", run1[0].ID)
	}

	// Timestamps must be a single run-scoped value (all findings in a run share
	// it) and must be set (load-bearing for the ASFF CreatedAt/UpdatedAt fields).
	if run1[0].CreatedAt.IsZero() || run1[0].UpdatedAt.IsZero() {
		t.Error("CreatedAt/UpdatedAt must be set (required by the ASFF exporter)")
	}
	if !run1[0].CreatedAt.Equal(run1[0].UpdatedAt) {
		t.Error("CreatedAt and UpdatedAt should be the single run timestamp")
	}
}

// TestBuildFindings_BomRefDrivenID confirms the id keys on the asset's BomRef
// when present (the preferred, ARN-derived discriminator the ASFF exporter also
// uses), so the scanner and Security Hub share one stable identity source.
func TestBuildFindings_BomRefDrivenID(t *testing.T) {
	a := models.CryptoAsset{
		Service:    "s3",
		ResourceID: "bucket-x",
		BomRef:     models.BomRefForARN("arn:aws:s3:::bucket-x"),
		Properties: map[string]string{"posture": string(models.PostureNoEncryption)},
	}
	f := BuildFindings([]models.CryptoAsset{a}, nil, nil)[0]
	want := "finding:" + a.BomRef + ":" + string(models.PostureNoEncryption)
	if f.ID != want {
		t.Errorf("BomRef-driven id: want %q, got %q", want, f.ID)
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

// TestBuildFindings_UnknownPostureNotMoscaEscalated is the verdict-honesty
// contract for the UNREADABLE posture (the inverse of the fabricated-all-clear
// class): an asset whose encryption attributes could NOT be read (posture=unknown,
// e.g. an API-error path) must NOT be escalated to a definite CRITICAL by the
// posture-blind per-service Mosca constant. The scanner has proven no vulnerable
// asset exists, so PostureUnknown stays at its honest "needs investigation" floor
// (MEDIUM), while the Mosca score is still recorded on the finding for
// transparency. Without the fix, rds/dynamodb (Mosca score 9 -> CRITICAL) would
// stamp an unreadable posture as a CRITICAL verdict sourced purely from a hardcoded
// table, not from anything the scanner observed.
func TestBuildFindings_UnknownPostureNotMoscaEscalated(t *testing.T) {
	// rds and dynamodb both default to X=10,Y=2,Z=3 -> score 9 -> CRITICAL, so a
	// regression that let the Mosca bump through would be loudly visible.
	for _, service := range []string{"rds", "dynamodb"} {
		a := assetWithPosture(service, models.PostureUnknown)
		findings := BuildFindings([]models.CryptoAsset{a}, nil, nil)
		if len(findings) != 1 {
			t.Fatalf("service=%s unknown: expected 1 finding, got %d", service, len(findings))
		}
		f := findings[0]
		// Sanity: the service really does produce a CRITICAL Mosca score, so this
		// test is genuinely exercising the escalation-suppression (not a service
		// whose score is MEDIUM anyway).
		if f.Mosca.Score < 7 {
			t.Fatalf("service=%s: expected CRITICAL Mosca score (>=7) to exercise suppression, got %d", service, f.Mosca.Score)
		}
		// Honest floor: MEDIUM (needs investigation) — never escalated to CRITICAL
		// by the data-blind Mosca constant, and never silently cleaned below MEDIUM.
		if f.Severity != models.SeverityMedium {
			t.Errorf("service=%s unknown posture: want MEDIUM (honest 'needs investigation' floor, not Mosca-escalated), got %s",
				service, f.Severity)
		}
		// The Mosca score MUST still be recorded on the finding for transparency,
		// even though it did not drive the severity.
		if f.Mosca.Score == 0 {
			t.Errorf("service=%s: Mosca score should still be recorded on the finding for transparency", service)
		}
	}
}

// TestBuildFindings_NonCanonicalPostureNotMoscaEscalated closes a residual that
// review of the item-1 fix found: a posture value that is neither
// quantum-resistant nor exactly PostureUnknown — an empty string, or a crafted/
// non-canonical value that an ingested CBOM can restore into
// Properties["posture"] (cbom_reader.go round-trips it verbatim) — must ALSO not
// be Mosca-escalated to CRITICAL. The severity gate is now an allowlist
// (risk.IsMoscaEscalatable) of exactly the three observed-vulnerable postures, so
// any unrecognized value fails closed at its posture floor rather than borrowing a
// hardcoded per-service CRITICAL it never earned.
func TestBuildFindings_NonCanonicalPostureNotMoscaEscalated(t *testing.T) {
	// rds Mosca score is 9 (CRITICAL) — the escalation this must suppress.
	for _, p := range []models.CryptoPosture{"", "garbage", "not-a-real-posture"} {
		a := assetWithPosture("rds", p)
		findings := BuildFindings([]models.CryptoAsset{a}, nil, nil)
		if len(findings) != 1 {
			t.Fatalf("posture=%q: expected 1 finding, got %d", p, len(findings))
		}
		if got := findings[0].Severity; got == models.SeverityCritical {
			t.Errorf("posture=%q: a non-vulnerable/non-canonical posture must NOT be Mosca-escalated to CRITICAL (got %s); only observed-vulnerable postures escalate", p, got)
		}
	}
}
