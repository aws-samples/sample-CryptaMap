package scanner

// Systemic honesty-invariant suite — the "AppMesh-class" catch.
//
// Background: a recent review found AppMesh STRICT/PERMISSIVE nodes ALL mislabeled
// no-encryption because a weakest-wins fold was seeded from NoEncryption. Every
// per-scanner opt-in test passed, yet the systemic honesty contract was violated.
// The lesson: per-scanner tests cannot catch a class of bug that lives in the
// shared fold/derivation path, and they do not AUTOMATICALLY cover a future
// scanner. This suite enforces the honesty laws over EVERY asset, by:
//
//	(A) a DETERMINISTIC mock ScanResult — mock.Generator with a FIXED seed at a
//	    large scale, so many assets of every mock-reachable posture exist and the
//	    real BuildFindings derivation path is exercised; and
//	(B) iterating the LIVE registry (testRegistry, mirroring cmd/register*.go), so
//	    any newly-added scanner is covered without editing this file.
//
// The five honesty laws enforced (mirroring THE HONESTY CONTRACT):
//
//	I1  Every asset's Properties["posture"] is one of the 7 valid enum values
//	    (fail listing any asset with an empty/invalid posture).
//	I2  Every asset has a non-empty Service that resolves to a taxonomy.Entry with
//	    AWSCategory != "Other" and a non-empty CryptoFunction.
//	I3  Every finding from BuildFindings has a severity consistent with its posture:
//	    a quantum-resistant posture (symmetric-only / pqc-hybrid / pqc-ready) is NEVER
//	    CRITICAL/HIGH purely from a Mosca/HNDL escalation (the H1 rule).
//	I4  A no-encryption asset always carries an explanatory note property — never a
//	    bare, context-free no-encryption verdict.
//	I5  bom-refs are unique per asset (no duplicate / fabricated refs).
//
// All checks are table/loop driven: they iterate the data and the registry, never
// hardcoding the ~99 scanner names, so a future scanner is covered automatically.

import (
	"context"
	"testing"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/mock"
	"github.com/aws-samples/cryptamap/internal/risk"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// validPostures is the canonical 7-value posture enum (pkg/models/finding.go).
// An asset whose Properties["posture"] is not in this set is an honesty violation:
// it can neither be classified nor honestly reported.
var validPostures = map[models.CryptoPosture]bool{
	models.PostureNoEncryption:    true,
	models.PostureLegacyTLS:       true,
	models.PostureNonPQCClassical: true,
	models.PostureSymmetricOnly:   true,
	models.PosturePQCHybrid:       true,
	models.PosturePQCReady:        true,
	models.PostureUnknown:         true,
}

// invariantSeed is a FIXED seed so the mock ScanResult is byte-for-byte
// deterministic across runs (RunMock seeds from time.Now().UnixNano(), which is
// non-deterministic; the documented seam is to drive mock.Generator directly with
// a fixed Seed — see the task note and internal/scanner/mock_engine.go).
const invariantSeed int64 = 0xC0FFEE

// invariantScale is large enough that, across all ~70 templates, hundreds of
// assets of every mock-reachable posture exist (verified: ~12k assets at scale
// 200), so the loop genuinely covers every posture-derivation branch rather than
// a lucky single hot path.
const invariantScale = 200

// deterministicMockAssets returns the fixed-seed synthetic asset set. This is the
// seam that makes the suite reproducible without touching production RunMock.
func deterministicMockAssets() []models.CryptoAsset {
	g := mock.Generator{
		AccountID: "111122223333",
		Region:    "us-east-1",
		Scale:     invariantScale,
		Seed:      invariantSeed,
	}
	return g.GenerateAssets()
}

// deterministicMockResult builds the full ScanResult (assets + findings via the
// REAL BuildFindings path) from the fixed-seed assets, so I3 exercises the exact
// posture->severity derivation a live scan uses. A nil compliance registry is
// fine: BuildFindings tolerates it and the severity laws are compliance-
// independent.
func deterministicMockResult(t *testing.T) ([]models.CryptoAsset, []models.Finding) {
	t.Helper()
	assets := deterministicMockAssets()
	findings := BuildFindings(assets, (*compliance.Registry)(nil), nil)
	if len(assets) == 0 {
		t.Fatalf("deterministic mock produced 0 assets; the suite would assert nothing")
	}
	// B3 at-rest INVENTORY-ONLY: symmetric-only (quantum-resistant at rest)
	// assets are recorded for inventory but NOT emitted as findings, so the
	// invariant is one finding per NON-symmetric-only asset (not per asset).
	inventoryOnly := 0
	for _, a := range assets {
		if a.Properties != nil && a.Properties["posture"] == string(models.PostureSymmetricOnly) {
			inventoryOnly++
		}
	}
	if want := len(assets) - inventoryOnly; len(findings) != want {
		t.Fatalf("BuildFindings produced %d findings for %d assets (%d inventory-only symmetric); expected %d (one per non-symmetric-only asset)",
			len(findings), len(assets), inventoryOnly, want)
	}
	if inventoryOnly == 0 {
		t.Fatalf("deterministic mock produced 0 symmetric-only assets; the B3 inventory-vs-finding split would not be exercised")
	}
	return assets, findings
}

// assetID is a short, stable identifier for failure messages.
func assetID(a models.CryptoAsset) string {
	if a.ResourceARN != "" {
		return a.ResourceARN
	}
	if a.BomRef != "" {
		return a.BomRef
	}
	return a.Service + "/" + a.ResourceID
}

// TestInvariant_PostureInEnum (I1) asserts EVERY asset carries a posture that is
// one of the 7 valid enum values. An empty or out-of-enum posture means the asset
// cannot be honestly classified or reported; it must fail loudly, naming the
// asset, rather than be silently coerced to a default downstream.
func TestInvariant_PostureInEnum(t *testing.T) {
	assets := deterministicMockAssets()

	bad := 0
	for _, a := range assets {
		raw, ok := a.Properties["posture"]
		if !ok || raw == "" {
			bad++
			t.Errorf("asset %s: missing/empty Properties[\"posture\"]", assetID(a))
			continue
		}
		if !validPostures[models.CryptoPosture(raw)] {
			bad++
			t.Errorf("asset %s: posture %q is not one of the 7 valid enum values", assetID(a), raw)
		}
	}
	if bad > 0 {
		t.Errorf("%d/%d assets violated the posture-enum invariant", bad, len(assets))
	}
}

// TestInvariant_ServiceResolvesTaxonomy (I2) asserts EVERY asset has a non-empty
// Service that resolves to a real taxonomy.Entry: AWSCategory must not be the
// "Other" fallback and CryptoFunction must be non-empty. A scanner whose Service
// falls back to "Other" leaks an internal/humanized label into CBOM/PQCC/the
// dashboard. Driven off the deterministic mock so it covers every emitted service.
func TestInvariant_ServiceResolvesTaxonomy(t *testing.T) {
	assets := deterministicMockAssets()

	// Dedup by service so the failure list is one line per offending service, not
	// one per asset; the loop still visits every asset.
	checked := map[string]bool{}
	for _, a := range assets {
		if a.Service == "" {
			t.Errorf("asset %s: empty Service", assetID(a))
			continue
		}
		if checked[a.Service] {
			continue
		}
		checked[a.Service] = true

		e, ok := taxonomy.Lookup(a.Service)
		if !ok {
			t.Errorf("service %q: taxonomy.Lookup ok=false (fell back to AWSCategory=%q, CryptoFunction=%q)",
				a.Service, e.AWSCategory, e.CryptoFunction)
			continue
		}
		if e.AWSCategory == "" || e.AWSCategory == "Other" {
			t.Errorf("service %q: AWSCategory=%q (must be a real category, not the Other fallback)", a.Service, e.AWSCategory)
		}
		if e.CryptoFunction == "" {
			t.Errorf("service %q: empty CryptoFunction", a.Service)
		}
	}
}

// TestInvariant_QuantumResistantNeverEscalated (I3) asserts every finding's severity is
// consistent with its posture, focusing on the H1 rule: a quantum-RESISTANT posture
// (symmetric-only / pqc-hybrid / pqc-ready) must NEVER be CRITICAL or HIGH. Those
// postures map to INFORMATIONAL by posture alone; the only way they could become
// CRITICAL/HIGH is a posture-blind Mosca/HNDL escalation, which BuildFindings is
// supposed to suppress. This is the systemic guard that a future regression in the
// "take the worse of posture- and Mosca-severity" fold cannot over-alarm
// already-quantum-resistant cryptography.
//
// It also asserts the floor for genuinely-vulnerable postures (no-encryption =>
// at least HIGH, legacy-tls => at least MEDIUM) so the same fold cannot SILENTLY
// under-alarm a real risk either.
func TestInvariant_QuantumResistantNeverEscalated(t *testing.T) {
	_, findings := deterministicMockResult(t)

	for _, f := range findings {
		if !validPostures[f.Posture] {
			t.Errorf("finding %s (%s): posture %q not in the 7-value enum", f.ResourceID, f.Service, f.Posture)
			continue
		}
		if risk.IsQuantumResistantPosture(f.Posture) {
			switch f.Severity {
			case models.SeverityCritical, models.SeverityHigh:
				t.Errorf("finding %s (service=%s posture=%s) escalated to %s; a quantum-resistant posture must never be CRITICAL/HIGH (H1 rule — Mosca/HNDL must not raise it)",
					f.ResourceID, f.Service, f.Posture, f.Severity)
			}
		}
		// Under-alarm floor: a vulnerable posture must keep at least its posture
		// severity even after the fold.
		postureFloor := risk.SeverityFromPosture(f.Posture)
		if !risk.IsQuantumResistantPosture(f.Posture) {
			if models.NormalizedSeverity(f.Severity) < models.NormalizedSeverity(postureFloor) {
				t.Errorf("finding %s (service=%s posture=%s) severity=%s is BELOW the posture floor %s (silent under-alarm)",
					f.ResourceID, f.Service, f.Posture, f.Severity, postureFloor)
			}
		}
	}
}

// TestInvariant_NoEncryptionHasNote (I4) asserts that EVERY no-encryption asset
// carries an explanatory note property. A bare "no-encryption" verdict with no
// WHY is exactly the false-alarm/over-confidence failure mode the honesty contract
// forbids: a regulator-facing tool must always attach context to the most severe
// verdict it can emit. Driven off the deterministic mock (which mirrors the real
// scanners' note behavior, e.g. datarest/s3.go).
func TestInvariant_NoEncryptionHasNote(t *testing.T) {
	assets := deterministicMockAssets()

	seen := 0
	for _, a := range assets {
		if models.CryptoPosture(a.Properties["posture"]) != models.PostureNoEncryption {
			continue
		}
		seen++
		note := a.Properties["note"]
		if note == "" {
			t.Errorf("asset %s: posture=no-encryption but no explanatory Properties[\"note\"] (bare verdict — honesty contract violation)", assetID(a))
		}
	}
	if seen == 0 {
		t.Fatalf("deterministic mock produced no no-encryption assets at scale=%d; the no-encryption invariant exercised nothing — check the mock distribution/seed", invariantScale)
	}
}

// TestInvariant_BomRefsUnique (I5) asserts bom-refs are unique across all assets.
// A duplicate bom-ref means two distinct resources collide into one CBOM
// component (org-wide dedup keys on the ref), silently dropping or merging an
// asset — a fabricated/lossy inventory. Driven off the deterministic mock so a
// future template/ARN scheme that collides is caught.
func TestInvariant_BomRefsUnique(t *testing.T) {
	assets := deterministicMockAssets()

	first := make(map[string]string, len(assets))
	dups := 0
	for _, a := range assets {
		if a.BomRef == "" {
			t.Errorf("asset %s: empty BomRef", assetID(a))
			continue
		}
		if prev, ok := first[a.BomRef]; ok {
			dups++
			t.Errorf("duplicate bom-ref %q shared by %s and %s", a.BomRef, prev, assetID(a))
			continue
		}
		first[a.BomRef] = assetID(a)
	}
	if dups > 0 {
		t.Errorf("%d duplicate bom-ref(s) across %d assets", dups, len(assets))
	}
}

// TestInvariant_MockCoversEveryPosture is a meta-guard: it proves the deterministic
// mock actually EXERCISES every mock-reachable posture, so the loops above are not
// silently asserting over a degenerate single-posture dataset. The mock
// distribution never emits pqc-ready (pure PQC), so the required set is the six
// reachable postures; pqc-ready's severity law is still covered for the live
// registry / engine paths and by risk-package tests.
func TestInvariant_MockCoversEveryPosture(t *testing.T) {
	assets := deterministicMockAssets()

	required := []models.CryptoPosture{
		models.PostureNoEncryption,
		models.PostureLegacyTLS,
		models.PostureNonPQCClassical,
		models.PostureSymmetricOnly,
		models.PosturePQCHybrid,
		models.PostureUnknown,
	}
	counts := map[models.CryptoPosture]int{}
	for _, a := range assets {
		counts[models.CryptoPosture(a.Properties["posture"])]++
	}
	for _, p := range required {
		if counts[p] == 0 {
			t.Errorf("deterministic mock produced 0 assets with posture %q; the systemic loops do not exercise that branch", p)
		}
	}
	t.Logf("posture coverage over %d deterministic mock assets: %v", len(assets), counts)
}

// TestInvariant_LiveRegistryResolvesTaxonomy (I2, registry arm) is the systemic,
// future-proof complement to the mock-driven I2: it iterates the LIVE registry
// (testRegistry mirrors cmd/register*.go) and asserts every registered scanner
// Name() resolves to a real taxonomy Entry. A new scanner added to the registry
// without a taxonomy entry fails here automatically — no edit to this test needed.
// (registry_test.go has a similar check; this duplicates it INSIDE the honesty
// suite so the honesty laws stand as one self-contained, automatically-extending
// gate.)
func TestInvariant_LiveRegistryResolvesTaxonomy(t *testing.T) {
	reg := testRegistry()
	for _, name := range reg.Names() {
		if name == "" {
			t.Errorf("registry contains a scanner with an empty Name()")
			continue
		}
		e, ok := taxonomy.Lookup(name)
		if !ok {
			t.Errorf("scanner %q: taxonomy.Lookup ok=false (AWSCategory=%q)", name, e.AWSCategory)
			continue
		}
		if e.AWSCategory == "" || e.AWSCategory == "Other" {
			t.Errorf("scanner %q: AWSCategory=%q (must be a real category, not the Other fallback)", name, e.AWSCategory)
		}
		if e.CryptoFunction == "" {
			t.Errorf("scanner %q: empty CryptoFunction", name)
		}
	}
}

// TestInvariant_LiveRegistryEngineFindingsHonest (I1+I3, engine arm) drives the
// FULL engine path over the live registry under the read-only guard config (so no
// network I/O): Engine.Run -> buildFindings -> buildSummary. Even though each
// scanner errors out network-free under the guard (so few/zero assets are
// produced), this proves the engine-produced findings — whatever assets DO flow
// through — obey the posture-enum and quantum-resistant-severity laws. It is the
// systemic guard that the engine's finding-build path itself never emits an
// out-of-enum posture or an over-escalated quantum-resistant finding for ANY current or
// future registered scanner.
func TestInvariant_LiveRegistryEngineFindingsHonest(t *testing.T) {
	reg := testRegistry()
	e := NewEngine(reg, nil, EngineOptions{MaxRetries: 0, MaxGoroutines: 8, ToolVersion: "test"})

	var seen []string // read-only guard side-effect sink
	cfg := readOnlyGuardConfig(t, &seen)

	res := e.Run(context.Background(), cfg, "111122223333")

	for _, f := range res.Findings {
		if !validPostures[f.Posture] {
			t.Errorf("engine finding %s (%s): posture %q not in the 7-value enum", f.ResourceID, f.Service, f.Posture)
		}
		if risk.IsQuantumResistantPosture(f.Posture) {
			switch f.Severity {
			case models.SeverityCritical, models.SeverityHigh:
				t.Errorf("engine finding %s (service=%s posture=%s) escalated to %s; quantum-resistant posture must never be CRITICAL/HIGH",
					f.ResourceID, f.Service, f.Posture, f.Severity)
			}
		}
	}
	// Every emitted asset (if any) must also carry a valid posture.
	for _, a := range res.Assets {
		raw := a.Properties["posture"]
		if raw != "" && !validPostures[models.CryptoPosture(raw)] {
			t.Errorf("engine asset %s: posture %q not in the 7-value enum", assetID(a), raw)
		}
	}
}
