package compliance

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func TestRegistryAllNine(t *testing.T) {
	r := NewRegistry(nil)
	asset := models.CryptoAsset{
		Service:  "alb",
		Category: models.CategoryDataInTransit,
		CryptoProps: models.CryptoProperties{
			AssetType: models.AssetTypeProtocol,
			AlgorithmProperties: &models.AlgorithmProperties{
				Primitive: models.PrimitiveKeyAgree,
			},
		},
	}
	maps := r.MapAll(asset, models.PostureNonPQCClassical)
	if len(maps) == 0 {
		t.Fatal("expected at least one mapping")
	}
	frameworks := map[string]bool{}
	for _, m := range maps {
		frameworks[m.Framework] = true
	}
	// All NINE frameworks — IRDAI was previously (silently) missing from this loop.
	for _, fw := range KnownFrameworkIDs() {
		if !frameworks[fw] {
			t.Errorf("framework %s not mapped for transit/non-pqc asset", fw)
		}
	}
}

func TestRegistryFiltersByEnabled(t *testing.T) {
	r := NewRegistry([]string{SEBI, IRDAI})
	asset := models.CryptoAsset{
		Service:  "s3",
		Category: models.CategoryDataAtRest,
	}
	maps := r.MapAll(asset, models.PostureNoEncryption)
	for _, m := range maps {
		if m.Framework != SEBI && m.Framework != IRDAI {
			t.Errorf("unexpected framework %s in filtered registry", m.Framework)
		}
	}
}

func TestSEBIFlagsNoEncryption(t *testing.T) {
	m := &SEBIMapper{}
	asset := models.CryptoAsset{
		Service:  "s3",
		Category: models.CategoryDataAtRest,
	}
	maps := m.Map(asset, models.PostureNoEncryption)
	hasEncryptCtrl := false
	for _, mp := range maps {
		if mp.ControlID == "CryptaMap→Data-Encryption" && mp.Status == "non-compliant" {
			hasEncryptCtrl = true
		}
	}
	if !hasEncryptCtrl {
		t.Error("SEBI should flag NoEncryption with CryptaMap→Data-Encryption non-compliant")
	}
}

func TestStatusFromPosture(t *testing.T) {
	if statusFromPosture(models.PostureNoEncryption) != "non-compliant" {
		t.Error("no-encryption should be non-compliant")
	}
	// B4: hybrid PQ KEX with a traditional certificate is NOT fully resistant; it
	// must be "partial" (hybrid KEX, traditional cert), never "compliant".
	if statusFromPosture(models.PosturePQCHybrid) != "partial" {
		t.Error("pqc-hybrid should be partial (hybrid KEX, traditional cert — not fully migrated)")
	}
	// pqc-ready (pure PQC) and symmetric-only (quantum-resistant at rest) are compliant.
	if statusFromPosture(models.PosturePQCReady) != "compliant" {
		t.Error("pqc-ready should be compliant")
	}
	if statusFromPosture(models.PostureSymmetricOnly) != "compliant" {
		t.Error("symmetric-only (quantum-resistant at rest) should be compliant")
	}
	if statusFromPosture(models.PostureNonPQCClassical) != "partial" {
		t.Error("non-pqc-classical should be partial")
	}
	// B4: an undetermined posture must NEVER be a clean/compliant verdict.
	if got := statusFromPosture(models.PostureUnknown); got == "compliant" {
		t.Errorf("unknown posture must never be compliant, got %q", got)
	}
}

// TestReadinessFromPosture pins the India-framework readiness vocabulary (no PQC
// mandate → no "compliant"/"non-compliant" overclaim).
func TestReadinessFromPosture(t *testing.T) {
	cases := map[models.CryptoPosture]string{
		models.PostureNoEncryption:    "quantum-vulnerable",
		models.PostureLegacyTLS:       "quantum-vulnerable",
		models.PostureNonPQCClassical: "partial",
		// B4: hybrid PQ KEX + traditional cert is "partial", not the fully-resistant
		// "quantum-safe" signal.
		models.PosturePQCHybrid:     "partial",
		models.PosturePQCReady:      "quantum-safe",
		models.PostureSymmetricOnly: "quantum-safe",
		models.PostureUnknown:       "informational",
	}
	for p, want := range cases {
		if got := readinessFromPosture(p); got != want {
			t.Errorf("readinessFromPosture(%s) = %q, want %q", p, got, want)
		}
		// Must NOT use the regulatory-compliance vocabulary for India frameworks.
		if got := readinessFromPosture(p); got == "compliant" || got == "non-compliant" {
			t.Errorf("readinessFromPosture(%s) used regulatory term %q (overclaim)", p, got)
		}
	}
}

// TestIndiaMappersConsistentReadiness pins the fix: SEBI, RBI, and IRDAI
// must report the SAME readiness for the identical posture on the same
// in-transit asset. A previous RBI-only override downgraded non-pqc-classical
// from "partial" to "quantum-vulnerable", silently flipping the Security Hub
// verdict from WARNING to FAILED for every classical TLS asset.
func TestIndiaMappersConsistentReadiness(t *testing.T) {
	// The asset carries AlgorithmProperties with a signature primitive because
	// IRDAI's readiness row (ControlID "CryptaMap→PQ-Vulnerable-Primitives") is
	// only emitted for assets whose primitive is signature/keyagree. Without it
	// (and with the old filter matching only "CryptaMap→PQC-Readiness", which
	// IRDAI never emits) IRDAI contributed ZERO rows and the loop silently
	// asserted nothing about it.
	asset := models.CryptoAsset{
		Service:  "alb",
		Category: models.CategoryDataInTransit,
		CryptoProps: models.CryptoProperties{
			AssetType: models.AssetTypeProtocol,
			AlgorithmProperties: &models.AlgorithmProperties{
				Primitive: models.PrimitiveSignature,
			},
		},
	}
	// Each India mapper's readiness-vocabulary ControlID (they differ by design:
	// SEBI/RBI use PQC-Readiness, IRDAI uses PQ-Vulnerable-Primitives).
	readinessControls := map[string]bool{
		"CryptaMap→PQC-Readiness":            true, // SEBI, RBI
		"CryptaMap→PQ-Vulnerable-Primitives": true, // IRDAI
	}
	for _, posture := range []models.CryptoPosture{
		models.PostureNonPQCClassical, models.PostureLegacyTLS,
		models.PosturePQCHybrid, models.PostureUnknown,
	} {
		want := readinessFromPosture(posture)
		for _, m := range []Mapper{&SEBIMapper{}, &RBIMapper{}, &IRDAIMapper{}} {
			found := false
			for _, mp := range m.Map(asset, posture) {
				if !readinessControls[mp.ControlID] {
					continue
				}
				found = true
				if mp.Status != want {
					t.Errorf("%s readiness row %s for %s = %q, want %q (shared readiness vocabulary)",
						m.ID(), mp.ControlID, posture, mp.Status, want)
				}
			}
			if !found {
				t.Errorf("%s emitted no readiness row for %s — the consistency check would silently assert nothing", m.ID(), posture)
			}
		}
	}
}

// TestCanadaMapperReadinessNotObligation pins the Canada fix: the CCCS
// roadmap is Government-of-Canada-scoped and PHASED (2031 high-priority / 2035
// remaining), so the mapper must use the readiness vocabulary — never
// "non-compliant" — and must not stamp a single hard DeadlineDate.
func TestCanadaMapperReadinessNotObligation(t *testing.T) {
	m := &CanadaMapper{}
	asset := models.CryptoAsset{Service: "alb", Category: models.CategoryDataInTransit}
	maps := m.Map(asset, models.PostureNonPQCClassical)
	if len(maps) == 0 {
		t.Fatal("expected a CCCS roadmap mapping for a transit asset")
	}
	for _, mp := range maps {
		if mp.Status == "compliant" || mp.Status == "non-compliant" {
			t.Errorf("Canada mapper used regulatory term %q — CCCS roadmap is GoC-scoped, must use readiness vocabulary", mp.Status)
		}
		if mp.DeadlineDate != "" {
			t.Errorf("Canada mapper stamped DeadlineDate %q — the phased 2031/2035 roadmap must not collapse to one hard date", mp.DeadlineDate)
		}
	}
}

// TestEuropolMapperReadinessAndAtRestCoverage pins two fixes: QSFF publishes
// VOLUNTARY recommendations (readiness vocabulary, never "non-compliant"), and
// the at-rest scope is category-based — a redshift at-rest asset must be
// covered, not just the former hardcoded rds/dynamodb/s3 trio.
func TestEuropolMapperReadinessAndAtRestCoverage(t *testing.T) {
	m := &EuropolMapper{}
	redshift := models.CryptoAsset{Service: "redshift", Category: models.CategoryDataAtRest}
	maps := m.Map(redshift, models.PostureNonPQCClassical)
	if len(maps) == 0 {
		t.Fatal("QSFF row missing for a redshift at-rest asset (category-based gate)")
	}
	for _, mp := range maps {
		if mp.Status == "compliant" || mp.Status == "non-compliant" {
			t.Errorf("Europol mapper used regulatory term %q for voluntary QSFF recommendations", mp.Status)
		}
	}
}

// TestCISAMigrationRowHasNoFabricatedDeadline pins the CISA fix: M-23-02
// (an OMB memorandum) publishes no single migration deadline; the previously
// hardcoded "2027-12-31" was unverifiable and must stay removed.
func TestCISAMigrationRowHasNoFabricatedDeadline(t *testing.T) {
	m := &CISAMapper{}
	asset := models.CryptoAsset{Service: "alb", Category: models.CategoryDataInTransit}
	for _, mp := range m.Map(asset, models.PostureNonPQCClassical) {
		if mp.ControlID == "M-23-02-MIGRATION" && mp.DeadlineDate != "" {
			t.Errorf("M-23-02-MIGRATION carries DeadlineDate %q; M-23-02 publishes no such date", mp.DeadlineDate)
		}
	}
}

// TestUnknownFrameworkIDsDetected pins the guard: a config typo must be
// detectable, not silently drop a regulator from all output.
func TestUnknownFrameworkIDsDetected(t *testing.T) {
	unknown := UnknownFrameworkIDs([]string{"SEBI-CSCRF", SEBI})
	if len(unknown) != 1 || unknown[0] != "SEBI-CSCRF" {
		t.Errorf("UnknownFrameworkIDs = %v, want [SEBI-CSCRF]", unknown)
	}
	if got := UnknownFrameworkIDs(KnownFrameworkIDs()); len(got) != 0 {
		t.Errorf("all known IDs flagged unknown: %v", got)
	}
	// A registry built from ONLY typos is empty — the warning path is the guard.
	r := NewRegistry([]string{"SEBI-CSCRF"})
	if n := len(r.mappers); n != 0 {
		t.Errorf("typo-only registry has %d mappers, want 0 (typos must not match)", n)
	}
}
