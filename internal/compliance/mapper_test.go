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
	for _, fw := range []string{SEBI, RBI, CISA, MITRE, CNSA, NIS2, CANADA, EUROPOL} {
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
