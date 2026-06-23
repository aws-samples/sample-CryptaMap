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
	if statusFromPosture(models.PosturePQCHybrid) != "compliant" {
		t.Error("pqc-hybrid should be compliant")
	}
	if statusFromPosture(models.PostureNonPQCClassical) != "partial" {
		t.Error("non-pqc-classical should be partial")
	}
}

// TestReadinessFromPosture pins the India-framework readiness vocabulary (no PQC
// mandate → no "compliant"/"non-compliant" overclaim).
func TestReadinessFromPosture(t *testing.T) {
	cases := map[models.CryptoPosture]string{
		models.PostureNoEncryption:    "quantum-vulnerable",
		models.PostureLegacyTLS:       "quantum-vulnerable",
		models.PostureNonPQCClassical: "partial",
		models.PosturePQCHybrid:       "quantum-safe",
		models.PosturePQCReady:        "quantum-safe",
		models.PostureSymmetricOnly:   "quantum-safe",
		models.PostureUnknown:         "informational",
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
