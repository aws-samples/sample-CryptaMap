package pqc

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestSymmetricStrengthForByName proves the strength tier is keyed off the
// asset algorithm name: AES-256 -> safe, AES-128 -> review, 3DES/DES/RC4 ->
// weak.
func TestSymmetricStrengthForByName(t *testing.T) {
	cases := []struct {
		name string
		want SymmetricStrength
	}{
		{"AES-256-GCM", StrengthSafe},
		{"AES-256", StrengthSafe},
		{"aes-256-cbc", StrengthSafe},
		{"SYMMETRIC_DEFAULT", StrengthSafe},
		{"AES-128", StrengthReview},
		{"aes-128-gcm", StrengthReview},
		{"AES-192", StrengthReview},
		{"3DES", StrengthWeak},
		{"des-ede3", StrengthWeak},
		{"tdea", StrengthWeak},
		{"DES", StrengthWeak},
		{"des-cbc", StrengthWeak},
		{"RC4", StrengthWeak},
		{"arcfour", StrengthWeak},
	}
	for _, c := range cases {
		ap := &models.AlgorithmProperties{AlgorithmName: c.name}
		if got := SymmetricStrengthFor(ap); got != c.want {
			t.Errorf("SymmetricStrengthFor(name=%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSymmetricStrengthForByKeySize proves KeySizeBits drives the tier for an
// AES/symmetric family even without a full algorithm label: 256 -> safe,
// 128/192 -> review, <=112 -> weak.
func TestSymmetricStrengthForByKeySize(t *testing.T) {
	cases := []struct {
		name string
		bits int
		want SymmetricStrength
	}{
		{"AES", 256, StrengthSafe},
		{"AES", 512, StrengthSafe},
		{"AES", 192, StrengthReview},
		{"AES", 128, StrengthReview},
		{"AES", 64, StrengthWeak},
		{"SYMMETRIC_DEFAULT", 256, StrengthSafe},
	}
	for _, c := range cases {
		ap := &models.AlgorithmProperties{AlgorithmName: c.name, KeySizeBits: c.bits}
		if got := SymmetricStrengthFor(ap); got != c.want {
			t.Errorf("SymmetricStrengthFor(name=%q,bits=%d) = %q, want %q", c.name, c.bits, got, c.want)
		}
	}
}

// TestSymmetricStrengthUnconfirmed proves a bare unsized "AES" with no key size
// and no parameter set yields the strength-unconfirmed tier (NOT safe, NOT
// weak), the conservative interim case.
func TestSymmetricStrengthUnconfirmed(t *testing.T) {
	ap := &models.AlgorithmProperties{AlgorithmName: "AES"}
	if got := SymmetricStrengthFor(ap); got != StrengthUnconfirmed {
		t.Errorf("bare unsized AES strength = %q, want %q", got, StrengthUnconfirmed)
	}
	// A bare "symmetric" with no size is also unconfirmed.
	if got := SymmetricStrengthFor(&models.AlgorithmProperties{AlgorithmName: "symmetric"}); got != StrengthUnconfirmed {
		t.Errorf("bare symmetric strength = %q, want %q", got, StrengthUnconfirmed)
	}
}

// TestSymmetricStrengthNA proves non-symmetric primitives (asymmetric / nil)
// carry StrengthNA — the symmetric tier does not apply.
func TestSymmetricStrengthNA(t *testing.T) {
	if got := SymmetricStrengthFor(nil); got != StrengthNA {
		t.Errorf("nil props strength = %q, want StrengthNA", got)
	}
	for _, name := range []string{"RSA-2048", "ECDSA-P256", "ML-DSA-87", "SHA-256"} {
		ap := &models.AlgorithmProperties{AlgorithmName: name}
		if got := SymmetricStrengthFor(ap); got != StrengthNA {
			t.Errorf("SymmetricStrengthFor(%q) = %q, want StrengthNA (non-symmetric)", name, got)
		}
	}
}

// TestPrimitiveStrengthTable proves the table-level strength tiers are set on
// the symmetric rows and absent on asymmetric/PQC rows.
func TestPrimitiveStrengthTable(t *testing.T) {
	if PrimitiveStrength("AES-256-GCM") != StrengthSafe {
		t.Errorf("AES-256-GCM strength != safe")
	}
	if PrimitiveStrength("AES-128") != StrengthReview {
		t.Errorf("AES-128 strength != review")
	}
	for _, w := range []string{"3DES", "DES", "RC4"} {
		if PrimitiveStrength(w) != StrengthWeak {
			t.Errorf("%s strength != weak", w)
		}
		// Weak ciphers are NOT a Shor target -> quantumVulnerable=false.
		if IsQuantumVulnerablePrimitive(w) {
			t.Errorf("%s should be quantumVulnerable=false (symmetric, classically weak)", w)
		}
	}
	for _, n := range []string{"RSA-2048", "ML-DSA-44 / 65 / 87", "SHA-256"} {
		if PrimitiveStrength(n) != StrengthNA {
			t.Errorf("%s should carry StrengthNA (non-symmetric)", n)
		}
	}
}

// TestEffectivePQCStatusAssetAware proves the asset-aware override: a
// quantum-resistant signal promotes a not-yet service status to not-applicable, but a
// genuine vulnerable asset or an unconfirmed bare-AES stays not-yet, and a real
// available/hybrid capability is never downgraded.
func TestEffectivePQCStatusAssetAware(t *testing.T) {
	// Symmetric AES-256 on a not-yet service (e.g. s3) -> promoted to NA.
	if got := EffectivePQCStatus(StatusNotYet, "AES-256-GCM", models.PostureSymmetricOnly); got != StatusNotApplicable {
		t.Errorf("AES-256 symmetric-only on not-yet = %q, want not-applicable", got)
	}
	// pqc-hybrid posture alone is a positive signal.
	if got := EffectivePQCStatus(StatusNotYet, "", models.PosturePQCHybrid); got != StatusNotApplicable {
		t.Errorf("pqc-hybrid posture on not-yet = %q, want not-applicable", got)
	}
	// Non-vulnerable primitive alone is a positive signal even with unknown posture.
	if got := EffectivePQCStatus(StatusNotYet, "ML-KEM-768", models.PostureUnknown); got != StatusNotApplicable {
		t.Errorf("ML-KEM primitive on not-yet = %q, want not-applicable", got)
	}
	// Vulnerable RSA asset on a not-yet service stays not-yet (needs PQC, no fix).
	if got := EffectivePQCStatus(StatusNotYet, "RSA-2048", models.PostureNonPQCClassical); got != StatusNotYet {
		t.Errorf("RSA non-pqc-classical on not-yet = %q, want not-yet (no promotion)", got)
	}
	// Bare unsized AES (unknown primitive, no quantum-resistant posture) stays not-yet.
	if got := EffectivePQCStatus(StatusNotYet, "", models.PostureUnknown); got != StatusNotYet {
		t.Errorf("unconfirmed/unknown on not-yet = %q, want not-yet (conservative)", got)
	}
	// A QUANTUM-RESISTANT asset must NOT advertise an actionable PQC capability, even
	// when the SERVICE matrix row is available/hybrid. A symmetric AES-256 key has
	// no asymmetric material to migrate, so "PQC available" is misleading — it is
	// promoted to the no-action not-applicable. (This is the alias/aws/es case: a
	// KMS symmetric key inheriting the kms row's StatusAvailable, which exists only
	// for ML-DSA *signing* keys, must not read "PQC available".)
	if got := EffectivePQCStatus(StatusAvailable, "AES-256-GCM", models.PostureSymmetricOnly); got != StatusNotApplicable {
		t.Errorf("available on a quantum-resistant (symmetric-only) asset = %q, want not-applicable (nothing to migrate)", got)
	}
	if got := EffectivePQCStatus(StatusHybridTLSOnly, "X25519MLKEM768", models.PosturePQCHybrid); got != StatusNotApplicable {
		t.Errorf("hybrid-tls-only on an already-PQC (pqc-hybrid) asset = %q, want not-applicable (already migrated)", got)
	}
	// But an actionable capability IS preserved on a VULNERABLE asset — that is a
	// genuine migration the operator should act on.
	if got := EffectivePQCStatus(StatusAvailable, "RSA-2048", models.PostureNonPQCClassical); got != StatusAvailable {
		t.Errorf("available on a vulnerable (non-pqc-classical) asset = %q, want available (real migration)", got)
	}
	if got := EffectivePQCStatus(StatusHybridTLSOnly, "ECDHE", models.PostureNonPQCClassical); got != StatusHybridTLSOnly {
		t.Errorf("hybrid-tls-only on a vulnerable asset = %q, want hybrid-tls-only", got)
	}
	// not-applicable passes through unchanged.
	if got := EffectivePQCStatus(StatusNotApplicable, "AES-256-GCM", models.PostureSymmetricOnly); got != StatusNotApplicable {
		t.Errorf("not-applicable passthrough, got %q", got)
	}
	// No-encryption posture -> not-encrypted (stage 0), checked FIRST and
	// regardless of the service's matrix status: it is neither quantum-resistant nor an
	// awaiting-fix vulnerable asset, so it must NOT read as not-applicable/not-yet.
	if got := EffectivePQCStatus(StatusNotYet, "", models.PostureNoEncryption); got != StatusNotEncrypted {
		t.Errorf("no-encryption on not-yet = %q, want not-encrypted", got)
	}
	// The no-encryption override fires even when the matrix status is not 'not-yet'
	// (e.g. a data-at-rest service whose row is not-applicable): an unencrypted
	// instance of it is still stage 0, never quantum-resistant.
	if got := EffectivePQCStatus(StatusNotApplicable, "", models.PostureNoEncryption); got != StatusNotEncrypted {
		t.Errorf("no-encryption on not-applicable = %q, want not-encrypted (override)", got)
	}
}

// TestCipherProfileTables proves the doc-sourced lookup tables resolve the key
// identifiers used by the scanners and carry citations.
func TestCipherProfileTables(t *testing.T) {
	if p, ok := KMSKeySpecProfile("RSA_2048"); !ok || p.KeySizeBits != 2048 || p.SourceURL == "" || p.AsOf == "" {
		t.Errorf("KMSKeySpecProfile(RSA_2048) = %+v ok=%v, want 2048-bit with citation", p, ok)
	}
	if p, ok := KMSKeySpecProfile("ML_DSA_87"); !ok || p.NistQuantumSecurityLevel != 5 {
		t.Errorf("KMSKeySpecProfile(ML_DSA_87) = %+v ok=%v, want NIST level 5", p, ok)
	}
	if p, ok := ACMKeyAlgorithmProfile("EC_prime256v1"); !ok || p.Curve != "P-256" {
		t.Errorf("ACMKeyAlgorithmProfile(EC_prime256v1) = %+v ok=%v, want curve P-256", p, ok)
	}
	if p, ok := S3SSEAlgorithmProfile("aws:kms"); !ok || p.KeySizeBits != 256 {
		t.Errorf("S3SSEAlgorithmProfile(aws:kms) = %+v ok=%v, want 256-bit AES", p, ok)
	}
	if _, ok := KMSKeySpecProfile("BOGUS_SPEC"); ok {
		t.Errorf("unknown KMS spec should return ok=false")
	}
	// Every entry across the three tables must cite a SourceURL + AsOf.
	for id, p := range kmsKeySpecProfiles {
		if p.SourceURL == "" || p.AsOf == "" {
			t.Errorf("kms profile %q missing SourceURL/AsOf", id)
		}
	}
	for id, p := range acmKeyAlgorithmProfiles {
		if p.SourceURL == "" || p.AsOf == "" {
			t.Errorf("acm profile %q missing SourceURL/AsOf", id)
		}
	}
	for id, p := range s3SSEAlgorithmProfiles {
		if p.SourceURL == "" || p.AsOf == "" {
			t.Errorf("s3 profile %q missing SourceURL/AsOf", id)
		}
	}
}
