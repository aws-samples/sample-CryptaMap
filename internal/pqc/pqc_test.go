package pqc

import "testing"

// TestPQCSupportFor exercises known keys, alias resolution, and the
// conservative fallback for unknown services.
func TestPQCSupportFor(t *testing.T) {
	t.Run("kms available config-change", func(t *testing.T) {
		e, ok := PQCSupportFor("kms")
		if !ok {
			t.Fatalf("PQCSupportFor(kms) ok=false, want true")
		}
		if e.PQCStatus != StatusAvailable {
			t.Errorf("kms PQCStatus=%q, want %q", e.PQCStatus, StatusAvailable)
		}
		if e.UpgradeEase != EaseConfigChange {
			t.Errorf("kms UpgradeEase=%q, want %q", e.UpgradeEase, EaseConfigChange)
		}
	})

	t.Run("alb hybrid-tls-only one-flip", func(t *testing.T) {
		e, ok := PQCSupportFor("alb")
		if !ok {
			t.Fatalf("PQCSupportFor(alb) ok=false, want true")
		}
		if e.PQCStatus != StatusHybridTLSOnly {
			t.Errorf("alb PQCStatus=%q, want %q", e.PQCStatus, StatusHybridTLSOnly)
		}
		if e.UpgradeEase != EaseOneFlip {
			t.Errorf("alb UpgradeEase=%q, want %q", e.UpgradeEase, EaseOneFlip)
		}
	})

	t.Run("apigw_rest hybrid-tls-only one-flip", func(t *testing.T) {
		// Corrected 2026-06-03: API Gateway REST custom domains DO support
		// PQ-enhanced TLS security policies (SecurityPolicy_TLS13_1_2_PQ_2025_09
		// family), per the AWS security-policies-list doc. Was previously stale
		// at not-yet/none-available.
		e, ok := PQCSupportFor("apigw_rest")
		if !ok {
			t.Fatalf("PQCSupportFor(apigw_rest) ok=false, want true")
		}
		if e.PQCStatus != StatusHybridTLSOnly {
			t.Errorf("apigw_rest PQCStatus=%q, want %q", e.PQCStatus, StatusHybridTLSOnly)
		}
		if e.UpgradeEase != EaseOneFlip {
			t.Errorf("apigw_rest UpgradeEase=%q, want %q", e.UpgradeEase, EaseOneFlip)
		}
	})

	t.Run("apigw_http kept conservative not-yet", func(t *testing.T) {
		// HTTP/WebSocket API PQ support is not independently reconfirmed; kept
		// conservative deliberately so the tool does not overstate readiness.
		e, ok := PQCSupportFor("apigw_http")
		if !ok {
			t.Fatalf("PQCSupportFor(apigw_http) ok=false, want true")
		}
		if e.PQCStatus != StatusNotYet {
			t.Errorf("apigw_http PQCStatus=%q, want %q", e.PQCStatus, StatusNotYet)
		}
	})

	t.Run("ebs not-applicable", func(t *testing.T) {
		e, ok := PQCSupportFor("ebs")
		if !ok {
			t.Fatalf("PQCSupportFor(ebs) ok=false, want true")
		}
		if e.PQCStatus != StatusNotApplicable {
			t.Errorf("ebs PQCStatus=%q, want %q", e.PQCStatus, StatusNotApplicable)
		}
	})

	t.Run("kms_spec alias resolves to kms", func(t *testing.T) {
		e, ok := PQCSupportFor("kms_spec")
		if !ok {
			t.Fatalf("PQCSupportFor(kms_spec) ok=false, want true via alias")
		}
		if e.ServiceKey != "kms" {
			t.Errorf("kms_spec resolved ServiceKey=%q, want %q", e.ServiceKey, "kms")
		}
		if e.PQCStatus != StatusAvailable {
			t.Errorf("kms_spec PQCStatus=%q, want %q", e.PQCStatus, StatusAvailable)
		}
	})

	t.Run("unknown service conservative fallback", func(t *testing.T) {
		e, ok := PQCSupportFor("totally_unknown_service")
		if ok {
			t.Fatalf("PQCSupportFor(unknown) ok=true, want false")
		}
		if e.ServiceKey != "totally_unknown_service" {
			t.Errorf("fallback ServiceKey=%q, want echo of input", e.ServiceKey)
		}
		if e.PQCStatus != StatusNotYet {
			t.Errorf("fallback PQCStatus=%q, want %q", e.PQCStatus, StatusNotYet)
		}
		if e.UpgradeEase != EaseNoneAvailable {
			t.Errorf("fallback UpgradeEase=%q, want %q", e.UpgradeEase, EaseNoneAvailable)
		}
		if e.Confidence != ConfLow {
			t.Errorf("fallback Confidence=%q, want %q", e.Confidence, ConfLow)
		}
	})
}

// TestPrimitiveReadiness asserts the load-bearing classifications: RSA/ECC and
// the DH family are quantum-vulnerable; AES-256 / SHA-2 / ML-KEM / ML-DSA are
// not; and unknown primitives behave conservatively.
func TestPrimitiveReadiness(t *testing.T) {
	vulnerable := []string{
		"RSA-2048", "RSA-3072", "RSA-4096",
		"ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
		"Ed25519 (EdDSA)", "secp256k1 (ECDSA)", "SM2",
		"ECDH / ECDHE", "X25519", "DH (finite-field Diffie-Hellman)",
	}
	for _, name := range vulnerable {
		e, ok := PrimitiveReadiness(name)
		if !ok {
			t.Errorf("PrimitiveReadiness(%q) ok=false, want true", name)
			continue
		}
		if !e.QuantumVulnerable {
			t.Errorf("%q QuantumVulnerable=false, want true (RSA/ECC/DH broken by Shor)", name)
		}
	}

	notVulnerable := []string{
		"AES-256-GCM", "AES-128", "SHA-256", "SHA-384", "SHA-512",
		"HMAC-SHA-256/384/512",
		"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"ML-DSA-44 / 65 / 87", "SLH-DSA", "LMS / XMSS",
	}
	for _, name := range notVulnerable {
		e, ok := PrimitiveReadiness(name)
		if !ok {
			t.Errorf("PrimitiveReadiness(%q) ok=false, want true", name)
			continue
		}
		if e.QuantumVulnerable {
			t.Errorf("%q QuantumVulnerable=true, want false (symmetric/hash/PQC)", name)
		}
	}

	// PQC schemes must be present and classified non-vulnerable (ML-KEM and
	// ML-DSA are the PQC replacements).
	if e, ok := PrimitiveReadiness("ML-KEM-768"); !ok || e.QuantumVulnerable {
		t.Errorf("ML-KEM-768 must be a non-vulnerable PQC primitive, got ok=%v entry=%+v", ok, e)
	}
	if e, ok := PrimitiveReadiness("ML-DSA-44 / 65 / 87"); !ok || e.QuantumVulnerable {
		t.Errorf("ML-DSA must be a non-vulnerable PQC primitive, got ok=%v entry=%+v", ok, e)
	}

	// Alias normalization: assorted spellings resolve to canonical entries.
	for _, alias := range []string{"rsa", "RSA-2048", "ecdsa", "X25519MLKEM768", "ML_DSA_87", "aes-256", "sha256WithRSAEncryption"} {
		if _, ok := PrimitiveReadiness(alias); !ok {
			t.Errorf("PrimitiveReadiness(%q) ok=false, want true via alias normalization", alias)
		}
	}
	// X25519MLKEM768 carries an ML-KEM half -> not vulnerable.
	if e, _ := PrimitiveReadiness("X25519MLKEM768"); e.QuantumVulnerable {
		t.Errorf("X25519MLKEM768 should normalize to ML-KEM (non-vulnerable), got vulnerable")
	}
	// AES-256 alias resolves to AES-256-GCM (non-vulnerable).
	if e, _ := PrimitiveReadiness("aes-256"); e.QuantumVulnerable {
		t.Errorf("aes-256 should normalize to AES-256-GCM (non-vulnerable), got vulnerable")
	}

	// Unknown primitive: ok=false, and conservatively treated as vulnerable.
	if _, ok := PrimitiveReadiness("FrobnicateCipher-9000"); ok {
		t.Errorf("PrimitiveReadiness(unknown) ok=true, want false")
	}
	if !IsQuantumVulnerablePrimitive("FrobnicateCipher-9000") {
		t.Errorf("IsQuantumVulnerablePrimitive(unknown)=false, want true (conservative)")
	}
	// Known non-vulnerable primitive: helper returns false.
	if IsQuantumVulnerablePrimitive("AES-256-GCM") {
		t.Errorf("IsQuantumVulnerablePrimitive(AES-256-GCM)=true, want false")
	}
	// Known vulnerable primitive: helper returns true.
	if !IsQuantumVulnerablePrimitive("RSA-2048") {
		t.Errorf("IsQuantumVulnerablePrimitive(RSA-2048)=false, want true")
	}
}

// TestMatrixInvariants asserts every SupportEntry has a non-empty SourceURL and
// that PQCStatus/UpgradeEase/Confidence are within their declared const sets,
// plus AsOf is set. It also checks AllPrimitives has the same property
// integrity (non-empty primitive + rationale).
func TestMatrixInvariants(t *testing.T) {
	if AsOf == "" {
		t.Fatalf("AsOf is empty, want a verification date")
	}

	validStatus := map[PQCStatus]bool{
		StatusAvailable: true, StatusHybridTLSOnly: true,
		StatusNotYet: true, StatusNotApplicable: true,
		// StatusNotEncrypted is effective-only (produced by EffectivePQCStatus, never
		// a matrix row), but include it so the const set remains exhaustive.
		StatusNotEncrypted: true,
	}
	validEase := map[UpgradeEase]bool{
		EaseOneFlip: true, EaseConfigChange: true, EaseAppChange: true,
		EaseAWSManagedAuto: true, EaseNoneAvailable: true,
	}
	validConf := map[Confidence]bool{ConfHigh: true, ConfMedium: true, ConfLow: true}

	entries := All()
	if len(entries) != 26 {
		t.Errorf("len(All())=%d, want 26 matrix rows", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.ServiceKey == "" {
			t.Errorf("entry with empty ServiceKey: %+v", e)
		}
		if seen[e.ServiceKey] {
			t.Errorf("duplicate ServiceKey %q in All()", e.ServiceKey)
		}
		seen[e.ServiceKey] = true
		if e.SourceURL == "" {
			t.Errorf("service %q has empty SourceURL", e.ServiceKey)
		}
		if e.DisplayName == "" {
			t.Errorf("service %q has empty DisplayName", e.ServiceKey)
		}
		if !validStatus[e.PQCStatus] {
			t.Errorf("service %q PQCStatus=%q not in const set", e.ServiceKey, e.PQCStatus)
		}
		if !validEase[e.UpgradeEase] {
			t.Errorf("service %q UpgradeEase=%q not in const set", e.ServiceKey, e.UpgradeEase)
		}
		if !validConf[e.Confidence] {
			t.Errorf("service %q Confidence=%q not in const set", e.ServiceKey, e.Confidence)
		}
	}

	// Sorted order from All().
	for i := 1; i < len(entries); i++ {
		if entries[i-1].ServiceKey > entries[i].ServiceKey {
			t.Errorf("All() not sorted by ServiceKey at %d: %q > %q", i, entries[i-1].ServiceKey, entries[i].ServiceKey)
		}
	}

	prims := AllPrimitives()
	if len(prims) == 0 {
		t.Fatalf("AllPrimitives() empty")
	}
	for _, p := range prims {
		if p.Primitive == "" {
			t.Errorf("primitive entry with empty Primitive: %+v", p)
		}
		if p.Rationale == "" {
			t.Errorf("primitive %q has empty Rationale", p.Primitive)
		}
	}
	for i := 1; i < len(prims); i++ {
		if prims[i-1].Primitive > prims[i].Primitive {
			t.Errorf("AllPrimitives() not sorted at %d: %q > %q", i, prims[i-1].Primitive, prims[i].Primitive)
		}
	}

	// Every serviceAlias target must resolve to a real matrix row.
	for alias, target := range serviceAlias {
		if _, ok := matrix[target]; !ok {
			t.Errorf("serviceAlias[%q]=%q not present in matrix", alias, target)
		}
	}
}

// TestBareKyberNotQuantumResistant guards the FIPS-203 non-equivalence gap: a bare
// "kyber*" token (pre-standard CRYSTALS-Kyber, which is NOT byte-compatible with
// FIPS-203 ML-KEM) must NOT be auto-credited as standardized, quantum-resistant PQ.
// It must fail to resolve (so the ranker treats it conservatively as
// vulnerable/unknown), while AWS hybrid TLS group names that explicitly carry an
// ML-KEM half still resolve to a non-vulnerable ML-KEM entry.
func TestBareKyberNotQuantumResistant(t *testing.T) {
	bareKyber := []string{"kyber768", "kyber1024", "kyber512", "Kyber768", "kyber"}
	for _, name := range bareKyber {
		if _, ok := canonPrimitive(name); ok {
			t.Errorf("bare %q resolved via canonPrimitive; must fall through to conservative unknown (FIPS-203 != Kyber)", name)
		}
		e, ok := PrimitiveReadiness(name)
		if ok {
			t.Errorf("PrimitiveReadiness(%q) ok=true (%+v); bare Kyber must NOT classify as a known (quantum-resistant) primitive", name, e)
		}
	}

	// Standardized ML-KEM hybrid group names MUST still resolve and be non-vulnerable.
	for _, name := range []string{"x25519mlkem768", "secp256r1mlkem768", "mlkem768x25519-sha256", "secp384r1mlkem1024", "ml-kem-768"} {
		e, ok := PrimitiveReadiness(name)
		if !ok {
			t.Fatalf("PrimitiveReadiness(%q) ok=false; standardized ML-KEM group must resolve", name)
		}
		if e.QuantumVulnerable {
			t.Errorf("%q resolved to QuantumVulnerable=true (%+v); standardized ML-KEM must be quantum-resistant", name, e)
		}
	}
}

// TestSymmetricNISTCategory pins the corrected NIST PQC security-category mapping
// for symmetric primitives: NIST defines categories 1/3/5 by AES-128/192/256 key
// search, so AES-256 anchors Category 5 (the prior code mislabeled it Category 1).
func TestSymmetricNISTCategory(t *testing.T) {
	cases := []struct {
		bits int
		want int
	}{
		{256, 5}, // AES-256 / HMAC-256 — defines Category 5
		{512, 5}, // HMAC-512 — >=256
		{384, 5}, // HMAC-384 — >=256
		{224, 3}, // HMAC-224 — >=192
		{192, 3}, // AES-192 — defines Category 3
		{128, 1}, // AES-128 — defines Category 1
		{112, 0}, // below 128 — no defined category
		{0, 0},
	}
	for _, c := range cases {
		if got := SymmetricNISTCategory(c.bits); got != c.want {
			t.Errorf("SymmetricNISTCategory(%d) = %d, want %d", c.bits, got, c.want)
		}
	}
}
