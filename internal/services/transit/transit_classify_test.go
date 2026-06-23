package transit

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyTransferPolicy verifies SSH KEX/cipher/MAC + TLS cipher mapping
// and that an ML-KEM KEX flags PQC-hybrid while a classical-only policy does not.
func TestClassifyTransferPolicy(t *testing.T) {
	t.Run("mlkem kex -> pqc-hybrid", func(t *testing.T) {
		props := classifyTransferPolicy(
			[]string{"mlkem768x25519-sha256", "ecdh-sha2-nistp256"},
			[]string{"aes256-gcm@openssh.com"},
			[]string{"hmac-sha2-256"},
			nil,
		)
		pp := props.ProtocolProperties
		if pp == nil {
			t.Fatalf("ProtocolProperties=nil, want non-nil")
		}
		if pp.Type != "ssh" {
			t.Errorf("Type=%q, want %q", pp.Type, "ssh")
		}
		if !pp.PQCHybrid {
			t.Errorf("PQCHybrid=%v, want true (mlkem KEX present)", pp.PQCHybrid)
		}
		if pp.KeyExchangeGroup != "mlkem768x25519-sha256" {
			t.Errorf("KeyExchangeGroup=%q, want %q", pp.KeyExchangeGroup, "mlkem768x25519-sha256")
		}
		// ssh-kex + ssh-ciphers + ssh-macs = 3 suites (no tls ciphers given).
		if len(pp.CipherSuites) != 3 {
			t.Errorf("len(CipherSuites)=%d, want 3", len(pp.CipherSuites))
		}
		if got := suiteByName(pp.CipherSuites, "ssh-ciphers"); got == nil || len(got.Algorithms) != 1 || got.Algorithms[0] != "aes256-gcm@openssh.com" {
			t.Errorf("ssh-ciphers suite=%v, want [aes256-gcm@openssh.com]", got)
		}
	})

	t.Run("classical kex -> not pqc, tls ciphers surfaced", func(t *testing.T) {
		props := classifyTransferPolicy(
			[]string{"ecdh-sha2-nistp256"},
			[]string{"aes128-ctr"},
			[]string{"hmac-sha2-256"},
			[]string{"TLS_AES_128_GCM_SHA256"},
		)
		pp := props.ProtocolProperties
		if pp.PQCHybrid {
			t.Errorf("PQCHybrid=%v, want false (classical only)", pp.PQCHybrid)
		}
		if suiteByName(pp.CipherSuites, "tls-ciphers") == nil {
			t.Errorf("tls-ciphers suite missing, want present")
		}
	})

	t.Run("empty lists -> no suites, no pqc", func(t *testing.T) {
		props := classifyTransferPolicy(nil, nil, nil, nil)
		pp := props.ProtocolProperties
		if pp.PQCHybrid {
			t.Errorf("PQCHybrid=%v, want false", pp.PQCHybrid)
		}
		if len(pp.CipherSuites) != 0 {
			t.Errorf("len(CipherSuites)=%d, want 0", len(pp.CipherSuites))
		}
	})
}

// TestPostureFromTransferKexs covers ML-KEM -> PQC-hybrid, classical ->
// non-pqc-classical, and empty -> empty (caller keeps its own default).
func TestPostureFromTransferKexs(t *testing.T) {
	cases := []struct {
		name string
		kexs []string
		want models.CryptoPosture
	}{
		{"mlkem", []string{"mlkem768nistp256-sha256"}, models.PosturePQCHybrid},
		{"ml-kem spelling", []string{"ml-kem-768-x25519"}, models.PosturePQCHybrid},
		{"classical", []string{"curve25519-sha256", "ecdh-sha2-nistp384"}, models.PostureNonPQCClassical},
		{"empty", nil, models.CryptoPosture("")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := postureFromTransferKexs(c.kexs); got != c.want {
				t.Errorf("postureFromTransferKexs(%v)=%q, want %q", c.kexs, got, c.want)
			}
		})
	}
}

// TestClassifyVPNTunnel verifies the IPsec mapping: encryption+integrity into
// cipher suites, IKE versions into IkeV2TransformTypes, DH group into the
// KeyExchangeGroup label, and that classical DH groups never flag PQC-hybrid.
func TestClassifyVPNTunnel(t *testing.T) {
	props := classifyVPNTunnel(
		[]string{"AES256-GCM-16"},  // phase1 enc
		[]string{"AES256-GCM-16"},  // phase2 enc (duplicate, deduped)
		[]string{"SHA2-256"},       // phase1 integrity
		[]string{"SHA2-512"},       // phase2 integrity
		[]int32{20, 21},            // DH groups
		[]string{"ikev2", "ikev2"}, // IKE versions (deduped)
	)
	pp := props.ProtocolProperties
	if pp == nil {
		t.Fatalf("ProtocolProperties=nil, want non-nil")
	}
	if pp.Type != "ipsec" {
		t.Errorf("Type=%q, want %q", pp.Type, "ipsec")
	}
	if pp.PQCHybrid {
		t.Errorf("PQCHybrid=%v, want false (classical DH groups)", pp.PQCHybrid)
	}
	if pp.KeyExchangeGroup != "DH-group-20" {
		t.Errorf("KeyExchangeGroup=%q, want %q", pp.KeyExchangeGroup, "DH-group-20")
	}
	if len(pp.IkeV2TransformTypes) != 1 || pp.IkeV2TransformTypes[0] != "ikev2" {
		t.Errorf("IkeV2TransformTypes=%v, want [ikev2]", pp.IkeV2TransformTypes)
	}
	enc := suiteByName(pp.CipherSuites, "ipsec-encryption")
	if enc == nil || len(enc.Algorithms) != 1 || enc.Algorithms[0] != "AES256-GCM-16" {
		t.Errorf("ipsec-encryption suite=%v, want deduped [AES256-GCM-16]", enc)
	}
	integ := suiteByName(pp.CipherSuites, "ipsec-integrity")
	if integ == nil || len(integ.Algorithms) != 2 {
		t.Errorf("ipsec-integrity suite=%v, want 2 algos", integ)
	}
}

// TestClassifyMSKTransit covers Plaintext -> no-encryption/none, TLS -> non-pqc
// (enforced), TLS_PLAINTEXT -> not-fully-enforced mixed mode, and that the
// InCluster pointer is surfaced as a string.
func TestClassifyMSKTransit(t *testing.T) {
	t.Run("plaintext", func(t *testing.T) {
		ver, suite, posture, _, inCluster, enforced := classifyMSKTransit("PLAINTEXT", nil)
		if ver != "none" || suite != "PLAINTEXT" {
			t.Errorf("ver/suite=%q/%q, want none/PLAINTEXT", ver, suite)
		}
		if posture != models.PostureNoEncryption {
			t.Errorf("posture=%q, want %q", posture, models.PostureNoEncryption)
		}
		if enforced != "false" {
			t.Errorf("enforced=%q, want false", enforced)
		}
		if inCluster != "" {
			t.Errorf("inCluster=%q, want empty (nil pointer)", inCluster)
		}
	})

	t.Run("tls with in-cluster true", func(t *testing.T) {
		b := true
		ver, _, posture, props, inCluster, enforced := classifyMSKTransit("TLS", &b)
		if ver != "1.2" {
			t.Errorf("ver=%q, want 1.2", ver)
		}
		if posture != models.PostureNonPQCClassical {
			t.Errorf("posture=%q, want %q", posture, models.PostureNonPQCClassical)
		}
		if enforced != "true" {
			t.Errorf("enforced=%q, want true (TLS-only enforces)", enforced)
		}
		if inCluster != "true" {
			t.Errorf("inCluster=%q, want true", inCluster)
		}
		if props.ProtocolProperties == nil || props.ProtocolProperties.Type != "tls" {
			t.Errorf("props.Type=%v, want tls", props.ProtocolProperties)
		}
	})

	t.Run("tls_plaintext is mixed/not-enforced (not clean TLS)", func(t *testing.T) {
		b := false
		_, suite, posture, _, inCluster, enforced := classifyMSKTransit("TLS_PLAINTEXT", &b)
		// Must NOT be reported identically to a pure-TLS cluster: it permits
		// plaintext client-broker traffic by definition.
		if posture != models.PostureLegacyTLS {
			t.Errorf("posture=%q, want %q (mixed mode permits plaintext)", posture, models.PostureLegacyTLS)
		}
		if enforced != "false" {
			t.Errorf("enforced=%q, want false (TLS_PLAINTEXT accepts plaintext)", enforced)
		}
		if suite != "TLS_PLAINTEXT-mixed" {
			t.Errorf("suite=%q, want TLS_PLAINTEXT-mixed", suite)
		}
		if inCluster != "false" {
			t.Errorf("inCluster=%q, want false", inCluster)
		}
	})
}

// TestClassifyOpenSearchTLSPolicy verifies the four REAL enum values map to the
// correct ver/posture and that PQCHybrid is never set (none are post-quantum).
func TestClassifyOpenSearchTLSPolicy(t *testing.T) {
	cases := []struct {
		policy      string
		wantVer     string
		wantPosture models.CryptoPosture
	}{
		{"Policy-Min-TLS-1-0-2019-07", "1.0", models.PostureLegacyTLS},
		{"Policy-Min-TLS-1-2-2019-07", "1.2", models.PostureNonPQCClassical},
		{"Policy-Min-TLS-1-2-PFS-2023-10", "1.3", models.PostureNonPQCClassical},
		{"Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08", "1.3", models.PostureNonPQCClassical},
		{"", "1.2", models.PostureNonPQCClassical},                    // empty default
		{"Some-Unknown-Policy", "1.2", models.PostureNonPQCClassical}, // unrecognized default
	}
	for _, c := range cases {
		t.Run(c.policy, func(t *testing.T) {
			ver, posture, pqc := classifyOpenSearchTLSPolicy(c.policy)
			if ver != c.wantVer {
				t.Errorf("ver=%q, want %q", ver, c.wantVer)
			}
			if posture != c.wantPosture {
				t.Errorf("posture=%q, want %q", posture, c.wantPosture)
			}
			if pqc {
				t.Errorf("pqcHybrid=%v, want false (no OpenSearch TLS policy is PQ)", pqc)
			}
		})
	}
}

// TestOpenSearchEnforceHTTPSOverride verifies the plaintext downgrade: a domain
// with EnforceHTTPS=false permits plaintext and must NOT be reported as clean
// classical TLS, while EnforceHTTPS=true and a nil pointer leave the classical
// verdict untouched (no fabricated alarm).
func TestOpenSearchEnforceHTTPSOverride(t *testing.T) {
	t.Run("enforce=false -> plaintext allowed, note set (not clean)", func(t *testing.T) {
		b := false
		plaintext, note := openSearchEnforceHTTPSOverride(&b)
		if !plaintext {
			t.Errorf("plaintextAllowed=%v, want true (EnforceHTTPS=false permits plaintext)", plaintext)
		}
		if note == "" {
			t.Errorf("note=%q, want a non-empty explanatory note", note)
		}
	})

	t.Run("enforce=true -> no downgrade, no note", func(t *testing.T) {
		b := true
		plaintext, note := openSearchEnforceHTTPSOverride(&b)
		if plaintext {
			t.Errorf("plaintextAllowed=%v, want false (TLS enforced)", plaintext)
		}
		if note != "" {
			t.Errorf("note=%q, want empty", note)
		}
	})

	t.Run("nil pointer -> no downgrade, no note (no fabricated alarm)", func(t *testing.T) {
		plaintext, note := openSearchEnforceHTTPSOverride(nil)
		if plaintext {
			t.Errorf("plaintextAllowed=%v, want false (field absent)", plaintext)
		}
		if note != "" {
			t.Errorf("note=%q, want empty", note)
		}
	})
}

// suiteByName returns a pointer to the cipher suite with the given name, or nil.
func suiteByName(suites []models.CipherSuite, name string) *models.CipherSuite {
	for i := range suites {
		if suites[i].Name == name {
			return &suites[i]
		}
	}
	return nil
}
