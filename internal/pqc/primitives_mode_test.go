package pqc

import (
	"strings"
	"testing"
	"time"
)

// TestModeAccurateAliases pins the fix: aes-256-cbc / aes-256-xts must NOT
// resolve to the AEAD AES-256-GCM row — the CBOM would otherwise fabricate an
// authenticated-encryption mode the scanner never observed. Both stay
// quantum-resistant (Grover-only) with mode-accurate rationale.
func TestModeAccurateAliases(t *testing.T) {
	for alias, wantPrim := range map[string]string{
		"aes-256-cbc": "AES-256-CBC",
		"aes-256-xts": "AES-256-XTS",
	} {
		e, ok := PrimitiveReadiness(alias)
		if !ok {
			t.Fatalf("PrimitiveReadiness(%q) not found", alias)
		}
		if e.Primitive != wantPrim {
			t.Errorf("PrimitiveReadiness(%q).Primitive = %q, want %q (mode must not be falsified)", alias, e.Primitive, wantPrim)
		}
		if e.QuantumVulnerable {
			t.Errorf("%q must remain quantum-resistant (Grover-only)", alias)
		}
		if e.Strength != StrengthSafe {
			t.Errorf("%q strength = %q, want %q", alias, e.Strength, StrengthSafe)
		}
	}
}

// TestSignatureOIDDoesNotFabricateModulusSize pins the fix: an x509
// signature-algorithm OID names the HASH + RSA, never the modulus size — a
// 2048-bit cert signed with SHA-384 must not be reported as "RSA-3072".
func TestSignatureOIDDoesNotFabricateModulusSize(t *testing.T) {
	for _, oid := range []string{"sha384WithRSAEncryption", "sha512WithRSAEncryption"} {
		e, ok := PrimitiveReadiness(oid)
		if !ok {
			t.Fatalf("PrimitiveReadiness(%q) not found", oid)
		}
		if strings.Contains(e.Primitive, "3072") || strings.Contains(e.Primitive, "4096") {
			t.Errorf("PrimitiveReadiness(%q).Primitive = %q fabricates a modulus size the scanner never observed", oid, e.Primitive)
		}
		if !e.QuantumVulnerable {
			t.Errorf("%q is RSA — must stay quantum-vulnerable", oid)
		}
	}
}

// TestS3SSENISTCategoryMatchesSymmetricAnchor pins the fix: the S3 SSE
// profiles must carry the same NIST PQC Category 5 for AES-256 that
// SymmetricNISTCategory and the KMS SYMMETRIC_DEFAULT row establish — the
// prior Category-1 mislabeling was corrected in one table and missed here.
func TestS3SSENISTCategoryMatchesSymmetricAnchor(t *testing.T) {
	want := SymmetricNISTCategory(256)
	if want != 5 {
		t.Fatalf("SymmetricNISTCategory(256) = %d, want 5", want)
	}
	for _, algo := range []string{"AES256", "aws:kms", "aws:kms:dsse"} {
		p, ok := S3SSEAlgorithmProfile(algo)
		if !ok {
			t.Fatalf("S3SSEAlgorithmProfile(%q) not found", algo)
		}
		if p.NistQuantumSecurityLevel != want {
			t.Errorf("S3SSEAlgorithmProfile(%q).NistQuantumSecurityLevel = %d, want %d (AES-256 anchors Category 5)", algo, p.NistQuantumSecurityLevel, want)
		}
	}
}

// TestValidateRejectsNonDateKnowledgeVersion pins the fix: override
// precedence is a string compare, so KnowledgeVersion must be a real
// YYYY-MM-DD date — otherwise "zzz"/"9999" lexicographically outranks any date.
func TestValidateRejectsNonDateKnowledgeVersion(t *testing.T) {
	base := KnowledgeFromLiterals()
	for _, bad := range []string{"zzz", "9999", "not-a-date", "2026-13-40"} {
		k := base
		k.KnowledgeVersion = bad
		if err := k.validate(); err == nil {
			t.Errorf("validate() accepted KnowledgeVersion %q; must require YYYY-MM-DD", bad)
		}
	}
	k := base
	k.KnowledgeVersion = "2026-07-03"
	if _, err := time.Parse("2006-01-02", k.KnowledgeVersion); err != nil {
		t.Fatalf("test date invalid: %v", err)
	}
	if err := k.validate(); err != nil {
		t.Errorf("validate() rejected a valid YYYY-MM-DD version: %v", err)
	}
}
