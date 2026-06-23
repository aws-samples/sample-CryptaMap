package pqc

import (
	"sort"
	"strings"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// SymmetricStrength is an ADDITIVE classification layered on top of the binary
// QuantumVulnerable flag. It tiers symmetric/block-cipher primitives by their
// classical (and Grover-reduced) strength, so the UI can distinguish a
// quantum-safe AES-256 from an adequate-but-review AES-128 and a
// classically-broken 3DES/RC4/DES. It is orthogonal to QuantumVulnerable:
// asymmetric Shor-broken primitives carry StrengthNA (their problem is the Shor
// flag, not symmetric strength).
type SymmetricStrength string

const (
	// StrengthSafe: AES-256 (or stronger). Grover only halves to ~128-bit
	// effective; quantum-safe, no action.
	StrengthSafe SymmetricStrength = "quantum-safe"
	// StrengthReview: AES-128/192. Adequate today but Grover-reduced margin is
	// smaller; flag for review / upgrade to AES-256.
	StrengthReview SymmetricStrength = "adequate-review"
	// StrengthWeak: 3DES/DES/RC4. Classically weak or broken irrespective of
	// quantum; replace now.
	StrengthWeak SymmetricStrength = "weak-replace"
	// StrengthUnconfirmed: a bare/unsized symmetric label (e.g. "AES" with no
	// key size) whose strength cannot be confirmed. Conservatively NOT treated
	// as safe and NOT treated as weak.
	StrengthUnconfirmed SymmetricStrength = "likely-safe-unconfirmed"
	// StrengthNA: not a symmetric primitive (asymmetric / hash / PQC), so the
	// symmetric-strength tier does not apply.
	StrengthNA SymmetricStrength = ""
)

// PrimitiveEntry is one verified row of the primitive quantum-vulnerability
// table: whether the cryptographic primitive is broken by a cryptographically
// relevant quantum computer (CRQC), with a short rationale. Strength is the
// additive symmetric-strength tier (StrengthNA for non-symmetric rows).
type PrimitiveEntry struct {
	Primitive         string            `json:"primitive"`
	QuantumVulnerable bool              `json:"quantumVulnerable"`
	Strength          SymmetricStrength `json:"strength,omitempty"`
	Rationale         string            `json:"rationale"`
}

// primitives is the verified primitiveReadiness table keyed by a canonical
// primitive label. Asymmetric schemes broken by Shor (RSA/ECC/DH families) are
// QuantumVulnerable=true; symmetric/hash primitives (only Grover-affected) and
// the PQC schemes (ML-KEM/ML-DSA/SLH-DSA/LMS/XMSS) are QuantumVulnerable=false.
var primitives = map[string]PrimitiveEntry{
	"RSA-2048": {
		Primitive:         "RSA-2048",
		QuantumVulnerable: true,
		Rationale:         "Shor's algorithm efficiently factors integers, breaking RSA at all sizes (2048/3072/4096). Migrate signing to ML-DSA; for confidentiality move to ML-KEM-based KEM. Present in KMS RSA_2048/3072/4096 and ACM/Private CA RSA key algorithms.",
	},
	"RSA-3072": {
		Primitive:         "RSA-3072",
		QuantumVulnerable: true,
		Rationale:         "Shor breaks RSA regardless of modulus size; larger keys do not help against a CRQC. KMS RSA_3072.",
	},
	"RSA-4096": {
		Primitive:         "RSA-4096",
		QuantumVulnerable: true,
		Rationale:         "Shor breaks RSA regardless of modulus size. KMS RSA_4096.",
	},
	"ECDSA-P256": {
		Primitive:         "ECDSA-P256",
		QuantumVulnerable: true,
		Rationale:         "Shor solves the elliptic-curve discrete log problem, breaking ECDSA. Replace with ML-DSA. KMS ECC_NIST_P256; ACM/Private CA EC_prime256v1.",
	},
	"ECDSA-P384": {
		Primitive:         "ECDSA-P384",
		QuantumVulnerable: true,
		Rationale:         "Shor breaks ECDSA at all curve sizes. KMS ECC_NIST_P384; ACM EC_secp384r1. PQC replacement: ML-DSA.",
	},
	"ECDSA-P521": {
		Primitive:         "ECDSA-P521",
		QuantumVulnerable: true,
		Rationale:         "Shor breaks ECDSA at all curve sizes. KMS ECC_NIST_P521. PQC replacement: ML-DSA.",
	},
	"Ed25519 (EdDSA)": {
		Primitive:         "Ed25519 (EdDSA)",
		QuantumVulnerable: true,
		Rationale:         "EdDSA over Curve25519 relies on ECDLP, which Shor solves. KMS ECC_NIST_EDWARDS25519. PQC replacement: ML-DSA.",
	},
	"secp256k1 (ECDSA)": {
		Primitive:         "secp256k1 (ECDSA)",
		QuantumVulnerable: true,
		Rationale:         "ECDLP-based, broken by Shor. KMS ECC_SECG_P256K1. PQC replacement: ML-DSA.",
	},
	"SM2": {
		Primitive:         "SM2",
		QuantumVulnerable: true,
		Rationale:         "Elliptic-curve scheme (China Regions), ECDLP-based, broken by Shor. PQC replacement: ML-DSA (sign) / ML-KEM (KEM).",
	},
	"ECDH / ECDHE": {
		Primitive:         "ECDH / ECDHE",
		QuantumVulnerable: true,
		Rationale:         "Elliptic-curve Diffie-Hellman key agreement relies on ECDLP, solved by Shor; classical TLS key exchange is harvest-now-decrypt-later exposed. PQC replacement: ML-KEM (hybrid X25519MLKEM768 etc.).",
	},
	"X25519": {
		Primitive:         "X25519",
		QuantumVulnerable: true,
		Rationale:         "X25519 ECDH key agreement is ECDLP-based, broken by Shor. Used as the classical half of hybrid X25519MLKEM768. PQC replacement: ML-KEM (kept hybrid for defense-in-depth).",
	},
	"DH (finite-field Diffie-Hellman)": {
		Primitive:         "DH (finite-field Diffie-Hellman)",
		QuantumVulnerable: true,
		Rationale:         "Finite-field DH relies on the discrete log problem, solved by Shor. PQC replacement: ML-KEM.",
	},
	"AES-256-GCM": {
		Primitive:         "AES-256-GCM",
		QuantumVulnerable: false,
		Strength:          StrengthSafe,
		Rationale:         "Grover gives only a quadratic speedup, halving effective key strength to ~128 bits, which remains infeasible to brute-force. AWS KMS SYMMETRIC_DEFAULT is AES-256-GCM and is explicitly described by AWS as quantum resistant; at-rest data needs no re-encryption.",
	},
	"AES-128": {
		Primitive:         "AES-128",
		QuantumVulnerable: false,
		Strength:          StrengthReview,
		Rationale:         "Grover halves effective strength to ~64 bits, which is weaker than AES-256 but still not a practical break with realistic quantum resources; flag for review/upgrade to AES-256 rather than classifying as broken.",
	},
	"3DES": {
		Primitive:         "3DES",
		QuantumVulnerable: false,
		Strength:          StrengthWeak,
		Rationale:         "Triple DES (TDEA) offers only ~112-bit effective strength and a 64-bit block (Sweet32 birthday-bound risk). NIST deprecated 3DES and disallowed it after 2023. Classically weak irrespective of quantum; replace with AES-256-GCM now. NOT a Shor target (symmetric), so quantumVulnerable=false, but strength=weak-replace.",
	},
	"DES": {
		Primitive:         "DES",
		QuantumVulnerable: false,
		Strength:          StrengthWeak,
		Rationale:         "Single DES has a 56-bit key and is brute-forceable classically; long broken. Replace immediately with AES-256-GCM. Symmetric (not a Shor target) but strength=weak-replace.",
	},
	"RC4": {
		Primitive:         "RC4",
		QuantumVulnerable: false,
		Strength:          StrengthWeak,
		Rationale:         "RC4 stream cipher has well-known biases/plaintext-recovery attacks (RFC 7465 prohibits RC4 in TLS). Classically broken irrespective of quantum; replace now. Symmetric (not a Shor target) but strength=weak-replace.",
	},
	"SHA-384": {
		Primitive:         "SHA-384",
		QuantumVulnerable: false,
		Rationale:         "Grover only square-root speeds up preimage search; SHA-384 retains ~192-bit preimage / ample collision resistance post-quantum. CNSA 2.0 approves SHA-384/512. Not broken.",
	},
	"SHA-512": {
		Primitive:         "SHA-512",
		QuantumVulnerable: false,
		Rationale:         "Grover only halves preimage security; SHA-512 remains secure post-quantum. CNSA 2.0 approved. Not broken.",
	},
	"SHA-256": {
		Primitive:         "SHA-256",
		QuantumVulnerable: false,
		Rationale:         "Grover reduces preimage resistance to ~128 bits, still infeasible; collision resistance ~128 bits classically. Not broken by quantum; flag only for collision-sensitive contexts, not as quantum-broken.",
	},
	"HMAC-SHA-256/384/512": {
		Primitive:         "HMAC-SHA-256/384/512",
		QuantumVulnerable: false,
		Rationale:         "Symmetric MAC built on SHA-2 with a secret key; only Grover-affected, effectively quantum resistant at these sizes. KMS HMAC_224/256/384/512.",
	},
	"ML-KEM-768": {
		Primitive:         "ML-KEM-768",
		QuantumVulnerable: false,
		Rationale:         "Post-quantum key-encapsulation mechanism (FIPS 203), MLWE-based, designed to resist Shor and Grover. The PQC replacement for ECDH/DH. Used in AWS hybrid groups X25519MLKEM768 / SecP256r1MLKEM768.",
	},
	"ML-KEM-1024": {
		Primitive:         "ML-KEM-1024",
		QuantumVulnerable: false,
		Rationale:         "Highest ML-KEM parameter set (FIPS 203); CNSA 2.0 mandates pure ML-KEM-1024 for key establishment. PQC, not vulnerable. Used in SecP384r1MLKEM1024 and s2n-tls cnsa_2 (pure).",
	},
	"ML-KEM-512": {
		Primitive:         "ML-KEM-512",
		QuantumVulnerable: false,
		Rationale:         "Lowest ML-KEM parameter set (FIPS 203). PQC KEM, quantum resistant. Not used in current AWS hybrid groups (which use 768/1024) but part of the standard.",
	},
	"ML-DSA-44 / 65 / 87": {
		Primitive:         "ML-DSA-44 / 65 / 87",
		QuantumVulnerable: false,
		Rationale:         "Post-quantum lattice signature (FIPS 204), MLWE/MSIS-based, resists Shor. The PQC replacement for RSA/ECDSA/EdDSA signatures. GA in AWS KMS (key specs ML_DSA_44/65/87, signing alg ML_DSA_SHAKE_256) and AWS Private CA. CNSA 2.0 mandates ML-DSA-87.",
	},
	"SLH-DSA": {
		Primitive:         "SLH-DSA",
		QuantumVulnerable: false,
		Rationale:         "Stateless hash-based signature (FIPS 205, SPHINCS+); security rests on hash functions, quantum resistant. Conservative backup to ML-DSA. NOT yet offered by any AWS managed service (KMS/Private CA/ACM/Signer).",
	},
	"LMS / XMSS": {
		Primitive:         "LMS / XMSS",
		QuantumVulnerable: false,
		Rationale:         "Stateful hash-based signatures (NIST SP 800-208); quantum resistant, designated by CNSA 2.0 for software/firmware signing. NOT offered as managed AWS signing algorithms - would require a customer-managed implementation.",
	},
}

// primitiveAlias normalizes assorted spellings/labels emitted by
// CryptoProperties (algorithm names, parameter-set identifiers, TLS key
// exchange group strings, x509 signature OIDs) to a canonical primitives key.
// Keys are matched case-insensitively (callers go through canonPrimitive).
var primitiveAlias = map[string]string{
	// RSA family
	"rsa":                     "RSA-2048",
	"rsa-2048":                "RSA-2048",
	"rsa2048":                 "RSA-2048",
	"rsa_2048":                "RSA-2048",
	"rsa-3072":                "RSA-3072",
	"rsa3072":                 "RSA-3072",
	"rsa_3072":                "RSA-3072",
	"rsa-4096":                "RSA-4096",
	"rsa4096":                 "RSA-4096",
	"rsa_4096":                "RSA-4096",
	"sha256withrsaencryption": "RSA-2048",
	"sha384withrsaencryption": "RSA-3072",
	"sha512withrsaencryption": "RSA-4096",

	// ECDSA / EC curves
	"ecdsa":             "ECDSA-P256",
	"ec":                "ECDSA-P256",
	"ecc":               "ECDSA-P256",
	"ecdsa-p256":        "ECDSA-P256",
	"ecdsa_p256":        "ECDSA-P256",
	"p256":              "ECDSA-P256",
	"prime256v1":        "ECDSA-P256",
	"ec_prime256v1":     "ECDSA-P256",
	"ecc_nist_p256":     "ECDSA-P256",
	"secp256r1":         "ECDSA-P256",
	"ecdsa-with-sha256": "ECDSA-P256",
	"ecdsa-p384":        "ECDSA-P384",
	"ecdsa_p384":        "ECDSA-P384",
	"p384":              "ECDSA-P384",
	"secp384r1":         "ECDSA-P384",
	"ec_secp384r1":      "ECDSA-P384",
	"ecc_nist_p384":     "ECDSA-P384",
	"ecdsa-with-sha384": "ECDSA-P384",
	"ecdsa-p521":        "ECDSA-P521",
	"ecdsa_p521":        "ECDSA-P521",
	"p521":              "ECDSA-P521",
	"secp521r1":         "ECDSA-P521",
	"ec_secp521r1":      "ECDSA-P521",
	"ecc_nist_p521":     "ECDSA-P521",

	// EdDSA / Edwards / secp256k1 / SM2
	"ed25519":               "Ed25519 (EdDSA)",
	"eddsa":                 "Ed25519 (EdDSA)",
	"edwards25519":          "Ed25519 (EdDSA)",
	"ecc_nist_edwards25519": "Ed25519 (EdDSA)",
	"secp256k1":             "secp256k1 (ECDSA)",
	"ecc_secg_p256k1":       "secp256k1 (ECDSA)",
	"sm2":                   "SM2",

	// Key exchange / Diffie-Hellman (classical halves)
	"ecdh":       "ECDH / ECDHE",
	"ecdhe":      "ECDH / ECDHE",
	"x25519":     "X25519",
	"curve25519": "X25519",
	"dh":         "DH (finite-field Diffie-Hellman)",
	"dhe":        "DH (finite-field Diffie-Hellman)",
	"ffdhe":      "DH (finite-field Diffie-Hellman)",

	// Symmetric
	"aes":               "AES-256-GCM",
	"aes-256":           "AES-256-GCM",
	"aes256":            "AES-256-GCM",
	"aes-256-gcm":       "AES-256-GCM",
	"aes256gcm":         "AES-256-GCM",
	"aes-256-xts":       "AES-256-GCM",
	"aes-256-cbc":       "AES-256-GCM",
	"symmetric_default": "AES-256-GCM",
	"aes-128":           "AES-128",
	"aes128":            "AES-128",
	"aes-128-gcm":       "AES-128",
	"aes-192":           "AES-128", // 192-bit also tiers to adequate-review (not 256)
	"aes192":            "AES-128",
	// Weak/broken symmetric ciphers (classically weak, NOT Shor targets).
	"3des":         "3DES",
	"des3":         "3DES",
	"des-ede3":     "3DES",
	"des-ede3-cbc": "3DES",
	"tdea":         "3DES",
	"triple-des":   "3DES",
	"des":          "DES",
	"des-cbc":      "DES",
	"rc4":          "RC4",
	"arcfour":      "RC4",

	// Hashes
	"sha256":      "SHA-256",
	"sha-256":     "SHA-256",
	"sha384":      "SHA-384",
	"sha-384":     "SHA-384",
	"sha512":      "SHA-512",
	"sha-512":     "SHA-512",
	"hmac":        "HMAC-SHA-256/384/512",
	"hmac-sha256": "HMAC-SHA-256/384/512",
	"hmac_256":    "HMAC-SHA-256/384/512",
	"hmac_384":    "HMAC-SHA-256/384/512",
	"hmac_512":    "HMAC-SHA-256/384/512",

	// PQC KEMs (incl. hybrid TLS group names that carry an ML-KEM half).
	//
	// IMPORTANT — no bare "kyber*" aliases. Pre-standardization CRYSTALS-Kyber is
	// NOT byte-compatible with FIPS-203 ML-KEM: the final standard changed the
	// Fujisaki-Okamoto transform and the public-key/ciphertext encoding, so a
	// "Kyber768/1024/512" implementation is a transitional/draft scheme, not the
	// durable, standardized ML-KEM. Auto-aliasing a raw "kyber" label to ML-KEM
	// would FALSE-SAFE it as quantum-safe standardized PQ. We therefore do NOT
	// map bare "kyber*" here; an isolated "kyber" token falls through to the
	// conservative unknown/vulnerable default (canonPrimitive returns false ->
	// the ranker treats it as quantum-vulnerable). Only the AWS hybrid TLS group
	// names below — which name an ML-KEM half explicitly — resolve to ML-KEM.
	"ml-kem":                   "ML-KEM-768",
	"mlkem":                    "ML-KEM-768",
	"ml-kem-768":               "ML-KEM-768",
	"mlkem768":                 "ML-KEM-768",
	"x25519mlkem768":           "ML-KEM-768",
	"secp256r1mlkem768":        "ML-KEM-768",
	"mlkem768x25519-sha256":    "ML-KEM-768",
	"mlkem768nistp256-sha256":  "ML-KEM-768",
	"ml-kem-1024":              "ML-KEM-1024",
	"mlkem1024":                "ML-KEM-1024",
	"secp384r1mlkem1024":       "ML-KEM-1024",
	"mlkem1024nistp384-sha384": "ML-KEM-1024",
	"ml-kem-512":               "ML-KEM-512",
	"mlkem512":                 "ML-KEM-512",

	// PQC signatures
	"ml-dsa":           "ML-DSA-44 / 65 / 87",
	"mldsa":            "ML-DSA-44 / 65 / 87",
	"ml_dsa_44":        "ML-DSA-44 / 65 / 87",
	"ml_dsa_65":        "ML-DSA-44 / 65 / 87",
	"ml_dsa_87":        "ML-DSA-44 / 65 / 87",
	"ml-dsa-44":        "ML-DSA-44 / 65 / 87",
	"ml-dsa-65":        "ML-DSA-44 / 65 / 87",
	"ml-dsa-87":        "ML-DSA-44 / 65 / 87",
	"ml_dsa_shake_256": "ML-DSA-44 / 65 / 87",
	"dilithium":        "ML-DSA-44 / 65 / 87",
	"slh-dsa":          "SLH-DSA",
	"slhdsa":           "SLH-DSA",
	"sphincs+":         "SLH-DSA",
	"sphincs":          "SLH-DSA",
	"lms":              "LMS / XMSS",
	"xmss":             "LMS / XMSS",
}

// canonPrimitive resolves a raw primitive label to its canonical primitives
// key. It first tries an exact match against the table, then a
// case-insensitive alias lookup, then a case-insensitive direct match. It
// returns ("", false) when nothing matches.
func canonPrimitive(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if _, ok := primitives[name]; ok {
		return name, true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if canon, ok := primitiveAlias[lower]; ok {
		return canon, true
	}
	// Case-insensitive direct match against canonical keys.
	for key := range primitives {
		if strings.ToLower(key) == lower {
			return key, true
		}
	}
	return "", false
}

// PrimitiveReadiness returns the PrimitiveEntry for a primitive name
// (alias-normalized, case-insensitive). ok=false on an unknown primitive; the
// ranker treats unknown primitives conservatively as vulnerable. It never
// panics.
func PrimitiveReadiness(name string) (PrimitiveEntry, bool) {
	canon, ok := canonPrimitive(name)
	if !ok {
		return PrimitiveEntry{}, false
	}
	return primitives[canon], true
}

// PrimitiveStrength returns the SymmetricStrength tier for a primitive label
// (alias-normalized, case-insensitive). Returns StrengthNA for unknown labels
// and for non-symmetric primitives (asymmetric / hash / PQC), where the
// symmetric-strength tier does not apply. It never panics.
func PrimitiveStrength(name string) SymmetricStrength {
	e, ok := PrimitiveReadiness(name)
	if !ok {
		return StrengthNA
	}
	return e.Strength
}

// SymmetricStrengthFor derives the symmetric-strength tier from an asset's
// AlgorithmProperties, keyed off the algorithm fields the scanners populate:
// AlgorithmName / ParameterSetIdentifier (names like "3DES"/"AES-256-GCM"),
// KeySizeBits, and KMSKeySpec. It is an ADDITIVE classification layered on top
// of the binary IsQuantumVulnerablePrimitive flag — orthogonal to it.
//
// Logic (conservative, never a false "safe"):
//  1. If the named primitive is a known WEAK symmetric cipher (3DES/DES/RC4) ->
//     StrengthWeak, regardless of any key-size field.
//  2. Else if KeySizeBits is set on a symmetric/AE primitive: >=256 -> Safe,
//     128/192 -> Review, <=112 (3DES effective) or <=64 (DES) -> Weak.
//  3. Else fall back to the primitive table's own Strength (so a fully-resolved
//     "AES-256-GCM" name yields Safe and "AES-128" yields Review).
//  4. Else, for a bare/unsized symmetric label (e.g. "AES" with no key size and
//     no parameter set) -> StrengthUnconfirmed (NOT safe, NOT weak).
//  5. Else (asymmetric / hash / PQC / nothing) -> StrengthNA.
//
// A nil AlgorithmProperties yields StrengthNA.
func SymmetricStrengthFor(ap *models.AlgorithmProperties) SymmetricStrength {
	if ap == nil {
		return StrengthNA
	}
	// Pick the most specific algorithm label available.
	name := ap.AlgorithmName
	if name == "" {
		name = ap.ParameterSetIdentifier
	}
	if name == "" {
		name = ap.KMSKeySpec
	}

	// (1) Known-weak ciphers short-circuit regardless of any key size.
	if isWeakSymmetricName(name) {
		return StrengthWeak
	}

	// (2) Key-size-driven tiering for symmetric/AE algorithms.
	if ap.KeySizeBits > 0 && isSymmetricFamily(name) {
		switch {
		case ap.KeySizeBits >= 256:
			return StrengthSafe
		case ap.KeySizeBits >= 128: // 128 or 192
			return StrengthReview
		default: // <=112 effective (3DES) / 56 (DES) etc.
			return StrengthWeak
		}
	}

	// (3) Bare/unsized symmetric label ("AES" / "symmetric") with no key size:
	// strength cannot be confirmed. Checked BEFORE the table fallback because
	// the alias table optimistically maps bare "aes" -> AES-256-GCM, which would
	// otherwise yield a false "safe".
	if isBareSymmetricName(name) && ap.KeySizeBits == 0 {
		return StrengthUnconfirmed
	}

	// (4) Resolved primitive-table strength (e.g. fully-qualified AES-256-GCM,
	// AES-128, 3DES).
	if s := PrimitiveStrength(name); s != StrengthNA {
		return s
	}

	// (5) Not a symmetric primitive (asymmetric / hash / PQC / empty).
	return StrengthNA
}

// isWeakSymmetricName reports whether a raw label denotes a classically
// weak/broken symmetric cipher (3DES/DES/RC4 family), matched via the alias
// table so spellings like "des-ede3", "tdea", "arcfour" are caught.
func isWeakSymmetricName(name string) bool {
	if name == "" {
		return false
	}
	canon, ok := canonPrimitive(name)
	if !ok {
		return false
	}
	return canon == "3DES" || canon == "DES" || canon == "RC4"
}

// isSymmetricFamily reports whether a raw label denotes an AES/symmetric-cipher
// family (so a KeySizeBits-driven tier applies). It matches AES variants and the
// KMS SYMMETRIC_DEFAULT spec.
func isSymmetricFamily(name string) bool {
	l := strings.ToLower(strings.TrimSpace(name))
	if l == "" {
		return false
	}
	return strings.HasPrefix(l, "aes") || strings.HasPrefix(l, "symmetric")
}

// isBareSymmetricName reports whether a label is an unqualified "AES" (no size
// qualifier and no mode), i.e. the strength-unconfirmed case.
func isBareSymmetricName(name string) bool {
	l := strings.ToLower(strings.TrimSpace(name))
	switch l {
	case "aes", "symmetric", "symmetric_default":
		// symmetric_default IS AES-256 (resolves in the table), so it never
		// reaches here; "aes" / bare "symmetric" are the unconfirmed cases.
		return l == "aes" || l == "symmetric"
	}
	return false
}

// AllPrimitives returns every PrimitiveEntry sorted by Primitive, for tests and
// UI enumeration.
func AllPrimitives() []PrimitiveEntry {
	out := make([]PrimitiveEntry, 0, len(primitives))
	for _, e := range primitives {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Primitive < out[j].Primitive })
	return out
}
