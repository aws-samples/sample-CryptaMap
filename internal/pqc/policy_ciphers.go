package pqc

// Versioned, doc-sourced cipher / key-algorithm lookup tables.
//
// Several crypto-detail fields are NOT returned by the AWS S3/KMS/ACM APIs: the
// APIs give only an algorithm IDENTIFIER (KMS KeySpec="RSA_2048", ACM
// KeyAlgorithm="EC_prime256v1", S3 SSEAlgorithm="aws:kms"). Translating that
// identifier into a human algorithm label, key size in bits, curve name,
// classical-security level, and NIST PQC category requires a hard-coded,
// doc-sourced table. This file is that single, versioned source of truth.
//
// Each entry cites the AWS documentation URL it is sourced from and the asOf
// date it was verified, so the mapping is auditable and can be re-verified.
// These are pure data + pure lookups (no I/O, no SDK), keeping internal/pqc
// dependency-light. The scanners (s3, kms_spec, kms_rotation, acm) wire these in
// to fill detail-panel blanks the APIs cannot.

// CipherProfile is a doc-sourced description of an algorithm identifier. Empty
// fields mean "not applicable" (e.g. Curve is empty for RSA/symmetric).
type CipherProfile struct {
	// Identifier is the raw AWS API enum string (e.g. "RSA_2048",
	// "EC_prime256v1", "SYMMETRIC_DEFAULT", "AES256", "aws:kms").
	Identifier string `json:"identifier"`
	// AlgorithmName is the human label (e.g. "RSA-2048", "ECDSA P-256",
	// "AES-256-GCM").
	AlgorithmName string `json:"algorithmName"`
	// KeySizeBits is the key size in bits (modulus for RSA, field size for ECC,
	// key length for symmetric). 0 when not meaningful.
	KeySizeBits int `json:"keySizeBits,omitempty"`
	// Curve is the friendly NIST curve name for EC algorithms (e.g. "P-256"),
	// empty otherwise.
	Curve string `json:"curve,omitempty"`
	// ClassicalSecurityLevel is the approximate classical security strength in
	// bits (e.g. RSA-2048 ~ 112, AES-256 = 256), 0 when unknown. NOTE: AWS docs do
	// not publish these per-spec strengths; they are NIST SP 800-57 Part 1 (Table 2)
	// comparable-strength estimates — see SecondarySourceURL where set.
	ClassicalSecurityLevel int `json:"classicalSecurityLevel,omitempty"`
	// NistQuantumSecurityLevel is the NIST PQC category (1/3/5) for PQC and
	// quantum-resistant symmetric algorithms; 0 for quantum-vulnerable classical
	// asymmetric algorithms (which have NO post-quantum security). For ML-DSA the
	// category (2/3/5) is defined by NIST FIPS 204, not the AWS page — see
	// SecondarySourceURL.
	NistQuantumSecurityLevel int `json:"nistQuantumSecurityLevel,omitempty"`
	// SourceURL is the AWS doc that names this key spec / algorithm.
	SourceURL string `json:"sourceUrl"`
	// SecondarySourceURL is the authoritative standard backing the DERIVED numeric
	// fields (classical strength / NIST PQC category) that the AWS page does not
	// itself state — NIST SP 800-57 Part 1 or NIST FIPS 204. Empty when the AWS
	// SourceURL already states the numbers (e.g. symmetric AES-256).
	SecondarySourceURL string `json:"secondarySourceUrl,omitempty"`
	// AsOf is the verification date (YYYY-MM-DD).
	AsOf string `json:"asOf"`
}

// kmsKeySpecDoc URL covers the KMS key-spec definitions (sizes, asymmetric vs
// symmetric, ML-DSA PQC specs).
const (
	docKMSKeySpecs  = "https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html"
	docKMSSymmetric = "https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html"
	docACMChars     = "https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate-characteristics.html"
	docS3SSE        = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"
	cipherTableAsOf = "2026-06-10"

	// AWS docs name the key specs (RSA_4096, ML_DSA_65, …) but do NOT publish the
	// derived numbers below. The classical security-strength estimates come from
	// NIST SP 800-57 Part 1 (Table 2: comparable strengths), and the ML-DSA NIST
	// PQC security categories come from NIST FIPS 204. Cite those standards for
	// those specific fields rather than an AWS page that does not state them.
	docNISTSP80057 = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf" // classical security strengths
	docNISTFIPS204 = "https://csrc.nist.gov/pubs/fips/204/final"                                     // ML-DSA security categories
	// NIST defines the five PQC security strength categories by reference to the
	// cost of a brute-force key search on a symmetric cipher: Category 1 = AES-128,
	// Category 3 = AES-192, Category 5 = AES-256 (and SHA-256/SHA-384 collision
	// search anchor categories 2/4). So a symmetric primitive's own NIST category is
	// its key-search strength: AES-256 *defines* Category 5, NOT Category 1.
	docNISTPQCCategories = "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)"
)

// SymmetricNISTCategory returns the NIST PQC security-strength category that a
// symmetric cipher of the given key size anchors: AES-256→5, AES-192→3, AES-128→1.
// NIST defined categories 1/3/5 as "at least as hard as a key search on AES-
// 128/192/256" (see docNISTPQCCategories), so the symmetric primitive that anchors
// a category IS that category. Sizes below 128-bit have no defined category (0).
// This is the single source of truth for the symmetric nistQuantumSecurityLevel,
// correcting the prior mislabeling of AES-256 as Category 1.
func SymmetricNISTCategory(keySizeBits int) int {
	switch {
	case keySizeBits >= 256:
		return 5
	case keySizeBits >= 192:
		return 3
	case keySizeBits >= 128:
		return 1
	default:
		return 0
	}
}

// kmsKeySpecProfiles maps AWS KMS KeySpec enum strings to their doc-sourced
// profile. AES-256 (SYMMETRIC_DEFAULT) and HMAC are quantum resistant (NIST
// level 1); RSA/ECC/SM2 are quantum-vulnerable (NIST level 0 — no PQ security);
// ML-DSA specs are PQC (FIPS 204, NIST levels 2/3/5 -> reported as 1/3/5 floor
// here per AWS guidance: ML-DSA-44=cat2, 65=cat3, 87=cat5).
var kmsKeySpecProfiles = map[string]CipherProfile{
	"SYMMETRIC_DEFAULT": {
		Identifier: "SYMMETRIC_DEFAULT", AlgorithmName: "AES-256-GCM", KeySizeBits: 256,
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 5, // AES-256 anchors NIST Category 5
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTPQCCategories, AsOf: cipherTableAsOf,
	},
	"RSA_2048": {
		Identifier: "RSA_2048", AlgorithmName: "RSA-2048", KeySizeBits: 2048,
		ClassicalSecurityLevel: 112, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"RSA_3072": {
		Identifier: "RSA_3072", AlgorithmName: "RSA-3072", KeySizeBits: 3072,
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"RSA_4096": {
		Identifier: "RSA_4096", AlgorithmName: "RSA-4096", KeySizeBits: 4096,
		// NIST SP 800-57 Part 1 Table 2 has no RSA-4096 row (3072→128, 7680→192);
		// RSA-4096 conservatively MEETS the 128-bit tier (exceeds 3072, below 7680).
		// Use the SP 800-57-anchored 128 rather than an un-sourced ~150 interpolation.
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"ECC_NIST_P256": {
		Identifier: "ECC_NIST_P256", AlgorithmName: "ECDSA P-256", KeySizeBits: 256, Curve: "P-256",
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"ECC_NIST_P384": {
		Identifier: "ECC_NIST_P384", AlgorithmName: "ECDSA P-384", KeySizeBits: 384, Curve: "P-384",
		ClassicalSecurityLevel: 192, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"ECC_NIST_P521": {
		Identifier: "ECC_NIST_P521", AlgorithmName: "ECDSA P-521", KeySizeBits: 521, Curve: "P-521",
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"ECC_NIST_EDWARDS25519": {
		Identifier: "ECC_NIST_EDWARDS25519", AlgorithmName: "Ed25519", KeySizeBits: 256, Curve: "Edwards25519",
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"ECC_SECG_P256K1": {
		Identifier: "ECC_SECG_P256K1", AlgorithmName: "ECDSA secp256k1", KeySizeBits: 256, Curve: "secp256k1",
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"SM2": {
		Identifier: "SM2", AlgorithmName: "SM2", KeySizeBits: 256, Curve: "SM2P256v1",
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	// HMAC keys: the NIST category is the symmetric key-search strength of the key
	// size (Cat1=128, Cat3=192, Cat5=256), per docNISTPQCCategories — corrects the
	// prior blanket Category 1.
	"HMAC_224": {
		Identifier: "HMAC_224", AlgorithmName: "HMAC-SHA-224", KeySizeBits: 224,
		ClassicalSecurityLevel: 224, NistQuantumSecurityLevel: 3, // 224-bit ≥192 → Cat 3
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTPQCCategories, AsOf: cipherTableAsOf,
	},
	"HMAC_256": {
		Identifier: "HMAC_256", AlgorithmName: "HMAC-SHA-256", KeySizeBits: 256,
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 5, // 256-bit → Cat 5
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTPQCCategories, AsOf: cipherTableAsOf,
	},
	"HMAC_384": {
		Identifier: "HMAC_384", AlgorithmName: "HMAC-SHA-384", KeySizeBits: 384,
		ClassicalSecurityLevel: 384, NistQuantumSecurityLevel: 5, // ≥256-bit → Cat 5
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTPQCCategories, AsOf: cipherTableAsOf,
	},
	"HMAC_512": {
		Identifier: "HMAC_512", AlgorithmName: "HMAC-SHA-512", KeySizeBits: 512,
		ClassicalSecurityLevel: 512, NistQuantumSecurityLevel: 5, // ≥256-bit → Cat 5
		SourceURL: docKMSKeySpecs, SecondarySourceURL: docNISTPQCCategories, AsOf: cipherTableAsOf,
	},
	// ML-DSA post-quantum signature key specs (FIPS 204). NIST PQC categories:
	// ML-DSA-44=cat2, ML-DSA-65=cat3, ML-DSA-87=cat5.
	"ML_DSA_44": {
		Identifier: "ML_DSA_44", AlgorithmName: "ML-DSA-44", NistQuantumSecurityLevel: 2,
		SourceURL: "https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html", SecondarySourceURL: docNISTFIPS204, AsOf: cipherTableAsOf,
	},
	"ML_DSA_65": {
		Identifier: "ML_DSA_65", AlgorithmName: "ML-DSA-65", NistQuantumSecurityLevel: 3,
		SourceURL: "https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html", SecondarySourceURL: docNISTFIPS204, AsOf: cipherTableAsOf,
	},
	"ML_DSA_87": {
		Identifier: "ML_DSA_87", AlgorithmName: "ML-DSA-87", NistQuantumSecurityLevel: 5,
		SourceURL: "https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html", SecondarySourceURL: docNISTFIPS204, AsOf: cipherTableAsOf,
	},
}

// acmKeyAlgorithmProfiles maps ACM KeyAlgorithm enum strings to their
// doc-sourced profile. ACM issues only classical RSA/ECDSA certs (no PQC), per
// the ACM characteristics doc; all are NIST quantum level 0.
var acmKeyAlgorithmProfiles = map[string]CipherProfile{
	"RSA_1024": {
		Identifier: "RSA_1024", AlgorithmName: "RSA-1024", KeySizeBits: 1024,
		ClassicalSecurityLevel: 80, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"RSA_2048": {
		Identifier: "RSA_2048", AlgorithmName: "RSA-2048", KeySizeBits: 2048,
		ClassicalSecurityLevel: 112, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"RSA_3072": {
		Identifier: "RSA_3072", AlgorithmName: "RSA-3072", KeySizeBits: 3072,
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"RSA_4096": {
		Identifier: "RSA_4096", AlgorithmName: "RSA-4096", KeySizeBits: 4096,
		// NIST SP 800-57 Part 1 Table 2 has no RSA-4096 row (3072→128, 7680→192);
		// RSA-4096 conservatively MEETS the 128-bit tier (exceeds 3072, below 7680).
		// Use the SP 800-57-anchored 128 rather than an un-sourced ~150 interpolation.
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"EC_prime256v1": {
		Identifier: "EC_prime256v1", AlgorithmName: "ECDSA P-256", KeySizeBits: 256, Curve: "P-256",
		ClassicalSecurityLevel: 128, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"EC_secp384r1": {
		Identifier: "EC_secp384r1", AlgorithmName: "ECDSA P-384", KeySizeBits: 384, Curve: "P-384",
		ClassicalSecurityLevel: 192, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
	"EC_secp521r1": {
		Identifier: "EC_secp521r1", AlgorithmName: "ECDSA P-521", KeySizeBits: 521, Curve: "P-521",
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 0,
		SourceURL: docACMChars, SecondarySourceURL: docNISTSP80057, AsOf: cipherTableAsOf,
	},
}

// s3SSEAlgorithmProfiles maps S3 SSEAlgorithm enum strings to their doc-sourced
// profile. All S3 server-side encryption modes use AES-256 (quantum resistant).
var s3SSEAlgorithmProfiles = map[string]CipherProfile{
	"AES256": {
		Identifier: "AES256", AlgorithmName: "AES-256-GCM", KeySizeBits: 256,
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 1,
		SourceURL: docS3SSE, AsOf: cipherTableAsOf,
	},
	"aws:kms": {
		Identifier: "aws:kms", AlgorithmName: "AES-256-GCM (SSE-KMS)", KeySizeBits: 256,
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 1,
		SourceURL: docS3SSE, AsOf: cipherTableAsOf,
	},
	"aws:kms:dsse": {
		Identifier: "aws:kms:dsse", AlgorithmName: "AES-256-GCM (DSSE-KMS)", KeySizeBits: 256,
		ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 1,
		SourceURL: docS3SSE, AsOf: cipherTableAsOf,
	},
}

// KMSKeySpecProfile returns the doc-sourced profile for a KMS KeySpec enum
// string. ok=false on an unknown spec.
func KMSKeySpecProfile(keySpec string) (CipherProfile, bool) {
	p, ok := kmsKeySpecProfiles[keySpec]
	return p, ok
}

// ACMKeyAlgorithmProfile returns the doc-sourced profile for an ACM KeyAlgorithm
// enum string. ok=false on an unknown algorithm.
func ACMKeyAlgorithmProfile(keyAlgo string) (CipherProfile, bool) {
	p, ok := acmKeyAlgorithmProfiles[keyAlgo]
	return p, ok
}

// S3SSEAlgorithmProfile returns the doc-sourced profile for an S3 SSEAlgorithm
// enum string. ok=false on an unknown algorithm.
func S3SSEAlgorithmProfile(sseAlgo string) (CipherProfile, bool) {
	p, ok := s3SSEAlgorithmProfiles[sseAlgo]
	return p, ok
}
