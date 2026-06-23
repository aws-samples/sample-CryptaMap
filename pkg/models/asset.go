// Package models defines the core data types used throughout CryptaMap.
package models

import (
	"hash/fnv"
	"strconv"
	"time"
)

// BomRefForARN returns a deterministic CycloneDX bom-ref derived from a
// resource ARN, so re-scanning the same resource yields a stable ref. This is
// the single source of truth used by both the live scanner path and the mock
// generator, and is what org-wide dedup keys on.
func BomRefForARN(arn string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(arn))
	return "crypto-" + strconv.FormatUint(h.Sum64(), 16) // 16-hex-char stable short hash
}

// Category classifies a discovered cryptographic asset by its primary surface.
type Category string

const (
	CategoryDataAtRest    Category = "data-at-rest"
	CategoryDataInTransit Category = "data-in-transit"
	CategoryCertificate   Category = "certificate"
	CategoryKeyManagement Category = "key-management"
	CategorySDKLibrary    Category = "sdk-library"
)

// AssetType reflects the CycloneDX 1.7 cryptoProperties.assetType enum.
type AssetType string

const (
	AssetTypeAlgorithm       AssetType = "algorithm"
	AssetTypeCertificate     AssetType = "certificate"
	AssetTypeProtocol        AssetType = "protocol"
	AssetTypeRelatedMaterial AssetType = "related-crypto-material"
)

// AlgorithmPrimitive — CycloneDX 1.7 cryptoProperties.algorithmProperties.primitive.
type AlgorithmPrimitive string

const (
	PrimitiveAE          AlgorithmPrimitive = "ae"
	PrimitiveBlockCipher AlgorithmPrimitive = "block-cipher"
	PrimitiveKEM         AlgorithmPrimitive = "kem"
	PrimitiveSignature   AlgorithmPrimitive = "signature"
	PrimitiveHash        AlgorithmPrimitive = "hash"
	PrimitiveKeyAgree    AlgorithmPrimitive = "key-agree"
	PrimitiveKDF         AlgorithmPrimitive = "kdf"
	PrimitiveMAC         AlgorithmPrimitive = "mac"
)

// CryptoState — material lifecycle state.
type CryptoState string

const (
	StateActive    CryptoState = "active"
	StateSuspended CryptoState = "suspended"
	StateDestroyed CryptoState = "destroyed"
	StateUnknown   CryptoState = "unknown"
)

// AlgorithmProperties mirrors CycloneDX 1.7 algorithmProperties.
type AlgorithmProperties struct {
	Primitive                AlgorithmPrimitive `json:"primitive,omitempty"`
	ParameterSetIdentifier   string             `json:"parameterSetIdentifier,omitempty"`
	Curve                    string             `json:"curve,omitempty"`
	ExecutionEnvironment     string             `json:"executionEnvironment,omitempty"`
	ImplementationPlatform   string             `json:"implementationPlatform,omitempty"`
	CertificationLevel       []string           `json:"certificationLevel,omitempty"`
	Mode                     string             `json:"mode,omitempty"`
	Padding                  string             `json:"padding,omitempty"`
	CryptoFunctions          []string           `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   int                `json:"classicalSecurityLevel,omitempty"`
	NistQuantumSecurityLevel int                `json:"nistQuantumSecurityLevel,omitempty"`
	// Additive deeper-detail fields (backward compatible, omitempty so zero values drop out).
	KeySizeBits   int    `json:"keySizeBits,omitempty"`   // symmetric/asymmetric key size in bits (e.g. 256, 2048)
	KMSKeySpec    string `json:"kmsKeySpec,omitempty"`    // AWS KMS KeySpec when KMS-backed (e.g. SYMMETRIC_DEFAULT, RSA_2048, ML_KEM_1024)
	AlgorithmName string `json:"algorithmName,omitempty"` // human algorithm label e.g. "AES-256-GCM", "RSA-2048", "ML-KEM-768"
}

// CertificateProperties mirrors CycloneDX 1.7 certificateProperties.
type CertificateProperties struct {
	SubjectName           string    `json:"subjectName,omitempty"`
	IssuerName            string    `json:"issuerName,omitempty"`
	NotValidBefore        time.Time `json:"notValidBefore,omitempty"`
	NotValidAfter         time.Time `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string    `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef   string    `json:"subjectPublicKeyRef,omitempty"`
	CertificateFormat     string    `json:"certificateFormat,omitempty"`
	CertificateExtension  string    `json:"certificateExtension,omitempty"`
}

// CipherSuite represents a TLS/IPsec cipher suite (CycloneDX 1.7 protocolProperties.cipherSuites[]).
type CipherSuite struct {
	Name        string   `json:"name,omitempty"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

// ProtocolProperties mirrors CycloneDX 1.7 protocolProperties.
type ProtocolProperties struct {
	Type                string        `json:"type,omitempty"` // tls | ipsec | ssh | ike | mqtt
	Version             string        `json:"version,omitempty"`
	CipherSuites        []CipherSuite `json:"cipherSuites,omitempty"`
	IkeV2TransformTypes []string      `json:"ikev2TransformTypes,omitempty"`
	// Additive deeper-detail fields (backward compatible, omitempty so zero values drop out).
	KeyExchangeGroup       string `json:"keyExchangeGroup,omitempty"`       // negotiated KEX group e.g. "x25519", "secp256r1", "X25519MLKEM768" (PQC hybrid)
	PQCHybrid              bool   `json:"pqcHybrid,omitempty"`              // true when KeyExchangeGroup is a PQC hybrid group
	CertSignatureAlgorithm string `json:"certSignatureAlgorithm,omitempty"` // signature algorithm of the served leaf cert e.g. "sha256WithRSAEncryption"
	CertKeySizeBits        int    `json:"certKeySizeBits,omitempty"`        // served cert public-key size in bits
	Source                 string `json:"source,omitempty"`                 // provenance of the TLS classification: "observed" (real handshake/policy) | "aws-doc" (documented guarantee)
	// TLSMinVersion is the LOWEST TLS version the endpoint's policy permits (the
	// negotiation FLOOR), distinct from Version which is the HIGHEST permitted.
	// Sourced from the floor AWS exposes (ELB SslProtocols lowest entry, CloudFront
	// MinimumProtocolVersion, API GW / IoT / OpenSearch SecurityPolicy enum). Left
	// empty when AWS exposes no floor (db-transit, cloudtrail evidence, VPN/SSH, the
	// ELB describe-failed fallback). NOT a posture or tier — an optional descriptive
	// property. A 1.0/1.1 floor is a legacy-deprecation (downgrade-hardening) signal,
	// quantum-IRRELEVANT: the floor does not change PQC vulnerability.
	TLSMinVersion string `json:"tlsMinVersion,omitempty"`
}

// RelatedCryptoMaterialProperties mirrors CycloneDX 1.7 relatedCryptoMaterialProperties.
type RelatedCryptoMaterialProperties struct {
	Type           string      `json:"type,omitempty"` // public-key | private-key | secret-key | nonce | ...
	ID             string      `json:"id,omitempty"`
	State          CryptoState `json:"state,omitempty"`
	AlgorithmRef   string      `json:"algorithmRef,omitempty"`
	CreationDate   time.Time   `json:"creationDate,omitempty"`
	ExpirationDate time.Time   `json:"expirationDate,omitempty"`
	UpdateDate     time.Time   `json:"updateDate,omitempty"`
	Value          string      `json:"value,omitempty"`
	Size           int         `json:"size,omitempty"`
	Format         string      `json:"format,omitempty"`
	SecuredBy      string      `json:"securedBy,omitempty"`
}

// CryptoProperties is the union of CycloneDX 1.7 crypto property types.
type CryptoProperties struct {
	AssetType                       AssetType                        `json:"assetType"`
	AlgorithmProperties             *AlgorithmProperties             `json:"algorithmProperties,omitempty"`
	CertificateProperties           *CertificateProperties           `json:"certificateProperties,omitempty"`
	ProtocolProperties              *ProtocolProperties              `json:"protocolProperties,omitempty"`
	RelatedCryptoMaterialProperties *RelatedCryptoMaterialProperties `json:"relatedCryptoMaterialProperties,omitempty"`
	OID                             string                           `json:"oid,omitempty"`
}

// CryptoAsset represents one discovered cryptographic asset on AWS.
// It carries enough context to render to CycloneDX 1.7 + ASFF + PQCC Excel.
type CryptoAsset struct {
	BomRef       string            `json:"bom-ref"`
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Service      string            `json:"service"`
	Category     Category          `json:"category"`
	AccountID    string            `json:"accountId"`
	Region       string            `json:"region"`
	ResourceID   string            `json:"resourceId"`
	ResourceARN  string            `json:"resourceArn,omitempty"`
	ResourceType string            `json:"resourceType,omitempty"`
	CryptoProps  CryptoProperties  `json:"cryptoProperties"`
	Tags         map[string]string `json:"tags,omitempty"`
	DiscoveredAt time.Time         `json:"discoveredAt"`
	Properties   map[string]string `json:"properties,omitempty"` // free-form k/v from scanner
}
