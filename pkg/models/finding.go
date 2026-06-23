package models

import "time"

// Severity is the canonical CryptaMap severity, mirrored to ASFF.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityInformational Severity = "INFORMATIONAL"
)

// NormalizedSeverity returns the ASFF normalized score for a Severity.
func NormalizedSeverity(s Severity) int {
	switch s {
	case SeverityCritical:
		return 90
	case SeverityHigh:
		return 70
	case SeverityMedium:
		return 40
	case SeverityInformational:
		return 0
	default:
		return 1
	}
}

// CryptoPosture summarises the encryption posture for a finding.
// Mapped directly to severity in risk/severity.go.
type CryptoPosture string

const (
	PostureNoEncryption    CryptoPosture = "no-encryption"
	PostureLegacyTLS       CryptoPosture = "legacy-tls"        // TLS 1.0/1.1
	PostureNonPQCClassical CryptoPosture = "non-pqc-classical" // RSA/ECDHE without ML-KEM
	PostureSymmetricOnly   CryptoPosture = "symmetric-only"    // AES at-rest, not quantum-vulnerable
	PosturePQCHybrid       CryptoPosture = "pqc-hybrid"        // X25519 + ML-KEM
	PosturePQCReady        CryptoPosture = "pqc-ready"         // pure PQC
	PostureUnknown         CryptoPosture = "unknown"
)

// ComplianceMapping ties a finding to one regulatory framework + control ID.
type ComplianceMapping struct {
	Framework    string `json:"framework"`
	ControlID    string `json:"controlId"`
	ControlName  string `json:"controlName,omitempty"`
	Status       string `json:"status"` // compliant | non-compliant | partial | informational
	Remediation  string `json:"remediation,omitempty"`
	DeadlineDate string `json:"deadlineDate,omitempty"`
}

// MoscaScore captures the inputs and result of Mosca's Theorem for a finding.
type MoscaScore struct {
	X     int    `json:"x"` // data shelf life (years)
	Y     int    `json:"y"` // migration time (years)
	Z     int    `json:"z"` // threat timeline (years)
	Score int    `json:"score"`
	Notes string `json:"notes,omitempty"`
}

// Finding is the regulator-facing record produced for each CryptoAsset that
// merits flagging. Findings flow to ASFF + DynamoDB + the dashboard.
type Finding struct {
	ID             string              `json:"id"`
	Title          string              `json:"title"`
	Description    string              `json:"description"`
	Severity       Severity            `json:"severity"`
	Posture        CryptoPosture       `json:"posture"`
	AccountID      string              `json:"accountId"`
	Region         string              `json:"region"`
	Service        string              `json:"service"`
	ResourceID     string              `json:"resourceId"`
	ResourceARN    string              `json:"resourceArn,omitempty"`
	ResourceType   string              `json:"resourceType,omitempty"`
	AssetBomRef    string              `json:"assetBomRef,omitempty"`
	Mosca          MoscaScore          `json:"mosca"`
	Compliance     []ComplianceMapping `json:"compliance,omitempty"`
	Recommendation string              `json:"recommendation,omitempty"`
	DocsURL        string              `json:"docsUrl,omitempty"`
	CreatedAt      time.Time           `json:"createdAt"`
	UpdatedAt      time.Time           `json:"updatedAt"`
}
