package risk

import "github.com/aws-samples/cryptamap/pkg/models"

// SeverityFromPosture maps the cryptographic posture to a Severity. This is the
// deterministic mapping per the spec: no encryption=CRITICAL through pqc-ready=INFO.
func SeverityFromPosture(p models.CryptoPosture) models.Severity {
	switch p {
	case models.PostureNoEncryption:
		return models.SeverityCritical
	case models.PostureLegacyTLS:
		return models.SeverityHigh
	case models.PostureNonPQCClassical:
		return models.SeverityMedium
	case models.PostureSymmetricOnly, models.PosturePQCHybrid, models.PosturePQCReady:
		return models.SeverityInformational
	default:
		return models.SeverityMedium
	}
}

// SeverityFromMosca maps the Mosca score back to severity per spec table:
// score >= 7 -> CRITICAL, 4-6 -> HIGH, 1-3 -> MEDIUM, <= 0 -> INFORMATIONAL.
func SeverityFromMosca(score int) models.Severity {
	switch {
	case score >= 7:
		return models.SeverityCritical
	case score >= 4:
		return models.SeverityHigh
	case score >= 1:
		return models.SeverityMedium
	default:
		return models.SeverityInformational
	}
}

// IsQuantumSafePosture reports whether a posture is already quantum-safe and
// therefore needs no PQC migration: AES symmetric-at-rest (Grover-only, not
// Shor-vulnerable), PQ-hybrid, or pure PQC. For these postures the Mosca/HNDL
// urgency must NOT raise the finding severity — data shelf-life is irrelevant
// once the cryptography is already quantum-resistant.
func IsQuantumSafePosture(p models.CryptoPosture) bool {
	switch p {
	case models.PostureSymmetricOnly, models.PosturePQCHybrid, models.PosturePQCReady:
		return true
	default:
		return false
	}
}

// HighestSeverity returns the worst of two severities.
func HighestSeverity(a, b models.Severity) models.Severity {
	if models.NormalizedSeverity(a) >= models.NormalizedSeverity(b) {
		return a
	}
	return b
}
