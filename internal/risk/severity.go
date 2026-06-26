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
	case models.PostureUnknown:
		// Fail-safe: an undetermined posture is "needs investigation", never a
		// silent clean. Returns MEDIUM (the same value the default branch yields)
		// but does so EXPLICITLY so the contract is visible and cannot be
		// regressed into an INFORMATIONAL/clean verdict by accident.
		return models.SeverityMedium
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
	case score <= 0:
		// Fail-safe: make the non-urgent branch EXPLICIT rather than an implicit
		// default fall-through. A Mosca score <= 0 means the asset's data does not
		// outlive the CRQC horizon, so HNDL urgency does not raise severity. This
		// is INFORMATIONAL by design — but note BuildFindings only applies the
		// Mosca floor to NON-quantum-resistant postures, and PostureUnknown is
		// pinned to MEDIUM by SeverityFromPosture, so an undetermined posture can
		// never be silently cleaned by a non-positive Mosca score here.
		return models.SeverityInformational
	default:
		return models.SeverityInformational
	}
}

// IsQuantumResistantPosture reports whether a posture is already quantum-resistant and
// therefore needs no PQC migration: AES symmetric-at-rest (Grover-only, not
// Shor-vulnerable), PQ-hybrid, or pure PQC. For these postures the Mosca/HNDL
// urgency must NOT raise the finding severity — data shelf-life is irrelevant
// once the cryptography is already quantum-resistant.
func IsQuantumResistantPosture(p models.CryptoPosture) bool {
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
