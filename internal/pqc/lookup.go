package pqc

import "github.com/aws-samples/cryptamap/pkg/models"

// EffectivePQCStatus makes the displayed pqcStatus ASSET-AWARE. The service
// matrix stamps some at-rest/transit rows (s3, ssm, apigw_http, s3-transit) as
// StatusNotYet even though the underlying asset is symmetric AES-256 and
// therefore quantum-resistant — that "not-yet" refers to a (still-unconfirmed)
// PQ-TLS *transit* capability, not to the at-rest primitive. Presenting an
// already-quantum-resistant asset as "not-yet" wrongly implies it needs a PQC fix it
// does not.
//
// Rule: a quantum-resistant asset must NEVER carry StatusNotYet. When the service
// status is StatusNotYet AND there is a POSITIVE quantum-resistant signal, the
// effective status is promoted to StatusNotApplicable (a no-action /
// quantum-resistant state). "not-yet" is reserved for quantum-VULNERABLE assets that
// need PQC but have no fix yet.
//
// A positive quantum-resistant signal is any of:
//   - the asset posture is symmetric-only / pqc-hybrid / pqc-ready, OR
//   - the resolved primitive is positively non-vulnerable (AES-256, SHA-2,
//     ML-KEM, ML-DSA, ...).
//
// The rule is deliberately conservative: it requires a POSITIVE signal, so a
// bare unsized "AES" (unknown primitive, strength unconfirmed) with no
// quantum-resistant posture stays at its matrix status (often not-yet) and is NOT
// promoted. It only ever promotes StatusNotYet -> StatusNotApplicable; it never
// downgrades a genuine StatusAvailable / StatusHybridTLSOnly capability (those
// real PQC capabilities are worth surfacing).
func EffectivePQCStatus(status PQCStatus, primitive string, posture models.CryptoPosture) PQCStatus {
	// No-encryption is a prerequisite / data-hygiene state (maturity stage 0):
	// there is no cryptographic baseline, so PQC readiness is not assessable.
	// This is checked FIRST and unconditionally (regardless of the service's
	// matrix status) because an unencrypted resource has no asymmetric material
	// to migrate AND is not quantum-resistant — it must read as neither "not-yet"
	// (awaiting a PQC fix it doesn't need) nor "not-applicable" (quantum-resistant, no
	// action). The CRITICAL severity lives on the posture axis, untouched here.
	if posture == models.PostureNoEncryption {
		return StatusNotEncrypted
	}
	// A quantum-resistant asset must NEVER advertise an actionable PQC capability
	// (available / hybrid-tls-only), even when the SERVICE matrix row is
	// available/hybrid. "Available" means "this asset has asymmetric crypto you can
	// migrate today" — but a symmetric AES-256 key (symmetric-only) or an
	// already-PQC asset (pqc-hybrid/pqc-ready) has nothing to migrate, so the
	// service capability simply does not apply to THIS asset. Example: an AWS KMS
	// symmetric encryption key (alias/aws/es) inherits the kms row's StatusAvailable
	// — which exists only because KMS offers ML-DSA *signing* key specs — and would
	// wrongly read "PQC available" on a key that is purely symmetric. Checking the
	// quantum-resistant posture FIRST (before the status passthrough below) promotes it
	// to the no-action StatusNotApplicable instead. Vulnerable postures
	// (non-pqc-classical / legacy-tls) are NOT affected, so genuinely actionable
	// migrations keep their available/hybrid status.
	if isQuantumResistantPosture(posture) {
		return StatusNotApplicable
	}
	if status != StatusNotYet {
		return status
	}
	if primitive != "" && !IsQuantumVulnerablePrimitive(primitive) {
		return StatusNotApplicable
	}
	return status
}

// isQuantumResistantPosture reports whether a posture is itself a positive
// quantum-resistant signal: symmetric-only (AES-256 at rest), pqc-hybrid (only auth
// remains classical), or pqc-ready (pure PQC). These map to INFORMATIONAL in
// risk.SeverityFromPosture, confirming they are no-action elsewhere.
func isQuantumResistantPosture(p models.CryptoPosture) bool {
	switch p {
	case models.PostureSymmetricOnly, models.PosturePQCHybrid, models.PosturePQCReady:
		return true
	default:
		return false
	}
}

// PQCSupportFor resolves a serviceKey (or a scanner Name() / risk-service key
// via serviceAlias) to its verified SupportEntry. When the key is unknown it
// returns a conservative fallback SupportEntry (PQCStatus=not-yet,
// UpgradeEase=none-available, Confidence=low) with ok=false, so callers such as
// the roadmap ranker never panic on an unmapped service and instead score it as
// a low-priority, no-action-available item. It never panics.
func PQCSupportFor(serviceKey string) (SupportEntry, bool) {
	key := resolveServiceKey(serviceKey)
	if e, ok := matrix[key]; ok {
		return e, true
	}
	return SupportEntry{
		ServiceKey:  serviceKey,
		PQCStatus:   StatusNotYet,
		UpgradeEase: EaseNoneAvailable,
		Confidence:  ConfLow,
	}, false
}

// IsQuantumVulnerablePrimitive is a convenience wrapper over PrimitiveReadiness:
// it returns true when the resolved primitive is QuantumVulnerable, and true
// (the conservative default) when the primitive is unknown, so already-resistant
// material is only sunk when it is positively identified as such.
func IsQuantumVulnerablePrimitive(name string) bool {
	e, ok := PrimitiveReadiness(name)
	if !ok {
		// Unknown primitive: assume vulnerable (conservative).
		return true
	}
	return e.QuantumVulnerable
}

// resolveServiceKey applies serviceAlias then returns the matrix key (or the
// input unchanged when there is no alias). It does not validate that the result
// is present in matrix; PQCSupportFor handles the miss.
func resolveServiceKey(name string) string {
	if canon, ok := serviceAlias[name]; ok {
		return canon
	}
	return name
}
