package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// RBIMapper — Reserve Bank of India.
//
// IMPORTANT: RBI has NOT issued a "quantum-safe protocols" mandate. Its only
// quantum action to date is the RBI Q-SAFE Expert Committee (an advisory study
// body, est. 25 May 2026), whose report is pending — there is no RBI PQC
// deadline. RBI references its directives by circular number (e.g.
// RBI/2025-26/28), not by "RBI-*" control codes; the ControlID values below are
// CryptaMap's OWN mapping labels (prefixed "CryptaMap→"), never official RBI
// identifiers. The one genuine, citable RBI mandate here is the .bank.in domain
// migration (Circular RBI/2025-26/28, 22 Apr 2025, "not later than October 31,
// 2025") — which is an anti-phishing / digital-trust requirement, NOT a PQC one.
// National PQC framing is CERT-In CIWP-2025-0002.
type RBIMapper struct{}

func (m *RBIMapper) ID() string { return RBI }

func (m *RBIMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{}
	if asset.Category == models.CategoryDataInTransit {
		// RBI has no PQC mandate, so report quantum-READINESS (not regulatory
		// compliance). A quantum-vulnerable in-transit posture is surfaced as
		// quantum-vulnerable, not "non-compliant" (there is no obligation to breach).
		status := readinessFromPosture(posture)
		if posture == models.PostureNonPQCClassical || posture == models.PostureLegacyTLS {
			status = "quantum-vulnerable"
		}
		out = append(out, models.ComplianceMapping{
			Framework:   RBI,
			ControlID:   "CryptaMap→PQC-Readiness",
			ControlName: "PQC readiness for in-transit cryptography (CERT-In CIWP-2025-0002)",
			Status:      status,
			Remediation: "Switch to PQ-hybrid TLS via AWS-LC/s2n-tls; enable ML-KEM key exchange where supported (KMS, ACM, Secrets Manager, Transfer Family, Payments Cryptography, ALB/NLB). No RBI PQC mandate exists yet (Q-SAFE committee report pending); migration is framed nationally by CERT-In CIWP-2025-0002.",
		})
	}
	if asset.Service == "acm" || asset.Service == "iam_certs" || asset.Service == "cloudfront_certs" {
		out = append(out, models.ComplianceMapping{
			Framework:    RBI,
			ControlID:    "CryptaMap→bank.in-Domain",
			ControlName:  ".bank.in domain migration (RBI Circular RBI/2025-26/28; anti-phishing, non-PQC)",
			Status:       "informational",
			Remediation:  "Confirm bank-customer-facing certificates are issued under the .bank.in TLD per RBI Circular RBI/2025-26/28 (deadline 31 Oct 2025). This is a digital-trust requirement, not a quantum-safe one.",
			DeadlineDate: "2025-10-31",
		})
	}
	return out
}
