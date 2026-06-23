package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// SEBIMapper — SEBI Cybersecurity & Cyber Resilience Framework (CSCRF),
// SEBI Circular SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113 (20 Aug 2024).
//
// IMPORTANT: CSCRF does NOT publish "CSCRF-*" control codes — it is structured
// around 5 Cyber Resilience Goals mapped to the NIST CSF, and it mandates an
// SBOM (FAQ Q35–Q37), not a "CBOM", for critical applications. The ControlID
// values below are therefore CryptaMap's OWN mapping labels (prefixed
// "CryptaMap→"), never official SEBI identifiers, so they cannot be mistaken
// for a real regulator code in the emitted CBOM/compliance output. The
// post-quantum framing is national (CERT-In CIWP-2025-0002), not a SEBI mandate,
// so no SEBI-specific PQC deadline is asserted here.
type SEBIMapper struct{}

func (m *SEBIMapper) ID() string { return SEBI }

func (m *SEBIMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{}
	// Every asset contributes to the CSCRF cryptographic-inventory (SBOM) substrate.
	out = append(out, models.ComplianceMapping{
		Framework:   SEBI,
		ControlID:   "CryptaMap→CSCRF-SBOM-Inventory",
		ControlName: "Cryptographic inventory substrate for the CSCRF-mandated SBOM",
		Status:      "informational",
		Remediation: "Asset is captured in the CryptaMap CBOM, which supersets the SBOM cryptographic inventory CSCRF expects for critical applications (CSCRF FAQ Q35–Q37).",
	})
	if asset.Category == models.CategoryDataInTransit ||
		asset.Category == models.CategoryCertificate {
		out = append(out, models.ComplianceMapping{
			Framework:   SEBI,
			ControlID:   "CryptaMap→PQC-Readiness",
			ControlName: "PQC readiness for transit/certificate cryptography (CERT-In CIWP-2025-0002)",
			// SEBI has no PQC mandate (PQC framing is national/CERT-In), so this row
			// reports quantum-READINESS, not regulatory compliance. (The separate
			// data-encryption row below DOES map to a real CSCRF encryption duty.)
			Status:      readinessFromPosture(posture),
			Remediation: "Adopt PQ-hybrid TLS (X25519 + ML-KEM) on AWS-LC/s2n-tls-aware endpoints; rotate to ML-DSA certs as ACM exposes them. PQC migration is framed nationally by CERT-In CIWP-2025-0002, not by a SEBI deadline.",
		})
	}
	if posture == models.PostureNoEncryption {
		out = append(out, models.ComplianceMapping{
			Framework:   SEBI,
			ControlID:   "CryptaMap→Data-Encryption",
			ControlName: "Encryption of customer/regulated data",
			Status:      "non-compliant",
			Remediation: "Enable AES-256 at-rest encryption with a customer-managed KMS key.",
		})
	}
	return out
}
