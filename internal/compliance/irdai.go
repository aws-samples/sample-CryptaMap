package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// IRDAIMapper — IRDAI Information & Cyber Security Guidelines (ICSG).
//
// IMPORTANT: there is no IRDAI "Control 110" crypto-inventory control. The ICSG
// is an information-security guideline whose published text contains NO
// post-quantum / ECC / cryptographic-inventory mandate; its §3.2.2.2 is an
// information-asset inventory, not a crypto inventory. The "IRDAI-CTRL-110*"
// codes previously emitted here were fabricated. The ControlID values below are
// CryptaMap's OWN mapping labels (prefixed "CryptaMap→"), never official IRDAI
// identifiers, and no IRDAI PQC deadline is asserted (PQC framing is national —
// CERT-In CIWP-2025-0002).
type IRDAIMapper struct{}

func (m *IRDAIMapper) ID() string { return IRDAI }

func (m *IRDAIMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{}
	out = append(out, models.ComplianceMapping{
		Framework:   IRDAI,
		ControlID:   "CryptaMap→Crypto-Inventory",
		ControlName: "Cryptographic asset inventory (maps to ICSG information-asset inventory)",
		Status:      "informational",
		Remediation: "Asset is included in the CryptaMap-generated inventory mapping algorithms, key sizes, and rotation status — a cryptographic superset of the ICSG asset-inventory expectation.",
	})
	if asset.CryptoProps.AlgorithmProperties != nil {
		alg := asset.CryptoProps.AlgorithmProperties
		// Flag RSA / ECDSA key material as PQ-vulnerable (national CERT-In CIWP framing).
		if alg.Primitive == models.PrimitiveSignature || alg.Primitive == models.PrimitiveKeyAgree {
			out = append(out, models.ComplianceMapping{
				Framework:   IRDAI,
				ControlID:   "CryptaMap→PQ-Vulnerable-Primitives",
				ControlName: "PQ-vulnerable asymmetric primitives (RSA/ECC)",
				// IRDAI has no PQC deadline — report quantum-READINESS, not compliance.
				Status:      readinessFromPosture(posture),
				Remediation: "Plan migration to ML-DSA (signatures) and ML-KEM (key agreement) per CNSA 2.0 / CERT-In CIWP-2025-0002. No IRDAI PQC deadline exists.",
			})
		}
	}
	return out
}
