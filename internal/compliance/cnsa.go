package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// CNSAMapper — NSA Commercial National Security Algorithm 2.0.
// Mandates ML-KEM (replacing ECDH) and ML-DSA (replacing RSA/ECDSA) by 2035.
type CNSAMapper struct{}

func (m *CNSAMapper) ID() string { return CNSA }

func (m *CNSAMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{}
	if asset.CryptoProps.AlgorithmProperties == nil {
		return out
	}
	prim := asset.CryptoProps.AlgorithmProperties.Primitive
	if prim == models.PrimitiveSignature {
		out = append(out, models.ComplianceMapping{
			Framework:    CNSA,
			ControlID:    "CNSA2-SIG",
			ControlName:  "ML-DSA migration for digital signatures",
			Status:       statusFromPosture(posture),
			Remediation:  "Migrate RSA/ECDSA signatures to ML-DSA-65 (or ML-DSA-87 for SECRET-and-above) by 2035.",
			DeadlineDate: "2035-12-31",
		})
	}
	if prim == models.PrimitiveKeyAgree || prim == models.PrimitiveKEM {
		out = append(out, models.ComplianceMapping{
			Framework:    CNSA,
			ControlID:    "CNSA2-KEM",
			ControlName:  "ML-KEM migration for key encapsulation",
			Status:       statusFromPosture(posture),
			Remediation:  "Migrate ECDH/X25519 to ML-KEM-768 (or ML-KEM-1024 for SECRET-and-above) by 2035.",
			DeadlineDate: "2035-12-31",
		})
	}
	return out
}
