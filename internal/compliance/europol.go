package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// EuropolMapper — Europol Quantum-Safe Financial Forum (QSFF) recommendations.
type EuropolMapper struct{}

func (m *EuropolMapper) ID() string { return EUROPOL }

func (m *EuropolMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	if asset.Category != models.CategoryDataInTransit &&
		asset.Category != models.CategoryCertificate &&
		asset.Category != models.CategoryKeyManagement &&
		asset.Service != "rds" && asset.Service != "dynamodb" && asset.Service != "s3" {
		return nil
	}
	return []models.ComplianceMapping{{
		Framework:   EUROPOL,
		ControlID:   "QSFF-FINANCIAL-CRYPTO",
		ControlName: "Quantum-Safe Financial Forum recommendation",
		Status:      statusFromPosture(posture),
		Remediation: "Apply QSFF guidance for financial-sector cryptographic agility and PQ-hybrid TLS.",
	}}
}
