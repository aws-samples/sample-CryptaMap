package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// EuropolMapper — Europol Quantum-Safe Financial Forum (QSFF) recommendations.
// QSFF publishes VOLUNTARY recommendations from a financial-sector forum, not a
// regulatory obligation, so this mapper reports quantum-READINESS (never
// "compliant"/"non-compliant" — there is no mandate to breach).
type EuropolMapper struct{}

func (m *EuropolMapper) ID() string { return EUROPOL }

func (m *EuropolMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	// Scope: all crypto-bearing categories relevant to financial data. The
	// at-rest gate is category-based (previously a hardcoded rds/dynamodb/s3
	// trio, which silently excluded equally sensitive at-rest stores such as
	// redshift/ebs/efs and drifted as scanners were added).
	if asset.Category != models.CategoryDataInTransit &&
		asset.Category != models.CategoryCertificate &&
		asset.Category != models.CategoryKeyManagement &&
		asset.Category != models.CategoryDataAtRest {
		return nil
	}
	return []models.ComplianceMapping{{
		Framework:   EUROPOL,
		ControlID:   "QSFF-FINANCIAL-CRYPTO",
		ControlName: "Quantum-Safe Financial Forum recommendation",
		Status:      readinessFromPosture(posture),
		Remediation: "Apply QSFF guidance (voluntary recommendations) for financial-sector cryptographic agility and PQ-hybrid TLS.",
	}}
}
