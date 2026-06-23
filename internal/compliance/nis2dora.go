package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// NIS2DORAMapper — EU NIS2 + DORA. Article 21 NIS2 (security measures) and
// Article 9 DORA (ICT risk management framework).
type NIS2DORAMapper struct{}

func (m *NIS2DORAMapper) ID() string { return NIS2 }

func (m *NIS2DORAMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{
		{
			Framework:   NIS2,
			ControlID:   "NIS2-ART-21",
			ControlName: "NIS2 Article 21 — cryptography & encryption",
			Status:      statusFromPosture(posture),
			Remediation: "Confirm cryptographic measures are appropriate per NIS2 Article 21(2)(h).",
		},
		{
			Framework:    NIS2,
			ControlID:    "DORA-ART-9",
			ControlName:  "DORA Article 9 — ICT risk management framework",
			Status:       statusFromPosture(posture),
			Remediation:  "Inventory and protect ICT assets with appropriate cryptographic controls per DORA Article 9.",
			DeadlineDate: "2025-01-17",
		},
	}
	return out
}
