package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// CanadaMapper — Canadian Centre for Cyber Security (CCCS) PQC roadmap.
type CanadaMapper struct{}

func (m *CanadaMapper) ID() string { return CANADA }

func (m *CanadaMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	if asset.Category != models.CategoryDataInTransit && asset.Category != models.CategoryCertificate &&
		asset.Category != models.CategoryKeyManagement {
		return nil
	}
	return []models.ComplianceMapping{{
		Framework:    CANADA,
		ControlID:    "CCCS-PQC-ROADMAP-2025",
		ControlName:  "Canada PQC migration roadmap",
		Status:       statusFromPosture(posture),
		Remediation:  "Adopt CCCS-recommended hybrid PQC where available; complete migration by 2031.",
		DeadlineDate: "2031-12-31",
	}}
}
