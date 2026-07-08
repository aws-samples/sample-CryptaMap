package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// CanadaMapper — Canadian Centre for Cyber Security (CCCS) PQC roadmap
// (ITSM.40.001). The roadmap is PHASED — end-2031 for high-priority systems,
// end-2035 for remaining systems — and is scoped to Government of Canada
// federal departments/agencies (non-classified systems). It is NOT an
// obligation on private-sector or non-Canadian entities, so this mapper
// reports quantum-READINESS (not regulatory compliance) and carries no single
// hard DeadlineDate (a blanket 2031 date would collapse the phased roadmap
// into its strictest milestone and over-claim scope).
type CanadaMapper struct{}

func (m *CanadaMapper) ID() string { return CANADA }

func (m *CanadaMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	if asset.Category != models.CategoryDataInTransit && asset.Category != models.CategoryCertificate &&
		asset.Category != models.CategoryKeyManagement {
		return nil
	}
	return []models.ComplianceMapping{{
		Framework:   CANADA,
		ControlID:   "CCCS-PQC-ROADMAP-2025",
		ControlName: "Canada PQC migration roadmap (ITSM.40.001, GoC-scoped; advisory reference elsewhere)",
		Status:      readinessFromPosture(posture),
		Remediation: "Adopt CCCS-recommended hybrid PQC where available. CCCS roadmap milestones (Government of Canada scope): migrate high-priority systems by end-2031 and remaining systems by end-2035; for entities outside that scope this is advisory guidance, not a mandate.",
	}}
}
