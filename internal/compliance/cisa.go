package compliance

import "github.com/aws-samples/cryptamap/pkg/models"

// CISAMapper — CISA M-23-02 cryptographic inventory requirements.
// Items 4 (algorithm), 5 (service type), 6 (key length) are the three items
// automatable by ACDI tools. CryptaMap collects all three.
type CISAMapper struct{}

func (m *CISAMapper) ID() string { return CISA }

func (m *CISAMapper) Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{}
	out = append(out, models.ComplianceMapping{
		Framework:   CISA,
		ControlID:   "M-23-02-ITEM-04",
		ControlName: "Algorithm identifier",
		Status:      "compliant",
		Remediation: "CryptaMap auto-collects algorithm identifier per asset.",
	})
	out = append(out, models.ComplianceMapping{
		Framework:   CISA,
		ControlID:   "M-23-02-ITEM-05",
		ControlName: "Service type",
		Status:      "compliant",
		Remediation: "Service category is recorded alongside each asset.",
	})
	out = append(out, models.ComplianceMapping{
		Framework:   CISA,
		ControlID:   "M-23-02-ITEM-06",
		ControlName: "Key length",
		Status:      "compliant",
		Remediation: "Key/parameter size is captured by the scanner.",
	})
	if posture == models.PostureNonPQCClassical || posture == models.PostureLegacyTLS {
		out = append(out, models.ComplianceMapping{
			Framework:    CISA,
			ControlID:    "M-23-02-MIGRATION",
			ControlName:  "Prioritized migration plan",
			Status:       "non-compliant",
			Remediation:  "Submit findings to agency CIO for prioritized PQC migration planning per M-23-02 § 4.",
			DeadlineDate: "2027-12-31",
		})
	}
	return out
}
