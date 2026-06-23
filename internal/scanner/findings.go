package scanner

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/risk"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// BuildFindings is the single, pure source of truth for turning discovered
// assets into Findings. It derives the cryptographic posture from
// asset.Properties["posture"] (defaulting to PostureUnknown / MEDIUM when
// absent, so it degrades gracefully), computes the Mosca urgency via
// risk.CalculateForService, takes the worse of the posture- and Mosca-derived
// severities, and attaches the compliance mappings.
//
// It is deliberately deterministic and dependency-light (stdlib + uuid +
// internal/risk + internal/compliance + pkg/models): it touches NOTHING that
// lives only in DynamoDB or AWS. That property is what lets the offline
// org-merge-files adapter regenerate the exact same findings a live scan would
// have produced, from CBOM-derived assets alone.
//
// comp may be nil (then no compliance mappings are attached). overrides is the
// per-service Mosca override map (nil for defaults).
func BuildFindings(assets []models.CryptoAsset, comp *compliance.Registry, overrides map[string]risk.MoscaParams) []models.Finding {
	now := time.Now().UTC()
	findings := make([]models.Finding, 0, len(assets))
	for _, a := range assets {
		posture := models.PostureUnknown
		if a.Properties != nil {
			if p, ok := a.Properties["posture"]; ok {
				posture = models.CryptoPosture(p)
			}
		}
		// Determine severity. For genuinely vulnerable/at-risk postures take the
		// worse of posture-derived and Mosca-derived (HNDL urgency rightly
		// applies). But when the posture is already quantum-SAFE
		// (symmetric-only / pqc-hybrid / pqc-ready), the Mosca/HNDL urgency is
		// irrelevant — the cryptography is quantum-resistant regardless of data
		// shelf-life — so the severity is the posture severity (INFORMATIONAL)
		// only, and we do NOT let the posture-blind Mosca score raise it.
		moscaScore := risk.CalculateForService(a.Service, overrides)
		sev := risk.SeverityFromPosture(posture)
		if !risk.IsQuantumSafePosture(posture) {
			sev = risk.HighestSeverity(sev, risk.SeverityFromMosca(moscaScore.Score))
		}
		complianceMaps := []models.ComplianceMapping{}
		if comp != nil {
			complianceMaps = comp.MapAll(a, posture)
		}
		findings = append(findings, models.Finding{
			ID:             uuid.NewString(),
			Title:          fmt.Sprintf("%s — %s posture for %s", a.Service, posture, a.ResourceID),
			Description:    fmt.Sprintf("CryptaMap detected posture=%s for %s resource %s in region %s.", posture, a.ResourceType, a.ResourceID, a.Region),
			Severity:       sev,
			Posture:        posture,
			AccountID:      a.AccountID,
			Region:         a.Region,
			Service:        a.Service,
			ResourceID:     a.ResourceID,
			ResourceARN:    a.ResourceARN,
			ResourceType:   a.ResourceType,
			AssetBomRef:    a.BomRef,
			Mosca:          moscaScore,
			Compliance:     complianceMaps,
			Recommendation: recommendation(posture, a.Service),
			DocsURL:        docsURL(a.Service),
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	return findings
}
