package scanner

import (
	"fmt"
	"hash/fnv"
	"time"

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
// It is deliberately deterministic and dependency-light (stdlib +
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
		// At-rest INVENTORY-ONLY (B3): quantum-resistant-at-rest (symmetric AES-256,
		// PostureSymmetricOnly) is NOT a PQC-migration item. It is Grover-only
		// (not Shor-vulnerable), so it must stay in the CBOM as a line item for
		// inventory completeness but must NEVER be emitted as a Finding or feed the
		// headline/severity buckets. We skip it from the finding stream here; the
		// count of these inventory-only assets is reconciled separately in
		// buildSummary (InventoryOnly) so the removed assets do not vanish silently.
		if posture == models.PostureSymmetricOnly {
			continue
		}
		// Determine severity. The Mosca/HNDL urgency floor (a posture-blind,
		// per-service constant) is applied ONLY to postures whose Shor-vulnerable
		// classical crypto the scanner actually OBSERVED — NoEncryption, LegacyTLS,
		// NonPQCClassical — where a definite HNDL-urgency escalation is justified by
		// real evidence. It is NOT applied when:
		//   - the posture is already quantum-resistant (pqc-hybrid / pqc-ready /
		//     symmetric-only): the crypto is quantum-resistant regardless of data shelf-life; or
		//   - the posture is UNKNOWN (unreadable / API-error path) OR any other
		//     non-vulnerable/non-canonical value (empty or a crafted posture from an
		//     ingested CBOM): the scanner has NOT proven a vulnerable asset exists,
		//     so raising it to a definite CRITICAL from a hardcoded score (e.g.
		//     rds=9) would fabricate an urgency verdict the data cannot support. Such
		//     postures keep their SeverityFromPosture floor (Unknown -> MEDIUM "needs
		//     investigation"); the Mosca score is still recorded on the finding for
		//     transparency but is never used to escalate. This is the inverse of the
		//     fabricated-all-clear class — do not fabricate alarm from a posture we
		//     could not read. risk.IsMoscaEscalatable is an ALLOWLIST of exactly the
		//     three observed-vulnerable postures, so unrecognized values fail closed.
		moscaScore := risk.CalculateForService(a.Service, overrides)
		sev := risk.SeverityFromPosture(posture)
		if risk.IsMoscaEscalatable(posture) {
			sev = risk.HighestSeverity(sev, risk.SeverityFromMosca(moscaScore.Score))
		}
		complianceMaps := []models.ComplianceMapping{}
		if comp != nil {
			complianceMaps = comp.MapAll(a, posture)
		}
		findings = append(findings, models.Finding{
			ID:             stableFindingID(a, posture),
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

// stableFindingID derives a deterministic, run-independent Finding.ID from the
// asset's stable identity plus its posture, so regulator-facing finding
// artifacts diff cleanly across scan runs (the previous uuid.NewString() minted
// a fresh id every run, making every re-scan look like a wholesale change).
//
// It reuses the same discriminator the ASFF exporter uses (see
// output.asffStableFindingKey): the preferred key is the asset's BomRef, which
// is itself deterministic (BomRefForARN = FNV-64a of the resource ARN, the same
// key org-wide dedup uses) and unique per discovered asset. When BomRef is
// absent (e.g. hand-built or CBOM-ingested assets that predate bomRef
// assignment) it falls back to an FNV-64a hash of the stable identity fields
// (account|region|service|resourceID), so the id is still reproducible
// run-over-run. Posture IS part of the id here (unlike the Security Hub key):
// this id identifies a specific finding record, and a posture change on the same
// asset is a materially different finding for diff purposes.
func stableFindingID(a models.CryptoAsset, posture models.CryptoPosture) string {
	key := a.BomRef
	if key == "" {
		h := fnv.New64a()
		_, _ = h.Write([]byte(a.AccountID + "|" + a.Region + "|" + a.Service + "|" + a.ResourceID))
		key = fmt.Sprintf("%016x", h.Sum64())
	}
	return fmt.Sprintf("finding:%s:%s", key, posture)
}
