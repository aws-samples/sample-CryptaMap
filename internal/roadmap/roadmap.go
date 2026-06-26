// Package roadmap implements a pure, deterministic PQC migration roadmap ranker.
// It scores every Finding for migration priority (Mosca urgency x cryptographic
// posture x harvest-now-decrypt-later exposure, tie-broken by the verified
// upgrade-ease and primitive readiness from internal/pqc) and rolls the scored
// items up per-service and per-account.
//
// The package is intentionally dependency-light: it imports only stdlib,
// internal/pqc (the web-verified support matrix + primitive table), internal/
// taxonomy (friendly display names / AWS category), and pkg/models. It performs
// NO I/O and makes NO AWS SDK calls, so Build is fully unit-testable and free of
// any cyclic-import / SDK-pull-in risk. It deliberately does NOT import
// internal/scanner.
//
// Build accepts any models.ScanResult; in production it is typically the single
// merged envelope produced by internal/merge (merge.Result.Merged), so one call
// yields an org-wide ranked roadmap.
package roadmap

import (
	"sort"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// RoadmapItem is one ranked migration recommendation, one per Finding. It
// carries the verified AWS action (RecommendedAction = pqc.SupportEntry.
// HowToEnable) and citation (SourceURL) so the output is directly actionable and
// auditable.
type RoadmapItem struct {
	Rank              int                   `json:"rank"`
	PriorityScore     float64               `json:"priorityScore"`
	Service           string                `json:"service"` // raw scanner id
	DisplayName       string                `json:"displayName"`
	AWSCategory       string                `json:"awsCategory"`
	CryptoFunction    string                `json:"cryptoFunction"`
	AccountID         string                `json:"accountId"`
	Region            string                `json:"region"`
	ResourceID        string                `json:"resourceId"`
	ResourceARN       string                `json:"resourceArn,omitempty"`
	AssetBomRef       string                `json:"assetBomRef,omitempty"`
	Posture           models.CryptoPosture  `json:"posture"`
	Severity          models.Severity       `json:"severity"`
	Mosca             models.MoscaScore     `json:"mosca"`
	ExposureFlag      bool                  `json:"hndlExposed"` // Mosca.Score > 0
	PQCStatus         pqc.PQCStatus         `json:"pqcStatus"`
	SymmetricStrength pqc.SymmetricStrength `json:"symmetricStrength,omitempty"`
	UpgradeEase       pqc.UpgradeEase       `json:"upgradeEase"`
	RecommendedAction string                `json:"recommendedAction"` // pqc.SupportEntry.HowToEnable
	SourceURL         string                `json:"sourceUrl"`         // pqc.SupportEntry.SourceURL
	Confidence        pqc.Confidence        `json:"confidence"`
	AsOf              string                `json:"asOf"` // pqc.AsOf
	QuickWin          bool                  `json:"quickWin"`
}

// ServiceRollup aggregates ranked items by raw scanner Service id.
type ServiceRollup struct {
	Service     string        `json:"service"`
	DisplayName string        `json:"displayName"`
	Items       int           `json:"items"`
	MaxPriority float64       `json:"maxPriority"`
	SumPriority float64       `json:"sumPriority"`
	QuickWins   int           `json:"quickWins"`
	PQCStatus   pqc.PQCStatus `json:"pqcStatus"`
}

// AccountRollup aggregates ranked items by AccountID.
type AccountRollup struct {
	AccountID   string  `json:"accountId"`
	Items       int     `json:"items"`
	MaxPriority float64 `json:"maxPriority"`
	SumPriority float64 `json:"sumPriority"`
	Critical    int     `json:"critical"`
	High        int     `json:"high"`
}

// Roadmap is the full ranked roadmap: the descending-priority item list plus the
// per-service and per-account roll-ups.
type Roadmap struct {
	AsOf          string          `json:"asOf"`
	GeneratedFrom string          `json:"generatedFrom"` // merged AccountID (e.g. "org")
	Items         []RoadmapItem   `json:"items"`         // ranked descending
	ByService     []ServiceRollup `json:"byService"`
	ByAccount     []AccountRollup `json:"byAccount"`
}

// Build is the pure entrypoint: it produces one RoadmapItem per Finding, scores
// and ranks them, and builds the per-service and per-account roll-ups. scan is
// typically merge.Result.Merged but works on any ScanResult.
func Build(scan models.ScanResult) Roadmap {
	// Index assets by BomRef so each finding can pull its underlying primitive
	// for the primitive cross-check (sink rule). The mock + live paths both key
	// findings to assets via AssetBomRef.
	assetByRef := make(map[string]models.CryptoAsset, len(scan.Assets))
	for _, a := range scan.Assets {
		assetByRef[a.BomRef] = a
	}

	items := make([]RoadmapItem, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		sup, _ := pqc.PQCSupportFor(f.Service)
		tax := taxonomy.MustLookup(f.Service)

		asset, hasAsset := assetByRef[f.AssetBomRef]
		primitive := ""
		var strength pqc.SymmetricStrength
		if hasAsset {
			primitive = primitiveFor(asset)
			strength = pqc.SymmetricStrengthFor(asset.CryptoProps.AlgorithmProperties)
		}

		// Asset-aware pqcStatus: a quantum-resistant asset (symmetric AES-256,
		// pqc-hybrid/pqc-ready posture, or a positively non-vulnerable resolved
		// primitive) must never present the alarming "not-yet" badge. Promote it
		// to the no-action / quantum-resistant StatusNotApplicable. Only fires on a
		// positive quantum-resistant signal, so a bare unsized "AES" stays put.
		effStatus := pqc.EffectivePQCStatus(sup.PQCStatus, primitive, f.Posture)

		item := RoadmapItem{
			PriorityScore:     scoreItemWithPrimitive(f, sup, primitive),
			Service:           f.Service,
			DisplayName:       tax.DisplayName,
			AWSCategory:       tax.AWSCategory,
			CryptoFunction:    tax.CryptoFunction,
			AccountID:         f.AccountID,
			Region:            f.Region,
			ResourceID:        f.ResourceID,
			ResourceARN:       f.ResourceARN,
			AssetBomRef:       f.AssetBomRef,
			Posture:           f.Posture,
			Severity:          f.Severity,
			Mosca:             f.Mosca,
			ExposureFlag:      f.Mosca.Score > 0,
			PQCStatus:         effStatus,
			SymmetricStrength: strength,
			UpgradeEase:       sup.UpgradeEase,
			RecommendedAction: sup.HowToEnable,
			SourceURL:         sup.SourceURL,
			Confidence:        sup.Confidence,
			AsOf:              pqc.AsOf,
			QuickWin:          isQuickWinEffective(sup, effStatus),
		}
		items = append(items, item)
	}

	rm := Roadmap{
		AsOf:          pqc.AsOf,
		GeneratedFrom: scan.AccountID,
	}
	rm.Items = items
	rankAndRoll(&rm)
	return rm
}

// scoreItem computes the PriorityScore for one finding without a resolved
// primitive (the cross-check sink rule is skipped, i.e. the primitive is treated
// as unknown -> vulnerable -> no clamp). Exported-for-test shape per spec.
func scoreItem(f models.Finding, sup pqc.SupportEntry) float64 {
	return scoreItemWithPrimitive(f, sup, "")
}

// scoreItemWithPrimitive computes the PriorityScore for one finding, applying the
// primitive cross-check (sink rule) when a primitive name is supplied:
//
//	PriorityScore = MoscaUrgency * PostureMultiplier * ExposureMultiplier + EaseTieBreak
//
// When the underlying primitive is positively identified as NOT quantum
// vulnerable (AES-256, SHA-2, ML-KEM, ML-DSA, ...), PostureMultiplier is clamped
// to <= symmetricOnlyMultiplier so already-quantum-resistant material can never
// outrank a vulnerable RSA/ECDSA asset, even when the posture string is richer.
// An unknown/empty primitive is treated as vulnerable (no clamp), the
// conservative default.
func scoreItemWithPrimitive(f models.Finding, sup pqc.SupportEntry, primitive string) float64 {
	posture := postureMultiplier(f.Posture)
	if primitive != "" && !pqc.IsQuantumVulnerablePrimitive(primitive) {
		if posture > symmetricOnlyMultiplier {
			posture = symmetricOnlyMultiplier
		}
	}
	core := moscaUrgency(f.Mosca) * posture * exposureMultiplier(f.Mosca)
	return core + easeTieBreak(sup.UpgradeEase, sup.PQCStatus)
}

// moscaUrgency is the base urgency derived from Mosca.Score (X+Y-Z), floored at a
// small positive so the posture/exposure multipliers and the additive tie-break
// can still order zero/negative-score assets. Score 9 -> 10.0; Score 0 -> 1.0;
// Score -1 (or lower) -> 0.5 floor. Monotonic in Mosca.Score and never zero.
func moscaUrgency(m models.MoscaScore) float64 {
	v := float64(m.Score) + 1.0
	if v < 0.5 {
		return 0.5
	}
	return v
}

// Posture multiplier constants, aligned with risk.SeverityFromPosture ordering.
const (
	noEncryptionMultiplier    = 3.0  // no-encryption (CRITICAL)
	legacyTLSMultiplier       = 2.5  // legacy-tls (HIGH)
	nonPQCClassicalMultiplier = 2.0  // non-pqc-classical: the prime migration target
	unknownMultiplier         = 1.5  // unknown: risk.go treats as MEDIUM
	pqcHybridMultiplier       = 0.5  // pqc-hybrid: only authentication remains classical
	symmetricOnlyMultiplier   = 0.25 // symmetric-only: AES-256 at rest, quantum resistant
	pqcReadyMultiplier        = 0.1  // pqc-ready: pure PQC, already migrated
)

// postureMultiplier returns how cryptographically exposed an asset is, aligned
// with risk.SeverityFromPosture ordering. AES-256-at-rest (symmetric-only) and
// already-PQC postures get the lowest weights so they sink toward the bottom.
func postureMultiplier(p models.CryptoPosture) float64 {
	switch p {
	case models.PostureNoEncryption:
		return noEncryptionMultiplier
	case models.PostureLegacyTLS:
		return legacyTLSMultiplier
	case models.PostureNonPQCClassical:
		return nonPQCClassicalMultiplier
	case models.PosturePQCHybrid:
		return pqcHybridMultiplier
	case models.PostureSymmetricOnly:
		return symmetricOnlyMultiplier
	case models.PosturePQCReady:
		return pqcReadyMultiplier
	default: // PostureUnknown and any unmapped value
		return unknownMultiplier
	}
}

// exposureMultiplier is the harvest-now-decrypt-later amplifier keyed on Mosca
// exposure: a positive Mosca.Score means the asset outlives the CRQC horizon
// while still in service.
func exposureMultiplier(m models.MoscaScore) float64 {
	if m.Score > 0 {
		return 1.5
	}
	return 1.0
}

// Ease tie-break constants. These are additive and intentionally smaller than
// the smallest gap the multiplicative core can produce, so the tie-break only
// orders otherwise-equal items (quick-wins float up, dead-ends sink) and never
// reorders across genuinely different urgency tiers.
const (
	easeOneFlipBoost      = 0.40 // one-flip quick-win
	easeConfigChangeBoost = 0.30
	easeAWSManagedBoost   = 0.20
	easeAppChangeBoost    = 0.10
	easeNoneBoost         = 0.00
)

// easeTieBreak returns the additive tie-break term for an upgrade ease, gated by
// PQCStatus so the boost only rewards services that can actually move to PQC. A
// status of not-yet or not-applicable yields no boost regardless of ease.
func easeTieBreak(e pqc.UpgradeEase, status pqc.PQCStatus) float64 {
	if status == pqc.StatusNotYet || status == pqc.StatusNotApplicable || status == pqc.StatusNotEncrypted {
		return easeNoneBoost
	}
	switch e {
	case pqc.EaseOneFlip:
		return easeOneFlipBoost
	case pqc.EaseConfigChange:
		return easeConfigChangeBoost
	case pqc.EaseAWSManagedAuto:
		return easeAWSManagedBoost
	case pqc.EaseAppChange:
		return easeAppChangeBoost
	default: // EaseNoneAvailable
		return easeNoneBoost
	}
}

// isQuickWin reports whether the support entry is a one-flip change on a service
// that can actually move to PQC (status available or hybrid-tls-only).
func isQuickWin(sup pqc.SupportEntry) bool {
	if sup.UpgradeEase != pqc.EaseOneFlip {
		return false
	}
	return sup.PQCStatus == pqc.StatusAvailable || sup.PQCStatus == pqc.StatusHybridTLSOnly
}

// isQuickWinEffective is isQuickWin gated on the ASSET-AWARE effective status, so
// a quantum-resistant asset (whose effStatus was promoted to not-applicable) is never
// counted as a quick-win even when its SERVICE row is one-flip+available. Without
// this, a symmetric AES key on a one-flip service would inflate the quick-win KPI
// despite having nothing to migrate. The effective status must itself be
// available/hybrid (i.e. the asset is genuinely vulnerable AND actionable).
func isQuickWinEffective(sup pqc.SupportEntry, effStatus pqc.PQCStatus) bool {
	if effStatus != pqc.StatusAvailable && effStatus != pqc.StatusHybridTLSOnly {
		return false
	}
	return isQuickWin(sup)
}

// primitiveFor derives a single representative primitive label from a crypto
// asset for the ranker's sink-rule cross-check, preferring the algorithm name /
// parameter set, then the TLS key-exchange group, then the certificate
// signature algorithm. Returns "" when nothing is available (treated as
// vulnerable / no clamp by the caller).
func primitiveFor(a models.CryptoAsset) string {
	if ap := a.CryptoProps.AlgorithmProperties; ap != nil {
		if ap.AlgorithmName != "" {
			return ap.AlgorithmName
		}
		if ap.ParameterSetIdentifier != "" {
			return ap.ParameterSetIdentifier
		}
		if ap.KMSKeySpec != "" {
			return ap.KMSKeySpec
		}
		if ap.Curve != "" {
			return ap.Curve
		}
	}
	if pp := a.CryptoProps.ProtocolProperties; pp != nil {
		if pp.KeyExchangeGroup != "" {
			return pp.KeyExchangeGroup
		}
		if pp.CertSignatureAlgorithm != "" {
			return pp.CertSignatureAlgorithm
		}
	}
	return ""
}

// rankAndRoll sorts the items by (PriorityScore desc, EaseTieBreak desc,
// NormalizedSeverity desc, Service asc, ResourceID asc), assigns Rank 1..N, and
// builds the per-service and per-account roll-ups sorted by MaxPriority desc.
func rankAndRoll(rm *Roadmap) {
	items := rm.Items
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.PriorityScore != b.PriorityScore {
			return a.PriorityScore > b.PriorityScore
		}
		ta := easeTieBreak(a.UpgradeEase, a.PQCStatus)
		tb := easeTieBreak(b.UpgradeEase, b.PQCStatus)
		if ta != tb {
			return ta > tb
		}
		na := models.NormalizedSeverity(a.Severity)
		nb := models.NormalizedSeverity(b.Severity)
		if na != nb {
			return na > nb
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		return a.ResourceID < b.ResourceID
	})
	for i := range items {
		items[i].Rank = i + 1
	}

	rm.ByService = buildServiceRollups(items)
	rm.ByAccount = buildAccountRollups(items)
}

func buildServiceRollups(items []RoadmapItem) []ServiceRollup {
	byKey := make(map[string]*ServiceRollup)
	order := make([]string, 0)
	for _, it := range items {
		r, ok := byKey[it.Service]
		if !ok {
			r = &ServiceRollup{
				Service:     it.Service,
				DisplayName: it.DisplayName,
				PQCStatus:   it.PQCStatus,
				MaxPriority: it.PriorityScore,
			}
			byKey[it.Service] = r
			order = append(order, it.Service)
		}
		r.Items++
		r.SumPriority += it.PriorityScore
		if it.PriorityScore > r.MaxPriority {
			r.MaxPriority = it.PriorityScore
		}
		if it.QuickWin {
			r.QuickWins++
		}
	}
	out := make([]ServiceRollup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MaxPriority != out[j].MaxPriority {
			return out[i].MaxPriority > out[j].MaxPriority
		}
		return out[i].Service < out[j].Service
	})
	return out
}

func buildAccountRollups(items []RoadmapItem) []AccountRollup {
	byKey := make(map[string]*AccountRollup)
	order := make([]string, 0)
	for _, it := range items {
		r, ok := byKey[it.AccountID]
		if !ok {
			r = &AccountRollup{
				AccountID:   it.AccountID,
				MaxPriority: it.PriorityScore,
			}
			byKey[it.AccountID] = r
			order = append(order, it.AccountID)
		}
		r.Items++
		r.SumPriority += it.PriorityScore
		if it.PriorityScore > r.MaxPriority {
			r.MaxPriority = it.PriorityScore
		}
		switch it.Severity {
		case models.SeverityCritical:
			r.Critical++
		case models.SeverityHigh:
			r.High++
		}
	}
	out := make([]AccountRollup, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MaxPriority != out[j].MaxPriority {
			return out[i].MaxPriority > out[j].MaxPriority
		}
		return out[i].AccountID < out[j].AccountID
	})
	return out
}
