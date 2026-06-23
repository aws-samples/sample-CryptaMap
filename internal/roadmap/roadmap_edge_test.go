package roadmap

import (
	"testing"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestActionableFirstOrdering proves the roadmap's headline promise: across a
// realistic mixed inventory, every actionable migration target (a finding on a
// service that can move to PQC and is genuinely exposed) ranks ABOVE every
// non-actionable item (already-resistant AES-256 at rest, already-PQC material).
// This is the "do these first" guarantee the report leads with.
func TestActionableFirstOrdering(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "org",
		Assets: []models.CryptoAsset{
			// Actionable, exposed targets.
			asset("a-alb", "alb", "ECDHE", "secp256r1"),         // hybrid-tls-only, one-flip
			asset("a-rds", "rds_transit", "ECDHE", "secp256r1"), // transit, non-pqc-classical
			asset("a-kms", "kms_spec", "RSA-2048", ""),          // available, config-change
			// Non-actionable: already resistant / already migrated.
			asset("n-ebs", "ebs", "AES-256-GCM", ""),  // symmetric-only AES
			asset("n-pca", "acmpca", "ML-DSA-87", ""), // already PQC
		},
		Findings: []models.Finding{
			finding("f-alb", "alb", "a-alb", models.PostureNonPQCClassical, models.SeverityHigh, 6, "111"),
			finding("f-rds", "rds_transit", "a-rds", models.PostureNonPQCClassical, models.SeverityHigh, 7, "111"),
			finding("f-kms", "kms_spec", "a-kms", models.PostureNonPQCClassical, models.SeverityMedium, 5, "222"),
			// Non-actionable findings still carry a (low) Mosca but resistant primitives.
			finding("f-ebs", "ebs", "n-ebs", models.PostureSymmetricOnly, models.SeverityInformational, 4, "111"),
			finding("f-pca", "acmpca", "n-pca", models.PosturePQCReady, models.SeverityInformational, 0, "222"),
		},
	}

	rm := Build(scan)
	if len(rm.Items) != 5 {
		t.Fatalf("expected 5 items, got %d", len(rm.Items))
	}

	byRes := map[string]RoadmapItem{}
	for _, it := range rm.Items {
		byRes[it.ResourceID] = it
	}
	actionable := []string{"a-alb-res", "a-rds-res", "a-kms-res"}
	nonActionable := []string{"n-ebs-res", "n-pca-res"}

	worstActionableRank := 0
	for _, id := range actionable {
		if byRes[id].Rank > worstActionableRank {
			worstActionableRank = byRes[id].Rank
		}
	}
	bestNonActionableRank := len(rm.Items) + 1
	for _, id := range nonActionable {
		if byRes[id].Rank < bestNonActionableRank {
			bestNonActionableRank = byRes[id].Rank
		}
	}
	if worstActionableRank >= bestNonActionableRank {
		t.Errorf("an actionable target ranked at/below a non-actionable item: worst actionable rank=%d, best non-actionable rank=%d",
			worstActionableRank, bestNonActionableRank)
		for _, it := range rm.Items {
			t.Logf("rank %d  score %.3f  %s  posture=%s", it.Rank, it.PriorityScore, it.ResourceID, it.Posture)
		}
	}

	// Ranks are contiguous 1..N.
	for i, it := range rm.Items {
		if it.Rank != i+1 {
			t.Errorf("ranks not contiguous: index %d has Rank %d", i, it.Rank)
		}
	}
}

// TestDeterministicTieOrdering proves the full deterministic comparator: when
// PriorityScore AND ease tie-break AND severity are all equal, ordering falls to
// Service asc then ResourceID asc — so the roadmap is byte-stable across runs.
func TestDeterministicTieOrdering(t *testing.T) {
	// Two findings on the SAME service, same posture/Mosca/severity, distinct
	// ResourceIDs: ResourceID asc must decide.
	scan := models.ScanResult{
		AccountID: "org",
		Assets: []models.CryptoAsset{
			asset("crypto-zeta", "alb", "ECDHE", "secp256r1"),
			asset("crypto-alpha", "alb", "ECDHE", "secp256r1"),
		},
		Findings: []models.Finding{
			finding("f-z", "alb", "crypto-zeta", models.PostureNonPQCClassical, models.SeverityHigh, 6, "111"),
			finding("f-a", "alb", "crypto-alpha", models.PostureNonPQCClassical, models.SeverityHigh, 6, "111"),
		},
	}
	rm := Build(scan)
	if len(rm.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(rm.Items))
	}
	// crypto-alpha-res < crypto-zeta-res lexicographically -> alpha first.
	if rm.Items[0].ResourceID != "crypto-alpha-res" {
		t.Errorf("on a full tie, ResourceID asc must order: got first=%q, want crypto-alpha-res", rm.Items[0].ResourceID)
	}

	// Stability: re-running Build on the same input yields the identical order.
	rm2 := Build(scan)
	for i := range rm.Items {
		if rm.Items[i].ResourceID != rm2.Items[i].ResourceID {
			t.Errorf("Build is not deterministic at index %d: %q vs %q", i, rm.Items[i].ResourceID, rm2.Items[i].ResourceID)
		}
	}
}

// TestEaseTieBreakGatedByStatus proves the ease boost is gated by PQCStatus:
// a one-flip ease on a not-yet/not-applicable service yields NO boost, so it
// cannot float a non-actionable service above an equal peer.
func TestEaseTieBreakGatedByStatus(t *testing.T) {
	cases := []struct {
		ease   pqc.UpgradeEase
		status pqc.PQCStatus
		want   float64
	}{
		{pqc.EaseOneFlip, pqc.StatusAvailable, easeOneFlipBoost},
		{pqc.EaseOneFlip, pqc.StatusHybridTLSOnly, easeOneFlipBoost},
		{pqc.EaseOneFlip, pqc.StatusNotYet, easeNoneBoost},            // gated off
		{pqc.EaseOneFlip, pqc.StatusNotApplicable, easeNoneBoost},     // gated off
		{pqc.EaseOneFlip, pqc.StatusNotEncrypted, easeNoneBoost},      // gated off: unencrypted is data-hygiene, not a PQC quick win
		{pqc.EaseConfigChange, pqc.StatusNotEncrypted, easeNoneBoost}, // gated off
		{pqc.EaseConfigChange, pqc.StatusAvailable, easeConfigChangeBoost},
		{pqc.EaseAWSManagedAuto, pqc.StatusHybridTLSOnly, easeAWSManagedBoost},
		{pqc.EaseAppChange, pqc.StatusAvailable, easeAppChangeBoost},
		{pqc.EaseNoneAvailable, pqc.StatusAvailable, easeNoneBoost},
	}
	for _, c := range cases {
		got := easeTieBreak(c.ease, c.status)
		if got != c.want {
			t.Errorf("easeTieBreak(%s, %s) = %.2f, want %.2f", c.ease, c.status, got, c.want)
		}
	}

	// The largest boost (one-flip 0.40) must stay below the smallest gap the
	// multiplicative core can produce between adjacent postures at equal Mosca,
	// so the tie-break never jumps an urgency tier. At Mosca 0 (urgency 1.0,
	// exposure 1.0): pqc-hybrid core = 0.5, symmetric-only core = 0.25 -> gap
	// 0.25 < 0.40 is intentionally allowed within the bottom tier, but the
	// non-pqc-classical(2.0) vs pqc-hybrid(0.5) gap = 1.5 must dominate.
	coreGapTopTier := postureMultiplier(models.PostureNonPQCClassical) - postureMultiplier(models.PosturePQCHybrid)
	if easeOneFlipBoost >= coreGapTopTier {
		t.Errorf("one-flip boost %.2f must stay below the non-pqc-classical→pqc-hybrid core gap %.2f", easeOneFlipBoost, coreGapTopTier)
	}
}

// TestByServiceRollupAggregates proves ByService sums Items/SumPriority, tracks
// MaxPriority and QuickWins, copies the taxonomy DisplayName + PQCStatus, and is
// sorted by MaxPriority desc with a stable Service-asc tiebreak.
func TestByServiceRollupAggregates(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "org",
		Assets: []models.CryptoAsset{
			asset("c-alb1", "alb", "ECDHE", "secp256r1"),
			asset("c-alb2", "alb", "ECDHE", "secp256r1"),
			asset("c-kms", "kms_spec", "RSA-2048", ""),
			asset("c-ebs", "ebs", "AES-256-GCM", ""),
		},
		Findings: []models.Finding{
			finding("f-alb1", "alb", "c-alb1", models.PostureNonPQCClassical, models.SeverityHigh, 6, "111"),
			finding("f-alb2", "alb", "c-alb2", models.PostureNonPQCClassical, models.SeverityMedium, 4, "111"),
			finding("f-kms", "kms_spec", "c-kms", models.PostureNonPQCClassical, models.SeverityHigh, 7, "111"),
			finding("f-ebs", "ebs", "c-ebs", models.PostureSymmetricOnly, models.SeverityInformational, 0, "111"),
		},
	}
	rm := Build(scan)

	get := func(svc string) *ServiceRollup {
		for i := range rm.ByService {
			if rm.ByService[i].Service == svc {
				return &rm.ByService[i]
			}
		}
		return nil
	}

	alb := get("alb")
	if alb == nil {
		t.Fatalf("alb rollup missing")
	}
	if alb.Items != 2 {
		t.Errorf("alb Items = %d, want 2", alb.Items)
	}
	if alb.QuickWins != 2 {
		t.Errorf("alb QuickWins = %d, want 2 (both one-flip hybrid-tls-only)", alb.QuickWins)
	}
	// SumPriority must equal the sum of the two alb item scores; MaxPriority the larger.
	var albItemScores []float64
	for _, it := range rm.Items {
		if it.Service == "alb" {
			albItemScores = append(albItemScores, it.PriorityScore)
		}
	}
	if len(albItemScores) != 2 {
		t.Fatalf("expected 2 alb items, got %d", len(albItemScores))
	}
	wantSum := albItemScores[0] + albItemScores[1]
	if !floatEq(alb.SumPriority, wantSum) {
		t.Errorf("alb SumPriority = %.4f, want %.4f", alb.SumPriority, wantSum)
	}
	wantMax := albItemScores[0]
	if albItemScores[1] > wantMax {
		wantMax = albItemScores[1]
	}
	if !floatEq(alb.MaxPriority, wantMax) {
		t.Errorf("alb MaxPriority = %.4f, want %.4f", alb.MaxPriority, wantMax)
	}
	if alb.PQCStatus != pqc.StatusHybridTLSOnly {
		t.Errorf("alb PQCStatus = %q, want hybrid-tls-only", alb.PQCStatus)
	}

	ebs := get("ebs")
	if ebs == nil || ebs.QuickWins != 0 {
		t.Errorf("ebs rollup should have 0 quick wins (not-applicable AES)")
	}

	// Sorted by MaxPriority desc, Service asc on ties.
	for i := 1; i < len(rm.ByService); i++ {
		prev, cur := rm.ByService[i-1], rm.ByService[i]
		if prev.MaxPriority < cur.MaxPriority {
			t.Errorf("ByService not sorted by MaxPriority desc at %d", i)
		}
		if floatEq(prev.MaxPriority, cur.MaxPriority) && prev.Service > cur.Service {
			t.Errorf("ByService tie not broken by Service asc at %d (%q before %q)", i, prev.Service, cur.Service)
		}
	}
}

// TestByAccountRollupSplits proves ByAccount splits items by AccountID, counts
// Critical/High per account, tracks Max/Sum priority, and is sorted by
// MaxPriority desc with an AccountID-asc tiebreak. It also proves an item with
// an empty AccountID still forms its own rollup bucket (no silent drop).
func TestByAccountRollupSplits(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "org",
		Assets: []models.CryptoAsset{
			asset("c-1a", "rds_transit", "ECDHE", "secp256r1"),
			asset("c-1b", "alb", "ECDHE", "secp256r1"),
			asset("c-2a", "kms_spec", "RSA-2048", ""),
			asset("c-blank", "acm", "RSA-2048", ""),
		},
		Findings: []models.Finding{
			finding("f-1a", "rds_transit", "c-1a", models.PostureNoEncryption, models.SeverityCritical, 9, "111"),
			finding("f-1b", "alb", "c-1b", models.PostureNonPQCClassical, models.SeverityHigh, 6, "111"),
			finding("f-2a", "kms_spec", "c-2a", models.PostureNonPQCClassical, models.SeverityCritical, 8, "222"),
			finding("f-blank", "acm", "c-blank", models.PostureNonPQCClassical, models.SeverityMedium, 3, ""),
		},
	}
	rm := Build(scan)

	acct := map[string]AccountRollup{}
	for _, a := range rm.ByAccount {
		acct[a.AccountID] = a
	}

	if acct["111"].Items != 2 {
		t.Errorf("account 111 Items = %d, want 2", acct["111"].Items)
	}
	if acct["111"].Critical != 1 || acct["111"].High != 1 {
		t.Errorf("account 111 Critical/High = %d/%d, want 1/1", acct["111"].Critical, acct["111"].High)
	}
	if acct["222"].Items != 1 || acct["222"].Critical != 1 {
		t.Errorf("account 222 Items/Critical = %d/%d, want 1/1", acct["222"].Items, acct["222"].Critical)
	}
	// Empty AccountID still forms a bucket (no silent drop).
	if _, ok := acct[""]; !ok {
		t.Errorf("an item with empty AccountID must still form its own rollup bucket")
	}
	if acct[""].Items != 1 {
		t.Errorf("empty-account rollup Items = %d, want 1", acct[""].Items)
	}

	// Total items across rollups equals total findings.
	total := 0
	for _, a := range rm.ByAccount {
		total += a.Items
	}
	if total != len(scan.Findings) {
		t.Errorf("sum of ByAccount Items = %d, want %d (no finding dropped)", total, len(scan.Findings))
	}

	// Sorted by MaxPriority desc, AccountID asc on ties.
	for i := 1; i < len(rm.ByAccount); i++ {
		prev, cur := rm.ByAccount[i-1], rm.ByAccount[i]
		if prev.MaxPriority < cur.MaxPriority {
			t.Errorf("ByAccount not sorted by MaxPriority desc at %d", i)
		}
		if floatEq(prev.MaxPriority, cur.MaxPriority) && prev.AccountID > cur.AccountID {
			t.Errorf("ByAccount tie not broken by AccountID asc at %d", i)
		}
	}
}

// TestUnknownServiceConservative proves a finding on a service NOT in the PQC
// matrix scores conservatively: PQCStatus=not-yet, no ease boost, QuickWin=false,
// and it still appears in the roadmap (never panics, never dropped).
func TestUnknownServiceConservative(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "org",
		Assets: []models.CryptoAsset{
			asset("c-unknown", "totally_made_up_service", "RSA-2048", ""),
		},
		Findings: []models.Finding{
			finding("f-unknown", "totally_made_up_service", "c-unknown", models.PostureNonPQCClassical, models.SeverityHigh, 6, "111"),
		},
	}
	rm := Build(scan)
	if len(rm.Items) != 1 {
		t.Fatalf("unknown-service finding must still appear, got %d items", len(rm.Items))
	}
	it := rm.Items[0]
	if it.PQCStatus != pqc.StatusNotYet {
		t.Errorf("unknown service PQCStatus = %q, want not-yet (conservative fallback)", it.PQCStatus)
	}
	if it.QuickWin {
		t.Errorf("unknown service must not be a QuickWin")
	}
	if it.UpgradeEase != pqc.EaseNoneAvailable {
		t.Errorf("unknown service UpgradeEase = %q, want none-available", it.UpgradeEase)
	}
	// Tie-break term must be zero (none-available + not-yet are both gated).
	if easeTieBreak(it.UpgradeEase, it.PQCStatus) != easeNoneBoost {
		t.Errorf("unknown service must contribute zero ease tie-break")
	}
}

// TestPrimitiveForResolutionOrder proves primitiveFor's preference order:
// AlgorithmName > ParameterSetIdentifier > KMSKeySpec > Curve > KeyExchangeGroup
// > CertSignatureAlgorithm, returning "" when nothing is present.
func TestPrimitiveForResolutionOrder(t *testing.T) {
	mk := func(ap *models.AlgorithmProperties, pp *models.ProtocolProperties) models.CryptoAsset {
		return models.CryptoAsset{CryptoProps: models.CryptoProperties{AlgorithmProperties: ap, ProtocolProperties: pp}}
	}

	if got := primitiveFor(mk(&models.AlgorithmProperties{AlgorithmName: "ML-DSA-87", ParameterSetIdentifier: "x"}, nil)); got != "ML-DSA-87" {
		t.Errorf("AlgorithmName should win: got %q", got)
	}
	if got := primitiveFor(mk(&models.AlgorithmProperties{ParameterSetIdentifier: "ML-KEM-768", KMSKeySpec: "RSA_2048"}, nil)); got != "ML-KEM-768" {
		t.Errorf("ParameterSetIdentifier should win over KMSKeySpec: got %q", got)
	}
	if got := primitiveFor(mk(&models.AlgorithmProperties{KMSKeySpec: "ECC_NIST_P256", Curve: "x"}, nil)); got != "ECC_NIST_P256" {
		t.Errorf("KMSKeySpec should win over Curve: got %q", got)
	}
	if got := primitiveFor(mk(&models.AlgorithmProperties{Curve: "secp256r1"}, nil)); got != "secp256r1" {
		t.Errorf("Curve should resolve: got %q", got)
	}
	// Fall through to protocol properties when algorithm props are empty.
	if got := primitiveFor(mk(nil, &models.ProtocolProperties{KeyExchangeGroup: "X25519MLKEM768"})); got != "X25519MLKEM768" {
		t.Errorf("KeyExchangeGroup should resolve when no algorithm props: got %q", got)
	}
	if got := primitiveFor(mk(nil, &models.ProtocolProperties{CertSignatureAlgorithm: "sha256WithRSAEncryption"})); got != "sha256WithRSAEncryption" {
		t.Errorf("CertSignatureAlgorithm should resolve last: got %q", got)
	}
	if got := primitiveFor(mk(nil, nil)); got != "" {
		t.Errorf("empty asset should yield empty primitive, got %q", got)
	}
}

// floatEq compares floats with a small epsilon for rollup-sum assertions.
func floatEq(a, b float64) bool {
	const eps = 1e-9
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < eps
}
