package roadmap

import (
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// mosca builds a MoscaScore with the given final Score (the ranker only reads
// .Score; X/Y/Z are illustrative).
func mosca(score int) models.MoscaScore {
	return models.MoscaScore{X: score, Y: 0, Z: 0, Score: score}
}

// asset builds a minimal CryptoAsset carrying a primitive via AlgorithmName, so
// the ranker's sink-rule cross-check has material to resolve.
func asset(bomRef, service, algName, kexGroup string) models.CryptoAsset {
	ap := &models.AlgorithmProperties{}
	pp := &models.ProtocolProperties{}
	if algName != "" {
		ap.AlgorithmName = algName
	}
	if kexGroup != "" {
		pp.KeyExchangeGroup = kexGroup
	}
	return models.CryptoAsset{
		BomRef:       bomRef,
		Service:      service,
		ResourceID:   bomRef + "-res",
		DiscoveredAt: time.Now(),
		CryptoProps: models.CryptoProperties{
			AlgorithmProperties: ap,
			ProtocolProperties:  pp,
		},
	}
}

// finding builds a Finding tied to a bomRef.
func finding(id, service, bomRef string, posture models.CryptoPosture, sev models.Severity, score int, account string) models.Finding {
	return models.Finding{
		ID:          id,
		Service:     service,
		AssetBomRef: bomRef,
		ResourceID:  bomRef + "-res",
		Posture:     posture,
		Severity:    sev,
		Mosca:       mosca(score),
		AccountID:   account,
	}
}

// TestScoreOrdering proves the headline requirement: a non-PQC internet-facing
// high-Mosca asset (RDS-transit, posture non-pqc-classical) outranks both a
// symmetric-only AES-256-at-rest asset (EBS) and an already-hybrid CloudFront
// asset.
func TestScoreOrdering(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "111111111111",
		Assets: []models.CryptoAsset{
			asset("crypto-rds", "rds_transit", "ECDHE", "secp256r1"),
			asset("crypto-ebs", "ebs", "AES-256-GCM", ""),
			asset("crypto-cf", "cloudfront", "", "X25519MLKEM768"),
		},
		Findings: []models.Finding{
			finding("f-rds", "rds_transit", "crypto-rds", models.PostureNonPQCClassical, models.SeverityMedium, 8, "111111111111"),
			finding("f-ebs", "ebs", "crypto-ebs", models.PostureSymmetricOnly, models.SeverityInformational, 5, "111111111111"),
			finding("f-cf", "cloudfront", "crypto-cf", models.PosturePQCHybrid, models.SeverityInformational, 5, "111111111111"),
		},
	}

	rm := Build(scan)
	if len(rm.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(rm.Items))
	}

	rankOf := func(id string) RoadmapItem {
		for _, it := range rm.Items {
			if it.ResourceID == id+"-res" {
				return it
			}
		}
		t.Fatalf("item %s not found", id)
		return RoadmapItem{}
	}
	rds := rankOf("crypto-rds")
	ebs := rankOf("crypto-ebs")
	cf := rankOf("crypto-cf")

	if !(rds.Rank < ebs.Rank) {
		t.Errorf("non-PQC HNDL-exposed RDS (rank %d, score %.3f) must outrank symmetric-only EBS (rank %d, score %.3f)",
			rds.Rank, rds.PriorityScore, ebs.Rank, ebs.PriorityScore)
	}
	if !(rds.Rank < cf.Rank) {
		t.Errorf("non-PQC HNDL-exposed RDS (rank %d, score %.3f) must outrank pqc-hybrid CloudFront (rank %d, score %.3f)",
			rds.Rank, rds.PriorityScore, cf.Rank, cf.PriorityScore)
	}
	if rds.Rank != 1 {
		t.Errorf("RDS should be rank 1, got %d", rds.Rank)
	}
	// Sanity: ranks are contiguous 1..N.
	for i, it := range rm.Items {
		if it.Rank != i+1 {
			t.Errorf("ranks not contiguous: item %d has Rank %d", i, it.Rank)
		}
	}
}

// TestQuickWinFloatUp proves that among items with equal Mosca + posture, a
// one-flip quick-win service (alb) ranks above a none-available peer
// (apigw_http). Both are data-in-transit non-pqc-classical, same Mosca, so only
// the additive ease tie-break differentiates them. (apigw_rest is no longer a
// valid none-available example since it gained PQ-enhanced TLS policies.)
func TestQuickWinFloatUp(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "acct",
		Assets: []models.CryptoAsset{
			asset("crypto-alb", "alb", "ECDHE", "secp256r1"),
			asset("crypto-api", "apigw_http", "ECDHE", "secp256r1"),
		},
		Findings: []models.Finding{
			finding("f-alb", "alb", "crypto-alb", models.PostureNonPQCClassical, models.SeverityMedium, 6, "acct"),
			finding("f-api", "apigw_http", "crypto-api", models.PostureNonPQCClassical, models.SeverityMedium, 6, "acct"),
		},
	}
	rm := Build(scan)

	var alb, api RoadmapItem
	for _, it := range rm.Items {
		switch it.Service {
		case "alb":
			alb = it
		case "apigw_http":
			api = it
		}
	}
	if !alb.QuickWin {
		t.Errorf("alb (one-flip, hybrid-tls-only) should be QuickWin=true")
	}
	if api.QuickWin {
		t.Errorf("apigw_http (none-available) should be QuickWin=false")
	}
	if !(alb.Rank < api.Rank) {
		t.Errorf("alb quick-win (rank %d, score %.3f) must float above apigw_http (rank %d, score %.3f)",
			alb.Rank, alb.PriorityScore, api.Rank, api.PriorityScore)
	}
	// But the tie-break must NOT overpower the multiplicative core: a higher-
	// posture none-available asset must still beat the alb quick-win.
	if alb.PriorityScore-api.PriorityScore >= 1.0 {
		t.Errorf("ease tie-break (%.3f gap) leaked beyond the multiplicative core", alb.PriorityScore-api.PriorityScore)
	}
}

// TestAESAndPQCSink proves AES-256 (symmetric-only) and already-PQC (pqc-ready)
// items get the lowest multipliers and sink to the bottom, and that
// ExposureFlag is false when Mosca <= 0. It also proves that a HIGH-Mosca AES
// asset can never outrank a vulnerable RSA asset thanks to the posture weights
// and the primitive cross-check clamp.
func TestAESAndPQCSink(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "acct",
		Assets: []models.CryptoAsset{
			asset("crypto-rsa", "acm", "RSA-2048", ""),
			// AES asset with an artificially HIGH Mosca to prove the clamp.
			asset("crypto-aes", "ebs", "AES-256-GCM", ""),
			asset("crypto-pqc", "acmpca", "ML-DSA-87", ""),
		},
		Findings: []models.Finding{
			finding("f-rsa", "acm", "crypto-rsa", models.PostureNonPQCClassical, models.SeverityMedium, 4, "acct"),
			// Even with Mosca 0 (ExposureFlag false), keep it symmetric-only.
			finding("f-aes", "ebs", "crypto-aes", models.PostureSymmetricOnly, models.SeverityInformational, 0, "acct"),
			finding("f-pqc", "acmpca", "crypto-pqc", models.PosturePQCReady, models.SeverityInformational, 0, "acct"),
		},
	}
	rm := Build(scan)

	byService := map[string]RoadmapItem{}
	for _, it := range rm.Items {
		byService[it.Service] = it
	}
	rsa := byService["acm"]
	aes := byService["ebs"]
	pqcReady := byService["acmpca"]

	if rsa.Rank != 1 {
		t.Errorf("vulnerable RSA must be rank 1, got %d (score %.3f)", rsa.Rank, rsa.PriorityScore)
	}
	if !(rsa.Rank < aes.Rank && rsa.Rank < pqcReady.Rank) {
		t.Errorf("RSA (rank %d) must outrank AES (rank %d) and PQC-ready (rank %d)", rsa.Rank, aes.Rank, pqcReady.Rank)
	}
	if aes.ExposureFlag {
		t.Errorf("AES finding with Mosca 0 must have ExposureFlag=false")
	}
	if pqcReady.ExposureFlag {
		t.Errorf("PQC-ready finding with Mosca 0 must have ExposureFlag=false")
	}
	// Both the AES and PQC-ready items must rank at/near the bottom (below the
	// vulnerable RSA asset). With three findings they occupy the bottom two ranks.
	if aes.Rank == 1 || pqcReady.Rank == 1 {
		t.Errorf("symmetric-only/pqc-ready must never be rank 1 (AES rank %d, PQC rank %d)", aes.Rank, pqcReady.Rank)
	}
	// The multiplicative core (urgency*posture*exposure) for pqc-ready (0.1) must
	// be strictly below symmetric-only (0.25) at equal Mosca/exposure — the
	// additive ease tie-break can still lift an actionable PQC-ready service
	// within the bottom tier, which is acceptable.
	coreAES := moscaUrgency(aes.Mosca) * postureMultiplier(models.PostureSymmetricOnly) * exposureMultiplier(aes.Mosca)
	corePQC := moscaUrgency(pqcReady.Mosca) * postureMultiplier(models.PosturePQCReady) * exposureMultiplier(pqcReady.Mosca)
	if !(corePQC < coreAES) {
		t.Errorf("pqc-ready core (%.3f) should sit below symmetric-only core (%.3f)", corePQC, coreAES)
	}
}

// TestAESClampBeatsRichPosture proves the primitive cross-check: even if a
// symmetric (AES-256) asset were mislabeled with a rich posture string, the
// sink-rule clamp keeps it from outranking a genuinely vulnerable asset.
func TestAESClampBeatsRichPosture(t *testing.T) {
	f := finding("f-mislabel", "ebs", "crypto-aes", models.PostureNoEncryption, models.SeverityCritical, 9, "acct")
	sup, _ := pqc.PQCSupportFor("ebs")

	// Without primitive context, scoreItem honors the (mislabeled) rich posture.
	rich := scoreItem(f, sup)
	// With the AES-256 primitive, the clamp drops posture to <= symmetric-only.
	clamped := scoreItemWithPrimitive(f, sup, "AES-256-GCM")
	if !(clamped < rich) {
		t.Errorf("AES-256 primitive clamp should lower score: clamped=%.3f rich=%.3f", clamped, rich)
	}
	// Clamped AES (posture 0.25) must lose to a real non-pqc-classical RSA asset
	// at equal Mosca.
	rsaFinding := finding("f-rsa", "acm", "crypto-rsa", models.PostureNonPQCClassical, models.SeverityMedium, 9, "acct")
	rsaSup, _ := pqc.PQCSupportFor("acm")
	rsaScore := scoreItemWithPrimitive(rsaFinding, rsaSup, "RSA-2048")
	if !(rsaScore > clamped) {
		t.Errorf("vulnerable RSA (%.3f) must outrank clamped AES (%.3f)", rsaScore, clamped)
	}
}

// TestRollups proves ByService aggregates counts/maxPriority/quickWins and
// ByAccount splits by AccountID with Critical/High counts.
func TestRollups(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "org",
		Assets: []models.CryptoAsset{
			asset("crypto-alb1", "alb", "ECDHE", "secp256r1"),
			asset("crypto-alb2", "alb", "ECDHE", "secp256r1"),
			asset("crypto-rds", "rds_transit", "ECDHE", "secp256r1"),
		},
		Findings: []models.Finding{
			finding("f-alb1", "alb", "crypto-alb1", models.PostureNonPQCClassical, models.SeverityHigh, 7, "111"),
			finding("f-alb2", "alb", "crypto-alb2", models.PostureLegacyTLS, models.SeverityCritical, 9, "222"),
			finding("f-rds", "rds_transit", "crypto-rds", models.PostureNoEncryption, models.SeverityCritical, 9, "111"),
		},
	}
	rm := Build(scan)

	// ByService: alb has 2 items, both quick-wins (one-flip, hybrid-tls-only).
	var albRollup *ServiceRollup
	for i := range rm.ByService {
		if rm.ByService[i].Service == "alb" {
			albRollup = &rm.ByService[i]
		}
	}
	if albRollup == nil {
		t.Fatalf("alb service rollup missing")
	}
	if albRollup.Items != 2 {
		t.Errorf("alb rollup Items = %d, want 2", albRollup.Items)
	}
	if albRollup.QuickWins != 2 {
		t.Errorf("alb rollup QuickWins = %d, want 2", albRollup.QuickWins)
	}
	if albRollup.DisplayName != "Application Load Balancer" {
		t.Errorf("alb rollup DisplayName = %q, want taxonomy display name", albRollup.DisplayName)
	}
	if albRollup.PQCStatus != pqc.StatusHybridTLSOnly {
		t.Errorf("alb rollup PQCStatus = %q, want hybrid-tls-only", albRollup.PQCStatus)
	}

	// ByService sorted by MaxPriority desc.
	for i := 1; i < len(rm.ByService); i++ {
		if rm.ByService[i-1].MaxPriority < rm.ByService[i].MaxPriority {
			t.Errorf("ByService not sorted by MaxPriority desc at %d", i)
		}
	}

	// ByAccount: account 111 has 2 items (one Critical), account 222 has 1 (Critical).
	acct := map[string]AccountRollup{}
	for _, a := range rm.ByAccount {
		acct[a.AccountID] = a
	}
	if acct["111"].Items != 2 {
		t.Errorf("account 111 Items = %d, want 2", acct["111"].Items)
	}
	if acct["111"].Critical != 1 {
		t.Errorf("account 111 Critical = %d, want 1", acct["111"].Critical)
	}
	if acct["111"].High != 1 {
		t.Errorf("account 111 High = %d, want 1", acct["111"].High)
	}
	if acct["222"].Critical != 1 {
		t.Errorf("account 222 Critical = %d, want 1", acct["222"].Critical)
	}
}

// TestRecommendedActionCitation proves RoadmapItem.RecommendedAction equals the
// pqc HowToEnable and SourceURL is non-empty for known services.
func TestRecommendedActionCitation(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "acct",
		Assets: []models.CryptoAsset{
			asset("crypto-alb", "alb", "ECDHE", "secp256r1"),
			asset("crypto-kms", "kms_spec", "RSA-2048", ""),
		},
		Findings: []models.Finding{
			finding("f-alb", "alb", "crypto-alb", models.PostureNonPQCClassical, models.SeverityMedium, 5, "acct"),
			finding("f-kms", "kms_spec", "crypto-kms", models.PostureNonPQCClassical, models.SeverityMedium, 5, "acct"),
		},
	}
	rm := Build(scan)

	for _, it := range rm.Items {
		sup, ok := pqc.PQCSupportFor(it.Service)
		if !ok {
			t.Errorf("service %s should resolve to a known PQC entry", it.Service)
			continue
		}
		if it.RecommendedAction != sup.HowToEnable {
			t.Errorf("service %s RecommendedAction mismatch:\n got  %q\n want %q", it.Service, it.RecommendedAction, sup.HowToEnable)
		}
		if it.SourceURL == "" {
			t.Errorf("service %s has empty SourceURL", it.Service)
		}
		if it.SourceURL != sup.SourceURL {
			t.Errorf("service %s SourceURL mismatch: got %q want %q", it.Service, it.SourceURL, sup.SourceURL)
		}
		if it.AsOf != pqc.AsOf {
			t.Errorf("service %s AsOf = %q, want %q", it.Service, it.AsOf, pqc.AsOf)
		}
	}
	// kms_spec must resolve (via serviceAlias) to the AWS KMS display + action.
	var kms RoadmapItem
	for _, it := range rm.Items {
		if it.Service == "kms_spec" {
			kms = it
		}
	}
	if kms.DisplayName != "AWS KMS" {
		t.Errorf("kms_spec DisplayName = %q, want AWS KMS", kms.DisplayName)
	}
	if kms.PQCStatus != pqc.StatusAvailable {
		t.Errorf("kms_spec PQCStatus = %q, want available", kms.PQCStatus)
	}
}

// TestAssetAwarePQCStatus proves the asset-aware pqcStatus override end-to-end
// through Build: a quantum-resistant asset (symmetric AES-256, or pqc posture) on a
// service whose matrix row is "not-yet" (s3, ssm) must NEVER present "not-yet";
// it is promoted to the no-action not-applicable state. A genuinely vulnerable
// asset on a not-yet service stays not-yet, and a real available/hybrid
// capability is never downgraded. It also asserts the SymmetricStrength tier.
func TestAssetAwarePQCStatus(t *testing.T) {
	// Build a finding whose asset carries AES-256 on s3 (matrix row = not-yet).
	mkAsset := func(bomRef, service, algName string, bits int) models.CryptoAsset {
		return models.CryptoAsset{
			BomRef:     bomRef,
			Service:    service,
			ResourceID: bomRef + "-res",
			CryptoProps: models.CryptoProperties{
				AlgorithmProperties: &models.AlgorithmProperties{AlgorithmName: algName, KeySizeBits: bits},
			},
		}
	}
	scan := models.ScanResult{
		AccountID: "acct",
		Assets: []models.CryptoAsset{
			mkAsset("s3-aes", "s3", "AES-256-GCM", 256),   // not-yet row, quantum-resistant asset
			mkAsset("ssm-aes", "ssm", "AES-256-GCM", 256), // not-yet row, quantum-resistant asset
			mkAsset("s3-128", "s3", "AES-128", 128),       // AES-128 review-tier symmetric
			mkAsset("acm-rsa", "acm", "RSA-2048", 2048),   // not-yet acm row, VULNERABLE asset
			mkAsset("alb-ec", "alb", "ECDHE", 0),          // hybrid-tls-only, must NOT downgrade
		},
		Findings: []models.Finding{
			finding("f-s3", "s3", "s3-aes", models.PostureSymmetricOnly, models.SeverityInformational, 2, "acct"),
			finding("f-ssm", "ssm", "ssm-aes", models.PostureSymmetricOnly, models.SeverityInformational, 2, "acct"),
			finding("f-s3-128", "s3", "s3-128", models.PostureSymmetricOnly, models.SeverityInformational, 2, "acct"),
			finding("f-acm", "acm", "acm-rsa", models.PostureNonPQCClassical, models.SeverityMedium, 5, "acct"),
			finding("f-alb", "alb", "alb-ec", models.PostureNonPQCClassical, models.SeverityMedium, 5, "acct"),
		},
	}
	rm := Build(scan)
	byRes := map[string]RoadmapItem{}
	for _, it := range rm.Items {
		byRes[it.ResourceID] = it
	}

	// Quantum-resistant symmetric assets on not-yet services must be promoted.
	for _, id := range []string{"s3-aes-res", "ssm-aes-res", "s3-128-res"} {
		it := byRes[id]
		if it.PQCStatus == pqc.StatusNotYet {
			t.Errorf("%s: symmetric quantum-resistant asset must NEVER carry not-yet (got %q)", id, it.PQCStatus)
		}
		if it.PQCStatus != pqc.StatusNotApplicable {
			t.Errorf("%s: expected promotion to not-applicable, got %q", id, it.PQCStatus)
		}
	}
	// Strength tiers surfaced.
	if byRes["s3-aes-res"].SymmetricStrength != pqc.StrengthSafe {
		t.Errorf("s3 AES-256 SymmetricStrength = %q, want quantum-safe", byRes["s3-aes-res"].SymmetricStrength)
	}
	if byRes["s3-128-res"].SymmetricStrength != pqc.StrengthReview {
		t.Errorf("s3 AES-128 SymmetricStrength = %q, want adequate-review", byRes["s3-128-res"].SymmetricStrength)
	}
	// Vulnerable RSA on the not-yet acm row stays not-yet (it genuinely needs a
	// fix it does not have via ACM).
	if byRes["acm-rsa-res"].PQCStatus != pqc.StatusNotYet {
		t.Errorf("vulnerable RSA on acm must stay not-yet, got %q", byRes["acm-rsa-res"].PQCStatus)
	}
	// Real hybrid-tls-only capability is preserved (never promoted/downgraded).
	if byRes["alb-ec-res"].PQCStatus != pqc.StatusHybridTLSOnly {
		t.Errorf("alb must keep hybrid-tls-only, got %q", byRes["alb-ec-res"].PQCStatus)
	}
}

// Test3DESWeakNeverNotApplicable proves a classically-weak 3DES symmetric asset
// is tiered weak-replace AND, although symmetric (not Shor-broken), it is NOT
// silently promoted to a quantum-resistant no-action state on a vulnerable-posture
// finding — the strength signal is additive, not a free pass. Here 3DES is
// non-vulnerable to Shor so on a not-yet service it would promote; the test
// pins the strength tier as the load-bearing weak signal.
func Test3DESWeakNeverNotApplicable(t *testing.T) {
	scan := models.ScanResult{
		AccountID: "acct",
		Assets: []models.CryptoAsset{
			{
				BomRef:     "k-3des",
				Service:    "kms_spec",
				ResourceID: "k-3des-res",
				CryptoProps: models.CryptoProperties{
					AlgorithmProperties: &models.AlgorithmProperties{AlgorithmName: "3DES", KeySizeBits: 168},
				},
			},
		},
		Findings: []models.Finding{
			finding("f-3des", "kms_spec", "k-3des", models.PostureSymmetricOnly, models.SeverityInformational, 1, "acct"),
		},
	}
	rm := Build(scan)
	if len(rm.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(rm.Items))
	}
	it := rm.Items[0]
	if it.SymmetricStrength != pqc.StrengthWeak {
		t.Errorf("3DES SymmetricStrength = %q, want weak-replace", it.SymmetricStrength)
	}
}

// TestPostureUnknownMidWeight proves PostureUnknown gets a mid multiplier (not
// treated as already-PQC), so genuinely unknown exposure is not silently sunk.
func TestPostureUnknownMidWeight(t *testing.T) {
	if postureMultiplier(models.PostureUnknown) != unknownMultiplier {
		t.Errorf("unknown posture multiplier = %.2f, want %.2f", postureMultiplier(models.PostureUnknown), unknownMultiplier)
	}
	// Unknown (1.5) sits between non-pqc-classical (2.0) and pqc-hybrid (0.5).
	if !(postureMultiplier(models.PostureUnknown) < postureMultiplier(models.PostureNonPQCClassical)) {
		t.Errorf("unknown should weigh below non-pqc-classical")
	}
	if !(postureMultiplier(models.PostureUnknown) > postureMultiplier(models.PosturePQCHybrid)) {
		t.Errorf("unknown should weigh above pqc-hybrid")
	}
}

// TestEmptyScan proves Build on an empty scan returns a safe zero roadmap.
func TestEmptyScan(t *testing.T) {
	rm := Build(models.ScanResult{AccountID: "org"})
	if len(rm.Items) != 0 || len(rm.ByService) != 0 || len(rm.ByAccount) != 0 {
		t.Errorf("empty scan should produce empty roadmap")
	}
	if rm.AsOf != pqc.AsOf {
		t.Errorf("AsOf = %q, want %q", rm.AsOf, pqc.AsOf)
	}
	if rm.GeneratedFrom != "org" {
		t.Errorf("GeneratedFrom = %q, want org", rm.GeneratedFrom)
	}
}
