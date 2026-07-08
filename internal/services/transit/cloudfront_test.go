package transit

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestCloudFrontPosture pins the MinimumProtocolVersion -> posture mapping to
// what the API data actually PROVES. MinimumProtocolVersion is a negotiation
// floor; nothing in ListDistributions observes a negotiated TLS version or a
// hybrid ML-KEM group, so NO input may yield PosturePQCHybrid (which maps to
// SeverityInformational and would suppress all migration findings on unproven
// evidence). Legacy floors are a PROVEN weakness -> PostureLegacyTLS; modern
// floors prove only classical TLS -> PostureNonPQCClassical; an unreadable
// floor proves nothing -> PostureUnknown.
func TestCloudFrontPosture(t *testing.T) {
	cases := []struct {
		minVer string
		want   models.CryptoPosture
	}{
		// Legacy floors provably permit SSL3/TLS1.0/1.1 negotiation -> LegacyTLS
		// (SeverityHigh), never Informational.
		{"SSLv3", models.PostureLegacyTLS},
		{"TLSv1", models.PostureLegacyTLS},
		{"TLSv1_2016", models.PostureLegacyTLS},
		{"TLSv1.1_2016", models.PostureLegacyTLS},
		// Unreadable floor: nothing proven -> Unknown (needs investigation).
		{"", models.PostureUnknown},
		// Modern floors prove classical TLS >= 1.2 only; PQ-hybrid negotiation
		// is NOT observed, so at most NonPQCClassical.
		{"TLSv1.2_2018", models.PostureNonPQCClassical},
		{"TLSv1.2_2019", models.PostureNonPQCClassical},
		{"TLSv1.2_2021", models.PostureNonPQCClassical},
		{"TLSv1.2_2025", models.PostureNonPQCClassical},
		{"TLSv1.3_2025", models.PostureNonPQCClassical},
	}
	for _, c := range cases {
		t.Run(c.minVer, func(t *testing.T) {
			got := cloudFrontPosture(c.minVer)
			if got != c.want {
				t.Errorf("cloudFrontPosture(%q) = %q, want %q", c.minVer, got, c.want)
			}
			// Hard honesty invariant: the floor alone can never prove a
			// quantum-resistant (Informational) posture.
			if got == models.PosturePQCHybrid || got == models.PosturePQCReady {
				t.Errorf("cloudFrontPosture(%q) = %q: a negotiation floor must never prove a quantum-resistant posture", c.minVer, got)
			}
		})
	}
	// A legacy floor MUST carry a warning naming the concrete downgrade concern;
	// a modern/unreadable floor carries none.
	for _, legacy := range []string{"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"} {
		if cloudFrontFloorWarning(legacy) == "" {
			t.Errorf("legacy floor %q must carry a downgrade warning", legacy)
		}
	}
	for _, modern := range []string{"TLSv1.2_2021", "TLSv1.3_2025", ""} {
		if w := cloudFrontFloorWarning(modern); w != "" {
			t.Errorf("non-legacy floor %q must not warn, got %q", modern, w)
		}
	}
}

// TestCloudFrontScanHonestAsset pins the full per-distribution asset shape:
// SSLv3 floors must surface as legacy-tls (not pqc-hybrid/Informational), the
// negotiated TLS version must not be fabricated from a floor, ML-KEM
// availability is recorded only as a doc-fact capability property, and the
// asset uses CloudFront's region-less distribution ARN so multi-region scans
// of this GLOBAL service dedup to one asset.
func TestCloudFrontScanHonestAsset(t *testing.T) {
	const (
		acct   = "111122223333"
		distID = "E1DISTRIBUTION"
		arn    = "arn:aws:cloudfront::111122223333:distribution/E1DISTRIBUTION"
	)
	page := func() *cloudfront.ListDistributionsOutput {
		return &cloudfront.ListDistributionsOutput{
			DistributionList: &cftypes.DistributionList{
				Items: []cftypes.DistributionSummary{{
					Id:  cloudfrontConfStrptr(distID),
					ARN: cloudfrontConfStrptr(arn),
					ViewerCertificate: &cftypes.ViewerCertificate{
						MinimumProtocolVersion: cftypes.MinimumProtocolVersionSSLv3,
					},
				}},
			},
		}
	}

	scanIn := func(region string) models.CryptoAsset {
		t.Helper()
		client := &fakeCloudFrontClient{pages: []*cloudfront.ListDistributionsOutput{page()}}
		assets, err := CloudFrontScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, region)
		if err != nil {
			t.Fatalf("scan(%s): %v", region, err)
		}
		if len(assets) != 1 {
			t.Fatalf("scan(%s): got %d assets, want 1", region, len(assets))
		}
		return assets[0]
	}

	a := scanIn("ap-south-1")

	// (1) Honest posture: an SSLv3 floor is a PROVEN legacy weakness, never
	// pqc-hybrid, and must map to a real (non-Informational) severity.
	if got := a.Properties["posture"]; got != string(models.PostureLegacyTLS) {
		t.Errorf("SSLv3 posture = %q, want %q", got, models.PostureLegacyTLS)
	}
	if got := a.Properties["posture"]; got == string(models.PosturePQCHybrid) {
		t.Errorf("SSLv3 floor must never be classified pqc-hybrid")
	}
	if a.Properties["warning"] == "" {
		t.Errorf("SSLv3 floor must carry a downgrade warning")
	}

	// (2) No fabricated negotiated version: only a floor was read, so the
	// protocol Version must be unasserted (SSLv3 proves no TLS version at all).
	if a.CryptoProps.ProtocolProperties == nil {
		t.Fatalf("missing protocol properties")
	}
	if v := a.CryptoProps.ProtocolProperties.Version; v != "" {
		t.Errorf("protocol Version = %q, want \"\" (negotiated version is not observed)", v)
	}
	if f := a.CryptoProps.ProtocolProperties.TLSMinVersion; f != "" {
		t.Errorf("TLSMinVersion = %q, want \"\" (SSLv3 policy asserts no TLS floor)", f)
	}

	// (3) ML-KEM availability is a documented capability, not a proven posture.
	if a.Properties["mlkemCapable"] != "true" || a.Properties["mlkemCapableSource"] != "aws-doc" {
		t.Errorf("ML-KEM capability must be recorded as a doc-fact property, got mlkemCapable=%q source=%q",
			a.Properties["mlkemCapable"], a.Properties["mlkemCapableSource"])
	}

	// (4) Global-service dedup: the asset must carry CloudFront's region-less
	// ARN, and scans from different region shards must yield the SAME ARN and
	// BomRef so org-merge dedup collapses them to one asset.
	if a.ResourceARN != arn {
		t.Errorf("ResourceARN = %q, want region-less %q", a.ResourceARN, arn)
	}
	b := scanIn("us-west-2")
	if a.ResourceARN != b.ResourceARN || a.BomRef != b.BomRef {
		t.Errorf("multi-region scans must dedup: ap-south-1 (ARN %q, BomRef %q) vs us-west-2 (ARN %q, BomRef %q)",
			a.ResourceARN, a.BomRef, b.ResourceARN, b.BomRef)
	}
}

// TestCloudFrontScanNilARNFallback pins the fallback when the SDK's ARN field
// is nil: a synthetic REGION-LESS CloudFront ARN is built (never the generic
// region-embedded NewAsset ARN), preserving multi-region dedup.
func TestCloudFrontScanNilARNFallback(t *testing.T) {
	const acct = "111122223333"
	client := &fakeCloudFrontClient{pages: []*cloudfront.ListDistributionsOutput{{
		DistributionList: &cftypes.DistributionList{
			Items: []cftypes.DistributionSummary{{
				Id: cloudfrontConfStrptr("E2NOARN"),
				ViewerCertificate: &cftypes.ViewerCertificate{
					MinimumProtocolVersion: cftypes.MinimumProtocolVersionTLSv122021,
				},
			}},
		},
	}}}
	assets, err := CloudFrontScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), acct, "eu-west-1")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("got %d assets, want 1", len(assets))
	}
	want := "arn:aws:cloudfront::111122223333:distribution/E2NOARN"
	if assets[0].ResourceARN != want {
		t.Errorf("fallback ResourceARN = %q, want %q", assets[0].ResourceARN, want)
	}
	// Modern floor -> classical, not pqc-hybrid; version 1.2 floor does not
	// prove a negotiated version.
	if got := assets[0].Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("TLSv1.2_2021 posture = %q, want %q", got, models.PostureNonPQCClassical)
	}
	if v := assets[0].CryptoProps.ProtocolProperties.Version; v != "" {
		t.Errorf("protocol Version = %q, want \"\" for a TLS 1.2 floor", v)
	}
	if f := assets[0].CryptoProps.ProtocolProperties.TLSMinVersion; f != "1.2" {
		t.Errorf("TLSMinVersion = %q, want \"1.2\"", f)
	}
}

// TestPolicyVersionPQ pins the ELB (ALB/NLB) SSL-policy classification, including
// the -PQ-2025-09 detection that fixes the false-alarm (PQC-hybrid listeners
// previously shown "Classical"). The PQ case must win over the generic tls13 case
// since PQ names contain "tls13".
func TestPolicyVersionPQ(t *testing.T) {
	cases := []struct {
		policy string
		want   models.CryptoPosture
	}{
		{"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", models.PosturePQCHybrid},
		{"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09", models.PosturePQCHybrid},
		{"ELBSecurityPolicy-TLS13-1-2-2021-06", models.PostureNonPQCClassical}, // plain TLS 1.3, no PQ
		// 2016-08 enables TLSv1/1.1/1.2 — the NAME proves no modern floor, so the
		// fallback must stay Unknown (only DescribeSSLPolicies may classify it).
		{"ELBSecurityPolicy-2016-08", models.PostureUnknown},
		{"ELBSecurityPolicy-TLS-1-0-2015-04", models.PostureLegacyTLS},
	}
	for _, c := range cases {
		t.Run(c.policy, func(t *testing.T) {
			if _, got := policyVersion(c.policy); got != c.want {
				t.Errorf("policyVersion(%q) posture = %q, want %q", c.policy, got, c.want)
			}
		})
	}
}

// TestApigwSecPolicyPQ pins the API Gateway REST custom-domain policy
// classification, including the _PQ_ detection that fixes the false-alarm.
func TestApigwSecPolicyPQ(t *testing.T) {
	cases := []struct {
		policy string
		want   models.CryptoPosture
	}{
		{"SecurityPolicy_TLS13_1_2_PQ_2025_09", models.PosturePQCHybrid},
		{"SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09", models.PosturePQCHybrid},
		{"TLS_1_2", models.PostureNonPQCClassical},
		{"TLS_1_0", models.PostureLegacyTLS},
	}
	for _, c := range cases {
		t.Run(c.policy, func(t *testing.T) {
			if _, got := secPolicyToVersion(c.policy); got != c.want {
				t.Errorf("secPolicyToVersion(%q) posture = %q, want %q", c.policy, got, c.want)
			}
		})
	}
}
