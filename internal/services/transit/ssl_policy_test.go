package transit

import (
	"testing"

	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestIsPQELBPolicyName locks the name-based PQ detector. The ML-KEM hybrid
// groups in an ELB PQ policy are NOT cipher names (the DescribeSSLPolicies
// Ciphers list holds only classical suites), so the policy NAME is the only
// config-derivable PQ signal — matched on "-PQ-" / "PQ-2025", case-insensitively.
func TestIsPQELBPolicyName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09", true},
		{"ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09", true},
		{"elbsecuritypolicy-tls13-1-0-pq-2025-09", true}, // case-insensitive
		{"ELBSecurityPolicy-TLS13-1-2-2021-06", false},   // classical TLS 1.3, not PQ
		{"ELBSecurityPolicy-2016-08", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isPQELBPolicyName(c.name); got != c.want {
			t.Errorf("isPQELBPolicyName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestClassifySSLPolicyPQByName proves the false-NEGATIVE fix: a real ELB PQ
// policy lists only CLASSICAL cipher suites (the ML-KEM groups are not ciphers),
// so cipher-token scanning alone would mis-classify it NonPQCClassical. The
// name-based detection must flip it to PosturePQCHybrid, set PQCHybrid=true, and
// surface the doc-known supported hybrid groups as the KEX label.
func TestClassifySSLPolicyPQByName(t *testing.T) {
	str := func(s string) *string { return &s }
	sp := elbv2types.SslPolicy{
		SslProtocols: []string{"TLSv1.3", "TLSv1.2"},
		// Only classical suites are present — exactly what the real API returns
		// for a PQ policy.
		Ciphers: []elbv2types.Cipher{
			{Name: str("ECDHE-RSA-AES128-GCM-SHA256")},
			{Name: str("TLS_AES_256_GCM_SHA384")},
		},
	}
	res := classifySSLPolicy(sp, "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09")
	if res.posture != models.PosturePQCHybrid {
		t.Errorf("posture = %q, want pqc-hybrid (name-based PQ detection)", res.posture)
	}
	pp := res.props.ProtocolProperties
	if pp == nil || !pp.PQCHybrid {
		t.Fatalf("PQCHybrid not set true on a PQ-named policy")
	}
	if pp.KeyExchangeGroup != elbPQHybridGroupsDoc {
		t.Errorf("KeyExchangeGroup = %q, want doc-known hybrid groups %q", pp.KeyExchangeGroup, elbPQHybridGroupsDoc)
	}

	// A classical TLS 1.3 policy (no PQ in the name, only classical ciphers) stays
	// NonPQCClassical with no hybrid flag — guards against a false POSITIVE.
	resC := classifySSLPolicy(elbv2types.SslPolicy{
		SslProtocols: []string{"TLSv1.3", "TLSv1.2"},
		Ciphers:      []elbv2types.Cipher{{Name: str("TLS_AES_256_GCM_SHA384")}},
	}, "ELBSecurityPolicy-TLS13-1-2-2021-06")
	if resC.posture != models.PostureNonPQCClassical {
		t.Errorf("classical policy posture = %q, want non-pqc-classical", resC.posture)
	}
	if resC.props.ProtocolProperties.PQCHybrid {
		t.Errorf("classical policy wrongly flagged PQCHybrid")
	}
}
