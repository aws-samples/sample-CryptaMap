package transit

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestCloudFrontPosture pins the MinimumProtocolVersion -> posture mapping.
// MinimumProtocolVersion is a negotiation FLOOR, not a ceiling: TLS 1.3 (hence the
// ML-KEM hybrid groups) is available under EVERY CloudFront security policy, so the
// KEX-channel posture is PQCHybrid wherever a floor is known. A weak floor is a
// real downgrade concern but is surfaced via cloudFrontFloorWarning, not by denying
// the PQC-hybrid capability (which was a false-alarm — see audit F14/F34).
func TestCloudFrontPosture(t *testing.T) {
	cases := []struct {
		minVer string
		want   models.CryptoPosture
	}{
		// Low floors still offer TLS 1.3 + ML-KEM -> PQCHybrid (with a warning).
		{"SSLv3", models.PosturePQCHybrid},
		{"TLSv1", models.PosturePQCHybrid},
		{"TLSv1_2016", models.PosturePQCHybrid},
		{"TLSv1.1_2016", models.PosturePQCHybrid},
		// Unknown/unreadable floor: conservative, not quantum-resistant.
		{"", models.PostureNonPQCClassical},
		// TLS 1.3-capable floors: ML-KEM hybrid negotiates -> quantum-resistant.
		{"TLSv1.2_2018", models.PosturePQCHybrid},
		{"TLSv1.2_2019", models.PosturePQCHybrid},
		{"TLSv1.2_2021", models.PosturePQCHybrid},
	}
	for _, c := range cases {
		t.Run(c.minVer, func(t *testing.T) {
			if got := cloudFrontPosture(c.minVer); got != c.want {
				t.Errorf("cloudFrontPosture(%q) = %q, want %q", c.minVer, got, c.want)
			}
		})
	}
	// The load-bearing guarantee for the downgrade concern: a legacy floor MUST
	// carry a warning (so the weak floor is not silently hidden behind the
	// PQC-hybrid capability), while a modern floor carries none.
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
		{"ELBSecurityPolicy-2016-08", models.PostureNonPQCClassical},
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
