package probing

// DORMANT / NOT WIRED: the probing package has no non-test caller and never
// feeds a live scan (verify: grep for IsKnownPQCEndpoint / probing across the
// tree). Do not wire it into a scanner without re-verifying every claim below
// against current AWS behavior — an unverified "known PQC default" here would
// fabricate a clean all-clear, violating the honesty contract.

// AWSPQHybridSuites lists the cipher-suite names AWS exposes via AWS-LC/s2n-tls
// for hybrid post-quantum TLS on KMS, ACM, Secrets Manager, Transfer Family,
// Payments Cryptography, and ALB/NLB.
var AWSPQHybridSuites = []string{
	"TLS_AES_256_GCM_SHA384_X25519_ML_KEM_768",
	"TLS_AES_128_GCM_SHA256_X25519_ML_KEM_768",
	"TLS_CHACHA20_POLY1305_SHA256_X25519_ML_KEM_768",
}

// IsKnownPQCEndpoint flags AWS service endpoint hosts that are confirmed to
// already negotiate PQ-hybrid by default.
func IsKnownPQCEndpoint(host string) bool {
	for _, suffix := range []string{
		// CloudFront has been PQC-default since 2024
		".cloudfront.net",
		// NOTE: .execute-api.amazonaws.com was removed — API Gateway is not a
		// verified PQ-hybrid default (regional/private endpoints do not route
		// via CloudFront), so claiming it would be an inaccurate all-clear.
	} {
		if hasSuffixCI(host, suffix) {
			return true
		}
	}
	return false
}

func hasSuffixCI(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	a := s[len(s)-len(suffix):]
	for i := 0; i < len(suffix); i++ {
		ca, cb := a[i], suffix[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
