package transit

import "testing"

// TestIsACMCertARN locks the gate that decides whether a bound certificate ARN
// can be resolved via acm:DescribeCertificate. Only ACM ARNs (":acm:") are
// resolvable; an IAM server-certificate ARN has no ACM lookup and must NOT be
// attempted (it would error) — the cert fields stay honestly blank instead.
func TestIsACMCertARN(t *testing.T) {
	cases := []struct {
		arn  string
		want bool
	}{
		{"arn:aws:acm:us-east-1:111122223333:certificate/abc-123", true},
		{"arn:aws-us-gov:acm:us-gov-west-1:111122223333:certificate/x", true},
		{"arn:aws:iam::111122223333:server-certificate/my-cert", false},
		{"arn:aws:cloudfront::111122223333:distribution/E123", false},
		{"", false},
		{"not-an-arn", false},
	}
	for _, c := range cases {
		if got := isACMCertARN(c.arn); got != c.want {
			t.Errorf("isACMCertARN(%q) = %v, want %v", c.arn, got, c.want)
		}
	}
}

// TestACMResolverNilAndNonACMSafe proves the resolver degrades gracefully: a nil
// resolver, an empty ARN, or a non-ACM ARN all yield found=false WITHOUT making
// (or panicking on) an API call, so callers can invoke it unconditionally.
func TestACMResolverNilAndNonACMSafe(t *testing.T) {
	var nilResolver *acmCertResolver
	if got := nilResolver.resolve(t.Context(), "arn:aws:acm:us-east-1:1:certificate/x"); got.found {
		t.Errorf("nil resolver: got found=true, want false")
	}
	// A resolver with a client but a non-ACM ARN must short-circuit to not-found
	// before any API call.
	r := &acmCertResolver{cache: map[string]acmCertDetail{}}
	if got := r.resolve(t.Context(), "arn:aws:iam::1:server-certificate/x"); got.found {
		t.Errorf("non-ACM ARN: got found=true, want false")
	}
	if got := r.resolve(t.Context(), ""); got.found {
		t.Errorf("empty ARN: got found=true, want false")
	}
}
