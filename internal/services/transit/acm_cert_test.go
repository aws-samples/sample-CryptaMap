package transit

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

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

// TestResolveACMCertDoesNotClobberAssetProvenance pins the provenance-honesty
// fix: resolveACMCert reads a REAL cert detail from ACM, but that detail is only
// a SUB-CLAIM of the asset — it must NOT overwrite the asset-level
// source/confidence set for the (possibly weaker-based) posture classification.
// Previously it StampObserved(a,"high") unconditionally, laundering a guessed
// classification into a verified one. The cert observation is recorded on
// additive certSource/certConfidence properties instead.
func TestResolveACMCertDoesNotClobberAssetProvenance(t *testing.T) {
	const arn = "arn:aws:acm:us-east-1:111122223333:certificate/abc-123"
	// Resolver with a pre-populated cache so no live API call is made (the cache
	// is consulted before any DescribeCertificate).
	r := &acmCertResolver{
		client: acm.NewFromConfig(aws.Config{Region: "us-east-1"}),
		cache: map[string]acmCertDetail{
			arn: {sigAlgo: "SHA256WITHRSA", keyBits: 2048, found: true},
		},
	}

	// Asset whose classification rests on a weaker doc-fact basis.
	a := models.CryptoAsset{Properties: map[string]string{
		services.PropSource:     services.SourceAWSDoc,
		services.PropConfidence: "medium",
	}}
	resolveACMCert(t.Context(), r, arn, &a)

	// The cert detail is stamped as an additive sub-claim...
	if got := a.Properties["certSignatureAlgorithm"]; got != "SHA256WITHRSA" {
		t.Errorf("certSignatureAlgorithm = %q, want SHA256WITHRSA", got)
	}
	if got := a.Properties["certKeySizeBits"]; got != "2048" {
		t.Errorf("certKeySizeBits = %q, want 2048", got)
	}
	if got := a.Properties["certSource"]; got != services.SourceObserved {
		t.Errorf("certSource = %q, want %q (the cert lookup IS observed)", got, services.SourceObserved)
	}
	// ...but the asset-level provenance of the posture is preserved.
	if got := a.Properties[services.PropSource]; got != services.SourceAWSDoc {
		t.Errorf("asset PropSource = %q, want %q (cert lookup must not clobber the posture's weaker basis)", got, services.SourceAWSDoc)
	}
	if got := a.Properties[services.PropConfidence]; got != "medium" {
		t.Errorf("asset PropConfidence = %q, want medium (must not be upgraded to high by a cert sub-claim)", got)
	}
}
