package transit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// acmCertDetail is the resolved crypto detail of an ACM certificate: the
// signature algorithm string (e.g. "SHA256WITHRSA") and the public-key size in
// bits parsed from the KeyAlgorithm enum (RSA_2048 -> 2048, EC_prime256v1 ->
// 256). found=false means the ARN was not an ACM cert, the lookup failed, or the
// detail was unavailable — callers leave the cert fields blank in that case.
type acmCertDetail struct {
	sigAlgo string
	keyBits int
	found   bool
}

// acmCertResolver caches acm:DescribeCertificate lookups keyed by certificate
// ARN so a cert bound to multiple resources (or seen across listeners/domains)
// is described at most once per scan. It is created lazily per region from the
// scanner's aws.Config; a nil resolver (or nil client) resolves to not-found so
// callers degrade gracefully. SDK clients are safe for concurrent use, but the
// cache map is NOT — callers must not share a resolver across goroutines without
// synchronization (the current per-scanner serial use is single-goroutine).
type acmCertResolver struct {
	client *acm.Client
	cache  map[string]acmCertDetail
}

// newACMCertResolver builds an ACM resolver bound to the region in cfg.
func newACMCertResolver(cfg aws.Config) *acmCertResolver {
	return &acmCertResolver{client: acm.NewFromConfig(cfg), cache: map[string]acmCertDetail{}}
}

// newACMCertResolverInRegion builds an ACM resolver pinned to a specific region,
// for services whose certs always live in a fixed region regardless of the scan
// region (e.g. CloudFront viewer certs are ALWAYS in us-east-1). An empty region
// falls back to the cfg region.
func newACMCertResolverInRegion(cfg aws.Config, region string) *acmCertResolver {
	return &acmCertResolver{
		client: acm.NewFromConfig(cfg, func(o *acm.Options) {
			if region != "" {
				o.Region = region
			}
		}),
		cache: map[string]acmCertDetail{},
	}
}

// isACMCertARN reports whether arn is an ACM certificate ARN (arn:*:acm:*).
// Only ACM ARNs can be resolved via acm:DescribeCertificate; an IAM server-cert
// ARN (arn:aws:iam::...:server-certificate/...) or a CloudFront/IAM cert id has
// no ACM lookup, so we must NOT attempt one (it would error) and instead leave
// the cert fields honestly blank.
func isACMCertARN(arn string) bool {
	return strings.Contains(arn, ":acm:")
}

// resolve returns the crypto detail for an ACM certificate ARN, calling
// DescribeCertificate once per distinct ARN and caching the result. A non-ACM
// ARN, a nil resolver/client, or a describe error all yield found=false.
func (r *acmCertResolver) resolve(ctx context.Context, arn string) acmCertDetail {
	if r == nil || r.client == nil || arn == "" || !isACMCertARN(arn) {
		return acmCertDetail{}
	}
	if cached, ok := r.cache[arn]; ok {
		return cached
	}
	det := acmCertDetail{}
	out, err := r.client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: &arn})
	if err != nil || out == nil || out.Certificate == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "transit acm DescribeCertificate %s: %v\n", arn, err)
		}
		r.cache[arn] = det // cache the negative so we don't re-call a failing ARN
		return det
	}
	c := out.Certificate
	if c.SignatureAlgorithm != nil {
		det.sigAlgo = *c.SignatureAlgorithm
	}
	if keyAlgo := string(c.KeyAlgorithm); keyAlgo != "" {
		if p, ok := pqc.ACMKeyAlgorithmProfile(keyAlgo); ok && p.KeySizeBits > 0 {
			det.keyBits = p.KeySizeBits
		}
	}
	det.found = det.sigAlgo != "" || det.keyBits != 0
	r.cache[arn] = det
	return det
}

// resolveACMCert resolves the ACM cert at arn and, if found, stamps the
// certificate's signature algorithm + key-size onto the asset's flat
// cryptamap:* protocol-detail props (the panel reads cryptamap:certSignatureAlgorithm
// / cryptamap:certKeySizeBits) AND the nested ProtocolProperties (so an in-memory
// asset is complete before the CBOM writer flattens it). The value is stamped as
// an AWS-doc/observed fact via StampObserved — it is read directly from the ACM
// API, not inferred. No-op when the resolver is nil or the ARN is not ACM.
func resolveACMCert(ctx context.Context, r *acmCertResolver, arn string, a *models.CryptoAsset) {
	det := r.resolve(ctx, arn)
	if !det.found {
		return
	}
	if a.Properties == nil {
		a.Properties = map[string]string{}
	}
	if det.sigAlgo != "" {
		a.Properties["certSignatureAlgorithm"] = det.sigAlgo
	}
	if det.keyBits != 0 {
		a.Properties["certKeySizeBits"] = fmt.Sprintf("%d", det.keyBits)
	}
	// Mirror onto the nested protocol block when present, so consumers reading
	// the in-memory asset (before CBOM flattening) see the same values.
	if cp := a.CryptoProps.ProtocolProperties; cp != nil {
		if det.sigAlgo != "" {
			cp.CertSignatureAlgorithm = det.sigAlgo
		}
		if det.keyBits != 0 {
			cp.CertKeySizeBits = det.keyBits
		}
	}
	// The cert detail is read live from ACM (observed), with high confidence.
	services.StampObserved(a, "high")
}
