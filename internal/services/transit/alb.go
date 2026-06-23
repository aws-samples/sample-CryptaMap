// Package transit contains per-service scanners for AWS data-in-transit
// resources. Each scanner emits []models.CryptoAsset describing the TLS / IPsec
// posture of a discoverable resource.
package transit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ALBScanner discovers Application Load Balancer listeners and their SSL policies.
type ALBScanner struct{}

// Name returns the canonical service identifier.
func (ALBScanner) Name() string { return "alb" }

// Category returns the data-in-transit category.
func (ALBScanner) Category() models.Category { return models.CategoryDataInTransit }

// policyVersion maps an ELB SSL policy name to a TLS version + posture from the
// policy NAME alone. It is the fallback used only when the authoritative
// DescribeSSLPolicies lookup (sslPolicyResolver, which reads the real
// SslProtocols + Ciphers) is unavailable. PQ-enhanced policy names (which also
// contain "tls13") are matched FIRST so they are not mis-labeled classical.
func policyVersion(p string) (string, models.CryptoPosture) {
	pl := strings.ToLower(p)
	switch {
	case strings.Contains(pl, "-pq-"), strings.Contains(pl, "pq-2025"):
		return "1.3", models.PosturePQCHybrid
	case strings.Contains(pl, "tls13"), strings.Contains(pl, "tls-1-3"):
		return "1.3", models.PostureNonPQCClassical
	case strings.Contains(pl, "2016-08"), strings.Contains(pl, "tls-1-2"), strings.Contains(pl, "fs-1-2"):
		return "1.2", models.PostureNonPQCClassical
	case strings.Contains(pl, "2015-05"), strings.Contains(pl, "tls-1-0"), strings.Contains(pl, "tls-1-1"):
		return "1.0", models.PostureLegacyTLS
	}
	// Unrecognized / custom / future name: do NOT assert a classical 1.2 default
	// (a guessed default must never masquerade as a verified classification).
	return "", models.PostureUnknown
}

// albELBV2API is the minimal slice of the elbv2 client this scanner uses.
// DescribeLoadBalancers is Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping load balancers in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *elbv2.Client satisfies it; it
// also satisfies sslPolicyDescribeAPI, so the resolver shares the same fake).
type albELBV2API interface {
	DescribeLoadBalancers(ctx context.Context, in *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(ctx context.Context, in *elbv2.DescribeListenersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error)
	DescribeSSLPolicies(ctx context.Context, in *elbv2.DescribeSSLPoliciesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeSSLPoliciesOutput, error)
}

// Scan lists ALBs and emits one CryptoAsset per HTTPS / TLS listener.
func (s ALBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := elbv2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	// Resolves the ACM cert bound to each HTTPS listener (cached per ARN) for the
	// cert signature algorithm + key size.
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates DescribeLoadBalancers, describes
// each ALB's listeners, and classifies each HTTPS/TLS listener into a
// CryptoAsset. A DescribeLoadBalancers error is NOT swallowed — it is returned so
// the engine records this scanner as errored (which surfaces in coverage),
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success. A per-LB DescribeListeners error is logged and that LB skipped
// (the top-level list already succeeded, so the scan is not wholly incomplete).
func (s ALBScanner) scan(ctx context.Context, client albELBV2API, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	// Resolver caches DescribeSSLPolicies so each distinct policy is described
	// once and reused across listeners; it reads the real SslProtocols + Ciphers.
	resolver := newSSLPolicyResolver(client)

	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("alb DescribeLoadBalancers: %w", err)
		}
		for _, lb := range out.LoadBalancers {
			if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
				continue
			}
			if lb.LoadBalancerArn == nil || lb.LoadBalancerName == nil {
				continue
			}
			lout, lerr := client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
			if lerr != nil {
				fmt.Fprintf(os.Stderr, "alb DescribeListeners %s: %v\n", *lb.LoadBalancerName, lerr)
				continue
			}
			for _, l := range lout.Listeners {
				policy := ""
				if l.SslPolicy != nil {
					policy = *l.SslPolicy
				}
				port := int32(0)
				if l.Port != nil {
					port = *l.Port
				}
				// Resolve version + posture from the REAL SslProtocols/Ciphers
				// (cached per policy) instead of guessing from the policy name.
				res := resolver.resolve(ctx, policy)
				id := fmt.Sprintf("%s-%d", *lb.LoadBalancerName, port)
				a := services.NewAsset("alb", models.CategoryDataInTransit, accountID, region, id, "AWS::ElasticLoadBalancingV2::Listener", res.props)
				services.PostureProperty(&a, res.posture)
				if policy != "" {
					a.Properties["sslPolicy"] = policy
				}
				if res.warning != "" {
					a.Properties["warning"] = res.warning
				}
				if res.observed {
					services.StampObserved(&a, "high")
				}
				// Resolve the listener's bound ACM cert (skip IAM server-cert ARNs)
				// for cert signature algorithm + key size.
				for _, lc := range l.Certificates {
					if lc.CertificateArn != nil && isACMCertARN(*lc.CertificateArn) {
						a.Properties["certificateArn"] = *lc.CertificateArn
						resolveACMCert(ctx, certResolver, *lc.CertificateArn, &a)
						break
					}
				}
				assets = append(assets, a)
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
