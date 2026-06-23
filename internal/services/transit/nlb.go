package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// NLBScanner discovers Network Load Balancer TLS listeners.
type NLBScanner struct{}

// Name returns the canonical service identifier.
func (NLBScanner) Name() string { return "nlb" }

// Category returns the data-in-transit category.
func (NLBScanner) Category() models.Category { return models.CategoryDataInTransit }

// nlbELBV2API is the minimal slice of the elbv2 client this scanner uses.
// DescribeLoadBalancers is Marker-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping load balancers in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *elbv2.Client satisfies it; it
// also satisfies sslPolicyDescribeAPI, so the resolver shares the same fake).
type nlbELBV2API interface {
	DescribeLoadBalancers(ctx context.Context, in *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
	DescribeListeners(ctx context.Context, in *elbv2.DescribeListenersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error)
	DescribeSSLPolicies(ctx context.Context, in *elbv2.DescribeSSLPoliciesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeSSLPoliciesOutput, error)
}

// Scan lists NLBs and emits one CryptoAsset per TLS listener.
func (s NLBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := elbv2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeLoadBalancers, describes
// each NLB's listeners, and classifies each TLS listener into a CryptoAsset. A
// DescribeLoadBalancers error is NOT swallowed — it is returned so the engine
// records this scanner as errored (which surfaces in coverage), keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success. A per-LB DescribeListeners error is logged and that LB skipped (the
// top-level list already succeeded, so the scan is not wholly incomplete).
func (s NLBScanner) scan(ctx context.Context, client nlbELBV2API, accountID, region string) ([]models.CryptoAsset, error) {
	// Shared DescribeSSLPolicies cache (reads real SslProtocols + Ciphers),
	// reused across listeners like the ALB scanner.
	resolver := newSSLPolicyResolver(client)

	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("nlb DescribeLoadBalancers: %w", err)
		}
		for _, lb := range out.LoadBalancers {
			if lb.Type != elbv2types.LoadBalancerTypeEnumNetwork {
				continue
			}
			if lb.LoadBalancerArn == nil || lb.LoadBalancerName == nil {
				continue
			}
			lout, lerr := client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn})
			if lerr != nil {
				fmt.Fprintf(os.Stderr, "nlb DescribeListeners %s: %v\n", *lb.LoadBalancerName, lerr)
				continue
			}
			for _, l := range lout.Listeners {
				policy := ""
				if l.SslPolicy != nil {
					policy = *l.SslPolicy
				}
				// Skip non-TLS listeners (TCP/UDP without SSL policy).
				if policy == "" && l.Protocol != elbv2types.ProtocolEnumTls {
					continue
				}
				port := int32(0)
				if l.Port != nil {
					port = *l.Port
				}
				// Resolve version + posture from the REAL SslProtocols/Ciphers
				// (cached per policy) instead of guessing from the policy name.
				res := resolver.resolve(ctx, policy)
				id := fmt.Sprintf("%s-%d", *lb.LoadBalancerName, port)
				a := services.NewAsset("nlb", models.CategoryDataInTransit, accountID, region, id, "AWS::ElasticLoadBalancingV2::Listener", res.props)
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
