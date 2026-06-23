package transit

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ClassicELBScanner inspects Classic Load Balancers (ELB v1) for TLS listeners.
// This is distinct from the ELBv2 ALB/NLB scanner — Classic LBs are a separate
// legacy resource that still carry HTTPS/SSL listeners with predefined SSL
// negotiation policies, and are a common home for weak/legacy cipher policies.
//
// Per HTTPS/SSL listener: a TLS listener is classical (no PQC option on Classic
// ELB) -> NonPQCClassical, unless the negotiation-policy name encodes a legacy
// floor (TLS 1.0/1.1), in which case LegacyTLS. A non-TLS listener (HTTP/TCP) is
// plaintext -> NoEncryption (a verified finding, not Unknown).
type ClassicELBScanner struct{}

// Name returns the canonical service identifier.
func (ClassicELBScanner) Name() string { return "classicelb" }

// Category returns the primary CryptaMap category.
func (ClassicELBScanner) Category() models.Category { return models.CategoryDataInTransit }

// classicELBAPI is the minimal slice of the elasticloadbalancing (ELB v1) client
// this scanner uses. DescribeLoadBalancers is Marker-paginated, so the scanner
// must loop; a single call returns only the first page, silently dropping load
// balancers in dense accounts. Defining it as an interface keeps the pagination +
// error propagation logic unit-testable with a fake (the concrete *elb.Client
// satisfies it).
type classicELBAPI interface {
	DescribeLoadBalancers(ctx context.Context, in *elb.DescribeLoadBalancersInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error)
}

// Scan paginates DescribeLoadBalancers (marker cursor) and emits one asset per
// HTTPS/SSL listener (plus a no-encryption asset per plaintext listener).
func (s ClassicELBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := elb.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeLoadBalancers and classifies
// each listener into a CryptoAsset. A DescribeLoadBalancers error is NOT swallowed
// — it is returned so the engine records this scanner as errored (which surfaces
// in coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s ClassicELBScanner) scan(ctx context.Context, client classicELBAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.DescribeLoadBalancers(ctx, &elb.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("classicelb DescribeLoadBalancers: %w", err)
		}
		for _, lb := range out.LoadBalancerDescriptions {
			if lb.LoadBalancerName == nil {
				continue
			}
			lbName := *lb.LoadBalancerName
			for _, ld := range lb.ListenerDescriptions {
				if ld.Listener == nil || ld.Listener.Protocol == nil {
					continue
				}
				proto := strings.ToUpper(*ld.Listener.Protocol)
				port := ld.Listener.LoadBalancerPort
				id := fmt.Sprintf("%s-%d", lbName, port)

				if proto != "HTTPS" && proto != "SSL" {
					// Plaintext listener (HTTP/TCP) -> verified no-encryption.
					a := services.NewAsset("classicelb", models.CategoryDataInTransit, accountID, region, id, "AWS::ElasticLoadBalancing::LoadBalancer", services.NoEncryption())
					services.PostureProperty(&a, models.PostureNoEncryption)
					a.Properties["listenerProtocol"] = proto
					a.Properties["note"] = "Classic ELB listener serves plaintext (HTTP/TCP, no TLS)."
					assets = append(assets, a)
					continue
				}

				// TLS listener: classify the negotiation policy by name where it
				// encodes a version; otherwise classical (no PQC on Classic ELB).
				policy := strings.Join(ld.PolicyNames, ",")
				ver, posture := policyVersion(policy)
				if posture == models.PostureUnknown {
					// Predefined policies have opaque names; default to classical TLS.
					posture = models.PostureNonPQCClassical
				}
				props := services.TLSProtocolProps(ver, policy)
				a := services.NewAsset("classicelb", models.CategoryDataInTransit, accountID, region, id, "AWS::ElasticLoadBalancing::LoadBalancer", props)
				services.PostureProperty(&a, posture)
				a.Properties["listenerProtocol"] = proto
				if policy != "" {
					a.Properties["sslPolicy"] = policy
				}
				if ld.Listener.SSLCertificateId != nil && *ld.Listener.SSLCertificateId != "" {
					a.Properties["sslCertificateId"] = *ld.Listener.SSLCertificateId
				}
				assets = append(assets, a)
				if services.TruncationCapReached(len(assets), s.Name(), region) {
					return assets, nil
				}
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
