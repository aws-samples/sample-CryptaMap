package transit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ClassicELBScanner inspects Classic Load Balancers (ELB v1) for TLS listeners.
// This is distinct from the ELBv2 ALB/NLB scanner — Classic LBs are a separate
// legacy resource that still carry HTTPS/SSL listeners with predefined SSL
// negotiation policies, and are a common home for weak/legacy cipher policies.
//
// Per HTTPS/SSL listener: the referenced SSL negotiation policy is resolved via
// elasticloadbalancing:DescribeLoadBalancerPolicies and classified from the REAL
// Protocol-* policy attributes (TLSv1/TLSv1.1/TLSv1.2/SSLv2/SSLv3 enablement) —
// never from the policy NAME, which is opaque for custom policies. A policy whose
// attributes cannot be read stays PostureUnknown (a scanner must not assert a
// clean classical verdict it cannot prove). A non-TLS listener (HTTP/TCP) is
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

// classicELBPolicyDescribeAPI is the OPTIONAL capability slice for resolving a
// listener's SSL negotiation policy to its REAL Protocol-* attributes — the
// authoritative classification basis (policy names are opaque for custom
// policies). The concrete *elb.Client always satisfies it; a test fake that does
// not implement it degrades honestly to PostureUnknown (never a fabricated
// classical verdict).
type classicELBPolicyDescribeAPI interface {
	DescribeLoadBalancerPolicies(ctx context.Context, in *elb.DescribeLoadBalancerPoliciesInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancerPoliciesOutput, error)
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
	// Cache DescribeLoadBalancerPolicies results per (load balancer, policy set):
	// custom Classic ELB policies are scoped to their LB, so the LB name is part
	// of the key. Many listeners on the same LB share one policy, so each distinct
	// pair is described at most once per scan.
	policyCache := map[string]classicELBPolicyResult{}
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

				// TLS listener: classify the negotiation policy from the REAL
				// Protocol-* attributes returned by DescribeLoadBalancerPolicies
				// (cached per LB+policy). A policy whose attributes cannot be
				// read stays PostureUnknown — an unrecognized/custom policy must
				// NEVER be asserted a clean classical endpoint.
				policy := strings.Join(ld.PolicyNames, ",")
				res := resolveClassicELBPolicy(ctx, client, lbName, ld.PolicyNames, policyCache)
				a := services.NewAsset("classicelb", models.CategoryDataInTransit, accountID, region, id, "AWS::ElasticLoadBalancing::LoadBalancer", res.props)
				services.PostureProperty(&a, res.posture)
				a.Properties["listenerProtocol"] = proto
				if policy != "" {
					a.Properties["sslPolicy"] = policy
				}
				if res.note != "" {
					a.Properties["note"] = res.note
				}
				if res.warning != "" {
					a.Properties["warning"] = res.warning
				}
				if res.observed {
					services.StampObserved(&a, "high")
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

// classicELBPolicyResult is the resolved classification for one Classic ELB SSL
// negotiation policy set on one load balancer.
type classicELBPolicyResult struct {
	posture  models.CryptoPosture
	props    models.CryptoProperties
	note     string // names exactly what could not be read when posture is Unknown
	warning  string // legacy-floor co-finding when a modern ceiling coexists with TLS 1.0/1.1
	observed bool   // true when DescribeLoadBalancerPolicies returned real Protocol-* attributes
}

// resolveClassicELBPolicy classifies a listener's SSL negotiation policies from
// the REAL Protocol-* attributes returned by
// elasticloadbalancing:DescribeLoadBalancerPolicies (the authoritative basis —
// a policy NAME is opaque for custom policies and must never be guessed from).
// When the describe is unavailable, fails, returns no policies, or exposes no
// recognizable Protocol-* attributes (e.g. a Reference-Security-Policy
// indirection with the attribute set withheld), the result is PostureUnknown
// with a note naming what could not be read — never a fabricated
// NonPQCClassical. Results are cached per (load balancer, policy set) because
// custom policies are LB-scoped.
func resolveClassicELBPolicy(ctx context.Context, client classicELBAPI, lbName string, policyNames []string, cache map[string]classicELBPolicyResult) classicELBPolicyResult {
	policyLabel := strings.Join(policyNames, ",")
	if len(policyNames) == 0 {
		return classicELBPolicyResult{
			posture: models.PostureUnknown,
			props:   services.TLSProtocolProps("", ""),
			note:    "Classic ELB TLS listener has no SSL negotiation policy attached that the scanner could read; the permitted protocol versions could not be determined.",
		}
	}
	cacheKey := lbName + "|" + policyLabel
	if cached, ok := cache[cacheKey]; ok {
		return cached
	}

	describer, ok := client.(classicELBPolicyDescribeAPI)
	if !ok {
		// No policy-describe capability on this client: degrade honestly to
		// Unknown rather than asserting a verdict without the attribute data.
		res := classicELBPolicyResult{
			posture: models.PostureUnknown,
			props:   services.TLSProtocolProps("", policyLabel),
			note:    "SSL negotiation policy attributes could not be read via elasticloadbalancing:DescribeLoadBalancerPolicies; the permitted TLS protocol versions are unverified.",
		}
		cache[cacheKey] = res
		return res
	}
	out, err := describer.DescribeLoadBalancerPolicies(ctx, &elb.DescribeLoadBalancerPoliciesInput{
		LoadBalancerName: &lbName,
		PolicyNames:      policyNames,
	})
	if err != nil || out == nil || len(out.PolicyDescriptions) == 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "classicelb DescribeLoadBalancerPolicies %s %s: %v\n", lbName, policyLabel, err)
		}
		res := classicELBPolicyResult{
			posture: models.PostureUnknown,
			props:   services.TLSProtocolProps("", policyLabel),
			note:    "SSL negotiation policy attributes could not be read via elasticloadbalancing:DescribeLoadBalancerPolicies; the permitted TLS protocol versions are unverified.",
		}
		cache[cacheKey] = res
		return res
	}

	res := classifyClassicELBPolicies(out.PolicyDescriptions, policyLabel)
	cache[cacheKey] = res
	return res
}

// classifyClassicELBPolicies derives (posture, protocol block) from the REAL
// Protocol-* PolicyAttributeDescriptions of one or more SSL negotiation policies
// (union across policies: if ANY attached policy enables a protocol, the
// listener can negotiate it). Recognized attributes: Protocol-SSLv2,
// Protocol-SSLv3, Protocol-TLSv1, Protocol-TLSv1.1, Protocol-TLSv1.2 (Classic
// ELB predates TLS 1.3 and has no PQC option). When no Protocol-* attribute is
// present at all, the posture stays Unknown with a note — the attribute set was
// not readable, so no version may be asserted.
func classifyClassicELBPolicies(descs []elbtypes.PolicyDescription, policyLabel string) classicELBPolicyResult {
	hasSSLv2, hasSSLv3, has10, has11, has12 := false, false, false, false, false
	sawProtocolAttr := false
	for _, pd := range descs {
		for _, attr := range pd.PolicyAttributeDescriptions {
			if attr.AttributeName == nil || attr.AttributeValue == nil {
				continue
			}
			name := strings.ToLower(*attr.AttributeName)
			if !strings.HasPrefix(name, "protocol-") {
				continue
			}
			sawProtocolAttr = true
			if !strings.EqualFold(*attr.AttributeValue, "true") {
				continue
			}
			switch name {
			case "protocol-sslv2":
				hasSSLv2 = true
			case "protocol-sslv3":
				hasSSLv3 = true
			case "protocol-tlsv1":
				has10 = true
			case "protocol-tlsv1.1":
				has11 = true
			case "protocol-tlsv1.2":
				has12 = true
			}
		}
	}

	if !sawProtocolAttr {
		return classicELBPolicyResult{
			posture: models.PostureUnknown,
			props:   services.TLSProtocolProps("", policyLabel),
			note:    "SSL negotiation policy exposes no Protocol-* attributes via DescribeLoadBalancerPolicies; the permitted TLS protocol versions are unverified.",
		}
	}

	// Ceiling and floor from the enabled protocol set.
	ver := ""
	switch {
	case has12:
		ver = "1.2"
	case has11:
		ver = "1.1"
	case has10:
		ver = "1.0"
	}
	floor := ""
	switch {
	case has10:
		floor = "1.0"
	case has11:
		floor = "1.1"
	case has12:
		floor = "1.2"
	}

	// Posture from the ceiling (mirrors postureFromTLS in ssl_policy.go); a
	// legacy 1.0/1.1 floor under a 1.2 ceiling is surfaced as a downgrade
	// warning below rather than silently passed as clean. SSLv2/SSLv3 enablement
	// is below even legacy TLS; legacy-tls is the strongest honest label in the
	// posture enum for it (with the enablement named in the warning).
	posture := models.PostureUnknown
	switch {
	case hasSSLv2 || hasSSLv3:
		posture = models.PostureLegacyTLS
	case ver == "1.0", ver == "1.1":
		posture = models.PostureLegacyTLS
	case ver == "1.2":
		posture = models.PostureNonPQCClassical
	}

	res := classicELBPolicyResult{
		posture:  posture,
		props:    services.TLSProtocolProps(ver, policyLabel),
		observed: true,
	}
	if res.props.ProtocolProperties != nil {
		res.props.ProtocolProperties.TLSMinVersion = floor
		res.props.ProtocolProperties.Source = services.SourceObserved
	}
	if hasSSLv2 || hasSSLv3 {
		res.warning = "SSL negotiation policy enables SSLv2/SSLv3; these protocols are cryptographically broken and below any acceptable TLS floor"
	} else if ver == "1.2" && (floor == "1.0" || floor == "1.1") {
		res.warning = "policy permits a legacy TLS " + floor +
			" floor; a downgrade-capable client can negotiate TLS " + floor +
			" despite the TLS 1.2 ceiling"
	}
	if posture == models.PostureUnknown {
		res.note = "SSL negotiation policy enables no recognizable SSL/TLS protocol version; the negotiated protocol could not be classified."
	}
	return res
}
