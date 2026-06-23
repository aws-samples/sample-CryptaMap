package transit

import (
	"context"
	"errors"
	"testing"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeNLBClient is a hand-rolled nlbELBV2API for unit-testing the NLB scanner's
// pagination + error propagation + SSL-policy classification without a live AWS
// client. lbPages is returned page-by-page (each DescribeLoadBalancers call
// consumes the next page) with Marker wired so the scanner loops every page;
// listeners maps a LoadBalancerArn to its listeners; listenersErr (keyed by ARN)
// forces a per-LB DescribeListeners failure; sslPolicies maps a policy name to
// the real SslPolicy returned by DescribeSSLPolicies (the authoritative path);
// lbErr / sslErr force top-level failures.
type fakeNLBClient struct {
	lbPages      []*elbv2.DescribeLoadBalancersOutput
	lbCalls      int
	lbErr        error
	listeners    map[string]*elbv2.DescribeListenersOutput
	listenersErr map[string]error
	sslPolicies  map[string]elbv2types.SslPolicy
	sslErr       error
}

func (f *fakeNLBClient) DescribeLoadBalancers(ctx context.Context, in *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	if f.lbErr != nil {
		return nil, f.lbErr
	}
	if f.lbCalls >= len(f.lbPages) {
		return &elbv2.DescribeLoadBalancersOutput{}, nil
	}
	out := f.lbPages[f.lbCalls]
	f.lbCalls++
	return out, nil
}

func (f *fakeNLBClient) DescribeListeners(ctx context.Context, in *elbv2.DescribeListenersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
	arn := ""
	if in.LoadBalancerArn != nil {
		arn = *in.LoadBalancerArn
	}
	if f.listenersErr != nil {
		if err := f.listenersErr[arn]; err != nil {
			return nil, err
		}
	}
	if f.listeners != nil {
		if out := f.listeners[arn]; out != nil {
			return out, nil
		}
	}
	return &elbv2.DescribeListenersOutput{}, nil
}

func (f *fakeNLBClient) DescribeSSLPolicies(ctx context.Context, in *elbv2.DescribeSSLPoliciesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeSSLPoliciesOutput, error) {
	if f.sslErr != nil {
		return nil, f.sslErr
	}
	out := &elbv2.DescribeSSLPoliciesOutput{}
	for _, name := range in.Names {
		if sp, ok := f.sslPolicies[name]; ok {
			out.SslPolicies = append(out.SslPolicies, sp)
		}
	}
	return out, nil
}

// nlbStrptr returns a pointer to s (prefixed to avoid colliding with sibling
// test files in package transit).
func nlbStrptr(s string) *string { return &s }

// nlbI32 returns a pointer to v.
func nlbI32(v int32) *int32 { return &v }

// nlbNetLB builds a network-type LoadBalancer description.
func nlbNetLB(name string) elbv2types.LoadBalancer {
	arn := "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/" + name
	return elbv2types.LoadBalancer{
		LoadBalancerArn:  nlbStrptr(arn),
		LoadBalancerName: nlbStrptr(name),
		Type:             elbv2types.LoadBalancerTypeEnumNetwork,
	}
}

// nlbAssetByID returns the first asset whose ResourceID equals id (helper local
// to the NLB tests; prefixed to avoid package-wide collisions).
func nlbAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// nlbPostureOf reads the posture stamped onto an asset's flat properties.
func nlbPostureOf(a models.CryptoAsset) string { return a.Properties["posture"] }

// TestNLBScanPaginatesLoadBalancers verifies the DescribeLoadBalancers Marker
// loop: a fake returning 2 pages (NextMarker on page 1) must describe BOTH pages'
// load balancers. Without the pagination loop, only the first page survives and
// NLBs in dense accounts are silently dropped.
func TestNLBScanPaginatesLoadBalancers(t *testing.T) {
	client := &fakeNLBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{
			{
				LoadBalancers: []elbv2types.LoadBalancer{nlbNetLB("nlb-page1")},
				NextMarker:    nlbStrptr("marker-page2"),
			},
			{
				LoadBalancers: []elbv2types.LoadBalancer{nlbNetLB("nlb-page2")},
				// no NextMarker -> last page
			},
		},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-page1": {
				Listeners: []elbv2types.Listener{{Port: nlbI32(443), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-page2": {
				Listeners: []elbv2types.Listener{{Port: nlbI32(443), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
		},
	}
	assets, err := NLBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.lbCalls != 2 {
		t.Errorf("expected DescribeLoadBalancers to be called 2 times (paginated), got %d", client.lbCalls)
	}
	if _, ok := nlbAssetByID(assets, "nlb-page1-443"); !ok {
		t.Errorf("expected listener asset from page 1; assets=%v", assets)
	}
	if _, ok := nlbAssetByID(assets, "nlb-page2-443"); !ok {
		t.Errorf("expected listener asset from page 2 (pagination dropped it); assets=%v", assets)
	}
}

// TestNLBScanLoadBalancersErrorPropagates verifies a top-level
// DescribeLoadBalancers failure (denied/throttled) is NOT swallowed as a clean
// empty success: it must return a non-nil error so the scan is visibly incomplete.
func TestNLBScanLoadBalancersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticloadbalancing:DescribeLoadBalancers")
	client := &fakeNLBClient{lbErr: sentinel}
	assets, err := NLBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected non-nil error on DescribeLoadBalancers failure, got nil with %d assets (silent empty success)", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeLoadBalancers failure, got: %v", err)
	}
}

// TestNLBScanListenersErrorSkipsLBNoCrash verifies a per-LB DescribeListeners
// failure does NOT abort the whole scan or panic: the failing LB is skipped and
// the other LBs' listeners are still emitted. The top-level list succeeded, so
// the scan is not wholly incomplete — but the bad LB must not silently corrupt it.
func TestNLBScanListenersErrorSkipsLBNoCrash(t *testing.T) {
	client := &fakeNLBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{
			{LoadBalancers: []elbv2types.LoadBalancer{nlbNetLB("nlb-bad"), nlbNetLB("nlb-good")}},
		},
		listenersErr: map[string]error{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-bad": errors.New("Throttling: rate exceeded"),
		},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-good": {
				Listeners: []elbv2types.Listener{{Port: nlbI32(443), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
		},
	}
	assets, err := NLBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("per-LB DescribeListeners error should not fail the scan, got: %v", err)
	}
	if _, ok := nlbAssetByID(assets, "nlb-good-443"); !ok {
		t.Errorf("expected the healthy LB's listener to survive a sibling LB's error; assets=%v", assets)
	}
	if _, ok := nlbAssetByID(assets, "nlb-bad-443"); ok {
		t.Errorf("did not expect any asset from the LB whose DescribeListeners errored")
	}
}

// TestNLBScanSkipsNonNetworkLBs verifies the scanner filters by LB type: an
// application-type LB in the page must NOT yield an NLB listener asset (ALB has
// its own scanner). A misclassification would double-count and mis-attribute
// posture across the two scanners.
func TestNLBScanSkipsNonNetworkLBs(t *testing.T) {
	alb := elbv2types.LoadBalancer{
		LoadBalancerArn:  nlbStrptr("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/the-alb"),
		LoadBalancerName: nlbStrptr("the-alb"),
		Type:             elbv2types.LoadBalancerTypeEnumApplication,
	}
	client := &fakeNLBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{{LoadBalancers: []elbv2types.LoadBalancer{alb}}},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/the-alb": {
				Listeners: []elbv2types.Listener{{Port: nlbI32(443), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
		},
	}
	assets, err := NLBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected zero assets for an application-type LB (NLB scanner must skip it), got %d: %v", len(assets), assets)
	}
}

// TestNLBScanSkipsNonTLSListeners verifies the listener-protocol filter: a plain
// TCP listener (no SSL policy, Protocol != TLS) must NOT become an asset — it
// carries no transport encryption to classify and inventing a posture for it
// would fabricate a finding. A TLS listener on the SAME NLB, however, MUST be
// emitted: the TCP skip must not silently drop the encrypted sibling.
func TestNLBScanSkipsNonTLSListeners(t *testing.T) {
	client := &fakeNLBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{{LoadBalancers: []elbv2types.LoadBalancer{nlbNetLB("nlb-mixed")}}},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-mixed": {
				Listeners: []elbv2types.Listener{
					{Port: nlbI32(80), Protocol: elbv2types.ProtocolEnumTcp}, // plain TCP, no SSL policy
					{Port: nlbI32(443), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")},
				},
			},
		},
		sslPolicies: map[string]elbv2types.SslPolicy{
			"ELBSecurityPolicy-TLS13-1-2-2021-06": {
				Name:         nlbStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06"),
				SslProtocols: []string{"TLSv1.2", "TLSv1.3"},
				Ciphers:      []elbv2types.Cipher{{Name: nlbStrptr("ECDHE-RSA-AES256-GCM-SHA384"), Priority: nlbI32(1)}},
			},
		},
	}
	assets, err := NLBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if _, ok := nlbAssetByID(assets, "nlb-mixed-80"); ok {
		t.Errorf("a plain TCP listener (no SSL policy) must NOT be emitted as an asset")
	}
	if _, ok := nlbAssetByID(assets, "nlb-mixed-443"); !ok {
		t.Errorf("the TLS listener must survive the TCP-sibling skip; assets=%v", assets)
	}
}

// TestNLBScanPostureHonesty drives the SSL-policy classification through the
// authoritative DescribeSSLPolicies path and asserts the honesty posture for the
// transit domain on NLB TLS listeners:
//   - a TLS 1.0/1.1 policy is legacy-tls (a downgrade-capable policy is NOT clean),
//   - a modern RSA/ECDHE policy is non-pqc-classical,
//   - a PQ policy NAME is pqc-hybrid even though the cipher list is classical
//     (AWS does not enumerate ML-KEM groups; the name is the only config signal),
//   - an unrecognized/custom policy with no describe data is unknown (a guessed
//     1.2 default must NEVER masquerade as a verified classical classification).
func TestNLBScanPostureHonesty(t *testing.T) {
	const legacyPolicy = "ELBSecurityPolicy-TLS-1-0-2015-04"
	const modernPolicy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
	const pqPolicy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
	const customPolicy = "ELBSecurityPolicy-Custom-Future-XYZ"

	client := &fakeNLBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{{LoadBalancers: []elbv2types.LoadBalancer{nlbNetLB("nlb-honesty")}}},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/nlb-honesty": {
				Listeners: []elbv2types.Listener{
					{Port: nlbI32(10), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr(legacyPolicy)},
					{Port: nlbI32(20), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr(modernPolicy)},
					{Port: nlbI32(30), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr(pqPolicy)},
					{Port: nlbI32(40), Protocol: elbv2types.ProtocolEnumTls, SslPolicy: nlbStrptr(customPolicy)},
				},
			},
		},
		// Authoritative DescribeSSLPolicies data for the legacy/modern/pq policies;
		// customPolicy is intentionally absent so it exercises the no-data fallback.
		sslPolicies: map[string]elbv2types.SslPolicy{
			legacyPolicy: {
				Name: nlbStrptr(legacyPolicy),
				// Highest negotiable protocol is TLS 1.0 (a genuinely legacy policy):
				// posture derives from the ceiling, so this is legacy-tls, not
				// classical. The transit honesty contract: a downgrade-only TLS 1.0
				// policy must never read as a clean classical endpoint.
				SslProtocols: []string{"TLSv1"},
				Ciphers:      []elbv2types.Cipher{{Name: nlbStrptr("ECDHE-RSA-AES128-SHA"), Priority: nlbI32(1)}},
			},
			modernPolicy: {
				Name:         nlbStrptr(modernPolicy),
				SslProtocols: []string{"TLSv1.2", "TLSv1.3"},
				Ciphers:      []elbv2types.Cipher{{Name: nlbStrptr("ECDHE-RSA-AES256-GCM-SHA384"), Priority: nlbI32(1)}},
			},
			pqPolicy: {
				Name:         nlbStrptr(pqPolicy),
				SslProtocols: []string{"TLSv1.2", "TLSv1.3"},
				// Cipher list is classical (AWS does NOT enumerate ML-KEM groups);
				// the PQ signal must be derived from the policy NAME.
				Ciphers: []elbv2types.Cipher{{Name: nlbStrptr("ECDHE-RSA-AES256-GCM-SHA384"), Priority: nlbI32(1)}},
			},
		},
	}
	assets, err := NLBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	cases := []struct {
		id          string
		wantPosture models.CryptoPosture
	}{
		{"nlb-honesty-10", models.PostureLegacyTLS},       // TLS 1.0 ceiling -> legacy, never clean
		{"nlb-honesty-20", models.PostureNonPQCClassical}, // RSA/ECDHE classical
		{"nlb-honesty-30", models.PosturePQCHybrid},       // PQ policy name -> hybrid
		{"nlb-honesty-40", models.PostureUnknown},         // unrecognized + no data -> unknown, not classical
	}
	for _, c := range cases {
		a, ok := nlbAssetByID(assets, c.id)
		if !ok {
			t.Errorf("expected an asset %q; assets=%v", c.id, assets)
			continue
		}
		if got := nlbPostureOf(a); got != string(c.wantPosture) {
			t.Errorf("listener %s: posture = %q, want %q", c.id, got, c.wantPosture)
		}
	}

	// A legacy listener must NOT be left without a posture (silent clean pass).
	if a, ok := nlbAssetByID(assets, "nlb-honesty-10"); ok && nlbPostureOf(a) == "" {
		t.Errorf("legacy TLS 1.0 listener has empty posture; a downgrade-capable policy must never read clean")
	}
}
