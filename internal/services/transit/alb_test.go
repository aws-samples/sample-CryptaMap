package transit

import (
	"context"
	"errors"
	"testing"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeALBClient is a hand-rolled albELBV2API for unit-testing the ALB scanner's
// pagination + error propagation + SSL-policy classification without a live AWS
// client. lbPages is returned page-by-page (each DescribeLoadBalancers call
// consumes the next page) with Marker wired so the scanner loops every page;
// listeners maps a LoadBalancerArn to its listeners; listenersErr (keyed by ARN)
// forces a per-LB DescribeListeners failure; sslPolicies maps a policy name to
// the real SslPolicy returned by DescribeSSLPolicies (the authoritative path);
// lbErr / sslErr force top-level failures.
type fakeALBClient struct {
	lbPages      []*elbv2.DescribeLoadBalancersOutput
	lbCalls      int
	lbErr        error
	listeners    map[string]*elbv2.DescribeListenersOutput
	listenersErr map[string]error
	sslPolicies  map[string]elbv2types.SslPolicy
	sslErr       error
}

func (f *fakeALBClient) DescribeLoadBalancers(ctx context.Context, in *elbv2.DescribeLoadBalancersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
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

func (f *fakeALBClient) DescribeListeners(ctx context.Context, in *elbv2.DescribeListenersInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeListenersOutput, error) {
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

func (f *fakeALBClient) DescribeSSLPolicies(ctx context.Context, in *elbv2.DescribeSSLPoliciesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeSSLPoliciesOutput, error) {
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

// albStrptr returns a pointer to s (prefixed to avoid colliding with sibling
// test files in package transit).
func albStrptr(s string) *string { return &s }

// albI32 returns a pointer to v.
func albI32(v int32) *int32 { return &v }

// albAppLB builds an application-type LoadBalancer description.
func albAppLB(name string) elbv2types.LoadBalancer {
	arn := "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/" + name
	return elbv2types.LoadBalancer{
		LoadBalancerArn:  albStrptr(arn),
		LoadBalancerName: albStrptr(name),
		Type:             elbv2types.LoadBalancerTypeEnumApplication,
	}
}

// albAssetByID returns the first asset whose ResourceID equals id (helper local
// to the ALB tests; prefixed to avoid package-wide collisions).
func albAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// albPostureOf reads the posture stamped onto an asset's flat properties.
func albPostureOf(a models.CryptoAsset) string { return a.Properties["posture"] }

// TestALBScanPaginatesLoadBalancers verifies the DescribeLoadBalancers Marker
// loop: a fake returning 2 pages (NextMarker on page 1) must describe BOTH pages'
// load balancers. Without the pagination restore, only the first page survives.
func TestALBScanPaginatesLoadBalancers(t *testing.T) {
	client := &fakeALBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{
			{
				LoadBalancers: []elbv2types.LoadBalancer{albAppLB("alb-page1")},
				NextMarker:    albStrptr("marker-page2"),
			},
			{
				LoadBalancers: []elbv2types.LoadBalancer{albAppLB("alb-page2")},
				// no NextMarker -> last page
			},
		},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/alb-page1": {
				Listeners: []elbv2types.Listener{{Port: albI32(443), SslPolicy: albStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/alb-page2": {
				Listeners: []elbv2types.Listener{{Port: albI32(443), SslPolicy: albStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
		},
	}
	assets, err := ALBScanner{}.scan(context.Background(), client, nil, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.lbCalls != 2 {
		t.Errorf("expected DescribeLoadBalancers to be called 2 times (paginated), got %d", client.lbCalls)
	}
	if _, ok := albAssetByID(assets, "alb-page1-443"); !ok {
		t.Errorf("expected listener asset from page 1; assets=%v", assets)
	}
	if _, ok := albAssetByID(assets, "alb-page2-443"); !ok {
		t.Errorf("expected listener asset from page 2 (pagination dropped it); assets=%v", assets)
	}
}

// TestALBScanLoadBalancersErrorPropagates verifies a top-level
// DescribeLoadBalancers failure (denied/throttled) is NOT swallowed as a clean
// empty success: it must return a non-nil error so the scan is visibly incomplete.
func TestALBScanLoadBalancersErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticloadbalancing:DescribeLoadBalancers")
	client := &fakeALBClient{lbErr: sentinel}
	assets, err := ALBScanner{}.scan(context.Background(), client, nil, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected non-nil error on DescribeLoadBalancers failure, got nil with %d assets (silent empty success)", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeLoadBalancers failure, got: %v", err)
	}
}

// TestALBScanListenersErrorSkipsLBNoCrash verifies a per-LB DescribeListeners
// failure does NOT abort the whole scan or panic: the failing LB is skipped and
// the other LBs' listeners are still emitted. The top-level list succeeded, so
// the scan is not wholly incomplete — but the bad LB must not silently corrupt it.
func TestALBScanListenersErrorSkipsLBNoCrash(t *testing.T) {
	client := &fakeALBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{
			{LoadBalancers: []elbv2types.LoadBalancer{albAppLB("alb-bad"), albAppLB("alb-good")}},
		},
		listenersErr: map[string]error{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/alb-bad": errors.New("Throttling: rate exceeded"),
		},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/alb-good": {
				Listeners: []elbv2types.Listener{{Port: albI32(443), SslPolicy: albStrptr("ELBSecurityPolicy-TLS13-1-2-2021-06")}},
			},
		},
	}
	assets, err := ALBScanner{}.scan(context.Background(), client, nil, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("per-LB DescribeListeners error should not fail the scan, got: %v", err)
	}
	if _, ok := albAssetByID(assets, "alb-good-443"); !ok {
		t.Errorf("expected the healthy LB's listener to survive a sibling LB's error; assets=%v", assets)
	}
	if _, ok := albAssetByID(assets, "alb-bad-443"); ok {
		t.Errorf("did not expect any asset from the LB whose DescribeListeners errored")
	}
}

// TestALBScanSkipsNonApplicationLBs verifies the scanner filters by LB type: a
// network-type LB in the page must NOT yield an ALB listener asset (NLB has its
// own scanner). A misclassification would double-count and mis-attribute posture.
func TestALBScanSkipsNonApplicationLBs(t *testing.T) {
	nlb := elbv2types.LoadBalancer{
		LoadBalancerArn:  albStrptr("arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/the-nlb"),
		LoadBalancerName: albStrptr("the-nlb"),
		Type:             elbv2types.LoadBalancerTypeEnumNetwork,
	}
	client := &fakeALBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{{LoadBalancers: []elbv2types.LoadBalancer{nlb}}},
	}
	assets, err := ALBScanner{}.scan(context.Background(), client, nil, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected zero assets for a network-type LB (ALB scanner must skip it), got %d: %v", len(assets), assets)
	}
}

// TestALBScanPostureHonesty drives the SSL-policy classification through the
// authoritative DescribeSSLPolicies path and asserts the honesty posture for the
// transit domain:
//   - a TLS 1.0/1.1 policy is legacy-tls (plaintext/downgrade-capable is NOT clean),
//   - a PQ policy NAME is pqc-hybrid even though the cipher list is classical,
//   - an unrecognized/custom policy with no describe data is unknown (a guessed
//     1.2 default must NEVER masquerade as a verified classical classification).
func TestALBScanPostureHonesty(t *testing.T) {
	const legacyPolicy = "ELBSecurityPolicy-TLS-1-0-2015-04"
	const modernPolicy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
	const pqPolicy = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
	const customPolicy = "ELBSecurityPolicy-Custom-Future-XYZ"

	client := &fakeALBClient{
		lbPages: []*elbv2.DescribeLoadBalancersOutput{{LoadBalancers: []elbv2types.LoadBalancer{albAppLB("alb-honesty")}}},
		listeners: map[string]*elbv2.DescribeListenersOutput{
			"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/alb-honesty": {
				Listeners: []elbv2types.Listener{
					{Port: albI32(10), SslPolicy: albStrptr(legacyPolicy)},
					{Port: albI32(20), SslPolicy: albStrptr(modernPolicy)},
					{Port: albI32(30), SslPolicy: albStrptr(pqPolicy)},
					{Port: albI32(40), SslPolicy: albStrptr(customPolicy)},
				},
			},
		},
		// Authoritative DescribeSSLPolicies data for the legacy/modern/pq policies;
		// customPolicy is intentionally absent so it exercises the no-data fallback.
		sslPolicies: map[string]elbv2types.SslPolicy{
			legacyPolicy: {
				Name: albStrptr(legacyPolicy),
				// Highest negotiable protocol is TLS 1.0 (a genuinely legacy
				// policy): posture derives from the ceiling, so this is legacy-tls,
				// not classical. The transit honesty contract: a downgrade-only TLS
				// 1.0 policy must never read as a clean classical endpoint.
				SslProtocols: []string{"TLSv1"},
				Ciphers:      []elbv2types.Cipher{{Name: albStrptr("ECDHE-RSA-AES128-SHA"), Priority: albI32(1)}},
			},
			modernPolicy: {
				Name:         albStrptr(modernPolicy),
				SslProtocols: []string{"TLSv1.2", "TLSv1.3"},
				Ciphers:      []elbv2types.Cipher{{Name: albStrptr("ECDHE-RSA-AES256-GCM-SHA384"), Priority: albI32(1)}},
			},
			pqPolicy: {
				Name:         albStrptr(pqPolicy),
				SslProtocols: []string{"TLSv1.2", "TLSv1.3"},
				// Cipher list is classical (AWS does NOT enumerate ML-KEM groups);
				// the PQ signal must be derived from the policy NAME.
				Ciphers: []elbv2types.Cipher{{Name: albStrptr("ECDHE-RSA-AES256-GCM-SHA384"), Priority: albI32(1)}},
			},
		},
	}
	assets, err := ALBScanner{}.scan(context.Background(), client, nil, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	cases := []struct {
		id          string
		wantPosture models.CryptoPosture
	}{
		{"alb-honesty-10", models.PostureLegacyTLS},       // TLS 1.0 ceiling -> legacy, never clean
		{"alb-honesty-20", models.PostureNonPQCClassical}, // RSA/ECDHE classical
		{"alb-honesty-30", models.PosturePQCHybrid},       // PQ policy name -> hybrid
		{"alb-honesty-40", models.PostureUnknown},         // unrecognized + no data -> unknown, not classical
	}
	for _, c := range cases {
		a, ok := albAssetByID(assets, c.id)
		if !ok {
			t.Errorf("expected an asset %q; assets=%v", c.id, assets)
			continue
		}
		if got := albPostureOf(a); got != string(c.wantPosture) {
			t.Errorf("listener %s: posture = %q, want %q", c.id, got, c.wantPosture)
		}
	}

	// A legacy listener must NOT be left without a posture (silent clean pass).
	if a, ok := albAssetByID(assets, "alb-honesty-10"); ok && albPostureOf(a) == "" {
		t.Errorf("legacy TLS 1.0 listener has empty posture; a downgrade-capable policy must never read clean")
	}
}
