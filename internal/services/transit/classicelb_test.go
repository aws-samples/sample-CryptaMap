package transit

import (
	"context"
	"errors"
	"testing"

	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeClassicELBClient is a hand-rolled classicELBAPI for unit-testing the
// scanner's pagination + error propagation + policy classification without a
// live AWS client. pages is returned page-by-page (each call consumes the next
// page) and the NextMarker is wired so the scanner loops through every page; err
// forces a DescribeLoadBalancers failure on the call indexed by errOnCall.
// classicelbPolicies maps a policy name to its real PolicyDescription (the
// authoritative Protocol-* attributes read by DescribeLoadBalancerPolicies);
// classicelbPoliciesErr forces that describe to fail.
type fakeClassicELBClient struct {
	classicelbPages       []*elb.DescribeLoadBalancersOutput
	classicelbCalls       int
	classicelbErr         error
	classicelbErrOnCall   int
	classicelbPolicies    map[string]elbtypes.PolicyDescription
	classicelbPoliciesErr error
	classicelbPolicyCalls int
}

func (f *fakeClassicELBClient) DescribeLoadBalancers(ctx context.Context, in *elb.DescribeLoadBalancersInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	call := f.classicelbCalls
	f.classicelbCalls++
	if f.classicelbErr != nil && call == f.classicelbErrOnCall {
		return nil, f.classicelbErr
	}
	if call >= len(f.classicelbPages) {
		return &elb.DescribeLoadBalancersOutput{}, nil
	}
	return f.classicelbPages[call], nil
}

func (f *fakeClassicELBClient) DescribeLoadBalancerPolicies(ctx context.Context, in *elb.DescribeLoadBalancerPoliciesInput, optFns ...func(*elb.Options)) (*elb.DescribeLoadBalancerPoliciesOutput, error) {
	f.classicelbPolicyCalls++
	if f.classicelbPoliciesErr != nil {
		return nil, f.classicelbPoliciesErr
	}
	out := &elb.DescribeLoadBalancerPoliciesOutput{}
	for _, name := range in.PolicyNames {
		if pd, ok := f.classicelbPolicies[name]; ok {
			out.PolicyDescriptions = append(out.PolicyDescriptions, pd)
		}
	}
	return out, nil
}

// classicelbPolicyDesc builds a PolicyDescription whose Protocol-* attributes
// enable exactly the named protocols (e.g. "Protocol-TLSv1.2").
func classicelbPolicyDesc(name string, enabledProtocols ...string) elbtypes.PolicyDescription {
	attrs := make([]elbtypes.PolicyAttributeDescription, 0, len(enabledProtocols))
	trueVal := "true"
	for i := range enabledProtocols {
		attrs = append(attrs, elbtypes.PolicyAttributeDescription{
			AttributeName:  &enabledProtocols[i],
			AttributeValue: &trueVal,
		})
	}
	typeName := "SSLNegotiationPolicyType"
	return elbtypes.PolicyDescription{
		PolicyName:                  classicelbStrptr(name),
		PolicyTypeName:              &typeName,
		PolicyAttributeDescriptions: attrs,
	}
}

func classicelbStrptr(s string) *string { return &s }

// classicelbListener builds a ListenerDescription with the given protocol/port,
// optional policy names, and optional SSL cert id.
func classicelbListener(proto string, port int32, certID string, policies ...string) elbtypes.ListenerDescription {
	l := &elbtypes.Listener{
		Protocol:         classicelbStrptr(proto),
		LoadBalancerPort: port,
	}
	if certID != "" {
		l.SSLCertificateId = classicelbStrptr(certID)
	}
	return elbtypes.ListenerDescription{
		Listener:    l,
		PolicyNames: policies,
	}
}

// classicelbAssetByID indexes scan output by ResourceID for assertions.
func classicelbAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// classicelbPostureOf extracts the posture property string from an asset.
func classicelbPostureOf(a models.CryptoAsset) string {
	if a.Properties == nil {
		return ""
	}
	return a.Properties["posture"]
}

// TestClassicELBScanPaginates verifies the DescribeLoadBalancers Marker loop: a
// fake that returns 2 pages (NextMarker on page 1) must yield listeners from BOTH
// pages as assets. Without the pagination loop, only the first page survives.
func TestClassicELBScanPaginates(t *testing.T) {
	client := &fakeClassicELBClient{
		classicelbPages: []*elb.DescribeLoadBalancersOutput{
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName:     classicelbStrptr("lb-page1"),
						ListenerDescriptions: []elbtypes.ListenerDescription{classicelbListener("HTTPS", 443, "", "ELBSecurityPolicy-2016-08")},
					},
				},
				NextMarker: classicelbStrptr("marker-page2"),
			},
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName:     classicelbStrptr("lb-page2"),
						ListenerDescriptions: []elbtypes.ListenerDescription{classicelbListener("HTTPS", 443, "", "ELBSecurityPolicy-2016-08")},
					},
				},
				// no NextMarker -> last page
			},
		},
	}
	assets, err := ClassicELBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.classicelbCalls; c != 2 {
		t.Errorf("expected DescribeLoadBalancers to be called 2 times (paginated), got %d", c)
	}
	got := classicelbAssetByID(assets)
	for _, want := range []string{"lb-page1-443", "lb-page2-443"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected listener %q from a paginated page to appear as an asset; assets=%v", want, classicelbKeysOf(got))
		}
	}
}

// classicelbKeysOf is a tiny local helper for error messages (prefixed-free name avoided by
// keeping it unexported + scanner-specific via classicelb prefix on the wrapper).
func classicelbKeysOf(m map[string]models.CryptoAsset) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestClassicELBScanErrorPropagates verifies the owner's incompleteness decision:
// a DescribeLoadBalancers failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestClassicELBScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticloadbalancing:DescribeLoadBalancers")
	client := &fakeClassicELBClient{
		classicelbErr:       sentinel,
		classicelbErrOnCall: 0,
	}
	assets, err := ClassicELBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeLoadBalancers fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeLoadBalancers failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on error, got %d", len(assets))
	}
}

// TestClassicELBScanErrorOnSecondPage verifies the error is NOT swallowed even
// after the first page succeeded — a mid-pagination failure must still surface.
func TestClassicELBScanErrorOnSecondPage(t *testing.T) {
	sentinel := errors.New("ThrottlingException")
	client := &fakeClassicELBClient{
		classicelbPages: []*elb.DescribeLoadBalancersOutput{
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName:     classicelbStrptr("lb-page1"),
						ListenerDescriptions: []elbtypes.ListenerDescription{classicelbListener("HTTPS", 443, "", "ELBSecurityPolicy-2016-08")},
					},
				},
				NextMarker: classicelbStrptr("marker-page2"),
			},
		},
		classicelbErr:       sentinel,
		classicelbErrOnCall: 1,
	}
	_, err := ClassicELBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when the 2nd page fails, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the page-2 failure, got: %v", err)
	}
}

// TestClassicELBHonestyPosture pins the transit honesty contract per listener type,
// classified from the REAL DescribeLoadBalancerPolicies Protocol-* attributes:
//   - plaintext (HTTP/TCP) -> NoEncryption, a VERIFIED finding, never Unknown/clean;
//   - HTTPS whose policy attributes enable only TLS 1.2 -> NonPQCClassical
//     (Classic ELB has no PQC), never NoEncryption and never PQC;
//   - SSL whose policy attributes enable TLS 1.0 -> LegacyTLS, never clean 1.2;
//   - HTTPS whose policy has NO describe data (custom/unreadable) -> Unknown with
//     a note — a policy the scanner cannot read must NEVER be asserted classical.
func TestClassicELBHonestyPosture(t *testing.T) {
	client := &fakeClassicELBClient{
		classicelbPages: []*elb.DescribeLoadBalancersOutput{
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName: classicelbStrptr("lb"),
						ListenerDescriptions: []elbtypes.ListenerDescription{
							classicelbListener("HTTP", 80, ""),                                        // plaintext
							classicelbListener("TCP", 9000, ""),                                       // plaintext
							classicelbListener("HTTPS", 443, "arn:cert", "ELBSecurityPolicy-2016-08"), // modern classical (proven by attributes)
							classicelbListener("SSL", 8443, "", "ELBSecurityPolicy-TLS-1-0-2015-04"),  // legacy floor (proven by attributes)
							classicelbListener("HTTPS", 8444, "", "my-custom-policy"),                 // custom, no describe data
						},
					},
				},
			},
		},
		classicelbPolicies: map[string]elbtypes.PolicyDescription{
			"ELBSecurityPolicy-2016-08":         classicelbPolicyDesc("ELBSecurityPolicy-2016-08", "Protocol-TLSv1.2"),
			"ELBSecurityPolicy-TLS-1-0-2015-04": classicelbPolicyDesc("ELBSecurityPolicy-TLS-1-0-2015-04", "Protocol-TLSv1"),
			// my-custom-policy is intentionally absent: no readable attributes.
		},
	}
	assets, err := ClassicELBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	by := classicelbAssetByID(assets)

	// Plaintext HTTP listener: verified no-encryption, not Unknown.
	http80, ok := by["lb-80"]
	if !ok {
		t.Fatalf("expected plaintext HTTP listener asset lb-80; assets=%v", classicelbKeysOf(by))
	}
	if p := classicelbPostureOf(http80); p != string(models.PostureNoEncryption) {
		t.Errorf("plaintext HTTP listener: expected posture %q (verified no-encryption), got %q", models.PostureNoEncryption, p)
	}
	if http80.Properties["note"] == "" {
		t.Errorf("plaintext HTTP listener: expected a note explaining the no-TLS finding, got empty")
	}

	// Plaintext TCP listener: same verified no-encryption posture.
	if tcp, ok := by["lb-9000"]; !ok {
		t.Errorf("expected plaintext TCP listener asset lb-9000")
	} else if p := classicelbPostureOf(tcp); p != string(models.PostureNoEncryption) {
		t.Errorf("plaintext TCP listener: expected posture %q, got %q", models.PostureNoEncryption, p)
	}

	// HTTPS listener with attribute-PROVEN TLS 1.2-only policy: encrypted
	// classical (Classic ELB has no PQC), NOT NoEncryption and NOT PQC, and
	// stamped observed because the classification came from real API attributes.
	https443, ok := by["lb-443"]
	if !ok {
		t.Fatalf("expected HTTPS listener asset lb-443")
	}
	if p := classicelbPostureOf(https443); p != string(models.PostureNonPQCClassical) {
		t.Errorf("TLS1.2-proven HTTPS listener: expected posture %q, got %q", models.PostureNonPQCClassical, p)
	}
	if https443.Properties["source"] != "observed" {
		t.Errorf("attribute-proven classification must be stamped observed, got source=%q", https443.Properties["source"])
	}
	if https443.Properties["sslCertificateId"] != "arn:cert" {
		t.Errorf("expected sslCertificateId surfaced on HTTPS listener, got %q", https443.Properties["sslCertificateId"])
	}

	// Legacy SSL listener whose attributes enable TLS 1.0: must surface as
	// LegacyTLS, never as a clean modern 1.2 classical.
	ssl8443, ok := by["lb-8443"]
	if !ok {
		t.Fatalf("expected legacy SSL listener asset lb-8443")
	}
	if p := classicelbPostureOf(ssl8443); p != string(models.PostureLegacyTLS) {
		t.Errorf("legacy-floor SSL listener: expected posture %q, got %q", models.PostureLegacyTLS, p)
	}

	// Custom/unreadable policy: HONESTY pin — the old scanner asserted
	// NonPQCClassical for any policy it could not recognize; it must now stay
	// Unknown with a note naming what could not be read.
	custom, ok := by["lb-8444"]
	if !ok {
		t.Fatalf("expected custom-policy listener asset lb-8444")
	}
	if p := classicelbPostureOf(custom); p != string(models.PostureUnknown) {
		t.Errorf("custom/unreadable policy: expected posture %q (never a fabricated classical), got %q", models.PostureUnknown, p)
	}
	if custom.Properties["note"] == "" {
		t.Errorf("custom/unreadable policy: expected a note naming what could not be read, got empty")
	}
	if custom.Properties["source"] == "observed" {
		t.Errorf("unreadable policy must NOT be stamped observed")
	}
}

// TestClassicELBPolicyDescribeErrorStaysUnknown pins the failure path: when
// DescribeLoadBalancerPolicies errors (denied/throttled), the TLS listener's
// posture must be Unknown with a note — NOT a fabricated NonPQCClassical.
func TestClassicELBPolicyDescribeErrorStaysUnknown(t *testing.T) {
	client := &fakeClassicELBClient{
		classicelbPages: []*elb.DescribeLoadBalancersOutput{
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName:     classicelbStrptr("lb"),
						ListenerDescriptions: []elbtypes.ListenerDescription{classicelbListener("HTTPS", 443, "", "ELBSecurityPolicy-2016-08")},
					},
				},
			},
		},
		classicelbPoliciesErr: errors.New("AccessDeniedException: not authorized to perform elasticloadbalancing:DescribeLoadBalancerPolicies"),
	}
	assets, err := ClassicELBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-policy describe error must not fail the scan, got: %v", err)
	}
	by := classicelbAssetByID(assets)
	a, ok := by["lb-443"]
	if !ok {
		t.Fatalf("expected the listener asset to still be emitted; assets=%v", classicelbKeysOf(by))
	}
	if p := classicelbPostureOf(a); p != string(models.PostureUnknown) {
		t.Errorf("describe-failed policy: expected posture %q, got %q", models.PostureUnknown, p)
	}
	if a.Properties["note"] == "" {
		t.Errorf("describe-failed policy: expected a note naming DescribeLoadBalancerPolicies, got empty")
	}
}

// TestClassicELBLegacyFloorUnderModernCeilingWarns pins the downgrade case: a
// policy enabling TLSv1 AND TLSv1.2 has a modern ceiling but a legacy floor.
// Mirroring the ELBv2 sibling (classifySSLPolicy), the posture credits the real
// ceiling (NonPQCClassical) but the legacy 1.0 floor MUST surface as a warning
// and as TLSMinVersion — never a silently clean 1.2.
func TestClassicELBLegacyFloorUnderModernCeilingWarns(t *testing.T) {
	client := &fakeClassicELBClient{
		classicelbPages: []*elb.DescribeLoadBalancersOutput{
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName:     classicelbStrptr("lb"),
						ListenerDescriptions: []elbtypes.ListenerDescription{classicelbListener("HTTPS", 443, "", "wide-policy")},
					},
				},
			},
		},
		classicelbPolicies: map[string]elbtypes.PolicyDescription{
			"wide-policy": classicelbPolicyDesc("wide-policy", "Protocol-TLSv1", "Protocol-TLSv1.1", "Protocol-TLSv1.2"),
		},
	}
	assets, err := ClassicELBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	by := classicelbAssetByID(assets)
	a, ok := by["lb-443"]
	if !ok {
		t.Fatalf("expected listener asset lb-443; assets=%v", classicelbKeysOf(by))
	}
	if p := classicelbPostureOf(a); p != string(models.PostureNonPQCClassical) {
		t.Errorf("legacy-floor + modern-ceiling policy: expected posture %q (ceiling credit), got %q", models.PostureNonPQCClassical, p)
	}
	if a.Properties["warning"] == "" {
		t.Errorf("legacy-floor + modern-ceiling policy: expected a downgrade warning, got empty")
	}
	if pp := a.CryptoProps.ProtocolProperties; pp == nil || pp.TLSMinVersion != "1.0" {
		t.Errorf("legacy-floor + modern-ceiling policy: expected TLSMinVersion 1.0 surfaced, got %+v", pp)
	}
}

// TestClassicELBPolicyDescribeCached verifies the per-(LB,policy) cache: two
// listeners on the same LB sharing one policy must cost a single
// DescribeLoadBalancerPolicies call.
func TestClassicELBPolicyDescribeCached(t *testing.T) {
	client := &fakeClassicELBClient{
		classicelbPages: []*elb.DescribeLoadBalancersOutput{
			{
				LoadBalancerDescriptions: []elbtypes.LoadBalancerDescription{
					{
						LoadBalancerName: classicelbStrptr("lb"),
						ListenerDescriptions: []elbtypes.ListenerDescription{
							classicelbListener("HTTPS", 443, "", "shared-policy"),
							classicelbListener("SSL", 8443, "", "shared-policy"),
						},
					},
				},
			},
		},
		classicelbPolicies: map[string]elbtypes.PolicyDescription{
			"shared-policy": classicelbPolicyDesc("shared-policy", "Protocol-TLSv1.2"),
		},
	}
	if _, err := (ClassicELBScanner{}).scan(context.Background(), client, "111122223333", "us-east-1"); err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.classicelbPolicyCalls != 1 {
		t.Errorf("expected 1 DescribeLoadBalancerPolicies call for a shared policy (cached), got %d", client.classicelbPolicyCalls)
	}
}
