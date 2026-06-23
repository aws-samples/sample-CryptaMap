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
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextMarker is
// wired so the scanner loops through every page; err forces a
// DescribeLoadBalancers failure on the call indexed by errOnCall.
type fakeClassicELBClient struct {
	classicelbPages     []*elb.DescribeLoadBalancersOutput
	classicelbCalls     int
	classicelbErr       error
	classicelbErrOnCall int
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

// TestClassicELBHonestyPosture pins the transit honesty contract per listener type:
//   - plaintext (HTTP/TCP) -> NoEncryption, a VERIFIED finding, never Unknown/clean;
//   - HTTPS with a legacy-floor policy name (TLS 1.0) -> LegacyTLS, never clean 1.2;
//   - HTTPS with a modern policy name -> NonPQCClassical (Classic ELB has no PQC),
//     never NoEncryption (it IS encrypted) and never PQC.
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
							classicelbListener("HTTPS", 443, "arn:cert", "ELBSecurityPolicy-2016-08"), // modern classical
							classicelbListener("SSL", 8443, "", "ELBSecurityPolicy-TLS-1-0-2015-04"),  // legacy floor
						},
					},
				},
			},
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

	// Modern HTTPS listener: encrypted classical (Classic ELB has no PQC), NOT
	// NoEncryption and NOT PQC.
	https443, ok := by["lb-443"]
	if !ok {
		t.Fatalf("expected HTTPS listener asset lb-443")
	}
	if p := classicelbPostureOf(https443); p != string(models.PostureNonPQCClassical) {
		t.Errorf("modern HTTPS listener: expected posture %q, got %q", models.PostureNonPQCClassical, p)
	}
	if p := classicelbPostureOf(https443); p == string(models.PostureNoEncryption) {
		t.Errorf("modern HTTPS listener must NOT be classified NoEncryption — it is encrypted")
	}
	if https443.Properties["sslCertificateId"] != "arn:cert" {
		t.Errorf("expected sslCertificateId surfaced on HTTPS listener, got %q", https443.Properties["sslCertificateId"])
	}

	// Legacy-floor SSL listener: must surface as LegacyTLS (TLS 1.0), never as a
	// clean modern 1.2 classical.
	ssl8443, ok := by["lb-8443"]
	if !ok {
		t.Fatalf("expected legacy SSL listener asset lb-8443")
	}
	if p := classicelbPostureOf(ssl8443); p != string(models.PostureLegacyTLS) {
		t.Errorf("legacy-floor SSL listener: expected posture %q, got %q", models.PostureLegacyTLS, p)
	}
}
