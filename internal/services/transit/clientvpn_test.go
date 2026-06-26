package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeClientVPNEC2Client is a hand-rolled clientVPNEC2API for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err forces a top-level
// DescribeClientVpnEndpoints failure.
type fakeClientVPNEC2Client struct {
	clientvpnPages []*ec2.DescribeClientVpnEndpointsOutput
	clientvpnCalls int
	clientvpnErr   error
}

func (f *fakeClientVPNEC2Client) DescribeClientVpnEndpoints(ctx context.Context, in *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error) {
	if f.clientvpnErr != nil {
		return nil, f.clientvpnErr
	}
	if f.clientvpnCalls >= len(f.clientvpnPages) {
		return &ec2.DescribeClientVpnEndpointsOutput{}, nil
	}
	out := f.clientvpnPages[f.clientvpnCalls]
	f.clientvpnCalls++
	return out, nil
}

func clientvpnStrptr(s string) *string { return &s }

func clientvpnAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestClientVPNScanPaginates verifies the DescribeClientVpnEndpoints NextToken
// loop: a fake that returns 2 pages (NextToken on page 1) must yield BOTH pages'
// endpoints as assets. Without the pagination loop, only the first page's
// endpoint survives — silently dropping endpoints in dense accounts.
func TestClientVPNScanPaginates(t *testing.T) {
	client := &fakeClientVPNEC2Client{
		clientvpnPages: []*ec2.DescribeClientVpnEndpointsOutput{
			{
				ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{ClientVpnEndpointId: clientvpnStrptr("cvpn-endpoint-page1")},
				},
				NextToken: clientvpnStrptr("tok-page2"),
			},
			{
				ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{ClientVpnEndpointId: clientvpnStrptr("cvpn-endpoint-page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := ClientVPNScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.clientvpnCalls; c != 2 {
		t.Errorf("expected DescribeClientVpnEndpoints to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"cvpn-endpoint-page1", "cvpn-endpoint-page2"} {
		if _, ok := clientvpnAssetByID(assets, want); !ok {
			t.Errorf("expected endpoint %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestClientVPNScanErrorPropagates verifies the owner's incompleteness decision:
// a DescribeClientVpnEndpoints failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestClientVPNScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("UnauthorizedOperation: not authorized to perform ec2:DescribeClientVpnEndpoints")
	client := &fakeClientVPNEC2Client{clientvpnErr: sentinel}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := ClientVPNScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when DescribeClientVpnEndpoints fails, got nil with %d assets (silent empty success)", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClientVpnEndpoints failure, got: %v", err)
	}
}

// TestClientVPNScanHonestPosture verifies the domain honesty posture: Client VPN
// is OpenVPN-over-TLS with a MANDATORY classical server cert + classical key
// exchange and NO AWS PQ-hybrid option, so every endpoint must be classified
// NonPQCClassical (a quantum-migration target) — never NoEncryption (the
// transport IS always encrypted) and never a quantum-resistant / clean posture.
func TestClientVPNScanHonestPosture(t *testing.T) {
	client := &fakeClientVPNEC2Client{
		clientvpnPages: []*ec2.DescribeClientVpnEndpointsOutput{
			{
				ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{
						ClientVpnEndpointId: clientvpnStrptr("cvpn-endpoint-tls"),
						TransportProtocol:   ec2types.TransportProtocolUdp,
						AuthenticationOptions: []ec2types.ClientVpnAuthentication{
							{Type: ec2types.ClientVpnAuthenticationTypeCertificateAuthentication},
						},
						ServerCertificateArn: clientvpnStrptr("arn:aws:acm:us-east-1:111122223333:certificate/abc"),
					},
				},
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := ClientVPNScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := clientvpnAssetByID(assets, "cvpn-endpoint-tls")
	if !ok {
		t.Fatalf("expected an asset for endpoint cvpn-endpoint-tls; assets=%v", assets)
	}
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("Client VPN endpoint must be posture %q (classical TLS, no PQ option), got %q (must never be NoEncryption or a clean/quantum-resistant posture)",
			models.PostureNonPQCClassical, got)
	}
	// Mandatory-encryption posture must never collapse to a no-encryption claim.
	if a.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Errorf("Client VPN transport is always TLS-encrypted; posture must NOT be %q", models.PostureNoEncryption)
	}
	// The honest "no PQ option today" note must accompany the asset.
	if a.Properties["note"] == "" {
		t.Errorf("expected the quantum-migration-target note to be stamped on the Client VPN asset")
	}
	// Crypto-surface evidence read from the endpoint must be preserved (not dropped).
	if got := a.Properties["transportProtocol"]; got != string(ec2types.TransportProtocolUdp) {
		t.Errorf("expected transportProtocol %q to be recorded, got %q", ec2types.TransportProtocolUdp, got)
	}
	if got := a.Properties["serverCertificateArn"]; got == "" {
		t.Errorf("expected serverCertificateArn evidence to be recorded on the asset")
	}
}

// TestClientVPNScanSkipsNilEndpointID verifies an endpoint with a nil
// ClientVpnEndpointId is skipped (no panic, no bogus empty-ID asset) while valid
// siblings on the same page are still emitted — a malformed entry must not drop
// the rest of the page.
func TestClientVPNScanSkipsNilEndpointID(t *testing.T) {
	client := &fakeClientVPNEC2Client{
		clientvpnPages: []*ec2.DescribeClientVpnEndpointsOutput{
			{
				ClientVpnEndpoints: []ec2types.ClientVpnEndpoint{
					{ClientVpnEndpointId: nil},
					{ClientVpnEndpointId: clientvpnStrptr("cvpn-endpoint-valid")},
				},
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := ClientVPNScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil-ID skipped, valid kept), got %d: %v", len(assets), assets)
	}
	if _, ok := clientvpnAssetByID(assets, "cvpn-endpoint-valid"); !ok {
		t.Errorf("expected the valid sibling endpoint to survive a nil-ID entry; assets=%v", assets)
	}
}
