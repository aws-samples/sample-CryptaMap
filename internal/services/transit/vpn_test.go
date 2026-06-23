package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeVPNEC2Client is a hand-rolled vpnEC2API for unit-testing the VPN scanner's
// core without a live AWS client. out is returned verbatim from
// DescribeVpnConnections (so tests drive the per-connection classification), and
// err forces a top-level list failure to exercise the no-silent-drop path.
type fakeVPNEC2Client struct {
	out   *ec2.DescribeVpnConnectionsOutput
	err   error
	calls int
}

func (f *fakeVPNEC2Client) DescribeVpnConnections(ctx context.Context, in *ec2.DescribeVpnConnectionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpnConnectionsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if f.out != nil {
		return f.out, nil
	}
	return &ec2.DescribeVpnConnectionsOutput{}, nil
}

func vpnStrptr(s string) *string { return &s }
func vpnI32ptr(i int32) *int32   { return &i }

// vpnAssetByID returns the asset with the given ResourceID, or false.
func vpnAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

func vpnPostureOf(a models.CryptoAsset) string { return a.Properties["posture"] }

// vpnTunnel builds a TunnelOption populated with the negotiated algorithms a
// real DescribeVpnConnections would return, exercising extractVPNTunnelAlgos +
// classifyVPNTunnel.
func vpnTunnel(p1Enc, p2Enc, p1Int, p2Int string, dh int32, ike string) ec2types.TunnelOption {
	return ec2types.TunnelOption{
		Phase1EncryptionAlgorithms: []ec2types.Phase1EncryptionAlgorithmsListValue{{Value: vpnStrptr(p1Enc)}},
		Phase2EncryptionAlgorithms: []ec2types.Phase2EncryptionAlgorithmsListValue{{Value: vpnStrptr(p2Enc)}},
		Phase1IntegrityAlgorithms:  []ec2types.Phase1IntegrityAlgorithmsListValue{{Value: vpnStrptr(p1Int)}},
		Phase2IntegrityAlgorithms:  []ec2types.Phase2IntegrityAlgorithmsListValue{{Value: vpnStrptr(p2Int)}},
		Phase1DHGroupNumbers:       []ec2types.Phase1DHGroupNumbersListValue{{Value: vpnI32ptr(dh)}},
		IkeVersions:                []ec2types.IKEVersionsListValue{{Value: vpnStrptr(ike)}},
	}
}

// TestVPNScanListError verifies the no-silent-drop posture: a
// DescribeVpnConnections failure (denied/throttled) must make the scan VISIBLY
// incomplete by returning a non-nil error that wraps the cause — NOT a clean
// empty success.
func TestVPNScanListError(t *testing.T) {
	sentinel := errors.New("UnauthorizedOperation: not authorized to perform ec2:DescribeVpnConnections")
	client := &fakeVPNEC2Client{err: sentinel}
	assets, err := VPNScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeVpnConnections fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeVpnConnections failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on error, got %d", len(assets))
	}
}

// TestVPNScanEnumeratesConnections verifies every returned VPN connection
// becomes an asset (no silent drop), that a nil VpnConnectionId is skipped
// without aborting, and that accountID/region/resourceType are stamped.
func TestVPNScanEnumeratesConnections(t *testing.T) {
	client := &fakeVPNEC2Client{
		out: &ec2.DescribeVpnConnectionsOutput{
			VpnConnections: []ec2types.VpnConnection{
				{
					VpnConnectionId: vpnStrptr("vpn-aaa"),
					Options: &ec2types.VpnConnectionOptions{
						TunnelOptions: []ec2types.TunnelOption{
							vpnTunnel("AES256", "AES256", "SHA2-256", "SHA2-256", 20, "ikev2"),
						},
					},
				},
				{VpnConnectionId: nil}, // must be skipped, not panic / abort
				{
					VpnConnectionId: vpnStrptr("vpn-bbb"),
					// no Options -> backward-compatible fallback path
				},
			},
		},
	}
	assets, err := VPNScanner{}.scan(context.Background(), client, "111122223333", "ap-south-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets (nil-id connection skipped), got %d", len(assets))
	}
	for _, want := range []string{"vpn-aaa", "vpn-bbb"} {
		a, ok := vpnAssetByID(assets, want)
		if !ok {
			t.Fatalf("expected VPN connection %q to appear as an asset", want)
		}
		if a.ResourceType != "AWS::EC2::VPNConnection" {
			t.Errorf("%s: expected resourceType AWS::EC2::VPNConnection, got %q", want, a.ResourceType)
		}
		if a.AccountID != "111122223333" {
			t.Errorf("%s: expected accountID stamped, got %q", want, a.AccountID)
		}
		if a.Region != "ap-south-1" {
			t.Errorf("%s: expected region stamped, got %q", want, a.Region)
		}
	}
}

// TestVPNScanHonestyPosture verifies the domain honesty rule: an IPsec VPN is
// ALWAYS encrypted (it transports encrypted traffic), and its classical DH
// groups (20/21/24 are ECP/MODP, not post-quantum) mean the posture is
// non-pqc-classical — never no-encryption and never falsely pqc-hybrid. This
// holds for both the observed-tunnel path and the fallback path.
func TestVPNScanHonestyPosture(t *testing.T) {
	client := &fakeVPNEC2Client{
		out: &ec2.DescribeVpnConnectionsOutput{
			VpnConnections: []ec2types.VpnConnection{
				{
					VpnConnectionId: vpnStrptr("vpn-observed"),
					Options: &ec2types.VpnConnectionOptions{
						TunnelOptions: []ec2types.TunnelOption{
							vpnTunnel("AES256-GCM-16", "AES256-GCM-16", "SHA2-512", "SHA2-512", 21, "ikev2"),
						},
					},
				},
				{
					VpnConnectionId: vpnStrptr("vpn-fallback"),
					// nil Options -> fallback to ipsec / AES-256-GCM
				},
			},
		},
	}
	assets, err := VPNScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	for _, want := range []string{"vpn-observed", "vpn-fallback"} {
		a, ok := vpnAssetByID(assets, want)
		if !ok {
			t.Fatalf("expected asset %q", want)
		}
		if p := vpnPostureOf(a); p != string(models.PostureNonPQCClassical) {
			t.Errorf("%s: IPsec VPN must be non-pqc-classical (encrypted, classical DH), got %q", want, p)
		}
		if vpnPostureOf(a) == string(models.PostureNoEncryption) {
			t.Errorf("%s: IPsec VPN must never be reported as no-encryption", want)
		}
		if a.CryptoProps.ProtocolProperties == nil {
			t.Fatalf("%s: expected ProtocolProperties to be populated", want)
		}
		if a.CryptoProps.ProtocolProperties.Type != "ipsec" {
			t.Errorf("%s: expected protocol Type ipsec, got %q", want, a.CryptoProps.ProtocolProperties.Type)
		}
	}

	// The observed connection must carry the real negotiated algorithms +
	// classical DH-group KEX label, not fabricated defaults.
	obs, _ := vpnAssetByID(assets, "vpn-observed")
	kex := obs.CryptoProps.ProtocolProperties.KeyExchangeGroup
	if kex != "DH-group-21" {
		t.Errorf("expected observed KeyExchangeGroup DH-group-21 from tunnel data, got %q", kex)
	}
	if obs.CryptoProps.ProtocolProperties.PQCHybrid {
		t.Errorf("classical DH group 21 must NOT be classified as PQC-hybrid")
	}
}
