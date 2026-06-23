package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// VPNScanner discovers Site-to-Site VPN connections (IPsec, not TLS).
type VPNScanner struct{}

func (VPNScanner) Name() string              { return "vpn" }
func (VPNScanner) Category() models.Category { return models.CategoryDataInTransit }

// vpnEC2API is the minimal slice of the ec2 client this scanner uses.
// DescribeVpnConnections returns all Site-to-Site VPN connections in a single
// call (the EC2 API has no required pagination loop here), so the interface
// names only that one method. Defining it as an interface keeps the error
// propagation + classification logic unit-testable with a fake (the concrete
// *ec2.Client satisfies it).
type vpnEC2API interface {
	DescribeVpnConnections(ctx context.Context, in *ec2.DescribeVpnConnectionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpnConnectionsOutput, error)
}

func (s VPNScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it lists VPN connections and classifies each
// into a CryptoAsset. A DescribeVpnConnections error is NOT swallowed — it is
// returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s VPNScanner) scan(ctx context.Context, client vpnEC2API, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("vpn DescribeVpnConnections: %w", err)
	}
	assets := []models.CryptoAsset{}
	for _, v := range out.VpnConnections {
		if v.VpnConnectionId == nil {
			continue
		}

		var props models.CryptoProperties
		if v.Options != nil && len(v.Options.TunnelOptions) > 0 {
			// Deepen: read the real negotiated IKE/IPsec algorithms across all
			// tunnels rather than fabricating AES-256-GCM. Pointers in the SDK
			// types can be nil, so every deref is guarded.
			p1Enc, p2Enc, p1Int, p2Int, dh, ike := extractVPNTunnelAlgos(v.Options.TunnelOptions)
			props = classifyVPNTunnel(p1Enc, p2Enc, p1Int, p2Int, dh, ike)
		} else {
			// Backward-compatible fallback when no tunnel options are present.
			props = services.TLSProtocolProps("ipsec", "AES-256-GCM")
			props.ProtocolProperties.Type = "ipsec"
		}

		a := services.NewAsset("vpn", models.CategoryDataInTransit, accountID, region, *v.VpnConnectionId, "AWS::EC2::VPNConnection", props)
		// VPN/IPsec has no PQ KEX option today (DH groups 20/21/24 are classical),
		// so the posture remains classical — but now reflects observed algorithms.
		services.PostureProperty(&a, models.PostureNonPQCClassical)
		assets = append(assets, a)
	}
	return assets, nil
}

// extractVPNTunnelAlgos nil-safely collects the phase 1/2 encryption and
// integrity algorithm names, DH group numbers, and IKE versions across all of a
// VPN connection's tunnels, returning plain Go slices for classifyVPNTunnel.
func extractVPNTunnelAlgos(tunnels []ec2types.TunnelOption) (p1Enc, p2Enc, p1Int, p2Int []string, dh []int32, ike []string) {
	for _, t := range tunnels {
		for _, e := range t.Phase1EncryptionAlgorithms {
			if e.Value != nil {
				p1Enc = append(p1Enc, *e.Value)
			}
		}
		for _, e := range t.Phase2EncryptionAlgorithms {
			if e.Value != nil {
				p2Enc = append(p2Enc, *e.Value)
			}
		}
		for _, i := range t.Phase1IntegrityAlgorithms {
			if i.Value != nil {
				p1Int = append(p1Int, *i.Value)
			}
		}
		for _, i := range t.Phase2IntegrityAlgorithms {
			if i.Value != nil {
				p2Int = append(p2Int, *i.Value)
			}
		}
		for _, g := range t.Phase1DHGroupNumbers {
			if g.Value != nil {
				dh = append(dh, *g.Value)
			}
		}
		for _, g := range t.Phase2DHGroupNumbers {
			if g.Value != nil {
				dh = append(dh, *g.Value)
			}
		}
		for _, k := range t.IkeVersions {
			if k.Value != nil {
				ike = append(ike, *k.Value)
			}
		}
	}
	return p1Enc, p2Enc, p1Int, p2Int, dh, ike
}
