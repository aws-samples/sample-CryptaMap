package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ClientVPNScanner inspects AWS Client VPN endpoints. Client VPN is TLS-based
// (OpenVPN over TLS) with a MANDATORY server certificate, so the transport is
// always encrypted — but the handshake is classical (X25519/ECDHE/RSA key
// exchange and an RSA/ECDSA server cert) with no AWS PQ-hybrid option, so posture
// is NonPQCClassical (a quantum-migration target, never NoEncryption and never
// quantum-resistant). When the server cert is an ACM cert, its signature algorithm /
// key size are resolved for evidence.
type ClientVPNScanner struct{}

// Name returns the canonical service identifier.
func (ClientVPNScanner) Name() string { return "clientvpn" }

// Category returns the primary CryptaMap category.
func (ClientVPNScanner) Category() models.Category { return models.CategoryDataInTransit }

// clientVPNEC2API is the minimal slice of the ec2 client this scanner uses.
// DescribeClientVpnEndpoints is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping endpoints in dense
// accounts. Defining it as an interface keeps the pagination + error-propagation
// logic unit-testable with a fake (the concrete *ec2.Client satisfies it).
type clientVPNEC2API interface {
	DescribeClientVpnEndpoints(ctx context.Context, in *ec2.DescribeClientVpnEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeClientVpnEndpointsOutput, error)
}

// Scan paginates DescribeClientVpnEndpoints (the list response carries the full
// crypto surface; ACM server certs are resolved for cert detail).
func (s ClientVPNScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates DescribeClientVpnEndpoints and
// classifies each endpoint into a CryptoAsset. A DescribeClientVpnEndpoints error
// is NOT swallowed — it is returned so the engine records this scanner as errored
// (which surfaces in coverage), keeping a denied/throttled scan VISIBLY incomplete
// rather than a clean-looking empty success.
func (s ClientVPNScanner) scan(ctx context.Context, client clientVPNEC2API, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeClientVpnEndpoints(ctx, &ec2.DescribeClientVpnEndpointsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("clientvpn DescribeClientVpnEndpoints: %w", err)
		}
		for _, ep := range out.ClientVpnEndpoints {
			if ep.ClientVpnEndpointId == nil {
				continue
			}
			id := *ep.ClientVpnEndpointId
			// Mandatory TLS with a classical server cert + classical KEX.
			props := services.TLSProtocolPropsDoc("", "client-vpn-tls", "high",
				"https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html")
			a := services.NewAsset("clientvpn", models.CategoryDataInTransit, accountID, region, id, "AWS::EC2::ClientVpnEndpoint", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			if ep.TransportProtocol != "" {
				a.Properties["transportProtocol"] = string(ep.TransportProtocol)
			}
			// Authentication types in use (certificate / directory / federated).
			for i, ao := range ep.AuthenticationOptions {
				if ao.Type != "" {
					a.Properties[fmt.Sprintf("authType%d", i)] = string(ao.Type)
				}
			}
			if ep.ServerCertificateArn != nil && *ep.ServerCertificateArn != "" {
				a.Properties["serverCertificateArn"] = *ep.ServerCertificateArn
				if isACMCertARN(*ep.ServerCertificateArn) {
					resolveACMCert(ctx, certResolver, *ep.ServerCertificateArn, &a)
				}
			}
			a.Properties["note"] = "Client VPN uses OpenVPN/TLS with a classical server certificate and classical key exchange; no post-quantum option exists today (quantum-migration target)."
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
