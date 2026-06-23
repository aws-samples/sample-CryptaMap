package transit

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type DirectConnectScanner struct{}

func (DirectConnectScanner) Name() string              { return "directconnect" }
func (DirectConnectScanner) Category() models.Category { return models.CategoryDataInTransit }

// directConnectAPI is the minimal slice of the directconnect client this scanner
// uses. DescribeConnections is not NextToken-paginated (it returns all
// connections in one call), so a single invocation is correct; defining the
// interface keeps error propagation + posture classification unit-testable with
// a fake (the concrete *directconnect.Client satisfies it).
type directConnectAPI interface {
	DescribeConnections(ctx context.Context, in *directconnect.DescribeConnectionsInput, optFns ...func(*directconnect.Options)) (*directconnect.DescribeConnectionsOutput, error)
}

func (s DirectConnectScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := directconnect.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it lists DirectConnect connections and
// classifies each into a CryptoAsset. A DescribeConnections error is NOT
// swallowed — it is returned so the engine records this scanner as errored,
// keeping a denied/throttled scan VISIBLY incomplete rather than a clean-looking
// empty success.
func (s DirectConnectScanner) scan(ctx context.Context, client directConnectAPI, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.DescribeConnections(ctx, &directconnect.DescribeConnectionsInput{})
	if err != nil {
		return nil, fmt.Errorf("directconnect DescribeConnections: %w", err)
	}
	assets := []models.CryptoAsset{}
	for _, c := range out.Connections {
		if c.ConnectionId == nil {
			continue
		}
		// DescribeConnections already returns EncryptionMode, MacSecCapable and
		// PortEncryptionStatus — no extra API call. We must NOT collapse
		// should_encrypt and must_encrypt: should_encrypt is the DEFAULT for new
		// MACsec connections and FALLS BACK to unencrypted communication if
		// MACsec negotiation fails, so it is only encrypted when MACsec is proven
		// live. PortEncryptionStatus=="Encryption Up" is the authoritative
		// live-MACsec signal; must_encrypt enforces encryption outright.
		em := ""
		if c.EncryptionMode != nil {
			em = *c.EncryptionMode
		}
		portStatus := ""
		if c.PortEncryptionStatus != nil {
			portStatus = *c.PortEncryptionStatus
		}
		encryptionUp := portStatus == "Encryption Up"

		posture := models.PostureNoEncryption
		suite := "none"
		switch {
		case em == "must_encrypt" || encryptionUp:
			// Encryption enforced (must_encrypt) or proven live ("Encryption Up").
			// MACsec uses AES-GCM — a SYMMETRIC cipher, quantum-resistant (Grover
			// only halves effective strength), so symmetric-only, NOT non-pqc-
			// classical (which would FALSE-ALARM it as a migration target).
			posture = models.PostureSymmetricOnly
			suite = "MACsec (AES-GCM)"
		case em == "should_encrypt":
			// MACsec PREFERRED but not currently active (portStatus is
			// "Encryption Down" or absent): falls back to cleartext, so the live
			// posture is no-encryption.
			posture = models.PostureNoEncryption
			suite = "none"
		default:
			// no_encrypt / nil EncryptionMode → no encryption.
			posture = models.PostureNoEncryption
			suite = "none"
		}

		// MACsec is a link-layer (L2) encryption protocol. CycloneDX 1.7
		// protocolProperties.type is a closed ENUM that has NO "macsec" member
		// (tls/ssh/ipsec/ike/sstp/wpa/dtls/quic/...), so emitting "macsec" there
		// fails schema validation. Use the valid "other" enum value and record the
		// real protocol via cryptamap:protocol below (the suite name already says
		// "MACsec (AES-GCM)").
		props := services.TLSProtocolProps("macsec", suite)
		props.ProtocolProperties.Type = "other"
		a := services.NewAsset("directconnect", models.CategoryDataInTransit, accountID, region, *c.ConnectionId, "AWS::DirectConnect::Connection", props)
		a.Properties["protocol"] = "macsec"
		services.PostureProperty(&a, posture)
		if em != "" {
			a.Properties["encryptionMode"] = em
		}
		if portStatus != "" {
			a.Properties["portEncryptionStatus"] = portStatus
		}
		if c.MacSecCapable != nil {
			if *c.MacSecCapable {
				a.Properties["macSecCapable"] = "true"
			} else {
				a.Properties["macSecCapable"] = "false"
			}
		}
		// The should_encrypt cleartext-fallback semantics are a universal AWS
		// guarantee; stamp its provenance when EncryptionMode drove the call.
		if em != "" {
			services.StampDocFactKeyed(&a, "transit/directconnect/macsec")
		}
		assets = append(assets, a)
	}
	return assets, nil
}
