package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vltypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// VPCLatticeScanner inspects Amazon VPC Lattice listeners for transit encryption.
//
// An HTTPS (or TLS_PASSTHROUGH) listener terminates/forwards TLS 1.2/1.3 with a
// classical RSA/ECDSA ACM cert -> NonPQCClassical (quantum-vulnerable handshake,
// no PQ option). An HTTP listener is plaintext L7 -> NoEncryption (a verified
// unencrypted finding, not Unknown). The service's ACM cert is resolved for
// evidence.
type VPCLatticeScanner struct{}

// Name returns the canonical service identifier.
func (VPCLatticeScanner) Name() string { return "vpclattice" }

// Category returns the primary CryptaMap category.
func (VPCLatticeScanner) Category() models.Category { return models.CategoryDataInTransit }

// vpcLatticeAPI is the minimal slice of the vpclattice client this scanner uses.
// ListServices and ListListeners are NextToken-paginated, so the scanner must
// loop; a single call returns only the first page, silently dropping
// services/listeners in dense accounts. Defining it as an interface keeps the
// pagination + error propagation logic unit-testable with a fake (the concrete
// *vpclattice.Client satisfies it).
type vpcLatticeAPI interface {
	ListServices(ctx context.Context, in *vpclattice.ListServicesInput, optFns ...func(*vpclattice.Options)) (*vpclattice.ListServicesOutput, error)
	GetService(ctx context.Context, in *vpclattice.GetServiceInput, optFns ...func(*vpclattice.Options)) (*vpclattice.GetServiceOutput, error)
	ListListeners(ctx context.Context, in *vpclattice.ListListenersInput, optFns ...func(*vpclattice.Options)) (*vpclattice.ListListenersOutput, error)
}

// Scan enumerates services -> listeners, emitting one asset per listener.
func (s VPCLatticeScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := vpclattice.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates ListServices and, per service,
// ListListeners, classifying each listener into a CryptoAsset. A ListServices
// error is NOT swallowed — it is returned so the engine records this scanner as
// errored (which surfaces in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s VPCLatticeScanner) scan(ctx context.Context, client vpcLatticeAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var svcToken *string
	for {
		svcs, err := client.ListServices(ctx, &vpclattice.ListServicesInput{NextToken: svcToken})
		if err != nil {
			return nil, fmt.Errorf("vpclattice ListServices: %w", err)
		}
		for _, svc := range svcs.Items {
			if svc.Id == nil {
				continue
			}
			// Resolve the service-bound ACM cert once (shared across its listeners).
			certARN := ""
			if g, gerr := client.GetService(ctx, &vpclattice.GetServiceInput{ServiceIdentifier: svc.Id}); gerr != nil {
				fmt.Fprintf(os.Stderr, "vpclattice GetService %s: %v\n", *svc.Id, gerr)
			} else if g.CertificateArn != nil {
				certARN = *g.CertificateArn
			}

			var lToken *string
			for {
				ls, lerr := client.ListListeners(ctx, &vpclattice.ListListenersInput{ServiceIdentifier: svc.Id, NextToken: lToken})
				if lerr != nil {
					fmt.Fprintf(os.Stderr, "vpclattice ListListeners %s: %v\n", *svc.Id, lerr)
					break
				}
				for _, l := range ls.Items {
					if l.Arn == nil {
						continue
					}
					posture := models.PostureNonPQCClassical
					props := services.TLSProtocolPropsDoc("1.2", "vpc-lattice-tls", "high",
						"https://docs.aws.amazon.com/vpc-lattice/latest/ug/https-listeners.html")
					if l.Protocol == vltypes.ListenerProtocolHttp {
						// Plaintext L7 — verified unencrypted.
						posture = models.PostureNoEncryption
						props = services.NoEncryption()
					}
					a := services.NewAsset("vpclattice", models.CategoryDataInTransit, accountID, region, *l.Arn, "AWS::VpcLattice::Listener", props)
					services.PostureProperty(&a, posture)
					a.Properties["protocol"] = string(l.Protocol)
					if posture == models.PostureNonPQCClassical && certARN != "" {
						a.Properties["certificateArn"] = certARN
						if isACMCertARN(certARN) {
							resolveACMCert(ctx, certResolver, certARN, &a)
						}
					}
					if posture == models.PostureNoEncryption {
						a.Properties["note"] = "VPC Lattice HTTP listener serves plaintext (no TLS)."
					}
					assets = append(assets, a)
					if services.TruncationCapReached(len(assets), s.Name(), region) {
						return assets, nil
					}
				}
				if ls.NextToken == nil || *ls.NextToken == "" {
					break
				}
				lToken = ls.NextToken
			}
		}
		if svcs.NextToken == nil || *svcs.NextToken == "" {
			break
		}
		svcToken = svcs.NextToken
	}
	return assets, nil
}
