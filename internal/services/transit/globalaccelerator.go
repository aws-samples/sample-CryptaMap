package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type GlobalAcceleratorScanner struct{}

func (GlobalAcceleratorScanner) Name() string              { return "globalaccelerator" }
func (GlobalAcceleratorScanner) Category() models.Category { return models.CategoryDataInTransit }

// Global Accelerator is a GLOBAL service: its only API endpoint lives in
// us-west-2 (globalaccelerator.<other-region>.amazonaws.com does not resolve).
// We therefore (a) emit GA assets exactly once across a multi-region fan-out by
// gating on a single run-once region, and (b) pin the client + emitted asset
// region to us-west-2 so the endpoint resolves and the synthetic ARN/bom-ref
// stays stable (the org merge dedups on BomRef, which embeds region).
const (
	// gaEndpointRegion is GA's only resolvable API endpoint region.
	gaEndpointRegion = "us-west-2"
	// gaRunOnceRegion is the scan-shard region on which GA is reported once.
	// us-east-1 is guaranteed present in the deployed/default fan-out
	// (us-east-1,ap-south-1), IndianBFSIDefaults, and CommercialDefaults.
	gaRunOnceRegion = "us-east-1"
)

// globalAcceleratorAPI is the minimal slice of the globalaccelerator client this
// scanner uses. Both calls are NextToken-paginated; defining it as an interface
// keeps the pagination + listener classification logic unit-testable with a fake
// (the concrete *globalaccelerator.Client satisfies it).
type globalAcceleratorAPI interface {
	ListAccelerators(ctx context.Context, in *globalaccelerator.ListAcceleratorsInput, optFns ...func(*globalaccelerator.Options)) (*globalaccelerator.ListAcceleratorsOutput, error)
	ListListeners(ctx context.Context, in *globalaccelerator.ListListenersInput, optFns ...func(*globalaccelerator.Options)) (*globalaccelerator.ListListenersOutput, error)
}

func (s GlobalAcceleratorScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	// Run exactly once across the multi-region fan-out: skip every shard
	// except the run-once region so global accelerators are not duplicated.
	if cfg.Region != gaRunOnceRegion {
		return []models.CryptoAsset{}, nil
	}
	// Pin the client to GA's home region; the regional endpoint for other
	// regions does not resolve (NXDOMAIN).
	client := globalaccelerator.NewFromConfig(cfg, func(o *globalaccelerator.Options) {
		o.Region = gaEndpointRegion
	})
	accountID := services.AccountID(ctx, cfg)
	// Stamp the asset region as GA's home region so the synthetic ARN/bom-ref
	// uses a resolvable region and stays stable across runs.
	region := gaEndpointRegion
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListAccelerators, then per
// accelerator paginates ListListeners (non-fatal per-accelerator errors are
// logged and skipped) and emits one L4 transit asset per listener. A
// ListAccelerators error is returned so a denied/throttled scan stays VISIBLY
// incomplete rather than a clean-looking empty success.
func (s GlobalAcceleratorScanner) scan(ctx context.Context, client globalAcceleratorAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListAccelerators(ctx, &globalaccelerator.ListAcceleratorsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("globalaccelerator ListAccelerators: %w", err)
		}
		for _, a := range out.Accelerators {
			if a.AcceleratorArn == nil {
				continue
			}
			lout, lerr := client.ListListeners(ctx, &globalaccelerator.ListListenersInput{AcceleratorArn: a.AcceleratorArn})
			if lerr != nil {
				fmt.Fprintf(os.Stderr, "globalaccelerator ListListeners: %v\n", lerr)
				continue
			}
			for _, l := range lout.Listeners {
				if l.ListenerArn == nil {
					continue
				}
				// Global Accelerator is Layer-4 (TCP/UDP) and does NOT terminate TLS;
				// TLS (if any) is negotiated end-to-end with the downstream endpoint
				// (ALB/NLB/EC2). So GA's served TLS version is genuinely UNKNOWN — and a
				// UDP listener carries no TLS at all. Previously every listener was
				// stamped NonPQCClassical-TLS regardless of protocol, a FALSE-ALARM on
				// UDP and an over-assertion on TCP. Read l.Protocol and stamp Unknown
				// (assess the downstream endpoint), recording the L4 protocol.
				props := services.TLSProtocolPropsDoc("", "ga-tls", "low", "https://docs.aws.amazon.com/global-accelerator/latest/dg/introduction-components.html")
				ass := services.NewAsset("globalaccelerator", models.CategoryDataInTransit, accountID, region, *l.ListenerArn, "AWS::GlobalAccelerator::Listener", props)
				services.PostureProperty(&ass, models.PostureUnknown)
				services.StampDocFactKeyed(&ass, "transit/globalaccelerator/aws-tls-policy")
				ass.Properties["l4Protocol"] = string(l.Protocol)
				ass.Properties["note"] = "Global Accelerator is Layer-4 (does not terminate TLS); assess the downstream endpoint (ALB/NLB/EC2) for the actual TLS posture."
				assets = append(assets, ass)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
