package sdkpqc

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EC2SSMScanner discovers SSM-managed EC2 / on-prem instances.
type EC2SSMScanner struct{}

// Name returns the canonical scanner identifier.
func (EC2SSMScanner) Name() string { return "ec2_ssm" }

// Category returns the primary category for this scanner.
func (EC2SSMScanner) Category() models.Category { return models.CategorySDKLibrary }

// ssmInstanceInfoAPI is the minimal slice of the ssm client this scanner uses.
// DescribeInstanceInformation is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page (documented default ~10), silently
// dropping managed instances in dense accounts. Defining it as an interface keeps
// the pagination + error-propagation logic unit-testable with a fake (the
// concrete *ssm.Client satisfies it).
type ssmInstanceInfoAPI interface {
	DescribeInstanceInformation(ctx context.Context, in *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
}

// Scan lists SSM-managed instances and emits one asset per instance.
// Pagination via NextToken; capped at 1000 items.
//
// DescribeInstanceInformation exposes only platform/agent metadata — no TLS
// version, cipher suite, or protocol field — so the instance's own outbound
// crypto posture is NOT observable here and is recorded as Unknown. We assert
// only the doc-backed control-plane floor: the SSM API endpoints require TLS and
// the documented minimum is TLS 1.2 (per the SSM/EC2 data-protection docs), with
// NO cipher-suite name (no AWS doc names a guaranteed suite). That floor is
// stamped source=aws-doc; it describes the SSM control-plane tunnel, not a
// determination of the instance's own outbound TLS.
func (s EC2SSMScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ssm.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeInstanceInformation and
// classifies each managed instance into a CryptoAsset. A DescribeInstanceInformation
// error is NOT swallowed — it is returned so the engine records this scanner as
// errored (which surfaces in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s EC2SSMScanner) scan(ctx context.Context, client ssmInstanceInfoAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	const maxItems = 1000
	var nextToken *string
	for {
		// MaxResults raises the page size from the documented default of 10 to cut
		// round-trips on dense accounts (50 is within the API's accepted range).
		out, err := client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{NextToken: nextToken, MaxResults: aws.Int32(50)})
		if err != nil {
			return nil, fmt.Errorf("ssm DescribeInstanceInformation: %w", err)
		}
		for _, i := range out.InstanceInformationList {
			if i.InstanceId == nil {
				continue
			}
			id := *i.InstanceId
			platformType := string(i.PlatformType)
			agentVersion := ""
			if i.AgentVersion != nil {
				agentVersion = *i.AgentVersion
			}
			platformName := ""
			if i.PlatformName != nil {
				platformName = *i.PlatformName
			}
			platformVersion := ""
			if i.PlatformVersion != nil {
				platformVersion = *i.PlatformVersion
			}
			// Doc-backed control-plane floor only: protocol=tls, version 1.2, with NO
			// cipher suite (the API returns none, and no AWS doc guarantees a suite, so
			// we must not invent one — not even an empty-named entry).
			props := models.CryptoProperties{
				AssetType: models.AssetTypeProtocol,
				ProtocolProperties: &models.ProtocolProperties{
					Type:    "tls",
					Version: "1.2",
				},
			}
			a := services.NewAsset("ec2_ssm", models.CategorySDKLibrary, accountID, region, id, "AWS::SSM::ManagedInstance", props)
			a.Properties["platformType"] = platformType
			a.Properties["platformName"] = platformName
			a.Properties["platformVersion"] = platformVersion
			a.Properties["agentVersion"] = agentVersion
			if i.IsLatestVersion != nil {
				a.Properties["ssmAgentIsLatestVersion"] = strconv.FormatBool(*i.IsLatestVersion)
			}
			a.Properties["pingStatus"] = string(i.PingStatus)
			// The instance's own crypto posture is not observable from
			// DescribeInstanceInformation -> Unknown (not a fabricated classical).
			services.PostureProperty(&a, models.PostureUnknown)
			// The TLS-1.2 floor is a documented control-plane guarantee, not a live
			// observation: stamp source=aws-doc so the basis is auditable.
			services.StampDocFactKeyed(&a, "sdkpqc/ec2_ssm/control-plane-tls-floor")
			assets = append(assets, a)
			if len(assets) >= maxItems {
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
