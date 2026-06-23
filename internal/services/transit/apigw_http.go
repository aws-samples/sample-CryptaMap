package transit

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigwv2 "github.com/aws/aws-sdk-go-v2/service/apigatewayv2"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

type APIGWHTTPScanner struct{}

func (APIGWHTTPScanner) Name() string              { return "apigw_http" }
func (APIGWHTTPScanner) Category() models.Category { return models.CategoryDataInTransit }

// apigwv2HTTPAPI is the minimal slice of the apigatewayv2 client this scanner
// uses. Both calls are NextToken-paginated, so the scanner must loop; a single
// call returns only the first page (default ~25), silently dropping APIs/domains
// in dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *apigwv2.Client
// satisfies it).
type apigwv2HTTPAPI interface {
	GetApis(ctx context.Context, in *apigwv2.GetApisInput, optFns ...func(*apigwv2.Options)) (*apigwv2.GetApisOutput, error)
	GetDomainNames(ctx context.Context, in *apigwv2.GetDomainNamesInput, optFns ...func(*apigwv2.Options)) (*apigwv2.GetDomainNamesOutput, error)
}

func (s APIGWHTTPScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := apigwv2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates GetApis and GetDomainNames and
// classifies each into a CryptoAsset. A GetDomainNames error is NOT swallowed —
// it is returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s APIGWHTTPScanner) scan(ctx context.Context, client apigwv2HTTPAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}

	// Paginate GetApis via NextToken — a single call returns only the first page
	// (default ~25), silently dropping APIs in accounts with many HTTP/WebSocket APIs.
	var apiToken *string
	for {
		out, err := client.GetApis(ctx, &apigwv2.GetApisInput{NextToken: apiToken})
		if err != nil {
			return nil, fmt.Errorf("apigw_http GetApis: %w", err)
		}
		for _, api := range out.Items {
			if api.ApiId == nil {
				continue
			}
			// API Gateway enforces TLS_1_2 for ALL HTTP API endpoints (accepts TLS
			// 1.2/1.3, rejects 1.0) — a genuine UNIVERSAL guarantee, so "1.2" is
			// correct but must carry aws-doc provenance, not masquerade as observed.
			props := services.TLSProtocolPropsDoc("1.2", "AWS-managed", "high", "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-ciphers.html")
			a := services.NewAsset("apigw_http", models.CategoryDataInTransit, accountID, region, *api.ApiId, "AWS::ApiGatewayV2::Api", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "transit/apigw_http/tls-floor")
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		apiToken = out.NextToken
	}

	// Paginate GetDomainNames likewise. A denied/throttled call must NOT be
	// swallowed as a clean success — propagate it so the scan is visibly incomplete.
	var domToken *string
	for {
		dout, derr := client.GetDomainNames(ctx, &apigwv2.GetDomainNamesInput{NextToken: domToken})
		if derr != nil {
			return nil, fmt.Errorf("apigw_http GetDomainNames: %w", derr)
		}
		for _, d := range dout.Items {
			if d.DomainName == nil {
				continue
			}
			policy := ""
			ver := "1.2"
			posture := models.PostureNonPQCClassical
			certARN := ""
			for _, dc := range d.DomainNameConfigurations {
				policy = string(dc.SecurityPolicy)
				if strings.ToUpper(policy) == "TLS_1_0" {
					ver = "1.0"
					posture = models.PostureLegacyTLS
				}
				if dc.CertificateArn != nil && *dc.CertificateArn != "" {
					certARN = *dc.CertificateArn
				}
				break
			}
			props := services.TLSProtocolProps(ver, policy)
			// The SecurityPolicy enum is itself the documented TLS floor.
			if props.ProtocolProperties != nil && ver != "" {
				props.ProtocolProperties.TLSMinVersion = ver
			}
			a := services.NewAsset("apigw_http", models.CategoryDataInTransit, accountID, region, *d.DomainName, "AWS::ApiGatewayV2::DomainName", props)
			services.PostureProperty(&a, posture)
			// Resolve the bound ACM cert (HTTP API custom domains are ACM-only) to
			// fill cert signature algorithm + key size.
			if certARN != "" {
				a.Properties["certificateArn"] = certARN
				resolveACMCert(ctx, certResolver, certARN, &a)
			}
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if dout.NextToken == nil || *dout.NextToken == "" {
			break
		}
		domToken = dout.NextToken
	}
	return assets, nil
}
