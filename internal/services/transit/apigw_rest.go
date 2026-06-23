package transit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	apigw "github.com/aws/aws-sdk-go-v2/service/apigateway"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// APIGWRestScanner discovers API Gateway REST custom-domain TLS settings.
type APIGWRestScanner struct{}

// Name returns the canonical service identifier.
func (APIGWRestScanner) Name() string { return "apigw_rest" }

// Category returns the data-in-transit category.
func (APIGWRestScanner) Category() models.Category { return models.CategoryDataInTransit }

// apigwPQHybridGroupsDoc is the doc-known set of hybrid PQ key-exchange groups
// that API Gateway "_PQ_2025_09" custom-domain security policies support. The
// API exposes only the policy name, not the groups, so this is a doc-sourced
// capability label (not an observed negotiated group).
// https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html
const apigwPQHybridGroupsDoc = "SecP256r1MLKEM768,SecP384r1MLKEM1024,X25519MLKEM768"

// secPolicyToVersion maps an APIGW SecurityPolicy enum to (version, posture).
func secPolicyToVersion(p string) (string, models.CryptoPosture) {
	up := strings.ToUpper(p)
	// PQ-enhanced REST custom-domain policies negotiate hybrid ML-KEM key exchange,
	// so the posture is PQCHybrid (a capability). But the TLS-VERSION FLOOR is
	// encoded in the policy NAME and differs:
	//   - SecurityPolicy_TLS13_1_2_*_PQ_2025_09 accepts TLS 1.2 AND 1.3 -> floor 1.2
	//     (a TLS 1.2 client still connects, with classical ECDHE — PQ applies only
	//     to the TLS 1.3 subset). Recording "1.3" here OVERSTATED the floor.
	//   - SecurityPolicy_TLS13_1_3_*_PQ_2025_09 is TLS 1.3-only -> floor 1.3.
	// Checked FIRST (the names also contain "TLS13") so they are not false-alarmed
	// as classical.
	if strings.Contains(up, "_PQ_") || strings.Contains(up, "PQ_2025") {
		if strings.Contains(up, "TLS13_1_3") {
			return "1.3", models.PosturePQCHybrid
		}
		return "1.2", models.PosturePQCHybrid
	}
	switch up {
	case "TLS_1_0":
		return "1.0", models.PostureLegacyTLS
	case "TLS_1_2":
		return "1.2", models.PostureNonPQCClassical
	case "TLS_1_3":
		return "1.3", models.PostureNonPQCClassical
	}
	// Non-PQ TLS13_1_3 / EDGE 1.3-only policies have a true 1.3 floor.
	if strings.Contains(up, "TLS13_1_3") {
		return "1.3", models.PostureNonPQCClassical
	}
	return "1.2", models.PostureNonPQCClassical
}

// apigwRestAPI is the minimal slice of the apigateway client this scanner uses.
// Both calls are Position-paginated, so the scanner must loop; a single call
// returns only the first page, silently dropping REST APIs/domains in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *apigw.Client satisfies it).
type apigwRestAPI interface {
	GetRestApis(ctx context.Context, in *apigw.GetRestApisInput, optFns ...func(*apigw.Options)) (*apigw.GetRestApisOutput, error)
	GetDomainNames(ctx context.Context, in *apigw.GetDomainNamesInput, optFns ...func(*apigw.Options)) (*apigw.GetDomainNamesOutput, error)
}

// Scan lists REST APIs and custom domain names, emitting one asset per domain.
func (s APIGWRestScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := apigw.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	// Resolves the ACM cert bound to each custom domain (cached per ARN) to fill
	// the cert signature algorithm + key size on the protocol asset.
	certResolver := newACMCertResolver(cfg)
	return s.scan(ctx, client, certResolver, accountID, region)
}

// scan holds the testable core: it paginates GetRestApis and GetDomainNames and
// classifies each into a CryptoAsset. A GetRestApis error is NOT swallowed — it
// is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s APIGWRestScanner) scan(ctx context.Context, client apigwRestAPI, certResolver *acmCertResolver, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}

	// Walk REST APIs (informational — emits one asset per API as a baseline).
	var apiPos *string
	for {
		out, err := client.GetRestApis(ctx, &apigw.GetRestApisInput{Position: apiPos})
		if err != nil {
			return nil, fmt.Errorf("apigw_rest GetRestApis: %w", err)
		}
		for _, api := range out.Items {
			if api.Id == nil {
				continue
			}
			id := *api.Id
			// The default execute-api endpoint supports a TLSv1 (TLS 1.0) floor
			// per AWS docs — it is NOT a universal 1.2 guarantee, so do NOT
			// assert "1.2". Leave the version UNKNOWN and tag aws-doc provenance;
			// TLS 1.2+ is only guaranteed via a custom domain (handled below).
			props := services.TLSProtocolPropsDoc("", "AWS-managed", "low", "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html")
			a := services.NewAsset("apigw_rest", models.CategoryDataInTransit, accountID, region, id, "AWS::ApiGateway::RestApi", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "transit/apigw_rest/execute-api-tls-floor")
			assets = append(assets, a)
		}
		if out.Position == nil || *out.Position == "" {
			break
		}
		apiPos = out.Position
	}

	// Walk custom domains and inspect SecurityPolicy.
	var domPos *string
	for {
		out, err := client.GetDomainNames(ctx, &apigw.GetDomainNamesInput{Position: domPos})
		if err != nil {
			fmt.Fprintf(os.Stderr, "apigw_rest GetDomainNames: %v\n", err)
			break
		}
		for _, d := range out.Items {
			if d.DomainName == nil {
				continue
			}
			secPolicy := string(d.SecurityPolicy)
			ver, posture := secPolicyToVersion(secPolicy)
			// Surface the PQ-hybrid flag (and the doc-known supported KEX groups)
			// when the security policy is a hybrid PQ policy, so the dashboard's
			// "PQC hybrid key exchange" row reflects the config-derivable signal.
			// The policy pins the accepted hybrid groups; the NEGOTIATED group is
			// still client-dependent, so the KEX label is a doc-sourced capability,
			// not an observed group (left empty for non-PQ policies).
			pqHybrid := posture == models.PosturePQCHybrid
			kexGroup := ""
			if pqHybrid {
				kexGroup = apigwPQHybridGroupsDoc
			}
			props := services.TLSProtocolPropsDetailed(ver, secPolicy, kexGroup, "", 0, pqHybrid)
			// The SecurityPolicy enum is itself the documented TLS floor.
			if props.ProtocolProperties != nil && ver != "" {
				props.ProtocolProperties.TLSMinVersion = ver
			}
			a := services.NewAsset("apigw_rest", models.CategoryDataInTransit, accountID, region, *d.DomainName, "AWS::ApiGateway::DomainName", props)
			services.PostureProperty(&a, posture)
			// Capture the bound ACM certificate ARN (edge or regional) so the cert's
			// signature algorithm + key size can be resolved via ACM. resolveACMCert
			// fills CertSignatureAlgorithm/CertKeySizeBits when the ARN is an ACM cert.
			certARN := ""
			if d.RegionalCertificateArn != nil && *d.RegionalCertificateArn != "" {
				certARN = *d.RegionalCertificateArn
			} else if d.CertificateArn != nil && *d.CertificateArn != "" {
				certARN = *d.CertificateArn
			}
			if certARN != "" {
				a.Properties["certificateArn"] = certARN
				resolveACMCert(ctx, certResolver, certARN, &a)
			}
			assets = append(assets, a)
		}
		if out.Position == nil || *out.Position == "" {
			break
		}
		domPos = out.Position
	}
	return assets, nil
}
