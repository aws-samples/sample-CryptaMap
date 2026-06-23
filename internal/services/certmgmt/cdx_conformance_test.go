package certmgmt

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	asTypes "github.com/aws/aws-sdk-go-v2/service/appstream/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/aws-sdk-go-v2/service/rolesanywhere"
	ratypes "github.com/aws/aws-sdk-go-v2/service/rolesanywhere/types"
	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/aws-sdk-go-v2/service/signer"
	signertypes "github.com/aws/aws-sdk-go-v2/service/signer/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestCertMgmtScanners_CBOMSchemaConformance drives the REAL scan() cores (or
// pure classify helpers where no scan seam exists) of every certmgmt scanner
// with synthetic inputs, then validates the CBOM their output produces against
// the official CycloneDX 1.7 schema. This is the offline conformance seam: it
// proves the actual scanner output — not a hand-built approximation — is
// schema-valid, WITHOUT a live AWS account.
func TestCertMgmtScanners_CBOMSchemaConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	validate := func(t *testing.T, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(assets) == 0 {
			t.Fatal("expected at least one asset")
		}
		if err := output.ValidateAssetsCBOM(assets); err != nil {
			t.Fatalf("CBOM failed CycloneDX 1.7 schema validation: %v", err)
		}
	}

	t.Run("acm", func(t *testing.T) {
		client := &fakeACMClient{
			listPages: []*acm.ListCertificatesOutput{
				{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: acmStrptr("arn:cert-page1")}}},
			},
			describeOut: map[string]*acm.DescribeCertificateOutput{
				"arn:cert-page1": acmDescribeFor("arn:cert-page1", "RSA_2048"),
			},
		}
		assets, err := ACMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("acmpca", func(t *testing.T) {
		client := &fakeACMPCAClient{
			acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
				{CertificateAuthorities: []acmpcatypes.CertificateAuthority{acmpcaCA("arn:ca-1", "RSA_2048")}},
			},
		}
		assets, err := ACMPCAScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("appstream_certauth", func(t *testing.T) {
		// No scan() seam; drive the pure classify helper that produces the asset.
		a, ok := classifyAppStreamCertAuth(
			"111122223333", "us-east-1", "corp.example.com",
			&asTypes.CertificateBasedAuthProperties{
				Status:                  asTypes.CertificateBasedAuthStatusEnabled,
				CertificateAuthorityArn: aws.String("arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/abc-123"),
			},
		)
		if !ok {
			t.Fatal("expected appstream cert-auth asset")
		}
		validate(t, []models.CryptoAsset{a}, nil)
	})

	t.Run("cloudfront_certs", func(t *testing.T) {
		client := &fakeCloudfrontCertsClient{
			cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
				{
					DistributionList: &cloudfronttypes.DistributionList{
						Items: []cloudfronttypes.DistributionSummary{
							{
								Id:         cloudfrontcertsStrptr("dist-page1"),
								DomainName: cloudfrontcertsStrptr("d1.cloudfront.net"),
								ViewerCertificate: &cloudfronttypes.ViewerCertificate{
									ACMCertificateArn: cloudfrontcertsStrptr("arn:aws:acm:us-east-1:111122223333:certificate/abc"),
								},
							},
						},
					},
				},
			},
		}
		assets, err := CloudFrontCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("cloudfront_keygroups", func(t *testing.T) {
		pemStr := cloudfrontkeygroupsRSAPEM(t)
		client := &fakeCloudfrontKeyGroupsClient{
			pages: []*cloudfront.ListPublicKeysOutput{
				{
					PublicKeyList: &cloudfronttypes.PublicKeyList{
						Items: []cloudfronttypes.PublicKeySummary{
							{Id: cloudfrontcertsStrptr("pk-rsa"), Name: cloudfrontcertsStrptr("signer"), EncodedKey: cloudfrontcertsStrptr(pemStr)},
						},
					},
				},
			},
		}
		assets, err := CloudFrontKeyGroupsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("iam_certs", func(t *testing.T) {
		client := &fakeIAMCertsClient{
			listPages: []*iam.ListServerCertificatesOutput{
				{
					ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
						iamCertsMeta("classical", "arn:aws:iam::111122223333:server-certificate/classical"),
					},
				},
			},
			getBodies: map[string]string{"classical": iamCertsClassicalPEM},
		}
		assets, err := IAMCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("iot_certs", func(t *testing.T) {
		rsaPem := iotCertsRSAPEM(t)
		client := &fakeIoTCertsClient{
			listPages: []*iot.ListCertificatesOutput{
				{
					Certificates: []iottypes.Certificate{{
						CertificateArn: iotCertsStrptr("arn:cert-rsa"),
						CertificateId:  iotCertsStrptr("cert-rsa"),
						Status:         iottypes.CertificateStatusActive,
					}},
				},
			},
			describePem: map[string]string{"cert-rsa": rsaPem},
		}
		assets, err := IoTCertsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("rolesanywhere", func(t *testing.T) {
		pem1 := rolesanywhereRSACertPEM(t)
		client := &fakeRolesAnywhereClient{
			rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
				{
					TrustAnchors: []ratypes.TrustAnchorDetail{
						rolesanywhereTA("arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/ta-bundle", "bundle", &ratypes.Source{
							SourceType: ratypes.TrustAnchorTypeCertificateBundle,
							SourceData: &ratypes.SourceDataMemberX509CertificateData{Value: pem1},
						}),
					},
				},
			},
		}
		assets, err := RolesAnywhereScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("ses_dkim", func(t *testing.T) {
		// No scan() seam; drive the pure classify helper that produces the asset.
		a := classifySESDKIM(
			"111122223333", "us-east-1", "example.com",
			sesv2types.IdentityTypeDomain,
			&sesv2types.DkimAttributes{
				SigningEnabled:          true,
				SigningAttributesOrigin: sesv2types.DkimSigningAttributesOriginAwsSes,
				Status:                  sesv2types.DkimStatusSuccess,
				CurrentSigningKeyLength: sesv2types.DkimSigningKeyLengthRsa2048Bit,
			},
		)
		validate(t, []models.CryptoAsset{a}, nil)
	})

	t.Run("signer", func(t *testing.T) {
		client := &fakeSignerClient{
			listPages: []*signer.ListSigningProfilesOutput{
				{
					Profiles: []signertypes.SigningProfile{
						{ProfileName: signerStrptr("rsa-prof"), Arn: signerStrptr("arn:rsa")},
						{ProfileName: signerStrptr("ecdsa-prof"), Arn: signerStrptr("arn:ecdsa")},
					},
				},
			},
			getOverrides: map[string]signertypes.EncryptionAlgorithm{
				"rsa-prof":   signertypes.EncryptionAlgorithmRsa,
				"ecdsa-prof": signertypes.EncryptionAlgorithmEcdsa,
			},
		}
		assets, err := SignerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	// certparse is not a scanner (no struct/Scan()); its offline entry parseCertPEM
	// returns a parsedCert, not a CryptoAsset, so it has no CBOM to validate. Its
	// classical-cert path is exercised transitively via iam_certs/iot_certs above.
}
