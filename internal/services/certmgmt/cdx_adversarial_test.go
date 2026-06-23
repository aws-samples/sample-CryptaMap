package certmgmt

import (
	"context"
	"strings"
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

// TestCertMgmtScanners_AdversarialInputs drives HOSTILE / edge-case AWS API
// shapes through every certmgmt scanner's scan() seam (and the two pure classify
// helpers) and asserts only the two robustness invariants that MUST hold for any
// input, no matter how malformed:
//
//	(i)  the scanner NEVER panics (a nil-pointer deref on an assumed-present SDK
//	     field is a real bug). Each subtest installs a deferred recover() that
//	     converts a panic into a t.Errorf with the triggering input description,
//	     so one bad case reports the bug instead of crashing the whole run.
//	(ii) whatever assets it returns (when len>0) pass CycloneDX 1.7 schema
//	     validation. A raw AWS enum string (assetType/state/algorithm/etc.) copied
//	     straight into a CBOM enum field would break this on a future enum value.
//
// Returning 0 assets or an error for adversarial input is FINE — only a panic or
// a schema-validation failure on non-empty returned assets is a robustness bug.
//
// NOTE: a fully nil *Output page (the fake returning a stored nil with a nil
// error) is intentionally NOT tested. Every scanner here dereferences out.X
// directly with no out==nil guard, but the aws-sdk-go-v2 contract guarantees a
// non-nil *Output whenever the returned error is nil, so that input is not
// producible by a real AWS response — only by a misconfigured fake. It is a
// test-harness artifact, not a scanner robustness bug, so it is excluded.
func TestCertMgmtScanners_AdversarialInputs(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable: %v", err)
	}

	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"
	huge := strings.Repeat("A", 10000)

	// checkAssets validates the (i)/(ii) contract for one scanner invocation that
	// has ALREADY run (so a panic, if any, was caught by the caller's recover).
	checkAssets := func(t *testing.T, desc string, assets []models.CryptoAsset, err error) {
		t.Helper()
		// An error or empty output is acceptable for adversarial input.
		if err != nil || len(assets) == 0 {
			return
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Errorf("ROBUSTNESS BUG (schema): input %q produced %d non-empty assets that FAILED CycloneDX 1.7 validation: %v",
				desc, len(assets), verr)
		}
	}

	// run executes a scan-like closure under a per-subtest panic guard. A panic is
	// reported (with the input description) rather than crashing the process.
	run := func(t *testing.T, desc string, fn func() ([]models.CryptoAsset, error)) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ROBUSTNESS BUG (panic): input %q PANICKED: %v", desc, r)
			}
		}()
		assets, err := fn()
		checkAssets(t, desc, assets, err)
	}

	strptr := func(s string) *string { return &s }

	// ---------------------------------------------------------------- acm
	t.Run("acm", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeACMClient
		}{
			{"empty cert list", &fakeACMClient{listPages: []*acm.ListCertificatesOutput{{}}}},
			{"summary with nil ARN", &fakeACMClient{listPages: []*acm.ListCertificatesOutput{
				{CertificateSummaryList: []acmtypes.CertificateSummary{{}}}}}},
			{"describe returns nil Certificate", &fakeACMClient{
				listPages:   []*acm.ListCertificatesOutput{{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: strptr("arn:a")}}}},
				describeOut: map[string]*acm.DescribeCertificateOutput{"arn:a": {}},
			}},
			{"all-nil CertificateDetail fields", &fakeACMClient{
				listPages:   []*acm.ListCertificatesOutput{{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: strptr("arn:b")}}}},
				describeOut: map[string]*acm.DescribeCertificateOutput{"arn:b": {Certificate: &acmtypes.CertificateDetail{}}},
			}},
			{"future KeyAlgorithm enum + empty sig", &fakeACMClient{
				listPages: []*acm.ListCertificatesOutput{{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: strptr("arn:c")}}}},
				describeOut: map[string]*acm.DescribeCertificateOutput{"arn:c": {Certificate: &acmtypes.CertificateDetail{
					CertificateArn: strptr("arn:c"),
					KeyAlgorithm:   acmtypes.KeyAlgorithm("ML_DSA_87_FUTURE"),
					Status:         acmtypes.CertificateStatus("FUTURE_STATUS"),
					Type:           acmtypes.CertificateType("FUTURE_TYPE"),
				}}},
			}},
			{"empty-string ARN + 10k domain", &fakeACMClient{
				listPages: []*acm.ListCertificatesOutput{{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: strptr("")}, {CertificateArn: strptr("arn:d")}}}},
				describeOut: map[string]*acm.DescribeCertificateOutput{"arn:d": {Certificate: &acmtypes.CertificateDetail{
					CertificateArn: strptr("arn:d"),
					DomainName:     strptr(huge),
					Subject:        strptr(huge),
					KeyAlgorithm:   acmtypes.KeyAlgorithm(huge),
				}}},
			}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return ACMScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- acmpca
	t.Run("acmpca", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeACMPCAClient
		}{
			{"empty CA list", &fakeACMPCAClient{acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{{}}}},
			{"CA with nil ARN + nil config", &fakeACMPCAClient{acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
				{CertificateAuthorities: []acmpcatypes.CertificateAuthority{{}}}}}},
			{"nil config / nil Subject", &fakeACMPCAClient{acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
				{CertificateAuthorities: []acmpcatypes.CertificateAuthority{{Arn: strptr("arn:ca-a")}}}}}},
			{"config present, nil Subject pointer", &fakeACMPCAClient{acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
				{CertificateAuthorities: []acmpcatypes.CertificateAuthority{{
					Arn:                               strptr("arn:ca-b"),
					CertificateAuthorityConfiguration: &acmpcatypes.CertificateAuthorityConfiguration{KeyAlgorithm: acmpcatypes.KeyAlgorithm("FUTURE_PQ")},
				}}}}}},
			{"future enums + 10k subject", &fakeACMPCAClient{acmpcaPages: []*acmpca.ListCertificateAuthoritiesOutput{
				{CertificateAuthorities: []acmpcatypes.CertificateAuthority{{
					Arn:    strptr(huge),
					Status: acmpcatypes.CertificateAuthorityStatus("FUTURE_STATUS"),
					CertificateAuthorityConfiguration: &acmpcatypes.CertificateAuthorityConfiguration{
						KeyAlgorithm:     acmpcatypes.KeyAlgorithm("ML_DSA_999"),
						SigningAlgorithm: acmpcatypes.SigningAlgorithm("FUTURE_SIG"),
						Subject:          &acmpcatypes.ASN1Subject{CommonName: strptr(huge)},
					},
				}}}}}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return ACMPCAScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- cloudfront_certs
	t.Run("cloudfront_certs", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeCloudfrontCertsClient
		}{
			{"nil DistributionList", &fakeCloudfrontCertsClient{cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{{}}}},
			{"empty Items", &fakeCloudfrontCertsClient{cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
				{DistributionList: &cloudfronttypes.DistributionList{}}}}},
			{"summary with nil Id", &fakeCloudfrontCertsClient{cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
				{DistributionList: &cloudfronttypes.DistributionList{Items: []cloudfronttypes.DistributionSummary{{}}}}}}},
			{"nil ViewerCertificate + nil DomainName", &fakeCloudfrontCertsClient{cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
				{DistributionList: &cloudfronttypes.DistributionList{Items: []cloudfronttypes.DistributionSummary{{Id: strptr("d1")}}}}}}},
			{"future MinimumProtocolVersion enum + 10k id", &fakeCloudfrontCertsClient{cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
				{DistributionList: &cloudfronttypes.DistributionList{Items: []cloudfronttypes.DistributionSummary{{
					Id:         strptr(huge),
					DomainName: strptr(huge),
					ViewerCertificate: &cloudfronttypes.ViewerCertificate{
						ACMCertificateArn:      strptr(huge),
						MinimumProtocolVersion: cloudfronttypes.MinimumProtocolVersion("TLSv9_FUTURE"),
						SSLSupportMethod:       cloudfronttypes.SSLSupportMethod("FUTURE_METHOD"),
					},
				}}}}}}},
			{"empty-string Id + empty cert refs", &fakeCloudfrontCertsClient{cloudfrontcertsPages: []*cloudfront.ListDistributionsOutput{
				{DistributionList: &cloudfronttypes.DistributionList{Items: []cloudfronttypes.DistributionSummary{{
					Id:                strptr(""),
					ViewerCertificate: &cloudfronttypes.ViewerCertificate{ACMCertificateArn: strptr(""), IAMCertificateId: strptr("")},
				}}}}}}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return CloudFrontCertsScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- cloudfront_keygroups
	t.Run("cloudfront_keygroups", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeCloudfrontKeyGroupsClient
		}{
			{"nil PublicKeyList", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{{}}}},
			{"empty Items", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{
				{PublicKeyList: &cloudfronttypes.PublicKeyList{}}}}},
			{"summary with nil Id", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{
				{PublicKeyList: &cloudfronttypes.PublicKeyList{Items: []cloudfronttypes.PublicKeySummary{{}}}}}}},
			{"nil EncodedKey + nil Name/CreatedTime", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{
				{PublicKeyList: &cloudfronttypes.PublicKeyList{Items: []cloudfronttypes.PublicKeySummary{{Id: strptr("pk1")}}}}}}},
			{"garbage non-PEM EncodedKey", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{
				{PublicKeyList: &cloudfronttypes.PublicKeyList{Items: []cloudfronttypes.PublicKeySummary{
					{Id: strptr("pk2"), Name: strptr("bad"), EncodedKey: strptr("not-a-pem")}}}}}}},
			{"truncated PEM EncodedKey", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{
				{PublicKeyList: &cloudfronttypes.PublicKeyList{Items: []cloudfronttypes.PublicKeySummary{
					{Id: strptr("pk3"), Name: strptr(huge), EncodedKey: strptr("-----BEGIN CERTIFICATE-----\nXXXX")}}}}}}},
			{"empty-string Id + empty EncodedKey", &fakeCloudfrontKeyGroupsClient{pages: []*cloudfront.ListPublicKeysOutput{
				{PublicKeyList: &cloudfronttypes.PublicKeyList{Items: []cloudfronttypes.PublicKeySummary{
					{Id: strptr(""), EncodedKey: strptr("")}}}}}}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return CloudFrontKeyGroupsScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- iam_certs
	t.Run("iam_certs", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeIAMCertsClient
		}{
			{"empty metadata list", &fakeIAMCertsClient{listPages: []*iam.ListServerCertificatesOutput{{}}}},
			{"metadata all-nil (nil ARN)", &fakeIAMCertsClient{listPages: []*iam.ListServerCertificatesOutput{
				{ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{{}}}}}},
			{"nil name, valid ARN", &fakeIAMCertsClient{listPages: []*iam.ListServerCertificatesOutput{
				{ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{{Arn: strptr("arn:c-a")}}}}}},
			{"GetServerCertificate nil body", &fakeIAMCertsClient{
				listPages: []*iam.ListServerCertificatesOutput{{ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					{Arn: strptr("arn:c-b"), ServerCertificateName: strptr("b")}}}},
				// getBodies has no "b" entry -> fake returns empty GetServerCertificateOutput (nil ServerCertificate)
			}},
			{"garbage PEM body", &fakeIAMCertsClient{
				listPages: []*iam.ListServerCertificatesOutput{{ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					{Arn: strptr("arn:c-c"), ServerCertificateName: strptr("c")}}}},
				getBodies: map[string]string{"c": "not-a-pem"},
			}},
			{"truncated PEM + 10k name", &fakeIAMCertsClient{
				listPages: []*iam.ListServerCertificatesOutput{{ServerCertificateMetadataList: []iamtypes.ServerCertificateMetadata{
					{Arn: strptr(huge), ServerCertificateName: strptr(huge)}}}},
				getBodies: map[string]string{huge: "-----BEGIN CERTIFICATE-----\nXXXX"},
			}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return IAMCertsScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- iot_certs
	t.Run("iot_certs", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeIoTCertsClient
		}{
			{"empty cert list", &fakeIoTCertsClient{listPages: []*iot.ListCertificatesOutput{{}}}},
			{"cert all-nil (nil ARN)", &fakeIoTCertsClient{listPages: []*iot.ListCertificatesOutput{
				{Certificates: []iottypes.Certificate{{}}}}}},
			{"nil CertificateId, valid ARN", &fakeIoTCertsClient{listPages: []*iot.ListCertificatesOutput{
				{Certificates: []iottypes.Certificate{{CertificateArn: strptr("arn:i-a")}}}}}},
			{"future Status/Mode enums", &fakeIoTCertsClient{
				listPages: []*iot.ListCertificatesOutput{{Certificates: []iottypes.Certificate{{
					CertificateArn:  strptr("arn:i-b"),
					CertificateId:   strptr("i-b"),
					Status:          iottypes.CertificateStatus("FUTURE_STATUS"),
					CertificateMode: iottypes.CertificateMode("FUTURE_MODE"),
				}}}},
				describePem: map[string]string{"i-b": "not-a-pem"},
			}},
			{"truncated PEM + 10k id", &fakeIoTCertsClient{
				listPages: []*iot.ListCertificatesOutput{{Certificates: []iottypes.Certificate{{
					CertificateArn: strptr(huge),
					CertificateId:  strptr(huge),
				}}}},
				describePem: map[string]string{huge: "-----BEGIN CERTIFICATE-----\nXXXX"},
			}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return IoTCertsScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- rolesanywhere
	t.Run("rolesanywhere", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeRolesAnywhereClient
		}{
			{"empty anchor list", &fakeRolesAnywhereClient{rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{{}}}},
			{"anchor all-nil (nil ARN)", &fakeRolesAnywhereClient{rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
				{TrustAnchors: []ratypes.TrustAnchorDetail{{}}}}}},
			{"nil Source + nil Name/Enabled", &fakeRolesAnywhereClient{rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
				{TrustAnchors: []ratypes.TrustAnchorDetail{{TrustAnchorArn: strptr("arn:ta-a")}}}}}},
			{"Source present, nil SourceData union", &fakeRolesAnywhereClient{rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
				{TrustAnchors: []ratypes.TrustAnchorDetail{{
					TrustAnchorArn: strptr("arn:ta-b"),
					Source:         &ratypes.Source{SourceType: ratypes.TrustAnchorType("FUTURE_TYPE")},
				}}}}}},
			{"garbage PEM in bundle + 10k name", &fakeRolesAnywhereClient{rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
				{TrustAnchors: []ratypes.TrustAnchorDetail{{
					TrustAnchorArn: strptr(huge),
					Name:           strptr(huge),
					Source: &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeCertificateBundle,
						SourceData: &ratypes.SourceDataMemberX509CertificateData{Value: "not-a-pem"},
					},
				}}}}}},
			{"empty PEM bundle + empty ARN sibling", &fakeRolesAnywhereClient{rolesanywherePages: []*rolesanywhere.ListTrustAnchorsOutput{
				{TrustAnchors: []ratypes.TrustAnchorDetail{
					{TrustAnchorArn: strptr("")},
					{TrustAnchorArn: strptr("arn:ta-c"), Source: &ratypes.Source{
						SourceType: ratypes.TrustAnchorTypeCertificateBundle,
						SourceData: &ratypes.SourceDataMemberX509CertificateData{Value: ""},
					}},
				}}}}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return RolesAnywhereScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- signer
	t.Run("signer", func(t *testing.T) {
		cases := []struct {
			desc   string
			client *fakeSignerClient
		}{
			{"empty profile list", &fakeSignerClient{listPages: []*signer.ListSigningProfilesOutput{{}}}},
			{"profile all-nil (nil ProfileName)", &fakeSignerClient{listPages: []*signer.ListSigningProfilesOutput{
				{Profiles: []signertypes.SigningProfile{{}}}}}},
			{"nil Arn, valid name", &fakeSignerClient{listPages: []*signer.ListSigningProfilesOutput{
				{Profiles: []signertypes.SigningProfile{{ProfileName: strptr("p-a")}}}}}},
			{"future EncryptionAlgorithm enum", &fakeSignerClient{
				listPages: []*signer.ListSigningProfilesOutput{{Profiles: []signertypes.SigningProfile{
					{ProfileName: strptr("p-b"), Arn: strptr("arn:p-b")}}}},
				getOverrides: map[string]signertypes.EncryptionAlgorithm{"p-b": signertypes.EncryptionAlgorithm("PQC_FUTURE")},
			}},
			{"10k name + 10k arn + future platform", &fakeSignerClient{
				listPages: []*signer.ListSigningProfilesOutput{{Profiles: []signertypes.SigningProfile{
					{ProfileName: strptr(huge), Arn: strptr(huge), PlatformId: strptr(huge)}}}},
				getOverrides: map[string]signertypes.EncryptionAlgorithm{huge: signertypes.EncryptionAlgorithm(huge)},
			}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					return SignerScanner{}.scan(ctx, c.client, acct, region)
				})
			})
		}
	})

	// ---------------------------------------------------------------- appstream_certauth (pure classify helper)
	t.Run("appstream_certauth", func(t *testing.T) {
		cases := []struct {
			desc string
			cba  *asTypes.CertificateBasedAuthProperties
			dir  string
		}{
			// cba == nil -> ok=false, no asset; still must not panic.
			{"nil cba", nil, "dir"},
			{"zero-value cba (empty Status, nil CA ARN)", &asTypes.CertificateBasedAuthProperties{}, "dir"},
			{"future CertificateBasedAuthStatus enum", &asTypes.CertificateBasedAuthProperties{
				Status:                  asTypes.CertificateBasedAuthStatus("ENABLED_FUTURE_MODE"),
				CertificateAuthorityArn: aws.String(huge),
			}, huge},
			{"empty dir name + empty CA ARN", &asTypes.CertificateBasedAuthProperties{
				Status:                  asTypes.CertificateBasedAuthStatusEnabled,
				CertificateAuthorityArn: aws.String(""),
			}, ""},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					a, ok := classifyAppStreamCertAuth(acct, region, c.dir, c.cba)
					if !ok {
						return nil, nil
					}
					return []models.CryptoAsset{a}, nil
				})
			})
		}
	})

	// ---------------------------------------------------------------- ses_dkim (pure classify helper)
	t.Run("ses_dkim", func(t *testing.T) {
		cases := []struct {
			desc   string
			name   string
			idType sesv2types.IdentityType
			dkim   *sesv2types.DkimAttributes
		}{
			{"nil dkim attributes", "example.com", sesv2types.IdentityTypeDomain, nil},
			{"zero-value dkim (empty enums)", "example.com", "", &sesv2types.DkimAttributes{}},
			{"future DkimSigningKeyLength + future Status, enabled", huge, sesv2types.IdentityType("FUTURE_IDENTITY_TYPE"),
				&sesv2types.DkimAttributes{
					SigningEnabled:          true,
					SigningAttributesOrigin: sesv2types.DkimSigningAttributesOrigin("FUTURE_ORIGIN"),
					Status:                  sesv2types.DkimStatus("FUTURE_STATUS"),
					CurrentSigningKeyLength: sesv2types.DkimSigningKeyLength("RSA_8192_BIT"),
					NextSigningKeyLength:    sesv2types.DkimSigningKeyLength("RSA_16384_BIT"),
				}},
			{"empty name, signing disabled", "", sesv2types.IdentityTypeEmailAddress,
				&sesv2types.DkimAttributes{SigningEnabled: false}},
		}
		for _, c := range cases {
			c := c
			t.Run(c.desc, func(t *testing.T) {
				run(t, c.desc, func() ([]models.CryptoAsset, error) {
					a := classifySESDKIM(acct, region, c.name, c.idType, c.dkim)
					return []models.CryptoAsset{a}, nil
				})
			})
		}
	})
}
