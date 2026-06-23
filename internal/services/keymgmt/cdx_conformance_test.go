package keymgmt

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudhsmv2"
	cloudhsmv2types "github.com/aws/aws-sdk-go-v2/service/cloudhsmv2/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	pctypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestRelatedMaterialScanners_CBOMSchemaConformance drives the REAL scan() cores
// of the related-crypto-material scanners (the ones whose CycloneDX
// relatedCryptoMaterialProperties.type values were previously invalid enum
// members) with synthetic SDK inputs, then validates the CBOM their output
// produces against the official CycloneDX 1.7 schema.
//
// This is the offline conformance seam: it proves the actual scanner output — not
// a hand-built approximation — is schema-valid, WITHOUT a live AWS account. Before
// the enum fix (hsm-cluster / secret), this test would FAIL schema validation.
func TestRelatedMaterialScanners_CBOMSchemaConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		// Schema bundle resolution sanity: a trivial valid doc must pass; if the
		// vendored schema is absent, skip rather than false-fail.
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	t.Run("cloudhsm", func(t *testing.T) {
		client := &cloudhsmFakeClient{
			pages: []*cloudhsmv2.DescribeClustersOutput{{
				Clusters: []cloudhsmv2types.Cluster{
					{ClusterId: cloudhsmStrptr("cluster-1"), HsmType: cloudhsmStrptr("hsm1.medium"), State: cloudhsmv2types.ClusterStateActive},
				},
			}},
		}
		assets, err := CloudHSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(assets) == 0 {
			t.Fatal("expected at least one CloudHSM asset")
		}
		if err := output.ValidateAssetsCBOM(assets); err != nil {
			t.Fatalf("CloudHSM CBOM failed CycloneDX 1.7 schema validation: %v", err)
		}
	})

	t.Run("secrets_rotation", func(t *testing.T) {
		client := &secretsrotationFakeSM{
			pages: []*secretsmanager.ListSecretsOutput{{
				SecretList: []smtypes.SecretListEntry{
					{ARN: secretsrotationStrptr("arn:secret:managed")},
				},
			}},
		}
		assets, err := SecretsRotationScanner{}.scan(context.Background(), client, &secretsrotationFakeKMS{}, "111122223333", "us-east-1")
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(assets) == 0 {
			t.Fatal("expected at least one Secrets Manager asset")
		}
		if err := output.ValidateAssetsCBOM(assets); err != nil {
			t.Fatalf("SecretsManager CBOM failed CycloneDX 1.7 schema validation: %v", err)
		}
	})

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

	t.Run("cognito", func(t *testing.T) {
		client := &fakeCognitoClient{
			cognitoListPages: []*cognitoidentityprovider.ListUserPoolsOutput{
				{UserPools: []cognitotypes.UserPoolDescriptionType{{Id: cognitoStrptr("pool-1"), Name: cognitoStrptr("MyPool")}}},
			},
		}
		assets, err := CognitoScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("ec2keypairs", func(t *testing.T) {
		created := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
		client := &fakeEC2KeyPairsClient{
			out: &ec2.DescribeKeyPairsOutput{
				KeyPairs: []ec2types.KeyPairInfo{
					{KeyPairId: ec2keypairsStrptr("key-rsa"), KeyName: ec2keypairsStrptr("rsa-key"), KeyType: ec2types.KeyTypeRsa, KeyFingerprint: ec2keypairsStrptr("aa:bb"), CreateTime: &created},
					{KeyPairId: ec2keypairsStrptr("key-ed"), KeyName: ec2keypairsStrptr("ed-key"), KeyType: ec2types.KeyTypeEd25519},
				},
			},
		}
		assets, err := EC2KeyPairsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("kms_custom_key_store", func(t *testing.T) {
		client := &fakeKMSCustomKeyStoreClient{
			kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{
				{
					CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{
						{
							CustomKeyStoreId:   kmscustomkeystoreStrptr("cks-hsm"),
							CustomKeyStoreName: kmscustomkeystoreStrptr("hsm-store"),
							CustomKeyStoreType: kmstypes.CustomKeyStoreTypeAwsCloudhsm,
							ConnectionState:    kmstypes.ConnectionStateTypeConnected,
							CloudHsmClusterId:  kmscustomkeystoreStrptr("cluster-abc"),
						},
					},
				},
			},
		}
		assets, err := KMSCustomKeyStoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("kms_rotation", func(t *testing.T) {
		client := &fakeKMSRotationClient{
			listPages: []*kms.ListKeysOutput{
				{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-sym")}}},
			},
			describeByID: map[string]*kms.DescribeKeyOutput{
				"key-sym": kmsRotationDescribeOut(kmstypes.KeySpecSymmetricDefault, kmstypes.KeyUsageTypeEncryptDecrypt, kmstypes.OriginTypeAwsKms),
			},
			rotationByID: map[string]*kms.GetKeyRotationStatusOutput{
				"key-sym": {KeyRotationEnabled: true},
			},
		}
		assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("kms_spec", func(t *testing.T) {
		client := &fakeKMSSpecClient{
			listPages: []*kms.ListKeysOutput{
				{Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("key-1")}}},
			},
			describeByID: map[string]*kmstypes.KeyMetadata{
				"key-1": {KeyId: kmsspecStrptr("key-1"), KeySpec: kmstypes.KeySpecSymmetricDefault, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeyState: kmstypes.KeyStateEnabled},
			},
		}
		assets, err := KMSSpecScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("payments", func(t *testing.T) {
		client := &paymentsFakeClient{
			listPages: []*paymentcryptography.ListKeysOutput{
				{
					Keys: []pctypes.KeySummary{
						paymentsKeySummary("arn:aes", pctypes.KeyAlgorithmAes256, pctypes.KeyClassSymmetricKey),
						paymentsKeySummary("arn:rsa", pctypes.KeyAlgorithmRsa3072, pctypes.KeyClassAsymmetricKeyPair),
						paymentsKeySummary("arn:ecc", pctypes.KeyAlgorithmEccNistP256, pctypes.KeyClassAsymmetricKeyPair),
					},
				},
			},
		}
		assets, err := PaymentCryptographyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("kms_usage", func(t *testing.T) {
		// Alias -> symmetric encryption key (resolved via DescribeKey). Exercises
		// relatedCryptoMaterialProperties.type "other" (alias is a mapping, not key
		// material), which the schema enum must accept.
		client := &fakeKMSUsageClient{
			listPages: []*kms.ListAliasesOutput{
				{Aliases: []kmstypes.AliasListEntry{
					{AliasName: kmsusageStrptr("alias/app-key"), TargetKeyId: kmsusageStrptr("key-sym")},
				}},
			},
			describeByID: map[string]*kms.DescribeKeyOutput{
				"key-sym": {KeyMetadata: &kmstypes.KeyMetadata{
					KeyId:      kmsusageStrptr("key-sym"),
					KeySpec:    kmstypes.KeySpecSymmetricDefault,
					KeyUsage:   kmstypes.KeyUsageTypeEncryptDecrypt,
					KeyState:   kmstypes.KeyStateEnabled,
					Origin:     kmstypes.OriginTypeAwsKms,
					KeyManager: kmstypes.KeyManagerTypeCustomer,
				}},
			},
		}
		assets, err := KMSUsageScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})
}

func kmsusageStrptr(s string) *string { return &s }

// fakeKMSUsageClient is a hand-rolled kmsUsageAPI: it returns canned ListAliases
// pages and, per target key id, a canned DescribeKey output.
type fakeKMSUsageClient struct {
	listPages    []*kms.ListAliasesOutput
	listCalls    int
	describeByID map[string]*kms.DescribeKeyOutput
}

func (f *fakeKMSUsageClient) ListAliases(ctx context.Context, in *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if f.listCalls >= len(f.listPages) {
		return &kms.ListAliasesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeKMSUsageClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if in.KeyId != nil {
		if out, ok := f.describeByID[*in.KeyId]; ok {
			return out, nil
		}
	}
	return &kms.DescribeKeyOutput{}, nil
}
