package keymgmt

import (
	"context"
	"runtime/debug"
	"strings"
	"testing"

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

// TestKeymgmtScanners_AdversarialInputs drives HOSTILE / edge-case AWS API
// responses through every keymgmt scanner's scan() seam and asserts only two
// robustness invariants:
//
//	(i)  scan() never PANICS — a nil-pointer deref on an assumed-present SDK
//	     field is a real bug, so each subtest recovers the panic, t.Errorf's it
//	     with the triggering input, and keeps the process alive.
//	(ii) any NON-EMPTY returned []CryptoAsset passes output.ValidateAssetsCBOM —
//	     a raw/future AWS enum copied into a CBOM schema-enum field (e.g.
//	     relatedCryptoMaterialProperties.type / .state) would break CycloneDX 1.7
//	     validation; that is a real bug.
//
// Returning zero assets or an error for adversarial input is FINE: only a panic
// or a schema-validation failure on non-empty output is a defect. These tests
// reuse the SAME fakes/ctors as cdx_conformance_test.go and the sibling per-
// scanner unit tests (shared package).
//
// The big string used to stress id/ARN handling.
var advBigStr = strings.Repeat("A", 10000)

// advRun runs one adversarial case: it recovers any panic (t.Errorf with input
// + stack), and validates non-empty returned assets against the CBOM schema.
// A nil-error / zero-asset / non-nil-error outcome is all acceptable.
func advRun(t *testing.T, desc string, fn func() ([]models.CryptoAsset, error)) {
	t.Helper()
	t.Run(desc, func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC on adversarial input %q: %v\n%s", desc, r, debug.Stack())
			}
		}()
		assets, err := fn()
		_ = err // an error for adversarial input is acceptable.
		if len(assets) == 0 {
			return // zero assets is acceptable.
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Errorf("CBOM schema-validation FAILED on %q (%d assets): %v", desc, len(assets), verr)
		}
	})
}

func TestKeymgmtScanners_AdversarialInputs(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable: %v", err)
	}
	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	// NOTE on "nil *Output": injecting a nil operation-output pointer together
	// with a nil error is NOT a reachable AWS state — aws-sdk-go-v2 operation
	// methods return a non-nil output struct whenever the returned error is nil.
	// All nine scanners (reasonably) rely on that contract and dereference out.X
	// directly, so a synthetic nil-output would only manufacture a panic against
	// an impossible input — a false alarm. We therefore drive the REALISTIC
	// adversarial surface instead: an EMPTY but non-nil output, nil pointers
	// WITHIN a non-nil output, and unknown/future enum values.

	// ---- cloudhsm -----------------------------------------------------------
	t.Run("cloudhsm", func(t *testing.T) {
		advRun(t, "empty-cluster-list", func() ([]models.CryptoAsset, error) {
			c := &cloudhsmFakeClient{pages: []*cloudhsmv2.DescribeClustersOutput{{}}}
			return CloudHSMScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "all-nil-pointers-cluster", func() ([]models.CryptoAsset, error) {
			c := &cloudhsmFakeClient{pages: []*cloudhsmv2.DescribeClustersOutput{{
				Clusters: []cloudhsmv2types.Cluster{{}}, // nil ClusterId/HsmType/Certificates/CreateTimestamp
			}}}
			return CloudHSMScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "unknown-state-enum-and-empty-id", func() ([]models.CryptoAsset, error) {
			c := &cloudhsmFakeClient{pages: []*cloudhsmv2.DescribeClustersOutput{{
				Clusters: []cloudhsmv2types.Cluster{
					{ClusterId: cloudhsmStrptr(""), State: cloudhsmv2types.ClusterState("PENDING_QUANTUM"), Mode: cloudhsmv2types.ClusterMode("FUTURE")},
					{ClusterId: cloudhsmStrptr(advBigStr), HsmType: cloudhsmStrptr(advBigStr)},
				},
			}}}
			return CloudHSMScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- cognito ------------------------------------------------------------
	t.Run("cognito", func(t *testing.T) {
		advRun(t, "empty-pool-list", func() ([]models.CryptoAsset, error) {
			c := &fakeCognitoClient{cognitoListPages: []*cognitoidentityprovider.ListUserPoolsOutput{{}}}
			return CognitoScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "all-nil-pointers-pool", func() ([]models.CryptoAsset, error) {
			c := &fakeCognitoClient{cognitoListPages: []*cognitoidentityprovider.ListUserPoolsOutput{{
				UserPools: []cognitotypes.UserPoolDescriptionType{{}}, // nil Id/Name
			}}}
			return CognitoScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "empty-id-and-huge-name", func() ([]models.CryptoAsset, error) {
			c := &fakeCognitoClient{cognitoListPages: []*cognitoidentityprovider.ListUserPoolsOutput{{
				UserPools: []cognitotypes.UserPoolDescriptionType{
					{Id: cognitoStrptr(""), Name: cognitoStrptr("")},
					{Id: cognitoStrptr(advBigStr), Name: cognitoStrptr(advBigStr)},
				},
			}}}
			return CognitoScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- ec2keypairs --------------------------------------------------------
	t.Run("ec2keypairs", func(t *testing.T) {
		advRun(t, "empty-output", func() ([]models.CryptoAsset, error) {
			c := &fakeEC2KeyPairsClient{out: &ec2.DescribeKeyPairsOutput{}}
			return EC2KeyPairsScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "all-nil-pointers-keypair", func() ([]models.CryptoAsset, error) {
			c := &fakeEC2KeyPairsClient{out: &ec2.DescribeKeyPairsOutput{
				KeyPairs: []ec2types.KeyPairInfo{{}}, // nil KeyPairId -> skipped
			}}
			return EC2KeyPairsScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "unknown-keytype-empty-id-huge-fields", func() ([]models.CryptoAsset, error) {
			c := &fakeEC2KeyPairsClient{out: &ec2.DescribeKeyPairsOutput{
				KeyPairs: []ec2types.KeyPairInfo{
					{KeyPairId: ec2keypairsStrptr("k-future"), KeyType: ec2types.KeyType("pqc")},
					{KeyPairId: ec2keypairsStrptr(""), KeyName: ec2keypairsStrptr(advBigStr), KeyFingerprint: ec2keypairsStrptr(advBigStr)},
				},
			}}
			return EC2KeyPairsScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- kms_custom_key_store ----------------------------------------------
	t.Run("kms_custom_key_store", func(t *testing.T) {
		advRun(t, "empty-list", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSCustomKeyStoreClient{kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{{}}}
			return KMSCustomKeyStoreScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "all-nil-pointers-entry", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSCustomKeyStoreClient{kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{{
				CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{{}}, // nil CustomKeyStoreId -> skipped
			}}}
			return KMSCustomKeyStoreScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "unknown-type-and-connstate-enums", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSCustomKeyStoreClient{kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{{
				CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{{
					CustomKeyStoreId:   kmscustomkeystoreStrptr(""),
					CustomKeyStoreName: kmscustomkeystoreStrptr(advBigStr),
					CustomKeyStoreType: kmstypes.CustomKeyStoreType("AWS_FUTURE"),
					ConnectionState:    kmstypes.ConnectionStateType("FUTURE"),
				}},
			}}}
			return KMSCustomKeyStoreScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- kms_spec (highest risk: raw KeySpec/KeyState/KeyUsage -> CBOM) -----
	t.Run("kms_spec", func(t *testing.T) {
		advRun(t, "empty-list", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSSpecClient{listPages: []*kms.ListKeysOutput{{}}}
			return KMSSpecScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "nil-keyid-entry", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSSpecClient{listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{}}}}}
			return KMSSpecScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "describe-returns-nil-metadata-mismatch", func() ([]models.CryptoAsset, error) {
			// list had the key, DescribeKey returns nil KeyMetadata (configured-empty).
			c := &fakeKMSSpecClient{listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("k-mismatch")}}}}}
			return KMSSpecScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "all-nil-metadata-fields", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSSpecClient{
				listPages:    []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("k-bare")}}}},
				describeByID: map[string]*kmstypes.KeyMetadata{"k-bare": {}}, // nil KeyId & all pointers, zero enums
			}
			return KMSSpecScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "future-keyspec-keystate-keyusage-origin-enums", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSSpecClient{
				listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("k-future")}}}},
				describeByID: map[string]*kmstypes.KeyMetadata{"k-future": {
					KeyId:    kmsspecStrptr("k-future"),
					KeySpec:  kmstypes.KeySpec("ML_KEM_1024"),
					KeyUsage: kmstypes.KeyUsageType("KEY_AGREEMENT_FUTURE"),
					KeyState: kmstypes.KeyState("PendingQuantumMigration"),
					Origin:   kmstypes.OriginType("EXTERNAL_PQC"),
				}},
			}
			return KMSSpecScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "huge-keyid-and-desc", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSSpecClient{
				listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr(advBigStr)}}}},
				describeByID: map[string]*kmstypes.KeyMetadata{advBigStr: {
					KeyId:       kmsspecStrptr(advBigStr),
					KeySpec:     kmstypes.KeySpec(advBigStr),
					Description: kmsspecStrptr(advBigStr),
				}},
			}
			return KMSSpecScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- kms_rotation -------------------------------------------------------
	t.Run("kms_rotation", func(t *testing.T) {
		advRun(t, "empty-list", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSRotationClient{listPages: []*kms.ListKeysOutput{{}}}
			return KMSRotationScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "nil-keyid-entry", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSRotationClient{listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{}}}}}
			return KMSRotationScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "describe-nil-metadata", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSRotationClient{
				listPages:    []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("k-nilmeta")}}}},
				describeByID: map[string]*kms.DescribeKeyOutput{"k-nilmeta": {}}, // nil KeyMetadata
			}
			return KMSRotationScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "future-enums-symmetric-default-with-nil-rotation-output", func() ([]models.CryptoAsset, error) {
			// SYMMETRIC_DEFAULT + AWS_KMS makes rotation applicable, so
			// GetKeyRotationStatus is called; fake returns empty (non-nil) output.
			c := &fakeKMSRotationClient{
				listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("k-sym-future")}}}},
				describeByID: map[string]*kms.DescribeKeyOutput{"k-sym-future": {KeyMetadata: &kmstypes.KeyMetadata{
					KeySpec:  kmstypes.KeySpecSymmetricDefault,
					KeyUsage: kmstypes.KeyUsageType("KEY_AGREEMENT_FUTURE"),
					KeyState: kmstypes.KeyState("PendingQuantumMigration"),
					Origin:   kmstypes.OriginTypeAwsKms,
				}}},
				// rotationByID intentionally unset -> fake returns empty output (nil ptrs).
			}
			return KMSRotationScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "future-asymmetric-keyspec-rotation-inapplicable", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSRotationClient{
				listPages: []*kms.ListKeysOutput{{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("k-mlkem")}}}},
				describeByID: map[string]*kms.DescribeKeyOutput{"k-mlkem": {KeyMetadata: &kmstypes.KeyMetadata{
					KeySpec: kmstypes.KeySpec("ML_KEM_1024"),
					Origin:  kmstypes.OriginType("EXTERNAL_PQC"),
				}}},
			}
			return KMSRotationScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- kms_usage ----------------------------------------------------------
	t.Run("kms_usage", func(t *testing.T) {
		advRun(t, "empty-list", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSUsageClient{listPages: []*kms.ListAliasesOutput{{}}}
			return KMSUsageScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "nil-aliasname-entry", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSUsageClient{listPages: []*kms.ListAliasesOutput{{Aliases: []kmstypes.AliasListEntry{{}}}}}
			return KMSUsageScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "alias-target-describe-nil-metadata", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSUsageClient{
				listPages: []*kms.ListAliasesOutput{{Aliases: []kmstypes.AliasListEntry{
					{AliasName: kmsusageStrptr("alias/app"), TargetKeyId: kmsusageStrptr("k-target")},
				}}},
				describeByID: map[string]*kms.DescribeKeyOutput{"k-target": {}}, // nil KeyMetadata
			}
			return KMSUsageScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "alias-target-future-enums", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSUsageClient{
				listPages: []*kms.ListAliasesOutput{{Aliases: []kmstypes.AliasListEntry{
					{AliasName: kmsusageStrptr("alias/aws/future"), TargetKeyId: kmsusageStrptr("k-fut")},
				}}},
				describeByID: map[string]*kms.DescribeKeyOutput{"k-fut": {KeyMetadata: &kmstypes.KeyMetadata{
					KeySpec:    kmstypes.KeySpec("ML_KEM_1024"),
					KeyUsage:   kmstypes.KeyUsageType("KEY_AGREEMENT_FUTURE"),
					KeyState:   kmstypes.KeyState("PendingQuantumMigration"),
					Origin:     kmstypes.OriginType("EXTERNAL_PQC"),
					KeyManager: kmstypes.KeyManagerType("FUTURE"),
				}}},
			}
			return KMSUsageScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "empty-aliasname-and-empty-target", func() ([]models.CryptoAsset, error) {
			c := &fakeKMSUsageClient{listPages: []*kms.ListAliasesOutput{{Aliases: []kmstypes.AliasListEntry{
				{AliasName: kmsusageStrptr(""), TargetKeyId: kmsusageStrptr("")},
				{AliasName: kmsusageStrptr(advBigStr)},
			}}}}
			return KMSUsageScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- payments -----------------------------------------------------------
	t.Run("payments", func(t *testing.T) {
		advRun(t, "empty-list", func() ([]models.CryptoAsset, error) {
			c := &paymentsFakeClient{listPages: []*paymentcryptography.ListKeysOutput{{}}}
			return PaymentCryptographyScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "nil-keyarn-and-nil-attributes", func() ([]models.CryptoAsset, error) {
			c := &paymentsFakeClient{listPages: []*paymentcryptography.ListKeysOutput{{
				Keys: []pctypes.KeySummary{
					{},                                       // nil KeyArn -> skipped
					{KeyArn: paymentsStrptr("arn:no-attrs")}, // nil KeyAttributes/Enabled/Exportable
				},
			}}}
			return PaymentCryptographyScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "future-algorithm-and-keyclass-enums", func() ([]models.CryptoAsset, error) {
			c := &paymentsFakeClient{listPages: []*paymentcryptography.ListKeysOutput{{
				Keys: []pctypes.KeySummary{{
					KeyArn:   paymentsStrptr("arn:future"),
					KeyState: pctypes.KeyState("FUTURE_STATE"),
					KeyAttributes: &pctypes.KeyAttributes{
						KeyAlgorithm: pctypes.KeyAlgorithm("ML_DSA_87"),
						KeyClass:     pctypes.KeyClass("FUTURE"),
						KeyUsage:     pctypes.KeyUsage("FUTURE_USAGE"),
					},
				}},
			}}}
			return PaymentCryptographyScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "getkey-returns-future-enums-and-nil-key", func() ([]models.CryptoAsset, error) {
			c := &paymentsFakeClient{
				listPages: []*paymentcryptography.ListKeysOutput{{
					Keys: []pctypes.KeySummary{{KeyArn: paymentsStrptr("arn:getkey")}},
				}},
				getKeys: map[string]*paymentcryptography.GetKeyOutput{
					"arn:getkey": {Key: &pctypes.Key{
						KeyOrigin: pctypes.KeyOrigin("FUTURE_ORIGIN"),
						KeyAttributes: &pctypes.KeyAttributes{
							KeyAlgorithm: pctypes.KeyAlgorithm("ML_DSA_87"),
							KeyClass:     pctypes.KeyClass("FUTURE"),
						},
					}},
				},
			}
			return PaymentCryptographyScanner{}.scan(ctx, c, acct, region)
		})
		advRun(t, "huge-arn", func() ([]models.CryptoAsset, error) {
			c := &paymentsFakeClient{listPages: []*paymentcryptography.ListKeysOutput{{
				Keys: []pctypes.KeySummary{paymentsKeySummary(advBigStr, pctypes.KeyAlgorithmAes256, pctypes.KeyClassSymmetricKey)},
			}}}
			return PaymentCryptographyScanner{}.scan(ctx, c, acct, region)
		})
	})

	// ---- secrets_rotation ---------------------------------------------------
	t.Run("secrets_rotation", func(t *testing.T) {
		advRun(t, "empty-list", func() ([]models.CryptoAsset, error) {
			c := &secretsrotationFakeSM{pages: []*secretsmanager.ListSecretsOutput{{}}}
			return SecretsRotationScanner{}.scan(ctx, c, &secretsrotationFakeKMS{}, acct, region)
		})
		advRun(t, "nil-arn-entry", func() ([]models.CryptoAsset, error) {
			c := &secretsrotationFakeSM{pages: []*secretsmanager.ListSecretsOutput{{
				SecretList: []smtypes.SecretListEntry{{}}, // nil ARN -> skipped
			}}}
			return SecretsRotationScanner{}.scan(ctx, c, &secretsrotationFakeKMS{}, acct, region)
		})
		advRun(t, "empty-arn-nil-rotationrules", func() ([]models.CryptoAsset, error) {
			c := &secretsrotationFakeSM{pages: []*secretsmanager.ListSecretsOutput{{
				SecretList: []smtypes.SecretListEntry{{ARN: secretsrotationStrptr("")}},
			}}}
			return SecretsRotationScanner{}.scan(ctx, c, &secretsrotationFakeKMS{}, acct, region)
		})
		advRun(t, "customer-cmk-future-keyspec", func() ([]models.CryptoAsset, error) {
			c := &secretsrotationFakeSM{pages: []*secretsmanager.ListSecretsOutput{{
				SecretList: []smtypes.SecretListEntry{{
					ARN:      secretsrotationStrptr("arn:secret:future"),
					KmsKeyId: secretsrotationStrptr("arn:kms:future-cmk"),
				}},
			}}}
			// fake KMS returns DescribeKey with a future KeySpec string.
			return SecretsRotationScanner{}.scan(ctx, c, &secretsrotationFakeKMS{spec: "ML_KEM_1024"}, acct, region)
		})
		advRun(t, "huge-arn-and-name", func() ([]models.CryptoAsset, error) {
			c := &secretsrotationFakeSM{pages: []*secretsmanager.ListSecretsOutput{{
				SecretList: []smtypes.SecretListEntry{{ARN: secretsrotationStrptr(advBigStr), Name: secretsrotationStrptr(advBigStr)}},
			}}}
			return SecretsRotationScanner{}.scan(ctx, c, &secretsrotationFakeKMS{}, acct, region)
		})
	})
}
