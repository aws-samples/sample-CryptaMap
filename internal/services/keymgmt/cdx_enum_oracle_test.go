package keymgmt

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/internal/output"
)

// TestKeymgmtScanners_EnumOracle_CBOMConformance is a CONTRACT-DRIVEN bug hunt.
//
// Instead of hand-picking a few enum values, it iterates AWS's OWN authoritative
// value set for every SDK enum field a keymgmt scanner reads — via the generated
// EnumType("").Values() method — and asserts the scanner produces a schema-valid
// CycloneDX 1.7 CBOM for EVERY member. AWS's generated .Values() is the oracle: if
// a real enum value makes the scanner panic or emit a CBOM that fails official
// schema validation, that is a REAL BUG (e.g. an empty algorithmName, an invalid
// relatedCryptoMaterialProperties.type/state, a uniqueItems violation, a bad
// crypto primitive). The test is deliberately NOT softened: a failing value is
// left failing and reported.
//
// Enum fields covered:
//   - kms KeySpec       (kms_spec, kms_usage classification)
//   - kms KeyState      (kmsCryptoState -> CryptoState)
//   - kms KeyUsageType  (kmsMaterialType -> relatedCryptoMaterialProperties.type)
//   - kms OriginType    (origin property; rotation applicability)
//   - kms CustomKeyStoreType (kms_custom_key_store)
//   - ec2 KeyType       (ec2keypairs)
//
// Cognito is intentionally NOT covered: cognito.go reads no SDK enum (it derives
// a fixed RS256 signing asset from string-typed UserPoolDescriptionType fields).
func TestKeymgmtScanners_EnumOracle_CBOMConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		// Schema bundle resolution sanity: a trivial valid doc must pass; if the
		// vendored schema is absent, skip rather than false-fail.
		t.Skipf("vendored CDX schema unavailable, skipping enum-oracle conformance: %v", err)
	}

	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	// Fixed valid baselines used when iterating one KMS enum while holding the
	// other three constant. SYMMETRIC_DEFAULT / ENABLED / ENCRYPT_DECRYPT / AWS_KMS
	// is the canonical healthy symmetric CMK.
	const (
		fixedSpec   = kmstypes.KeySpecSymmetricDefault
		fixedState  = kmstypes.KeyStateEnabled
		fixedUsage  = kmstypes.KeyUsageTypeEncryptDecrypt
		fixedOrigin = kmstypes.OriginTypeAwsKms
	)

	// specClient builds a fakeKMSSpecClient returning one key whose KeyMetadata
	// carries the four supplied enum members.
	specClient := func(spec kmstypes.KeySpec, state kmstypes.KeyState, usage kmstypes.KeyUsageType, origin kmstypes.OriginType) *fakeKMSSpecClient {
		return &fakeKMSSpecClient{
			listPages: []*kms.ListKeysOutput{
				{Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("key-1")}}},
			},
			describeByID: map[string]*kmstypes.KeyMetadata{
				"key-1": {
					KeyId:    kmsspecStrptr("key-1"),
					KeySpec:  spec,
					KeyState: state,
					KeyUsage: usage,
					Origin:   origin,
				},
			},
		}
	}

	// runSpec drives KMSSpecScanner.scan and asserts no panic + schema validity for
	// the given enum label/value. assertNonEmpty: kms_spec emits an asset for every
	// real key, so a dropped asset would itself be a finding.
	runSpec := func(t *testing.T, label string, client *fakeKMSSpecClient) {
		t.Helper()
		assets, err := KMSSpecScanner{}.scan(ctx, client, acct, region)
		if err != nil {
			t.Fatalf("kms_spec scan errored for %s: %v", label, err)
		}
		if len(assets) == 0 {
			t.Fatalf("kms_spec produced no asset for %s (key silently dropped)", label)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("kms_spec CBOM failed CycloneDX 1.7 schema validation for %s: %v", label, verr)
		}
	}

	t.Run("kms_spec/KeySpec", func(t *testing.T) {
		vals := kmstypes.KeySpec("").Values()
		t.Logf("iterating %d kms KeySpec values", len(vals))
		for _, v := range vals {
			runSpec(t, "KeySpec="+string(v), specClient(v, fixedState, fixedUsage, fixedOrigin))
		}
		// Also cover the empty KeySpec ("") — a field-population gap the SDK does
		// NOT list in Values() but which DescribeKey can return; an empty spec must
		// not yield an empty/invalid algorithmName in the CBOM.
		runSpec(t, "KeySpec=(empty)", specClient(kmstypes.KeySpec(""), fixedState, fixedUsage, fixedOrigin))
	})

	t.Run("kms_spec/KeyState", func(t *testing.T) {
		vals := kmstypes.KeyState("").Values()
		t.Logf("iterating %d kms KeyState values", len(vals))
		for _, v := range vals {
			runSpec(t, "KeyState="+string(v), specClient(fixedSpec, v, fixedUsage, fixedOrigin))
		}
		runSpec(t, "KeyState=(empty)", specClient(fixedSpec, kmstypes.KeyState(""), fixedUsage, fixedOrigin))
	})

	t.Run("kms_spec/KeyUsageType", func(t *testing.T) {
		vals := kmstypes.KeyUsageType("").Values()
		t.Logf("iterating %d kms KeyUsageType values", len(vals))
		for _, v := range vals {
			runSpec(t, "KeyUsageType="+string(v), specClient(fixedSpec, fixedState, v, fixedOrigin))
		}
		runSpec(t, "KeyUsageType=(empty)", specClient(fixedSpec, fixedState, kmstypes.KeyUsageType(""), fixedOrigin))
	})

	t.Run("kms_spec/OriginType", func(t *testing.T) {
		vals := kmstypes.OriginType("").Values()
		t.Logf("iterating %d kms OriginType values", len(vals))
		for _, v := range vals {
			runSpec(t, "OriginType="+string(v), specClient(fixedSpec, fixedState, fixedUsage, v))
		}
		runSpec(t, "OriginType=(empty)", specClient(fixedSpec, fixedState, fixedUsage, kmstypes.OriginType("")))
	})

	// kms_usage resolves an alias's TARGET key spec via DescribeKey and classifies
	// with the same kmsSpecPosture used by kms_spec. Iterate KeySpec through the
	// target key to exercise the alias path independently.
	t.Run("kms_usage/KeySpec", func(t *testing.T) {
		vals := kmstypes.KeySpec("").Values()
		t.Logf("iterating %d kms KeySpec values (alias target)", len(vals))
		for _, v := range vals {
			client := &fakeKMSUsageClient{
				listPages: []*kms.ListAliasesOutput{
					{Aliases: []kmstypes.AliasListEntry{
						{AliasName: kmsusageStrptr("alias/app-key"), TargetKeyId: kmsusageStrptr("key-tgt")},
					}},
				},
				describeByID: map[string]*kms.DescribeKeyOutput{
					"key-tgt": {KeyMetadata: &kmstypes.KeyMetadata{
						KeyId:    kmsusageStrptr("key-tgt"),
						KeySpec:  v,
						KeyUsage: fixedUsage,
						KeyState: fixedState,
						Origin:   fixedOrigin,
					}},
				},
			}
			assets, err := KMSUsageScanner{}.scan(ctx, client, acct, region)
			if err != nil {
				t.Fatalf("kms_usage scan errored for KeySpec=%s: %v", v, err)
			}
			if len(assets) == 0 {
				t.Fatalf("kms_usage produced no asset for KeySpec=%s", v)
			}
			if verr := output.ValidateAssetsCBOM(assets); verr != nil {
				t.Fatalf("kms_usage CBOM failed schema validation for target KeySpec=%s: %v", v, verr)
			}
		}
	})

	// kms_rotation reads KeySpec/KeyUsageType/OriginType from DescribeKey to decide
	// classification AND rotation applicability. Iterate each independently.
	rotClient := func(spec kmstypes.KeySpec, usage kmstypes.KeyUsageType, origin kmstypes.OriginType) *fakeKMSRotationClient {
		return &fakeKMSRotationClient{
			listPages: []*kms.ListKeysOutput{
				{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-rot")}}},
			},
			describeByID: map[string]*kms.DescribeKeyOutput{
				"key-rot": kmsRotationDescribeOut(spec, usage, origin),
			},
			rotationByID: map[string]*kms.GetKeyRotationStatusOutput{
				"key-rot": {KeyRotationEnabled: true},
			},
		}
	}
	runRot := func(t *testing.T, label string, client *fakeKMSRotationClient) {
		t.Helper()
		assets, err := KMSRotationScanner{}.scan(ctx, client, acct, region)
		if err != nil {
			t.Fatalf("kms_rotation scan errored for %s: %v", label, err)
		}
		if len(assets) == 0 {
			t.Fatalf("kms_rotation produced no asset for %s", label)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("kms_rotation CBOM failed schema validation for %s: %v", label, verr)
		}
	}

	t.Run("kms_rotation/KeySpec", func(t *testing.T) {
		vals := kmstypes.KeySpec("").Values()
		t.Logf("iterating %d kms KeySpec values", len(vals))
		for _, v := range vals {
			runRot(t, "KeySpec="+string(v), rotClient(v, fixedUsage, fixedOrigin))
		}
	})

	t.Run("kms_rotation/KeyUsageType", func(t *testing.T) {
		vals := kmstypes.KeyUsageType("").Values()
		t.Logf("iterating %d kms KeyUsageType values", len(vals))
		for _, v := range vals {
			runRot(t, "KeyUsageType="+string(v), rotClient(fixedSpec, v, fixedOrigin))
		}
	})

	t.Run("kms_rotation/OriginType", func(t *testing.T) {
		vals := kmstypes.OriginType("").Values()
		t.Logf("iterating %d kms OriginType values", len(vals))
		for _, v := range vals {
			runRot(t, "OriginType="+string(v), rotClient(fixedSpec, fixedUsage, v))
		}
	})

	t.Run("kms_custom_key_store/CustomKeyStoreType", func(t *testing.T) {
		vals := kmstypes.CustomKeyStoreType("").Values()
		t.Logf("iterating %d kms CustomKeyStoreType values", len(vals))
		for _, v := range vals {
			client := &fakeKMSCustomKeyStoreClient{
				kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{
					{CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{
						{
							CustomKeyStoreId:   kmscustomkeystoreStrptr("cks-1"),
							CustomKeyStoreName: kmscustomkeystoreStrptr("store-1"),
							CustomKeyStoreType: v,
							ConnectionState:    kmstypes.ConnectionStateTypeConnected,
						},
					}},
				},
			}
			assets, err := KMSCustomKeyStoreScanner{}.scan(ctx, client, acct, region)
			if err != nil {
				t.Fatalf("kms_custom_key_store scan errored for CustomKeyStoreType=%s: %v", v, err)
			}
			if len(assets) == 0 {
				t.Fatalf("kms_custom_key_store produced no asset for CustomKeyStoreType=%s", v)
			}
			if verr := output.ValidateAssetsCBOM(assets); verr != nil {
				t.Fatalf("kms_custom_key_store CBOM failed schema validation for CustomKeyStoreType=%s: %v", v, verr)
			}
		}
	})

	t.Run("ec2keypairs/KeyType", func(t *testing.T) {
		vals := ec2types.KeyType("").Values()
		t.Logf("iterating %d ec2 KeyType values", len(vals))
		for _, v := range vals {
			client := &fakeEC2KeyPairsClient{
				out: &ec2.DescribeKeyPairsOutput{
					KeyPairs: []ec2types.KeyPairInfo{
						{
							KeyPairId:      ec2keypairsStrptr("key-" + string(v)),
							KeyName:        ec2keypairsStrptr("name-" + string(v)),
							KeyType:        v,
							KeyFingerprint: ec2keypairsStrptr("aa:bb:cc"),
						},
					},
				},
			}
			assets, err := EC2KeyPairsScanner{}.scan(ctx, client, acct, region)
			if err != nil {
				t.Fatalf("ec2keypairs scan errored for KeyType=%s: %v", v, err)
			}
			if len(assets) == 0 {
				t.Fatalf("ec2keypairs produced no asset for KeyType=%s", v)
			}
			if verr := output.ValidateAssetsCBOM(assets); verr != nil {
				t.Fatalf("ec2keypairs CBOM failed schema validation for KeyType=%s: %v", v, verr)
			}
		}
	})
}
