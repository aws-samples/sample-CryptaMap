package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeKMSSpecClient is a hand-rolled kmsSpecAPI for unit-testing the scanner's
// ListKeys pagination + per-key DescribeKey handling without a live AWS client.
// listPages is returned page-by-page (each ListKeys call consumes the next page)
// with the Marker/Truncated fields wired so the scanner loops through every page;
// listErr forces a top-level ListKeys failure; describeByID supplies per-key
// metadata and describeErrByID forces a per-key DescribeKey failure.
type fakeKMSSpecClient struct {
	listPages       []*kms.ListKeysOutput
	listCalls       int
	listErr         error
	describeByID    map[string]*kmstypes.KeyMetadata
	describeErrByID map[string]error
	describeCalls   int
}

func (f *fakeKMSSpecClient) ListKeys(ctx context.Context, in *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &kms.ListKeysOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeKMSSpecClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.describeCalls++
	id := ""
	if in.KeyId != nil {
		id = *in.KeyId
	}
	if f.describeErrByID != nil {
		if err, ok := f.describeErrByID[id]; ok {
			return nil, err
		}
	}
	if f.describeByID != nil {
		if meta, ok := f.describeByID[id]; ok {
			return &kms.DescribeKeyOutput{KeyMetadata: meta}, nil
		}
	}
	// No metadata configured for this key -> nil metadata (scanner drops it).
	return &kms.DescribeKeyOutput{}, nil
}

func kmsspecStrptr(s string) *string { return &s }

// kmsspecAssetByID indexes assets by ResourceID for assertions.
func kmsspecAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// kmsspecPostureOf returns the posture property stamped on an asset.
func kmsspecPostureOf(a models.CryptoAsset) string {
	return a.Properties["posture"]
}

// TestKMSSpecScanPaginatesKeys verifies the ListKeys Marker loop: a fake that
// returns 2 pages (Truncated + NextMarker on page 1) must yield BOTH pages' keys
// as assets. Without the pagination restore, only the first page's key survives.
func TestKMSSpecScanPaginatesKeys(t *testing.T) {
	client := &fakeKMSSpecClient{
		listPages: []*kms.ListKeysOutput{
			{
				Keys:       []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("key-page1")}},
				Truncated:  true,
				NextMarker: kmsspecStrptr("marker-page2"),
			},
			{
				Keys: []kmstypes.KeyListEntry{{KeyId: kmsspecStrptr("key-page2")}},
				// Truncated false -> last page
			},
		},
		describeByID: map[string]*kmstypes.KeyMetadata{
			"key-page1": {KeyId: kmsspecStrptr("key-page1"), KeySpec: kmstypes.KeySpecSymmetricDefault, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeyState: kmstypes.KeyStateEnabled},
			"key-page2": {KeyId: kmsspecStrptr("key-page2"), KeySpec: kmstypes.KeySpecSymmetricDefault, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeyState: kmstypes.KeyStateEnabled},
		},
	}
	assets, err := KMSSpecScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.listCalls; c != 2 {
		t.Errorf("expected ListKeys to be called 2 times (paginated), got %d", c)
	}
	got := kmsspecAssetByID(assets)
	for _, want := range []string{"key-page1", "key-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected key %q from a paginated page to appear as an asset; assets=%v", want, kmsspecKeysOfMap(got))
		}
	}
}

// kmsspecKeysOfMap is a tiny prefixed-via-helper-name diagnostic — kept local & uniquely
// named so it cannot collide with sibling test files in the package.
func kmsspecKeysOfMap(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestKMSSpecScanListKeysErrorPropagates verifies the incompleteness posture: a
// ListKeys failure (denied/rate-limited) must make the scan VISIBLY incomplete by
// returning a non-nil error — NOT a silent empty success.
func TestKMSSpecScanListKeysErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform kms:ListKeys")
	client := &fakeKMSSpecClient{listErr: sentinel}
	_, err := KMSSpecScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListKeys fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListKeys failure, got: %v", err)
	}
}

// TestKMSSpecScanPerKeyDescribeErrorDropsOnlyThatKey verifies a DescribeKey error
// on one key does not fail the whole scan and does not silently drop the OTHER
// healthy keys — only the errored key is absent. (Per the scanner's documented
// behavior, a DescribeKey error drops that single key.)
func TestKMSSpecScanPerKeyDescribeErrorDropsOnlyThatKey(t *testing.T) {
	client := &fakeKMSSpecClient{
		listPages: []*kms.ListKeysOutput{
			{Keys: []kmstypes.KeyListEntry{
				{KeyId: kmsspecStrptr("key-ok")},
				{KeyId: kmsspecStrptr("key-denied")},
			}},
		},
		describeByID: map[string]*kmstypes.KeyMetadata{
			"key-ok": {KeyId: kmsspecStrptr("key-ok"), KeySpec: kmstypes.KeySpecSymmetricDefault, KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt, KeyState: kmstypes.KeyStateEnabled},
		},
		describeErrByID: map[string]error{
			"key-denied": errors.New("AccessDeniedException: kms:DescribeKey"),
		},
	}
	assets, err := KMSSpecScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("per-key DescribeKey error must not fail the whole scan, got: %v", err)
	}
	got := kmsspecAssetByID(assets)
	if _, ok := got["key-ok"]; !ok {
		t.Error("expected the healthy key-ok to survive a sibling DescribeKey error")
	}
	if _, ok := got["key-denied"]; ok {
		t.Error("expected the DescribeKey-errored key-denied to be dropped, but it appeared")
	}
}

// TestKMSSpecKeyTierAndOrigin asserts the scanner faithfully surfaces the
// key-custody evidence regulated (BFSI) customers depend on: KeyManager
// (CUSTOMER vs AWS) and Origin (AWS_KMS vs EXTERNAL=imported BYOK vs
// AWS_CLOUDHSM). These are the fields that distinguish a customer-managed CMK and
// imported BYOK material from an AWS-managed/owned key. The internal Layer-4 live
// pass (kms_byok leg; see docs/VALIDATION.md) proves the CUSTOMER/AWS_KMS path
// against real AWS; this unit test covers what live CANNOT cheaply create —
// notably Origin=EXTERNAL (imported
// BYOK is not atomically CFN-creatable) — and the NEGATIVE side (an AWS-managed
// key must report KeyManager=AWS, so a bug stamping CUSTOMER on everything fails).
func TestKMSSpecKeyTierAndOrigin(t *testing.T) {
	cases := []struct {
		name        string
		keyID       string
		manager     kmstypes.KeyManagerType
		origin      kmstypes.OriginType
		wantManager string
		wantOrigin  string
	}{
		{"customer-managed-kms-origin", "k-cust", kmstypes.KeyManagerTypeCustomer, kmstypes.OriginTypeAwsKms, "CUSTOMER", "AWS_KMS"},
		{"imported-byok-external-origin", "k-byok", kmstypes.KeyManagerTypeCustomer, kmstypes.OriginTypeExternal, "CUSTOMER", "EXTERNAL"},
		{"cloudhsm-backed-origin", "k-hsm", kmstypes.KeyManagerTypeCustomer, kmstypes.OriginTypeAwsCloudhsm, "CUSTOMER", "AWS_CLOUDHSM"},
		{"aws-managed-key", "k-awsmanaged", kmstypes.KeyManagerTypeAws, kmstypes.OriginTypeAwsKms, "AWS", "AWS_KMS"},
	}
	keys := make([]kmstypes.KeyListEntry, 0, len(cases))
	meta := map[string]*kmstypes.KeyMetadata{}
	for _, c := range cases {
		keys = append(keys, kmstypes.KeyListEntry{KeyId: kmsspecStrptr(c.keyID)})
		meta[c.keyID] = &kmstypes.KeyMetadata{
			KeyId:      kmsspecStrptr(c.keyID),
			KeySpec:    kmstypes.KeySpecSymmetricDefault,
			KeyUsage:   kmstypes.KeyUsageTypeEncryptDecrypt,
			KeyState:   kmstypes.KeyStateEnabled,
			KeyManager: c.manager,
			Origin:     c.origin,
		}
	}
	client := &fakeKMSSpecClient{
		listPages:    []*kms.ListKeysOutput{{Keys: keys}},
		describeByID: meta,
	}
	assets, err := KMSSpecScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := kmsspecAssetByID(assets)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := got[c.keyID]
			if !ok {
				t.Fatalf("expected asset for key %q", c.keyID)
			}
			if m := a.Properties["keyManager"]; m != c.wantManager {
				t.Errorf("key %q: keyManager = %q, want %q", c.keyID, m, c.wantManager)
			}
			if o := a.Properties["origin"]; o != c.wantOrigin {
				t.Errorf("key %q: origin = %q, want %q", c.keyID, o, c.wantOrigin)
			}
		})
	}
}

// TestKMSSpecPostureHonesty asserts the spec->posture mapping is honest across
// the KMS domain: symmetric/HMAC keys are SymmetricOnly (always-encrypted, never
// NoEncryption); classical asymmetric RSA/ECC/SM2 are NonPQCClassical; the pure
// PQC signature spec ML-DSA is PQCReady (NOT hybrid); and an unknown/future spec
// is Unknown (NOT false-safed to symmetric-only).
func TestKMSSpecPostureHonesty(t *testing.T) {
	cases := []struct {
		name    string
		keyID   string
		spec    kmstypes.KeySpec
		usage   kmstypes.KeyUsageType
		wantPos models.CryptoPosture
	}{
		{"symmetric-default-symmetric-only", "k-sym", kmstypes.KeySpecSymmetricDefault, kmstypes.KeyUsageTypeEncryptDecrypt, models.PostureSymmetricOnly},
		{"hmac-symmetric-only", "k-hmac", kmstypes.KeySpecHmac256, kmstypes.KeyUsageTypeGenerateVerifyMac, models.PostureSymmetricOnly},
		{"rsa-classical", "k-rsa", kmstypes.KeySpecRsa2048, kmstypes.KeyUsageTypeSignVerify, models.PostureNonPQCClassical},
		{"ecc-classical", "k-ecc", kmstypes.KeySpecEccNistP256, kmstypes.KeyUsageTypeSignVerify, models.PostureNonPQCClassical},
		{"sm2-classical", "k-sm2", kmstypes.KeySpecSm2, kmstypes.KeyUsageTypeSignVerify, models.PostureNonPQCClassical},
		{"mldsa-pqc-ready", "k-mldsa", kmstypes.KeySpec("ML_DSA_65"), kmstypes.KeyUsageTypeSignVerify, models.PosturePQCReady},
		{"unknown-future-spec", "k-future", kmstypes.KeySpec("PQ_KEM_FUTURE_9999"), kmstypes.KeyUsageTypeEncryptDecrypt, models.PostureUnknown},
	}

	keys := make([]kmstypes.KeyListEntry, 0, len(cases))
	meta := map[string]*kmstypes.KeyMetadata{}
	for _, c := range cases {
		keys = append(keys, kmstypes.KeyListEntry{KeyId: kmsspecStrptr(c.keyID)})
		meta[c.keyID] = &kmstypes.KeyMetadata{
			KeyId:    kmsspecStrptr(c.keyID),
			KeySpec:  c.spec,
			KeyUsage: c.usage,
			KeyState: kmstypes.KeyStateEnabled,
		}
	}
	client := &fakeKMSSpecClient{
		listPages:    []*kms.ListKeysOutput{{Keys: keys}},
		describeByID: meta,
	}
	assets, err := KMSSpecScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := kmsspecAssetByID(assets)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := got[c.keyID]
			if !ok {
				t.Fatalf("expected asset for key %q to be emitted", c.keyID)
			}
			if pos := kmsspecPostureOf(a); pos != string(c.wantPos) {
				t.Errorf("key %q (spec %s): posture = %q, want %q", c.keyID, c.spec, pos, c.wantPos)
			}
			// A KMS key is always key material — it must never be classified as
			// NoEncryption regardless of spec.
			if kmsspecPostureOf(a) == "no-encryption" {
				t.Errorf("key %q must never be NoEncryption (it is key material)", c.keyID)
			}
		})
	}
}
