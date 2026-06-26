package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeKMSRotationClient is a hand-rolled kmsRotationAPI for unit-testing the
// scanner's pagination, per-key error handling, and posture/rotation honesty
// without a live AWS client. listPages is returned page-by-page (each call
// consumes the next page) with Marker wired so the scanner loops through every
// page. describeByID/rotationByID drive per-key metadata, and describeErrByID/
// rotationErrByID force per-call failures. A top-level ListKeys failure is
// forced via listErr.
type fakeKMSRotationClient struct {
	listPages []*kms.ListKeysOutput
	listCalls int
	listErr   error

	describeByID    map[string]*kms.DescribeKeyOutput
	describeErrByID map[string]error

	rotationByID    map[string]*kms.GetKeyRotationStatusOutput
	rotationErrByID map[string]error

	rotationCalls int // counts GetKeyRotationStatus invocations
}

func (f *fakeKMSRotationClient) ListKeys(ctx context.Context, in *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
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

func (f *fakeKMSRotationClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	id := ""
	if in != nil && in.KeyId != nil {
		id = *in.KeyId
	}
	if err, ok := f.describeErrByID[id]; ok {
		return nil, err
	}
	if out, ok := f.describeByID[id]; ok {
		return out, nil
	}
	return &kms.DescribeKeyOutput{}, nil
}

func (f *fakeKMSRotationClient) GetKeyRotationStatus(ctx context.Context, in *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	f.rotationCalls++
	id := ""
	if in != nil && in.KeyId != nil {
		id = *in.KeyId
	}
	if err, ok := f.rotationErrByID[id]; ok {
		return nil, err
	}
	if out, ok := f.rotationByID[id]; ok {
		return out, nil
	}
	return &kms.GetKeyRotationStatusOutput{}, nil
}

func kmsRotationStrptr(s string) *string { return &s }

// kmsRotationDescribeOut builds a DescribeKey output for the given spec/origin,
// with no custom key store (the common applicable case).
func kmsRotationDescribeOut(spec kmstypes.KeySpec, usage kmstypes.KeyUsageType, origin kmstypes.OriginType) *kms.DescribeKeyOutput {
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeySpec:  spec,
			KeyUsage: usage,
			Origin:   origin,
		},
	}
}

// kmsRotationAssetByID indexes scan output by ResourceID.
func kmsRotationAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestKMSRotationScanPaginates verifies the ListKeys Marker loop: a fake that
// returns 2 pages (Truncated+NextMarker on page 1) must yield BOTH pages' keys
// as assets. Without the Marker restore, only the first page's key survives.
func TestKMSRotationScanPaginates(t *testing.T) {
	client := &fakeKMSRotationClient{
		listPages: []*kms.ListKeysOutput{
			{
				Keys:       []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-page1")}},
				Truncated:  true,
				NextMarker: kmsRotationStrptr("marker-page2"),
			},
			{
				Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-page2")}},
				// not truncated -> last page
			},
		},
		describeByID: map[string]*kms.DescribeKeyOutput{
			"key-page1": kmsRotationDescribeOut(kmstypes.KeySpecSymmetricDefault, kmstypes.KeyUsageTypeEncryptDecrypt, kmstypes.OriginTypeAwsKms),
			"key-page2": kmsRotationDescribeOut(kmstypes.KeySpecSymmetricDefault, kmstypes.KeyUsageTypeEncryptDecrypt, kmstypes.OriginTypeAwsKms),
		},
	}
	assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListKeys to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := kmsRotationAssetByID(assets)
	for _, want := range []string{"key-page1", "key-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected key %q from a paginated page to appear as an asset; assets=%v", want, kmsRotationKeysOf(got))
		}
	}
}

// kmsRotationKeysOf is a local debug helper to list emitted asset IDs.
func kmsRotationKeysOf(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestKMSRotationScanListKeysErrorPropagates verifies a top-level ListKeys
// failure (denied/throttled) makes the scan VISIBLY incomplete by returning a
// non-nil error wrapping the cause — NOT a silent empty success.
func TestKMSRotationScanListKeysErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform kms:ListKeys")
	client := &fakeKMSRotationClient{listErr: sentinel}
	_, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListKeys fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListKeys failure, got: %v", err)
	}
}

// TestKMSRotationDescribeKeyErrorNotSilentlyDropped verifies the no-silent-drop
// posture for per-key failures: a DescribeKey error logs to stderr but the key
// is STILL emitted as an asset (with best-effort default metadata), rather than
// vanishing from the CBOM. A dropped key would understate the key inventory.
func TestKMSRotationDescribeKeyErrorNotSilentlyDropped(t *testing.T) {
	client := &fakeKMSRotationClient{
		listPages: []*kms.ListKeysOutput{
			{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-describe-fail")}}},
		},
		describeErrByID: map[string]error{
			"key-describe-fail": errors.New("AccessDeniedException: kms:DescribeKey"),
		},
	}
	assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := kmsRotationAssetByID(assets)
	a, ok := got["key-describe-fail"]
	if !ok {
		t.Fatalf("expected the key to still be emitted despite DescribeKey error (no silent drop); assets=%v", kmsRotationKeysOf(got))
	}
	// With no metadata, keySpec stays the "kms-managed" placeholder. The
	// conservative posture for an UNKNOWN spec is Unknown (NOT a false-safe
	// SymmetricOnly that would imply quantum-resistant, and NOT a no-encryption
	// verdict). Rotation must also be reported inapplicable.
	if p := a.Properties["posture"]; p != string(models.PostureUnknown) {
		t.Errorf("DescribeKey-failed key: expected Unknown fallback posture (conservative), got %q", p)
	}
	if a.Properties["rotationApplicable"] != "false" {
		t.Errorf("DescribeKey-failed key: rotation must be inapplicable, got %q", a.Properties["rotationApplicable"])
	}
}

// TestKMSRotationAsymmetricIsClassicalNotSymmetric guards the honesty fix: an
// asymmetric RSA key must be classified NonPQCClassical (quantum-vulnerable) and
// must NOT false-safe to SymmetricOnly. It must also report rotation as
// INAPPLICABLE (not a misleading rotationEnabled=false) and must NOT call
// GetKeyRotationStatus.
func TestKMSRotationAsymmetricIsClassicalNotSymmetric(t *testing.T) {
	client := &fakeKMSRotationClient{
		listPages: []*kms.ListKeysOutput{
			{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-rsa")}}},
		},
		describeByID: map[string]*kms.DescribeKeyOutput{
			"key-rsa": kmsRotationDescribeOut(kmstypes.KeySpecRsa2048, kmstypes.KeyUsageTypeSignVerify, kmstypes.OriginTypeAwsKms),
		},
	}
	assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmsRotationAssetByID(assets)["key-rsa"]
	if p := a.Properties["posture"]; p != string(models.PostureNonPQCClassical) {
		t.Errorf("asymmetric RSA key: expected NonPQCClassical posture, got %q", p)
	}
	if a.Properties["rotationApplicable"] != "false" {
		t.Errorf("asymmetric key: rotation must be inapplicable, got rotationApplicable=%q", a.Properties["rotationApplicable"])
	}
	if a.Properties["rotationEnabled"] != "inapplicable" {
		t.Errorf("asymmetric key: rotationEnabled must be 'inapplicable' (not a misleading false), got %q", a.Properties["rotationEnabled"])
	}
	if client.rotationCalls != 0 {
		t.Errorf("asymmetric key: GetKeyRotationStatus must NOT be called for an inapplicable key, got %d calls", client.rotationCalls)
	}
}

// TestKMSRotationSymmetricDefaultIsApplicableAndSymmetricOnly verifies a
// symmetric-default AWS_KMS key: posture SymmetricOnly (always-encrypted, never
// NoEncryption), rotation APPLICABLE, GetKeyRotationStatus called, and the
// reported enabled flag reflecting the SDK response.
func TestKMSRotationSymmetricDefaultIsApplicableAndSymmetricOnly(t *testing.T) {
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
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmsRotationAssetByID(assets)["key-sym"]
	if p := a.Properties["posture"]; p != string(models.PostureSymmetricOnly) {
		t.Errorf("symmetric-default key: expected SymmetricOnly posture, got %q", p)
	}
	if a.Properties["rotationApplicable"] != "true" {
		t.Errorf("symmetric-default AWS_KMS key: rotation must be applicable, got %q", a.Properties["rotationApplicable"])
	}
	if client.rotationCalls != 1 {
		t.Errorf("applicable key: GetKeyRotationStatus must be called exactly once, got %d", client.rotationCalls)
	}
	if a.Properties["rotationEnabled"] != "true" {
		t.Errorf("applicable key: rotationEnabled must reflect SDK true, got %q", a.Properties["rotationEnabled"])
	}
}

// TestKMSRotationCustomKeyStoreIsInapplicable verifies that a symmetric-default
// key in a custom key store (CloudHSM/external) is rotation-INAPPLICABLE even
// though spec+origin alone would qualify — and GetKeyRotationStatus is skipped.
func TestKMSRotationCustomKeyStoreIsInapplicable(t *testing.T) {
	client := &fakeKMSRotationClient{
		listPages: []*kms.ListKeysOutput{
			{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-cks")}}},
		},
		describeByID: map[string]*kms.DescribeKeyOutput{
			"key-cks": {
				KeyMetadata: &kmstypes.KeyMetadata{
					KeySpec:          kmstypes.KeySpecSymmetricDefault,
					KeyUsage:         kmstypes.KeyUsageTypeEncryptDecrypt,
					Origin:           kmstypes.OriginTypeAwsCloudhsm,
					CustomKeyStoreId: kmsRotationStrptr("cks-12345"),
				},
			},
		},
	}
	assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmsRotationAssetByID(assets)["key-cks"]
	if a.Properties["rotationApplicable"] != "false" {
		t.Errorf("custom-key-store key: rotation must be inapplicable, got %q", a.Properties["rotationApplicable"])
	}
	if client.rotationCalls != 0 {
		t.Errorf("custom-key-store key: GetKeyRotationStatus must NOT be called, got %d", client.rotationCalls)
	}
}

// TestKMSRotationUnknownSpecIsUnknownNotSymmetric guards the conservative
// fallback: a future/unrecognized asymmetric-looking KeySpec must classify as
// Unknown (NOT SymmetricOnly), so a new quantum-vulnerable spec is never
// false-safed as quantum-resistant.
func TestKMSRotationUnknownSpecIsUnknownNotSymmetric(t *testing.T) {
	client := &fakeKMSRotationClient{
		listPages: []*kms.ListKeysOutput{
			{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-future")}}},
		},
		describeByID: map[string]*kms.DescribeKeyOutput{
			"key-future": {
				KeyMetadata: &kmstypes.KeyMetadata{
					KeySpec:  kmstypes.KeySpec("FUTURE_PQC_KEM_2048"),
					KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt,
					Origin:   kmstypes.OriginTypeAwsKms,
				},
			},
		},
	}
	assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmsRotationAssetByID(assets)["key-future"]
	if p := a.Properties["posture"]; p != string(models.PostureUnknown) {
		t.Errorf("unknown KeySpec: expected Unknown posture (conservative), got %q", p)
	}
}

// TestKMSRotationMLDSAIsPQCReady verifies an ML-DSA (FIPS 204) signing key is
// classified PQCReady (pure PQC signature), not classical or symmetric.
func TestKMSRotationMLDSAIsPQCReady(t *testing.T) {
	client := &fakeKMSRotationClient{
		listPages: []*kms.ListKeysOutput{
			{Keys: []kmstypes.KeyListEntry{{KeyId: kmsRotationStrptr("key-mldsa")}}},
		},
		describeByID: map[string]*kms.DescribeKeyOutput{
			"key-mldsa": {
				KeyMetadata: &kmstypes.KeyMetadata{
					KeySpec:  kmstypes.KeySpec("ML_DSA_65"),
					KeyUsage: kmstypes.KeyUsageTypeSignVerify,
					Origin:   kmstypes.OriginTypeAwsKms,
				},
			},
		},
	}
	assets, err := KMSRotationScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmsRotationAssetByID(assets)["key-mldsa"]
	if p := a.Properties["posture"]; p != string(models.PosturePQCReady) {
		t.Errorf("ML-DSA key: expected PQCReady posture, got %q", p)
	}
}
