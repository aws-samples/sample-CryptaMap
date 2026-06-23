package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeKMSCustomKeyStoreClient is a hand-rolled kmsCustomKeyStoreAPI for
// unit-testing the scanner's pagination + error propagation without a live AWS
// client. pages is returned page-by-page (each call consumes the next page) and
// the NextMarker is wired so the scanner loops through every page; err forces a
// DescribeCustomKeyStores failure.
type fakeKMSCustomKeyStoreClient struct {
	kmscustomkeystorePages []*kms.DescribeCustomKeyStoresOutput
	kmscustomkeystoreCalls int
	kmscustomkeystoreErr   error
}

func (f *fakeKMSCustomKeyStoreClient) DescribeCustomKeyStores(ctx context.Context, in *kms.DescribeCustomKeyStoresInput, optFns ...func(*kms.Options)) (*kms.DescribeCustomKeyStoresOutput, error) {
	if f.kmscustomkeystoreErr != nil {
		return nil, f.kmscustomkeystoreErr
	}
	if f.kmscustomkeystoreCalls >= len(f.kmscustomkeystorePages) {
		return &kms.DescribeCustomKeyStoresOutput{}, nil
	}
	out := f.kmscustomkeystorePages[f.kmscustomkeystoreCalls]
	f.kmscustomkeystoreCalls++
	return out, nil
}

func kmscustomkeystoreStrptr(s string) *string { return &s }

func kmscustomkeystoreAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// TestKMSCustomKeyStoreScanPaginates verifies the DescribeCustomKeyStores
// NextMarker loop: a fake that returns 2 pages (NextMarker on page 1) must yield
// BOTH pages' key stores as assets. Without the pagination restore, only the
// first page's store survives.
func TestKMSCustomKeyStoreScanPaginates(t *testing.T) {
	client := &fakeKMSCustomKeyStoreClient{
		kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{
			{
				CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{
					{CustomKeyStoreId: kmscustomkeystoreStrptr("cks-page1")},
				},
				NextMarker: kmscustomkeystoreStrptr("marker-page2"),
			},
			{
				CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{
					{CustomKeyStoreId: kmscustomkeystoreStrptr("cks-page2")},
				},
				// no NextMarker -> last page
			},
		},
	}
	assets, err := KMSCustomKeyStoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.kmscustomkeystoreCalls; c != 2 {
		t.Errorf("expected DescribeCustomKeyStores to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"cks-page1", "cks-page2"} {
		if kmscustomkeystoreAssetByID(assets, want) == nil {
			t.Errorf("expected key store %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestKMSCustomKeyStoreScanErrorPropagates verifies the owner's incompleteness
// decision: a DescribeCustomKeyStores failure (denied/rate-limited) must make the
// scan VISIBLY incomplete by returning a non-nil error — NOT a silent empty
// success.
func TestKMSCustomKeyStoreScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform kms:DescribeCustomKeyStores")
	client := &fakeKMSCustomKeyStoreClient{
		kmscustomkeystoreErr: sentinel,
	}
	_, err := KMSCustomKeyStoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeCustomKeyStores fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeCustomKeyStores failure, got: %v", err)
	}
}

// TestKMSCustomKeyStoreScanSymmetricPosture verifies the honesty posture for this
// scanner's domain: a custom key store fronts SYMMETRIC AES-256 keys to KMS, so it
// must be classified SymmetricOnly (always-encrypted, not quantum-vulnerable) and
// NEVER NoEncryption. The algorithm must map to AES-256.
func TestKMSCustomKeyStoreScanSymmetricPosture(t *testing.T) {
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
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmscustomkeystoreAssetByID(assets, "cks-hsm")
	if a == nil {
		t.Fatalf("expected an asset for cks-hsm; assets=%v", assets)
	}
	posture := a.Properties["posture"]
	if posture != string(models.PostureSymmetricOnly) {
		t.Errorf("expected posture %q (symmetric AES is always-encrypted, not quantum-vulnerable), got %q", models.PostureSymmetricOnly, posture)
	}
	if posture == string(models.PostureNoEncryption) {
		t.Errorf("a KMS custom key store must NEVER be classified NoEncryption, got %q", posture)
	}
	if a.CryptoProps.AlgorithmProperties == nil {
		t.Fatalf("expected AlgorithmProperties to be populated for an AES-backed key store")
	}
	if a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
		t.Errorf("expected AlgorithmName AES-256, got %q", a.CryptoProps.AlgorithmProperties.AlgorithmName)
	}
	if a.CryptoProps.AlgorithmProperties.KeySizeBits != 256 {
		t.Errorf("expected KeySizeBits 256, got %d", a.CryptoProps.AlgorithmProperties.KeySizeBits)
	}
	if a.Properties["cloudHsmClusterId"] != "cluster-abc" {
		t.Errorf("expected cloudHsmClusterId cluster-abc, got %q", a.Properties["cloudHsmClusterId"])
	}
}

// TestKMSCustomKeyStoreScanExternalNoteNoSilentDrop verifies that an external
// (XKS) key store is recorded (not silently dropped) and carries the external-
// custody note, while still being symmetric-only.
func TestKMSCustomKeyStoreScanExternalNoteNoSilentDrop(t *testing.T) {
	client := &fakeKMSCustomKeyStoreClient{
		kmscustomkeystorePages: []*kms.DescribeCustomKeyStoresOutput{
			{
				CustomKeyStores: []kmstypes.CustomKeyStoresListEntry{
					// nil ID -> skipped (not an asset).
					{CustomKeyStoreId: nil},
					{
						CustomKeyStoreId:   kmscustomkeystoreStrptr("cks-xks"),
						CustomKeyStoreType: kmstypes.CustomKeyStoreTypeExternalKeyStore,
						ConnectionState:    kmstypes.ConnectionStateTypeConnected,
					},
				},
			},
		},
	}
	assets, err := KMSCustomKeyStoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := kmscustomkeystoreAssetByID(assets, "cks-xks")
	if a == nil {
		t.Fatalf("expected an asset for cks-xks; assets=%v", assets)
	}
	if a.Properties["customKeyStoreType"] != string(kmstypes.CustomKeyStoreTypeExternalKeyStore) {
		t.Errorf("expected customKeyStoreType external, got %q", a.Properties["customKeyStoreType"])
	}
	if a.Properties["note"] == "" {
		t.Errorf("expected an external-custody note for an XKS key store, got empty")
	}
	if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("expected XKS key store posture symmetric-only, got %q", a.Properties["posture"])
	}
}
