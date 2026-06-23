package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRedshiftClient is a hand-rolled redshiftClustersAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the Marker is
// wired so the scanner loops through every page; err forces a DescribeClusters
// failure on the first call.
type fakeRedshiftClient struct {
	pages []*redshift.DescribeClustersOutput
	calls int
	err   error
}

func (f *fakeRedshiftClient) DescribeClusters(ctx context.Context, in *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &redshift.DescribeClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func rsStr(s string) *string { return &s }
func rsBool(b bool) *bool    { return &b }

func rsAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestRedshiftScanPaginates verifies the DescribeClusters Marker loop: a fake that
// returns 2 pages (Marker on page 1) must yield BOTH pages' clusters as assets.
// Without the pagination restore, only the first page's cluster survives.
func TestRedshiftScanPaginates(t *testing.T) {
	client := &fakeRedshiftClient{
		pages: []*redshift.DescribeClustersOutput{
			{
				Clusters: []redshifttypes.Cluster{
					{ClusterIdentifier: rsStr("cluster-page1"), Encrypted: rsBool(true)},
				},
				Marker: rsStr("marker-page2"),
			},
			{
				Clusters: []redshifttypes.Cluster{
					{ClusterIdentifier: rsStr("cluster-page2"), Encrypted: rsBool(false)},
				},
				// no Marker -> last page
			},
		},
	}
	assets, err := RedshiftScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeClusters to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := rsAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestRedshiftScanErrorPropagates verifies the owner's incompleteness decision: a
// DescribeClusters failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the cause — NOT a silent empty
// success.
func TestRedshiftScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform redshift:DescribeClusters")
	client := &fakeRedshiftClient{err: sentinel}
	assets, err := RedshiftScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClusters failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on a top-level error, got %d", len(assets))
	}
}

// TestRedshiftScanPostureHonesty asserts the at-rest posture mapping. Redshift
// encryption is OPT-IN (not always-on), so a genuinely-unencrypted cluster is
// correctly NoEncryption; an encrypted cluster is SymmetricOnly (AES, classical),
// never NoEncryption. A CMK present must be recorded; absent (AWS-managed/owned
// default) must NOT fabricate a kmsKeyId.
func TestRedshiftScanPostureHonesty(t *testing.T) {
	client := &fakeRedshiftClient{
		pages: []*redshift.DescribeClustersOutput{
			{
				Clusters: []redshifttypes.Cluster{
					// Encrypted with a customer/managed KMS key -> recorded.
					{
						ClusterIdentifier: rsStr("enc-cmk"),
						Encrypted:         rsBool(true),
						KmsKeyId:          rsStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
					},
					// Encrypted but no KmsKeyId in the response -> recorded as encrypted,
					// but no kmsKeyId fabricated.
					{
						ClusterIdentifier: rsStr("enc-nokey"),
						Encrypted:         rsBool(true),
					},
					// Genuinely not encrypted (opt-in off) -> NoEncryption.
					{
						ClusterIdentifier: rsStr("plain"),
						Encrypted:         rsBool(false),
					},
					// Encrypted field nil -> treated as not encrypted (no false-safe).
					{
						ClusterIdentifier: rsStr("nilenc"),
					},
				},
			},
		},
	}
	assets, err := RedshiftScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	encCMK, ok := rsAssetByID(assets, "enc-cmk")
	if !ok {
		t.Fatal("missing asset enc-cmk")
	}
	if got := encCMK.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("enc-cmk: expected posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if encCMK.Properties["kmsKeyId"] != "arn:aws:kms:us-east-1:111122223333:key/abc" {
		t.Errorf("enc-cmk: expected kmsKeyId recorded, got %q", encCMK.Properties["kmsKeyId"])
	}

	encNoKey, ok := rsAssetByID(assets, "enc-nokey")
	if !ok {
		t.Fatal("missing asset enc-nokey")
	}
	if got := encNoKey.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("enc-nokey: expected posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if _, present := encNoKey.Properties["kmsKeyId"]; present {
		t.Errorf("enc-nokey: expected NO fabricated kmsKeyId, but key was present: %q", encNoKey.Properties["kmsKeyId"])
	}

	plain, ok := rsAssetByID(assets, "plain")
	if !ok {
		t.Fatal("missing asset plain")
	}
	if got := plain.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("plain: expected posture %q (opt-in encryption genuinely off), got %q", models.PostureNoEncryption, got)
	}

	nilEnc, ok := rsAssetByID(assets, "nilenc")
	if !ok {
		t.Fatal("missing asset nilenc")
	}
	if got := nilEnc.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("nilenc: expected posture %q when Encrypted is nil (no false-safe), got %q", models.PostureNoEncryption, got)
	}
}
