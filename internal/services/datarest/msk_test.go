package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kafka"
	kafkatypes "github.com/aws/aws-sdk-go-v2/service/kafka/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeMSKClient is a hand-rolled mskAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the NextToken is wired so
// the scanner loops through every page; err forces a ListClustersV2 failure.
type fakeMSKClient struct {
	pages []*kafka.ListClustersV2Output
	calls int
	err   error
}

func (f *fakeMSKClient) ListClustersV2(ctx context.Context, in *kafka.ListClustersV2Input, optFns ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &kafka.ListClustersV2Output{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func mskSP(s string) *string { return &s }

func mskProvisionedCluster(name, kmsKey string) kafkatypes.Cluster {
	c := kafkatypes.Cluster{ClusterName: mskSP(name)}
	if kmsKey != "" {
		c.Provisioned = &kafkatypes.Provisioned{
			EncryptionInfo: &kafkatypes.EncryptionInfo{
				EncryptionAtRest: &kafkatypes.EncryptionAtRest{DataVolumeKMSKeyId: mskSP(kmsKey)},
			},
		}
	} else {
		c.Provisioned = &kafkatypes.Provisioned{}
	}
	return c
}

func mskServerlessCluster(name string) kafkatypes.Cluster {
	return kafkatypes.Cluster{ClusterName: mskSP(name), Serverless: &kafkatypes.Serverless{}}
}

func mskAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestMSKScanPaginates verifies the ListClustersV2 NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' clusters as
// assets. Without the pagination loop, only the first page's cluster survives.
func TestMSKScanPaginates(t *testing.T) {
	client := &fakeMSKClient{
		pages: []*kafka.ListClustersV2Output{
			{
				ClusterInfoList: []kafkatypes.Cluster{mskProvisionedCluster("cluster-page1", "")},
				NextToken:       mskSP("tok-page2"),
			},
			{
				ClusterInfoList: []kafkatypes.Cluster{mskProvisionedCluster("cluster-page2", "")},
				// no NextToken -> last page
			},
		},
	}
	assets, err := MSKScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListClustersV2 to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := mskAssetByID(assets, want); !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestMSKScanListErrorPropagates verifies the owner's incompleteness decision: a
// ListClustersV2 failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestMSKScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform kafka:ListClustersV2")
	client := &fakeMSKClient{err: sentinel}
	assets, err := MSKScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListClustersV2 fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListClustersV2 failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a top-level list error, got %d", len(assets))
	}
}

// TestMSKScanPostureAndKMS verifies the honesty posture mapping for MSK's domain.
// MSK ALWAYS encrypts at rest (universal AWS-doc guarantee for both provisioned
// and serverless), so every cluster MUST be SymmetricOnly and NEVER NoEncryption.
// A provisioned cluster with a customer-supplied DataVolumeKMSKeyId records that
// CMK; a serverless (or provisioned-without-CMK) cluster leaves kmsKeyId unset
// (MSK uses an AWS-managed/owned key on your behalf) rather than inventing one.
func TestMSKScanPostureAndKMS(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
	client := &fakeMSKClient{
		pages: []*kafka.ListClustersV2Output{
			{
				ClusterInfoList: []kafkatypes.Cluster{
					mskProvisionedCluster("with-cmk", cmk),
					mskProvisionedCluster("no-cmk", ""),
					mskServerlessCluster("serverless"),
					// nil ClusterName must be skipped, not panic.
					{ClusterName: nil},
				},
			},
		},
	}
	assets, err := MSKScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 assets (nil-name cluster skipped), got %d", len(assets))
	}

	for _, a := range assets {
		posture := a.Properties["posture"]
		if posture == string(models.PostureNoEncryption) {
			t.Errorf("cluster %q reported NoEncryption; MSK always encrypts at rest and must never be NoEncryption", a.ResourceID)
		}
		if posture != string(models.PostureSymmetricOnly) {
			t.Errorf("cluster %q: expected posture %q, got %q", a.ResourceID, models.PostureSymmetricOnly, posture)
		}
	}

	// CMK present -> recorded.
	withCMK, ok := mskAssetByID(assets, "with-cmk")
	if !ok {
		t.Fatal("expected with-cmk cluster asset")
	}
	if got := withCMK.Properties["kmsKeyId"]; got != cmk {
		t.Errorf("expected with-cmk to record kmsKeyId %q, got %q", cmk, got)
	}

	// CMK absent (provisioned-without-CMK and serverless) -> AWS-managed/owned
	// default, key id left UNSET rather than fabricated.
	for _, id := range []string{"no-cmk", "serverless"} {
		a, ok := mskAssetByID(assets, id)
		if !ok {
			t.Fatalf("expected %s cluster asset", id)
		}
		if _, present := a.Properties["kmsKeyId"]; present {
			t.Errorf("expected %s to leave kmsKeyId unset (AWS-managed key), but it was recorded", id)
		}
	}
}
