package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRDSClient is a hand-rolled rdsAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the Marker is wired so the
// scanner loops through every page; err forces a DescribeDBInstances failure.
type fakeRDSClient struct {
	pages []*rds.DescribeDBInstancesOutput
	calls int
	err   error
}

func (f *fakeRDSClient) DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &rds.DescribeDBInstancesOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func rdsStrptr(s string) *string { return &s }
func rdsBoolptr(b bool) *bool    { return &b }

// rdsFindAsset returns the first asset with the given ResourceID, or nil.
func rdsFindAsset(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// TestRDSScanPaginates verifies the DescribeDBInstances Marker loop: a fake that
// returns 2 pages (Marker on page 1) must yield BOTH pages' instances as assets.
// Without the pagination loop, only the first page's instance survives.
func TestRDSScanPaginates(t *testing.T) {
	client := &fakeRDSClient{
		pages: []*rds.DescribeDBInstancesOutput{
			{
				DBInstances: []rdstypes.DBInstance{
					{DBInstanceIdentifier: rdsStrptr("db-page1"), StorageEncrypted: rdsBoolptr(true), KmsKeyId: rdsStrptr("arn:aws:kms:us-east-1:111122223333:key/abc")},
				},
				Marker: rdsStrptr("marker-page2"),
			},
			{
				DBInstances: []rdstypes.DBInstance{
					{DBInstanceIdentifier: rdsStrptr("db-page2"), StorageEncrypted: rdsBoolptr(false)},
				},
				// no Marker -> last page
			},
		},
	}
	assets, err := RDSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeDBInstances to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"db-page1", "db-page2"} {
		if rdsFindAsset(assets, want) == nil {
			t.Errorf("expected instance %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestRDSScanErrorPropagates verifies a DescribeDBInstances failure
// (denied/rate-limited) makes the scan VISIBLY incomplete by returning a non-nil
// error — NOT a silent empty success.
func TestRDSScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBInstances")
	client := &fakeRDSClient{err: sentinel}
	assets, err := RDSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDBInstances fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDBInstances failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on error, got %v", assets)
	}
}

// TestRDSScanPostureHonesty verifies the at-rest posture mapping for RDS, whose
// storage encryption is OPT-IN (off by default):
//   - encrypted instance -> SymmetricOnly (AES at-rest, quantum-resistant), never NoEncryption
//   - genuinely-unencrypted instance -> NoEncryption (correct, not a false all-clear)
//   - a present CMK KmsKeyId is recorded on the encrypted asset
func TestRDSScanPostureHonesty(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/cmk-1234"
	client := &fakeRDSClient{
		pages: []*rds.DescribeDBInstancesOutput{
			{
				DBInstances: []rdstypes.DBInstance{
					{DBInstanceIdentifier: rdsStrptr("db-encrypted"), StorageEncrypted: rdsBoolptr(true), KmsKeyId: rdsStrptr(cmk)},
					{DBInstanceIdentifier: rdsStrptr("db-plaintext"), StorageEncrypted: rdsBoolptr(false)},
					{DBInstanceIdentifier: rdsStrptr("db-nil-flag")}, // StorageEncrypted nil -> treated as not encrypted
				},
			},
		},
	}
	assets, err := RDSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	enc := rdsFindAsset(assets, "db-encrypted")
	if enc == nil {
		t.Fatal("expected encrypted instance asset")
	}
	if got := enc.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("encrypted instance: expected posture %q (AES at-rest, quantum-resistant), got %q", models.PostureSymmetricOnly, got)
	}
	if got := enc.Properties["posture"]; got == string(models.PostureNoEncryption) {
		t.Errorf("encrypted instance must NOT be classified no-encryption")
	}
	if got := enc.Properties["kmsKeyId"]; got != cmk {
		t.Errorf("expected present CMK %q to be recorded, got %q", cmk, got)
	}

	plain := rdsFindAsset(assets, "db-plaintext")
	if plain == nil {
		t.Fatal("expected plaintext instance asset")
	}
	if got := plain.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("genuinely-unencrypted instance: expected posture %q, got %q", models.PostureNoEncryption, got)
	}
	if _, ok := plain.Properties["kmsKeyId"]; ok {
		t.Errorf("plaintext instance must not record a kmsKeyId")
	}

	nilFlag := rdsFindAsset(assets, "db-nil-flag")
	if nilFlag == nil {
		t.Fatal("expected nil-flag instance asset")
	}
	if got := nilFlag.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("nil StorageEncrypted instance: expected conservative posture %q, got %q", models.PostureNoEncryption, got)
	}
}
