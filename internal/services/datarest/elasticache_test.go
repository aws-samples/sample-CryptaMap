package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	ectypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// ecStr / ecBool are file-local pointer helpers (the package already declares
// strptr/sptr/bptr/boolptr in sibling test files, so we use distinct names to
// avoid redeclaration collisions).
func ecStr(s string) *string { return &s }
func ecBool(b bool) *bool    { return &b }

// fakeElastiCacheClient is a hand-rolled elasticacheAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the Marker is
// wired so the scanner loops through every page; err forces a failure on the
// first call.
type fakeElastiCacheClient struct {
	pages []*elasticache.DescribeReplicationGroupsOutput
	calls int
	err   error
}

func (f *fakeElastiCacheClient) DescribeReplicationGroups(ctx context.Context, in *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &elasticache.DescribeReplicationGroupsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

// TestElastiCacheScanPaginates verifies the DescribeReplicationGroups Marker
// loop: a fake that returns 2 pages (Marker on page 1) must yield BOTH pages'
// replication groups as assets. Without the pagination loop, only the first
// page's group survives — the commonest real bug.
func TestElastiCacheScanPaginates(t *testing.T) {
	client := &fakeElastiCacheClient{
		pages: []*elasticache.DescribeReplicationGroupsOutput{
			{
				ReplicationGroups: []ectypes.ReplicationGroup{
					{ReplicationGroupId: ecStr("rg-page1"), AtRestEncryptionEnabled: ecBool(true)},
				},
				Marker: ecStr("marker-page2"),
			},
			{
				ReplicationGroups: []ectypes.ReplicationGroup{
					{ReplicationGroupId: ecStr("rg-page2"), AtRestEncryptionEnabled: ecBool(true)},
				},
				// no Marker -> last page
			},
		},
	}
	assets, err := ElastiCacheScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected DescribeReplicationGroups to be called 2 times (paginated), got %d", c)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"rg-page1", "rg-page2"} {
		if !got[want] {
			t.Errorf("expected replication group %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestElastiCacheScanErrorPropagates verifies the owner's incompleteness
// decision: a DescribeReplicationGroups failure (denied/rate-limited) must make
// the scan VISIBLY incomplete by returning a non-nil error — NOT a silent empty
// success that would masquerade as "no unencrypted caches found".
func TestElastiCacheScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticache:DescribeReplicationGroups")
	client := &fakeElastiCacheClient{err: sentinel}
	assets, err := ElastiCacheScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when DescribeReplicationGroups fails, got nil (silent empty success); assets=%v", assets)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeReplicationGroups failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on a top-level List error, got %v", assets)
	}
}

// findAsset returns the asset with the given ResourceID, or nil.
func findElastiCacheAsset(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// TestElastiCacheScanPostureMapping pins the honesty posture mapping for
// at-rest encryption, which is OPT-IN for ElastiCache (off unless
// AtRestEncryptionEnabled is set). The three rows:
//   - encryption genuinely off  -> PostureNoEncryption (truthful, not masked)
//   - encryption on, no CMK     -> PostureSymmetricOnly, kmsKeyId UNSET
//     (AWS-managed default recorded WITHOUT synthesizing a key id)
//   - encryption on, CMK present -> PostureSymmetricOnly, kmsKeyId recorded
func TestElastiCacheScanPostureMapping(t *testing.T) {
	client := &fakeElastiCacheClient{
		pages: []*elasticache.DescribeReplicationGroupsOutput{
			{
				ReplicationGroups: []ectypes.ReplicationGroup{
					// Opt-in SSE genuinely OFF (nil treated as off).
					{ReplicationGroupId: ecStr("rg-plaintext")},
					// Explicitly false.
					{ReplicationGroupId: ecStr("rg-explicit-off"), AtRestEncryptionEnabled: ecBool(false)},
					// Encrypted with AWS-managed default (no CMK).
					{ReplicationGroupId: ecStr("rg-aws-managed"), AtRestEncryptionEnabled: ecBool(true)},
					// Encrypted with a customer CMK.
					{ReplicationGroupId: ecStr("rg-cmk"), AtRestEncryptionEnabled: ecBool(true), KmsKeyId: ecStr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
				},
			},
		},
	}
	assets, err := ElastiCacheScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets, got %d", len(assets))
	}

	// Opt-in SSE off -> NoEncryption only when genuinely off.
	for _, id := range []string{"rg-plaintext", "rg-explicit-off"} {
		a := findElastiCacheAsset(assets, id)
		if a == nil {
			t.Fatalf("missing asset %q", id)
		}
		if got := a.Properties["posture"]; got != string(models.PostureNoEncryption) {
			t.Errorf("%s: expected posture %q (opt-in SSE genuinely off), got %q", id, models.PostureNoEncryption, got)
		}
		if _, ok := a.Properties["kmsKeyId"]; ok {
			t.Errorf("%s: expected no kmsKeyId on an unencrypted group, got %q", id, a.Properties["kmsKeyId"])
		}
	}

	// Encrypted, AWS-managed default -> SymmetricOnly, NO synthesized kmsKeyId.
	awsManaged := findElastiCacheAsset(assets, "rg-aws-managed")
	if awsManaged == nil {
		t.Fatal("missing asset rg-aws-managed")
	}
	if got := awsManaged.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("rg-aws-managed: expected posture %q (AES at-rest, never NoEncryption when encrypted), got %q", models.PostureSymmetricOnly, got)
	}
	if v, ok := awsManaged.Properties["kmsKeyId"]; ok {
		t.Errorf("rg-aws-managed: expected kmsKeyId UNSET for AWS-managed default (no synthesized value), got %q", v)
	}

	// Encrypted, customer CMK -> SymmetricOnly, kmsKeyId recorded verbatim.
	cmk := findElastiCacheAsset(assets, "rg-cmk")
	if cmk == nil {
		t.Fatal("missing asset rg-cmk")
	}
	if got := cmk.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("rg-cmk: expected posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if got := cmk.Properties["kmsKeyId"]; got != "arn:aws:kms:us-east-1:111122223333:key/abc-123" {
		t.Errorf("rg-cmk: expected the customer CMK arn recorded in kmsKeyId, got %q", got)
	}
}
