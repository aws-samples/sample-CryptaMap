package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	elasticachetypes "github.com/aws/aws-sdk-go-v2/service/elasticache/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeElasticacheTransitClient is a hand-rolled elasticacheTransitAPI for
// unit-testing the scanner's pagination + error propagation without a live AWS
// client. groupPages is returned page-by-page (each call consumes the next page)
// and the Marker is wired so the scanner loops through every page; describeErr
// forces a DescribeReplicationGroups failure on the configured call index.
type fakeElasticacheTransitClient struct {
	groupPages  []*elasticache.DescribeReplicationGroupsOutput
	describeErr error
	errOnCall   int
	calls       int
}

func (f *fakeElasticacheTransitClient) DescribeReplicationGroups(ctx context.Context, in *elasticache.DescribeReplicationGroupsInput, optFns ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	call := f.calls
	f.calls++
	if f.describeErr != nil && call == f.errOnCall {
		return nil, f.describeErr
	}
	if call >= len(f.groupPages) {
		return &elasticache.DescribeReplicationGroupsOutput{}, nil
	}
	return f.groupPages[call], nil
}

func elasticachetransitStrptr(s string) *string { return &s }
func elasticachetransitBoolptr(b bool) *bool    { return &b }

// elasticachetransitPostureOf extracts the posture property recorded on an asset.
func elasticachetransitPostureOf(a models.CryptoAsset) string {
	if a.Properties == nil {
		return ""
	}
	if v, ok := a.Properties["posture"]; ok {
		return v
	}
	return ""
}

// elasticachetransitAssetByID locates an asset by its ResourceID.
func elasticachetransitAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestElastiCacheTransitScanPaginates verifies the DescribeReplicationGroups
// Marker loop: a fake that returns 2 pages (Marker on page 1) must yield BOTH
// pages' replication groups as assets. Without the pagination loop, only the
// first page's group survives.
func TestElastiCacheTransitScanPaginates(t *testing.T) {
	client := &fakeElasticacheTransitClient{
		groupPages: []*elasticache.DescribeReplicationGroupsOutput{
			{
				ReplicationGroups: []elasticachetypes.ReplicationGroup{
					{
						ReplicationGroupId:       elasticachetransitStrptr("rg-page1"),
						TransitEncryptionEnabled: elasticachetransitBoolptr(true),
						TransitEncryptionMode:    elasticachetypes.TransitEncryptionModeRequired,
					},
				},
				Marker: elasticachetransitStrptr("mark-page2"),
			},
			{
				ReplicationGroups: []elasticachetypes.ReplicationGroup{
					{
						ReplicationGroupId:       elasticachetransitStrptr("rg-page2"),
						TransitEncryptionEnabled: elasticachetransitBoolptr(true),
						TransitEncryptionMode:    elasticachetypes.TransitEncryptionModeRequired,
					},
				},
				// no Marker -> last page
			},
		},
	}
	assets, err := ElastiCacheTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeReplicationGroups to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"rg-page1", "rg-page2"} {
		if _, ok := elasticachetransitAssetByID(assets, want); !ok {
			t.Errorf("expected replication group %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestElastiCacheTransitScanErrorPropagates verifies the owner's incompleteness
// decision: a DescribeReplicationGroups failure (denied/rate-limited) must make
// the scan VISIBLY incomplete by returning a non-nil error — NOT a silent empty
// success.
func TestElastiCacheTransitScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticache:DescribeReplicationGroups")
	client := &fakeElasticacheTransitClient{
		describeErr: sentinel,
		errOnCall:   0,
	}
	_, err := ElastiCacheTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeReplicationGroups fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeReplicationGroups failure, got: %v", err)
	}
}

// TestElastiCacheTransitScanErrorMidPaginationPropagates verifies the error path
// on a SECOND page is also not swallowed: page-1 groups are not silently returned
// as a clean success when page-2 retrieval fails.
func TestElastiCacheTransitScanErrorMidPaginationPropagates(t *testing.T) {
	sentinel := errors.New("ThrottlingException: rate exceeded")
	client := &fakeElasticacheTransitClient{
		groupPages: []*elasticache.DescribeReplicationGroupsOutput{
			{
				ReplicationGroups: []elasticachetypes.ReplicationGroup{
					{ReplicationGroupId: elasticachetransitStrptr("rg-page1"), TransitEncryptionEnabled: elasticachetransitBoolptr(true), TransitEncryptionMode: elasticachetypes.TransitEncryptionModeRequired},
				},
				Marker: elasticachetransitStrptr("mark-page2"),
			},
		},
		describeErr: sentinel,
		errOnCall:   1, // fail on the second page fetch
	}
	_, err := ElastiCacheTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when a later page fails, got nil (silent partial success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the mid-pagination failure, got: %v", err)
	}
}

// TestElastiCacheTransitPostureHonesty pins the domain honesty posture: the
// transit-encryption MODE must drive classification correctly.
//   - required  -> NonPQCClassical (TLS enforced, plaintext refused)
//   - preferred -> LegacyTLS       (mixed mode STILL accepts plaintext; NOT clean)
//   - enabled but no mode -> NonPQCClassical (TLS on, enforcement unknown)
//   - disabled  -> NoEncryption    (plaintext)
//
// The critical false-safe to guard against is treating a "preferred" (mixed)
// group as clean classical TLS — it provably still accepts plaintext.
func TestElastiCacheTransitPostureHonesty(t *testing.T) {
	client := &fakeElasticacheTransitClient{
		groupPages: []*elasticache.DescribeReplicationGroupsOutput{
			{
				ReplicationGroups: []elasticachetypes.ReplicationGroup{
					{
						ReplicationGroupId:       elasticachetransitStrptr("rg-required"),
						TransitEncryptionEnabled: elasticachetransitBoolptr(true),
						TransitEncryptionMode:    elasticachetypes.TransitEncryptionModeRequired,
						Engine:                   elasticachetransitStrptr("redis"),
					},
					{
						ReplicationGroupId:       elasticachetransitStrptr("rg-preferred"),
						TransitEncryptionEnabled: elasticachetransitBoolptr(true),
						TransitEncryptionMode:    elasticachetypes.TransitEncryptionModePreferred,
						Engine:                   elasticachetransitStrptr("redis"),
					},
					{
						ReplicationGroupId:       elasticachetransitStrptr("rg-enabled-nomode"),
						TransitEncryptionEnabled: elasticachetransitBoolptr(true),
						// no TransitEncryptionMode reported
					},
					{
						ReplicationGroupId:       elasticachetransitStrptr("rg-disabled"),
						TransitEncryptionEnabled: elasticachetransitBoolptr(false),
					},
				},
			},
		},
	}
	assets, err := ElastiCacheTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	cases := []struct {
		id      string
		posture models.CryptoPosture
	}{
		{"rg-required", models.PostureNonPQCClassical},
		{"rg-preferred", models.PostureLegacyTLS},
		{"rg-enabled-nomode", models.PostureNonPQCClassical},
		{"rg-disabled", models.PostureNoEncryption},
	}
	for _, c := range cases {
		a, ok := elasticachetransitAssetByID(assets, c.id)
		if !ok {
			t.Errorf("expected asset %q to be present", c.id)
			continue
		}
		if got := elasticachetransitPostureOf(a); got != string(c.posture) {
			t.Errorf("group %q: expected posture %q, got %q", c.id, c.posture, got)
		}
	}

	// Explicit guard: a "preferred" (mixed) group must NOT be classified as the
	// clean enforced-TLS posture, because it still accepts plaintext.
	if pref, ok := elasticachetransitAssetByID(assets, "rg-preferred"); ok {
		if elasticachetransitPostureOf(pref) == string(models.PostureNonPQCClassical) {
			t.Error("false-safe: a mixed-mode (preferred) ElastiCache group was reported as clean classical TLS, but it still accepts plaintext")
		}
	}
}
