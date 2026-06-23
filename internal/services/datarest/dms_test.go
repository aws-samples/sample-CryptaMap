package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeDMSClient is a hand-rolled dmsAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. pages is returned
// page-by-page (each call consumes the next page) and the Marker is wired so the
// scanner loops through every page; err forces a DescribeReplicationInstances
// failure on the first call.
type fakeDMSClient struct {
	pages []*databasemigrationservice.DescribeReplicationInstancesOutput
	calls int
	err   error
}

func (f *fakeDMSClient) DescribeReplicationInstances(ctx context.Context, in *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &databasemigrationservice.DescribeReplicationInstancesOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func dmsStrptr(s string) *string { return &s }

// TestDMSScanPaginates verifies the Marker loop: a fake that returns 2 pages
// (Marker set on page 1) must yield BOTH pages' replication instances as assets.
// Without the pagination loop, only the first page's instance survives — the
// commonest real bug in dense accounts.
func TestDMSScanPaginates(t *testing.T) {
	client := &fakeDMSClient{
		pages: []*databasemigrationservice.DescribeReplicationInstancesOutput{
			{
				ReplicationInstances: []dmstypes.ReplicationInstance{
					{ReplicationInstanceIdentifier: dmsStrptr("ri-page1")},
				},
				Marker: dmsStrptr("marker-page2"),
			},
			{
				ReplicationInstances: []dmstypes.ReplicationInstance{
					{ReplicationInstanceIdentifier: dmsStrptr("ri-page2")},
				},
				// no Marker -> last page
			},
		},
	}
	assets, err := DMSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeReplicationInstances to be called 2 times (paginated), got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"ri-page1", "ri-page2"} {
		if !got[want] {
			t.Errorf("expected instance %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestDMSScanErrorPropagates verifies the owner's incompleteness decision: a
// DescribeReplicationInstances failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success that would read as a clean all-clear.
func TestDMSScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform dms:DescribeReplicationInstances")
	client := &fakeDMSClient{err: sentinel}
	assets, err := DMSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeReplicationInstances fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeReplicationInstances failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on error, got %v", assets)
	}
}

// TestDMSScanHonestyPosture is the regulator-honesty guardrail for the DMS
// at-rest classifier. DMS ALWAYS encrypts replication-instance storage at rest
// with AES-256 and there is NO toggle to disable it, so the posture must be
// UNCONDITIONALLY SymmetricOnly — never NoEncryption — regardless of whether a
// customer CMK is present. The only thing that varies is the KEY TIER recorded
// in kmsKeyId: the real CMK ARN when present, else the aws/dms AWS-owned default
// key sentinel (which must NOT masquerade as a customer-custodied key). This test
// fails loudly if anyone later collapses an absent CMK to NoEncryption (false
// alarm on an always-encrypted service) or drops the AWS-owned default marker.
func TestDMSScanHonestyPosture(t *testing.T) {
	const cmkARN = "arn:aws:kms:us-east-1:111122223333:key/abcd-1234-ef56"

	cases := []struct {
		name      string
		kmsKeyId  *string
		wantKeyID string
	}{
		{
			// Customer/CMK present -> recorded verbatim as the key tier.
			name:      "CMK present is recorded",
			kmsKeyId:  dmsStrptr(cmkARN),
			wantKeyID: cmkARN,
		},
		{
			// CMK absent -> AWS-owned default key sentinel, NOT a clean all-clear,
			// NOT NoEncryption.
			name:      "CMK absent falls back to AWS-owned default",
			kmsKeyId:  nil,
			wantKeyID: "AWS_OWNED_KMS_KEY",
		},
		{
			// Empty-string CMK is treated as absent (defensive against a stray "").
			name:      "empty CMK string falls back to AWS-owned default",
			kmsKeyId:  dmsStrptr(""),
			wantKeyID: "AWS_OWNED_KMS_KEY",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeDMSClient{
				pages: []*databasemigrationservice.DescribeReplicationInstancesOutput{
					{
						ReplicationInstances: []dmstypes.ReplicationInstance{
							{
								ReplicationInstanceIdentifier: dmsStrptr("ri-1"),
								KmsKeyId:                      tc.kmsKeyId,
							},
						},
					},
				},
			}
			assets, err := DMSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			if len(assets) != 1 {
				t.Fatalf("expected exactly 1 asset, got %d", len(assets))
			}
			a := assets[0]
			if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
				t.Errorf("posture = %q, want %q (DMS is always-encrypted; never NoEncryption)",
					a.Properties["posture"], models.PostureSymmetricOnly)
			}
			if a.Properties["kmsKeyId"] != tc.wantKeyID {
				t.Errorf("kmsKeyId = %q, want %q", a.Properties["kmsKeyId"], tc.wantKeyID)
			}
		})
	}
}

// TestDMSScanSkipsNilIdentifier guards the nil-guard: an instance with no
// identifier is skipped (cannot mint a stable resource ID) rather than panicking
// or emitting a blank-ID asset.
func TestDMSScanSkipsNilIdentifier(t *testing.T) {
	client := &fakeDMSClient{
		pages: []*databasemigrationservice.DescribeReplicationInstancesOutput{
			{
				ReplicationInstances: []dmstypes.ReplicationInstance{
					{ReplicationInstanceIdentifier: nil},
					{ReplicationInstanceIdentifier: dmsStrptr("ri-valid")},
				},
			},
		},
	}
	assets, err := DMSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 || assets[0].ResourceID != "ri-valid" {
		t.Fatalf("expected only the identified instance to yield an asset, got %+v", assets)
	}
}
