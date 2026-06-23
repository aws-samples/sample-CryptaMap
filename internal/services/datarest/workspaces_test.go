package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeWorkSpacesClient is a hand-rolled workspacesAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err forces a DescribeWorkspaces
// failure.
type fakeWorkSpacesClient struct {
	pages []*workspaces.DescribeWorkspacesOutput
	calls int
	err   error
}

func (f *fakeWorkSpacesClient) DescribeWorkspaces(ctx context.Context, in *workspaces.DescribeWorkspacesInput, optFns ...func(*workspaces.Options)) (*workspaces.DescribeWorkspacesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &workspaces.DescribeWorkspacesOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func wsStrptr(s string) *string { return &s }
func wsBoolptr(b bool) *bool    { return &b }

// wsAssetByID indexes scan results by ResourceID for assertions.
func wsAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestWorkSpacesScanPaginates verifies the DescribeWorkspaces NextToken loop: a
// fake that returns 2 pages (NextToken on page 1) must yield BOTH pages'
// WorkSpaces as assets. Without the pagination loop, only the first page's
// WorkSpace survives — the commonest real-world drop bug.
func TestWorkSpacesScanPaginates(t *testing.T) {
	client := &fakeWorkSpacesClient{
		pages: []*workspaces.DescribeWorkspacesOutput{
			{
				Workspaces: []workspacestypes.Workspace{
					{WorkspaceId: wsStrptr("ws-page1")},
				},
				NextToken: wsStrptr("tok-page2"),
			},
			{
				Workspaces: []workspacestypes.Workspace{
					{WorkspaceId: wsStrptr("ws-page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := WorkSpacesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeWorkspaces to be called 2 times (paginated), got %d", client.calls)
	}
	got := wsAssetByID(assets)
	for _, want := range []string{"ws-page1", "ws-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected WorkSpace %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestWorkSpacesScanErrorPropagates verifies the owner's incompleteness decision:
// a DescribeWorkspaces failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the cause — NOT a silent empty
// success.
func TestWorkSpacesScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform workspaces:DescribeWorkspaces")
	client := &fakeWorkSpacesClient{err: sentinel}
	assets, err := WorkSpacesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when DescribeWorkspaces fails, got nil (silent empty success); assets=%v", assets)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeWorkspaces failure, got: %v", err)
	}
}

// TestWorkSpacesScanPosture asserts the honesty posture mapping for WorkSpaces
// (an opt-in-SSE domain): encryption off on BOTH volumes -> NoEncryption (genuine
// off); EITHER volume encrypted -> SymmetricOnly (never NoEncryption when a volume
// is encrypted); a present CMK -> recorded as kmsKeyId.
func TestWorkSpacesScanPosture(t *testing.T) {
	client := &fakeWorkSpacesClient{
		pages: []*workspaces.DescribeWorkspacesOutput{
			{
				Workspaces: []workspacestypes.Workspace{
					// Neither volume encrypted -> genuinely off.
					{
						WorkspaceId:                 wsStrptr("ws-plain"),
						RootVolumeEncryptionEnabled: wsBoolptr(false),
						UserVolumeEncryptionEnabled: wsBoolptr(false),
					},
					// Only the USER volume encrypted -> must NOT be reported as
					// NoEncryption (keying solely off root would falsely flag it).
					{
						WorkspaceId:                 wsStrptr("ws-user-enc"),
						RootVolumeEncryptionEnabled: wsBoolptr(false),
						UserVolumeEncryptionEnabled: wsBoolptr(true),
						VolumeEncryptionKey:         wsStrptr("arn:aws:kms:us-east-1:111122223333:key/abc"),
					},
					// Root volume encrypted, no explicit CMK in the response ->
					// SymmetricOnly, kmsKeyId absent (AWS-managed default, not a
					// recorded customer CMK).
					{
						WorkspaceId:                 wsStrptr("ws-root-enc"),
						RootVolumeEncryptionEnabled: wsBoolptr(true),
						UserVolumeEncryptionEnabled: wsBoolptr(false),
					},
				},
			},
		},
	}
	assets, err := WorkSpacesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := wsAssetByID(assets)

	plain, ok := got["ws-plain"]
	if !ok {
		t.Fatalf("expected ws-plain asset, assets=%v", got)
	}
	if plain.Properties["posture"] != string(models.PostureNoEncryption) {
		t.Errorf("ws-plain (both volumes off): expected posture %q, got %q", models.PostureNoEncryption, plain.Properties["posture"])
	}

	userEnc, ok := got["ws-user-enc"]
	if !ok {
		t.Fatalf("expected ws-user-enc asset, assets=%v", got)
	}
	if userEnc.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("ws-user-enc (user volume encrypted): expected posture %q (never NoEncryption), got %q", models.PostureSymmetricOnly, userEnc.Properties["posture"])
	}
	if userEnc.Properties["kmsKeyId"] != "arn:aws:kms:us-east-1:111122223333:key/abc" {
		t.Errorf("ws-user-enc: expected the present CMK to be recorded as kmsKeyId, got %q", userEnc.Properties["kmsKeyId"])
	}
	if userEnc.Properties["userVolumeEncrypted"] != "true" || userEnc.Properties["rootVolumeEncrypted"] != "false" {
		t.Errorf("ws-user-enc: expected userVolumeEncrypted=true rootVolumeEncrypted=false, got user=%q root=%q",
			userEnc.Properties["userVolumeEncrypted"], userEnc.Properties["rootVolumeEncrypted"])
	}

	rootEnc, ok := got["ws-root-enc"]
	if !ok {
		t.Fatalf("expected ws-root-enc asset, assets=%v", got)
	}
	if rootEnc.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("ws-root-enc (root volume encrypted): expected posture %q, got %q", models.PostureSymmetricOnly, rootEnc.Properties["posture"])
	}
	if _, present := rootEnc.Properties["kmsKeyId"]; present {
		t.Errorf("ws-root-enc: no CMK in response, kmsKeyId should be absent (AWS-managed default), got %q", rootEnc.Properties["kmsKeyId"])
	}
}
