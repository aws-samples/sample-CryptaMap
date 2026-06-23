package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	amtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeAppMeshClient is a hand-rolled appMeshAPI for unit-testing the scanner's
// pagination + error handling without a live AWS client. ListMeshes and
// ListVirtualNodes are returned page-by-page (each call consumes the next page)
// with NextToken wired so the scanner loops through every page; the *Err fields
// force the corresponding call to fail; describeByNode supplies the per-node
// DescribeVirtualNode response keyed by virtual node name.
type fakeAppMeshClient struct {
	meshPages []*appmesh.ListMeshesOutput
	meshCalls int
	meshErr   error

	vnPages []*appmesh.ListVirtualNodesOutput
	vnCalls int
	vnErr   error

	describeByNode map[string]*appmesh.DescribeVirtualNodeOutput
	describeErr    error
}

func (f *fakeAppMeshClient) ListMeshes(ctx context.Context, in *appmesh.ListMeshesInput, optFns ...func(*appmesh.Options)) (*appmesh.ListMeshesOutput, error) {
	if f.meshErr != nil {
		return nil, f.meshErr
	}
	if f.meshCalls >= len(f.meshPages) {
		return &appmesh.ListMeshesOutput{}, nil
	}
	out := f.meshPages[f.meshCalls]
	f.meshCalls++
	return out, nil
}

func (f *fakeAppMeshClient) ListVirtualNodes(ctx context.Context, in *appmesh.ListVirtualNodesInput, optFns ...func(*appmesh.Options)) (*appmesh.ListVirtualNodesOutput, error) {
	if f.vnErr != nil {
		return nil, f.vnErr
	}
	if f.vnCalls >= len(f.vnPages) {
		return &appmesh.ListVirtualNodesOutput{}, nil
	}
	out := f.vnPages[f.vnCalls]
	f.vnCalls++
	return out, nil
}

func (f *fakeAppMeshClient) DescribeVirtualNode(ctx context.Context, in *appmesh.DescribeVirtualNodeInput, optFns ...func(*appmesh.Options)) (*appmesh.DescribeVirtualNodeOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if in.VirtualNodeName != nil {
		if out, ok := f.describeByNode[*in.VirtualNodeName]; ok {
			return out, nil
		}
	}
	return &appmesh.DescribeVirtualNodeOutput{}, nil
}

func appmeshStrptr(s string) *string { return &s }

// appmeshNode builds a DescribeVirtualNode response for a node with a single
// listener whose TLS block is `tls` (nil => no listener TLS at all).
func appmeshNode(tls *amtypes.ListenerTls) *appmesh.DescribeVirtualNodeOutput {
	return &appmesh.DescribeVirtualNodeOutput{
		VirtualNode: &amtypes.VirtualNodeData{
			Spec: &amtypes.VirtualNodeSpec{
				Listeners: []amtypes.Listener{{Tls: tls}},
			},
		},
	}
}

// appmeshPostureOf returns the posture stamped on the asset with the given
// resource ID, or "" if absent.
func appmeshPostureOf(assets []models.CryptoAsset, id string) string {
	for _, a := range assets {
		if a.ResourceID == id {
			return a.Properties["posture"]
		}
	}
	return ""
}

// TestAppMeshScanPaginatesMeshesAndNodes verifies both NextToken loops: a fake
// returning 2 mesh pages, each with virtual nodes across 2 node pages, must yield
// every node as an asset. Without pagination only the first page survives,
// silently dropping nodes in dense accounts.
func TestAppMeshScanPaginatesMeshesAndNodes(t *testing.T) {
	client := &fakeAppMeshClient{
		meshPages: []*appmesh.ListMeshesOutput{
			{
				Meshes:    []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-1")}},
				NextToken: appmeshStrptr("mesh-tok-2"),
			},
			{
				Meshes: []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-2")}},
			},
		},
		// ListVirtualNodes pages are consumed across BOTH meshes' inner loops; the
		// first mesh consumes pages 0 (NextToken) + 1 (last), the second mesh
		// consumes page 2 (last).
		vnPages: []*appmesh.ListVirtualNodesOutput{
			{
				VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: appmeshStrptr("vn-a")}},
				NextToken:    appmeshStrptr("vn-tok-2"),
			},
			{
				VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: appmeshStrptr("vn-b")}},
			},
			{
				VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: appmeshStrptr("vn-c")}},
			},
		},
		describeByNode: map[string]*appmesh.DescribeVirtualNodeOutput{
			"vn-a": appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeStrict}),
			"vn-b": appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeStrict}),
			"vn-c": appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeStrict}),
		},
	}
	assets, err := AppMeshScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.meshCalls != 2 {
		t.Errorf("expected ListMeshes to be called 2 times (paginated), got %d", client.meshCalls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"vn-a", "vn-b", "vn-c"} {
		if !got[want] {
			t.Errorf("expected virtual node %q from a paginated page to appear as an asset; got=%v", want, got)
		}
	}
}

// TestAppMeshScanListMeshesErrorPropagates verifies a top-level ListMeshes
// failure (denied/throttled) makes the scan VISIBLY incomplete by returning a
// non-nil error wrapping the cause — NOT a silent empty success.
func TestAppMeshScanListMeshesErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform appmesh:ListMeshes")
	client := &fakeAppMeshClient{meshErr: sentinel}
	_, err := AppMeshScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListMeshes fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListMeshes failure, got: %v", err)
	}
}

// TestAppMeshScanListVirtualNodesErrorSkipsMesh verifies a per-mesh
// ListVirtualNodes failure is logged and that mesh skipped, while OTHER meshes
// still scan. The top-level scan must NOT error (only ListMeshes is fatal), and
// the failing mesh contributes no assets but does not corrupt the rest.
func TestAppMeshScanListVirtualNodesErrorSkipsMesh(t *testing.T) {
	sentinel := errors.New("ThrottlingException")
	client := &fakeAppMeshClient{
		meshPages: []*appmesh.ListMeshesOutput{
			{Meshes: []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-1")}}},
		},
		vnErr: sentinel,
	}
	assets, err := AppMeshScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("ListVirtualNodes error should be per-mesh (logged+skipped), not fatal; got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected the skipped mesh to contribute no assets, got %d", len(assets))
	}
}

// TestAppMeshHonestyPostureLadder asserts the App Mesh honesty posture for each
// listener TLS mode. This is the core anti-false-clear contract: opt-in TLS that
// is off/disabled/absent must NOT read as clean, PERMISSIVE (plaintext still
// accepted) must read as weakened, and only STRICT with a classical cert is
// NonPQCClassical (never PQC-safe). Reported per node as the WEAKEST listener.
func TestAppMeshHonestyPostureLadder(t *testing.T) {
	client := &fakeAppMeshClient{
		meshPages: []*appmesh.ListMeshesOutput{
			{Meshes: []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-1")}}},
		},
		vnPages: []*appmesh.ListVirtualNodesOutput{
			{VirtualNodes: []amtypes.VirtualNodeRef{
				{VirtualNodeName: appmeshStrptr("vn-strict")},
				{VirtualNodeName: appmeshStrptr("vn-permissive")},
				{VirtualNodeName: appmeshStrptr("vn-disabled")},
				{VirtualNodeName: appmeshStrptr("vn-notls")},
				{VirtualNodeName: appmeshStrptr("vn-nolistener")},
			}},
		},
		describeByNode: map[string]*appmesh.DescribeVirtualNodeOutput{
			"vn-strict":     appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeStrict}),
			"vn-permissive": appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModePermissive}),
			"vn-disabled":   appmeshNode(&amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeDisabled}),
			"vn-notls":      appmeshNode(nil), // listener present, no TLS block
			"vn-nolistener": {
				VirtualNode: &amtypes.VirtualNodeData{
					Spec: &amtypes.VirtualNodeSpec{Listeners: []amtypes.Listener{}},
				},
			},
		},
	}
	assets, err := AppMeshScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	cases := []struct {
		id   string
		want models.CryptoPosture
	}{
		{"vn-strict", models.PostureNonPQCClassical},
		{"vn-permissive", models.PostureLegacyTLS},
		{"vn-disabled", models.PostureNoEncryption},
		{"vn-notls", models.PostureNoEncryption},
		{"vn-nolistener", models.PostureNoEncryption},
	}
	for _, c := range cases {
		if got := appmeshPostureOf(assets, c.id); got != string(c.want) {
			t.Errorf("node %s: expected posture %q, got %q (App Mesh opt-in TLS must not read as clean)", c.id, c.want, got)
		}
	}
}

// TestAppMeshWeakestListenerWins verifies that a node with multiple listeners is
// reported at its WEAKEST listener posture: a STRICT + a DISABLED listener on the
// same node must surface as NoEncryption, not the STRICT (over-clean) reading.
func TestAppMeshWeakestListenerWins(t *testing.T) {
	client := &fakeAppMeshClient{
		meshPages: []*appmesh.ListMeshesOutput{
			{Meshes: []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-1")}}},
		},
		vnPages: []*appmesh.ListVirtualNodesOutput{
			{VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: appmeshStrptr("vn-mixed")}}},
		},
		describeByNode: map[string]*appmesh.DescribeVirtualNodeOutput{
			"vn-mixed": {
				VirtualNode: &amtypes.VirtualNodeData{
					Spec: &amtypes.VirtualNodeSpec{
						Listeners: []amtypes.Listener{
							{Tls: &amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeStrict}},
							{Tls: &amtypes.ListenerTls{Mode: amtypes.ListenerTlsModeDisabled}},
						},
					},
				},
			},
		},
	}
	assets, err := AppMeshScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if got := appmeshPostureOf(assets, "vn-mixed"); got != string(models.PostureNoEncryption) {
		t.Errorf("mixed-listener node must report the WEAKEST posture (no-encryption), got %q", got)
	}
}

// TestAppMeshDescribeErrorDropsNodeNotMesh verifies a per-node DescribeVirtualNode
// failure drops only that node (returns ok=false) without erroring the whole scan
// or fabricating an asset.
func TestAppMeshDescribeErrorDropsNode(t *testing.T) {
	client := &fakeAppMeshClient{
		meshPages: []*appmesh.ListMeshesOutput{
			{Meshes: []amtypes.MeshRef{{MeshName: appmeshStrptr("mesh-1")}}},
		},
		vnPages: []*appmesh.ListVirtualNodesOutput{
			{VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: appmeshStrptr("vn-x")}}},
		},
		describeErr: errors.New("AccessDeniedException: appmesh:DescribeVirtualNode"),
	}
	assets, err := AppMeshScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("per-node Describe error should not fail the scan; got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no asset fabricated for a node whose Describe failed, got %d", len(assets))
	}
}
