package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/globalaccelerator"
	gatypes "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeGAClient is a scripted globalAcceleratorAPI: ListAccelerators is served
// from acceleratorPages (NextToken-chained), and ListListeners from a per-ARN
// map. Either call can be forced to error to exercise the propagation / skip
// paths. It records call counts so the pagination + per-accelerator loop can be
// asserted.
type fakeGAClient struct {
	acceleratorPages []*globalaccelerator.ListAcceleratorsOutput
	listenersByArn   map[string]*globalaccelerator.ListListenersOutput
	listAccErr       error
	listListenersErr error

	listAccCalls   int
	listListCalls  int
}

func (f *fakeGAClient) ListAccelerators(ctx context.Context, in *globalaccelerator.ListAcceleratorsInput, _ ...func(*globalaccelerator.Options)) (*globalaccelerator.ListAcceleratorsOutput, error) {
	if f.listAccErr != nil {
		return nil, f.listAccErr
	}
	idx := 0
	if in.NextToken != nil {
		idx = int((*in.NextToken)[0] - '0') // token is the next page index as a 1-char string
	}
	f.listAccCalls++
	if idx >= len(f.acceleratorPages) {
		return &globalaccelerator.ListAcceleratorsOutput{}, nil
	}
	return f.acceleratorPages[idx], nil
}

func (f *fakeGAClient) ListListeners(ctx context.Context, in *globalaccelerator.ListListenersInput, _ ...func(*globalaccelerator.Options)) (*globalaccelerator.ListListenersOutput, error) {
	f.listListCalls++
	if f.listListenersErr != nil {
		return nil, f.listListenersErr
	}
	if in.AcceleratorArn == nil {
		return &globalaccelerator.ListListenersOutput{}, nil
	}
	if out, ok := f.listenersByArn[*in.AcceleratorArn]; ok {
		return out, nil
	}
	return &globalaccelerator.ListListenersOutput{}, nil
}

func gaStr(s string) *string { return &s }

// TestGlobalAcceleratorRunOnceGate verifies the run-once gate: Global
// Accelerator is a global service and must be reported exactly once across a
// multi-region fan-out. Every shard except the run-once region (us-east-1)
// returns empty with no error and WITHOUT making an API call, so the global
// accelerators are not duplicated (each shard would otherwise produce a
// distinct region-stamped bom-ref that the merge dedup could not collapse).
func TestGlobalAcceleratorRunOnceGate(t *testing.T) {
	skipRegions := []string{"ap-south-1", "ap-south-2", "us-west-2", "eu-west-1", "us-east-2"}
	for _, r := range skipRegions {
		t.Run(r, func(t *testing.T) {
			// Empty config (no credentials/endpoint) is fine: the gate must
			// short-circuit before any AWS call for non-run-once regions.
			assets, err := GlobalAcceleratorScanner{}.Scan(context.Background(), aws.Config{Region: r})
			if err != nil {
				t.Fatalf("Scan(region=%s) returned error, want nil: %v", r, err)
			}
			if len(assets) != 0 {
				t.Fatalf("Scan(region=%s) returned %d assets, want 0 (skipped shard)", r, len(assets))
			}
		})
	}
}

// TestGlobalAcceleratorRunOnceRegionConstants documents the invariant that the
// run-once region is part of the deployed fan-out and the endpoint region is
// GA's resolvable home region, so gating + pinning are consistent.
func TestGlobalAcceleratorRunOnceRegionConstants(t *testing.T) {
	if gaRunOnceRegion != "us-east-1" {
		t.Errorf("gaRunOnceRegion = %q, want us-east-1 (must be present in the deployed fan-out)", gaRunOnceRegion)
	}
	if gaEndpointRegion != "us-west-2" {
		t.Errorf("gaEndpointRegion = %q, want us-west-2 (GA's only resolvable endpoint)", gaEndpointRegion)
	}
}

// TestGlobalAcceleratorScanClassifiesListeners exercises the scan() core (the
// coverage gap a code review flagged: only the run-once gate was tested). It
// drives a fake client with two accelerators across two ListAccelerators pages,
// each with a listener, and asserts: (a) one transit asset per listener, (b) GA
// is Layer-4 so EVERY listener — TCP or UDP — gets PostureUnknown (GA does not
// terminate TLS; the old code fabricated NonPQCClassical-TLS on all listeners,
// a false alarm on UDP), (c) the L4 protocol is recorded, (d) no concrete TLS
// version is asserted, and (e) the asset carries the "assess downstream" note.
func TestGlobalAcceleratorScanClassifiesListeners(t *testing.T) {
	client := &fakeGAClient{
		acceleratorPages: []*globalaccelerator.ListAcceleratorsOutput{
			{
				Accelerators: []gatypes.Accelerator{{AcceleratorArn: gaStr("arn:aws:globalaccelerator::111122223333:accelerator/aaa")}},
				NextToken:    gaStr("1"), // -> page index 1
			},
			{
				Accelerators: []gatypes.Accelerator{{AcceleratorArn: gaStr("arn:aws:globalaccelerator::111122223333:accelerator/bbb")}},
			},
		},
		listenersByArn: map[string]*globalaccelerator.ListListenersOutput{
			"arn:aws:globalaccelerator::111122223333:accelerator/aaa": {
				Listeners: []gatypes.Listener{{ListenerArn: gaStr("arn:aws:globalaccelerator::111122223333:accelerator/aaa/listener/l-tcp"), Protocol: gatypes.ProtocolTcp}},
			},
			"arn:aws:globalaccelerator::111122223333:accelerator/bbb": {
				Listeners: []gatypes.Listener{{ListenerArn: gaStr("arn:aws:globalaccelerator::111122223333:accelerator/bbb/listener/l-udp"), Protocol: gatypes.ProtocolUdp}},
			},
		},
	}

	assets, err := GlobalAcceleratorScanner{}.scan(context.Background(), client, "111122223333", gaEndpointRegion)
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets (one per listener across 2 paginated accelerators), got %d", len(assets))
	}
	if client.listAccCalls < 2 {
		t.Errorf("expected ListAccelerators to paginate (>=2 calls), got %d", client.listAccCalls)
	}

	byProto := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byProto[a.Properties["l4Protocol"]] = a
	}
	for _, proto := range []string{"TCP", "UDP"} {
		a, ok := byProto[proto]
		if !ok {
			t.Fatalf("no asset with l4Protocol=%s", proto)
		}
		// GA is L4: every listener, TCP or UDP, must be Unknown (never a fabricated
		// classical-TLS verdict — that was the pre-fix false alarm, esp. on UDP).
		if got := a.Properties["posture"]; got != string(models.PostureUnknown) {
			t.Errorf("proto=%s: posture=%q, want unknown (GA does not terminate TLS)", proto, got)
		}
		// No concrete TLS version may be asserted.
		if pp := a.CryptoProps.ProtocolProperties; pp != nil && pp.Version != "" {
			t.Errorf("proto=%s: asserted TLS Version=%q, want empty (GA does not terminate TLS)", proto, pp.Version)
		}
		if a.Properties["note"] == "" {
			t.Errorf("proto=%s: expected the 'assess downstream endpoint' note", proto)
		}
	}
}

// TestGlobalAcceleratorScanListAcceleratorsErrorPropagates pins the visible-
// incompleteness contract: a ListAccelerators failure is RETURNED (not swallowed
// into a clean-looking empty success), so a denied/throttled scan is recorded as
// errored rather than silently reporting zero accelerators.
func TestGlobalAcceleratorScanListAcceleratorsErrorPropagates(t *testing.T) {
	client := &fakeGAClient{listAccErr: errors.New("AccessDeniedException: globalaccelerator:ListAccelerators")}
	assets, err := GlobalAcceleratorScanner{}.scan(context.Background(), client, "111122223333", gaEndpointRegion)
	if err == nil {
		t.Fatal("expected ListAccelerators error to propagate, got nil (silent empty success)")
	}
	if assets != nil {
		t.Errorf("expected nil assets on error, got %d", len(assets))
	}
}

// TestGlobalAcceleratorScanListenerErrorSkipsAccelerator verifies the per-
// accelerator resilience path: a ListListeners failure for one accelerator is
// logged and skipped (non-fatal) so the scan continues and still emits the OTHER
// accelerator's listeners, rather than aborting the whole shard.
func TestGlobalAcceleratorScanListenerErrorSkipsAccelerator(t *testing.T) {
	client := &fakeGAClient{
		acceleratorPages: []*globalaccelerator.ListAcceleratorsOutput{{
			Accelerators: []gatypes.Accelerator{{AcceleratorArn: gaStr("arn:aws:globalaccelerator::111122223333:accelerator/aaa")}},
		}},
		listListenersErr: errors.New("throttled"),
	}
	assets, err := GlobalAcceleratorScanner{}.scan(context.Background(), client, "111122223333", gaEndpointRegion)
	if err != nil {
		t.Fatalf("a per-accelerator ListListeners error must be non-fatal, got scan error: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected 0 assets when the only accelerator's listeners could not be read, got %d", len(assets))
	}
}
