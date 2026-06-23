package transit

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

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
