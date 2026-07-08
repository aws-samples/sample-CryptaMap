package main

import "testing"

// TestFlagChangedGating locks the wiring the item-5 fix depends on: cobra's
// Flags().Changed(name) must report false for a flag left at its default and true
// for one passed on the command line. runScan uses exactly this predicate to
// decide whether a value flag (mock/mock-scale/output-dir/verbose) overrides the
// YAML config, so a stale predicate would silently reintroduce the clobber bug.
func TestFlagChangedGating(t *testing.T) {
	// No value flags set: every value flag must report NOT changed, so runScan
	// leaves the corresponding config values alone.
	cmd := newRootCmd()
	cmd.SetArgs([]string{"--config", "x.yaml"})
	if err := cmd.Flags().Parse([]string{"--config", "x.yaml"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, name := range []string{"mock", "mock-scale", "output-dir", "verbose"} {
		if cmd.Flags().Changed(name) {
			t.Errorf("flag %q reported Changed with no value flags on the command line; it would clobber config", name)
		}
	}

	// Explicitly set flags must report changed.
	cmd2 := newRootCmd()
	if err := cmd2.Flags().Parse([]string{"--mock-scale", "20", "--output-dir", "/tmp/o"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !cmd2.Flags().Changed("mock-scale") {
		t.Error("--mock-scale passed but Changed reported false")
	}
	if !cmd2.Flags().Changed("output-dir") {
		t.Error("--output-dir passed but Changed reported false")
	}
	if cmd2.Flags().Changed("mock") {
		t.Error("--mock NOT passed but Changed reported true")
	}
}
