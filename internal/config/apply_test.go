package config

import "testing"

// TestApply_UnsetFieldsDoNotClobberConfig pins the CLIOverrides contract that the
// main.go flag-gating relies on: a nil/empty override field must LEAVE the config
// value untouched, and only a supplied field overrides it. Before the fix,
// main.go always passed the flag defaults (Mock/MockScale/OutputDir), so Apply's
// non-nil/non-empty branches always fired and silently overwrote YAML — e.g. a
// config mock.scale.resources_per_service: 20 was clobbered to the --mock-scale
// default 5. main.go now only fills these fields when cobra reports the flag as
// Changed; this test locks the Apply half of that contract.
func TestApply_UnsetFieldsDoNotClobberConfig(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.Mock.Enabled = true
		c.Mock.Scale.ResourcesPerService = 20 // a YAML-set value the flag default (5) must not clobber
		c.Output.LocalDir = "/from/yaml"
		c.Scan.Profile = "yaml-profile"
		return c
	}

	// (1) An empty override (the "no flag set" case) leaves every field as loaded.
	c := base()
	c.Apply(CLIOverrides{})
	if !c.Mock.Enabled {
		t.Error("empty override flipped Mock.Enabled off")
	}
	if c.Mock.Scale.ResourcesPerService != 20 {
		t.Errorf("empty override clobbered mock scale: got %d, want 20 (the config value)", c.Mock.Scale.ResourcesPerService)
	}
	if c.Output.LocalDir != "/from/yaml" {
		t.Errorf("empty override clobbered LocalDir: got %q, want /from/yaml", c.Output.LocalDir)
	}
	if c.Scan.Profile != "yaml-profile" {
		t.Errorf("empty override clobbered Profile: got %q", c.Scan.Profile)
	}

	// (2) A supplied override DOES take effect (the "user set the flag" case).
	c = base()
	scale := 5
	mock := false
	c.Apply(CLIOverrides{Mock: &mock, MockScale: &scale, OutputDir: "/from/flag", Regions: []string{"eu-west-1"}})
	if c.Mock.Enabled {
		t.Error("explicit --mock=false override did not take effect")
	}
	if c.Mock.Scale.ResourcesPerService != 5 {
		t.Errorf("explicit --mock-scale=5 did not take effect: got %d", c.Mock.Scale.ResourcesPerService)
	}
	if c.Output.LocalDir != "/from/flag" {
		t.Errorf("explicit --output-dir did not take effect: got %q", c.Output.LocalDir)
	}
	if len(c.Scan.Regions) != 1 || c.Scan.Regions[0] != "eu-west-1" {
		t.Errorf("explicit --regions did not take effect: got %v", c.Scan.Regions)
	}
	// Profile was not supplied in this override, so it stays as loaded.
	if c.Scan.Profile != "yaml-profile" {
		t.Errorf("unsupplied Profile was clobbered: got %q", c.Scan.Profile)
	}
}
