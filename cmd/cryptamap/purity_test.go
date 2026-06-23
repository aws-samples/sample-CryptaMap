package main

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenDocOracleDeps are import-path substrings that MUST NEVER appear in
// the transitive dependency set of the cmd/cryptamap scan binary. These are the
// doc-oracle / knowledge-refresh MCP markers: the customer scan binary classifies
// crypto from baked-in baseline data only, and must NOT carry a live
// documentation/MCP client that could phone home or make scan answers depend on
// an external oracle.
//
// NOTE: net/http and os/exec are deliberately ALLOWED here — the AWS SDK and the
// credentials processcreds provider legitimately use them. This guard is narrower
// than internal/pqc's air-gap guard: it only blocks the doc-oracle, which is the
// pre-commitment fence against a future knowledge-refresh MCP client leaking into
// the customer scan binary.
var forbiddenDocOracleDeps = []struct {
	marker string
	why    string
}{
	{"aws-documentation-mcp", "cmd/cryptamap must not depend on the AWS documentation MCP doc-oracle — the scan binary classifies from baked-in knowledge, never a live oracle"},
	{"awslabs", "cmd/cryptamap must not depend on an awslabs MCP client — a future knowledge-refresh MCP client must not leak into the customer scan binary"},
	{"mcp-server", "cmd/cryptamap must not depend on any MCP server client — the scan binary must not phone home to a doc-oracle"},
}

// TestScanBinaryHasNoDocOracleDeps statically asserts that the cmd/cryptamap scan
// binary carries no doc-oracle / MCP knowledge-refresh dependency, by shelling
// out to `go list -deps` and scanning the full transitive import set. (os/exec
// inside this test is fine — the guard polices the PRODUCT dependency graph.)
//
// This is the pre-commitment guard blocking a future knowledge-refresh MCP
// client from leaking into the customer scan binary: it bites the moment such a
// dependency is added, BEFORE it can ship.
func TestPurityScanBinaryHasNoDocOracleDeps(t *testing.T) {
	const pkg = "github.com/aws-samples/cryptamap/cmd/cryptamap"

	out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s failed: %v\n%s", pkg, err, out)
	}

	deps := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, dep := range deps {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}
		for _, f := range forbiddenDocOracleDeps {
			if strings.Contains(dep, f.marker) {
				t.Errorf("cmd/cryptamap transitive dep %q matches forbidden doc-oracle marker %q: %s", dep, f.marker, f.why)
			}
		}
	}
}
