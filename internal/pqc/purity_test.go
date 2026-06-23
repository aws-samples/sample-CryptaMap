package pqc

import (
	"os/exec"
	"strings"
	"testing"
)

// forbiddenPQCDeps are import-path substrings that MUST NEVER appear in the
// transitive dependency set of internal/pqc. The PQC knowledge subsystem is the
// air-gap-pure core of the customer scan path: it answers "is this crypto
// quantum-safe?" purely from baked-in baseline data, with NO network, NO
// subprocess execution, and NO AWS / doc-oracle (knowledge-refresh MCP) code.
// If any of these leaks in, the knowledge answers could become dependent on a
// live oracle or egress channel — exactly what the air-gap guarantee forbids.
var forbiddenPQCDeps = []struct {
	marker string
	why    string
}{
	{"net/http", "internal/pqc must not open network connections — the knowledge baseline is air-gap-pure and answers entirely from embedded data"},
	{"os/exec", "internal/pqc must not shell out to subprocesses — no external oracle may sit in the customer scan path"},
	{"aws-sdk-go-v2", "internal/pqc must not depend on the AWS SDK — classification is offline and must not be coupled to live AWS API calls"},
	{"smithy-go", "internal/pqc must not pull in the smithy-go AWS transport runtime — that would imply an AWS/network dependency in the air-gap core"},
	{"aws-documentation-mcp", "internal/pqc must not depend on the AWS documentation MCP doc-oracle — knowledge is baked-in, never fetched live"},
	{"awslabs", "internal/pqc must not depend on an awslabs MCP client — the knowledge-refresh oracle must stay out of the customer scan path"},
	{"mcp-server", "internal/pqc must not depend on any MCP server client — no doc-oracle may leak into the air-gap knowledge core"},
}

// TestKnowledgeSubsystemHasNoNetworkDeps statically asserts dependency purity of
// the internal/pqc knowledge subsystem by shelling out to `go list -deps` and
// scanning the full transitive import set. (Running os/exec INSIDE a test is
// fine — the guard polices the PRODUCT dependency graph, not the test harness.)
//
// This is a pre-commitment guard: it bites the moment anyone adds an import that
// drags net/http, os/exec, the AWS SDK / smithy, or a doc-oracle MCP client into
// the air-gap-pure knowledge core, BEFORE such a regression can ship.
func TestPurityKnowledgeSubsystemHasNoNetworkDeps(t *testing.T) {
	const pkg = "github.com/aws-samples/cryptamap/internal/pqc"

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
		for _, f := range forbiddenPQCDeps {
			if strings.Contains(dep, f.marker) {
				t.Errorf("internal/pqc transitive dep %q matches forbidden marker %q: %s", dep, f.marker, f.why)
			}
		}
	}
}
