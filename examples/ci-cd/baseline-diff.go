// Command baseline-diff is a REFERENCE CI gate for the "continuous QBOM"
// pattern (see README.md in this directory). It compares the CRITICAL finding
// set produced by a fresh CryptaMap scan against a committed baseline and exits
// NON-ZERO if the new run introduces a CRITICAL finding that is not already in
// the baseline — i.e. it fails the build only on a NEW critical, not on
// pre-existing accepted ones.
//
// It reads CryptaMap ASFF JSON (`*.asff.json`), which is the canonical
// severity-bearing artifact: each element carries `Severity.Label` ("CRITICAL")
// and the resource ARN under `Resources[].Id`. The CycloneDX CBOM itself carries
// crypto-asset components but no severity, so the ASFF (derived from the SAME
// scan) is what a Security-Hub-shaped gate diffs.
//
// IDENTITY KEY — CryptaMap's ASFF `Id` field embeds a per-run UUID, so it is NOT
// stable across scans. Diffing on it would flag every finding as "new" on every
// run. We instead key each finding on the STABLE tuple
// (AwsAccountId | Resources[0].Id | Title); the ARN is a deterministic identity
// and the Title is deterministically derived from service + posture + resource
// name, so the same unresolved critical re-appears under the same key.
//
// This file is a CUSTOMER-ADAPTABLE EXAMPLE; it is intentionally stdlib-only and
// is NOT wired into this repository's own build. Run it with:
//
//	go run ./examples/ci-cd/baseline-diff.go \
//	  -baseline baseline.asff.json -current run.asff.json
//
// Exit codes: 0 = no new criticals (gate passes); 1 = at least one NEW critical
// (gate fails the build); 2 = usage / I/O / parse error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// asffFinding is a minimal projection of the CryptaMap ASFF record — only the
// fields this gate needs. Unknown fields are ignored by encoding/json.
type asffFinding struct {
	AwsAccountID string `json:"AwsAccountId"`
	Title        string `json:"Title"`
	Severity     struct {
		Label string `json:"Label"`
	} `json:"Severity"`
	Resources []struct {
		ID string `json:"Id"`
	} `json:"Resources"`
}

func main() {
	baselinePath := flag.String("baseline", "", "path to the committed baseline ASFF JSON (the accepted critical set)")
	currentPath := flag.String("current", "", "path to the fresh run's ASFF JSON to gate")
	severity := flag.String("severity", "CRITICAL", "ASFF severity Label to gate on")
	flag.Parse()

	if *baselinePath == "" || *currentPath == "" {
		fmt.Fprintln(os.Stderr, "usage: baseline-diff -baseline <baseline.asff.json> -current <run.asff.json> [-severity CRITICAL]")
		os.Exit(2)
	}

	gate := strings.ToUpper(*severity)

	baseline, err := loadKeys(*baselinePath, gate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline-diff: read baseline: %v\n", err)
		os.Exit(2)
	}
	current, err := loadKeys(*currentPath, gate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "baseline-diff: read current: %v\n", err)
		os.Exit(2)
	}

	// New criticals = current critical keys not present in the baseline.
	var introduced []string
	for key := range current {
		if _, ok := baseline[key]; !ok {
			introduced = append(introduced, key)
		}
	}
	sort.Strings(introduced)

	fmt.Printf("baseline-diff: gating on %s — baseline=%d current=%d\n", gate, len(baseline), len(current))

	if len(introduced) == 0 {
		fmt.Printf("baseline-diff: no NEW %s findings — gate PASSED.\n", gate)
		return
	}

	fmt.Printf("baseline-diff: %d NEW %s finding(s) not in baseline — gate FAILED:\n", len(introduced), gate)
	for _, key := range introduced {
		fmt.Printf("  + %s | %s\n", gate, current[key])
	}
	fmt.Fprintf(os.Stderr,
		"baseline-diff: build failed on a new critical. If this finding is accepted, re-seed the baseline (see examples/ci-cd/README.md).\n")
	os.Exit(1)
}

// loadKeys parses an ASFF JSON array from path and returns the set of stable
// identity keys for findings whose severity Label matches gate. The map value
// is a human-readable label used in the failure report.
func loadKeys(path, gate string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []asffFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("parse ASFF %q: %w", path, err)
	}
	keys := make(map[string]string)
	for _, f := range findings {
		if !strings.EqualFold(f.Severity.Label, gate) {
			continue
		}
		keys[stableKey(f)] = describe(f)
	}
	return keys, nil
}

// stableKey derives a run-independent identity for a finding. The volatile ASFF
// `Id` (per-run UUID) and the CreatedAt/UpdatedAt timestamps are deliberately
// excluded; the resource ARN plus the deterministic Title uniquely identify a
// distinct unresolved critical on a distinct resource.
func stableKey(f asffFinding) string {
	resource := ""
	if len(f.Resources) > 0 {
		resource = f.Resources[0].ID
	}
	return strings.Join([]string{f.AwsAccountID, resource, f.Title}, "|")
}

func describe(f asffFinding) string {
	resource := "(no-resource)"
	if len(f.Resources) > 0 && f.Resources[0].ID != "" {
		resource = f.Resources[0].ID
	}
	return fmt.Sprintf("%s — %s", resource, f.Title)
}
