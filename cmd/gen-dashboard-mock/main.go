// Command gen-dashboard-mock regenerates the dashboard's static demo data
// (dashboard/public/mock/org-cbom.json + roadmap.json) ENTIRELY SYNTHETICALLY —
// no AWS calls, no real account, no credentials. It is the sibling of cmd/gen-policy
// / cmd/gen-ts / cmd/gen-knowledge. Generating the demo data entirely synthetically
// (rather than from a real deployed org scan) keeps real account IDs and bucket
// names out of the committed mock artifacts by construction.
//
//	go run ./cmd/gen-dashboard-mock           # rewrite the committed mock artifacts
//	go run ./cmd/gen-dashboard-mock -check    # fail if the committed mock is stale (CI guard)
//
// WHAT IT PRODUCES: a synthetic Indian-BFSI organization — 11 generic-role accounts
// across 2 regions (ap-south-1 Mumbai, ap-south-2 Hyderabad) — run through the SAME
// mock generator (internal/mock), findings builder (scanner.BuildFindings) and org
// merge (merge.Merge) that a real scan uses, then written with the SAME output
// writers (output.WriteCBOM / WriteRoadmapJSON) the live dashboard API serves. So
// the demo data is shape-identical to a real org scan, exercises the real merge/
// classification code, and shows a realistic spread of postures (the generator's
// per-template PostureFor distribution yields quantum-resistant / classical / no-encryption
// / legacy-tls / pqc-hybrid mixes, plus AWS-managed vs customer-CMK key tiers).
//
// HONESTY / SAFETY:
//   - Account IDs are SYNTHETIC, from the AWS-documentation example range
//     (1111xxxxxxxx) — never a real account. Determinism: each (account,region)
//     uses a fixed seed so re-running yields byte-identical output (CI -check works).
//   - Compliance mappings are produced ONLY by the real compliance.Registry mapper
//     from the synthetic postures — NO hand-authored control IDs (the mapper is the
//     single source of truth, so nothing can be fabricated here).
//   - Coverage: asserts the generator emitted at least one asset for EVERY registered
//     scanner; it FAILS LOUDLY (non-zero exit) rather than ship partial demo data.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/merge"
	"github.com/aws-samples/cryptamap/internal/mock"
	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// account is one synthetic org member. ID is a 12-digit example-range id (never real).
type account struct {
	id   string
	name string
}

// The synthetic Indian-BFSI org: 11 generic-role accounts. IDs are in the
// AWS-docs example range (1111-prefixed) so they are unmistakably non-real.
var orgAccounts = []account{
	{"111100000001", "core-banking-prod"},
	{"111100000002", "payments-prod"},
	{"111100000003", "mobile-banking-prod"},
	{"111100000004", "treasury-prod"},
	{"111100000005", "data-lake-analytics"},
	{"111100000006", "security-audit"},
	{"111100000007", "dr-site"},
	{"111100000008", "shared-services"},
	{"111100000009", "dev"},
	{"111100000010", "staging"},
	{"111100000011", "sandbox"},
}

// Two regions: Mumbai + Hyderabad (the first Indian-BFSI target).
var orgRegions = []string{"ap-south-1", "ap-south-2"}

// scalePerService — resources per service per (account,region). 1 keeps the
// committed JSON lean (~2k components across 11 accts x 2 regions x ~99 services)
// while STILL showing full diversity: posture is chosen per-template by PostureFor's
// distribution, so even one asset/service/account yields a realistic mix of
// quantum-resistant / classical / no-encryption / legacy-tls / pqc-hybrid across the org.
const scalePerService = 1

// The orchestrator/management account that owns the org run (the merged CBOM's
// metadata account). Synthetic.
const orchestratorAccountID = "111100000000"

// Indian-BFSI-first framework set (mirrors configs/default.yaml). Compliance
// mappings are derived from these by the REAL mapper, never hand-authored.
var frameworks = []string{
	"SEBI_CSCRF", "RBI_BANK_IN", "IRDAI_ICSG",
	"CISA_M2302", "MITRE_PQCC", "CNSA_2_0", "EU_NIS2_DORA",
	"CANADA_PQC", "EUROPOL_QSFF",
}

func main() {
	check := flag.Bool("check", false, "fail (non-zero) if the committed mock artifacts are stale instead of rewriting them")
	repoRoot := flag.String("repo-root", ".", "repository root (defaults to CWD)")
	flag.Parse()

	cbomBytes, roadmapBytes, err := build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-dashboard-mock: %v\n", err)
		os.Exit(1)
	}

	mockDir := filepath.Join(*repoRoot, "dashboard", "public", "mock")
	cbomPath := filepath.Join(mockDir, "org-cbom.json")
	roadmapPath := filepath.Join(mockDir, "roadmap.json")

	if *check {
		stale := false
		for _, f := range []struct {
			path string
			want []byte
		}{{cbomPath, cbomBytes}, {roadmapPath, roadmapBytes}} {
			got, rerr := os.ReadFile(f.path)
			if rerr != nil || !bytes.Equal(got, f.want) {
				fmt.Fprintf(os.Stderr, "STALE: %s differs from generator output (run: go run ./cmd/gen-dashboard-mock)\n", f.path)
				stale = true
			}
		}
		if stale {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "gen-dashboard-mock -check: mock artifacts up to date.")
		return
	}

	if err := os.MkdirAll(mockDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "gen-dashboard-mock: mkdir %s: %v\n", mockDir, err)
		os.Exit(1)
	}
	for _, f := range []struct {
		path string
		data []byte
	}{{cbomPath, cbomBytes}, {roadmapPath, roadmapBytes}} {
		if err := os.WriteFile(f.path, f.data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "gen-dashboard-mock: write %s: %v\n", f.path, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "gen-dashboard-mock: wrote %s (%d bytes)\n", f.path, len(f.data))
	}
}

// build produces the synthetic merged org CBOM + roadmap as deterministic bytes.
func build() (cbom, roadmap []byte, err error) {
	ctx := context.Background()
	comp := compliance.NewRegistry(frameworks)

	// Fixed timestamps so output is byte-deterministic (CI -check). Mock data is
	// not time-sensitive; a fixed "as of" date is fine for demo data.
	fixedStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fixedEnd := fixedStart.Add(time.Minute)

	covered := map[string]bool{}
	var scans []models.ScanResult

	for ai, acct := range orgAccounts {
		for ri, region := range orgRegions {
			// Deterministic per-(account,region) seed -> reproducible output.
			seed := int64(1_000_000*(ai+1) + 1000*(ri+1))
			g := mock.Generator{
				AccountID: acct.id,
				Region:    region,
				Scale:     scalePerService,
				Seed:      seed,
			}
			assets := g.GenerateAssets()
			for _, a := range assets {
				covered[a.Service] = true
			}
			findings := scanner.BuildFindings(assets, comp, nil)
			scans = append(scans, models.ScanResult{
				ScanID:      fmt.Sprintf("mock-%s-%s", acct.id, region),
				AccountID:   acct.id,
				Region:      region,
				StartedAt:   fixedStart,
				CompletedAt: fixedEnd,
				Mode:        "mock",
				Assets:      assets,
				Findings:    findings,
				ToolVersion: "demo",
			})
		}
	}

	// COVERAGE GATE: every mock-template service must appear at least once (and
	// Templates() == the full registered scanner set, per the mock coverage_test),
	// else the demo data is incomplete -> fail loudly rather than ship a partial
	// dashboard.
	if missing := missingServices(covered); len(missing) > 0 {
		return nil, nil, fmt.Errorf("mock coverage incomplete: %d template services produced no asset: %v", len(missing), missing)
	}

	merged := merge.Merge(scans, orchestratorAccountID).Merged
	// Pin the merged timestamps too, for deterministic output.
	merged.StartedAt = fixedStart
	merged.CompletedAt = fixedEnd
	merged.ScanID = "mock-org-demo"

	var cbomBuf, rmBuf bytes.Buffer
	if err := output.WriteCBOM(&cbomBuf, merged); err != nil {
		return nil, nil, fmt.Errorf("write CBOM: %w", err)
	}
	if err := output.WriteRoadmapJSON(&rmBuf, merged); err != nil {
		return nil, nil, fmt.Errorf("write roadmap: %w", err)
	}

	// WriteCBOM stamps a fresh random serialNumber (urn:uuid:...) AND a wall-clock
	// metadata.timestamp per call — correct for a real, uniquely-identified scan, but
	// both break byte-determinism of the committed demo artifact. Pin them so
	// re-running the generator is reproducible (and `-check` works). Live scans are
	// unaffected (this only post-processes the demo output here).
	cb := pinNonDeterministic(cbomBuf.Bytes())
	_ = ctx
	return cb, rmBuf.Bytes(), nil
}

// fixedDemoSerial is the stable serialNumber for the committed demo CBOM.
const fixedDemoSerial = "urn:uuid:00000000-0000-4000-8000-000000000d3e" // "d3e" ~ demo

// fixedDemoTimestamp is the stable metadata.timestamp for the committed demo CBOM.
const fixedDemoTimestamp = "2026-01-01T00:00:00Z"

var (
	reSerial    = regexp.MustCompile(`"serialNumber":\s*"urn:uuid:[0-9a-fA-F-]+"`)
	reTimestamp = regexp.MustCompile(`"timestamp":\s*"[0-9T:.\-]+Z"`)
)

// pinNonDeterministic replaces the (random) serialNumber and the (wall-clock)
// metadata.timestamp in a CBOM with fixed demo values, so the committed artifact is
// byte-reproducible and `gen-dashboard-mock -check` is a meaningful CI guard.
func pinNonDeterministic(b []byte) []byte {
	b = reSerial.ReplaceAll(b, []byte(`"serialNumber": "`+fixedDemoSerial+`"`))
	b = reTimestamp.ReplaceAll(b, []byte(`"timestamp": "`+fixedDemoTimestamp+`"`))
	return b
}

// missingServices returns the mock-template services that produced no asset in the
// generated org. The authoritative expected set is mock.Templates() — NOT
// scanner.NewRegistry(), which is EMPTY here (scanners are registered by
// registerAllScanners() in package main/cmd, not importable from this tool). The
// mock package's own coverage_test (TestMockCoverageNoDrift) independently proves
// Templates() == the full registered scanner set, so checking against Templates()
// IS the 100%-scanner-coverage gate, and it actually fails when a template is missing.
func missingServices(covered map[string]bool) []string {
	var missing []string
	seen := map[string]bool{}
	for _, t := range mock.Templates() {
		if seen[t.Service] {
			continue
		}
		seen[t.Service] = true
		if !covered[t.Service] {
			missing = append(missing, t.Service)
		}
	}
	sort.Strings(missing)
	return missing
}
