package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/merge"
	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// orgMergeFilesFlags configure the offline org-merge-files subcommand.
type orgMergeFilesFlags struct {
	in         []string // dir(s) and/or comma-separated glob patterns of CBOM JSON files
	outputDir  string
	frameworks []string
	verbose    bool
}

// defaultMergeFrameworks mirrors config.Default().Compliance.Frameworks so the
// regenerated findings carry the same compliance mappings a live scan would.
var defaultMergeFrameworks = []string{
	"SEBI_CSCRF", "RBI_BANK_IN", "IRDAI_ICSG",
	"CISA_M2302", "MITRE_PQCC", "CNSA_2_0", "EU_NIS2_DORA",
	"CANADA_PQC", "EUROPOL_QSFF",
}

// newOrgMergeFilesCmd builds the `cryptamap org-merge-files` subcommand. It
// ingests N already-produced per-account CycloneDX CBOM JSON files (e.g. the
// per-account partials an org scan wrote to S3, downloaded locally) and reuses
// the existing pure pipeline verbatim — output.ParseCBOMFile to reconstruct
// assets, scanner.BuildFindings to regenerate findings deterministically,
// merge.Merge to dedup into one org envelope, then output.WriteCBOM +
// WriteRoadmapJSON/Markdown to emit a unified org CBOM + roadmap.
//
// It is strictly local file I/O: it makes NO AWS SDK calls, so the
// no-deploy / no-mutation guarantee is structural.
func newOrgMergeFilesCmd() *cobra.Command {
	f := orgMergeFilesFlags{}
	cmd := &cobra.Command{
		Use:   "org-merge-files",
		Short: "Merge N local per-account CBOM JSON files into one org CBOM + PQC roadmap",
		Long: `org-merge-files reads existing per-account CycloneDX 1.7 CBOM JSON files
(such as the per-account partials an org scan wrote to S3, downloaded locally),
reconstructs each into a ScanResult, regenerates the PQC findings deterministically
(Mosca / posture / compliance), merges + dedups them into one org-wide envelope,
and writes a single merged CBOM + PQC roadmap (JSON + markdown) + coverage matrix.

This runs entirely locally and makes NO AWS calls.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOrgMergeFiles(f)
		},
	}
	cmd.Flags().StringSliceVar(&f.in, "in", nil, "input directory or comma-separated glob(s) of CBOM JSON files (required)")
	cmd.Flags().StringVarP(&f.outputDir, "output-dir", "o", "./dist/org-merge", "local output directory")
	cmd.Flags().StringSliceVar(&f.frameworks, "frameworks", nil, "compliance frameworks for regenerated findings (default: all built-in)")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "verbose logging")
	_ = cmd.MarkFlagRequired("in")
	return cmd
}

func runOrgMergeFiles(f orgMergeFilesFlags) error {
	files, err := resolveCBOMInputs(f.in)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no CBOM JSON files matched --in=%s", strings.Join(f.in, ","))
	}
	if f.verbose {
		fmt.Fprintf(os.Stderr, "[org-merge-files] %d input file(s)\n", len(files))
	}

	frameworks := f.frameworks
	if len(frameworks) == 0 {
		frameworks = defaultMergeFrameworks
	}
	complianceReg := compliance.NewRegistry(frameworks)

	// Parse each CBOM file into shards, then regenerate findings on each shard so
	// the roadmap is fully populated (the CBOM carries assets, not findings).
	var scans []models.ScanResult
	for _, path := range files {
		shards, err := output.ParseCBOMFile(path)
		if err != nil {
			return err
		}
		for i := range shards {
			shards[i].Findings = scanner.BuildFindings(shards[i].Assets, complianceReg, nil)
			shards[i].Summary = recomputeSummary(shards[i])
		}
		if f.verbose {
			for _, s := range shards {
				fmt.Fprintf(os.Stderr, "[org-merge-files]   %s → account=%s region=%s assets=%d findings=%d\n",
					filepath.Base(path), s.AccountID, s.Region, len(s.Assets), len(s.Findings))
			}
		}
		scans = append(scans, shards...)
	}

	output.SortScansByAccountRegion(scans)
	res := merge.Merge(scans, merge.SentinelAccount)

	if err := os.MkdirAll(f.outputDir, 0o755); err != nil {
		return err
	}
	prefix := fmt.Sprintf("cryptamap-org-%s", res.Merged.CompletedAt.Format("20060102T150405Z"))
	if res.Merged.CompletedAt.IsZero() {
		prefix = "cryptamap-org-merged"
	}

	// Merged org-wide CBOM.
	cbomPath := filepath.Join(f.outputDir, prefix+".cbom.json")
	if err := writeFile(cbomPath, func(w *os.File) error { return output.WriteCBOM(w, res.Merged) }); err != nil {
		return err
	}

	// Org-wide PQC roadmap (JSON + markdown), reusing the shared helper in main.go.
	if err := writeRoadmap(f.outputDir, prefix, res.Merged, f.verbose); err != nil {
		return err
	}

	// Coverage matrix.
	covPath := filepath.Join(f.outputDir, prefix+".coverage.json")
	if cb, err := json.MarshalIndent(res.Coverage, "", "  "); err == nil {
		_ = os.WriteFile(covPath, cb, 0o644)
	}

	fmt.Fprintf(os.Stderr, "[org-merge-files] %d file(s) → %d shards → %d deduped assets, %d findings (CRIT %d / HIGH %d / MED %d / INFO %d)\n",
		len(files), len(scans), res.Merged.Summary.TotalAssets, res.Merged.Summary.TotalFindings,
		res.Merged.Summary.Critical, res.Merged.Summary.High, res.Merged.Summary.Medium, res.Merged.Summary.Informational)
	fmt.Fprintf(os.Stderr, "[org-merge-files] wrote %s + %s.roadmap.json/.md + %s.coverage.json\n", cbomPath, prefix, prefix)
	return nil
}

// recomputeSummary recomputes a per-shard ScanSummary from its assets+findings,
// mirroring the engine/merge severity switch so the per-shard summary is
// consistent before merge recomputes the org-wide one.
func recomputeSummary(s models.ScanResult) models.ScanSummary {
	sum := models.ScanSummary{
		TotalAssets:   len(s.Assets),
		TotalFindings: len(s.Findings),
	}
	services := make(map[string]struct{})
	for _, a := range s.Assets {
		services[a.Service] = struct{}{}
	}
	sum.ServiceCount = len(services)
	for _, fn := range s.Findings {
		switch fn.Severity {
		case models.SeverityCritical:
			sum.Critical++
		case models.SeverityHigh:
			sum.High++
		case models.SeverityMedium:
			sum.Medium++
		case models.SeverityInformational:
			sum.Informational++
		}
	}
	// Mirror scanner.buildSummary (B3): reconcile the inventory-only count
	// (quantum-resistant-at-rest symmetric AES-256, PostureSymmetricOnly) from the
	// shard's assets so the assets removed from the finding stream do not vanish.
	for _, a := range s.Assets {
		if a.Properties != nil && a.Properties["posture"] == string(models.PostureSymmetricOnly) {
			sum.InventoryOnly++
		}
	}
	return sum
}

// resolveCBOMInputs expands the --in arguments (each may be a directory or a
// glob pattern) into a sorted, de-duplicated list of *.json file paths. A bare
// directory is expanded to its top-level *.json files. Non-JSON files are
// ignored so the org-merge / coverage / roadmap outputs of a prior run dropped
// into the same dir do not get re-ingested.
func resolveCBOMInputs(in []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		if !strings.HasSuffix(strings.ToLower(p), ".json") {
			return
		}
		// Skip our own merge outputs so re-runs over the same dir are idempotent.
		base := filepath.Base(p)
		if strings.HasPrefix(base, "cryptamap-org-") || strings.HasSuffix(base, ".roadmap.json") || strings.HasSuffix(base, ".coverage.json") {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, arg := range in {
		info, statErr := os.Stat(arg)
		if statErr == nil && info.IsDir() {
			matches, err := filepath.Glob(filepath.Join(arg, "*.json"))
			if err != nil {
				return nil, err
			}
			for _, m := range matches {
				add(m)
			}
			continue
		}
		// Treat as a glob (also matches a literal file path).
		matches, err := filepath.Glob(arg)
		if err != nil {
			return nil, fmt.Errorf("bad glob %q: %w", arg, err)
		}
		for _, m := range matches {
			add(m)
		}
	}
	sort.Strings(out)
	return out, nil
}

// writeFile is a tiny helper that creates path and runs fn against the open
// file, always closing it.
func writeFile(path string, fn func(w *os.File) error) error {
	fb, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := fn(fb); err != nil {
		fb.Close()
		return err
	}
	return fb.Close()
}
