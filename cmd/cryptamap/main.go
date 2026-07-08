// Package main is the CryptaMap CLI + Lambda entrypoint.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	"github.com/aws-samples/cryptamap/internal/compliance"
	cmconfig "github.com/aws-samples/cryptamap/internal/config"
	"github.com/aws-samples/cryptamap/internal/merge"
	"github.com/aws-samples/cryptamap/internal/org"
	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/pkg/models"
)

const toolVersion = "1.0.0"

func main() {
	if mode := os.Getenv("CRYPTAMAP_MODE"); mode == "lambda" {
		runLambda()
		return
	}
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type cliFlags struct {
	configPath string
	regions    []string
	accounts   []string
	org        bool
	mock       bool
	mockScale  int
	outputDir  string
	verbose    bool
	profile    string
	orgMerge   bool
}

// registeredScannerCount returns the number of distinct scanners the registry
// wires, so the --help banner reports the real coverage instead of a literal
// that drifts as scanners are added. It mirrors the registry built in runScan.
func registeredScannerCount() int {
	reg := scanner.NewRegistry()
	registerAllScanners(reg)
	return reg.Len()
}

func newRootCmd() *cobra.Command {
	f := cliFlags{}
	cmd := &cobra.Command{
		Use:   "cryptamap",
		Short: "AWS Cryptographic Asset Discovery & CBOM Generation",
		// Derive the scanner count from the live registry rather than hardcoding a
		// literal that goes stale (the banner previously claimed "63 AWS services"
		// while the registry actually wires more). TestBannerScannerCount guards
		// that this number tracks the registry length.
		Long: fmt.Sprintf(`CryptaMap discovers cryptographic assets across %d AWS service scanners and emits
CycloneDX 1.7 CBOM, MITRE PQCC Excel, and Security Hub ASFF findings.

Indian BFSI regulators (SEBI / RBI / IRDAI) are first-class customers; the
default Mosca's-Theorem parameters are calibrated for X=7y/Y=2y/Z=3y.`, registeredScannerCount()),
		Version: toolVersion,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Pass cobra's per-flag "was it set on the command line?" predicate so
			// runScan only overrides YAML config for flags the user ACTUALLY set —
			// a flag left at its default must not clobber a config-file value (e.g.
			// --mock-scale's default 5 silently overwriting a YAML
			// mock.scale.resources_per_service: 20).
			return runScan(cmd.Context(), f, cmd.Flags().Changed)
		},
	}
	cmd.Flags().StringVarP(&f.configPath, "config", "c", "", "path to YAML config file")
	cmd.Flags().StringSliceVarP(&f.regions, "regions", "r", nil, "regions to scan (comma-separated); pass 'all' to scan every enabled region in the caller account")
	cmd.Flags().StringSliceVarP(&f.accounts, "accounts", "a", nil, "specific account IDs (org mode only)")
	cmd.Flags().BoolVar(&f.org, "org", false, "NOT honored by the CLI scan path (warns and scans only the caller account); org-wide scanning is the deployed Step Functions fan-out")
	cmd.Flags().BoolVar(&f.mock, "mock", false, "synthesize mock data instead of calling AWS APIs")
	cmd.Flags().IntVar(&f.mockScale, "mock-scale", 5, "resources per service in mock mode")
	cmd.Flags().StringVarP(&f.outputDir, "output-dir", "o", "./dist/scan-output", "local output directory")
	cmd.Flags().BoolVarP(&f.verbose, "verbose", "v", false, "verbose logging")
	cmd.Flags().StringVar(&f.profile, "profile", "", "AWS named profile to use")
	cmd.Flags().BoolVar(&f.orgMerge, "org-merge", false, "merge all scanned regions/accounts into one org-wide CBOM + PQC roadmap")

	// Offline: merge N already-produced per-account CBOM JSON files (no AWS calls).
	cmd.AddCommand(newOrgMergeFilesCmd())
	// Offline: report PQC-knowledge freshness/provenance (no AWS/network calls).
	cmd.AddCommand(newKnowledgeStatusCmd())
	// Offline: serve the embedded dashboard over 127.0.0.1 against local scan output.
	cmd.AddCommand(newServeCmd())
	return cmd
}

// runScan loads config, applies the CLI overrides the user explicitly set, and
// runs the scan. changed(flagName) reports whether a flag was set on the command
// line (cobra's Flags().Changed), so a flag left at its default never overrides a
// value from the YAML config file. changed may be nil (e.g. in a test that builds
// cliFlags directly); a nil predicate is treated as "no flag was explicitly set",
// so only the slice/string fields that are non-empty in f still apply.
func runScan(ctx context.Context, f cliFlags, changed func(string) bool) error {
	cfg, err := cmconfig.Load(f.configPath)
	if err != nil {
		return err
	}
	if changed == nil {
		changed = func(string) bool { return false }
	}
	ov := cmconfig.CLIOverrides{
		// Regions/Accounts are slices with no meaningful default, so a non-empty
		// value already means "user supplied it" — Apply gates on len()>0.
		Regions:  f.regions,
		Accounts: f.accounts,
		Profile:  f.profile,
	}
	// Value flags with non-zero defaults (mock, mock-scale, output-dir, verbose)
	// only override config when the user actually passed them.
	if changed("mock") {
		ov.Mock = ptrBool(f.mock)
	}
	if changed("mock-scale") {
		ov.MockScale = ptrInt(f.mockScale)
	}
	if changed("output-dir") {
		ov.OutputDir = f.outputDir
	}
	if changed("verbose") {
		ov.Verbose = ptrBool(f.verbose)
	}
	cfg.Apply(ov)

	if err := os.MkdirAll(cfg.Output.LocalDir, 0o700); err != nil {
		return err
	}

	complianceReg := compliance.NewRegistry(cfg.Compliance.Frameworks)
	engineOpts := scanner.EngineOptions{
		MaxGoroutines: cfg.Scan.Concurrency.MaxGoroutines,
		BaseDelayMs:   cfg.Scan.RateLimiting.BaseDelayMs,
		MaxDelayMs:    cfg.Scan.RateLimiting.MaxDelayMs,
		MaxRetries:    cfg.Scan.RateLimiting.MaxRetries,
		Verbose:       f.verbose,
		ToolVersion:   toolVersion,
		// Wire the operator's YAML risk.mosca.overrides into the engine so
		// per-service Mosca (X+Y-Z) parameters actually take effect in
		// BuildFindings (previously cfg.Risk was loaded but never consumed).
		MoscaOverrides: cfg.MoscaOverrideParams(),
	}

	if cfg.Mock.Enabled {
		fmt.Fprintf(os.Stderr, "[cryptamap] mock mode — generating %d resources/service\n", cfg.Mock.Scale.ResourcesPerService)
		regions := cfg.Scan.Regions
		switch {
		case isAllRegionsToken(regions):
			// Mock mode has no creds, so we can't call EC2 DescribeRegions. Expand
			// `--regions all` to the commercial-default region set as a representative
			// stand-in so the opt-in flag still exercises a realistic multi-region run.
			regions = org.CommercialDefaults()
			fmt.Fprintf(os.Stderr, "[cryptamap] --regions all (mock) -> %d representative regions: %s\n",
				len(regions), strings.Join(regions, ", "))
		case len(regions) == 0:
			regions = []string{"us-east-1"}
		}
		eng := scanner.NewEngine(scanner.NewRegistry(), complianceReg, engineOpts)
		var results []models.ScanResult
		mockAcct := mockAccountID()
		for _, region := range regions {
			res := scanner.RunMock(ctx, mockAcct, region, cfg.Mock.Scale.ResourcesPerService, complianceReg, eng)
			results = append(results, res)
			if err := writeArtifacts(res, cfg, f.verbose); err != nil {
				return err
			}
		}
		if f.orgMerge {
			if err := writeOrgMerge(results, mockAcct, cfg, f.verbose); err != nil {
				return err
			}
		}
		printSummary(results)
		return nil
	}

	awsCfg, err := loadAWSConfig(ctx, cfg.Scan.Profile)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	regions := cfg.Scan.Regions
	switch {
	case isAllRegionsToken(regions):
		// OPT-IN: `--regions all` means "scan EVERY enabled region in the caller
		// account". Resolve the live list via EC2 DescribeRegions. EnabledRegions
		// falls back to CommercialDefaults *and* returns a non-nil error on failure,
		// so we surface that to the operator instead of silently scanning a subset
		// while still claiming "all".
		enabled, rerr := org.EnabledRegions(ctx, awsCfg)
		regions = enabled
		if rerr != nil {
			fmt.Fprintf(os.Stderr,
				"[cryptamap] WARNING: --regions all could not enumerate enabled regions (%v); falling back to %d commercial-default regions — this may NOT cover every region in the account: %s\n",
				rerr, len(regions), strings.Join(regions, ", "))
		} else {
			fmt.Fprintf(os.Stderr, "[cryptamap] --regions all -> %d enabled regions: %s\n",
				len(regions), strings.Join(regions, ", "))
		}
	case len(regions) == 0:
		regions = []string{awsCfg.Region}
		if regions[0] == "" {
			regions = []string{"us-east-1"}
		}
	}

	accountID, _, err := org.CallerIdentity(ctx, awsCfg)
	if err != nil {
		return fmt.Errorf("identify caller: %w", err)
	}
	if f.verbose {
		fmt.Fprintf(os.Stderr, "[cryptamap] caller=%s regions=%s\n", accountID, strings.Join(regions, ","))
	}

	// The CLI scan path is SINGLE-ACCOUNT (the caller account) only. Org-wide
	// cross-account fan-out is performed by the Lambda + Step Functions Distributed
	// Map deployment, not this binary. Warn LOUDLY if the operator passed --org or
	// --accounts here so they are never misled into thinking a one-account scan
	// covered the whole organization.
	if f.org || len(f.accounts) > 0 {
		fmt.Fprintf(os.Stderr,
			"[cryptamap] WARNING: --org/--accounts are NOT honored by the CLI scan path; this run scans ONLY the caller account %s across %d region(s). For org-wide cross-account scanning, deploy the Step Functions fan-out stack. Use `cryptamap org-merge-files` to merge externally-produced per-account CBOMs.\n",
			accountID, len(regions))
	}

	reg := scanner.NewRegistry()
	registerAllScanners(reg)
	if f.verbose {
		fmt.Fprintf(os.Stderr, "[cryptamap] %d scanners registered\n", reg.Len())
	}

	eng := scanner.NewEngine(reg, complianceReg, engineOpts)

	var results []models.ScanResult
	for _, region := range regions {
		regionCfg := awsCfg.Copy()
		regionCfg.Region = region
		fmt.Fprintf(os.Stderr, "[cryptamap] scanning region %s …\n", region)
		res := eng.Run(ctx, regionCfg, accountID)
		if err := writeArtifacts(res, cfg, f.verbose); err != nil {
			return err
		}
		// Retain the full per-shard Assets/Findings in memory ONLY when an org-merge
		// will consume them afterward. Without --org-merge, the artifacts are already
		// written to disk and only res.Summary is needed for printSummary, so drop the
		// heavy slices to keep peak memory ~flat across a many-region scan instead of
		// growing with every region.
		if !f.orgMerge {
			res.Assets = nil
			res.Findings = nil
		}
		results = append(results, res)
	}
	if f.orgMerge {
		if err := writeOrgMerge(results, accountID, cfg, f.verbose); err != nil {
			return err
		}
	}
	printSummary(results)
	return nil
}

func writeArtifacts(scan models.ScanResult, cfg *cmconfig.Config, verbose bool) error {
	dir := cfg.Output.LocalDir
	prefix := fmt.Sprintf("cryptamap-scan-%s-%s-%s", scan.AccountID, scan.Region, scan.CompletedAt.Format("20060102T150405Z"))

	// CycloneDX CBOM
	if cfg.Output.Formats.CycloneDX {
		path := filepath.Join(dir, prefix+".cbom.json")
		fb, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := output.WriteCBOM(fb, scan); err != nil {
			fb.Close()
			return err
		}
		if err := fb.Close(); err != nil {
			return err
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[cryptamap]   wrote %s\n", path)
		}
	}

	// PQCC Excel
	if cfg.Output.Formats.PQCCExcel {
		path := filepath.Join(dir, prefix+".pqcc.xlsx")
		fb, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		opts := output.PQCCOptions{
			OwnerName:    cfg.Owner.Name,
			OwnerEmail:   cfg.Owner.Email,
			OwnerPhone:   cfg.Owner.Phone,
			OwnerOrgUnit: cfg.Owner.OrgUnit,
			VendorPOC:    cfg.Owner.VendorPOC,
		}
		if err := output.WritePQCCExcel(fb, scan, opts); err != nil {
			fb.Close()
			return err
		}
		if err := fb.Close(); err != nil {
			return err
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[cryptamap]   wrote %s\n", path)
		}
	}

	// Self-contained offline HTML evidence report (single file, opens file://).
	if cfg.Output.Formats.HTML {
		path := filepath.Join(dir, prefix+".report.html")
		fb, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := output.WriteHTMLReport(fb, scan); err != nil {
			fb.Close()
			return err
		}
		if err := fb.Close(); err != nil {
			return err
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[cryptamap]   wrote %s\n", path)
		}
	}

	// ASFF JSON
	if cfg.Output.Formats.ASFF {
		path := filepath.Join(dir, prefix+".asff.json")
		fb, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		productArn := cfg.Output.SecurityHub.ProductARN
		if err := output.WriteASFF(fb, scan, productArn); err != nil {
			fb.Close()
			return err
		}
		if err := fb.Close(); err != nil {
			return err
		}
	}

	// Raw scan result (debug/local). Propagate write failures — this file is the
	// verbatim evidence record, so a silent miss would look like a complete run.
	rawPath := filepath.Join(dir, prefix+".scan.json")
	rb, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal raw scan result: %w", err)
	}
	if err := os.WriteFile(rawPath, rb, 0o600); err != nil {
		return err
	}

	// PDF/markdown summary. Propagate create/write/close errors so a truncated
	// report.md never passes as complete with a zero exit code.
	if cfg.Output.Formats.PDF {
		path := filepath.Join(dir, prefix+".report.md")
		fb, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := output.WritePDFSummary(fb, scan); err != nil {
			fb.Close()
			return err
		}
		if err := fb.Close(); err != nil {
			return err
		}
	}

	// PQC migration roadmap (roadmap.json + roadmap.md)
	if cfg.Output.Formats.Roadmap {
		if err := writeRoadmap(dir, prefix, scan, verbose); err != nil {
			return err
		}
	}

	return nil
}

// writeRoadmap emits the PQC migration roadmap as JSON + concise markdown for a
// single ScanResult (a per-region scan or the merged org-wide result).
func writeRoadmap(dir, prefix string, scan models.ScanResult, verbose bool) error {
	jsonPath := filepath.Join(dir, prefix+".roadmap.json")
	jf, err := os.OpenFile(jsonPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	mdPath := filepath.Join(dir, prefix+".roadmap.md")
	mf, err := os.OpenFile(mdPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		jf.Close()
		return err
	}
	// Build the roadmap once and render both artifacts from it.
	if err := output.WriteRoadmapJSONAndMarkdown(jf, mf, scan); err != nil {
		jf.Close()
		mf.Close()
		return err
	}
	if err := jf.Close(); err != nil {
		mf.Close()
		return err
	}
	if err := mf.Close(); err != nil {
		return err
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[cryptamap]   wrote %s + %s\n", jsonPath, mdPath)
	}
	return nil
}

// writeOrgMerge merges all per-region/account ScanResults into one org-wide
// envelope and emits a single merged CBOM + PQC roadmap, plus the coverage
// matrix so no account is silently treated as clean.
func writeOrgMerge(results []models.ScanResult, orchestratorAccountID string, cfg *cmconfig.Config, verbose bool) error {
	if len(results) == 0 {
		return nil
	}
	res := merge.Merge(results, orchestratorAccountID)
	dir := cfg.Output.LocalDir
	prefix := fmt.Sprintf("cryptamap-org-%s", res.Merged.CompletedAt.Format("20060102T150405Z"))

	// Merged org-wide CBOM. os.OpenFile failures MUST propagate (mirroring
	// writeArtifacts): the merged CBOM is the primary org-wide deliverable, so
	// skipping it silently and still printing the success line below would be a
	// fabricated "org-merge succeeded" verdict.
	if cfg.Output.Formats.CycloneDX {
		path := filepath.Join(dir, prefix+".cbom.json")
		fb, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := output.WriteCBOM(fb, res.Merged); err != nil {
			fb.Close()
			return err
		}
		if err := fb.Close(); err != nil {
			return err
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[cryptamap]   wrote %s\n", path)
		}
	}

	// Org-wide PQC roadmap.
	if cfg.Output.Formats.Roadmap {
		if err := writeRoadmap(dir, prefix, res.Merged, verbose); err != nil {
			return err
		}
	}

	// Coverage matrix (which account/region was scanned, and whether it errored).
	// Its stated purpose is "so no account is silently treated as clean" — so its
	// own write failure must not be silent either.
	covPath := filepath.Join(dir, prefix+".coverage.json")
	cb, err := json.MarshalIndent(res.Coverage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal coverage matrix: %w", err)
	}
	if err := os.WriteFile(covPath, cb, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "[cryptamap] org-merge: %d regions → %d deduped assets, %d findings (coverage: %d shards)\n",
		len(results), res.Merged.Summary.TotalAssets, res.Merged.Summary.TotalFindings, len(res.Coverage))
	return nil
}

func printSummary(results []models.ScanResult) {
	fmt.Println()
	fmt.Println("CryptaMap scan complete.")
	fmt.Println("==========================")
	for _, r := range results {
		fmt.Printf("Account %s · Region %s · Mode %s\n", r.AccountID, r.Region, r.Mode)
		fmt.Printf("  Assets:   %d\n", r.Summary.TotalAssets)
		fmt.Printf("  Findings: %d (CRIT %d / HIGH %d / MED %d / INFO %d)\n",
			r.Summary.TotalFindings, r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Informational)
		fmt.Printf("  Services: %d\n", r.Summary.ServiceCount)
		fmt.Printf("  Duration: %s\n", r.CompletedAt.Sub(r.StartedAt))
	}
}

func loadAWSConfig(ctx context.Context, profile string) (aws.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{
		// Adaptive retry mode adds a client-side token-bucket rate limiter on top
		// of exponential backoff, so a fleet scan that throttles backs OFF its send
		// rate instead of hammering the API. This is the SINGLE owner of throttle
		// retries — the engine's runWithRetries no longer double-retries throttles
		// (which previously multiplied attempts ~3-6x and worsened throttling storms
		// at 100s of accounts).
		awsconfig.WithRetryMode(aws.RetryModeAdaptive),
		awsconfig.WithRetryMaxAttempts(8),
		awsconfig.WithDefaultRegion("us-east-1"),
	}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	return awsconfig.LoadDefaultConfig(ctx, opts...)
}

func mockAccountID() string {
	return fmt.Sprintf("%012d", time.Now().Unix()%1_000_000_000_000)
}

// isAllRegionsToken reports whether the operator passed the literal `--regions all`
// sentinel (the single token "all", case-insensitive) requesting every enabled
// region rather than naming a region called "all".
func isAllRegionsToken(regions []string) bool {
	return len(regions) == 1 && strings.EqualFold(strings.TrimSpace(regions[0]), "all")
}

func ptrBool(v bool) *bool { return &v }
func ptrInt(v int) *int    { return &v }
