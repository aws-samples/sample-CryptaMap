//go:build lambda

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws-samples/cryptamap/internal/compliance"
	cmconfig "github.com/aws-samples/cryptamap/internal/config"
	"github.com/aws-samples/cryptamap/internal/org"
	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/scanner"
)

// LambdaEvent (the input shape for the Scanner Lambda) and the pure region/event
// helpers live in the untagged lambda_event.go so they remain unit-testable and
// compile under the default `go build ./...` without the lambda build tag.

// LambdaResponse is the JSON returned by the Scanner Lambda.
//
// For a scan invocation the per-(account,region) counts and the CycloneDX
// S3Key are populated, plus RunID/RawKey when the scan was part of an org run
// (so they flow back through the Distributed Map for observability). For a
// merge invocation (evt.Merge) the org-wide totals are populated and the
// MergedCBOMKey/RoadmapKey point at the emitted artifacts.
type LambdaResponse struct {
	ScanID    string `json:"scanId"`
	AccountID string `json:"accountId"`
	Region    string `json:"region"`
	Findings  int    `json:"findings"`
	Critical  int    `json:"critical"`
	Assets    int    `json:"assets"`
	S3Key     string `json:"s3Key,omitempty"`
	RunID     string `json:"runId,omitempty"`
	RawKey    string `json:"rawKey,omitempty"`
	// Merge-mode fields (populated only when evt.Merge is true).
	Merged        bool   `json:"merged,omitempty"`
	Shards        int    `json:"shards,omitempty"`
	MergedCBOMKey string `json:"mergedCbomKey,omitempty"`
	RoadmapKey    string `json:"roadmapKey,omitempty"`
	// Incomplete is the LOUD top-level flag (DECISION: loud-incomplete) set when the
	// merged org output is incomplete for ANY reason — vanished shards, errored
	// shards, or missing per-account objects. It mirrors mergeSummary.Incomplete so
	// the Step Functions execution output makes a decimated run impossible to miss.
	Incomplete bool `json:"incomplete,omitempty"`
	// MissingShards is the count of expected (account,region) shards that never
	// landed (ExpectedShards-ObservedShards, clamped >=0). 0 when fully reconciled
	// or when the expected count is unknown (legacy replay).
	MissingShards int `json:"missingShards,omitempty"`
	// Per-account completion barrier (final merge tier): account IDs whose tier-1
	// per-account merged object failed to fetch/decode. A partially-failed tier-1
	// merge is RECORDED here (and flagged incomplete in the summary) rather than
	// aborting the whole org merge, so the org report is never a silently-decimated
	// "success". Empty when every per-account object folded (or on the raw-shard
	// fallback path).
	MissingAccounts []string `json:"missingAccounts,omitempty"`
	// FailedShards is the STRUCTURED list of dropped/failed (account,region) tuples
	// with the failure reason where known (mirrors mergeSummary.FailedShards), so a
	// downstream alarm/notification can name exactly which accounts/regions were
	// dropped and why — not just a count. Empty on a clean run.
	FailedShards []failedShard `json:"failedShards,omitempty"`
}

// runLambda is invoked from main() when CRYPTAMAP_MODE=lambda.
func runLambda() {
	lambda.Start(handle)
}

func handle(ctx context.Context, evt LambdaEvent) (LambdaResponse, error) {
	cfg := cmconfig.Default()

	// baseCfg holds the orchestrator's OWN credentials. It is used to write the
	// partial centrally (RESULTS_BUCKET / SCANS_TABLE) regardless of whether we
	// assume a member-account role to scan.
	// Adaptive retry mode adds a client-side rate limiter so a throttled shard
	// backs off its send rate. The engine no longer double-retries throttles, so
	// this is the single throttle-retry owner (prevents the ~3-6x attempt
	// amplification that worsened throttling at fleet scale).
	baseCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRetryMode(aws.RetryModeAdaptive),
		awsconfig.WithRetryMaxAttempts(8),
	)
	if err != nil {
		return LambdaResponse{}, fmt.Errorf("load AWS config: %w", err)
	}
	// baseCfg.Region MUST stay the central/home region (where RESULTS_BUCKET +
	// SCANS_TABLE live). Do NOT repoint it to the scan region: for an ap-south-1
	// branch, writing the central partial through an ap-south-1 S3 client fails
	// the cross-region write to the us-east-1 bucket (verified 2026-06-04: only
	// us-east-1 shards landed in a multi-region run). The SCAN region is applied
	// to scanCfg only, below.
	region := resolveScanRegion(evt, baseCfg.Region)

	// Merge branch: a terminal org-merge invocation reuses this same binary to
	// recombine all raw shards for the run (scans/raw/<runId>/) into one org
	// CBOM + roadmap, reusing the exact merge/roadmap/output pipeline that
	// `cryptamap org-merge-files` uses. It performs NO scan and assumes no role.
	if evt.MergeAccount {
		// Hierarchical merge tier 1: merge one account's region shards into a single
		// per-account merged object. No scan, no role assumed.
		return runMergeAccountMode(ctx, baseCfg, evt.RunID, evt.AccountID)
	}
	if evt.Merge {
		return runMergeMode(ctx, baseCfg, evt.RunID, evt.ExpectedShards)
	}

	// scanCfg is the config the engine scans with — it carries the TARGET region
	// (and, for org fan-out, the assumed member-account credentials). It is
	// distinct from baseCfg so the scan can hit ap-south-1 while writes stay in
	// the central bucket's region.
	scanCfg := baseCfg.Copy()
	scanCfg.Region = region
	if evt.RoleArn != "" {
		scanCfg = org.AssumeRole(ctx, baseCfg, evt.RoleArn, evt.ExternalId, evt.RoleSessionName)
		// AssumeRole only does base.Copy(), so the target region MUST be re-set.
		scanCfg.Region = region

		// EAGERLY verify the assumed credentials. stscreds resolves lazily, so a
		// denied/untrusted role would otherwise surface only as caught per-scanner
		// errors inside eng.Run — and the shard would still return SUCCEEDED with 0
		// assets, making a permission failure look like a legitimately empty account.
		// Failing here records the shard as FAILED in the Distributed Map (visible),
		// and confirms we actually landed in the intended account.
		assumedAcct, _, cerr := org.CallerIdentity(ctx, scanCfg)
		if cerr != nil {
			return LambdaResponse{}, fmt.Errorf("assume-role verification failed for %s (account %s): %w", evt.RoleArn, evt.AccountID, cerr)
		}
		if evt.AccountID != "" && assumedAcct != "" && assumedAcct != evt.AccountID {
			return LambdaResponse{}, fmt.Errorf("assumed-role account mismatch: landed in %s, expected %s (role %s)", assumedAcct, evt.AccountID, evt.RoleArn)
		}
	}

	complianceReg := compliance.NewRegistry(cfg.Compliance.Frameworks)
	reg := scanner.NewRegistry()
	registerAllScanners(reg)
	eng := scanner.NewEngine(reg, complianceReg, scanner.EngineOptions{
		MaxGoroutines: cfg.Scan.Concurrency.MaxGoroutines,
		ToolVersion:   toolVersion,
	})

	// Scan the member account/region. res.AccountID == evt.AccountID and
	// res.Region == scanCfg.Region, so the partial carries correct identity.
	res := eng.Run(ctx, scanCfg, evt.AccountID)

	resp := LambdaResponse{
		ScanID:    res.ScanID,
		AccountID: res.AccountID,
		Region:    res.Region,
		Findings:  res.Summary.TotalFindings,
		Critical:  res.Summary.Critical,
		Assets:    res.Summary.TotalAssets,
		RunID:     evt.RunID,
	}

	// Write partials with the BASE config (central creds), NOT scanCfg, so
	// artifacts land in the central account. The S3 Key and Dynamo PK already
	// encode ACCOUNT#/REGION#, so each (account,region) partial is unique.
	bucket := os.Getenv("RESULTS_BUCKET")
	if bucket != "" {
		w := output.NewS3Writer(baseCfg, bucket, "scans/")
		key, err := w.PutCBOM(ctx, res)
		if err == nil {
			resp.S3Key = key
		} else {
			fmt.Fprintf(os.Stderr, "PutCBOM: %v\n", err)
		}

		// ADDITIVE: upload the full RAW ScanResult JSON (assets AND findings,
		// verbatim) under a runId-namespaced key so the org merge step can
		// recombine shards losslessly without re-deriving findings from
		// CycloneDX. Uses the BASE config (central creds), never scanCfg. The
		// "scans/" prefix on the writer makes the effective key absolute, so we
		// strip it from the relative key before calling PutBytes.
		if rawBody, merr := json.MarshalIndent(res, "", "  "); merr == nil {
			relKey := strings.TrimPrefix(rawScanKey(evt.RunID, res.AccountID, res.Region, res.ScanID), "scans/")
			if rawKey, rerr := w.PutBytes(ctx, relKey, rawBody, "application/json"); rerr == nil {
				resp.RawKey = rawKey
			} else {
				fmt.Fprintf(os.Stderr, "PutBytes(raw): %v\n", rerr)
			}
		} else {
			fmt.Fprintf(os.Stderr, "marshal raw ScanResult: %v\n", merr)
		}
	}

	table := os.Getenv("SCANS_TABLE")
	if table != "" {
		dw := output.NewDynamoWriter(baseCfg, table)
		// Surface a metadata-write failure to stderr (matching the S3 PutCBOM/PutBytes
		// paths above) so a missing SCANS_TABLE record is observable. The raw S3
		// artifact is already written, so the merge step is unaffected; we keep
		// returning success rather than failing the shard on a metadata-only error.
		if derr := dw.PutScan(ctx, res, resp.S3Key); derr != nil {
			fmt.Fprintf(os.Stderr, "PutScan: %v\n", derr)
		}
	}

	return resp, nil
}
