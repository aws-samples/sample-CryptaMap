package main

import (
	"encoding/json"
	"fmt"
)

// LambdaEvent is the input shape for the Scanner Lambda.
//
// The Step Functions Distributed Map orchestrator (cdk/lib/org-fanout-stack.ts)
// invokes the Lambda once per (account,region) with a SCAN event that also
// carries the cross-account role to assume plus the fan-out run id:
//
//	{ "mode":"lambda", "accountId":"...", "region":"...", "runId":"run-...",
//	  "roleArn":"arn:<partition>:iam::<acct>:role/CryptaMapScannerRole",
//	  "externalId":"<scannerExternalId>" }
//
// When RoleArn is set, handle() (in lambda.go, build-tagged) assumes that role
// to scan the TARGET member account, while writing the resulting partial to the
// central RESULTS_BUCKET / SCANS_TABLE using the orchestrator's own base config.
// When RoleArn is empty the handler preserves single-account behavior.
//
// In ADDITION to the existing CycloneDX partial + Dynamo row, a scan invocation
// uploads the full RAW ScanResult JSON (assets AND findings, verbatim) to a
// runId-namespaced key under RESULTS_BUCKET so the org merge step can recombine
// the shards losslessly without re-deriving findings from CycloneDX:
//
//	scans/raw/<runId>/<accountId>-<region>-<scanId>.json
//
// The partition is baked into the event-supplied roleArn, so the handler passes
// it through to org.AssumeRole verbatim rather than reconstructing it.
//
// The terminal MERGE event reuses the SAME Lambda binary (no separate merge
// Lambda). The Step Functions MergeResults step invokes the scanner with:
//
//	{ "mode":"lambda", "merge":true, "runId":"run-..." }
//
// When Merge is true, handle() runs runMergeMode(): it lists scans/raw/<runId>/,
// downloads + unmarshals each raw ScanResult, then reuses the exact merge +
// roadmap + output pipeline used by `cryptamap org-merge-files` to emit the
// merged org CBOM + roadmap (JSON/MD) + coverage + a dashboard-compatible
// summary under scans/latest/<runId>.* (runId already carries the "run-"
// prefix) — all via the central base config.
//
// This struct and the pure helpers below intentionally live in an UNTAGGED file
// (no //go:build lambda) so they compile and are unit-testable under the default
// `go build ./...` / `go test ./cmd/...` commands.
type LambdaEvent struct {
	Mode            string   `json:"mode"`
	Region          string   `json:"region"`
	Regions         []string `json:"regions"`
	AccountID       string   `json:"accountId"`
	RoleArn         string   `json:"roleArn,omitempty"`
	ExternalId      string   `json:"externalId,omitempty"`
	RoleSessionName string   `json:"roleSessionName,omitempty"`
	// RunID is the fan-out run identifier used to namespace raw artifacts under
	// scans/raw/<runId>/ and to scope the merge to a single org-scan execution.
	RunID string `json:"runId,omitempty"`
	// Merge selects the org merge path instead of a scan. When true, handle()
	// runs the FINAL merge: it streams the per-account merged objects produced by
	// the MergeAccount tier (scans/account-merged/<runId>/) one at a time through
	// the streaming merger, so peak memory is bounded by the deduped set rather
	// than the sum of all raw shards. (Back-compat: if no per-account objects
	// exist for the run — e.g. a pre-hierarchical run — it falls back to streaming
	// the raw shards directly.) Performs no scan.
	Merge bool `json:"merge,omitempty"`
	// MergeAccount selects the per-account merge tier (tier 1 of the hierarchical
	// merge). Set with AccountID: handle() lists scans/raw/<runId>/<accountId>-*,
	// streams that account's region shards through the merger, and writes ONE
	// per-account merged object to scans/account-merged/<runId>/<accountId>.json.
	// Each such invocation only ever holds one account's data, which fits a small
	// Lambda regardless of org size.
	MergeAccount bool `json:"mergeAccount,omitempty"`
	// ExpectedShards is the seed-emitted count of (account,region) shards the run
	// fanned out (post region-filtering). The final merge reconciles the OBSERVED
	// shard count against it to surface silently-vanished / tolerated-failed shards
	// (completion barrier, SCALING.md §4.4). 0/absent = unknown (legacy replay):
	// the merge then reports complete with no gap rather than a bogus shortfall.
	ExpectedShards int `json:"expectedShards,omitempty"`
}

// resolveScanRegion picks the region to scan, following the documented chain:
// explicit event region first, then the base/default config region, then a
// final fallback of us-east-1.
func resolveScanRegion(evt LambdaEvent, fallbackCfgRegion string) string {
	region := evt.Region
	if region == "" {
		region = fallbackCfgRegion
	}
	if region == "" {
		region = "us-east-1"
	}
	return region
}

// parseLambdaEvent unmarshals a raw JSON event into a LambdaEvent. It is a small
// pure helper that aids testing the fan-out event contract without invoking the
// Lambda runtime.
func parseLambdaEvent(jsonBytes []byte) (LambdaEvent, error) {
	var evt LambdaEvent
	if err := json.Unmarshal(jsonBytes, &evt); err != nil {
		return LambdaEvent{}, err
	}
	return evt, nil
}

// rawRunPrefix is the S3 key prefix (relative to the writer's own prefix) under
// which all raw ScanResult shards for a single fan-out run are stored. A scan
// invoked with an empty runId (e.g. a scheduled single-account scan) falls back
// to a fixed "_norun" namespace so its raw object never collides with an org
// run and the org merge (which lists a specific run prefix) never picks it up.
func rawRunPrefix(runID string) string {
	if runID == "" {
		runID = "_norun"
	}
	return fmt.Sprintf("scans/raw/%s/", runID)
}

// rawScanKey is the namespaced key for one raw ScanResult shard. It is kept as a
// small pure helper (like resolveScanRegion) so the raw-key contract is unit-
// testable without the lambda runtime. The (account,region,scanId) triple keeps
// each shard unique within a run.
func rawScanKey(runID, accountID, region, scanID string) string {
	return fmt.Sprintf("%s%s-%s-%s.json", rawRunPrefix(runID), accountID, region, scanID)
}

// accountRawPrefix is the S3 listing prefix for one account's raw shards within a
// run (scans/raw/<runId>/<accountId>-). Because rawScanKey formats shards as
// "<accountId>-<region>-<scanId>.json", listing this prefix returns exactly that
// account's region shards — the input to the per-account merge tier.
func accountRawPrefix(runID, accountID string) string {
	return fmt.Sprintf("%s%s-", rawRunPrefix(runID), accountID)
}

// accountMergedPrefix is the S3 key prefix under which the per-account merge tier
// writes its outputs (scans/account-merged/<runId>/). The final merge lists this
// prefix and streams each per-account merged object through the merger.
func accountMergedPrefix(runID string) string {
	if runID == "" {
		runID = "_norun"
	}
	return fmt.Sprintf("scans/account-merged/%s/", runID)
}

// accountMergedKey is the key for one account's merged object within a run.
func accountMergedKey(runID, accountID string) string {
	return fmt.Sprintf("%s%s.json", accountMergedPrefix(runID), accountID)
}
