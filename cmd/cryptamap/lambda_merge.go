//go:build lambda

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aws-samples/cryptamap/internal/merge"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// streamMergeUnderPrefix lists every .json object under prefix and folds each one
// into the streaming merger ONE AT A TIME, discarding each ScanResult after Add.
// This is the memory-bounded core of the hierarchical merge: peak memory is the
// deduped working set, never the sum of all objects. keepShards is passed to the
// Merger (false on these paths — nothing downstream reads Multi.Scans). Returns
// the number of objects folded so callers can detect an empty prefix.
//
// Objects are listed (deterministic, lexicographic by key from S3) then fetched
// with a bounded-concurrent prefetch pool, but folded into the (non-thread-safe)
// Merger sequentially in key order — preserving the deterministic Add order the
// streaming-equals-batch guarantee depends on.
func streamMergeUnderPrefix(ctx context.Context, client *s3.Client, bucket, prefix string, m *merge.Merger) (int, error) {
	// Fold each raw ScanResult shard via Merger.Add (raw-shard fallback path).
	return streamObjectsUnderPrefix(ctx, client, bucket, prefix,
		func(raw []byte) error {
			var scan models.ScanResult
			if err := json.Unmarshal(raw, &scan); err != nil {
				return err
			}
			m.Add(scan)
			return nil
		})
}

// streamAccountMergedObjects folds each per-account merged object (tier 1 output)
// via Merger.AddPreMerged, carrying through its real (account,region) coverage
// rows so the final summary's succeeded/failed/perAccount stays correct.
//
// It is TOLERANT of a partially-failed tier-1 merge: a per-account object that
// fails to fetch or decode (missing/corrupt/truncated) is RECORDED — its account
// ID (parsed from the key) is appended to missingAccounts — and skipped, rather
// than aborting the whole org merge. runMergeMode surfaces missingAccounts into
// the completion barrier so the org report is flagged incomplete with the
// specific missing accounts, never a silently-decimated success. Returns
// (objects folded, listed object count, sorted missing account IDs, fatal error).
// A fatal error is reserved for the LIST itself failing (no objects can be
// attributed); per-object fetch/decode failures are non-fatal and recorded.
func streamAccountMergedObjects(ctx context.Context, client *s3.Client, bucket, prefix string, m *merge.Merger) (folded, listed int, missingAccounts []missingAccount, err error) {
	keys, err := listJSONKeys(ctx, client, bucket, prefix)
	if err != nil {
		return 0, 0, nil, err
	}
	if len(keys) == 0 {
		return 0, 0, nil, nil
	}

	// Reuse the bounded sliding-window prefetch (peak memory O(window), NOT
	// O(len(keys))) but attribute any per-object failure to its account key and
	// keep going, instead of cancelling the whole fold.
	streamKeyedBodies(ctx, client, bucket, keys, func(key string, body []byte, gerr error) {
		acct := accountIDFromMergedKey(key)
		if gerr != nil {
			fmt.Fprintf(os.Stderr, "[merge] WARN per-account object %s (account %s) fetch failed, recording as missing: %v\n", key, acct, gerr)
			missingAccounts = append(missingAccounts, missingAccount{
				accountID: acct,
				reason:    fmt.Sprintf("per-account merged object fetch failed: %v", gerr),
			})
			return
		}
		var obj accountMergedObject
		if uerr := json.Unmarshal(body, &obj); uerr != nil {
			fmt.Fprintf(os.Stderr, "[merge] WARN per-account object %s (account %s) decode failed, recording as missing: %v\n", key, acct, uerr)
			missingAccounts = append(missingAccounts, missingAccount{
				accountID: acct,
				reason:    fmt.Sprintf("per-account merged object decode failed (corrupt/truncated): %v", uerr),
			})
			return
		}
		m.AddPreMerged(obj.Merged, obj.Coverage)
		folded++
	})
	sort.Slice(missingAccounts, func(i, j int) bool {
		return missingAccounts[i].accountID < missingAccounts[j].accountID
	})
	return folded, len(keys), missingAccounts, nil
}

// accountIDFromMergedKey extracts the account ID from a per-account merged object
// key (scans/account-merged/<runId>/<accountId>.json) so a fetch/decode failure
// can be attributed to the specific account whose tier-1 merge produced it.
func accountIDFromMergedKey(key string) string {
	base := key
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, ".json")
}

// streamObjectsUnderPrefix lists every .json object under prefix and feeds each
// one's bytes to fold ONE AT A TIME in deterministic (lexicographic key) order,
// so peak memory is the deduped working set, never the sum of all objects. Bytes
// are fetched with a bounded-concurrent prefetch pool to hide download latency,
// but fold() is invoked sequentially on this goroutine (the Merger is not
// thread-safe) in key order — preserving the deterministic fold order the
// streaming-equals-batch guarantee depends on. Returns the number of objects
// folded so callers can detect an empty prefix.
func streamObjectsUnderPrefix(ctx context.Context, client *s3.Client, bucket, prefix string, fold func([]byte) error) (int, error) {
	keys, err := listJSONKeys(ctx, client, bucket, prefix)
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}
	// Strict raw-shard path: any fetch/fold error aborts (there is no per-object
	// account identity here to attribute a tolerated failure to). streamKeyedBodies
	// cancels the remaining window on the first error via the abort signal.
	var foldErr error
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	streamKeyedBodies(cctx, client, bucket, keys, func(_ string, body []byte, gerr error) {
		if foldErr != nil {
			return // already aborting; drain the window
		}
		if gerr != nil {
			foldErr = gerr
			cancel()
			return
		}
		if ferr := fold(body); ferr != nil {
			foldErr = ferr
			cancel()
		}
	})
	if foldErr != nil {
		return 0, foldErr
	}
	return len(keys), nil
}

// listJSONKeys lists every .json object under prefix and returns the keys in
// deterministic (lexicographic) order — the fold order the streaming-equals-batch
// guarantee depends on. The prefix "directory" placeholder key is skipped.
func listJSONKeys(ctx context.Context, client *s3.Client, bucket, prefix string) ([]string, error) {
	var keys []string
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("merge mode: list %s/%s: %w", bucket, prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			key := *obj.Key
			if key == prefix || !strings.HasSuffix(key, ".json") {
				continue
			}
			keys = append(keys, key)
		}
	}
	sort.Strings(keys) // deterministic fold order
	return keys, nil
}

// streamKeyedBodies fetches each key's body with a bounded sliding-window prefetch
// pool and invokes consume(key, body, err) sequentially on THIS goroutine in
// deterministic key order. At most `window` downloads run ahead of the consume
// cursor, so at most `window` decoded bodies are live at once — peak memory stays
// O(window), NOT O(len(keys)). The body is released right after consume returns.
// consume receives any per-object fetch error in its err arg (body is nil then);
// it decides whether that is fatal (raw path cancels ctx) or tolerated (per-account
// path records the account and continues). Because consume runs sequentially in
// key order, the streaming-equals-batch fold order is preserved.
func streamKeyedBodies(ctx context.Context, client *s3.Client, bucket string, keys []string, consume func(key string, body []byte, err error)) {
	type slot struct {
		body []byte
		err  error
	}
	window := mergeDownloadConcurrency
	if window > len(keys) {
		window = len(keys)
	}
	launch := func(key string) chan slot {
		ch := make(chan slot, 1)
		go func() {
			if ctx.Err() != nil {
				ch <- slot{err: ctx.Err()}
				return
			}
			body, err := getObjectBytes(ctx, client, bucket, key)
			ch <- slot{body: body, err: err}
		}()
		return ch
	}
	inflight := make([]chan slot, 0, window)
	for i := 0; i < window; i++ {
		inflight = append(inflight, launch(keys[i]))
	}
	next := window // index of the next key not yet launched
	for i := 0; i < len(keys); i++ {
		s := <-inflight[0]
		inflight = inflight[1:]
		consume(keys[i], s.body, s.err)
		s.body = nil // release before refilling the window
		if next < len(keys) {
			inflight = append(inflight, launch(keys[next]))
			next++
		}
	}
}

// runMergeAccountMode is the per-account merge tier (hierarchical merge tier 1).
// It streams one account's raw region shards through the merger and writes a
// single per-account merged ScanResult to scans/account-merged/<runId>/. Because
// it only ever holds one account's data, it fits a small Lambda regardless of org
// size. keepShards=false: the per-account object carries the deduped Merged
// payload, not verbatim shards.
func runMergeAccountMode(ctx context.Context, baseCfg aws.Config, runID, accountID string) (LambdaResponse, error) {
	bucket := os.Getenv("RESULTS_BUCKET")
	if bucket == "" {
		return LambdaResponse{}, fmt.Errorf("merge-account mode: RESULTS_BUCKET not set")
	}
	if accountID == "" {
		return LambdaResponse{}, fmt.Errorf("merge-account mode: accountId required")
	}
	client := s3.NewFromConfig(baseCfg)

	m := merge.NewMerger(merge.SentinelAccount, false)
	n, err := streamMergeUnderPrefix(ctx, client, bucket, accountRawPrefix(runID, accountID), m)
	if err != nil {
		return LambdaResponse{}, err
	}
	res := m.Finish()

	// Persist the per-account merged ScanResult AND its real (account,region)
	// coverage rows. The final tier folds these via Merger.AddPreMerged so the
	// org-wide succeeded/failed/perAccount summary is computed from genuine shard
	// identity — NOT from this object's sentinel AccountID="org" envelope.
	body, merr := json.Marshal(accountMergedObject{Merged: res.Merged, Coverage: res.Coverage})
	if merr != nil {
		return LambdaResponse{}, fmt.Errorf("merge-account mode: marshal %s: %w", accountID, merr)
	}
	key := accountMergedKey(runID, accountID)
	if _, perr := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(bucket),
		Key:                  aws.String(key),
		Body:                 bytes.NewReader(body),
		ContentType:          aws.String("application/json"),
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	}); perr != nil {
		return LambdaResponse{}, fmt.Errorf("merge-account mode: put %s: %w", key, perr)
	}

	fmt.Fprintf(os.Stderr, "[merge-account] runId=%s account=%s shards=%d -> assets=%d findings=%d -> %s\n",
		runID, accountID, n, res.Merged.Summary.TotalAssets, res.Merged.Summary.TotalFindings, key)

	return LambdaResponse{
		RunID:     runID,
		AccountID: accountID,
		Merged:    true,
		Shards:    n,
		Findings:  res.Merged.Summary.TotalFindings,
		Critical:  res.Merged.Summary.Critical,
		Assets:    res.Merged.Summary.TotalAssets,
		S3Key:     key,
	}, nil
}

// runMergeMode is the build-tagged S3 I/O front-end around the pure merge core
// (mergeRawShards + buildMergeArtifacts in lambda_merge_core.go). It is the org
// equivalent of `cryptamap org-merge-files`, but sources the raw ScanResult
// shards from S3 (scans/raw/<runId>/) instead of a local glob, and uploads the
// merged outputs back to S3 (scans/latest/<runId>.*; runId already carries the
// "run-" prefix).
//
// It reuses the EXACT merge/roadmap/output pipeline org_merge_files.go uses
// (output.SortScansByAccountRegion + merge.Merge + output.WriteCBOM /
// WriteRoadmapJSON / WriteRoadmapMarkdown). Unlike org-merge-files it does NOT
// re-parse CycloneDX or re-derive findings, because the raw shards already carry
// Assets AND Findings verbatim (uploaded by the scan branch in handle()).
//
// All I/O uses the central base config (the orchestrator's own credentials),
// never an assumed member-account role.
func runMergeMode(ctx context.Context, baseCfg aws.Config, runID string, expectedShards int) (LambdaResponse, error) {
	bucket := os.Getenv("RESULTS_BUCKET")
	if bucket == "" {
		return LambdaResponse{}, fmt.Errorf("merge mode: RESULTS_BUCKET not set")
	}
	// baseCfg.Region is already set by handle() (resolveScanRegion); the results
	// bucket lives in the lambda's own region, which baseCfg already targets.

	client := s3.NewFromConfig(baseCfg)

	// FINAL merge tier (hierarchical): stream the per-account merged objects
	// (scans/account-merged/<runId>/) one at a time through the streaming merger,
	// so peak memory is bounded by the deduped org set, NOT the sum of all raw
	// shards — this is what removes the org-merge OOM cliff (docs/SCALING.md §4.1).
	// keepShards=false: Multi.Scans is not retained (nothing downstream reads it).
	m := merge.NewMerger(merge.SentinelAccount, false)
	folded, listed, missingAccounts, err := streamAccountMergedObjects(ctx, client, bucket, accountMergedPrefix(runID), m)
	if err != nil {
		return LambdaResponse{}, err
	}
	n := folded
	if listed == 0 {
		// Back-compat / fallback: a run without the per-account tier (or with zero
		// accounts) streams the raw shards directly. Still bounded by streaming —
		// raw shards are folded one at a time, not bulk-loaded. No per-account
		// barrier applies on this path (there are no per-account objects to miss).
		fmt.Fprintf(os.Stderr, "[merge] runId=%s: no per-account objects, falling back to raw shards\n", runID)
		n, err = streamMergeUnderPrefix(ctx, client, bucket, rawRunPrefix(runID), m)
		if err != nil {
			return LambdaResponse{}, err
		}
	}
	res := m.Finish()

	// Per-account completion barrier: a tier-1 per-account merge whose object was
	// missing/corrupt is recorded (not aborted on) above. Surface it LOUDLY and
	// thread it into the summary so the org report is flagged incomplete with the
	// SPECIFIC missing accounts — never a silently-decimated "success".
	acctBarrier := accountBarrier{expectedAccounts: listed, missingAccounts: missingAccounts}
	missingAccountIDs := acctBarrier.accountIDs()
	if len(missingAccounts) > 0 {
		fmt.Fprintf(os.Stderr,
			"[merge] runId=%s INCOMPLETE: %d/%d per-account objects missing/corrupt; org report flagged incomplete. missing accounts: %s\n",
			runID, len(missingAccounts), listed, strings.Join(missingAccountIDs, ","))
		for _, ma := range missingAccounts {
			fmt.Fprintf(os.Stderr, "[merge] runId=%s   missing account %s: %s\n", runID, ma.accountID, ma.reason)
		}
	}

	// buildMergeArtifacts is the PURE render core (lambda_merge_core.go), shared
	// with org_merge_files.go. An empty set still produces a well-formed (empty)
	// merged envelope so the run always emits artifacts.
	artifacts, keys, summary, err := buildMergeArtifacts(res, runID, expectedShards, acctBarrier)
	if err != nil {
		return LambdaResponse{}, err
	}

	// Loud-incomplete (DECISION): if the merged org output is incomplete for ANY
	// reason — vanished shards, errored shards, or missing per-account objects —
	// make it impossible to miss in the orchestration logs and name every dropped
	// (account,region) tuple with its reason. The summary JSON carries the same
	// structured list (FailedShards) for the dashboard/CLI banner. We do NOT fail
	// the run: a partial inventory is still emitted, just loudly flagged.
	if summary.Incomplete {
		fmt.Fprintf(os.Stderr,
			"[merge] runId=%s ===== ORG SCAN INCOMPLETE ===== shards observed=%d expected=%d missing=%d; %d failed/dropped (account,region) tuple(s) follow:\n",
			runID, summary.ObservedShards, summary.ExpectedShards, summary.MissingShards, len(summary.FailedShards))
		for _, fs := range summary.FailedShards {
			fmt.Fprintf(os.Stderr, "[merge] runId=%s   FAILED account=%s region=%s reason=%s\n",
				runID, fs.AccountID, fs.Region, fs.Reason)
		}
	}

	// Upload each merged artifact at its absolute results-bucket key. The keys in
	// `artifacts` are already absolute (scans/latest/...), so we use a prefix-less
	// S3 writer-style PutObject directly rather than output.S3Writer (whose Prefix
	// would double-prepend "scans/").
	for key, body := range artifacts {
		contentType := "application/json"
		if strings.HasSuffix(key, ".md") {
			contentType = "text/markdown"
		}
		if _, perr := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:               aws.String(bucket),
			Key:                  aws.String(key),
			Body:                 bytes.NewReader(body),
			ContentType:          aws.String(contentType),
			ServerSideEncryption: types.ServerSideEncryptionAes256,
		}); perr != nil {
			return LambdaResponse{}, fmt.Errorf("merge mode: put %s: %w", key, perr)
		}
	}

	fmt.Fprintf(os.Stderr,
		"[merge] runId=%s mergedObjects=%d -> assets=%d findings=%d (CRIT %d) -> %s\n",
		runID, n, res.Merged.Summary.TotalAssets, res.Merged.Summary.TotalFindings,
		res.Merged.Summary.Critical, keys.CBOM)

	return LambdaResponse{
		RunID:           runID,
		Merged:          true,
		Shards:          n,
		Findings:        res.Merged.Summary.TotalFindings,
		Critical:        res.Merged.Summary.Critical,
		Assets:          res.Merged.Summary.TotalAssets,
		MergedCBOMKey:   keys.CBOM,
		RoadmapKey:      keys.Roadmap,
		Incomplete:      summary.Incomplete,
		MissingShards:   summary.MissingShards,
		MissingAccounts: missingAccountIDs,
		FailedShards:    summary.FailedShards,
	}, nil
}

// mergeDownloadConcurrency bounds the number of in-flight shard GETs. Serial
// download of thousands of shards (e.g. 300 accounts x 17 regions = 5100 GETs at
// ~50-150ms each) approaches/breaches the 15-min Lambda budget before any merge
// work begins; a bounded pool collapses that to wall-time/concurrency while
// staying well under S3 GET rate limits and not ballooning peak memory.
const mergeDownloadConcurrency = 16

// getObjectBytes downloads a single S3 object's body into memory. The caller
// unmarshals into the appropriate type (raw ScanResult shard, or per-account
// accountMergedObject) and releases the bytes immediately after folding, so the
// bounded prefetch pool never holds more than ~mergeDownloadConcurrency bodies.
func getObjectBytes(ctx context.Context, client *s3.Client, bucket, key string) ([]byte, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("merge mode: get %s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(out.Body); err != nil {
		return nil, fmt.Errorf("merge mode: read %s/%s: %w", bucket, key, err)
	}
	return buf.Bytes(), nil
}
