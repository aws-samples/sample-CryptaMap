# CryptaMap Scaling: Large-Org Hardening & Distributed-Map Redesign

**Status:** the safe fixes below are implemented; of the redesign items, §4.1, §4.2, §4.4, and §4.5 are now **implemented**, §4.3 was **superseded** by the local-first redesign, and only the residual off-Lambda/disk-backed dedup term (§4.1 C/D) and browser-side scale remain open.
**Target scale:** hundreds of AWS accounts × thousands of resources/account × many regions, with each unit of work fitting AWS Lambda's 15-minute / memory ceilings and scaling horizontally.

This document records (1) the verified scalability bottlenecks, (2) the low-risk fixes already applied, and (3) the architectural redesign required for the bottlenecks that cannot be fixed safely in-place — chiefly the **terminal merge memory cliff**.

It is the output of an adversarially-verified audit (39 candidate findings → 34 confirmed, 5 refuted as dead code / non-paginating APIs) plus empirical profiling of the merge path.

---

## 1. Architecture recap

Two run modes:

- **CLI** (`cmd/cryptamap` `runScan`): scans the **caller account only**, looping regions sequentially, writing artifacts per (account, region). `--org-merge` merges the in-memory shards. `--org`/`--accounts` are **not** honored here (now warned — see §3).
- **Lambda + Step Functions Distributed Map** (the real org engine): a seed Lambda enumerates `(account, region)` tuples; the Map fans out one **scan shard** Lambda per tuple (assume member-account role → scan ~99 services → write a partial CBOM + a raw `ScanResult` JSON to `s3://…/scans/raw/<runId>/`); a terminal **merge** invocation (`evt.Merge`) lists + downloads every raw shard and merges them into one org CBOM + roadmap.

The per-shard scan model is horizontally scalable and sound. The problems are concentrated at the **fan-in (merge)**, the **fan-out enumeration (seed→Map)**, and the **serving layer (dashboard/API)**.

---

## 2. The memory cliff (empirically measured)

The terminal merge loads **all** raw shards into one Lambda, builds dedup maps over every asset + finding, and renders the full CBOM/roadmap in memory. Measured with a synthetic merge harness (`internal/merge/scale_validation_test.go`, live-like density: per-asset `CryptoProps` + `Properties`, 1 finding/asset):

| Accounts × Regions | Shards | Merged assets | Merge time | Peak `Sys` mem |
|---|---|---|---|---|
| 50 × 4 | 200 | 400 k | 0.45 s | **~1.1 GB** |
| 100 × 5 | 500 | 1 M | 1.3 s | **~2.7 GB** |
| 300 × 5 | 1 500 | 3 M | 4.8 s | **~8.2 GB** |

**Conclusion:** merge *time* is a non-issue (<5 s even at 3 M assets); the killer is **memory**. The deployed merge function is `memorySize: 1024` (`cdk/lib/scanner-stack.ts:50`, reused via `org-fanout-stack.ts` `BuildOrgCbom`). At ~300 accounts the merge needs ~8 GB — 8× over the 1 GB config and near the 10 GB Lambda hard max. Every per-shard scan can succeed and the run still produces **no** org CBOM because the single unshardable merge OOMs. This is a hard ceiling; retries don't help.

A second, related cliff: the merged CBOM **itself** scales 1:1 with the org. A 90 k-asset org-merge produced a **156 MB** `cbom.json` (measured). Such an artifact is consumed via the local/artifact path (downloaded from the results bucket with operator creds, then opened locally or via `cryptamap serve`) — there is no deployed query API that would try to proxy it whole (see §4.3).

---

## 3. Safe fixes already shipped

These are low-risk, in-place changes; full build (default + `-tags lambda`) and tests pass.

### Correctness — silent truncation (data-loss → false "all clear")
- **13 scanners** (`acm, acmpca, cloudfront_certs, cloudhsm, container_images, ec2_ssm, iam_certs, iot_certs, kms_spec, kms_rotation, kms_usage, lambda_runtime, secrets_rotation`) silently `return` at a hidden `const maxItems = 1000`. Replaced with a shared `services.TruncationCapReached()` helper that raises the bound to `MaxAssetsPerScanner = 25000` and **logs loudly** when hit, so truncation is never silent.
- **`s3`** `ListBuckets` now paginates (`ContinuationToken`) with server-side `BucketRegion` filtering (previously truncated at the ~10 k service page cap).
- **`apigw_http`** `GetApis` + `GetDomainNames` now paginate (`NextToken`); previously first-page-only (~25).
- **`iotcore`** `ListThings` now paginates (was a hard first-page cap of 50), bounded by `MaxAssetsPerScanner`.
- *Refuted / left alone:* `opensearch`, `directconnect`, `vpn` (their APIs return all results, no pagination); `alb`/`nlb` per-LB listeners and `globalaccelerator` listeners (quota-bounded to ~tens — cannot truncate at scale).

### Throttling / retry
- AWS SDK clients now use **adaptive retry mode** (`WithRetryMode(aws.RetryModeAdaptive)`, max 8 attempts) in both CLI and Lambda — adds the previously-missing client-side rate limiter so a throttled fleet scan backs off its send rate.
- The engine's `runWithRetries` **no longer double-retries throttles** (`shouldRetry` excludes `Throttling/TooManyRequests/RequestLimitExceeded/503`) — the SDK now owns those. This removes the ~3-6× attempt amplification that *worsened* throttling at fleet scale. The engine layer retains only coarse between-call transient recovery (`i/o timeout`, `connection reset`).
- `EngineOptions.PerServiceCap` (previously declared but **never enforced** — dead config) is now applied in `Engine.Run`, letting an operator bound a single pathological service in one shard.

### Memory (mitigations — do NOT remove the §5 redesign need)
- **Lambda merge download** is now **bounded-concurrent** (16 in flight) instead of strictly serial, removing the ~4-13 min serial-GET latency risk for thousand-shard runs. Each shard body is read into a per-object buffer (`bytes.Buffer.ReadFrom`, `cmd/cryptamap/lambda_merge.go:442-444`) and then unmarshalled; the concurrency cap (not per-object streaming) is what bounds transient memory — at most ~16 shard bodies are resident at once. (A true `json.NewDecoder` streaming decode per body is a possible future optimization; it is **not** implemented today.)
- **CLI** drops each shard's heavy `Assets`/`Findings` slices after writing artifacts when `--org-merge` is **off** (only `Summary` is needed downstream), keeping peak memory ~flat across a many-region scan instead of growing per region. Verified: a 120 k-asset 4-region CLI scan peaked at ~1.65 GB RSS.

### Guards / observability
- **DynamoDB `PutScan`** now caps the inline gzipped findings blob at 300 KB; oversize dense shards omit the inline blob (findings remain in S3 via `cbomRef`) + log, instead of failing the whole `PutItem` on the 400 KB item limit.
- **Lambda scan shard** now **eagerly verifies assumed credentials** (`GetCallerIdentity` after `AssumeRole`) and checks the landed account matches `evt.AccountID`. Previously a denied/untrusted role surfaced only as caught per-scanner errors and the shard still returned **SUCCEEDED with 0 assets** — a permission failure masquerading as a clean account. Now it fails the shard (visible as FAILED in the Map).
- **CLI** warns loudly when `--org`/`--accounts` are passed (they are silently ignored by the single-account CLI path).

---

## 4. Redesign — orchestration/serving shape

These changed the orchestration/serving shape rather than being safe in-place fixes. §4.1, §4.2, §4.4, and §4.5 are now **implemented**; §4.3 was **superseded** by the local-first redesign. Each item is labelled with its current status.

### 4.1 Streaming / hierarchical merge — **IMPLEMENTED**
Both the streaming primitive and the hierarchical orchestration are now built (this was previously propose-only):

- **Streaming `Merger` (`internal/merge/streaming.go`).** Folds shards one at a time via `Add(scan)`; the caller discards each `ScanResult` afterward. Peak memory is bounded by the **deduped working set**, not the sum of raw shards. Batch `Merge` is reimplemented on top of it (single dedup code path); `streaming_test.go` proves `NewMerger(...).Add(...).Finish()` is byte-identical to `Merge(...)` for the same input order. (Fixing the equivalence test also surfaced + fixed a latent non-determinism: the finding sort wasn't total — many same-`(severity,service,resourceID)` findings across accounts sorted non-deterministically; now tie-broken by `account/region/ARN`.)
- **Hierarchical two-tier merge (Lambda + CDK).** Tier 1: a per-account merge Distributed Map (`AccountMergeFanout`, one child per distinct account, `mergeAccount:true`) streams that account's `scans/raw/<runId>/<accountId>-*` shards into one `scans/account-merged/<runId>/<accountId>.json`. Each child holds only one account's data. Tier 2 (`BuildOrgCbom`, `merge:true`) streams the much smaller per-account objects through the streaming `Merger` (raw-shard fallback if tier 1 produced nothing). CDK synth-validated (not deploy-tested).
- **`Multi.Scans` dead copy:** dropped on the streaming Lambda path via `NewMerger(keepShards:false)` (nothing downstream reads it); batch `Merge` keeps `keepShards:true` to preserve the asserted contract.

**Measured win (honest).** Synthetic 300 accounts × 5 regions = 3 M assets, `internal/merge/scale_validation_test.go` (`TestStreamingVsBatchMemory`, run per-mode for a fair peak): **batch 8.0 GB → streaming 6.8 GB peak Sys (~16%).** The win is *modest here because the test data is fully distinct* (zero cross-account dedup), so the deduped working set (3 M assets) dominates. **Streaming bounds the "all raw shards resident at once" term; it does NOT bound the deduped-set term.** Real orgs (shared AMIs, replicated buckets, common KMS/cert patterns → heavy overlap) dedup far more, so the real-world win is larger. For an org whose *distinct* asset count alone exceeds a Lambda's memory, the residual fix is **(C) /tmp- or DynamoDB-backed dedup maps** (Lambda gives 10 GB ephemeral) or **(D) off-Lambda merge** (Fargate/Batch, no 15-min limit) — both still open, lower priority now that the common case is bounded.

### 4.2 SFN seed: S3 ItemReader instead of inline `itemsPath` — **IMPLEMENTED**
Originally propose-only: the inline `itemsPath: $.seed.tuples` enumerated the tuple array **from Step Functions state**, capped at the **256 KB** state-payload quota (~215 bytes/tuple ⇒ **~1,219 tuples max**; a 300-account multi-region run of e.g. 300×17 = 5,100 tuples would throw `States.DataLimitExceeded` at the seed→Map transition before any scan starts). This is now built: the seed Lambda writes the tuples to S3 and the Map consumes them via `new sfn.S3JsonItemReader({ ... })` (`cdk/lib/org-fanout-stack.ts:402-404`, and again for the account-merge Map at `:478`), removing the 256 KB ceiling.

### 4.3 Dashboard / API serving — **SUPERSEDED by the local-first redesign**
This section described a dies-at-scale problem in a serving layer that **no longer exists**: an earlier design proxied the entire merged CBOM/roadmap through a 256 MB query Lambda + API Gateway (breaking at ~4,000 components / 6 MB Lambda sync-response, ~6,400 / 10 MB API-GW; a 90 k-asset org produced a **156 MB** body). That query API + dashboard tier was **removed** in the local-first redesign — there is no deployed `/cbom`/`/roadmap` endpoint to overflow. The supported way to consume a large org CBOM is the **local/artifact path** (CLI output + `cryptamap serve` over loopback, or the signed HTML report), which has no Lambda/API-Gateway response ceiling. Browser-side scale (virtualized/paginated asset tables for very large CBOMs) remains a forward-looking dashboard-usability item, independent of any serving API.

### 4.4 Orchestration robustness — **IMPLEMENTED**
- **Completion barrier.** `toleratedFailurePercentage: 25` (`org-fanout-stack.ts:364`, and again for the account-merge Map at `:431`) still lets up to a quarter of shards fail, but the merge no longer proceeds over whatever landed with no expected-count check. The seed emits an `expectedShards` count computed **after** region filtering (`org-fanout-stack.ts:261`) and threads it into the terminal merge (`'expectedShards.$': '$.seed.expectedShards'`, `:470`). The merge reconciles the observed shard count against it and surfaces the gap — vanished/tolerated-failed shards become `MissingShards`/`FailedShards` rows and force `Complete=false` (`cmd/cryptamap/lambda_merge_core.go`), so a decimated run reads as INCOMPLETE, never as a clean smaller result.
- **Region enablement.** The static region list is no longer crossed with every account blindly. The seed resolves each account's **enabled** regions by assuming its member role and calling `ec2:DescribeRegions` (`enabledRegionsFor`, `org-fanout-stack.ts:171`): in explicit-list mode it returns the enabled subset of the static regions (opt-in regions a member has not enabled are skipped — no dead shards); in `all` mode it returns the account's full enabled set. A discovery failure does not silently collapse to one region — the account is recorded in `regionDiscoveryFailedAccounts`, threaded into the merge (`:478`), and folded into `FailedShards` forcing `Complete=false` (see §6 Bug B).

### 4.5 Per-shard inner concurrency — **IMPLEMENTED**
`s3` (`GetBucketEncryption` + per-SSE-KMS `DescribeKey`) and `dynamodb` (`DescribeTable`) no longer make **serial per-resource** calls. Both now fan those per-resource loops out through a bounded inner worker pool (`services.MapConcurrent`, `internal/services/common.go:352`, at `DefaultInnerConcurrency = 12`) — order-preserving and no extra retry (each call is a single SDK op whose adaptive retryer handles throttle; the engine's outer retry still wraps the whole `Scan`). See `internal/services/datarest/s3.go:140` and `internal/services/datarest/dynamodb.go:95`; the same primitive is reused across the other dense per-resource scanners (kms, athena, firehose, etc.). This keeps a region with thousands of buckets/tables inside the 15-min shard timeout. *(`SecretsManager`/`RDS` do NOT need this — they read everything off the List page.)*

---

## 5. Recommended sequencing

Of the original sequence, **§4.1 hierarchical merge**, **§4.2 SFN S3 ItemReader**, **§4.4 completion barrier + region enablement**, and **§4.5 inner concurrency** are now implemented, and **§4.3** (serving-layer overflow) was made moot by removing the query API in the local-first redesign. The remaining open work, in priority order:

1. **Browser-side scale** — virtualized/paginated asset tables so very large org CBOMs render in the local dashboard without loading everything into the tab (dashboard usability, no serving API involved).
2. **Off-Lambda / disk-backed dedup for the residual merge term** — §4.1 (C)/(D): /tmp- or DynamoDB-backed dedup maps, or a Fargate/Batch merge, for an org whose *distinct* asset count alone exceeds a Lambda's memory. Lower priority now that the common case is bounded.

---

## 6. All-regions fan-out — the region-discovery design hazard

When the Step Functions fan-out runs at full width (`-c fanoutRegions=all`), the seed
step must discover each account's enabled regions before emitting per-`(account,region)`
scan tasks. This path has a subtle two-part failure mode worth calling out, because it
is exactly the kind of *false-clean* result the tool exists to prevent.

### The hazard (two coupled bugs to avoid)
- **Region discovery must authenticate as a principal the scanner role trusts.** If the
  seed calls `ec2:DescribeRegions` by assuming `CryptaMapScannerRole` directly, it fails:
  the scanner role's trust policy trusts **only `CryptaMapOrchestratorRole`** (ExternalId
  + `PrincipalOrgID` gated), not the seed's own service role — so `AssumeRole` is denied
  callee-side even though the seed holds `sts:AssumeRole` caller-side.
- **A silent fallback turns that failure into a fake success.** If discovery returns
  `null` and the caller falls back to a default region list, a *broken* discovery path
  reports a *successful* small scan (e.g. one `us-east-1` shard per account). A narrow
  fixed-region run can mask this entirely — the fallback happens to include the always-on
  regions, so the output looks correct while silently omitting most of the org's crypto
  surface. This is the false-clean failure mode (cf. §3 silent-truncation) on the region
  axis.

### The design rules that close it
1. **Discover regions via the orchestrator role** — the principal the scanner roles
   already trust. The seed assumes `CryptaMapOrchestratorRole`, then chains into each
   child scanner role, mirroring the scanner Lambda's working assume-and-verify path. No
   trust-policy change, smallest confused-deputy surface. (Alternative: move region
   discovery into the scanner Lambda, which already assumes correctly, and have the seed
   emit one self-expanding "discover+scan" task per account.)
2. **A region-discovery failure MUST surface, never silently collapse.** It has to appear
   as `UNCOVERED`/error in the coverage matrix, and the coverage headline must be sourced
   from the per-`(account,region)` coverage rows, not from a raw shard count — so a
   discovery gap can never read as a clean subset.

### Scale read at full-region width
- All-regions multiplies shard count by ~enabled-regions-per-account (≈17×). A handful of
  accounts produces ~100 shards end-to-end in a few minutes; the Distributed Map
  parallelism absorbs it and cost is dominated by short scanner-Lambda invocations plus a
  per-account assume + `DescribeRegions` (pennies at this size).
- Seed region-discovery is **~accounts × 1** STS+`DescribeRegions` (it does NOT multiply
  by region count), so it scales to 100s of accounts without an STS storm.
- The gating limits at **100s of accounts** are still the §2 merge memory cliff and the
  §4.2 seed inline-payload (mitigated by the S3 ItemReader). A 200-account org at
  all-regions width is ~3,400 shards — squarely in the regime the §4.1 hierarchical merge
  and §4.2 ItemReader were built for; re-profile there before declaring 100s-of-accounts
  ready.

### Re-test command
`cd cdk && npx cdk deploy --all -c orgScanningEnabled=true -c fanoutRegions=all` (deploy the full app with org scanning enabled; avoid `--exclusively CryptaMap-OrgFanout`, which skips the trust/dependency stacks the fan-out relies on)
then `aws stepfunctions start-execution --state-machine-arn <CryptaMapOrgScan> --input '{}'`;
verify the seed tuple count ≈ accounts × enabled-regions and that region-discovery
reported zero failures.

---

*The `internal/merge/scale_validation_test.go` harness (skipped by default) reproduces the
§2 memory/scale numbers — remove its `t.Skip` to re-profile.*
