# CryptaMap Architecture

This document describes the redesigned CryptaMap: how a scan flows from
read-only AWS API calls to an org-wide CycloneDX CBOM and a prioritized PQC
migration roadmap. For purpose, quick start, and how-to-run, see
[`README.md`](./README.md).

## Design goals

1. **Org-wide inventory, not per-account silos.** A single merged CBOM +
   roadmap that spans every scanned account/region, with a coverage matrix so
   no account is silently treated as "clean".
2. **Actionable PQC roadmap.** Every finding is ranked into a "do these first"
   list, each item carrying the exact AWS action to enable PQC and a citation.
3. **Verifiable claims.** The PQC support matrix is web-verified against live
   AWS docs; each row carries a `SourceURL`, a `Confidence`, and an `AsOf` date.
4. **No internal IDs leak.** Internal scanner IDs (`kms_spec`, `rds_transit`)
   are mapped to friendly display names before they reach the CBOM or UI.
5. **One source of truth for wire types.** Dashboard TypeScript types are
   generated from the Go structs; drift fails CI.
6. **Pure, testable cores.** The merge and roadmap engines are pure functions
   over `models.ScanResult` — no I/O, no AWS SDK, no `internal/scanner` import —
   so they are fully unit-testable and free of import-cycle risk.

## End-to-end data flow

```
read-only AWS APIs
        │
        ▼
 internal/scanner (engine + registry)         one models.ScanResult per region
        │   99 scanners, bounded goroutine pool, rate-limit/backoff
        │   (in-transit posture derived from config/API metadata, not active probing)
        ▼
 []models.ScanResult  ──(--org-merge)──▶  internal/merge.Merge
        │                                       │ dedup assets by BomRef
        │                                       │ union findings by (ref,svc,posture)
        │                                       │ recompute summary, build coverage
        ▼                                       ▼
 per-region artefacts                     one merged models.ScanResult + Coverage
        │                                       │
        └───────────────┬───────────────────────┘
                        ▼
              internal/roadmap.Build  ──uses──▶ internal/pqc (matrix + primitives)
                        │                        internal/taxonomy (friendly names)
                        ▼
              internal/output writers
        CycloneDX 1.7 | roadmap.json/.md | PQCC xlsx | ASFF | coverage.json
                        │
                        ▼
        dashboard/ (React + Vite + Cloudscape)  ← dashboard/src/types/generated.ts
```

## Components

### `internal/scanner` — engine + registry

The engine runs every registered scanner over a bounded goroutine pool with
rate-limiting and exponential backoff, collecting one `models.ScanResult` per
region (assets, findings, per-service `ServiceScanReport` stats, and a recomputed
summary). The registry is the deduplicating, deterministically-ordered set of
scanners; `cmd/cryptamap/register.go` wires all **99** scanners into it:
49 data-at-rest, 27 data-in-transit, 10 certificates/PKI, 9 key-management,
3 SDK/library, and 1 runtime-evidence (CloudTrail KMS data-plane).

Scanners are intentionally thin SDK shims; the **pure classification helpers**
(TLS/SSL policy name → posture, KMS key spec → posture/primitive, cert signature
algorithm → posture, etc.) are factored out so they can be unit-tested without
AWS.

### `internal/taxonomy` — friendly names

`taxonomy.go` maps every scanner `Name()` to an `Entry{DisplayName, AWSCategory,
CryptoFunction, SubAspect}` (99 entries) so internal IDs never leak to the CBOM
or UI. `Lookup`/`MustLookup` apply an alias table and a safe humanized fallback,
so an unknown ID never panics. The package is dependency-free (stdlib only) to
avoid an import cycle with `internal/scanner`.

### `internal/pqc` — web-verified support matrix

`matrix.go` encodes 26 web-verified AWS PQC support rows. Each `SupportEntry`
carries:

- `PQCStatus` — `available` / `hybrid-tls-only` / `not-yet` / `not-applicable`,
- `UpgradeEase` — `one-flip` / `config-change` / `app-change` /
  `aws-managed-automatic` / `none-available`,
- `PQCMechanism` and `HowToEnable` — the exact, citable action,
- `SourceURL` + `Confidence` (`high`/`medium`/`low`),
- a package-level `AsOf` verification date cited verbatim in the roadmap.

`primitives.go` is a primitive quantum-vulnerability table (RSA/ECDSA/ECDH →
vulnerable; AES-256, SHA-2/3, ML-KEM, ML-DSA → resistant). `lookup.go` resolves
a scanner `Name()` (via `serviceAlias`) to its row, returning a conservative
`not-yet`/`none-available` fallback for unknown services so the ranker never
panics. Notable confirmed rows include AWS Private CA ML-DSA certificate signing
(`ML_DSA_44|65|87`), AWS KMS ML-DSA key specs + `ML_DSA_SHAKE_256`, ELB/API
Gateway hybrid ML-KEM TLS 1.3 `-PQ-2025-09` policies, and Transfer Family
`mlkem*` SSH KEX policies.

### `internal/merge` — pure org-wide merge (`--org-merge`)

`Merge([]ScanResult, orchestratorAccountID)` collapses N per-region/per-account
shards into a single merged `ScanResult` envelope (sentinel account `org`, region
`multi`, mode `merged`) plus a `[]Coverage` and a `MultiScanResult` provenance
envelope. It is pure (stdlib + `pkg/models` only, no I/O, no SDK).

- **Asset dedup** keys on `BomRef` (`models.BomRefForARN`). On collision the
  higher **detection source** wins (`active-probe > targeted-sdk > config >
  tagging > unknown`, read from `Properties["source"]` with a `Mode`-derived
  baseline). Ties break by richer asset → later `DiscoveredAt` → smaller ARN.
  This is why a global resource (e.g. a CloudFront distribution) seen in two
  region shards collapses to one asset, while genuinely regional resources stay
  distinct. Per-asset `AccountID`/`Region` provenance is preserved on the merged
  records even though the envelope uses sentinels.
- **Finding union** keys on `(AssetBomRef|ResourceARN, Service, Posture)` and
  keeps the highest `NormalizedSeverity`; the summary severity counts are
  recomputed from the deduped set (duplicates never double-count).
- **Service stats** sum `AssetCount`/`DurationMS` and concatenate `Errors` per
  service; **coverage** is one row per input shard with an `errored` flag.

### `internal/roadmap` — PQC migration ranker

`Build(ScanResult)` produces one `RoadmapItem` per finding, ranked descending by
a priority score, plus by-service and by-account roll-ups. It is pure and
depends only on `internal/pqc`, `internal/taxonomy`, and `pkg/models`. Typically
it is called on the single merged envelope from `internal/merge`, so one call
yields an org-wide ranked roadmap.

The score is:

```
PriorityScore = MoscaUrgency × PostureMultiplier × ExposureMultiplier + EaseTieBreak
```

- **MoscaUrgency** is monotonic in `Mosca.Score` (X+Y-Z), floored at 0.5 so even
  zero/negative-score items still order.
- **PostureMultiplier** weights cryptographic exposure: no-encryption (3.0) >
  legacy-TLS (2.5) > non-pqc-classical (2.0) > unknown (1.5) > pqc-hybrid (0.5)
  > symmetric-only (0.25) > pqc-ready (0.1).
- **ExposureMultiplier** is the harvest-now-decrypt-later amplifier (1.5 when
  `Mosca.Score > 0`, else 1.0).
- **AES/PQC sink clamp**: if the finding's underlying primitive is positively
  identified as *not* quantum-vulnerable (AES-256, ML-KEM, ML-DSA, …), the
  posture multiplier is clamped to ≤ symmetric-only, so already-resistant
  material can never outrank a vulnerable RSA/ECDSA asset even when its posture
  string looks richer. An unknown primitive is treated as vulnerable (no clamp).
- **EaseTieBreak** is a small additive term (one-flip 0.40 → none 0.00), gated by
  `PQCStatus` so a quick win only floats up among otherwise-equal items and never
  jumps an urgency tier.

Each `RoadmapItem` carries `RecommendedAction` (`pqc.SupportEntry.HowToEnable`),
`SourceURL`, `Confidence`, and `AsOf`, so the output is directly actionable and
auditable. `QuickWin` = a one-flip change on a service that can actually move to
PQC (`available`/`hybrid-tls-only`).

### `internal/output` — writers

`WriteCBOM` (CycloneDX 1.7), `WriteRoadmapJSON`/`WriteRoadmapMarkdown(TopN)`,
`WritePQCCExcel`, `WriteASFF`, and the S3/DynamoDB/PDF writers all take an
`io.Writer` and a single `ScanResult` (the per-region shard or the merged
envelope), so the merged path reuses every writer unchanged. The roadmap
markdown writer escapes pipes/newlines per cell (`mdCell`) and emits a top-N
"Do These First" table plus by-service/by-account roll-ups.

### `cmd/gen-ts` — generated TypeScript types

`gen-ts` reflects the Go wire structs (`pkg/models`, `internal/output`,
`internal/roadmap`) for struct shape — field names from the `json` tag,
optionality from `omitempty`/pointer/slice/map — and lists the enum vocabularies
(`pkg/models`, `internal/pqc`) explicitly, guarded so a non-`string` enum type
fails the generator. The output is `dashboard/src/types/generated.ts` (*"Code
generated by gen-ts; DO NOT EDIT"*). `make check-types` regenerates and runs
`git diff --exit-code`, so any Go field drift fails CI.

### `dashboard/` — Cloudscape SPA

React 18 + Vite + **AWS Cloudscape** (`@cloudscape-design/components`,
`collection-hooks`, `global-styles`) with `react-router-dom`. There is no
Tailwind and no ECharts; charts are Cloudscape. Pages: Overview, Assets (with the
`AssetDetailPanel` rendering deep crypto detail), Roadmap (`RoadmapTable` +
`RoadmapRollups`), and SEBI/RBI/IRDAI compliance tabs. `ExportButton` produces a
regulator-grade PDF via `html2pdf.js`. The dashboard imports its wire types from
the generated `dashboard/src/types/generated.ts`.

## Org fan-out topology (deployed multi-account path)

The supported organization-wide scan is the deployed fan-out (the CLI
`--org-merge` is the single-orchestrator merge path). Two pieces:

1. **StackSet (member accounts).** A CloudFormation StackSet creates a read-only
   `CryptaMapScannerRole` in every member account that the orchestrator may
   assume, guarded by a shared `ExternalId` (confused-deputy guard).

2. **Step Functions state machine (Audit/orchestrator account).**
   `cdk/lib/org-fanout-stack.ts` provisions a Standard state machine:
   - **Seed** (Lambda) — `organizations:ListAccounts` × the region list →
     `{accountId, region, roleArn, externalId}` tuples.
   - **ScanFanout** (Distributed Map, `maxConcurrency: 20`, tolerated-failure
     25%) — one child execution per tuple invoking the Go scanner Lambda; each
     child scans a single (account, region) and writes a per-(account,region)
     partial to the central results bucket. A `ResultWriter` persists the Map
     manifest + child results under `scans/_runs/`.
   - **MergeResults** (Lambda) — rolls the manifest into one run summary at
     `scans/latest/run-<id>.json`.

**Event contract (CDK → Go Lambda)** per tuple:

```json
{ "mode": "lambda", "accountId": "<member>", "region": "<region>",
  "roleArn": "arn:<partition>:iam::<member>:role/CryptaMapScannerRole",
  "externalId": "<scannerExternalId>" }
```

> **Assume-role fan-out (implemented + verified).** The Distributed Map passes
> `roleArn`/`externalId`, and the Go handler reads them
> (`cmd/cryptamap/lambda_event.go:53-54`) and assumes the member role:
> `lambda.go:121-137` calls `internal/org.AssumeRole(...)` to get an assumed-role
> `aws.Config`, re-sets `Region = evt.Region`, runs an eager STS
> caller-identity check as a confused-deputy guard (failing the shard on a
> mismatch), then runs the engine against the member account and writes partials
> with the **base/central** config so they land in the central results bucket
> (`lambda.go:122,134-137`). The contract is documented in `org-fanout-stack.ts:69-79`
> ("IMPLEMENTED — verified end-to-end against the live org"). `--org-merge` remains
> available for merging single-account CLI runs offline.

## CDK stacks

`cdk/bin/app.ts` wires five stacks: **Data** (results S3, DynamoDB, KMS; no
query API), **Security** (scanner role + StackSet, orchestrator role),
**Scanner** (scanner Lambda + schedule), **Alerting** (SNS critical-finding
alerts), and **OrgFanout** (the Step Functions fan-out above, built only when
`orgScanning=true`). There is no public CloudFront/dashboard stack — the
dashboard is served locally by `cryptamap serve` (local-first model). See
`DEPLOYMENT.md` for a templated deployment snapshot.

## Invariants worth preserving

- `internal/merge`, `internal/roadmap`, `internal/pqc`, and `internal/taxonomy`
  must stay **pure** (no I/O, no AWS SDK, no `internal/scanner` import) so they
  remain unit-testable and cycle-free.
- The taxonomy registry holds exactly **99** entries (one per scanner); aliases
  widen `Lookup`'s input domain without changing the count.
- Posture multiplier ordering and the AES/PQC sink clamp are load-bearing for
  roadmap correctness — change them only with matching test updates.
- `dashboard/src/types/generated.ts` is generated; never hand-edit it
  (`make generate-types`).
