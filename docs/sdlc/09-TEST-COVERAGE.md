# 09 — Test Coverage

> **Audience & purpose:** Engineers, reviewers, and auditors who need an honest, citation-grounded picture of *what CryptaMap actually tests, what it deliberately validates by other means, and where the genuine gaps are.* This is not a marketing coverage badge — it explains every low number.

## Table of contents

1. [How to read this report](#1-how-to-read-this-report)
2. [The layered test strategy](#2-the-layered-test-strategy)
3. [Per-package coverage table](#3-per-package-coverage-table)
4. [What IS tested (the high-value core)](#4-what-is-tested-the-high-value-core)
5. [Why the low numbers are low (and mostly fine)](#5-why-the-low-numbers-are-low-and-mostly-fine)
6. [Layer 4 — internal live-validation (the other half of correctness)](#6-layer-4--internal-live-validation-the-other-half-of-correctness)
7. [Prioritized genuine test gaps](#7-prioritized-genuine-test-gaps)
8. [How to run and reproduce these numbers](#8-how-to-run-and-reproduce-these-numbers)
9. [Cross-links](#9-cross-links)

---

## 1. How to read this report

Coverage numbers below are Go statement coverage from `go test ./internal/... ./pkg/... ./cmd/... -cover` (the project's `make test` target, `Makefile:47-48`, scoped by `GOPACKAGES = ./internal/... ./pkg/... ./cmd/...` at `Makefile:3`). Every percentage in this document was produced by an actual run, not estimated.

A **low statement-coverage number is not automatically a defect.** CryptaMap's code splits cleanly into two kinds of package:

- **Logic packages** — pure, deterministic functions (classification, scoring, merge, compliance mapping, knowledge tables). These *should* and *do* have high unit coverage, because they are cheap to test and carry the regulator-facing correctness contract.
- **I/O packages** — per-service scanners that are mostly `aws-sdk-go-v2` `List*`/`Describe*` plumbing wrapped around a small classification call. Some of their statement count is SDK marshalling that only runs against live AWS, but the plumbing logic (pagination, error-propagation) and the classification are now driven in CI by **per-scanner fake-client tests** (Layer 1, §2), with the **live-fixture harness** (see §6) and AWS-documentation facts as confirmation. This is a change from the earlier posture of mocking nothing and leaning on the harness — see §5.1.

> **One important caveat to keep honest:** "validated by the harness or by doc-facts" is a *real* but *manual / out-of-band* validation path. It is genuine coverage of correctness, but it is **not** continuous-integration coverage. Where a scanner's decision logic is *not* extracted into a unit-tested pure helper, it is effectively only covered when an operator runs the harness. Those cases are called out in §7.
>
> **What changed (2026-06-16):** this manual/out-of-band reliance has been **substantially reduced**. A comprehensive code review found a class of defect — over-alarms, false all-clears, and fabricated verdicts — that *per-scanner opt-in tests structurally could not catch* (a per-scanner test passes on its own resource yet never proves a shared fold/derivation path is honest, and never auto-covers a *future* scanner). The remediation is a three-layer test strategy (§2): per-scanner `Scan()`-level fake-client tests, **systemic honesty-invariant tests that iterate every scanner and the live registry**, and **adversarial fuzz + a full end-to-end output-pipeline net** — all CI-gated. So this class of defect can no longer recur silently.

---

## 2. The layered test strategy

CryptaMap's correctness net is organized in deliberately complementary layers: three CI-gated unit layers (1–3), a fourth per-package **CBOM-conformance** unit layer (also CI-gated), and a separate internal **live-validation** tier (Layer 4) that runs against real AWS resources. The driving lesson — from the review that found the **App Mesh mislabel** (every STRICT/PERMISSIVE mesh node collapsed to `no-encryption` because a weakest-wins fold was *seeded* from `NoEncryption`; `internal/services/transit/appmesh.go:117-134`) — is that a per-scanner test can pass while a *systemic* honesty law is violated, and that opt-in tests never automatically cover a scanner added tomorrow. Each layer answers a failure mode the layer above cannot:

### Layer 1 — Per-scanner `Scan()`-level fake-client tests
Each scanner was refactored to a small **testable client interface**, and a hand-rolled fake client drives its `scan()` core. These tests assert the three things SDK plumbing gets wrong: **pagination** (the `NextToken`/marker loop actually iterates), **error-propagation-not-silent-drop** (a `List*`/`Describe*` error surfaces as a visibly incomplete scan, never a clean empty success), and the per-scanner **honesty posture** (the right verdict for the resource's known crypto state). There is now one `_test.go` per scanner across `internal/services/{datarest,transit,certmgmt,keymgmt,sdkpqc,runtime}` (83 added this cycle on top of the pre-existing helper tests). **This layer caught a real bug:** the App Mesh weakest-wins fold above. It raised the scanner-dir coverage from ~1–12% into the **70s–80s** range, which the later CBOM-conformance layer lifted further (see §3).

### Layer 2 — Systemic honesty-invariant tests (over every scanner + the live registry)
`internal/scanner/invariants_test.go` enforces the **honesty contract as laws over ALL data**, not per scanner. It drives a **deterministic, fixed-seed** mock at large scale (`mock.Generator{Seed:0xC0FFEE, Scale:200}` → ~12k assets exercising every mock-reachable posture) through the **real `BuildFindings` path**, *and* iterates the **live registry** (`testRegistry`, mirroring `cmd/register*.go`) and drives the full `Engine.Run`. The eight tests assert five laws, all loop-driven so the ~99 scanner names are never hardcoded and **a future scanner is covered automatically**:

- **I1 — posture-in-enum:** every asset's `Properties["posture"]` is one of the 7 valid enum values (no empty / out-of-enum posture that downstream silently coerces).
- **I2 — service resolves to a real taxonomy `Entry`:** non-empty `Service`, `AWSCategory != "Other"`, non-empty `CryptoFunction` — over both the mock assets *and* the live registry names (`TestInvariant_ServiceResolvesTaxonomy` + `TestInvariant_LiveRegistryResolvesTaxonomy`).
- **I3 — quantum-safe never escalated (the H1 rule):** a quantum-safe posture (symmetric-only / pqc-hybrid / pqc-ready) is **never** CRITICAL/HIGH from a Mosca/HNDL bump — and, the other direction, a vulnerable posture never drops *below* its posture floor (no silent under-alarm). This is the exact systemic guard the App Mesh class of bug needed; it is mutation-verified (fails on the old unconditional worse-of fold).
- **I4 — no-encryption carries a note:** every `no-encryption` asset has an explanatory `Properties["note"]` — never a bare, context-free severe verdict.
- **I5 — bom-refs are unique:** no duplicate/fabricated ref (the org-wide dedup key); a colliding ARN scheme is caught.

A meta-guard (`TestInvariant_MockCoversEveryPosture`) proves the loops actually exercise every reachable posture rather than a degenerate single-posture dataset, and the engine arm (`TestInvariant_LiveRegistryEngineFindingsHonest`) proves the engine's own finding-build path obeys I1+I3 for any current or future registered scanner.

### Layer 3 — Adversarial fuzz + end-to-end output pipeline
- **Adversarial property tests** (`internal/services/{datarest,transit,certmgmt,keymgmt}/fuzz_invariant_test.go`) throw four **hostile fake-client shapes** — top-level list error, per-resource describe error, nil/empty output, empty page — at a cross-section of **23 scanner cores** and assert: **no panic**, a top-level read error **propagates** (nil/empty assets, visibly incomplete — never a clean empty success), and **no fabricated verdict on a failed read** (a failed read may emit `Unknown`+note, or for cert/key scanners the conservative `NonPQCClassical`, but **never** `no-encryption` / `symmetric-only` / a PQC-safe all-clear).
- **Two Go-native fuzz targets** back-stop the security-critical parsers: `FuzzParseCertPEM` (`internal/services/certmgmt`, ~1.8M execs locally) and `FuzzKMSSpecPosture` (`internal/services/keymgmt`) — arbitrary garbage bytes must not panic and must not fabricate a PQC-safe verdict.
- **True end-to-end pipeline** (`internal/output/e2e_pipeline_test.go`): one deterministic mock `ScanResult` → real `BuildFindings`/summary → **every** output writer, asserting each artifact is structurally valid **and** honesty-consistent: CBOM validates against the CycloneDX 1.7 schema (and no component carries a PQC-safe claim contradicting its posture), ASFF severities reconcile with the summary and ProductArn placeholders expand, the **PQCC Excel formula-injection regression** (an `=HYPERLINK(...)` payload comes out quote-prefixed, never an evaluatable cell), roadmap counts reconcile with the summary, the HTML report is self-contained (air-gap: no external resource refs) and auto-escapes injected XSS, and a capstone cross-artifact check proves CBOM / ASFF / HTML all agree on inventory and finding counts.

### The mock-coverage drift guard (what makes Layers 2 & 3 trustworthy)
Layers 2 and 3 are only as honest as the mock they iterate. `internal/mock/coverage_test.go` (`TestMockCoverageNoDrift`) **fails the build** if any registered scanner lacks a mock `Template`, plus reverse/well-formed guards (`TestMockNoOrphanTemplates`, `TestMockTemplatesWellFormed`). To satisfy it the mock generator (`internal/mock/templates.go`) was extended from ~40 templates to **all 99**, and `internal/mock/generator.go` now stamps a `note` on every no-encryption mock asset (faithfully modeling the real scanners, so I4 has something honest to assert). Before this guard, `--mock` and every mock-driven e2e silently skipped ~39 services.

### The CBOM-conformance layer — per-package schema conformance against the official CycloneDX 1.7 standard
Layers 1–3 prove the scanners are honest and the *aggregate* pipeline emits a schema-valid CBOM. The CBOM-conformance class closes the remaining gap **per package**: it proves that *each scanner's own* `scan()` output, and the **full range of SDK enum values AWS can return**, both serialize to a CBOM that validates against the official CycloneDX 1.7 JSON schema. These are CI-gated unit tests (no AWS) — distinct from the Layer 4 live-validation tier — and each of the **6** `internal/services/*` packages (`datarest`, `transit`, `certmgmt`, `keymgmt`, `sdkpqc`, `runtime`) carries three files:
- **`cdx_conformance_test.go`** — drives the scanner's **real `scan()` output** through the official CycloneDX 1.7 JSON schema (via `output.ValidateAssetsCBOM`). Proves the bytes a scanner actually produces are standard-conformant, not just a hand-built sample.
- **`cdx_enum_oracle_test.go`** — iterates the AWS SDK's own `EnumType.Values()` (**270+** values across the scanned services) as the **authoritative input contract**, asserting each produces schema-valid CBOM. This is the "test against what AWS actually returns" net at the type level: if AWS adds an enum value, the oracle exercises it.
- **`cdx_adversarial_test.go`** — feeds nil / empty / unknown-enum / oversize SDK responses and asserts **no panic** plus schema-valid output (a malformed AWS response must never produce a malformed or schema-invalid CBOM).

Backing these are reusable validators and contract tests in `internal/output/`: **`cdx_schema_validate.go`** (`ValidateCBOMBytes` / `ValidateAssetsCBOM` — the shared CycloneDX 1.7 validators), **`asff_validate.go`** (the Security Hub ASFF contract), **`pqcc_validate.go`** (the MITRE PQCC workbook contract), and `crypto_graph_test.go`; plus **`internal/merge/merge_integrity_test.go`** (the org-merge no-loss / no-double-count contract — the 9 tests that took `internal/merge` from 20 to 29).

### Layer 4 — Internal live-validation (the input-fidelity tier, above CI)
Layers 1–3 are CI-gated but all drive **fake/mock inputs**: they prove the plumbing, the honesty contract, and the output pipeline are correct *for the inputs the test author imagined*. They cannot prove that a real AWS API actually returns the field shape the scanner parses. That **input-fidelity gap** is closed by a tier that sits deliberately *above* unit/fuzz/invariant/e2e: an operator-supervised **create → scan → verify → teardown** harness that stands up real AWS resources of known crypto state, runs the scanner binary against them, asserts the emitted posture matches an oracle, then guarantees teardown plus an honest orphan sweep. This tier is **internal-only** — its resource-creating fixtures are deliberately *not* shipped in this public sample (see §6 for why) — but it is described here because it is part of the real correctness story. The **2026-06-17/18 pass** (see [`CHANGELOG.md`](../../CHANGELOG.md)) is the proof this tier earns its place: it caught **two genuine scanner bugs that every Layer-1 fake-client test had passed** (codebuild + backup key-custody mislabels — see §6). This layer is **not** CI (it is destructive, billable, and operator-driven); it is the deliberate out-of-band confirmation that real-resource fields land where the scanners expect. Full detail in §6, and in [docs/VALIDATION.md](../VALIDATION.md).

### CI gating
`.github/workflows/ci.yml` runs the broad `go test ./internal/... ./pkg/... -cover` (which already includes all of the above, since they are plain `_test.go` files), **plus** two explicit named-and-labelled steps so a regression is unmissable: *"honesty invariants + e2e pipeline (named tests)"* (`go test -run 'Invariant|Honesty'` / `'E2E|Pipeline'` / `'Coverage'`) and *"fuzz security-critical parsers (brief)"* (`-fuzz=FuzzKMSSpecPosture` and `-fuzz=FuzzParseCertPEM`, `-fuzztime=20s` each, exercising inputs beyond the seed corpus).

---

## 3. Per-package coverage table

Sorted high → low. The bar is a quick visual (each `█` ≈ 5%). All percentages were produced by an actual `go test ./internal/... -cover` run on **2026-06-22**, after the CBOM-conformance test class landed on top of the Scan()-level harness waves. The scanner-dir numbers below are the headline change: they jumped from ~1–12% into the 72–90% band once each scanner got a `Scan()`-level fake-client test (Layer 1, §2) and then a per-package CBOM-conformance suite (the new test class, §2).

| Package | Coverage | Bar | Kind | Why this number |
|---|---:|---|---|---|
| `internal/taxonomy` | **100.0%** | `████████████████████` | Logic | Tiny pure lookup table; exhaustively tested incl. an "every scanner has a display name" guard. **Note:** the 20 previously-`Other` scanners now have real entries, and `taxonomy_test.go:TestCount` asserts the table holds exactly **99** entries (was 86 before the coverage-expansion); `TestAllScannersCovered` walks the full 99-name list. |
| `internal/roadmap` | **95.6%** | `███████████████████` | Logic | Scoring/ranking/rollup engine; 17 tests across ordering, tie-breaks, clamps, edge cases. |
| `internal/compliance` | **91.9%** | `██████████████████` | Logic | Framework mapper; tests all-9-frameworks load, enabled-filtering, posture→status, SEBI no-encryption flag. |
| `internal/scanner` | **89.5%** | `██████████████████` | Engine / I/O | **Note:** was 0.0% with no test file. Now `findings_test.go` directly tables `BuildFindings` (the H1 fix), `registry_test.go` adds read-only-middleware + coverage reconciliation + registry↔taxonomy, and `invariants_test.go` (Layer 2, §2) drives a deterministic large-scale mock **and** the full `Engine.Run` over the live registry — which is what lifts the engine package into the high-80s by exercising the goroutine-pool/finding-build path systemically. |
| `internal/services/runtime` | **88.3%** | `██████████████████` | I/O scanner | Its pure JSON/posture parsers (`parseRuntimeAlgo`, `runtimePosture`, `chooseAlgo`, `parseTLSDetails`) ARE unit-tested. **Note:** was 32.4%. The big jump is from the CBOM-conformance class (§2) — `cloudtrail_evidence` got a refactored `scan()` seam plus `cdx_conformance_test.go` / `cdx_enum_oracle_test.go` / `cdx_adversarial_test.go` driving its real `scan()` output (and the SDK enum-oracle inputs) through the CycloneDX 1.7 schema. |
| `internal/services/sdkpqc` | **85.0%** | `█████████████████` | I/O scanners | 3 compute scanners (lambda runtime, container images, EC2/SSM). **Note:** was 0.0% with no test file; each now has a `Scan()`-level fake-client test (Layer 1) asserting pagination + error-propagation + posture, plus the CBOM-conformance suite (§2). |
| `internal/pqc` | **82.7%** | `█████████████████` | Logic | PQC knowledge tables + strength + golden/embedded-vs-literal reproducibility + purity guard. |
| `internal/services/transit` | **79.3%** | `████████████████` | I/O scanners | 27 SDK in-transit scanners + 3 pure-classifier helper files. **Note:** was 12.0%. Every transit scanner now has a `Scan()`-level fake-client test (Layer 1) — this is the wave that **caught the App Mesh weakest-wins bug** — and `fuzz_invariant_test.go` adds the adversarial cores (Layer 3), plus the CBOM-conformance suite (§2). |
| `internal/services/certmgmt` | **78.1%** | `████████████████` | I/O scanners | 10 cert scanners + `parseCertPEM`. **Note:** was 9.7%. Every cert scanner now has a `Scan()`-level fake-client test (Layer 1), `fuzz_invariant_test.go` adds the adversarial cores plus the `FuzzParseCertPEM` native fuzz target (Layer 3) — the PEM parser's "never fabricate classical/PQC-safe on garbage" rule is now fuzzed, closing the former §7 P1 gap — and the CBOM-conformance suite (§2). |
| `internal/output` | **76.8%** | `███████████████` | Mixed | CBOM round-trip, CycloneDX 1.7 schema (live-shape + merged org artifact), ASFF partition mapping, HTML self-containment all tested. **Note:** `e2e_pipeline_test.go` (Layer 3, §2) drives one deterministic scan through **every** writer — CBOM/ASFF/PQCC-Excel/roadmap/HTML — with structural + honesty + cross-artifact-consistency assertions, lifting the package from 46.9%; the reusable validators `cdx_schema_validate.go` / `asff_validate.go` / `pqcc_validate.go` and `crypto_graph_test.go` then added the per-package CBOM-conformance contract (§2). The remaining untested lines are the PDF/markdown serializers. |
| `internal/services/keymgmt` | **74.9%** | `███████████████` | I/O scanners | 9 key scanners. **Note:** was 0.8% (only the `kms_usage` helper). Every key scanner now has a `Scan()`-level fake-client test (Layer 1), `fuzz_invariant_test.go` adds the adversarial cores plus the `FuzzKMSSpecPosture` native fuzz target (Layer 3) — closing the former §7 P1 keymgmt-mapper gap — and the CBOM-conformance suite (§2). |
| `internal/services/datarest` | **72.5%** | `███████████████` | I/O scanners | 49 SDK at-rest scanners. **Note:** was 8.3%. All 49 scanners now have a `Scan()`-level fake-client test (Layer 1, the first harness wave — 33 datarest scanners) asserting pagination + error-propagation + posture, `fuzz_invariant_test.go` adds the adversarial at-rest cores (Layer 3), and the CBOM-conformance suite (§2) raised it further. |
| `cmd/knowledge-drift` | **70.3%** | `██████████████` | Logic | Enum-drift detector; tests no-drift, drift-on-change, judgment-fields-not-projected, report-only. |
| `internal/merge` | **63.4%** | `█████████████` | Logic | Org dedup + provenance ladder + streaming==batch + scale/memory; 29 tests (including the 9 in `merge_integrity_test.go`, §2/§4.4). The remaining lines are error/IO branches. |
| `internal/services` | **62.8%** | `█████████████` | Logic (shared helpers) | The shared `common.go` primitives: truncation cap, doc-fact stamping, ARN preservation, `MapConcurrent` order/bound/drop. |
| `internal/risk` | **45.5%** | `█████████` | Logic | Mosca `X+Y-Z`, severity-from-posture, severity-from-mosca all tested; **Note:** `severity_test.go:TestIsQuantumSafePosture` now pins the `IsQuantumSafePosture` predicate (`severity.go:42-49`) that gates the H1 Mosca-bump suppression. The *per-service defaults table* (`defaults.go`) is data, not exercised line-by-line. |
| `cmd/cryptamap` | **43.6%** | `█████████` | CLI / I/O | Lambda-event parsing, serve mux, purity guard, posture summarization tested; **Note:** `count_guard_test.go` asserts the `--help` banner derives its scanner count from the live registry (`registeredScannerCount()` → `reg.Len()`) and pins the total at **99**. The `runScan`/`writeArtifacts` live AWS lifecycle is still not exercised. |
| `internal/mock` | **14.2%** | `███` | Generator | **Note:** was 0.0%. `coverage_test.go` (`TestMockCoverageNoDrift` + orphan/well-formed guards) is the drift guard that fails the build if any registered scanner lacks a mock template — which is why the generator was extended to all **99** templates (§2). The bulk of the generator's lines (synthetic value generation) are still exercised end-to-end via `make mock`, not unit-asserted, hence the still-modest number. |
| `internal/probing` | **9.5%** | `██` | I/O | Only `isPQHybridGroup`/`kexGroupName` pure helpers tested; the active TLS prober is a dormant/optional feature. |
| `internal/config` | **0.0%** | ` ` | Declarative | Pure defaults + YAML/env loading; no test file. |
| `internal/org` | **0.0%** | ` ` | I/O | STS `AssumeRole`/`CallerIdentity` wrappers; pure SDK plumbing. |
| `pkg/models` | **0.0%** | ` ` | Declarative | Type/enum declarations + `BomRefForARN`; structs and constants, no behavior to test in isolation. |
| `cmd/gen-knowledge` | **0.0%** | ` ` | Codegen tool | Build-time generator; its *output* is what `internal/pqc` golden-tests assert. |
| `cmd/gen-ts` | **0.0%** | ` ` | Codegen tool | Build-time TS-type generator; *staleness* is gate-checked by `make check-types` (`Makefile`), not unit-tested. |

> Note: the only `FAIL` in a raw `go test ./...` is the vendored `cdk/node_modules/aws-cdk/.../%name%.template.go` Go template fixture — it is third-party node_modules, **outside** `GOPACKAGES`, and is not part of CryptaMap's own suite. `make test` never sees it.

---

## 4. What IS tested (the high-value core)

The correctness-critical, regulator-facing logic is well covered. The systemic, adversarial, and end-to-end layers (§2) sit on top of the per-package tests catalogued here. Concretely:

### 4.1 Purity guards (the air-gap / no-network invariant)
- `cmd/cryptamap/purity_test.go:TestPurityScanBinaryHasNoDocOracleDeps` — asserts the scan binary has **no** doc-oracle/network dependency baked in.
- `internal/pqc/purity_test.go:TestPurityKnowledgeSubsystemHasNoNetworkDeps` — the PQC knowledge subsystem is offline-only.

These guard the design invariant that the default scan path never leaves the account/network (cross-ref [10-SECURITY-AND-DATA-LOCALIZATION.md](10-SECURITY-AND-DATA-LOCALIZATION.md) and the deployment topology in [04-HIGH-LEVEL-DESIGN.md](04-HIGH-LEVEL-DESIGN.md)).

### 4.2 Classification helpers (the pure decision logic, extracted on purpose)
- **Transit:** `internal/services/transit/transit_classify_test.go` (6 tests) covers `classifyTransferPolicy`, `postureFromTransferKexs`, `classifyVPNTunnel`, `classifyMSKTransit`, `classifyOpenSearchTLSPolicy` — the SDK-free helpers shared across Transfer Family / VPN / MSK / OpenSearch readers (`internal/services/transit/transit_classify.go:23-260`).
- **SSL policy / `policyVersion`:** `internal/services/transit/ssl_policy_test.go` covers `isPQELBPolicyName` and PQ-by-name classification (the name→version/posture fallback that matters because the ELBv2 API does **not** enumerate ML-KEM groups; `internal/services/transit/ssl_policy.go:41-44,118-136`). CloudFront/APIGW PQ name-mapping is covered by `internal/services/transit/cloudfront_test.go` (`TestCloudFrontPosture`, `TestPolicyVersionPQ`, `TestApigwSecPolicyPQ`).
- **ACM cert resolver safety:** `internal/services/transit/acm_cert_test.go` — `isACMCertARN` and nil/non-ACM safety (IAM server-cert ARNs left blank, not errored).
- **Global Accelerator run-once gate:** `internal/services/transit/globalaccelerator_test.go` — the global-service single-run region gate.
- **Runtime evidence parsers:** `internal/services/runtime/cloudtrail_evidence_test.go` — `parseRuntimeAlgo`, `runtimePosture`, `chooseAlgo`, `parseTLSDetails` plus a `Scan()`-level test; the CBOM-conformance suite (§2) on the refactored `scan()` seam is what lifts `runtime` to 88.3%.
- **Datarest pure edges:** S3 `BucketRegion`/SSE-rule-error classification (`s3_test.go`), keyspaces system-name skip, qldb endpoint-unavailable graceful skip, documentdb-elastic always-on classify.
- **Keymgmt:** `kms_usage_test.go` — `isAWSManagedAlias` (case-sensitive) and the shared `kmsSpecPosture` consistency check. `kms_spec_test.go:TestKMSSpecKeyTierAndOrigin` pins the key-tier/origin surfacing (incl. the `EXTERNAL` imported-BYOK and `AWS_CLOUDHSM` origins that the live harness does **not** exercise).
- **Key-custody regressions (from the 2026-06 live pass, §6.1):** `internal/services/datarest/codebuild_test.go` adds the live-form ARN case — a default key returned as the fully-qualified `arn:…:alias/aws/s3` must classify `aws-managed-default`, not `customer-cmk` (regression for `isAWSManagedS3Key`); `internal/services/datarest/backup_test.go:TestBackupKeyTierResolution` pins `resolveBackupKeyTier` mapping `KeyMetadata.KeyManager` via `kms:DescribeKey` and staying `kms-key-custody-undetermined` on a DescribeKey failure.

### 4.3 Mosca / risk scoring
- `internal/risk/mosca_test.go` — `TestCalculate` (X+Y−Z), `TestSeverityFromMosca`, `TestSeverityFromPosture` (`internal/risk/severity.go:7-35`).
- **Note:** the severity model is no longer an *unconditional* "worse-of-two-signals". `internal/risk/severity_test.go:TestIsQuantumSafePosture` pins the new `IsQuantumSafePosture` predicate (`severity.go:42-49`): true for symmetric-only / pqc-hybrid / pqc-ready. `BuildFindings` now takes `SeverityFromPosture` and applies the Mosca/HNDL bump (`HighestSeverity` with `SeverityFromMosca`) **only when the posture is not quantum-safe** (`internal/scanner/findings.go:39-50`). The direct verification that a quantum-safe asset stays INFORMATIONAL while a vulnerable one keeps the worse-of lives in §4.8's `findings_test.go`, and the *systemic* version (the same law over every scanner) is invariant I3 in §2 / §4.9's `invariants_test.go`.

### 4.4 Merge (the org-scale dedup + provenance engine)
- 29 tests across `merge_test.go`, `merge_edge_test.go`, `streaming_test.go`, `scale_validation_test.go`, and `merge_integrity_test.go`: bom-ref dedup, the full source-precedence ladder, finding-union severity, summary recomputation, sentinels, multi-account provenance, **streaming == batch equivalence**, hierarchical == flat, a memory/scale profile, and the 9 `merge_integrity_test.go` no-loss / no-double-count contract tests (§2). This is the package most directly tied to the scale-hardening work (cross-ref [SCALING](../SCALING.md)).

### 4.5 Roadmap (scoring & ranking)
- 17 tests: score ordering, quick-win float-up, AES/PQC sink, AES-clamp-beats-rich-posture, rollups (by service / by account), deterministic tie-ordering, actionable-first, 3DES-never-N/A, empty scan.

### 4.6 Compliance mappers
- `internal/compliance/mapper_test.go` — all-9-frameworks present, enabled-filter, posture→status, SEBI flags no-encryption.

### 4.7 PQC knowledge + golden reproducibility
- `internal/pqc` (`pqc_test.go`, `strength_test.go`, `knowledge_golden_test.go`): matrix invariants, symmetric/primitive strength tables, asset-aware effective-PQC-status, and — critically — `TestEmbeddedKnowledgeMatchesLiterals` / `TestEmbeddedKnowledgeReproducesAllLookups` / `TestScannerDocFactsRoundTripThroughAccessor`, which prove the **baked-in baseline** equals the generated source. This underpins the self-updating-knowledge design (cross-ref [SELF-UPDATING-KNOWLEDGE](../SELF-UPDATING-KNOWLEDGE.md)).

### 4.8 Output + CLI seams
- `internal/output`: CBOM parse round-trip (incl. `resourceType` round-trip — the merge dedup depends on it), CycloneDX schema validation, friendly taxonomy props, no-mutation-on-sanitize, HTML self-containment + empty-scan.
  - **Note:** the CycloneDX schema validation was previously a *false green* — it only validated a synthetic shape and missed two live shapes that failed the official schema (a TLS protocol component carrying the non-schema `ProtocolProperties.Source` field, and a Lambda-style component with empty `CryptoProperties{}`). `cyclonedx_test.go` now deliberately includes both live shapes in `sampleScan` and adds `TestCycloneDXSchemaValidationMerged`, which merges two per-account shards and validates the **merged org artifact** against the schema too — so both the live single-scan and merged paths are now schema-covered, not just a hand-built sample.
  - **Note:** `securityhub_partition_test.go` covers the H6 partition fix — `TestPartitionForRegion` tables `us-gov-*`→`aws-us-gov`, `cn-*`→`aws-cn`, else `aws`, and `TestASFFPartitionFollowsRegion` asserts both partition-bearing ASFF fields (the resource `Partition` and the `ProductArn` prefix) track the finding's region, with commercial regions staying byte-for-byte `aws`.
- `internal/scanner`: **Note:** previously had no test file (exercised only indirectly). Now directly tested:
  - `findings_test.go` — `TestBuildFindings_QuantumSafePostureNotMoscaAlarmed` proves a quantum-SAFE posture on a CRITICAL-Mosca service (rds/dynamodb) stays INFORMATIONAL (the H1 fix; this fails on the old worse-of logic), and `TestBuildFindings_VulnerablePostureKeepsWorseOf` confirms no-encryption/legacy-tls/non-pqc-classical assets still get the worse-of severity. (The tests read only `Service` + `Properties["posture"]`, so they sidestep the volatile `ID`/`CreatedAt`/`UpdatedAt` fields noted in §7-P0.)
  - `registry_test.go` — three acceptance checks that were the E-4 gaps: (a) `TestScannerReadOnlyMiddleware`/`TestNonReadOperationDetected` assert the read-only contract via a Finalize-step middleware that fails on any non-read SDK verb (network-free, short-circuited); (b) `TestCoverageReconciliation` runs the full registry through the engine and asserts every registered scanner appears in the per-service report (`reg.Len()` stats); (c) `TestRegistryResolvesToTaxonomy` asserts every registered scanner resolves to a taxonomy `Entry` with `AWSCategory != "Other"` and a non-empty `CryptoFunction`, and that `taxonomy.All()` and the live registry are the same size.
- `cmd/cryptamap`: 16 Lambda-event tests (fan-out / single-account / malformed / region resolve / merge / merge-account / completion barrier / posture summarization), 4 serve tests (local-data contract, SPA fallback, `findLatest`, **no-bind-all flag** security guard), and the purity test.
  - **Note:** `count_guard_test.go` asserts the `--help` banner reports the live `registeredScannerCount()` (`TestBannerScannerCount`, which also fails if any of the stale `63`/`64`/`66 AWS services` literals leak back in) and pins the registry total at **99** (`TestRegisteredScannerCount`).

### 4.9 The systemic / adversarial / e2e layers (the new net — see §2)
These are the files behind the layered strategy; they are catalogued here so the per-file map stays current. The systemic/adversarial/e2e files below landed across the Scan()-wave (the fuzz cores), the scanner invariants, and the output e2e; the per-package **CBOM-conformance** files and the reusable validators landed alongside them. **All are CI-gated** (`.github/workflows/ci.yml` named steps "honesty invariants + e2e pipeline" and "fuzz security-critical parsers").
- `internal/scanner/invariants_test.go` (Layer 2) — 8 honesty-invariant tests (`TestInvariant_*`) iterating a fixed-seed large-scale mock through the real `BuildFindings` path **and** the live registry through `Engine.Run`; enforces laws I1–I5 (posture-in-enum, taxonomy-resolves-no-Other, quantum-safe-never-escalated/H1, no-encryption-has-note, unique-bom-refs), plus a posture-coverage meta-guard. Auto-covers any future scanner.
- `internal/services/{datarest,transit,certmgmt,keymgmt}/fuzz_invariant_test.go` (Layer 3) — adversarial property tests driving 23 scanner cores with four hostile fake-client shapes (list-error / describe-error / nil / empty), asserting no-panic, error-propagates-not-silent-success, and no-fabricated-verdict-on-failed-read; plus the two Go-native fuzz targets `FuzzParseCertPEM` (certmgmt) and `FuzzKMSSpecPosture` (keymgmt).
- `internal/output/e2e_pipeline_test.go` (Layer 3) — one deterministic mock scan through **every** output writer (`TestE2EPipeline_*`): CBOM schema-valid + no contradictory PQC claim, ASFF severity/ProductArn + summary reconciliation, PQCC formula-injection regression, roadmap count reconciliation, HTML self-contained + XSS-escaped, and a cross-artifact-consistency capstone.
- `internal/mock/coverage_test.go` (drift guard) — `TestMockCoverageNoDrift` fails the build if any registered scanner lacks a mock template (the reason the generator now has all 99 templates), plus `TestMockNoOrphanTemplates` / `TestMockTemplatesWellFormed`. `internal/mock/generator.go` now stamps a `note` on no-encryption mock assets so invariant I4 has honest data to assert.
- **CBOM-conformance suite** (§2), one set per `internal/services/*` package (`datarest`, `transit`, `certmgmt`, `keymgmt`, `sdkpqc`, `runtime`):
  - `cdx_conformance_test.go` (×6) — each scanner's real `scan()` output validated against the CycloneDX 1.7 schema via `output.ValidateAssetsCBOM`.
  - `cdx_enum_oracle_test.go` (×6) — iterates the AWS SDK `EnumType.Values()` (270+ values) as the authoritative input contract, asserting schema-valid CBOM for each.
  - `cdx_adversarial_test.go` (×6) — nil / empty / unknown-enum / oversize SDK responses → no panic + schema-valid output.
- **Reusable output validators / contract tests:** `internal/output/cdx_schema_validate.go` (`ValidateCBOMBytes` / `ValidateAssetsCBOM`), `internal/output/asff_validate.go` (Security Hub ASFF contract), `internal/output/pqcc_validate.go` (MITRE PQCC workbook contract), `internal/output/crypto_graph_test.go`, and `internal/merge/merge_integrity_test.go` (org-merge no-loss / no-double-count, the 9 tests that took `internal/merge` to 29).

---

## 5. Why the low numbers are low (and mostly fine)

### 5.1 The scanner packages — `datarest` 72.5%, `transit` 79.3%, `certmgmt` 78.1%, `keymgmt` 74.9%, `sdkpqc` 85.0%
These five dirs hold **98 of CryptaMap's 99** per-service scanners (datarest 49 + transit 27 + keymgmt 9 + certmgmt 10 + sdkpqc 3; the 99th is the single `runtime` CloudTrail-evidence scanner, broken out separately below). The 99 total is the count of `r.Register(...)` calls across `cmd/cryptamap/register.go` (23: certmgmt 10 + keymgmt 9 + sdkpqc 3 + runtime 1), `register_datarest.go` (49), and `register_transit.go` (27), and is matched by the files carrying a `Scan(ctx` method under `internal/services/`. The `--help` banner reports this true 99 (derived from `registeredScannerCount()` → `reg.Len()`, guarded by `cmd/cryptamap/count_guard_test.go`), and the count is locked by `internal/scanner/registry_test.go:TestCoverageReconciliation` + `internal/taxonomy/taxonomy_test.go:TestCount`.

**These numbers are no longer "low".** Until the 2026-06-16 harness work these dirs sat at ~1–12%, on the rationale that each scanner file is overwhelmingly `aws-sdk-go-v2` paginated `List*`/`Describe*` plumbing around a *small* classification decision, and that the plumbing could only be validated against live AWS. That rationale has been superseded: every scanner was refactored to a **testable client interface** and now has a `Scan()`-level fake-client test (Layer 1, §2) that drives the plumbing with a hand-rolled fake — proving pagination, error-propagation, and posture **in CI, without AWS**. That single change is what lifted the dirs out of single digits, and it is what **caught the App Mesh weakest-wins bug** that the harness and the per-helper tests had both missed; the later CBOM-conformance class (§2) then pushed the dirs into the **72–85% band**.

The pure-helper extraction (`transit_classify.go`/`ssl_policy.go`, the at-rest archetype classifiers, `kmsSpecPosture`/`acmPosture`, etc.) is still the right pattern for non-trivial logic and is still unit-tested directly, and the doc-fact anchoring (`StampDocFactKeyed` into `internal/pqc`, golden-tested in `internal/pqc/knowledge_golden_test.go`) is unchanged. What changed is that the *SDK-plumbing-to-classification round trip* is now a CI fake-client assertion first, with the live-fixture harness (§6) as confirmation rather than the sole net. The §1 caveat — "out-of-band, operator-run, not CI" — now applies only to the *posture-against-a-real-resource* check the harness still owns, not to the plumbing or the honesty contract, both of which are CI-gated (Layers 1–3).

The remaining uncovered lines in these dirs are predominantly the genuinely AWS-only branches (deep SDK marshalling, real-credential paths) plus the few scanners whose detail-read logic is not yet behind the fake-client seam — proportionate residue, not a correctness gap.

### 5.2 The declarative packages — `config` 0%, `pkg/models` 0%
- `internal/config` is `Default()` returning a struct literal plus YAML-unmarshal-onto-defaults and `${ENV}` expansion (`internal/config/loader.go:14-166`). It is data + a thin loader.
- `pkg/models` is type, enum, and struct declarations plus the one pure function `BomRefForARN` (`pkg/models/asset.go:14`). Constants and structs have no behavior to exercise in isolation; `NormalizedSeverity` and `BomRefForARN` are exercised transitively by risk/merge tests.

These zeros are appropriate — there is little independent behavior to assert. (The two extractable bits — `expandEnv` and `BomRefForARN` collision/determinism — are noted as cheap wins in §7.)

### 5.3 The engine + generators — `scanner` 89.5%, `mock` 14.2%, `gen-knowledge`/`gen-ts` 0%
- `internal/scanner` (engine, registry, `BuildFindings`, mock engine). Its pure output path `BuildFindings` is the shared spine reused by live, `--mock`, and offline `org-merge-files`. **Note:** the package was 0% with no test file; it now has `findings_test.go` (direct `BuildFindings` tables — the H1 fix), `registry_test.go` (read-only-middleware + coverage reconciliation + registry↔taxonomy), and `invariants_test.go` (Layer 2), which drives both a deterministic large-scale mock and the full `Engine.Run` over the live registry — lifting the package to 89.5% by exercising the goroutine-pool/finding-build path systemically. The thinnest remaining branches are the no-throttle-retry decision and the `PerServiceCap` truncation path (the invariant/reconciliation runs are single-attempt, `MaxRetries: 0`), tracked in §7-P0.
- `internal/mock` 14.2% (was 0%): `coverage_test.go` is now the **drift guard** that fails the build if any registered scanner lacks a template (§2, §4.9), which is why the generator carries all 99 templates and stamps a no-encryption `note`. The bulk of the generator's synthetic-value code is still exercised end-to-end via `make mock` rather than unit-asserted, hence the still-modest number.
- `cmd/gen-knowledge`/`cmd/gen-ts` are build-time codegen tools. Their correctness is enforced *downstream*: `gen-knowledge` output is asserted by `internal/pqc/knowledge_golden_test.go`; `gen-ts` staleness is gate-checked by `make check-types` (`Makefile` `check-types` target diffs `dashboard/src/types/generated.ts`).

### 5.4 The runtime / I/O wrappers — `org` 0%, `probing` 9.5%, `cmd/cryptamap` 43.6%, `output` 76.8%
- `internal/org` is STS `AssumeRole`/`CallerIdentity` plumbing — nothing to unit-test without AWS.
- `internal/probing` is the **dormant** active-TLS prober (the optional feature, currently parked); only its two pure helpers are tested, which is proportionate to a parked feature.
- `cmd/cryptamap` 43.6% (was 22.3%): the testable seams (event parsing, serve, purity, summary) are tested, and `count_guard_test.go` now also exercises the banner + `registeredScannerCount`/`registerAllScanners` path; `runScan`/`writeArtifacts`/`loadAWSConfig` still need live AWS or full artifact-writing fixtures.
- `internal/output` 76.8% (was 46.9%): the *readers* and schema validators were already tested (live-shape + merged-org CycloneDX 1.7 schema, ASFF GovCloud/China partition mapping); `e2e_pipeline_test.go` (Layer 3, §2/§4.9) then drove **every writer** — CBOM/ASFF/PQCC-Excel/roadmap/HTML — through one deterministic scan with structural + honesty + cross-artifact assertions, and the reusable `cdx_schema_validate.go` / `asff_validate.go` / `pqcc_validate.go` validators (§2) added the per-package CBOM-conformance contract — which together lifted the package to 76.8%. The remaining untested *writers* are the PDF/markdown serializers.

---

## 6. Layer 4 — internal live-validation (the other half of correctness)

The scanner packages are also validated outside the Go unit suite by an **internal, operator-supervised `create → scan → verify → teardown` loop**. It deploys real AWS resources via CloudFormation fixtures in a sandbox account, runs the scanner binary against them, verifies the emitted posture matches an oracle for the resource's known crypto state, then tears the resources down with **guaranteed teardown plus an honest orphan sweep** (the sweep cross-checks each tagged ARN against the owning service's real state, so lag-ghost ARNs are not false-alarmed as orphans). The manifest fixes the target environment (`ap-south-1` primary, `us-east-1` CloudFront leg), tags everything `cryptamap-run=cryptamap-live-val`, and enforces production-safety gates on every destructive `delete-stack`.

**Why this tier is not shipped in the public sample.** This harness and its fixtures are an **internal QA mechanism, not customer sample content**: it is operator-run testing tooling that creates real, billable, and sometimes *deliberately insecure* AWS resources to exercise the scanners (a weak-TLS endpoint, an unencrypted bucket, a legacy cipher) — exactly what a 1:many public sample repo must not hand a reader as ready-to-deploy CloudFormation. Per AWS's sample-code guidance, shipped samples should succinctly show *how to use the product*, not serve as a test rig. So the resource-provisioning fixtures live only in CryptaMap's internal source history and are **not** part of this public repository. What ships publicly is the validation *strategy* and its results — see [docs/VALIDATION.md](../VALIDATION.md), which documents Layers 1–3 (the CI-gated nets that *do* ship) and frames Layer 4 as this internal-only tier. (The Go unit tests, `*_test.go`, and the customer-facing `examples/ci-cd/` pipeline example both remain in the repo; only the live-validation harness was removed.)

**This is a distinct validation tier (Layer 4, §2) above unit/fuzz/invariant/e2e — it closes the input-fidelity gap mocks cannot.** Layers 1–3 prove the scanners are correct for the inputs the test author imagined; only a real AWS response proves the scanner parses the field shape AWS actually returns.

### 6.1 The 2026-06-17/18 live-validation pass
Run internally in a sandbox account (`ap-south-1` / `us-east-1` CloudFront leg, $0 billing after verified teardown; see [`CHANGELOG.md`](../../CHANGELOG.md)). It is the strongest evidence to date that this tier catches what CI cannot:

- **Two genuine scanner bugs found and fixed — both invisible to Layer-1 fake-client tests, surfaced only against live AWS.** Both were the same BFSI-critical class: a **false key-custody positive**, labeling the **AWS-managed default KMS key as a customer CMK** (which would mislead a regulated customer about who holds key custody).
  - **codebuild:** with no `EncryptionKey` set, AWS returns the AWS-managed default as the **fully-qualified ARN** `arn:…:alias/aws/s3`, but the scanner compared only the bare alias `alias/aws/s3` → mislabeled `customer-cmk`. Fixed `isAWSManagedS3Key()` to match the alias as an **ARN suffix** (`internal/services/datarest/codebuild.go:50`), plus a **live-form regression case** in `codebuild_test.go` (the "aws-managed default returned as fully-qualified ARN (live form)" row).
  - **backup:** the scanner recorded a raw key-id ARN with **no custody tier**. Now `resolveBackupKeyTier()` (`internal/services/datarest/backup.go:65`) calls `kms:DescribeKey` and maps `KeyMetadata.KeyManager` (`AWS` → `aws-managed-default`, `CUSTOMER` → `customer-cmk`); on a `DescribeKey` failure it **stays `kms-key-custody-undetermined`** — it never guesses. `kms:DescribeKey` was already in the scanner's read-only IAM policy. Pinned by `TestBackupKeyTierResolution` (`internal/services/datarest/backup_test.go:247`).
- **BYOK / customer-CMK detection proven live** (the `kms_byok` leg of the internal Layer-4 pass — see [`VALIDATION.md`](../VALIDATION.md)): a customer symmetric CMK and an RSA-3072 CMK classified correctly — `keyManager=CUSTOMER`, `origin=AWS_KMS`, the RSA key flagged non-pqc-classical (quantum-vulnerable) — and **contrasted against AWS-managed keys (`keyManager=AWS`) in the same scan**. The `EXTERNAL` (imported BYOK) and `AWS_CLOUDHSM` origins are **unit-tested** by `TestKMSSpecKeyTierAndOrigin` (`internal/services/keymgmt/kms_spec_test.go:179`), **not** live (no fixture stands up an imported/CloudHSM key).
- **27 wave-3 bucket-A scanners live-validated, 60/60 oracle rows passed** on the clean confirmation run: `alb`, `apigw_http`, `apigw_rest`, `appsync`, `backup`, `cloudwatchlogs`, `codebuild`, `container_images`, `ebs`, `ecs`, `efs`, `eventbridge`, `keyspaces`, `kinesis`, `lambda`, `lightsail`, `rolesanywhere`, `secrets_rotation`, `secretsmanager`, `ses_dkim`, `sns`, `sqs`, `ssm`, `stepfunctions`, `transferfamily`, `vpn`, `workspaces_web`. Plus the earlier fast fixtures (`s3` Jan-2023 default-SSE tripwire, `dynamodb` key-tier, `bedrock`) and the cluster scanners (`rds`/`aurora`/`msk`/`opensearch`/`elasticache`/`neptune`/`documentdb` and their `_transit` variants).
- **Deliberately NOT live-tested (unit-only, documented reasons):** `iotcore` (an IoT domain config cannot be deleted for 7 days → cannot auto-teardown); `fsx` (FSx-OpenZFS failed to reach AVAILABLE twice in `ap-south-1`, and a FAILED filesystem blocks `DeleteStack` — its unconditional AES-256-XTS posture is unit-covered); `connect_customer_profiles` (no CloudFormation resource type exists); and the bucket-B/C set (CloudHSM, Directory Service, amazonmq, etc.) — expensive / orphan-prone for ~zero incremental signal.

Historically this harness was the *primary* validation for the scanner dirs (which sat at ~0–12% Go coverage), confirming each classification against a live resource of known posture. **As of 2026-06-16 it is no longer the primary net** — the CI unit layers (§2) now carry pagination, error-propagation, the honesty contract, the output-pipeline shape, and (since 2026-06-19) per-package CBOM-conformance continuously and offline. The harness's remaining, irreplaceable job is the one thing CI genuinely cannot do: confirm the emitted posture against a *real AWS resource's real fields* — and the 2026-06 pass shows that job is not academic (two real bugs). Its limitations, kept honest:
- It is **manual** (operator drives each gate), not CI.
- It currently has authored (internal) `.cfn.yaml` fixtures for a subset of the 99 scanners (the wave-3 bucket-A set above plus the earlier fast/cluster fixtures). The fixture-less scanners are covered in CI by their Layer-1 `Scan()`-level fake-client tests for pagination/error/posture-against-fake-fields, plus doc-facts and the systemic invariants — so "no live fixture" does not mean "untested", it means "real-resource field validation is still open". (The 13 scanners promoted in the coverage-expansion fall in this bucket — their resource types were absent from the test org.)

So the systemic layers have **inverted the reliance**: the operator-run harness went from the load-bearing correctness net to a confirmation step for the real-field check. On top of that, the **contract and metadata** of all 99 scanners have a CI safety net (reinforced by the §2 systemic invariants): `internal/scanner/registry_test.go` and `invariants_test.go` assert in CI that every registered scanner (a) issues only read-only SDK operations under a guard middleware, (b) appears in the engine's per-service coverage report, (c) resolves to a real taxonomy `Entry` with no `Other` fallback, and (d) obeys the I1–I5 honesty laws through the engine path. A newly-added scanner can no longer silently ship without a category, leak an `Other` label, be omitted from the coverage report, fabricate a verdict on a failed read, or over-alarm a quantum-safe posture — all before anyone runs the live harness against it.

The gaps behind these postures are tracked in [COVERAGE-AND-GAPS](../COVERAGE-AND-GAPS.md).

---

## 7. Prioritized genuine test gaps

Ranked by correctness risk vs. cost-to-cover. "Risk" = likelihood a regression here silently corrupts a regulator-facing result.

| # | Gap | Risk | Cost | Why it matters |
|---|---|---|---|---|
| **P0 (partly resolved)** | `internal/scanner` engine retry / `PerServiceCap` truncation branches still undriven (`internal/scanner/engine.go:72-210`) | High | Med | **Note:** `registry_test.go:TestCoverageReconciliation` now drives the full registry through `Engine.Run` and asserts every scanner appears in the per-service report — the always-emit-a-report path and basic worker-pool fan-out are now exercised. **Remaining:** that test runs single-attempt (`MaxRetries: 0`), so the no-throttle-retry decision and the per-service-cap truncation branch still have no direct coverage; a table-driven test over a fake `ServiceScanner` returning throttle/overflow remains the cheap close. |
| **P0 (RESOLVED)** | ~~`BuildFindings` not directly tested~~ (`internal/scanner/findings.go:29-75`) | High | Low | **Note:** `findings_test.go` now directly tables `BuildFindings` — `TestBuildFindings_QuantumSafePostureNotMoscaAlarmed` locks the H1 fix (quantum-safe posture stays INFORMATIONAL despite a CRITICAL Mosca) and `TestBuildFindings_VulnerablePostureKeepsWorseOf` confirms vulnerable postures still take the worse-of. The tests read only `Service` + `Properties["posture"]`, so they sidestep the volatile `ID` (`uuid.NewString()`, `findings.go:56`) and `CreatedAt`/`UpdatedAt` (`time.Now().UTC()`, `findings.go:30,72-73`) fields. (Severity is **no longer** an unconditional worse-of — see §4.3; a future expansion could still assert the compliance-mapping attach across paths.) |
| **P1 (RESOLVED)** | ~~`certmgmt/parseCertPEM` untested~~ (`internal/services/certmgmt/certparse.go:41`) | Med-High | Low | **Note:** `certparse_test.go` table-tests the parser and `fuzz_invariant_test.go:FuzzParseCertPEM` fuzzes it (~1.8M execs locally, CI `-fuzztime=20s`) — arbitrary garbage bytes must not panic and must not fabricate a classical/PQC-safe verdict (the "Unknown unless classical confirmed" anti-false-safe rule is now adversarially enforced). |
| **P1 (RESOLVED)** | ~~`keymgmt` posture mappers beyond `kms_usage` — `kmsSpecPosture`, `payAlgoPosture`~~ (`kms_spec.go:36`, `payments.go:79`) | Med-High | Low | **Note:** `kms_spec_test.go` / `payments_test.go` table-test the mappers, and `FuzzKMSSpecPosture` fuzzes the key-spec→posture path against garbage. The dir is now 74.9% (was 0.8%). |
| **P1 (RESOLVED)** | ~~`certmgmt` posture mappers `acmPosture`/`acmpcaPosture`~~ (`acm.go:35`, `acmpca.go:38`) | Med | Low | **Note:** `acm_test.go` / `acmpca_test.go` cover these as part of the per-scanner `Scan()`-level wave. The dir is now 78.1% (was 9.7%). |
| **P2** | Datarest archetype classifiers (Type-A always-on, Type-B opt-in, Type-B not-retroactive S3/SQS) | Med | Med | The "absent KMS key ≠ no-encryption" and "dated-default is conditional, never a clean all-clear" rules are now exercised by the per-scanner `Scan()`-level tests + the adversarial at-rest cores, but much of the decision is still inline (not a named extracted helper), so a targeted regression for the dated-default conditionality would still harden it. |
| **P2** | `internal/config` `expandEnv` + `Apply` override merge (`loader.go:118-166`) | Med | Low | The known "PerServiceCap / MoscaOverrides / Verbose are accepted but not wired" footguns are exactly the kind of silent config-drop a test would catch. |
| **P2 (partly resolved)** | `internal/output` writers — PDF/markdown serializers | Med | Med | **Note:** the ASFF builder has partition assertions, `e2e_pipeline_test.go` drives the **PQCC Excel** writer (incl. the formula-injection regression), CBOM, ASFF, roadmap, and HTML through one deterministic scan, and the reusable `cdx_schema_validate.go` / `asff_validate.go` / `pqcc_validate.go` validators add the per-package CBOM-conformance contract. **Remaining:** the PDF and markdown serializers still have no dedicated golden assertion. (Package is 76.8% today, up from 46.9%.) |
| **P3 (partly resolved)** | `internal/mock` generator distribution + `enrichMockProtocolDetail` (`generator.go:147-300`) | Low | Low | **Note:** `coverage_test.go` now guards 100% scanner→template coverage + well-formed distributions, and the no-encryption `note` stamp is asserted transitively by invariant I4. **Remaining:** a direct test of the posture *distribution* and `enrichMockProtocolDetail` protocol-detail rules. |
| **P3** | `pkg/models.BomRefForARN` determinism/collision (`asset.go:14`) | Low | Low | It is the org-wide dedup key; invariant I5 now asserts uniqueness across ~12k mock assets, but a focused determinism + region-less-S3-ARN-invariant unit test is still nearly free. |
| **P3 (partly resolved)** | Expand the live-validation harness toward the full scanner set (real-resource field validation) | Low-Med | High | **Advanced by the 2026-06-17/18 pass (§6.1):** 27 wave-3 bucket-A scanners are now live-validated (60/60 oracle rows) on top of the earlier fast+cluster fixtures, and the pass caught two real key-custody bugs — proof the tier earns its cost. **Remaining:** the fixture-less scanners still lack real-resource field validation, and three (`iotcore`, `fsx`, `connect_customer_profiles`) are documented as **unit-only** with stated reasons (no auto-teardown / no AVAILABLE create / no CFN resource type). The "operator-run, not CI" caveat stays narrow — Layers 1–3 cover plumbing, honesty, and pipeline in CI for all 99 scanners. |

---

## 8. How to run and reproduce these numbers

```bash
# Project unit suite + per-package coverage (this is the source of the table above)
make test                 # => go test ./internal/... ./pkg/... ./cmd/... -cover

# Per-package profile (what produced the percentages here)
go test ./internal/... ./pkg/... ./cmd/... -coverprofile=cov.out

# The CI unit net, by name (mirrors the gated CI steps in .github/workflows/ci.yml)
go test ./internal/scanner/ -run 'Invariant|Honesty'   # Layer 2 — systemic honesty invariants
go test ./internal/output/  -run 'E2E|Pipeline'         # Layer 3 — end-to-end output pipeline
go test ./internal/mock/    -run 'Coverage'             # mock scanner->template drift guard
go test ./internal/services/... -run 'Conformance|EnumOracle|Adversarial'  # CBOM-conformance class (§2)

# Adversarial fuzz of the security-critical parsers (CI runs -fuzztime=20s each)
go test -run=XXX -fuzz=FuzzKMSSpecPosture -fuzztime=20s ./internal/services/keymgmt/
go test -run=XXX -fuzz=FuzzParseCertPEM   -fuzztime=20s ./internal/services/certmgmt/

# End-to-end mock scan (exercises internal/mock + internal/scanner + writers)
make mock                 # => cryptamap --mock --mock-scale 10 ...

# Codegen staleness gate (covers cmd/gen-ts correctness indirectly)
make check-types
```

> **Layer 4 (live-validation)** is *not* reproducible from this public repo: it is an internal, operator-supervised, real-AWS, destructive tier whose resource-creating fixtures are not shipped here (see §6 and [docs/VALIDATION.md](../VALIDATION.md)). Everything above (Layers 1–3) is the full CI-gated net and runs offline with no AWS resources.

> Running raw `go test ./...` from the repo root will report one unrelated `FAIL` for `cdk/node_modules/.../%name%.template.go` — that is a vendored aws-cdk Go *template* fixture, not CryptaMap code, and is excluded by `GOPACKAGES`. Use `make test` for the true signal.

---

## 9. Cross-links

- [COVERAGE-AND-GAPS](../COVERAGE-AND-GAPS.md) — scanner/service coverage gaps.
- [SELF-UPDATING-KNOWLEDGE](../SELF-UPDATING-KNOWLEDGE.md) — the knowledge baseline the `internal/pqc` golden tests lock down.
- [SCALING](../SCALING.md) — the org-scale work behind the `internal/merge` streaming/scale tests.
- [VALIDATION](../VALIDATION.md) — the full validation strategy: Layers 1–3 (ship + CI) and Layer 4 (internal-only live-validation; its resource-creating fixtures are not shipped in this public sample).
- [`CHANGELOG.md`](../../CHANGELOG.md) — the 2026-06-17/18 live-validation pass (Layer 4, §6.1): two live-caught key-custody bugs, BYOK proof, 60/60 wave-3 oracle rows, and the unit-only fallbacks.
