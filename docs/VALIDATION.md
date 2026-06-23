# Validation & Test Strategy

> **Audience & purpose:** Engineers, reviewers, and auditors who want an honest
> picture of *how CryptaMap's scanners are validated* — what runs in this public
> repository's CI, and what is deliberately validated out-of-band and kept internal.
> This is a prose companion to [`sdlc/09-TEST-COVERAGE.md`](sdlc/09-TEST-COVERAGE.md)
> (the per-package coverage numbers) and [`COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md)
> (what is and isn't scanned). It is not a coverage badge.

CryptaMap's correctness rests on four layers. The first three **ship in this repo and
run in CI** — they are plain Go tests that create no AWS resources. The fourth is an
operator-supervised pass against *real* AWS resources; its resource-creating
CloudFormation fixtures are **deliberately not part of this public sample** (see
[§3](#3-the-fourth-layer-live-validation-not-shipped)). This document explains why,
and records what the fourth layer has actually proven.

## Table of contents

1. [What ships and runs in CI (Layers 1–3)](#1-what-ships-and-runs-in-ci-layers-13)
2. [What the in-repo tests cover](#2-what-the-in-repo-tests-cover)
3. [The fourth layer: live validation (not shipped)](#3-the-fourth-layer-live-validation-not-shipped)
4. [What the 2026-06 live-validation pass proved](#4-what-the-2026-06-live-validation-pass-proved)
5. [Live-validation coverage register](#5-live-validation-coverage-register)
6. [Running the tests yourself](#6-running-the-tests-yourself)

---

## 1. What ships and runs in CI (Layers 1–3)

Layers 1–3 are ordinary `*_test.go` files in this repository. They run with
`go test ./...`, are gated in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml),
and **create no AWS resources** — every input is a hand-rolled fake client or a
deterministic in-process mock. They cover all 99 scanners' plumbing, the honesty
contract, and the full output pipeline.

### Layer 1 — Per-scanner fake-client tests
Each scanner was refactored to a small testable client interface, and a hand-rolled
fake drives its `Scan()` core. These tests assert the three things SDK plumbing gets
wrong: **pagination** (the `NextToken`/marker loop actually iterates),
**error-propagation-not-silent-drop** (a `List*`/`Describe*` error surfaces as a
visibly incomplete scan, never a clean empty success), and the per-scanner **honesty
posture** (the right verdict for the resource's known crypto state). There is one
`_test.go` per scanner under
`internal/services/{datarest,transit,certmgmt,keymgmt,sdkpqc,runtime}`.

### Layer 2 — Systemic honesty-invariant tests
`internal/scanner/invariants_test.go` enforces the honesty contract as **laws over
all data**, not per scanner. It drives a deterministic, fixed-seed mock at large scale
through the real `BuildFindings` path *and* iterates the **live registry** through the
full `Engine.Run`. The laws are loop-driven, so scanner names are never hardcoded and
**a scanner added tomorrow is covered automatically**: every posture is in the valid
enum, every service resolves to a real taxonomy entry (no `Other` fallback), a
quantum-safe posture is never escalated by a Mosca/HNDL bump (and a vulnerable one
never drops below its floor), every `no-encryption` asset carries an explanatory note,
and BOM-refs are unique.

### Layer 3 — Adversarial fuzz + end-to-end output pipeline
- **Adversarial property tests** (`internal/services/{datarest,transit,certmgmt,keymgmt}/fuzz_invariant_test.go`)
  throw hostile fake-client shapes — top-level list error, per-resource describe
  error, nil/empty output, empty page — at a cross-section of scanner cores and assert
  **no panic**, **error-propagates-not-silent-success**, and **no fabricated verdict on
  a failed read**.
- **Go-native fuzz targets** back-stop the security-critical parsers: `FuzzParseCertPEM`
  (`internal/services/certmgmt`) and `FuzzKMSSpecPosture` (`internal/services/keymgmt`)
  — arbitrary garbage must not panic and must not fabricate a PQC-safe verdict.
- **True end-to-end pipeline** (`internal/output/e2e_pipeline_test.go`): one
  deterministic mock scan flows through **every** output writer, asserting each
  artifact is both structurally valid and honesty-consistent — CBOM validates against
  the CycloneDX 1.7 schema, ASFF severities reconcile with the summary, the PQCC Excel
  formula-injection regression holds, the HTML report is self-contained, and a
  cross-artifact check proves CBOM/ASFF/HTML agree on inventory and finding counts.

A **drift guard** (`internal/mock/coverage_test.go`) fails the build if any registered
scanner lacks a mock template, which is what makes Layers 2 and 3 trustworthy: they
cannot silently skip a service.

These layers prove the scanners are correct **for the inputs the test author
imagined** — pagination, error handling, classification, honesty, and the output
shape. They cannot prove that a real AWS API returns the field shape the scanner
parses; that is the job of Layer 4.

---

## 2. What the in-repo tests cover

Two further things in this repository are **part of the shipped sample** and should
not be confused with the removed live-validation harness:

- **The Go unit tests** (`*_test.go`, everywhere under `internal/`, `pkg/`, `cmd/`) —
  in-process, no AWS calls, no credentials. They are Layers 1–3 above plus the
  pure-logic tests (classification helpers, Mosca/risk scoring, merge/dedup, compliance
  mappers, the PQC knowledge golden tests). Run them with `go test ./...` or
  `make test`. Per-package coverage and the rationale for every number are in
  [`sdlc/09-TEST-COVERAGE.md`](sdlc/09-TEST-COVERAGE.md).
- **[`examples/ci-cd/`](../examples/ci-cd/)** — a genuine customer-facing example of
  wiring CryptaMap into a CI/CD pipeline (run a scan, emit a CBOM/QBOM, gate on it).
  This is sample content for customers and **remains in the repo**.

---

## 3. The fourth layer: live validation (not shipped)

The input-fidelity gap that Layers 1–3 leave open is closed by a fourth layer that
sits deliberately *above* CI: an operator-supervised **create → scan → verify →
teardown** pass against real AWS resources.

How it works, in prose:

1. **Create** real AWS resources of *known* crypto state — including some
   intentionally-insecure ones (e.g. a bucket relying on a dated default, a classical
   RSA key) so the scanners' *detection* path is exercised, not just their happy path.
2. **Scan** them with the real CryptaMap binary.
3. **Verify** the emitted posture matches an oracle for each resource's known state.
4. **Teardown** every resource, then run an honest orphan sweep that cross-checks each
   tagged ARN against the owning service's real state (so lag-ghost ARNs are not
   false-alarmed as orphans).

The pass runs in an **internal sandbox account**, with `ap-south-1` as the primary
region and `us-east-1` for the CloudFront leg (CloudFront is a global service fronted
there). Everything is tagged for the run, teardown is guaranteed, and production-safety
gates guard every destructive delete.

### Why the harness is not in this public sample

The resource-creating CloudFormation fixtures and the run script that drives this pass
are **kept internal and are not part of this public repository**, for two concrete
reasons:

- **They create billable resources.** This is an operator-run QA mechanism that stands
  up and tears down real infrastructure — that is internal testing tooling, not
  customer sample content. AWS's guidance for posting sample code is that it should
  succinctly show customers *how to use a product* — it is not a tool, a CI/CD rig, or
  a test harness.
- **Several fixtures are intentionally insecure.** They deliberately create resources
  in a weak crypto state so the scanners have something to detect. Shipping
  intentionally-insecure, deployable CloudFormation to a 1-to-many public repository is
  a footgun: a reader could deploy it verbatim and stand up insecure infrastructure.

So this layer is described here, and its *results* are recorded below, but its
deployable fixtures are not shipped. The harness continues to live in CryptaMap's
internal source history; the value it provides — reproducibility and breadth of
real-resource validation — is preserved in prose by this document.

---

## 4. What the 2026-06 live-validation pass proved

The most recent live-validation pass (2026-06) is the concrete evidence that this tier
earns its place. It **caught two genuine scanner bugs that every Layer-1 fake-client
test had passed** — both the same BFSI-critical class of error: a false key-custody
positive that labeled the **AWS-managed default KMS key as a customer-managed CMK**,
which would mislead a regulated customer about who actually holds key custody. (See
[`CHANGELOG.md`](../CHANGELOG.md).)

- **codebuild** — with no encryption key set, AWS returns the AWS-managed default as a
  **fully-qualified ARN** (`arn:…:alias/aws/s3`), but the scanner compared only the
  bare alias and mislabeled it `customer-cmk`. Fixed to match the alias as an ARN
  suffix, with a live-form regression case added to the unit tests.
- **backup** — vault keys returned as an opaque key-id ARN carried no custody tier.
  The scanner now resolves the tier via `kms:DescribeKey` (`KeyManager`:
  `AWS` → `aws-managed-default`, `CUSTOMER` → `customer-cmk`), and on a `DescribeKey`
  failure it stays honestly `kms-key-custody-undetermined` rather than guessing.

Both bugs were invisible to the fake-client tests because a fake returns exactly the
field shape the test author imagined; only a real AWS response exposed the mismatch.
The same pass also proved **BYOK / customer-CMK detection live** (a customer symmetric
CMK and an RSA-3072 CMK classified correctly, the RSA key flagged quantum-vulnerable,
contrasted against AWS-managed keys in the same scan).

---

## 5. Live-validation coverage register

The 2026-06 pass live-validated the following services (create → scan → verify →
teardown against real resources). This list documents the **breadth** of the tier; it
is not a coverage claim — a scanner is "covered" whether or not it has been
live-proven (see [`COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md)).

| Category | Services live-validated |
|---|---|
| **Data at rest** | `athena`, `backup`, `bedrock`, `cloudwatchlogs`, `container_images`, `dax`, `documentdb`, `dynamodb`, `ebs`, `efs`, `elasticache`, `emr`, `emr_serverless`, `eventbridge`, `firehose`, `keyspaces`, `kinesis`, `lambda`, `lightsail`, `neptune`, `opensearch`, `opensearch_serverless`, `redshiftserverless`, `s3`, `secretsmanager`, `secrets_rotation`, `ssm`, `stepfunctions` |
| **Data in transit** | `alb`, `apigw_http`, `apigw_rest`, `appsync`, `aurora_transit`, `classicelb`, `clientvpn`, `cloudfront_keygroups`, `ecs`, `msk`, `networking`, `rds`, `transferfamily`, `vpclattice`, `vpn`, `workspaces_web` |
| **Key & secret management** | `cognito`, `ec2keypairs`, `kms_byok` |
| **Certificates & signing** | `rolesanywhere`, `ses_dkim`, `signer` |

That is **55** validated service identifiers in total. (Some appear in more than one
crypto dimension; they are listed once, in their primary dimension.)

### Unit-validated only (with reasons)

Three services are validated by unit tests only — they could not be put through the
live create → scan → verify → teardown loop, for the documented reasons below:

| Service | Why no live fixture | Posture coverage |
|---|---|---|
| **iotcore** | An IoT domain configuration **cannot be deleted for 7 days**, so the harness cannot auto-tear it down. | unit-tested |
| **fsx** | FSx-OpenZFS **failed to reach `AVAILABLE`** on create twice in `ap-south-1`, and a `FAILED` filesystem **blocks `DeleteStack`** (no clean teardown path). Its unconditional AES-256-XTS posture is unit-covered. | unit-tested |
| **connect_customer_profiles** | **No CloudFormation resource type** exists for `AWS::CustomerProfiles`, so there is no fixture to create. | unit-tested |

> "Not live-validated" does **not** mean "not tested." Every service above is covered
> in CI by its Layer-1 fake-client test plus the systemic invariants — only the
> real-resource field check is unavailable for these three.

---

## 6. Running the tests yourself

Everything in this section runs locally with no AWS account and no credentials.

```bash
# Full unit suite + per-package coverage (Layers 1–3 are plain _test.go files)
make test                 # => go test ./internal/... ./pkg/... ./cmd/... -cover

# The systemic / e2e net, by name (mirrors the gated CI steps)
go test ./internal/scanner/ -run 'Invariant|Honesty'   # Layer 2 — honesty invariants
go test ./internal/output/  -run 'E2E|Pipeline'         # Layer 3 — end-to-end pipeline
go test ./internal/mock/    -run 'Coverage'             # mock scanner->template drift guard

# Adversarial fuzz of the security-critical parsers (CI runs -fuzztime=20s each)
go test -run=XXX -fuzz=FuzzKMSSpecPosture -fuzztime=20s ./internal/services/keymgmt/
go test -run=XXX -fuzz=FuzzParseCertPEM   -fuzztime=20s ./internal/services/certmgmt/

# End-to-end mock scan (no AWS): exercises internal/mock + internal/scanner + writers
make mock
```

The fourth layer (live validation) is intentionally not runnable from this repository
— its resource-creating fixtures are kept internal for the reasons in
[§3](#3-the-fourth-layer-live-validation-not-shipped).

---

## Cross-links

- [`sdlc/09-TEST-COVERAGE.md`](sdlc/09-TEST-COVERAGE.md) — per-package coverage numbers and the rationale for each.
- [`COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md) — what CryptaMap scans, what it doesn't, and why.
- [`../CHANGELOG.md`](../CHANGELOG.md) — the 2026-06 key-custody fixes the live pass surfaced.
- [`../examples/ci-cd/`](../examples/ci-cd/) — the shipped, customer-facing CI/CD pipeline example.
