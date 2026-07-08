# Evaluating CryptaMap — a 30-minute path for a skeptical reviewer

**Audience:** a CISO, regulator, or security auditor who wants to know — from a fresh laptop —
**exactly what CryptaMap proves, what it does not, and which files are authoritative.** This page
synthesizes and links existing docs; it introduces no new claims. Where a claim matters, it points
to the code, test, or artifact that backs it.

> **One-line summary.** CryptaMap is an open-source (MIT-0) tool that discovers cryptographic
> assets across AWS and emits a schema-validated **CycloneDX 1.7 CBOM**. It is deliberately
> **honest over broad**: it admits what it cannot scan rather than emit a false all-clear. It is
> **source you build yourself** (no prebuilt/signed release) and runs **local-first** (loopback-only
> dashboard, no internet-facing surface).

---

## 1. What it proves (and does not)

**Proves:**
- A **CycloneDX 1.7-conformant CBOM** of discovered cryptographic assets, validated against the
  vendored CycloneDX 1.7 schema (`internal/output/cdx_schema_validate.go`; tests in
  `internal/output/cyclonedx_test.go`). CryptaMap-specific detail rides as `cryptamap:*` extension
  properties (the schema marks the native sub-objects `additionalProperties:false`) —
  see [`sdlc/06-DATA-FLOW.md`](sdlc/06-DATA-FLOW.md).
- Coverage across **99 scanners / 92 resource types / 78 AWS services** (pinned by
  `cmd/cryptamap/count_guard_test.go`; catalog in [`COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md)).
- **Posture per asset** on a six-tier maturity ladder (no-encryption, quantum-vulnerable,
  symmetric-only, pqc-hybrid, pqc-ready, unknown) — key-size-neutral (it never asserts a key length
  it did not observe).

**Does NOT prove / claim:**
- It is **not a regulator-specific CBOM standard.** The Indian-regulator control IDs are CryptaMap's
  own mapping labels (`CryptaMap→…`), and the PQC framing is national (CERT-In), **not** a
  per-regulator mandate — see the README compliance section and the **draft**-flagged
  compliance data in the dashboard.
- It does **not** claim complete AWS coverage. Deferred / cannot-scan-honestly / out-of-scope
  services are enumerated with reasons in [`COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md).
- It does **not** perform live Security Hub import in this release (local ASFF export only), and it
  holds **no write/modify/delete IAM on scanned customer resources** — the only writes are
  append-only evidence-store puts (`s3:PutObject`, `dynamodb:PutItem`) to the customer-owned bucket
  and table. See [`sdlc/10-SECURITY-AND-DATA-LOCALIZATION.md`](sdlc/10-SECURITY-AND-DATA-LOCALIZATION.md).
- India data-residency is **operator-controlled** (the CDK warns, and can fail-closed under a
  regulated profile — see backlog — but does not silently enforce a region).

## 2. The 30-minute evaluation path (no AWS account needed)

```sh
# Build (source-only; no prebuilt binary — see docs/INSTALL.md)
make build-cli

# 1. Generate a synthetic scan (no AWS calls)
./dist/cryptamap --mock --mock-scale 10 --output-dir ./out

# 2. Open the local dashboard (loopback only, 127.0.0.1)
./dist/cryptamap serve --dir ./out

# 3. Validate the CBOM against the CycloneDX 1.7 schema
CRYPTAMAP_REQUIRE_SCHEMA=1 go test ./internal/output/ -run CycloneDX -count=1

# 4. Run the guard tests that pin the honesty/coverage claims
go test ./internal/... ./pkg/... ./cmd/... -count=1
```

What to look at, in order: the **Overview** (posture ladder + the two honest callouts — no single
"% quantum-resistant" headline), the **Assets** inventory, the **Roadmap**, and the **draft**-labelled
compliance pages. Then read [`COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md) to see what is deliberately
not scanned and why.

## 3. Authoritative files (what to trust for what)

| Question | Authoritative source |
|---|---|
| What is covered / not covered | [`docs/COVERAGE-AND-GAPS.md`](COVERAGE-AND-GAPS.md) |
| CBOM format & field mapping | [`docs/sdlc/06-DATA-FLOW.md`](sdlc/06-DATA-FLOW.md) |
| Security & data-locality model | [`docs/sdlc/10-SECURITY-AND-DATA-LOCALIZATION.md`](sdlc/10-SECURITY-AND-DATA-LOCALIZATION.md) |
| Test coverage (honest, per-package) | [`docs/sdlc/09-TEST-COVERAGE.md`](sdlc/09-TEST-COVERAGE.md) |
| Build / install / no prebuilt binary | [`docs/INSTALL.md`](INSTALL.md), [`SECURITY.md`](../SECURITY.md) |
| Regulator crosswalk (with caveats) | [`docs/PQC-READINESS-CROSSWALK.md`](PQC-READINESS-CROSSWALK.md) + dashboard compliance pages (**draft**) |
| Common evaluation questions | [`docs/FAQ.md`](FAQ.md) |
| Scale envelope & limits | [`docs/SCALING.md`](SCALING.md) |
| Known limitations / future work | [§4 below](#4-known-limitations-v1) |

Deeper reading orders for engineers/auditors are in [`docs/sdlc/README.md`](sdlc/README.md).

## 4. Known limitations (v1)

- **Source-only distribution:** no maintainer-signed release; an air-gapped operator signs the build
  with their own key (see [`docs/INSTALL.md`](INSTALL.md) and `examples/airgap/`).
- **Compliance mappings are draft** and clearly labelled as such in the UI; treat them as a starting
  point, not validated legal guidance.
- **Large-org scale** has a documented memory envelope ([`SCALING.md`](SCALING.md)); very large orgs
  (100s of accounts) are a defined future workstream.
- Planned future work (tracked by the maintainers, not committed scope) includes typed evidence
  fields, an enforceable regulated deploy profile, signed evidence manifests, external
  CycloneDX-consumer testing, and a maintained regulator evidence map.
