# Changelog

All notable, user-facing changes to CryptaMap. This file consolidates what were
previously several dated working documents; internal point-in-time review/QA notes
have been retired in favor of this single record (their durable conclusions live in
the code and in [`docs/COVERAGE-AND-GAPS.md`](docs/COVERAGE-AND-GAPS.md)).

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Security / hygiene (public-release readiness)
- Removed all real-AWS-account data from the repo. The dashboard demo data is now
  generated **synthetically** by `cmd/gen-dashboard-mock` (a synthetic Indian-BFSI
  org — 11 generic-role accounts × 2 regions, full posture spread, all scanners
  represented, deterministic, compliance mappings produced only by the real
  `internal/compliance` mapper). It replaces the previous `refresh-dashboard-mock.sh`,
  which read a real org scan.
- Scrubbed a real account ID from a unit test; removed a committed throwaway TLS
  private key from the ALB live-validation fixture (it was reworked to take the key
  as a deploy-time stack parameter). That fixture has since been removed from the
  public sample altogether along with the rest of the live-validation harness — see
  "Repository structure" below and [`docs/VALIDATION.md`](docs/VALIDATION.md).
- Added a CI guard that fails the build on any committed real AWS account ID, ARN,
  bucket name, `/Users/...` path, or private-key block.
- CycloneDX CBOM property output is now emitted in deterministic (sorted) order, so
  two scans diff cleanly and the committed demo artifact is byte-verifiable.

### Repository structure
- Renamed `tests/` → `testdata/` (Go-idiomatic), removing the `test/` vs `tests/`
  ambiguity.
- **Removed the live-validation harness and its CloudFormation fixtures from the
  public sample** (they had briefly lived under `test/live-validation/` and then
  `examples/live-validation/`). This is the operator-run, resource-provisioning QA
  rig — it creates real, billable, sometimes-deliberately-insecure AWS resources to
  validate scanners end-to-end (create → scan → verify → teardown). Per the
  aws-samples ["Posting Sample Code"](https://aws.amazon.com/code/) guidance, sample
  code should succinctly show customers how to use the product — it is not a test rig
  or CI/CD tooling — and shipping intentionally-insecure CloudFormation to a public
  1:many repo is a footgun. The harness is retained in internal history only. The
  in-process Go unit tests (`*_test.go`, which create no AWS resources) and the
  customer-facing `examples/ci-cd/` pipeline example **remain in the repo**. See
  [`docs/VALIDATION.md`](docs/VALIDATION.md) for the full strategy: Layers 1–3 ship
  and run in CI; Layer 4 (live validation) is internal-only.
- Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.

### Scanner correctness (key-custody)
- **codebuild**: the AWS-managed default KMS key, returned by the API as a
  fully-qualified ARN, was mislabeled as a customer-managed CMK. Now matched as an
  ARN suffix → correct `aws-managed-default` tier.
- **backup**: vault encryption keys given as an opaque key-id ARN are now resolved
  via `kms:DescribeKey` (`KeyManager`) to a definitive `aws-managed-default` /
  `customer-cmk` tier, staying honestly `kms-key-custody-undetermined` only when the
  key cannot be resolved (never guessing custody).
- Both validated against live AWS resources.

## Earlier (June 2026 hardening, pre-public-release)

These changes landed during internal review rounds (cross-validation review and a
comprehensive code review of ~100 findings). Highlights:

- **Severity reclassification (correction, not new risk):** quantum-resistant AES-256
  assets are no longer over-alarmed as Critical/High. The drop in Critical/High
  counts reflects removing over-counted safe assets, not hidden risk — severity is
  gated on `risk.IsQuantumResistantPosture`.
- API-pagination and error-propagation fixes so a denied/throttled scan is VISIBLY
  incomplete rather than a silent empty success.
- CycloneDX CBOM made schema-valid for both single and merged (org) output.
- All ~20 previously-"Other" scanners categorized in the taxonomy.
- Management/org IAM hardened: PrincipalOrgID + ExternalId required; org deploy
  fails closed on placeholder org IDs; ASFF partition-aware (GovCloud/China).
- Custom least-privilege scanner IAM policy (read actions + 3 resource-scoped
  writes) generated from a single source by `cmd/gen-policy`, CI-guarded against
  drift.
- Compliance honest-rebuild: regulator mappings are produced by the
  `internal/compliance` mapper from real framework definitions, with advisory-vs-
  mandate tiers disclosed. (Hand-authored/unsourced control IDs were removed during
  this rebuild.)
