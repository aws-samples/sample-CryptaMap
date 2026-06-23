# Continuous QBOM — CI/CD reference pipeline

This directory holds **customer-adaptable reference samples** for running
CryptaMap as a **continuous QBOM** (Quantum Bill of Materials) gate in CI/CD —
the CERT-In CIWP "continuous QBOM" requirement read literally:

> on every pipeline run, regenerate the cryptographic bill of materials, sign
> and date it, and **fail the build if the run introduces a new critical
> post-quantum finding** versus an accepted baseline.

These files are **examples, not this repository's own pipeline** — copy them
into your application repo and adapt the role ARN, regions, and baseline path.

| File | What it is |
| ---- | ---------- |
| [`github-actions-qbom.yml`](./github-actions-qbom.yml) | GitHub Actions workflow (OIDC role → scan → cosign-sign → ASFF diff gate). |
| [`gitlab-ci-qbom.yml`](./gitlab-ci-qbom.yml) | GitLab CI equivalent (OIDC ID token → scan → cosign-sign → ASFF diff gate). |
| [`qbom-pipeline.sh`](./qbom-pipeline.sh) | Portable shell version for any CI (or local) using `awscli` + the `cryptamap` binary. |
| [`baseline-diff.go`](./baseline-diff.go) | Tiny stdlib-only Go helper: compares two ASFF files and exits non-zero on a **new** critical. |
| [`baseline.asff.json`](./baseline.asff.json) | The committed accepted-critical baseline (ships empty; seed it — see below). |

## The pattern

Each run performs the same five steps; the CI workflows and the shell script are
three renderings of the same flow:

1. **Assume a read-only AWS role via OIDC.** No long-lived keys in CI. The role
   only needs `Describe*`/`List*`/`Get*` (and optionally
   `securityhub:BatchImportFindings`). CryptaMap never mutates resources.
2. **Run `cryptamap`** against the caller account (see the repo's
   [run-a-scan instructions](../../README.md#path-2--single-account-live-scan)).
3. **Emit a dated CBOM + ASFF.** CryptaMap writes
   `cryptamap-scan-<account>-<region>-<UTC-timestamp>.cbom.json` and the matching
   `.asff.json`; the `<UTC-timestamp>` is the "dated" part of the dated CBOM.
4. **Sign the dated CBOM** (cosign keyless, or minisign — see below).
5. **Diff the run's critical set vs the committed baseline** and **fail the
   build on a new critical**.

### Why the diff runs on ASFF, not the CBOM body

The CycloneDX CBOM lists cryptographic-asset components but **carries no
severity** — severity lives on CryptaMap _findings_, which are emitted as the
sibling **ASFF** file (`*.asff.json`, each record carrying `Severity.Label`).
The ASFF is derived from the same scan, so it is the canonical
"critical set" artifact a Security-Hub-shaped gate diffs.

### Stable identity (why re-scans don't false-fail)

CryptaMap's ASFF `Id` field embeds a **per-run UUID**, and `CreatedAt`/`UpdatedAt`
change every run. Diffing on those would flag every finding as "new" on every
run. The helper therefore keys each critical on the **stable tuple**:

```
AwsAccountId | Resources[0].Id (resource ARN) | Title
```

The resource ARN is a deterministic identity and the `Title` is deterministically
derived from service + posture + resource name, so the same unresolved critical
re-appears under the same key and does **not** re-fail the build — only a
genuinely new critical does.

## Signing the dated CBOM

Sign the **dated CBOM file** so auditors can verify exactly which bill of
materials was produced on which date.

**cosign (keyless / Sigstore, recommended in CI):** the OIDC identity that the
pipeline already holds signs the blob; no key management.

```bash
COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
  --output-signature  cryptamap-…-<date>.cbom.json.sig \
  --output-certificate cryptamap-…-<date>.cbom.json.pem \
  cryptamap-…-<date>.cbom.json

# verify later (auditor side):
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
  --signature   cryptamap-…-<date>.cbom.json.sig \
  --certificate cryptamap-…-<date>.cbom.json.pem \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*' \
  cryptamap-…-<date>.cbom.json
```

**minisign (air-gapped / no Sigstore):** for the local-artifact-first /
air-gapped deployment mode, sign with a minisign keypair you control.

```bash
minisign -G                               # one-time: generate a keypair
minisign -S -m cryptamap-…-<date>.cbom.json   # sign  → .minisig
minisign -V -m cryptamap-…-<date>.cbom.json   # verify (with the public key)
```

Both the GitHub Actions and GitLab samples sign with cosign by default; the
portable `qbom-pipeline.sh` signs only when `COSIGN_ENABLED=1` or `MINISIGN_KEY`
is set, and otherwise logs that signing was skipped.

## Seeding the baseline

The gate fails on criticals **not already in** `baseline.asff.json`. On a brand
new repo there are no accepted criticals, so the shipped baseline is `[]` (every
critical is new and the build fails until you triage). To accept the current
critical set as your starting point, seed the baseline from one clean run:

```bash
make build-cli
./dist/cryptamap --regions ap-south-1 --output-dir ./dist/qbom-output --verbose

# adopt this run's ASFF as the accepted baseline, then commit it:
cp "$(ls -1t ./dist/qbom-output/*.asff.json | head -n1)" examples/ci-cd/baseline.asff.json
git add examples/ci-cd/baseline.asff.json
git commit -m "Seed continuous-QBOM baseline"
```

## Updating the baseline (accepting a new critical)

When a new critical is genuinely accepted (risk-accepted, or scheduled for a
later migration wave), re-seed the baseline the same way — copy the latest
`.asff.json` over `baseline.asff.json` and commit it. Treat that commit as the
**audit record of an accepted exception**: it should be reviewed like any other
change, since it is what lets a critical through the gate.

To keep the baseline tidy, you can reduce it to just the critical records before
committing:

```bash
jq '[.[] | select(.Severity.Label=="CRITICAL")]' \
  "$(ls -1t ./dist/qbom-output/*.asff.json | head -n1)" \
  > examples/ci-cd/baseline.asff.json
```

## Running the diff helper directly

```bash
go run ./examples/ci-cd/baseline-diff.go \
  -baseline examples/ci-cd/baseline.asff.json \
  -current  ./dist/qbom-output/<run>.asff.json
# exit 0 = no new criticals (pass); 1 = new critical (fail); 2 = usage/IO error.
```

Or run the whole pipeline locally (uses your `AWS_PROFILE`, read-only):

```bash
AWS_PROFILE=my-readonly examples/ci-cd/qbom-pipeline.sh
```

## Safety

Every AWS call in these samples is **read-only** (`sts` assume-role /
get-caller-identity and CryptaMap's own `Describe*`/`List*`/`Get*` APIs). Nothing
is created, modified, or deleted. The OIDC role you attach should be least-
privilege read-only; do not grant it write permissions to satisfy the pipeline.
