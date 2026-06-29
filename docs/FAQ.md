# CryptaMap — Frequently Asked Questions

This FAQ answers the questions teams ask most often when evaluating and running
CryptaMap. It is grounded in the shipped code and docs; where an answer points to a
deeper reference, the link is given.

> **One-line framing.** CryptaMap is a read-only, config-plane tool that *inventories*
> your AWS cryptographic posture and *prioritizes* a post-quantum migration roadmap
> from configuration evidence. It does not certify protection, and it does not change
> any of your resources.

**Contents**

1. [What CryptaMap is & what it produces](#1-what-cryptamap-is--what-it-produces)
2. [What it scans & what it deliberately does not scan](#2-what-it-scans--what-it-deliberately-does-not-scan)
3. [Is it safe, read-only, and where does my data go?](#3-is-it-safe-read-only-and-where-does-my-data-go)
4. [How do I run it? (three paths + offline merge)](#4-how-do-i-run-it-three-paths--offline-merge)
5. [Installation, build & getting started](#5-installation-build--getting-started)
6. [Cross-account trust & deployment topology](#6-cross-account-trust--deployment-topology)
7. [Reading the results — KPIs, severity & Mosca's Theorem](#7-reading-the-results--kpis-severity--moscas-theorem)
8. [Accuracy, validation & limitations](#8-accuracy-validation--limitations)
9. [Outputs & how to use them](#9-outputs--how-to-use-them)
10. [Compliance mapping & the AWS Config PQC-Readiness crosswalk](#10-compliance-mapping--the-aws-config-pqc-readiness-crosswalk)
11. [Data residency, retention & AWS cost](#11-data-residency-retention--aws-cost)
12. [Operations, teardown, partitions & offline use](#12-operations-teardown-partitions--offline-use)
13. [License, support, contributing & reporting](#13-license-support-contributing--reporting)

---

## 1. What CryptaMap is & what it produces

**What is CryptaMap?**
An open-source (MIT-0) tool that discovers cryptographic assets across **99 AWS
service scanners**, merges every scanned account/region into one organization-wide
inventory, and produces a **CycloneDX 1.7 CBOM** plus a **prioritized post-quantum
(PQC) migration roadmap**. It inventories cryptographic posture from configuration
evidence; it does not certify protection.

**What outputs does it produce?**
A CycloneDX 1.7 CBOM (`*.cbom.json`); a PQC migration roadmap (`*.roadmap.json` and
`.md`) where each item carries a verified AWS action and a source-URL citation; a
MITRE PQCC Inventory Workbook (Excel); AWS Security Hub ASFF findings; a coverage
matrix (org-merge runs); a raw scan dump; and a Markdown summary. See
[Outputs](#9-outputs--how-to-use-them).

**Who is it calibrated for?**
v1 is calibrated for Indian BFSI regulators (SEBI CSCRF, RBI, IRDAI ICSG) under the
national CERT-In CIWP-2025-0002 quantum-readiness umbrella, but it is usable by any
organization preparing for the post-quantum transition.

**What is a CBOM, and what standard does CryptaMap follow?**
A CBOM (Cryptography Bill of Materials) is an inventory of cryptographic assets.
CryptaMap emits **CycloneDX 1.7**: each scanned resource becomes a component of type
`cryptographic-asset` with a stable `bom-ref`, a `cryptoProperties` block, and
`cryptamap:*` properties for account, region, ARN, and posture. See
[What a finding looks like](#what-does-a-finding-look-like).

**Is the PQC support data it ranks against trustworthy?**
Yes. The PQC support matrix is web-verified against live AWS documentation, and each
row carries a source URL, a confidence level, and an `AsOf` verification date.

**What do "v1" and "v2" mean?**
**v1** is this published sample — everything described here is what v1 does today.
References to **v2** describe capabilities intentionally **deferred to a future
version** (for example, active TLS-endpoint probing, which ships only as a dormant
scaffold, and the self-updating-knowledge refresh design). There is no separate
version tag; "v1" simply means the current shipped tool.

---

## 2. What it scans & what it deliberately does not scan

**How many services does it scan, and across which crypto functions?**
99 service scanners spanning **data-at-rest (49)**, **data-in-transit (27)**,
**certificates/PKI (10)**, **key management (9)**, **SDK/library PQC (3)**, and
**runtime evidence (1)** — the last reads KMS data-plane crypto evidence from
CloudTrail. See [`README.md` → What gets scanned](../README.md#what-gets-scanned-99-scanners).

**What does it deliberately NOT scan?**
CryptaMap is a config-plane tool — it does not read filesystems, network packets, or
source code. Its published not-scanned register has three buckets: **10** that cannot
be scanned honestly (no API returns the posture), **59** deferred to a later version,
and **30** out of scope (they delegate to a covered service or have no crypto
surface). The authoritative, current register is
[`docs/COVERAGE-AND-GAPS.md`](./COVERAGE-AND-GAPS.md).

**Why exclude a service rather than guess?**
The honesty contract comes first. For a regulator-facing tool, a false all-clear —
asserting a posture that was never actually read from an AWS API — is worse than an
admitted gap. Every excluded service was evaluated and excluded for a stated, verified
reason.

**If a service delegates its encryption to another (e.g. to S3, KMS, or ACM), is that
crypto missed?**
No. Where a service delegates encryption to a covered service, that crypto appears in
the CBOM under the owning service's scanner. Listing the delegating service
separately would double-count the same key or certificate and distort the
posture-breakdown figures.

**Does an empty result for a service or account mean "clean"?**
No — it means **not assessed**. A scanned account with no findings is distinct from an
account reported **UNCOVERED** (e.g. the scanner role is missing). CryptaMap never
treats absence of data as a clean result.

---

## 3. Is it safe, read-only, and where does my data go?

**Does CryptaMap modify any AWS resources?**
No. The scanners make only read/describe/list calls (`Describe*`/`List*`/`Get*`) and
never mutate resources. The deployed least-privilege policy contains read actions plus
three resource-scoped writes used **solely by the org orchestrator** (writing results
to your own S3/DynamoDB and importing to your own Security Hub).

**Where does my scan data go?**
It never leaves your AWS account/org. There is **no internet-facing API or dashboard
and no SaaS backend** — CryptaMap is local-first by design. Output is written locally,
or to a customer-owned S3 bucket in org mode, and viewed via `cryptamap serve` on
loopback (`127.0.0.1` only).

**Is the dashboard exposed to the network?**
No. `cryptamap serve` renders results over loopback only. The screenshots in the
README show synthetic demo data, not a real scan.

**Is the crypto inventory itself sensitive?**
Yes. The CBOM and reports describe your cryptographic posture and are effectively a
*harvest-now-decrypt-later* target list, so treat them as security findings: store
them in a controlled location and do not commit them to public source control.

**Does the published sample contain any real account data?**
No. It ships no real account data; demo data is synthetically generated, and CI fails
the build on any committed real AWS account ID, ARN, bucket name, or private key.

---

## 4. How do I run it? (three paths + offline merge)

**What are the ways to run CryptaMap?**
Three documented quick-start paths (1–3) plus a no-deploy offline-merge option:

| Path | What it does | Needs |
|---|---|---|
| **1 — Demo** | Synthetic data, no AWS account | Node 20 (or the prebuilt-embedded binary) |
| **2 — Single-account** | Live scan of one account from your laptop | Your own read-only credentials |
| **3 — Org fan-out** | Deployed scan across every member account | StackSet + Step Functions deploy |
| **org-merge-files** | Merge per-account CBOMs offline, no deploy | Per-account CLI output files |

See [`README.md` → Quick start](../README.md#quick-start).

**Does the CLI fan out across accounts if I pass `--org` or `--accounts`?**
No. The CLI deliberately does not fan out; if you pass `--org`/`--accounts` it warns
and scans only the caller account. Org-wide coverage is the deployed StackSet +
Step Functions fan-out (Path 3), not a CLI flag.

**How do I run the demo with no AWS account?**
Path 1: `cd dashboard && npm install && npm run dev` (loads the synthetic demo
dataset at `http://localhost:5173`), or build the embedded binary with
`make build-serve`, run `./dist/cryptamap --mock --mock-scale 10 --output-dir ./out`,
then `./dist/cryptamap serve --dir ./out`.

**How do I scan a single account live?**
Path 2: `make build-cli`, then
`./dist/cryptamap --profile <PROFILE> --regions ap-south-1 --output-dir ./out`, then
`./dist/cryptamap serve --dir ./out`. Region coverage is explicit and opt-in;
`--regions all` scans every enabled region.

**What does plain `make deploy` do versus org-wide scanning?**
Plain `make deploy` provisions only the single-account scheduled-scan stacks
(`orgScanningEnabled` defaults to false); the org fan-out stack is not even
synthesized. Pass `-c orgScanningEnabled=true` (with your real org id, root id, and a
chosen ExternalId) to get org-wide coverage.

---

## 5. Installation, build & getting started

> Full detail is in **[`docs/INSTALL.md`](./INSTALL.md)**. The essentials:

**What toolchain do I need?**
**Go 1.26.2** (pinned in `go.mod`) and **Node 20** (pinned in CI for the dashboard and
CDK jobs), plus npm. These are the only authoritative pins — there is no `.nvmrc` or
`engines` field.

**How do I build the CLI?**
`make build-cli` produces `./dist/cryptamap` with a *placeholder* dashboard UI. To get
the **real dashboard embedded**, run `make build-serve` (it builds the dashboard and
copies it into the binary via `go:embed`, with a guard that fails the build if any
`*.local.json` data file would be baked in).

**Is there a prebuilt binary I can download?**
No. There is no prebuilt or signed release artifact — build from the latest `main`.
For offline use, `make release` cross-compiles locally for four targets
(`darwin`/`linux` × `amd64`/`arm64`) with a `SHA256SUMS` manifest; signing is
operator-side. See [`docs/INSTALL.md`](./INSTALL.md#no-prebuilt-binary).

**What IAM does the operator running the local scan need?**
Path 2 uses your own credentials directly (no role assumption), so your principal must
hold the read actions. The recommended minimum is a custom read-only policy equal to
the **140 read actions** (`readActions`) in
[`cdk/policy/scanner-actions.json`](../cdk/policy/scanner-actions.json) — the file also
defines 3 orchestrator-only writes you do **not** need for a local Path-2 scan —
narrower than AWS-managed `ReadOnlyAccess`. You can drop `organizations:ListAccounts`
for a strict single-account run and need none of the three orchestrator writes. Full detail:
[`docs/INSTALL.md`](./INSTALL.md#iam-for-the-local-operator-path-2-single-account-scan).

**Any Go-command gotcha in this repo?**
Yes — scope Go commands to the module packages
(`go build ./internal/... ./pkg/... ./cmd/...`) and avoid bare `./...`, because
`cdk/node_modules` vendors invalid standalone `.go` init-template files.

---

## 6. Cross-account trust & deployment topology

**What cross-account setup does org-wide scanning require?**
A read-only `CryptaMapScannerRole` must exist in every target account. You don't
create it by hand — the Path 3 deploy provisions it org-wide via a **SERVICE_MANAGED**
CloudFormation StackSet (including future accounts, via AutoDeployment). CryptaMap is
read-only and cannot create it itself. See
[`DEPLOYMENT.md`](../DEPLOYMENT.md#cross-account-role-prerequisite).

**How is the scanner role protected against misuse (the confused-deputy problem)?**
Double-gated trust: only the orchestrator role may assume the scanner role, and only
when the caller is inside your org (`aws:PrincipalOrgID`) **and** presents the agreed
`sts:ExternalId`. The docs warn against reusing `OrganizationAccountAccessRole` —
it is full `AdministratorAccess` and lacks both guards.

**What does the org fan-out actually do once deployed?**
A StackSet creates the read-only role in every member account; orchestration stacks in
the Audit account run a Step Functions state machine that seeds
`{account, region, roleArn, externalId}` tuples, fans out one scanner-Lambda per tuple
(each assumes the member role and scans that single account/region), and merges the
partials into one org CBOM in the central results bucket.

**What if the scanner role is missing in an account?**
That account is reported **UNCOVERED** — never silently treated as clean.

**Where should I deploy from?**
A dedicated **Audit / Security-Tooling account** is recommended (with the Audit
account registered as a StackSets delegated administrator), rather than the
management/payer account. See
[`DEPLOYMENT.md` → Where to deploy](../DEPLOYMENT.md#where-to-deploy-account-topology).

---

## 7. Reading the results — KPIs, severity & Mosca's Theorem

**Is there a single headline "% quantum-resistant" number?**
No — a single percentage was retired because it over-credited AES-256 at rest as if it
were post-quantum migration progress. CryptaMap instead shows a **six-tier maturity
breakdown** (no-encryption, quantum-vulnerable, symmetric-only, PQC-hybrid, PQC-ready,
unknown), plus two honest derived callouts:

- **% quantum-vulnerable** — traditional public-key assets (`legacy-tls` +
  `non-pqc-classical`) ÷ all *classifiable* assets, where classifiable is every tier
  **except** `unknown`. (`no-encryption` is in this denominator but is not itself
  counted as quantum-vulnerable.)
- **% migrated to post-quantum end-to-end** — `pqc-ready` ÷ **all** assets (including
  `unknown`).

Hybrid post-quantum key exchange (`pqc-hybrid`) and symmetric-only AES-256 are **never**
counted as fully quantum-resistant. See
[`docs/PQC-READINESS-CROSSWALK.md`](./PQC-READINESS-CROSSWALK.md).

**How is severity assigned?**
Severity derives from a **Mosca's-Theorem** urgency score (`Risk = X + Y − Z`): a score
≥ 7 is CRITICAL, 4–6 HIGH, 1–3 MEDIUM, ≤ 0 INFORMATIONAL. Severity is a field on the
roadmap/finding, not on the CBOM component.

**How is Mosca's Theorem configured?**
Defaults are Indian-BFSI-calibrated — `X` = 7–10y data shelf-life, `Y` = 1–3y migration
time, `Z` = 3y CRQC horizon — and are overridable per service via YAML under
`risk.mosca.overrides`.

**How is the roadmap ordered?**
The ranker combines Mosca urgency, cryptographic posture, and harvest-now-decrypt-later
exposure, with an AES/PQC sink clamp and an upgrade-ease tie-break, to order migration
work — most urgent first.

**What posture verdicts will I see per asset?**
`pqc-hybrid` (TLS 1.3 cipher with X25519 + ML-KEM — key-exchange only), `symmetric-only`
(e.g. AES-256-GCM at rest), `non-pqc-classical` (traditional RSA/ECDHE), `legacy-tls`
(TLS 1.0/1.1), `no-encryption`, and `unknown`. **AES-256 at rest is quantum-resistant**
(Grover only halves effective strength), so **no action is required** — it is never
counted as PQC migration progress.

---

## 8. Accuracy, validation & limitations

**How is CryptaMap validated?**
Three layers ship and run in CI: per-scanner fake-client tests, systemic
honesty-invariant tests, and adversarial fuzz plus an end-to-end output pipeline. A
fourth live-validation layer is documented but not shipped in the public sample. See
[`docs/VALIDATION.md`](./VALIDATION.md).

**Is the CBOM schema-valid?**
Yes — the CycloneDX 1.7 CBOM is schema-validated against the official CycloneDX 1.7
bundle (committed under `testdata/schemas/`) on every `make test`; set
`CRYPTAMAP_REQUIRE_SCHEMA=1` to make a missing bundle a hard failure rather than a
graceful skip.

**What are CryptaMap's key limitations?**
It is config-plane: it reads AWS APIs only, not filesystems, network packets, or source
code, and it inventories posture from configuration evidence rather than certifying
protection. Coverage is 99 scanners with a documented not-scanned register, and an
asset whose posture no API returns is marked `unknown` rather than guessed.

**Does enabling hybrid post-quantum key exchange make an endpoint end-to-end quantum-resistant?**
No. Hybrid post-quantum key exchange (X25519 + ML-KEM) helps make the TLS session
**key exchange** quantum-resistant only; the leaf-certificate authentication remains
traditional RSA/ECDSA. A `pqc-hybrid` posture reflects quantum resistance on the
key-exchange axis, not end-to-end.

**Can I run the tests myself?**
Yes — `make test` runs the full unit suite and per-package coverage, with named
systemic/e2e steps mirroring CI and adversarial fuzz of the security-critical parsers.

---

## 9. Outputs & how to use them

**What output files does a scan produce, and what are they for?**
Per region (and a merged set with `--org-merge`):

| File | Purpose |
|---|---|
| `*.cbom.json` | CycloneDX 1.7 CBOM — the cryptographic inventory |
| `*.roadmap.json` / `.md` | Prioritized PQC migration roadmap, each item cited |
| `*.pqcc.xlsx` | MITRE PQCC Inventory Workbook (Excel) |
| `*.asff.json` | AWS Security Hub ASFF findings |
| `*.coverage.json` | Per-(account,region) coverage matrix (org-merge only) |
| `*.scan.json` | Raw scan dump |
| `*.report.md` | Markdown summary |

See [`README.md` → Output formats](../README.md#output-formats).

### What does a finding look like?

A finding has **two joined parts**. The **CBOM component** carries the cryptographic
facts and posture; the **roadmap item** carries severity, the recommended action, and
the source-URL citation (joined per-service from the verified PQC matrix). The citation
is *not* stored inside the CBOM component itself.

A trimmed real component (account id is a fictitious mock value):

```jsonc
{
  "type": "cryptographic-asset",
  "bom-ref": "crypto-100a0adf174af2f5",      // stable id linking asset → roadmap item
  "name": "AWS Secrets Manager — secret-0",
  "cryptoProperties": {
    "assetType": "algorithm",                // 'algorithm' (cipher/key) or 'protocol' (TLS/SSH)
    "algorithmProperties": {
      "primitive": "ae",                     // authenticated encryption
      "parameterSetIdentifier": "256",
      "mode": "gcm",
      "classicalSecurityLevel": 256,         // strength against classical (non-quantum) attack, in bits
      "nistQuantumSecurityLevel": 5          // NIST PQ category (5 = highest)
    }
  },
  "properties": [
    { "name": "cryptamap:category",    "value": "data-at-rest" },
    { "name": "cryptamap:accountId",   "value": "111100000007" },
    { "name": "cryptamap:region",      "value": "ap-south-2" },
    { "name": "cryptamap:algorithmName","value": "AES-256-GCM" },
    { "name": "cryptamap:posture",     "value": "symmetric-only" }   // the maturity-ladder verdict
  ]
}
```

The matching roadmap item for this asset cites
`https://docs.aws.amazon.com/secretsmanager/latest/userguide/pqtls.html` and its
recommended action notes that **at-rest AES-256 needs no action**, and that enabling
hybrid post-quantum key exchange using ML-KEM is a client-side opt-in that helps make
the TLS key exchange quantum-resistant. Posture vocabulary you'll see across the
inventory: `pqc-hybrid`, `symmetric-only`, `non-pqc-classical`, `legacy-tls`,
`no-encryption`, `unknown`.

**How do I view results?**
Run `cryptamap serve --dir <output>` to view results in the local dashboard over
loopback; the dashboard's Export button produces a regulator-grade PDF. The Markdown
summary is a CLI-friendly alternative.

**How do I import the ASFF output into AWS Security Hub?**
CryptaMap writes a local ASFF JSON array; you run the import. In short: enable Security
Hub in the target account/region, grant the importing principal
`securityhub:BatchImportFindings` on the built-in `product/<account>/default` ARN (no
custom onboarding needed), then
`aws securityhub batch-import-findings --findings file://<scan>.asff.json --region <region>`,
in batches of 100. Step-by-step recipe:
[`docs/SECURITY-HUB-IMPORT.md`](./SECURITY-HUB-IMPORT.md).

---

## 10. Compliance mapping & the AWS Config PQC-Readiness crosswalk

**Which compliance frameworks does it map findings to?**
Nine: SEBI CSCRF, RBI, IRDAI ICSG, CISA M-23-02, MITRE PQCC, CNSA 2.0, EU NIS2 + DORA,
Canada PQC Roadmap, and Europol QSFF. See
[`README.md` → Compliance frameworks](../README.md#compliance-frameworks).

**Are the Indian-regulator control IDs official?**
No. They are **CryptaMap's own mapping labels**, not official regulator codes — those
regulators do not publish such identifiers. The India PQC framing is national
(CERT-In CIWP-2025-0002), not a per-regulator mandate. The mappings are a crosswalk to
help your auditors, not an attestation.

**How does CryptaMap's vocabulary line up with the AWS Config PQC-Readiness scanner's
Tier 1/2/3?**
[`docs/PQC-READINESS-CROSSWALK.md`](./PQC-READINESS-CROSSWALK.md) is the translation
layer: `pqc-ready`/`pqc-hybrid` map to Tier 1/2 (quantum-resistant on key exchange),
`non-pqc-classical`/`legacy-tls` to Tier 3 (quantum-vulnerable), both anchored to NIST
IR 8547. CryptaMap deliberately does not adopt the Tier labels — they're a single-tool
convention and collide with its own roadmap tiers.

**I ran AWS Config's PQC-Readiness rule and got "Tier 1 everywhere" — am I done?**
No. A clean Config Tier 1 covers only your ALB/NLB/API Gateway TLS endpoints. It says
nothing about CloudFront, at-rest data, certificate signature algorithms, or
library/SDK crypto — all of which CryptaMap inventories and which can still be
quantum-vulnerable.

**Do CryptaMap's roadmap tiers mean the same as AWS Config's tiers?**
No — they point in **opposite directions**. CryptaMap's `act-now | plan-watch |
no-action` tiers are a priority-to-fix ordering (act-now = most urgent), while AWS
Config Tier 1 = best. Don't equate "CryptaMap act-now" with "AWS Tier 1".

---

## 11. Data residency, retention & AWS cost

**Where does the evidence store live?**
In whatever region you deploy `CryptaMap-Data` to; each per-region scan partial lands
there and nowhere else. v1 targets Indian regions (`ap-south-1` / `ap-south-2`); the
deploy default fan-out is `us-east-1,ap-south-1`.

**What happens if I deploy outside India?**
CryptaMap emits a loud stderr **notice** at synth time if the Data-stack region or any
fan-out region is not Indian, so a non-India deployment is never silent. It is a notice
only — CryptaMap never hard-blocks a region.

**How long are results retained?**
By default **30 days**, on the configurable `retentionScans` window: an S3 lifecycle
rule expires current and noncurrent objects, and DynamoDB TTL deletes each scan record.
Change it at deploy with `-c retentionScans=<days>`.

**Does `cdk destroy` delete my collected evidence?**
No. The results bucket, access-logs bucket, KMS CMK, and scans table are
**RETAIN-on-destroy by design**, so a `cdk destroy` cannot wipe in-window evidence;
only the lifecycle/TTL windows expire individual results. Decommissioning the evidence
store is a deliberate manual step — see [Teardown](#12-operations-teardown-partitions--offline-use).

**What AWS costs does CryptaMap incur?**
Scanning uses read-only API calls and creates no resources, but **deploying the org
fan-out provisions billable resources** (Step Functions, Lambda, an evidence
S3 bucket / DynamoDB, CloudWatch Logs, cross-region API traffic). A monthly AWS Budget
guardrail (default **$100**, configurable via `-c monthlyBudgetUSD`, `0` disables) is
provisioned. You are responsible for any charges incurred.

---

## 12. Operations, teardown, partitions & offline use

**How do I tear down CryptaMap?**
`make destroy` runs `cdk destroy --all --force` for the in-account stacks
(destructive). Full uninstall is multi-step and partly manual: delete the StackSet
stack instances from member accounts **first**, run the destroy, then manually clean
the RETAINed evidence store, and in DELEGATED_ADMIN mode deregister the StackSets
delegated administrator. Full ordered procedure:
[`DEPLOYMENT.md` → Teardown](../DEPLOYMENT.md#teardown--uninstall-ordered-procedure).

**What survives a `cdk destroy`?**
The KMS CMK, results bucket (versioned), access-logs bucket, DynamoDB scans table, and
the state-machine CloudWatch log group are RETAIN-on-destroy and survive; delete them
manually (emptying all object versions from the bucket) to fully decommission.
`make clean` only removes local build artifacts.

**Does CryptaMap work in AWS GovCloud (US) and China partitions?**
Yes, with documented caveats. ASFF/Security Hub findings are partition-correct and the
org fan-out cross-account assume path is partition-aware, so findings import and roles
resolve in those partitions. A residual cosmetic detail: CBOM `bom-ref` resource ARNs
carry an `arn:aws:` prefix (a dedup key, not submitted to any API). Detail:
[`DEPLOYMENT.md` → Partition support](../DEPLOYMENT.md#aws-govcloud-us-and-china-partition-support).

**Can CryptaMap run air-gapped / egress-blocked?**
Yes — a first-class supported environment. The baked-in PQC knowledge baseline is
mandatory and the optional network refresh is never a precondition; scans are fully
functional offline. See [`docs/SELF-UPDATING-KNOWLEDGE.md`](./SELF-UPDATING-KNOWLEDGE.md).

**How often does the deployed scan run?**
The default scheduled scan runs **weekly, Sunday 06:00 UTC** (`cron(0 6 ? * SUN *)`),
via an EventBridge rule on the **single-account** scanner Lambda — it covers only the
deployed account. The org Step Functions run has no schedule and is started manually
(`aws stepfunctions start-execution`). Change the schedule with `-c scanSchedule=<expr>`.

**Roughly how many API calls does a scan make — will it trip detection alarms?**
There is no fixed number: a floor of ~99 enumerate/list calls per account/region, plus
per-resource describes for a few high-volume scanners (notably S3 and DynamoDB), plus
~7 paginated CloudTrail `LookupEvents` sequences. All calls are **read-only** and use
client-side adaptive rate-limiting. CryptaMap does not encode detection-alarm
avoidance; if you run detection tooling (GuardDuty, CloudTrail Insights), consider
allowlisting the scanner principal, since a broad read sweep can register as unusual
read activity.

---

## 13. License, support, contributing & reporting

**What license is CryptaMap released under?**
MIT-0 (MIT No Attribution). See [`LICENSE`](../LICENSE).

**How do I report a security vulnerability?**
Notify AWS/Amazon Security via the
[vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or email **aws-security@amazon.com**. **Do not** open a public GitHub issue for
security vulnerabilities. See [`SECURITY.md`](../SECURITY.md).

**How do I report bugs or request features?**
Use the GitHub issue tracker. Check existing open and recently closed issues first, and
include a reproducible test case, the version of the code used, any relevant
modifications, and notes about your environment. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

**How do I contribute code?**
Via pull requests against the latest `main`: check existing PRs, open an issue to
discuss significant work, fork the repo, and keep the change focused.

**Which version receives security fixes?**
Security fixes are applied to `main` — run against the latest source. No semver release
tag is published, and there is no downloadable prebuilt release artifact.

---

*This FAQ is part of the CryptaMap sample. It describes the tool as shipped (v1); it is
not AWS guidance or a compliance attestation. CryptaMap is provided as AWS sample code
for evaluation and as a starting point — review, test, and harden it for your own
environment before any production use; it is not a ready-to-deploy production solution.
For the deeper design, see [`ARCHITECTURE.md`](../ARCHITECTURE.md).*
