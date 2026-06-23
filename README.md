# CryptaMap

**Organization-wide AWS cryptographic inventory → CycloneDX CBOM + PQC migration roadmap**

CryptaMap is an open-source (MIT-0) tool that discovers cryptographic assets
across **99 AWS service scanners**, merges every scanned account/region into a
single org-wide inventory, and emits:

- a **CycloneDX 1.7 CBOM** (Cryptography Bill of Materials),
- a **prioritized PQC migration roadmap** ("upgrade these to post-quantum
  first"), each item carrying a verified AWS action and a citation,
- a **MITRE PQCC** Inventory Workbook (Excel), and
- **AWS Security Hub ASFF** findings.

It is calibrated for Indian BFSI regulators (SEBI CSCRF, RBI, IRDAI ICSG),
under the national CERT-In CIWP-2025-0002 quantum-readiness umbrella, but is
usable by any organization preparing for the post-quantum transition. The PQC support matrix it ranks against is web-verified
against live AWS documentation, with each row carrying a source URL, a
confidence level, and an `AsOf` verification date.

For the deeper design — taxonomy, the PQC matrix, the merge/roadmap engines, the
org fan-out topology, and the generated-types contract — see
[`ARCHITECTURE.md`](./ARCHITECTURE.md).

## Architecture at a glance

```
                         single account (CLI)                 org (deployed)
                         ┌──────────────────┐                 ┌────────────────────────┐
  AWS APIs (read-only) ─▶│  Scanner engine  │                 │ StackSet: member roles │
                         │  99 scanners     │                 │ (CryptaMapScannerRole) │
                         │  goroutine pool  │                 └───────────┬────────────┘
                         │  (config-based)  │                             │ assume-role
                         └────────┬─────────┘     Step Functions          ▼
                                  │              ┌─────────────────────────────────────┐
                       per-region │              │ Audit/orchestrator account          │
                       ScanResult │              │  Seed (ListAccounts × regions)      │
                                  ▼              │   → Distributed Map: scanner Lambda │
                  ┌─────────────────────────┐    │   → Merge → S3 run summary          │
                  │ taxonomy → pqc matrix    │    └─────────────────────────────────────┘
                  │ merge (--org-merge)      │
                  │ roadmap ranker           │
                  └───────────┬─────────────┘
                              │
        ┌─────────────────────┼───────────────────────────────┐
        ▼                     ▼               ▼                 ▼
  CycloneDX 1.7 CBOM   PQC roadmap     MITRE PQCC xlsx    Security Hub ASFF
        │                     │
        └──────────┬──────────┘
                   ▼
        Cloudscape dashboard (React + Vite)
        Overview / Assets / Roadmap / SEBI / RBI / IRDAI
```

- **Scanner engine** (`internal/scanner`) runs the 99 per-service scanners over a
  bounded goroutine pool with rate-limiting/backoff, producing one
  `models.ScanResult` per region.
- **Taxonomy** (`internal/taxonomy`) maps internal scanner IDs (`kms_spec`,
  `rds_transit`, …) to friendly display names + AWS categories so internal IDs
  never leak to the CBOM or UI.
- **PQC matrix** (`internal/pqc`) is the web-verified, single source of truth for
  per-service PQC availability, upgrade ease, the exact "how to enable" action,
  and a source-URL citation, plus a primitive quantum-vulnerability table.
- **Merge** (`internal/merge`, behind `--org-merge`) is a pure, deterministic
  engine that collapses N per-region/per-account shards into one org-wide
  `ScanResult` envelope plus a coverage matrix.
- **Roadmap** (`internal/roadmap`) ranks every finding into a prioritized PQC
  migration roadmap and rolls it up by service and by account.
- **Org fan-out** (deployed path) is a CloudFormation StackSet (member-account
  roles) plus a Step Functions state machine in the Audit/orchestrator account
  that fans out one scanner-Lambda execution per (account, region).
- **Dashboard** (`dashboard/`) is a React + Vite single-page app built on **AWS
  Cloudscape** components (no Tailwind, no ECharts), with an Overview, an Assets
  explorer, a Roadmap view, and SEBI/RBI/IRDAI compliance tabs.

## Quick start

CryptaMap runs in two very different scopes. Pick your path first, then jump to
its recipe:

| I want to… | Path | Cross-account setup? |
| --- | --- | --- |
| See every dashboard page populated with **synthetic demo data** (no AWS, no scan) | **Path 1 — Demo** | None |
| Scan **one account** (the caller) and view the result | **Path 2 — Single-account scan** | None |
| Inventory the **whole AWS Organization** (every member account) | **Path 3 — Deployed org fan-out** | Yes — read-only role in each account |

> **Which path am I on?** If you just want *one* account scanned, you are on
> **Path 2** — it runs entirely from your laptop with your own credentials, no
> deployment. If you want **org-wide** coverage across every member account, you
> are on **Path 3** — that is a *deployed* StackSet + Step Functions fan-out, not a
> CLI flag. **The CryptaMap CLI deliberately does NOT fan out across accounts**: if
> you pass `--org`/`--accounts` it warns and scans only the caller account.

All reference-grade deployment detail (the full IAM trust + permission JSON, the
account topology, and the one-time StackSets delegated-admin setup) lives in the
companion doc **[DEPLOYMENT.md](./DEPLOYMENT.md)**. This section is the fast path.

### Command reference (verified forms)

These are the exact, working invocations used by the recipes below. Copy from here
to avoid the common positional-argument mistakes:

| Goal | Command |
| --- | --- |
| Build the CLI | `make build-cli` |
| Mock end-to-end (no AWS) | `./dist/cryptamap --mock --mock-scale 10 --regions us-east-1,ap-south-1 --org-merge --output-dir ./dist/mock-output` |
| Scan one account | `./dist/cryptamap --regions ap-south-1 --output-dir ./out` |
| Scan every enabled region | `./dist/cryptamap --regions all --output-dir ./out` |
| Serve your scan locally | `cryptamap serve --dir ./out` |
| Merge per-account CBOMs offline | `cryptamap org-merge-files --in './out-acct1/*.cbom.json,./out-acct2/*.cbom.json' -o ./org-out` |
| Deploy org fan-out (Path 3) | `cd cdk && npx cdk deploy CryptaMap-OrgFanout --exclusively -c orgScanningEnabled=true -c organizationId=<ORG_ID> -c orgRootId=<ROOT_ID> -c scannerExternalId=<EXTERNAL_ID>` |

> **`serve` takes `--dir`, not a positional path**, and **`org-merge-files` takes
> `--in`, not positional files** — running either with a bare path silently serves
> the default `./dist/scan-output` (serve) or fails with `required flag(s) "in" not
> set` (merge). The forms above are the correct ones.

### Path 1 — Demo (synthetic data, no AWS)

```bash
cd dashboard && npm install && npm run dev   # http://localhost:5173
```

With no API configured the dashboard runs in **mock mode** and loads the committed
demo dataset at `dashboard/public/mock/{org-cbom.json,roadmap.json}` — a synthetic
Indian-BFSI organization. **This data is 100% synthetic and contains no real AWS
account, ARN, or customer information.** It is produced by:

```bash
go run ./cmd/gen-dashboard-mock          # regenerate the committed demo dataset
go run ./cmd/gen-dashboard-mock -check   # CI guard: fail if it drifts / was hand-edited
```

The dashboard banner shows **MOCK** for this demo dataset and **LIVE** when pointed
at real scan output. **Demo data is never shown once a real source is configured.**

### Path 2 — Single-account live scan

```bash
make build-cli

# If your ~/.aws/config is clean, --profile works directly:
./dist/cryptamap --profile <PROFILE> --regions ap-south-1 \
  --output-dir ./dist/live-output --verbose

# Then view YOUR scan (note: --dir, not a positional path):
cryptamap serve --dir ./dist/live-output
```

> **Credential workaround:** a malformed SSO entry in `~/.aws/config` can break the
> default credential chain. If `--profile` fails, export resolved credentials into
> the environment first and run *without* `--profile`:
> ```bash
> eval "$(aws configure export-credentials --profile <PROFILE> --format env)"
> export AWS_REGION=ap-south-1
> ./dist/cryptamap --regions ap-south-1 --org-merge --output-dir ./dist/live-output --verbose
> ```

**Region coverage is explicit and opt-in.** `--regions us-east-1,ap-south-1` scans
exactly those; **`--regions all`** scans every region enabled in the account
(resolved live via EC2 `DescribeRegions`; on failure it falls back to the
commercial-default set and prints a WARNING — never a silent subset). With no
`--regions`, only the single caller region is scanned.

The scanner uses **read-only** AWS APIs only (`Describe*`/`List*`/`Get*`); it never
mutates resources.

### Path 3 — Deployed org fan-out (whole organization)

Org-wide scanning is a fundamentally different problem — it must assume a role into
*every other account* — so it runs as a deployed StackSet + Step Functions fan-out,
not from your laptop.

**Prerequisite:** a read-only `CryptaMapScannerRole` must exist in every target
account (CryptaMap is read-only and cannot create it itself). You do not create it
by hand — **the deploy below provisions it org-wide via a StackSet**; this is just
naming the dependency. See **[Cross-account role prerequisite and IAM
setup](./DEPLOYMENT.md#cross-account-role-prerequisite)** for what the role is, its
double-gated trust, and the copy-paste JSON.

```bash
make build-cli   # builds the Lambda bootstrap + CDK assets via make deploy's deps

# Deploy the org fan-out. orgScanningEnabled MUST be set or you get a
# single-account scheduled scan, NOT org-wide coverage (see warning below).
cd cdk && npx cdk deploy CryptaMap-OrgFanout --exclusively \
  -c orgScanningEnabled=true \
  -c organizationId=<ORG_ID> \
  -c orgRootId=<ROOT_ID> \
  -c scannerExternalId=<EXTERNAL_ID>
```

> Where these come from: `<ORG_ID>` / `<ROOT_ID>` are your AWS Organizations id and
> root id (`aws organizations describe-organization` / `list-roots`). The
> orchestrator account id is taken automatically from your deploy environment
> (`CDK_DEFAULT_ACCOUNT`). **`<EXTERNAL_ID>` is a private string you choose** (any
> value — it is a shared secret for the confused-deputy guard, not something to look
> up), e.g. `acme-cryptamap-7f3a9`.

> **Plain `make deploy` does NOT turn on org scanning.** `make deploy` runs
> `npx cdk deploy --all` with `orgScanningEnabled` at its default of `false`
> (`cdk.json`), so it provisions only the **single-account scheduled-scan** stacks —
> the `CryptaMap-OrgFanout` stack is not even synthesized. You would believe you had
> org-wide coverage while only one account was scanned. **You must pass
> `-c orgScanningEnabled=true`** (as in the command above) to get the org fan-out.

> **You also need your real org ids.** When `orgScanningEnabled=true`, synth
> **refuses** to deploy with the placeholder organization id (`o-exampleorgid`), the
> placeholder root id (`r-exam`), or the default ExternalId (`cryptamap-scanner`) —
> it errors and tells you to pass `-c organizationId=<your-org-id>`,
> `-c orgRootId=<your-root-id>`, and `-c scannerExternalId=<your-private-value>`.
> **These refusals only fire when `orgScanningEnabled=true`** — in the default
> single-account path (`orgScanningEnabled:false`) nothing is refused because no org
> scanning happens. So the guard protects the org path; it does not "bless" a
> defaults-only run.

What the org fan-out does once deployed:

1. A **SERVICE_MANAGED** CloudFormation StackSet creates the read-only
   `CryptaMapScannerRole` in **every** member account (including future ones via
   AutoDeployment).
2. The orchestration stacks (in the **Audit/orchestrator** account) provision a Step
   Functions state machine that **seeds** `{accountId, region, roleArn, externalId}`
   tuples via `organizations:ListAccounts` × the configured regions, fans out one
   scanner-Lambda execution per tuple (each assumes the member role and scans that
   single account/region), and **merges** the per-(account,region) partials into one
   org CBOM in the central results bucket.
3. View the merged result with `cryptamap serve --dir <merged-output>` or from the
   bucket with operator credentials.

**Fan-out region coverage** is opt-in via the `fanoutRegions` context value (default
`us-east-1,ap-south-1`, intersected with each account's enabled regions). Set
**`-c fanoutRegions=all`** to fan out over every region each member account has
enabled. `all` is thorough but heavier (e.g. ~17 enabled regions × N accounts is
many more scan shards); narrow with an explicit list for a fast targeted run.

> The org-fanout topology is the single source of truth in
> [`cdk/lib/org-fanout-stack.ts`](./cdk/lib/org-fanout-stack.ts).

#### No-deploy middle option: `org-merge-files`

If you want an org-wide view without standing up the Step Functions stack (a handful
of accounts, or an evaluator), each account team runs the single-account CLI
themselves and you merge the resulting CBOMs **locally, with no AWS calls**:

```bash
# each account: cryptamap --regions … -o ./out-<account>   (produces a *.cbom.json)
# then merge them all into one org CBOM + roadmap, offline (note: --in, comma-separated globs):
cryptamap org-merge-files --in './out-acct1/*.cbom.json,./out-acct2/*.cbom.json' -o ./org-out
```

This avoids any cross-account role and keeps every step local — but it requires
someone to run the CLI in each account. For a true hands-off org scan, use the
deployed fan-out above.

### Safety, residency, and retention (read before deploying org-wide)

- **Read-only by construction.** The scanner role carries a **custom
  least-privilege** inline policy (`CryptaMapScannerReadActions`) — exactly the
  `Describe*`/`List*`/`Get*` actions the scanners call, **NOT** the broad
  AWS-managed `ReadOnlyAccess`. **No write access.** The action list is the single
  source of truth in [`cdk/policy/scanner-actions.json`](./cdk/policy/scanner-actions.json)
  (generated by `cmd/gen-policy`; CI `make check-policy` fails on drift).
- **Double-gated trust (confused-deputy guard).** Only the orchestrator role may
  assume the scanner role, and only when the caller is inside **your** org
  (`aws:PrincipalOrgID`) **and** presents the agreed `sts:ExternalId`. **Do NOT use
  `OrganizationAccountAccessRole` for scanning** — it is full `AdministratorAccess`
  and lacks both guards.
- **Missing role ⇒ UNCOVERED, never silently "clean".** If `CryptaMapScannerRole` is
  absent in an account, that account is reported **UNCOVERED**.
- **Data residency.** The evidence store and per-region fan-out land data in their
  respective regions; v1 targets Indian regulators (ap-south-1 / ap-south-2). Synth
  emits a **loud non-India notice** on stderr if any resolved region falls outside
  India (notice only; never blocks). See [Data residency](#data-residency) below.
- **Retention.** Results auto-expire after `retentionScans` days (default **30**;
  override with `-c retentionScans=<n>`). See
  [Retention (results auto-expire)](#retention-results-auto-expire) below.
- **AWS costs.** CryptaMap scans with read-only API calls (no resources created),
  but deploying the org fan-out provisions billable AWS resources (Step Functions,
  Lambda, an evidence S3 bucket / DynamoDB, CloudWatch Logs, and cross-region API
  traffic). You are responsible for any AWS charges incurred by deploying and
  running it in your account(s). Review the AWS pricing for these services and the
  CDK stack in [`cdk/`](./cdk/) before deploying. This is sample code provided
  as-is; see [LICENSE](./LICENSE).

Full IAM JSON, the three values you substitute (`<ORCHESTRATOR_ACCOUNT_ID>`,
`<ORG_ID>`, `<EXTERNAL_ID>`) **plus the `<ROOT_ID>` the org-deploy guard requires**,
the account topology, and the one-time delegated-admin registration are all in
**[DEPLOYMENT.md](./DEPLOYMENT.md)**.

## Data residency

**CryptaMap v1 targets Indian regulators (CERT-In CIWP-2025-0002, SEBI CSCRF, RBI,
IRDAI), so the intended home is an Indian region** — `ap-south-1` (Mumbai), with
`ap-south-2` (Hyderabad) also recognized. The deploy default fan-out is
`us-east-1,ap-south-1` (us-east-1 is kept only because global-endpoint services
such as IAM and CloudFront surface their config there).

- **The operator picks the region.** The evidence store (KMS CMK, results bucket,
  scans table) lives in whatever region you deploy `CryptaMap-Data` to
  (`CDK_DEFAULT_REGION`), and each per-region scan's partial lands in that
  evidence store — never anywhere else.
- **Deploying outside India prints a notice.** At synth time, if the Data-stack
  region or any fan-out region is not an Indian region, CryptaMap emits a loud
  stderr notice ("deploying CryptaMap outside India … confirm this meets your
  data-residency obligations") so a non-India deployment is never silent. It is a
  **notice only** — CryptaMap never hard-blocks a region; you may have legitimate
  reasons to deploy elsewhere.
- **Data never leaves your AWS org, regardless of region.** There is no
  internet-facing API or dashboard and no SaaS backend (local-first by design).
  Results are viewed via `cryptamap serve` on loopback or
  pulled from the results bucket with the operator's own credentials. The crypto
  inventory — a harvest-now-decrypt-later target list — stays inside the customer's
  own account/org.

## Retention (results auto-expire)

Collected evidence is **not** kept forever. Both halves of the evidence store age
out on the same configurable window, `retentionScans` (**default 30 days**):

- **Results bucket:** an S3 lifecycle rule expires current objects, and noncurrent
  versions, `retentionScans` days after they are written/become noncurrent — so a
  versioned bucket does not silently accumulate old scan evidence.
- **Scans table:** DynamoDB TTL deletes each record on its `expiresAt` attribute
  (stamped `now + retentionScans` days by the writer), so metadata and object
  payloads age out together.

Change the window at deploy time with `-c retentionScans=<days>`, e.g.
`-c retentionScans=90`. (The buckets/tables themselves are `RETAIN`-on-destroy so a
`cdk destroy` can't wipe in-window evidence; only the lifecycle/TTL windows expire
individual scan results.)

## What gets scanned (99 scanners)

| Crypto function       | Count | Examples |
| --------------------- | ----: | -------- |
| Data at rest          | 49 | S3, EBS, RDS, DynamoDB, Redshift, ElastiCache, DocumentDB, Neptune, OpenSearch, EFS, FSx, Backup, Glue, MSK, SQS, SNS, Kinesis, Secrets Manager, SSM, CloudWatch Logs, SageMaker, WorkSpaces, Lightsail, DMS, Timestream, QLDB, Keyspaces, MemoryDB, EMR, DAX, Firehose, Athena, Amazon MQ, Storage Gateway, Bedrock, QuickSight, Managed Flink, EventBridge, Step Functions, Connect Customer Profiles, WorkSpaces Secure Browser, CodeBuild, X-Ray, MGN, Kendra |
| Data in transit       | 27 | ALB, NLB, API Gateway REST/HTTP, CloudFront, ElastiCache, DocumentDB, RDS, Aurora, OpenSearch, MSK, Redshift, Neptune, EKS, ECS, Lambda, AppSync, IoT Core, Transfer Family, VPN, Direct Connect, Global Accelerator, Client VPN, VPC Lattice, Classic ELB, App Mesh, Directory Service (LDAPS) |
| Certificates / PKI    | 10 | ACM, AWS Private CA, IAM server certs, CloudFront custom certs + key groups, IoT device certs, IAM Roles Anywhere, AWS Signer, SES DKIM signing, AppStream 2.0 certificate-based auth |
| Key management        | 9  | KMS key spec / usage / rotation / custom key store, CloudHSM, Secrets Manager rotation, Payment Cryptography keys, Cognito token signing, EC2 key pairs |
| SDK / library PQC     | 3  | Lambda runtime, ECS/EKS container images, EC2 via SSM inventory |
| Runtime evidence      | 1  | CloudTrail KMS data-plane crypto evidence |

The full friendly mapping (display name, AWS category, crypto function,
sub-aspect) lives in `internal/taxonomy/taxonomy.go`.

> Already ran AWS's Config PQC-Readiness scanner? See
> [`docs/PQC-READINESS-CROSSWALK.md`](./docs/PQC-READINESS-CROSSWALK.md) for how
> CryptaMap's posture / `% quantum-safe` vocabulary lines up with AWS's Tier 1/2/3
> and NIST's quantum-vulnerable / quantum-resistant terms.

## What CryptaMap does NOT scan (the absolute list)

CryptaMap is a **config-plane** PQC inventory tool: it reads AWS APIs to build the
CBOM. It does **not** read filesystems, network packets, or source code.

**Our honesty contract comes first.** For a regulator-facing tool (CERT-In /
SEBI / RBI / IRDAI), a *false all-clear* — asserting a crypto posture we never
actually read from an AWS API — is worse than an admitted gap. So every service
below was deliberately evaluated and excluded for a stated, verified reason;
nothing was silently dropped. A periodic audit (cross-checked against live AWS
documentation) re-derives this list — most recently **2026-06-15**, which
evaluated **112** additional crypto-touching services and **promoted 13 into the
scanner set** (Bedrock, QuickSight, Managed Flink, EventBridge, Step Functions,
Connect Customer Profiles, WorkSpaces Secure Browser, CodeBuild, X-Ray, MGN,
Kendra, SES DKIM, AppStream 2.0). The remaining **99** stay out of v1, in three
buckets:

### ⛔ Cannot scan honestly (10) — no API returns the posture, so any verdict would be fabricated
AWS Nitro Enclaves · Amazon EKS Anywhere · Amazon S3 Glacier (vault) · Amazon S3
on Outposts · AWS IAM Identity Center (SAML assertion signing — cert is
console-download-only; *blocked pending an AWS read API*) · Amazon WorkMail (org
CMK is write-only) · Amazon Honeycode (service shut down) · AWS Elemental
on-premises appliances (Live/Server/Conductor/Delta/Link) · Amazon WorkDocs · AWS
App2Container.

### 🕓 Deferred to a later version (59) — buildable and honest, but low PQC leverage and/or low India-FSI adoption
*Compute & containers:* App Runner, EC2 Image Builder, Fargate (ECS managed
storage), Lightsail container certs. *Storage:* File Cache, Elastic Disaster
Recovery, Snow Family, Backup Gateway. *Databases & analytics:* HealthOmics,
AppFlow, DataZone, Clean Rooms, Entity Resolution, FinSpace *(EOS 2026)*.
*Networking & CDN:* Verified Access, Network Firewall (TLS inspection), Route 53
DNSSEC, Transit Gateway (encryption-support state). *Security & identity:* Macie,
GuardDuty, Inspector, Audit Manager, Verified Permissions, Private CA Connector
for AD, Private CA Connector for SCEP. *Application integration:* EventBridge
Pipes, EventBridge Scheduler, MWAA, EventBridge Connections. *ML & AI:* Bedrock
AgentCore, Q Business, Q Developer, Comprehend, HealthLake, Forecast, Personalize,
Lex V2 (conversation logs), Transcribe, SageMaker Feature Store, Rekognition
(Custom Labels), Textract (Custom Queries Adapters), Translate. *IoT:* IoT Core
for LoRaWAN, IoT SiteWise, IoT FleetWise, IoT Greengrass V1 *(EOS Oct 2026 — do
not read complete Greengrass coverage into the IoT Core cert scanner)*. *Media:*
Nimble Studio, MediaConnect, MediaPackage, IVS, Kinesis Video Streams. *End-user
& business:* Connect Voice ID, Chime SDK (voice analytics). *Developer tools &
management:* CodeArtifact, CodePipeline, CodeCommit, Managed Grafana, Managed
Service for Prometheus, Proton *(EOS Oct 2026)*.

### 🔁 Out of scope (30) — delegates to a covered service, or has no crypto surface of its own
*Compute & containers:* Batch, Elastic Beanstalk, Outposts, ECS Anywhere,
Wavelength, Local Zones, Serverless Application Repository. *Storage:* S3 Access
Points / Object Lambda Access Points. *Databases & analytics:* Lake Formation,
Data Exchange. *Networking & CDN:* Gateway Load Balancer, PrivateLink / VPC
Endpoint Services, Cloud WAN, Network Manager, Route 53 Resolver DNS Firewall.
*Security & identity:* Detective, Resource Access Manager (RAM), KMS External Key
Store / XKS *(covered by extending the existing custom-key-store scanner, not a
new one)*, Cognito Identity Pools. *Application integration:* EventBridge Schema
Registry, Amazon MQ for RabbitMQ *(already covered by the engine-agnostic Amazon
MQ scanner)*, SWF, Pinpoint, Connect Cases. *Media:* MediaLive, MediaConvert,
MediaStore *(retired Nov 2025)*, MediaTailor. *Developer tools & management:*
CodeDeploy, Cloud9.

> Where a service delegates its encryption to S3, EBS, KMS, ACM, or another
> covered service, that crypto **is** in the CBOM — under the owning service's
> scanner. Listing the delegating service separately would double-count the same
> key/certificate and distort the `% quantum-safe` figures. The authoritative,
> always-current register (with per-service reasons and the full deferred backlog)
> is [`docs/COVERAGE-AND-GAPS.md`](./docs/COVERAGE-AND-GAPS.md).

## Risk scoring — Mosca's Theorem

CryptaMap implements `Risk = X + Y - Z` with Indian BFSI-calibrated defaults
(X = 7-10y data shelf-life, Y = 1-3y migration time, Z = 3y CRQC horizon).
Per-service defaults live in `internal/risk/defaults.go`; users override via the
YAML config under `risk.mosca.overrides`.

| Mosca score | Severity        |
| ----------- | --------------- |
| ≥ 7         | CRITICAL        |
| 4-6         | HIGH            |
| 1-3         | MEDIUM          |
| ≤ 0         | INFORMATIONAL   |

The roadmap ranker combines Mosca urgency, cryptographic posture, and
harvest-now-decrypt-later exposure (with an AES/PQC "sink" clamp and an
upgrade-ease tie-break) to order migration work — see `ARCHITECTURE.md`.

## Compliance frameworks

Findings are mapped to nine frameworks (`internal/compliance`, 9 mappers):

Indian-regulator control IDs are CryptaMap's own mapping labels (`CryptaMap→…`),
not official regulator codes — those regulators do not publish such identifiers.
PQC framing for India is
national (CERT-In CIWP-2025-0002), not a per-regulator mandate.

| Framework               | What CryptaMap maps to it                    |
| ----------------------- | -------------------------------------------- |
| SEBI CSCRF              | SBOM crypto-inventory substrate (Circular 2024/113) |
| RBI                     | `.bank.in` migration (RBI/2025-26/28) + PQC readiness |
| IRDAI ICSG              | crypto asset inventory (ICSG §3.2.2.2)       |
| CISA M-23-02            | items 4 / 5 / 6 (algorithm, type, key len)   |
| MITRE PQCC              | 18-field PQCC Inventory Workbook export      |
| CNSA 2.0                | `CNSA2-SIG`, `CNSA2-KEM` migration timeline  |
| EU NIS2 + DORA          | NIS2 Art. 21, DORA Art. 9                    |
| Canada PQC Roadmap      | CCCS-PQC-ROADMAP-2025                        |
| Europol QSFF            | financial-sector PQ guidance                 |

## Configuration

`configs/default.yaml` ships sensible defaults. CLI flags take precedence:

```
--config, -c <path>           YAML config file
--regions, -r us-east-1,ap-south-1
--accounts, -a 111122223333   specific account IDs (org mode only)
--org                         enable AWS Organizations cross-account scanning
--org-merge                   merge all scanned regions/accounts into one
                              org-wide CBOM + PQC roadmap + coverage matrix
--mock                        synthesize mock data (no AWS calls)
--mock-scale 10               resources per service in mock mode
--output-dir, -o ./dist/scan-output
--profile <name>              AWS named profile (see credential workaround above)
--verbose, -v
```

## Output formats

Per region (always), plus a single merged set when `--org-merge` is set:

- **CycloneDX 1.7 CBOM** (`*.cbom.json`) — schema-validated against the official
  CycloneDX 1.7 bundle in unit tests (`make test`).
- **PQC migration roadmap** (`*.roadmap.json` + `*.roadmap.md`) — every finding
  ranked by migration priority, each item carrying the verified AWS action and a
  source-URL citation, with by-service and by-account roll-ups.
- **MITRE PQCC Excel** (`*.pqcc.xlsx`) — Overview / Baseline Inventory / Glossary
  sheets matching the PQCC Inventory Workbook.
- **AWS Security Hub ASFF** (`*.asff.json`) — `BatchImportFindings`-ready;
  CRITICAL findings trigger SNS alerts via the Alerting stack.
- **Coverage matrix** (`*-org-*.coverage.json`, `--org-merge` only) — one row per
  scanned (account, region) shard with counts and an `errored` flag, so no
  account is silently treated as clean.
- **Raw scan dump** (`*.scan.json`) — full `ScanResult` for debugging.
- **Markdown summary** (`*.report.md`) — CLI-friendly report; the dashboard's
  Export button produces the regulator-grade PDF.

## Generated TypeScript types (single source of truth)

The dashboard does not hand-maintain its wire types. `cmd/gen-ts` reflects the
canonical Go structs (`pkg/models`, `internal/output`, `internal/roadmap`) and
the enum vocabularies (`pkg/models`, `internal/pqc`) into
`dashboard/src/types/generated.ts` (header: *"Code generated by gen-ts; DO NOT
EDIT"*). Any Go field rename/add/remove surfaces as a diff in that file.

```bash
make generate-types   # regenerate dashboard/src/types/generated.ts from Go
make check-types      # CI guard: fails if generated.ts is stale (git diff)
```

## Make targets

```
make build            # CLI + CDK + dashboard
make build-cli        # CryptaMap CLI for the host platform
make build-lambda     # Lambda bootstrap (linux/arm64, build tag: lambda)
make build-cdk        # CDK TypeScript build + synth
make build-dashboard  # React/Vite/Cloudscape dashboard build
make test             # Go unit tests with coverage (incl. CycloneDX 1.7 schema)
make vet              # go vet
make mock             # mock end-to-end scan
make generate-types   # regenerate dashboard TS types from Go
make check-types      # fail if generated.ts is stale
make synth            # CDK synth (no deploy)
make deploy           # CDK deploy to the current AWS account (DESTRUCTIVE infra)
make destroy          # tear down CryptaMap CDK stacks
```

> **Note on `go build`/`go test`:** scope Go commands to the module's own packages
> — `go build ./internal/... ./pkg/... ./cmd/...` (as the `make` targets and CI do).
> The CDK app vendors AWS CDK init-template `.go` files under `cdk/node_modules`
> that are not valid standalone Go, so a bare `go build ./...` / `go test ./...`
> reports errors on those template files. This is expected, not a build break.

## Repository layout

```
cmd/cryptamap/        CLI (cobra) + Lambda handler (build tag: lambda)
cmd/gen-ts/           Go→TypeScript type generator (single source of truth)
internal/scanner/     orchestrator, registry, mock-engine
internal/services/    99 per-service scanners
                      (datarest / transit / certmgmt / keymgmt / sdkpqc / runtime)
internal/taxonomy/    scanner-ID → friendly display name / AWS category (99 entries)
internal/pqc/         web-verified AWS PQC support matrix + primitive table (AsOf)
internal/merge/       pure org-wide dedup/merge engine (--org-merge)
internal/roadmap/     pure PQC migration roadmap ranker + roll-ups
internal/probing/     TLS prober + PQ-hybrid detector (v2 scaffold; not wired into v1 scans)
internal/output/      CycloneDX, ASFF, PQCC Excel, roadmap, S3, DynamoDB, PDF
internal/compliance/  9 framework mappers
internal/risk/        Mosca's Theorem + severity mapping
internal/org/         Organizations + STS assume-role
internal/config/      YAML loader + CLI overrides
internal/mock/        synthetic data generator
pkg/models/           CryptoAsset, Finding, ScanResult, MultiScanResult
cdk/                  TypeScript CDK app (5 stacks incl. OrgFanout)
dashboard/            React + Vite + AWS Cloudscape SPA
```

## License

MIT-0 (No Attribution). See `LICENSE`.
