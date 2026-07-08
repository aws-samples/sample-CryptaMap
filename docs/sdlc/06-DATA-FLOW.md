# 06 — Data Flow

> **Audience & purpose:** For engineers and reviewers who need to follow a single
> datum from an AWS API response all the way to a dashboard pixel — what shape it
> takes at each hop, where it transforms, and where it physically lives. Every
> claim below is grounded in a `file:line` citation.

## Table of contents

1. [The one-paragraph pipeline](#1-the-one-paragraph-pipeline)
2. [Stage 1 — AWS API response → `CryptoAsset`](#2-stage-1--aws-api-response--cryptoasset)
3. [Stage 2 — `CryptoAsset` → `CryptoProperties` classification + posture](#3-stage-2--cryptoasset--cryptoproperties-classification--posture)
4. [Stage 3 — `CryptoAsset` → `Finding` + posture rollup](#4-stage-3--cryptoasset--finding--posture-rollup)
5. [Stage 4 — `ScanResult` → output artifacts](#5-stage-4--scanresult--output-artifacts)
6. [The CBOM schema (CycloneDX 1.7) field mapping](#6-the-cbom-schema-cyclonedx-17-field-mapping)
7. [Org-merge data flow (shards → S3 → hierarchical merge → org CBOM)](#7-org-merge-data-flow-shards--s3--hierarchical-merge--org-cbom)
8. [Dashboard data flow](#8-dashboard-data-flow)
9. [Data localization — where data lives](#9-data-localization--where-data-lives)
10. [Transformation-point index](#10-transformation-point-index)

Sibling SDLC docs (relative links): high-level design / architecture
[`04-HIGH-LEVEL-DESIGN.md`](./04-HIGH-LEVEL-DESIGN.md), low-level design /
scanners & classification/posture [`05-LOW-LEVEL-DESIGN.md`](./05-LOW-LEVEL-DESIGN.md),
API & org fan-out flow [`07-API-FLOW.md`](./07-API-FLOW.md), tech stack
[`08-TECH-STACK.md`](./08-TECH-STACK.md), test coverage
[`09-TEST-COVERAGE.md`](./09-TEST-COVERAGE.md), security & data localization
[`10-SECURITY-AND-DATA-LOCALIZATION.md`](./10-SECURITY-AND-DATA-LOCALIZATION.md).
Deeper background lives in [`../SCALING.md`](../SCALING.md) and
[`../SELF-UPDATING-KNOWLEDGE.md`](../SELF-UPDATING-KNOWLEDGE.md).

---

## 1. The one-paragraph pipeline

A scanner calls an AWS `List/Describe` API, turns each resource into a
`models.CryptoAsset` (stamping a **posture** string into a free-form
`Properties` map and a structured `CryptoProperties` block), the engine collects
all assets and derives one `models.Finding` per asset (posture × Mosca → severity
+ compliance mappings), the whole thing is wrapped in a `models.ScanResult`, and
the writers render that single struct into CycloneDX CBOM / ASFF / Excel / HTML /
roadmap files. For an org, each `(account,region)` shard is produced
independently, written to S3, then folded by a memory-bounded streaming merge into
a single org-wide CBOM + roadmap + summary that the dashboard reads.

```mermaid
flowchart LR
    AWS["AWS APIs<br/>(List/Describe)"] -->|SDK structs| SC["Scanner.Scan()"]
    SC -->|"[]CryptoAsset<br/>(+posture, +CryptoProperties)"| EN["Engine.Run()"]
    EN -->|"BuildFindings"| FN["[]Finding"]
    EN -->|assemble| SR["ScanResult<br/>(Assets + Findings + Summary)"]
    SR --> CBOM["CycloneDX 1.7 CBOM"]
    SR --> ASFF["ASFF JSON"]
    SR --> XLSX["PQCC Excel"]
    SR --> HTML["HTML report"]
    SR --> RM["Roadmap JSON/MD"]
    CBOM --> DASH["Dashboard SPA"]
    RM --> DASH
```

The two data-model files that everything pivots on are
`pkg/models/asset.go` (the asset/CBOM model) and `pkg/models/finding.go`
(the regulator-facing finding model). `pkg/models/scan.go` is the top-level
container.

---

## 2. Stage 1 — AWS API response → `CryptoAsset`

### 2.1 The contract

Every per-service scanner implements `ServiceScanner`
(`internal/scanner/types.go:14-18`):

```go
Name() string                 // canonical registry id, e.g. "s3", "kms_spec"
Category() models.Category    // primary category for severity defaults
Scan(ctx, cfg aws.Config) ([]models.CryptoAsset, error)
```

One `Scan` call = scanning one service in **one** `(account, region)` — the
`aws.Config` it receives is already region-scoped (`internal/scanner/types.go:14-18`).
A `Scan` returns a slice of `CryptoAsset`; it does **not** return findings — finding
generation is a separate, shared stage (§4).

### 2.2 The shape of a `CryptoAsset`

The asset is defined at `pkg/models/asset.go:153-168`. The load-bearing fields:

| Field | Source | Role downstream |
|---|---|---|
| `BomRef` | `models.BomRefForARN(arn)` — FNV-64a → `"crypto-"+16hex` (`pkg/models/asset.go:14`) | **The org-wide dedup key.** Shared by live + mock paths. |
| `Service` | scanner `Name()` | raw scanner id, kept for traceability |
| `Category` | one of `data-at-rest`, `data-in-transit`, `certificate`, `key-management`, `sdk-library` (`pkg/models/asset.go:23-29`) | severity defaults |
| `AccountID` / `Region` | scan context | provenance, dedup shard key |
| `ResourceARN` / `ResourceID` / `ResourceType` | scanner | identity; round-tripped via CBOM |
| `CryptoProps` | the structured `CryptoProperties` block (§3) | CBOM `cryptoProperties` |
| `Properties` | free-form `map[string]string` from the scanner | **where `posture` lives** + all detail k/v |
| `DiscoveredAt` | scan time | merge tie-break |

The shared builders that produce these live in `internal/services/common.go`:
`NewAsset` embeds the scan region in the ARN (`internal/services/common.go:74`),
while `NewAssetWithARN` takes a caller-supplied ARN and is used by **S3 only** to
emit a region-less `arn:aws:s3:::bucket` for org-wide dedup
(`internal/services/common.go:86`). `PostureProperty` stamps the classification
into `Properties["posture"]` (`internal/services/common.go:420`).

```mermaid
flowchart TD
    API["s3:ListBuckets + GetBucketEncryption"] --> CLS{"classify"}
    CLS -->|"rule present"| SYM["AESAtRest()<br/>→ SymmetricOnly"]
    CLS -->|"no rule / not-found"| UNK["UnknownAtRest()<br/>→ Unknown (encConfidence=default-sse-s3)"]
    SYM --> A["CryptoAsset"]
    UNK --> A
    A -->|"NewAssetWithARN(arn:aws:s3:::bucket)"| BR["BomRef = BomRefForARN(arn)"]
    A -->|"PostureProperty"| PP["Properties[posture]=..."]
```

> **Why the BomRef matters here:** it is computed at asset-creation time from the
> ARN, so the *same* logical resource produces the *same* `BomRef` whether it was
> discovered by a live scan or fabricated by `--mock` (`internal/mock/generator.go`
> uses the identical `BomRefForARN`). That single key is the entire basis for
> cross-account/cross-region dedup in the merge (§7).

---

## 3. Stage 2 — `CryptoAsset` → `CryptoProperties` classification + posture

There are **two parallel data channels** attached to each asset, and it is
important not to conflate them:

1. **`CryptoProperties`** (`pkg/models/asset.go:142-149`) — the *structured,
   CycloneDX-aligned* crypto description: `AssetType` + up to four optional
   sub-blocks (`AlgorithmProperties`, `CertificateProperties`, `ProtocolProperties`,
   `RelatedCryptoMaterialProperties`) + an `OID`. This is what becomes the CBOM
   `cryptoProperties` object.
2. **`Properties["posture"]`** — a *flat string* such as `symmetric-only`,
   `non-pqc-classical`, `legacy-tls`, `no-encryption`, `pqc-hybrid`, `pqc-ready`,
   `unknown` (the enum is `pkg/models/finding.go:35-43`). **This string — not a
   typed field — is the single input the finding stage reads for posture** (§4).

### 3.1 How posture is decided

The per-service classifiers route observed values through a posture mapper and
then call `PostureProperty`:

- **At-rest scanners** pick one of `AESAtRest`/`AESXTSAtRest` (→ `symmetric-only`),
  `NoEncryption` (→ `no-encryption`), or `UnknownAtRest` (→ `unknown`)
  (`internal/services/common.go:110,138,316,331`).
- **Key/cert scanners** route the *real keyspec/cert algorithm* through a mapper:
  `kmsSpecPosture` (`internal/services/keymgmt/kms_spec.go:36`),
  `payAlgoPosture`, `acmPosture`, `acmpcaPosture`, `parseCertPEM`.
- **In-transit scanners** classify the real SSL policy / IKE / SSH KEX
  (`internal/services/transit/ssl_policy.go:106`,
  `internal/services/transit/transit_classify.go`).
- **Runtime evidence** infers posture from CloudTrail activity
  (`runtimePosture` / `tlsObservedPosture` in
  `internal/services/runtime/cloudtrail_evidence.go:101,196`).

> **Invariant — posture lives in `Properties`, not a typed field.** A scanner that
> forgets to set `Properties["posture"]` silently yields `unknown` → `MEDIUM`
> rather than an error (`internal/scanner/findings.go:33-38`). See
> [`05-LOW-LEVEL-DESIGN.md`](./05-LOW-LEVEL-DESIGN.md) for the full per-archetype rubric.

### 3.2 The deeper-detail fields are additive

`AlgorithmProperties` carries extra `AlgorithmName`/`KeySizeBits`/`KMSKeySpec`
(`pkg/models/asset.go:66-82`) and `ProtocolProperties` carries
`KeyExchangeGroup`/`PQCHybrid`/`CertSignatureAlgorithm`/`CertKeySizeBits`/`Source`/
`TLSMinVersion` (`pkg/models/asset.go:104-124`). These do **not** fit inside the
CBOM's schema-frozen sub-objects, so the writer relocates them to flat
component-level properties (§6.2). `TLSMinVersion` is documented as a descriptive
negotiation **floor**, explicitly *not* a posture/tier and quantum-irrelevant
(`pkg/models/asset.go:104-124`).

---

## 4. Stage 3 — `CryptoAsset` → `Finding` + posture rollup

### 4.1 The single pure finding generator

`internal/scanner/findings.go:29-71` (`BuildFindings`) is the **one** place assets
become findings. For each asset it:

1. reads posture from `asset.Properties["posture"]`, defaulting to
   `PostureUnknown` (`internal/scanner/findings.go:33-38`);
2. computes a Mosca score via `risk.CalculateForService(service, overrides)` —
   Mosca's Theorem `Score = X + Y − Z` (`internal/risk/mosca.go:12-32`), where X/Y/Z
   come from per-service Indian-BFSI defaults (`internal/risk/defaults.go:14-85`);
3. sets the base severity from the posture (`sev = SeverityFromPosture(posture)`,
   `internal/scanner/findings.go:47`) and applies the **worse-of** Mosca/HNDL bump
   (`sev = HighestSeverity(sev, SeverityFromMosca(...))`, `findings.go:49`) **only
   when the posture is not already quantum-resistant** (`!risk.IsQuantumResistantPosture(posture)`,
   `findings.go:48`; `IsQuantumResistantPosture` true for `symmetric-only`/`pqc-hybrid`/
   `pqc-ready` at `internal/risk/severity.go:42-49`);
4. attaches `comp.MapAll(asset, posture)` compliance mappings when a registry is
   present (`internal/scanner/findings.go:51-53`).

> **Invariant — severity is posture-first, with a *gated* worse-of bump.** A
> genuinely vulnerable RDS asset (e.g. `non-pqc-classical`) has Mosca
> `10+2−3 = 9 → CRITICAL`, so the worse-of bump raises it to CRITICAL even though its
> posture alone might map lower — HNDL urgency rightly applies. But a quantum-resistant
> `symmetric-only` (AES-256) RDS asset stays **INFORMATIONAL** (its posture severity);
> the posture-blind Mosca score does **not** raise it, because Shor's algorithm does
> not threaten AES no matter how long-lived the data
> (`internal/risk/severity.go:24-35` for the posture mapping, `:42-49` for the gate).
> **Note:** before this commit the worse-of was applied
> *unconditionally*, so this same AES-256 store was wrongly stamped CRITICAL purely
> from its Mosca score (a real mock scan had 38 such quantum-resistant CRITICAL/HIGH
> findings; now 0, with the assets still inventoried — only re-graded). Genuinely
> vulnerable postures (`no-encryption`/`legacy-tls`/`non-pqc-classical`/`unknown`)
> keep the worse-of behavior unchanged.

`BuildFindings` is deliberately dependency-light (stdlib `fmt`/`hash/fnv`/`time` +
`internal/risk` + `internal/compliance` + `pkg/models`; it no longer imports `uuid`)
so that the **same function** produces
**identical *classification*** — posture, posture-first severity (worse-of Mosca
only for non-quantum-resistant postures), Mosca score, and compliance mappings, all
derived purely from the input asset — in three contexts:
a live engine run (via the `buildFindings` wrapper, `internal/scanner/engine.go:380-381`,
called from `Run` at `engine.go:203`), a `--mock` run
(`internal/scanner/mock_engine.go:34`), and the offline CBOM-replay path
(`cmd/cryptamap/org_merge_files.go:112`).

> **Caveat — findings are NOT byte-identical run-to-run.** The only volatile fields
> are the timestamps: `BuildFindings` computes one `now = time.Now().UTC()` per call
> and stamps it as `CreatedAt`/`UpdatedAt` on every finding
> (`internal/scanner/findings.go:29,92-93`). `Finding.ID` is now the **deterministic**
> content key `ID: stableFindingID(a, posture)` (`internal/scanner/findings.go:76`,
> helper `findings.go:99-121`) — `finding:<key>:<posture>`, where `<key>` is the
> asset's `BomRef` (or an FNV-64a hash of `account|region|service|resourceID` when
> absent) — so it is stable across runs and finding artifacts diff cleanly. What is
> reproducible is the *classification content* (posture/severity/Mosca/compliance)
> **and** the `ID`; only `createdAt`/`updatedAt` differ per invocation, so a purity /
> reproducibility test may rely on the stable `ID` and need only exclude the two
> timestamps.

### 4.2 The `Finding` shape

`pkg/models/finding.go:66-85`. Key fields and their downstream meaning:

| Field | Built from | Downstream |
|---|---|---|
| `Severity` | posture severity, with a worse-of Mosca bump only when `!IsQuantumResistantPosture` (`findings.go:47-49`) | ASFF `Severity.Normalized` (90/70/40/0 via `NormalizedSeverity`, `pkg/models/finding.go:16-29`); summary tallies |
| `Posture` | `Properties["posture"]` | ASFF `ProductFields[cryptamap:posture]`; roadmap |
| `AssetBomRef` | links back to `CryptoAsset.BomRef` | merge dedup key; ASFF product field |
| `Mosca` | `risk.CalculateForService` | ASFF product field; roadmap urgency |
| `Compliance[]` | `comp.MapAll` | ASFF `Compliance.RelatedRequirements` |
| `Recommendation` / `DocsURL` | package-level `recommendation()` (`internal/scanner/engine.go:261-275`, incl. the `PostureSymmetricOnly` case at `:269-270`) / `docsURL()` (`internal/scanner/engine.go:277-279`), called bare by `BuildFindings` (`internal/scanner/findings.go:70-71`) — these are plain funcs, **not** `Engine` methods | ASFF remediation |

### 4.3 Assembly into `ScanResult`

The engine's worker pool (`internal/scanner/engine.go:72-163`) collects all assets,
then calls `buildFindings` + `buildSummary` and returns a `models.ScanResult`
(`pkg/models/scan.go:25-37`) with `Mode="live"`. `buildSummary`
(`internal/scanner/engine.go:240-259`) tallies Critical/High/Medium/Informational
counts and a `ServiceCount` into a `ScanSummary` (`pkg/models/scan.go:6-14`).

```mermaid
flowchart LR
    A["CryptoAsset"] -->|"Properties[posture]"| P["posture string"]
    A -->|"service"| M["risk.CalculateForService<br/>(X+Y−Z)"]
    P --> SP["SeverityFromPosture<br/>(base)"]
    M --> SM["SeverityFromMosca"]
    SP --> H["HighestSeverity bump<br/>only if !IsQuantumResistantPosture"]
    SM --> H
    A --> CM["compliance.MapAll"]
    H --> F["Finding"]
    M --> F
    CM --> F
    F --> SUM["buildSummary<br/>(severity tallies)"]
    F --> SR["ScanResult"]
    SUM --> SR
```

---

## 5. Stage 4 — `ScanResult` → output artifacts

A single `ScanResult` fans out to every enabled writer. In the local CLI path,
`writeArtifacts` (`cmd/cryptamap/main.go:216-316`) keys every file off the prefix
`cryptamap-scan-<account>-<region>-<timestamp>`:

| Format | Writer entry point | File suffix |
|---|---|---|
| CycloneDX CBOM | `output.WriteCBOM` (`internal/output/cyclonedx.go:66`) | `.cbom.json` |
| PQCC Excel | `output.WritePQCCExcel` | `.pqcc.xlsx` |
| HTML report | `output.WriteHTMLReport` | `.report.html` |
| ASFF JSON | `output.WriteASFF` (`internal/output/securityhub.go:139`) | `.asff.json` |
| Raw scan | `json.MarshalIndent(scan)` | `.scan.json` |
| Roadmap | `output.WriteRoadmapJSON/Markdown` (`internal/output/roadmap_writer.go:20,29`) | `.roadmap.json` / `.roadmap.md` |
| PDF/MD summary | `output.WritePDFSummary` (only when `Formats.PDF`) | `.report.md` |

Note that the **CBOM carries assets, not findings**. ASFF, Excel, and the roadmap
all consume `scan.Findings` directly; the CBOM is intentionally lossy for findings,
which is why offline merge has to regenerate them (§7.4).

### 5.1 ASFF (Security Hub) mapping

`BuildASFFFinding` (`internal/output/securityhub.go:73-136`) maps one `Finding` to
one ASFF v2018-10-08 record: `Severity.Normalized` = `NormalizedSeverity(f.Severity)`,
deterministic `Id = cryptamap/<account>/<region>/<resourceId>/<findingId>`,
`Compliance.Status` derived from the finding's compliance statuses (`FAILED` if any
`non-compliant`, else `PASSED` if any `compliant`, else `NOT_AVAILABLE`), and the
posture/Mosca/BomRef carried in `ProductFields`.

### 5.2 Roadmap mapping

`roadmap.Build(scan)` (`internal/roadmap/roadmap.go:91`) ranks findings into a
`Roadmap` (`internal/roadmap/roadmap.go:80-86`) with `AsOf` and
`GeneratedFrom = scan.AccountID` ("org" for a merged result). Each `RoadmapItem`
carries a `PriorityScore = MoscaUrgency × PostureMultiplier × ExposureMultiplier +
EaseTieBreak` (`internal/roadmap/roadmap.go:163-182`), an effective `PQCStatus`,
`UpgradeEase`, and a `QuickWin` flag. The markdown writer renders a Top-25 table
plus per-service and per-account roll-ups (`internal/output/roadmap_writer.go:39-108`).

---

## 6. The CBOM schema (CycloneDX 1.7) field mapping

The CBOM is the canonical, portable artifact. It is produced by `buildCBOM`
(`internal/output/cyclonedx.go:73-206`) and consumed back by `ParseCBOM`
(`internal/output/cbom_reader.go:42-105`) — a **structurally lossless** round-trip
for a CBOM CryptaMap itself produced (identity, `ResourceID`/`ResourceType`,
postures, and deeper-detail crypto fields all survive), with **one deliberate
security asymmetry on ingest**: a CBOM is *untrusted input*, so `ParseCBOM` does
NOT round-trip the finding-suppressing `symmetric-only` posture verbatim — it
SANITIZES it (§6.3). The verbatim `posture` restore for a genuine live scan (the
in-process `WriteCBOM`→consumer path never re-parses) is unaffected; only the
file-ingest path (`org-merge-files`) re-classifies.

### 6.1 Top-level BOM document

`CDXBOM` (`internal/output/cyclonedx.go:20-27`):

```
bomFormat    = "CycloneDX"
specVersion  = "1.7"
serialNumber = "urn:uuid:<random>"
version      = 1
metadata     = { timestamp, tools[CryptaMap], component{application}, properties[] }
components[] = one per CryptoAsset
```

`metadata.properties` carry scan context + **PQC-knowledge provenance**: the writer
appends `knowledge:source/version/asOf/minAsOf/maxAsOf/factCount/digest` so every
CBOM records how fresh the post-quantum knowledge was at scan time
(`internal/output/cyclonedx.go:88-93,448-468`). The dashboard reads these back
generically. See [`../SELF-UPDATING-KNOWLEDGE.md`](../SELF-UPDATING-KNOWLEDGE.md).

`metadata.properties` also carry **scan-incompleteness markers** so a consumer handed
only the CBOM file (not the stderr log or side-car summary) can tell an incomplete
inventory from a clean one. `scanIncompletenessProps`
(`internal/output/cyclonedx.go:401-438`) emits, **only when non-clean** (so a clean
single-scan CBOM stays byte-identical to before):

- `cryptamap:truncated` = `"true"` + `cryptamap:truncatedServices` (comma-joined,
  sorted) when any scanner hit a cap (a `services.TruncationSentinel` error the engine
  appends);
- `cryptamap:scanErrors` = error count + `cryptamap:erroredServices` (comma-joined,
  sorted) when any scanner returned a real error — so "0 assets" from an auth failure
  is distinguishable from a legitimately empty account.

For an **org-merged** CBOM the sibling `coverageProps`
(`internal/output/cyclonedx.go:371-382`) additionally stamps the shard-reconciliation
barrier (`cryptamap:incomplete`/`expectedShards`/`observedShards`/`missingShards`/
`failedShards`); it returns nil (adds nothing) for a single live scan.

### 6.2 Component mapping (`CryptoAsset` → `CDXComponent`)

`CDXComponent` (`internal/output/cyclonedx.go:56-63`). The mapping in
`buildCBOM` (`internal/output/cyclonedx.go:106-201`):

| CBOM field | Source | Note |
|---|---|---|
| `type` | constant `"cryptographic-asset"` | |
| `bom-ref` | `asset.BomRef` | the FNV dedup key |
| `name` | `"<DisplayName> — <asset.Name>"` | friendly taxonomy, **internal scanner ids never leak into `name`** (`internal/output/cyclonedx.go:143`) |
| `description` | `asset.Description` | |
| `cryptoProperties` | `sanitizeForCDX(asset.CryptoProps)` | additive fields zeroed for schema validity (see below) |
| `properties[]` | `cryptamap:*` namespaced k/v | see property table |

The flat `properties[]` array carries everything else, namespaced `cryptamap:`:
`service` (raw scanner id), `category`, `accountId`, `region`, `resourceArn`, and
(when present) `resourceType`, **`resourceId`**, `displayName`, `awsCategory`,
`cryptoFunction`, `subAspect`, plus **every** `asset.Properties` entry — including
`posture` (`internal/output/cyclonedx.go:113-161`).

> **Losslessness of `ResourceID` (load-bearing).** `buildCBOM` now emits the
> `ResourceID` verbatim as `cryptamap:resourceId`
> (`internal/output/cyclonedx.go:129-135`), alongside the already-explicit
> `cryptamap:resourceType`. Previously the reader re-derived the id from the ARN via
> `resourceFromARN`, which splits on the **last** `/`
> (`internal/output/cbom_reader.go:396-410`) — so a slash-containing id such as a KMS
> alias `alias/aws/dynamodb` or an S3-path-style key would be **corrupted** (only the
> trailing segment survived) on re-ingest. Carrying the id as its own property makes
> the round-trip lossless for it; older CBOMs without the property still fall back to
> the ARN-split (`internal/output/cbom_reader.go:126-141`).

> **Schema-validity trick (load-bearing).** CycloneDX 1.7 marks
> `cryptoProperties.algorithmProperties` and `.protocolProperties` as
> `additionalProperties:false`. CryptaMap's *additive* detail fields
> (`AlgorithmName`, `KeySizeBits`, `KMSKeySpec`, `KeyExchangeGroup`, `PQCHybrid`,
> `CertSignatureAlgorithm`, `CertKeySizeBits`, `TLSMinVersion`) would be rejected if
> emitted inside those sub-objects. So `deeperDetailProps`
> (`internal/output/cyclonedx.go:497-549`) relocates them to flat
> `cryptamap:algorithmName` / `cryptamap:tlsMinVersion` / etc. component
> properties, and `sanitizeForCDX` (`internal/output/cyclonedx.go:579-635`) zeroes
> them out of the marshaled `cryptoProperties` (without mutating the in-memory
> model). The canonical CycloneDX fields (`ParameterSetIdentifier`, `Mode`,
> `ClassicalSecurityLevel`, …) are preserved.

```mermaid
flowchart TD
    CA["CryptoAsset"] --> CP["CryptoProperties"]
    CA --> PROPS["Properties map<br/>(posture, note, ...)"]
    CP -->|"sanitizeForCDX<br/>(zero additive fields)"| CC["cryptoProperties<br/>(schema-valid)"]
    CP -->|"deeperDetailProps"| FLAT["cryptamap:algorithmName,<br/>cryptamap:tlsMinVersion, ..."]
    PROPS -->|"cryptamap: prefix"| NS["cryptamap:posture,<br/>cryptamap:service, ..."]
    CC --> COMP["CDXComponent"]
    FLAT --> COMP
    NS --> COMP
```

> **Enum/shape coercion (also load-bearing).** Beyond the additive-field trick,
> `sanitizeForCDX` coerces values a scanner can legitimately produce that fall
> outside a CDX *enum*: `algorithmProperties.mode` not in the enum (e.g. the
> EBS/FSx/MGN disk-encryption mode `"xts"`) → `"other"` (true value kept as
> `cryptamap:mode`); `relatedCryptoMaterialProperties.state` not in the enum (e.g.
> `"unknown"`) → dropped (kept as `cryptamap:materialState`); and
> `ProtocolProperties.IkeV2TransformTypes` — a model `[]string` but a CDX *object* —
> is stripped and re-emitted as `cryptamap:ikev2TransformTypes`. `buildCBOM` also
> **dedups components by `bom-ref`** so a degraded AWS List response (two resources
> with empty/identical ids → identical ARN → identical bom-ref) cannot emit
> byte-identical components and fail the schema's `uniqueItems`.

### 6.2a The crypto dependency graph (resolvable references)

CycloneDX types `cipherSuites[].algorithms[]` and
`certificateProperties.signatureAlgorithmRef` as `refType` — each value MUST be
the `bom-ref` of an algorithm `cryptographic-asset` component **in the same BOM**,
so a consumer can answer "which certificates are signed by a quantum-vulnerable
algorithm" or "which protocols use which algorithms." Scanners populate these
fields with genuine algorithm *tokens* (e.g. `RSA-PSS-SHA-256-2048`, `ML-DSA-65`,
SSH/IPsec algorithm lists), so `linkCryptoAssetGraph`
(`internal/output/cyclonedx.go`) makes them resolvable: for each distinct token it
synthesizes one minimal `algorithm` component (deterministic `crypto-alg-<slug>`
bom-ref, marked `cryptamap:synthetic=true`, **name only — no fabricated
primitive/security-level**), then rewrites every reference to that bom-ref and
drops empty/whitespace tokens (which would violate the `refType` `minLength`).

```mermaid
flowchart LR
    CERT["certificate component<br/>signatureAlgorithmRef: 'RSA-PSS-SHA-256-2048'"] -->|rewritten to| REF["bom-ref crypto-alg-rsa-pss-sha-256-2048"]
    REF --> ALG["synthesized algorithm component<br/>(cryptamap:synthetic=true)"]
    PROTO["protocol component<br/>cipherSuites[].algorithms: ['mlkem768x25519-sha256', ...]"] -->|rewritten to| ALG
```

Synthetic algorithm nodes are **definitions, not discovered resources**: every
consumer that counts assets (`ParseCBOM` via `isSyntheticComponent`, the dashboard
via `realComponents`) excludes them, so they never inflate asset counts or create
phantom account/region shards. The result is a CBOM with **zero dangling
references** — verified by `internal/output/crypto_graph_test.go`.

### 6.3 The round-trip (`ParseCBOM`) — structurally lossless, posture sanitized

`componentToAsset` (`internal/output/cbom_reader.go:113-193`) reverses every step:
it de-prefixes `cryptamap:*` props, maps the structural props back to dedicated
fields, and folds the flat deeper-detail props back into `CryptoProps` via
`foldDeeperDetail` (`internal/output/cbom_reader.go:310-356`). It prefers the
explicit `cryptamap:resourceId` / `cryptamap:resourceType` properties and only falls
back to deriving them from the ARN for older CBOMs
(`internal/output/cbom_reader.go:126-141`) — this is why the writer emits both
explicitly: the region-less S3 ARN carries no `<type>/<id>` segment to re-derive
from, and `resourceFromARN`'s last-`/` split would otherwise corrupt a
slash-containing id (§6.2). Reconstructed shards have `Assets` populated but
**`Findings` empty** — the caller regenerates them via `BuildFindings`
(`internal/output/cbom_reader.go:22-27`).

> **Posture is SANITIZED on ingest, not restored verbatim (security).** An ingested
> CBOM is *untrusted input*, so `ParseCBOM` treats it as such rather than as a live
> scan (`internal/output/cbom_reader.go:54-64` forces a non-`live` `mode` so a
> hand-edited file cannot win merge source-precedence; `internal/output/cbom_reader.go:154-161`
> likewise drops `source`). The load-bearing case is `posture`: `BuildFindings`
> emits **no finding at all** for `posture=symmetric-only` (Grover-only,
> inventory-only — `internal/scanner/findings.go:40-47`), so a tampered file that
> flips a vulnerable asset to `symmetric-only` would silence its finding on ingest.
> `sanitizeIngestedPosture` (`internal/output/cbom_reader.go:216-233`) therefore
> honors an ingested `symmetric-only` **only when the file's own `cryptoProperties`
> corroborate a symmetric primitive** (`symmetricOnlyCorroborated`,
> `internal/output/cbom_reader.go:241-276`); an uncorroborated claim **degrades to
> `unknown`** (→ MEDIUM, "needs investigation") with an auditable `note`. All other
> postures round-trip verbatim (they still produce a finding, so they cannot make an
> asset vanish). This is deliberate minimal hardening — it raises tamper effort from
> a one-field flip to a consistent multi-field forgery; full protection needs shard
> signing, which ingestion does not yet do.
>
> This is why §6's opener calls the round-trip lossless **structurally** (identity,
> `ResourceID`, deeper-detail crypto all survive) but not blindly verbatim on the
> untrusted-ingest path. A genuine live scan never re-parses its own CBOM in-process,
> so a real scanner's `symmetric-only` is unaffected.

---

## 7. Org-merge data flow (shards → S3 → hierarchical merge → org CBOM)

The CLI scans only the single caller account (it loudly warns that `--org`/
`--accounts` are not honored, `cmd/cryptamap/main.go:173-177`). True org-wide
scanning is the build-tagged Lambda + Step Functions Distributed Map stack. The
data flow has three tiers.

```mermaid
flowchart TD
    SFN["Step Functions<br/>Distributed Map"] -->|"one event per<br/>(account,region)"| L1["Scanner Lambda<br/>handle() (scan)"]
    L1 -->|"AssumeRole + eng.Run"| RES["ScanResult shard"]
    RES -->|"PutCBOM (central creds)"| S3C["s3: scans/<acct>-<region>-<scan>.json<br/>(CycloneDX partial)"]
    RES -->|"PutBytes RAW JSON"| S3R["s3: scans/raw/&lt;runId&gt;/&lt;acct&gt;-&lt;region&gt;-&lt;scan&gt;.json"]
    RES -->|"PutScan"| DDB["DynamoDB: SCANS_TABLE<br/>(summary + gzip findings)"]
    S3R --> L2["MergeAccount Lambda (tier 1)<br/>streamMergeUnderPrefix"]
    L2 -->|"per-account merged object"| S3A["s3: scans/account-merged/&lt;runId&gt;/&lt;acct&gt;.json"]
    S3A --> L3["Merge Lambda (tier 2)<br/>streamAccountMergedObjects"]
    L3 -->|"buildMergeArtifacts"| OUT["s3: scans/latest/&lt;runId&gt;.cbom.json<br/>+ .roadmap.json/.md + .coverage.json + .json"]
    OUT --> DASH["Dashboard"]
```

### 7.1 Tier 0 — per-shard scan

`handle()` (`cmd/cryptamap/lambda.go:56-186`) loads the orchestrator's base config
(central region/creds), optionally `AssumeRole`s into the member account and
**eagerly verifies** the assumed identity (`cmd/cryptamap/lambda.go:100-118`) so a
denied role fails the shard visibly instead of returning a falsely-empty success.
It then runs the engine and writes, **all with the central base config**:

- the CycloneDX **partial** to `scans/<acct>-<region>-<scan>.json`
  (`cmd/cryptamap/lambda.go:145-153`, key built by `output.Key`,
  `internal/output/s3_writer.go:29-31`);
- the **raw** `ScanResult` JSON (assets **and** findings, verbatim) to
  `scans/raw/<runId>/<acct>-<region>-<scan>.json`
  (`cmd/cryptamap/lambda.go:155-171`, key from `rawScanKey`,
  `cmd/cryptamap/lambda_event.go:123-125`);
- a DynamoDB row (summary + gzip+base64 findings, or `findingsTruncated` if over
  the 300 KB inline cap) (`internal/output/dynamodb_writer.go:39-93`).

> **Why a raw JSON shard exists alongside the CBOM:** the CBOM is lossy for
> findings, so the merge would otherwise have to re-derive them. The raw shard
> carries findings verbatim, making the org merge lossless and avoiding re-running
> `BuildFindings` on the merge path (`cmd/cryptamap/lambda_event.go:22-26`).

### 7.2 The streaming merge primitive

`merge.Merger` (`internal/merge/streaming.go:28-66`) folds shards one at a time via
`Add`, retaining only the **deduped working set** (asset/finding maps) plus small
per-shard summaries — never the sum of all raw shards. Peak memory is bounded by the
number of *distinct resources*, not by shards × size, which is what removes the
org-merge OOM cliff ([`../SCALING.md`](../SCALING.md)). The batch `merge.Merge`
(`internal/merge/merge.go:70-81`) is reimplemented on top of `Merger` so there is a
**single dedup code path**, and `NewMerger(...).Add(...).Finish()` is byte-identical
to `Merge(...)` for the same input order.

**Asset dedup** keys on `BomRef`; on collision the higher `Source` wins, ties broken
by richer asset (more `Properties` keys), then later `DiscoveredAt`, then smaller
ARN (`internal/merge/merge.go:117-156`). **Finding dedup** keys on
`(AssetBomRef|ResourceARN)+Service+Posture`, keeping the highest
`NormalizedSeverity` (`internal/merge/merge.go:158-209`). Both produce fully
deterministic sorted output (total tiebreakers in
`internal/merge/streaming.go:268-298`).

### 7.3 Hierarchical tiers (S3 key layout)

| Tier | Lambda mode | Reads | Writes |
|---|---|---|---|
| 0 (scan) | default | member account APIs | `scans/raw/<runId>/<acct>-<region>-<scan>.json` |
| 1 (per-account) | `mergeAccount` | `scans/raw/<runId>/<acct>-*` | `scans/account-merged/<runId>/<acct>.json` |
| 2 (final) | `merge` | `scans/account-merged/<runId>/` | `scans/latest/<runId>.*` |

Tier 1 (`runMergeAccountMode`, `cmd/cryptamap/lambda_merge.go:147-196`) folds one
account's region shards via `streamMergeUnderPrefix` and emits an
`accountMergedObject` that pairs the deduped `Merged` ScanResult with that account's
**real** `(account,region)` coverage rows (`cmd/cryptamap/lambda_merge_core.go:110-119`).
Tier 2 (`runMergeMode`, `cmd/cryptamap/lambda_merge.go:213-288`) streams those via
`AddPreMerged` (`internal/merge/streaming.go:152-199`) so the merged envelope's
sentinel `AccountID="org"` never corrupts the per-account succeeded/failed rollup. If
no per-account objects exist (legacy/pre-hierarchical run), tier 2 falls back to
streaming the raw shards directly (`cmd/cryptamap/lambda_merge.go:233-242`). S3 keys
are fetched with a bounded prefetch pool (concurrency 16) but **folded sequentially
in lexicographic key order** to preserve determinism
(`cmd/cryptamap/lambda_merge.go:69-139,290-295`).

### 7.4 Final artifacts + completion barrier

`buildMergeArtifacts` (`cmd/cryptamap/lambda_merge_core.go:136-176`) renders the
merged `Result` into the `scans/latest/<runId>.*` set using the **same**
`WriteCBOM` / `WriteRoadmapJSON` / `WriteRoadmapMarkdown` as the local path:

| Key | Content |
|---|---|
| `scans/latest/<runId>.cbom.json` | merged org CycloneDX CBOM |
| `scans/latest/<runId>.roadmap.json` / `.roadmap.md` | org PQC roadmap |
| `scans/latest/<runId>.coverage.json` | per-shard coverage matrix |
| `scans/latest/<runId>.json` | dashboard-compatible `mergeSummary` |

The `mergeSummary` (`cmd/cryptamap/lambda_merge_core.go:55-108`) carries
per-account rollups, a per-posture count (`summarizePostureCounts`, which buckets on
the same `cryptamap:posture` value the CBOM stamps,
`cmd/cryptamap/lambda_merge_core.go:257-278`), the honest posture **breakdown**
plus two derived headline callouts — `quantumVulnerablePct`
(`(legacyTLS + nonPQCClassical) / total-classifiable`) and `pqcEndToEndPct`
(`pqcReady / total`, hybrid-with-classical-cert deliberately excluded) — which
together REPLACE the retired single `quantumSafePct` number that conflated
symmetric-only AES-256-at-rest with genuine PQC migration
(`cmd/cryptamap/lambda_merge_core.go:284-294`), and a
**completion barrier**: `expectedShards` vs `observedShards` →
`missingShards`/`complete`, so a decimated run never reports a clean, silently-smaller
result (`cmd/cryptamap/lambda_merge_core.go:211-225`).

### 7.5 The offline equivalent (`org-merge-files`)

`cryptamap org-merge-files` (`cmd/cryptamap/org_merge_files.go:70-142`) does the
same merge from **local CBOM files** with no AWS at all: it `ParseCBOMFile`s each
input into shards, regenerates findings via `BuildFindings`
(`cmd/cryptamap/org_merge_files.go:97`) — because CBOMs are findings-lossy — then
`merge.Merge` + writes the merged CBOM + roadmap + coverage. This is the
no-network, no-mutation demonstration of the merge pipeline. It is also the **one
consumer that re-parses an untrusted CBOM file**, so it is where the ingest-side
hardening of §6.3 actually bites: a hand-edited shard's `mode`/`source`/uncorroborated
`symmetric-only` `posture` are neutralized by `ParseCBOM` before `BuildFindings`
runs, so a crafted file can neither outrank a real scan in dedup nor silence a
vulnerable asset's finding.

---

## 8. Dashboard data flow

The dashboard is a static React SPA. It first fetches `/config.json`
(`dashboard/src/services/api.ts:22-35`); the shape `{ apiBase, mockMode }` decides
the data source:

- **Local / mock mode** (`mockMode:true` or no `apiBase`): it reads the static
  `/mock/org-cbom.json` and `/mock/roadmap.json`
  (`dashboard/src/services/api.ts:37-54,163-178`). The Overview KPIs are derived
  client-side from the CBOM via `summaryFromCBOM` (`dashboard/src/services/api.ts:111-141`),
  which counts `perPosture`/`totalCritical` inline (api.ts:117-128) but **delegates** the
  headline posture-bucketing and the breakdown/callout maturity math (`quantumVulnerablePct`,
  `pqcEndToEndPct`) to `summarizePosture` / `summarizeMaturity`, imported from `../hooks/useScanData`
  (`dashboard/src/services/api.ts:3,112-113`) — so the breakdown callouts are computed in
  `dashboard/src/hooks/useScanData.ts`, not in `api.ts`.
- **Live mode** (dormant — not provisioned by anything CryptaMap ships): if a
  non-empty `apiBase` were configured, the client would GET `${apiBase}/cbom`,
  `${apiBase}/summary`, and `${apiBase}/roadmap`
  (`dashboard/src/services/api.ts`). The `/scans` and `/history` client helpers
  were dead code (zero call sites after the local-first redesign removed those
  endpoints) and have been deleted. **No CryptaMap component ever sets
  `apiBase`** — the query API + CloudFront dashboard that once backed this branch
  were removed in the local-first redesign, and `cryptamap serve` hard-codes
  `apiBase:""`. The branch is retained only as an extension point for an operator
  who chooses to self-host their own backend; CryptaMap provisions none.

```mermaid
flowchart TD
    SPA["Dashboard SPA"] -->|"GET /config.json"| CFG{"mockMode? (always yes — apiBase empty)"}
    CFG -->|"static-file mode<br/>(the only mode shipped)"| MOCK["/mock/org-cbom.json<br/>/mock/roadmap.json"]
    CFG -. dormant: only if an operator self-hosts a backend .-> API["GET apiBase/cbom"]
    MOCK --> RENDER["summaryFromCBOM /<br/>KPIs, maturity ladder"]
    API --> RENDER
```

### 8.1 The offline `serve` command

`cryptamap serve` (`cmd/cryptamap/serve.go:55-101`) is how the merged artifacts feed
the dashboard with no AWS. It binds **`127.0.0.1` only** — there is deliberately no
bind-all/`--host` flag (`cmd/cryptamap/serve.go:48,85,139`). It resolves the local CBOM +
roadmap from `--dir`, synthesizes `/config.json` as `{apiBase:'', mockMode:true}`,
serves the artifacts at `/mock/org-cbom.json` and `/mock/roadmap.json`, and serves
the embedded SPA (`web_embed.go go:embed all:webdist`,
`cmd/cryptamap/web_embed.go:18-19`) with index.html fallback for deep links
(`cmd/cryptamap/serve.go:117-133`). It makes **no AWS or network calls**.

> **Build dependency — the committed `webdist/` is only a PLACEHOLDER `index.html`.**
> `go:embed` cannot reach `dashboard/dist` (it is outside `cmd/cryptamap`), so the
> committed `cmd/cryptamap/webdist` holds a stub `index.html` purely to keep a plain
> `go build` compiling (`cmd/cryptamap/web_embed.go:8-13`). The **real** Vite bundle is
> staged into `cmd/cryptamap/webdist` only by `make build-serve` (`Makefile:23-29`)
> *before* `go build`. A binary from a vanilla `go build` / `make build-cli` therefore
> serves the placeholder shell, **not** the real dashboard — and if even that stub is
> missing, `serveIndex` returns `dashboard bundle missing index.html (run \`make build-serve\`)`
> (`cmd/cryptamap/serve.go:375`). Use `make build-serve` (or a release build) to embed the
> real SPA.

---

## 9. Data localization — where data lives

```mermaid
flowchart LR
    subgraph member["Member account (e.g. ap-south-1 / India)"]
      APIs["AWS APIs"]
    end
    subgraph central["Central account (orchestrator's home region)"]
      S3["Results S3 bucket<br/>(SSE-KMS / CMK default)"]
      DDB["SCANS_TABLE"]
    end
    subgraph local["Operator laptop / Cloud Desktop"]
      DIST["./dist/scan-output/*.cbom.json"]
      SERVE["cryptamap serve (127.0.0.1)"]
    end
    APIs -->|"read-only describe<br/>(assumed role)"| ENG["Scanner Lambda / CLI"]
    ENG -->|"central creds"| S3
    ENG --> DDB
    ENG -->|"local artifact-first"| DIST
    DIST --> SERVE
```

**Where data lives:**

- **Local-first (default A/D model):** the CLI writes only local files under
  `cfg.Output.LocalDir` (`./dist/scan-output`); no S3/DynamoDB write happens in the
  CLI scan path — data never leaves the account/laptop. The merged org artifacts can
  be served entirely offline via `cryptamap serve` on `127.0.0.1`.
- **Central account (org fan-out):** the Lambda path writes CBOM partials, raw
  shards, and merged artifacts to the **central** results bucket and DynamoDB table,
  always using the orchestrator's own (base) config — never the assumed
  member-account role (`cmd/cryptamap/lambda.go:142-147,155-171`). The base config's
  region is **kept at the central home region on purpose**: repointing it to the
  scan region caused a cross-region write failure where only `us-east-1` shards
  landed (verified 2026-06-04, documented at `cmd/cryptamap/lambda.go:73-78`).
- **At rest:** S3 PutObjects set **no explicit `ServerSideEncryption` header**, so
  every object inherits the results bucket's **default encryption — a customer-managed
  KMS CMK** (`internal/output/s3_writer.go:39-46`, `cmd/cryptamap/lambda_merge.go:259-266`;
  bucket default at `cdk/lib/data-stack.ts:65-83`). A bucket resource policy additionally
  **denies** any `s3:PutObject` whose `s3:x-amz-server-side-encryption` is not `aws:kms`
  (`cdk/lib/data-stack.ts:93-104`), so a future writer regression to SSE-S3 fails at put
  time. (Earlier revisions forced `ServerSideEncryption: AES256`, which silently overrode
  the CMK — removed as part of the SSE-KMS remediation.)
- **Member-account access is read-only:** scanners issue only `List`/`Describe`
  calls; the assumed role is verified before any scan (`cmd/cryptamap/lambda.go:100-118`).

**No network-exposed serving path:** there is no deployed dashboard API that serves
the org CBOM — the query API + CloudFront dashboard (which an earlier design backed
with a presigned-S3 / streamed-Lambda path) were removed in the local-first redesign.
The local-first principle is why the offline `serve` command is hard-pinned to
`127.0.0.1` with no bind-all option (`cmd/cryptamap/serve.go:48,85,139`), and why the
only supported way to view the inventory is local-artifact-first (loopback `serve` or
the signed HTML report) rather than any public-by-default surface.

---

## 10. Transformation-point index

The exact lines where data changes shape — useful as a jump table.

| Transformation | Function | Citation |
|---|---|---|
| ARN → dedup `BomRef` | `BomRefForARN` | `pkg/models/asset.go:14` |
| AWS struct → `CryptoAsset` | `NewAsset` / `NewAssetWithARN` | `internal/services/common.go:74,86` |
| classification → `Properties["posture"]` | `PostureProperty` | `internal/services/common.go:420` |
| keyspec → posture | `kmsSpecPosture` | `internal/services/keymgmt/kms_spec.go:36` |
| SSL policy → posture/version/floor | `classifySSLPolicy` | `internal/services/transit/ssl_policy.go:106` |
| assets → `[]Finding` (the pure spine) | `BuildFindings` | `internal/scanner/findings.go:29-71` |
| posture+Mosca → severity | `HighestSeverity` | `internal/risk/severity.go:38-43` |
| Mosca X+Y−Z | `Calculate` | `internal/risk/mosca.go:12-23` |
| assets+findings → `ScanResult` | `Engine.Run` | `internal/scanner/engine.go:72-163` |
| `ScanResult` → CBOM | `buildCBOM` | `internal/output/cyclonedx.go:73-206` |
| additive fields → flat props | `deeperDetailProps` / `sanitizeForCDX` | `internal/output/cyclonedx.go:497-635` |
| incompleteness → CBOM metadata | `scanIncompletenessProps` / `coverageProps` | `internal/output/cyclonedx.go:401-438,371-382` |
| CBOM → `ScanResult` (round-trip) | `componentToAsset` | `internal/output/cbom_reader.go:113-193` |
| ingested posture sanitize (untrusted) | `sanitizeIngestedPosture` | `internal/output/cbom_reader.go:216-233` |
| `Finding` → ASFF | `BuildASFFFinding` | `internal/output/securityhub.go:73-136` |
| `ScanResult` → Roadmap | `roadmap.Build` | `internal/roadmap/roadmap.go:91` |
| shard fold (memory-bounded) | `Merger.Add` / `AddPreMerged` | `internal/merge/streaming.go:72-199` |
| merged → org artifacts | `buildMergeArtifacts` | `cmd/cryptamap/lambda_merge_core.go:136-176` |
| merged → dashboard summary | `buildMergeSummary` | `cmd/cryptamap/lambda_merge_core.go:181-250` |
| CBOM → dashboard KPIs | `summaryFromCBOM` | `dashboard/src/services/api.ts:111-141` |

> **Determinism guarantee threading through all of it:** because `BomRefForARN`,
> `BuildFindings`, and the `Merger` are pure and order-stable, the same input
> resources produce **identical classification** — the same `BomRef`s, postures,
> severities (posture-first, with the worse-of Mosca bump gated on
> `!IsQuantumResistantPosture`), Mosca scores, and compliance mappings, in the same sorted
> order — whether they come from a live scan, `--mock`, the offline
> `org-merge-files` replay, or the org Lambda merge. This is the property the whole
> multi-path architecture relies on. Note it is *classification* determinism, not
> byte-for-byte output: each `Finding` gets one per-call `CreatedAt`/`UpdatedAt`
> `time.Now().UTC()` timestamp (`internal/scanner/findings.go:29,92-93`) — its `ID` is
> the **deterministic** `stableFindingID(a, posture)` content key (`findings.go:76`),
> stable across runs — and each CBOM gets a fresh `urn:uuid` `serialNumber` (§6.1),
> so the serialized bytes vary run-to-run only on the finding timestamps and the CBOM
> serial number, even when the classified content and finding ids are identical.
