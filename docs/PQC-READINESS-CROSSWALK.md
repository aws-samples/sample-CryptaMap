# CryptaMap ↔ AWS Config PQC-Readiness ↔ NIST: Vocabulary Crosswalk

**Status:** reference. CryptaMap does **not** adopt the AWS Config scanner's "Tier 1/2/3" labels (they collide with CryptaMap's own roadmap tiers and are a single-tool convention, not a standard). This doc is the translation layer for customers who run **both** tools.

If you have run the **AWS Config managed rule for PQC TLS readiness** (the "PQC-Readiness scanner") and also run CryptaMap, this page lets you line up the two outputs at a glance — and anchors both to the **NIST / industry-standard** binary so the mapping is honest rather than tool-specific.

## TL;DR

- CryptaMap's headline metric is **"% quantum-resistant"** — the share of assessable assets that are already quantum-resistant. We use **"quantum-resistant"** deliberately, matching **NIST IR 8547** and the **CycloneDX/CBOMkit** `quantum-safe | quantum-vulnerable | not-applicable | unknown` vocabulary.
- The AWS Config scanner's **Tier 1/2/3** ranking is a **single-Config-tool convention**. It is useful, but it is not an AWS-wide or industry standard — see [Why we don't adopt "Tier"](#why-cryptamap-does-not-adopt-tier).
- The two tools also have **very different scope** (below). A clean Config "Tier 1" tells you about your TLS endpoints; it does **not** mean your org is quantum-resistant.

## The crosswalk

| CryptaMap posture | CryptaMap maturity / `% quantum-resistant` | AWS Config PQC-Readiness tier | NIST / industry term | Migration priority |
|---|---|---|---|---|
| `pqc-ready` (pure PQC) **or** `pqc-hybrid` with a **TLS 1.3-only** floor | Stage 2 — counts toward `% quantum-resistant` | **Tier 1** — "PQ-ready (strongest)": TLS 1.3-only + PQC, Config priority *None* | **Quantum-resistant** | None / done |
| `pqc-hybrid` with a **TLS 1.2 + 1.3** floor (backward-compatible) | Stage 2 — counts toward `% quantum-resistant` | **Tier 2** — "PQ-ready (backward compatible)": TLS 1.2+1.3 + PQC, Config priority *Low* | **Quantum-resistant** (key exchange), with a downgrade-able floor | Low — tighten the TLS floor to 1.3 when clients allow |
| `non-pqc-classical` (RSA/ECDHE, no ML-KEM) | Stage 1 — NOT quantum-resistant | **Tier 3** — "Not PQ-ready": no PQC, Config priority *High* | **Quantum-vulnerable** | High — primary migration target |
| `legacy-tls` (TLS 1.0/1.1) | Stage 1 — NOT quantum-resistant | **Tier 3** — "Not PQ-ready" (also fails on protocol age) | **Quantum-vulnerable** (and classically deprecated) | High — fix the protocol first, then PQC |
| `no-encryption` | Stage 0 — not assessable for PQC | Out of scope (the rule evaluates TLS-enabled endpoints) | n/a — no cryptographic baseline | Highest — encrypt first; PQC is not assessable until a baseline exists |
| `symmetric-only` (AES-256 at rest) | Stage 2 — counts toward `% quantum-resistant` | **Out of tier scope** — the Config rule covers TLS endpoints, not at-rest symmetric data | **Quantum-resistant** (AES-256; Grover only halves effective strength) | None — already resistant |
| `unknown` | Excluded from the `% quantum-resistant` denominator | Not evaluated / `INSUFFICIENT_DATA` | **Unknown / unassessed** | Investigate to classify |

Notes on the mapping:

- **The TLS-1.3-only vs TLS-1.2+1.3 split is exactly what separates AWS Tier 1 from Tier 2.** CryptaMap captures it as an **optional protocol property** on the asset — the TLS floor (`cryptamap:tlsMinVersion`, the minimum version the endpoint's policy accepts) shown as "Minimum TLS version (floor)" in the asset detail panel — **not** as a separate posture or tier. A `pqc-hybrid` asset is quantum-resistant on the key-exchange axis whether its floor is 1.2 or 1.3. The floor is a *hardening* detail, not a readiness class.
- **`% quantum-resistant` denominator.** CryptaMap's headline ratio is `stage2 / (stage1 + stage2)` — i.e. quantum-resistant assets over all *assessable* assets. Stage-0 (`no-encryption`) and `unknown` are excluded from the denominator so an unencrypted resource never masquerades as a PQC "pass" and an unclassified one never silently counts either way.
- **Roadmap tier ≠ AWS tier.** CryptaMap's own `act-now | plan-watch | no-action` roadmap tiers are a **priority-to-fix** ordering (act-now = worst/most-urgent). AWS Config's Tier 1 = *best*. The two "tier" axes point in **opposite** directions — another reason CryptaMap keeps its vocabulary separate. Do not equate "CryptaMap act-now" with "AWS Tier 1".

## Scope: why a clean Config tier is not a clean bill of health

The two tools answer different questions.

| | AWS Config PQC-Readiness scanner | CryptaMap |
|---|---|---|
| What it inspects | TLS endpoints on **ALB / NLB / API Gateway** | **99 service scanners** across data-at-rest, in-transit, certificates/PKI, key management, SDK/library, runtime evidence |
| CloudFront | **Excluded** | Covered (viewer cert + minimum protocol version) |
| At-rest encryption | Not evaluated | Covered (S3, EBS, RDS, DynamoDB, KMS, …) |
| Output | AWS Config **COMPLIANT / NON_COMPLIANT** findings | Full **CycloneDX 1.7 CBOM** + prioritized PQC migration roadmap + compliance mappings + Security Hub ASFF |
| Vocabulary | Tier 1/2/3 (tool-specific) | NIST-anchored quantum-resistant / quantum-vulnerable + maturity ladder |

A "Tier 1 everywhere" Config result means your **load-balancer and API-Gateway TLS endpoints** are PQC-ready. It says nothing about CloudFront, at-rest data, certificate signature algorithms, or library/SDK crypto — all of which CryptaMap inventories and which can still be quantum-vulnerable.

## Why CryptaMap does not adopt "Tier"

The AWS "Tier 1/2/3 PQ-ready" labels appear in **one place**: the AWS Config PQC-readiness-scanner blog. They are **absent** from AWS's three core PQC references — the PQC landing page, the migration guidance, and the migration plan — and are not an industry standard. CryptaMap therefore treats "Tier" as a single-tool convention rather than a shared taxonomy, and additionally avoids the word because CryptaMap already uses "tier" for its own (oppositely-oriented) roadmap priority.

Instead, CryptaMap anchors to the universal axis that **is** standard:

- **NIST IR 8547** frames the transition as **quantum-vulnerable vs quantum-resistant**, on a **2030-deprecated / 2035-disallowed** timeline.
- **CycloneDX / IBM CBOMkit** emit `quantum-safe | quantum-vulnerable | not-applicable | unknown`.

(One caveat to keep the mapping honest: NIST **Security Categories 1–5** and the CycloneDX `nistQuantumSecurityLevel` 0–6 rank **algorithm strength**, not **asset readiness** — they are a different axis and are **not** what this crosswalk's "tier" column maps to.)

---

*Crosswalk of CryptaMap's posture/maturity vocabulary (`pkg/models/finding.go`, `dashboard/src/lib/posture.ts`) against the AWS Config PQC-Readiness scanner tiers and NIST IR 8547 / CycloneDX terminology. CryptaMap deliberately retains its own vocabulary and provides this table for cross-recognition only.*
