# CryptaMap — SDLC Documentation

This folder is the **reverse-engineered SDLC documentation set** for CryptaMap: a numbered series of design documents (`01` … `10`) that together describe what the system requires, who uses it, how it is built, how data flows through it, what it is made of, how it is tested, and how it is secured. Every factual claim in these docs is grounded in the actual source with a `file:line` citation — they describe the code *as it is*, not as it was once planned.

**Audience.** Engineers (new and contributing), product/program owners, open-source contributors, and security/compliance auditors. Each doc opens with its own audience-and-purpose header; the [reading orders](#reading-order-by-audience) below point each audience at the right starting subset.

**Scope note.** These docs are descriptive, not aspirational. Where the code diverges from older prose (for example dead CLI config knobs), the relevant doc calls the divergence out explicitly rather than papering over it. The registry wires **99** scanners as of the 2026-06-15 coverage-expansion (was 86; the skipped-services audit promoted 13 to v1) — the count is self-tracking via `registeredScannerCount()` and pinned by `count_guard_test.go`.

**Change record.** [`CHANGELOG.md`](../../CHANGELOG.md) records the must-fix batch (H1–H6 + C2) and the cross-validation review behind it: the per-fix commit, files touched, behavior change, and regression test for the six fixes that landed 2026-06-15.

---

## The document set

| # | Document | What it covers | Sections |
|---|----------|----------------|---------:|
| 01 | [Requirements Specification](01-REQUIREMENTS.md) | Reverse-engineered functional (FR), non-functional (NFR), and security/data-localization (SEC) requirements, plus a full traceability matrix and a known-gaps register. | 7 |
| 02 | [User Stories](02-USER-STORIES.md) | 5 personas and 37 user stories across 6 epics (Discover/Classify/Prioritize/Comply/Operate/Extend), each marked Built / Partial / Backlog. | 10 |
| 03 | [User Journeys](03-USER-JOURNEYS.md) | Five end-to-end journeys (local scan, org fan-out, auditor review, adding a scanner, air-gapped operator) with diagrams and code paths. | 7 |
| 04 | [High-Level Design](04-HIGH-LEVEL-DESIGN.md) | C4 system-context and container views, the five crypto dimensions, scan engine, analysis layer, output writers, three run modes, org fan-out, and deployment topology. | 13 |
| 05 | [Low-Level Design](05-LOW-LEVEL-DESIGN.md) | The Go core in detail: data model, `ServiceScanner` contract, registry, engine pool/retry, classification, risk engine, knowledge loader, merge, roadmap ranker, plus how-to-add-a-scanner. | 15 |
| 06 | [Data Flow](06-DATA-FLOW.md) | A datum traced end-to-end: AWS API → `CryptoAsset` → classification → `Finding` → `ScanResult` → output artifacts, with the CycloneDX 1.7 field mapping and the org-merge flow. | 10 |
| 07 | [API Flow](07-API-FLOW.md) | The read-only AWS APIs each scanner *calls*, the CLI commands/flags, the Lambda event contract, and how the local-first dashboard loads its data. | 6 |
| 08 | [Tech Stack](08-TECH-STACK.md) | Layer-by-layer technology × version × rationale matrix (Go core, AWS SDK v2, analysis/output, React dashboard, CDK infra, build/CI, codegen) grounded in the manifests. | 5 |
| 09 | [Test Coverage](09-TEST-COVERAGE.md) | The three-layer test strategy that ships and runs in CI (per-scanner fake-client + systemic honesty-invariants + adversarial fuzz/e2e), a verified per-package coverage table, the internal-only Layer 4 live-validation harness, and a prioritized P0–P3 gap list. | 9 |
| 10 | [Security & Data Localization](10-SECURITY-AND-DATA-LOCALIZATION.md) | Threat model, read-only IAM posture, cross-account confused-deputy guard, secure-by-default CDK, the no-anonymous-data-path serving design, data-localization guarantees, and a reviewer checklist. | 9 |

---

## Reading order by audience

### New engineer
You want a working mental model fast, then enough depth to make a change safely.

1. [04 — High-Level Design](04-HIGH-LEVEL-DESIGN.md) — the big picture and the major subsystems.
2. [03 — User Journeys](03-USER-JOURNEYS.md) — see the system run end-to-end (especially Journey A and Journey D).
3. [05 — Low-Level Design](05-LOW-LEVEL-DESIGN.md) — the Go core, the `ServiceScanner` contract, and the "how to add a new scanner" walkthrough.
4. [06 — Data Flow](06-DATA-FLOW.md) — how a single asset becomes a finding becomes a CBOM.
5. [08 — Tech Stack](08-TECH-STACK.md) and [09 — Test Coverage](09-TEST-COVERAGE.md) — what you build with and how you verify your change.

### Product / program owner
You care about scope, who benefits, and what is actually built versus planned.

1. [01 — Requirements Specification](01-REQUIREMENTS.md) — the full FR/NFR/SEC scope and the known-gaps register.
2. [02 — User Stories](02-USER-STORIES.md) — personas, epics, and the Built/Partial/Backlog status rollup.
3. [03 — User Journeys](03-USER-JOURNEYS.md) — the value delivered per journey.
4. [04 — High-Level Design](04-HIGH-LEVEL-DESIGN.md) §§1–4 — what the system is and its five crypto dimensions.

### OSS contributor
You want to extend a scanner or wire a new capability and stay within the project's invariants.

1. [05 — Low-Level Design](05-LOW-LEVEL-DESIGN.md) — start here; §14 is the step-by-step add-a-scanner guide and §15 is the must-not-break invariants.
2. [03 — User Journeys](03-USER-JOURNEYS.md) Journey D — the same task as a narrative.
3. [07 — API Flow](07-API-FLOW.md) — the read-only AWS call discipline your scanner must follow.
4. [08 — Tech Stack](08-TECH-STACK.md) and [09 — Test Coverage](09-TEST-COVERAGE.md) — toolchain, codegen drift guards, and where tests are expected.
5. [02 — User Stories](02-USER-STORIES.md) Epic: Extend — the contributor-facing stories.

### Auditor / security reviewer
You want assurance about data handling, least privilege, and the serving-layer design.

1. [10 — Security & Data Localization](10-SECURITY-AND-DATA-LOCALIZATION.md) — start here; threat model, IAM posture, confused-deputy guard, the local-first no-web-surface serving design, and the reviewer checklist.
2. [01 — Requirements Specification](01-REQUIREMENTS.md) §5 — the SEC-1…SEC-6 data-localization and security constraints.
3. [06 — Data Flow](06-DATA-FLOW.md) §9 — where data lives and how the local-first viewer reads it.
4. [07 — API Flow](07-API-FLOW.md) §2 — why no query API is exposed and how the dashboard loads data locally.
5. [09 — Test Coverage](09-TEST-COVERAGE.md) — the three-layer correctness net (systemic honesty-invariants, adversarial fuzz, end-to-end pipeline — all CI-gated), and the now-narrowed manual/out-of-band caveats.

---

## Related deep-dives (one level up, in [`../`](../))

These pre-existing documents are referenced throughout the SDLC set and provide implementation-level detail beyond the design docs:

- [`../VALIDATION.md`](../VALIDATION.md) — the end-to-end validation strategy: Layers 1–3 ship in the repo and gate CI, while Layer 4 (the resource-provisioning live-validation harness) is run internally only.
- [`../SCALING.md`](../SCALING.md) — large-org scalability bottlenecks and mitigations.
- [`../SELF-UPDATING-KNOWLEDGE.md`](../SELF-UPDATING-KNOWLEDGE.md) — the PQC knowledge-refresh design.
- [`../COVERAGE-AND-GAPS.md`](../COVERAGE-AND-GAPS.md) — service-coverage analysis.
- [`../PQC-READINESS-CROSSWALK.md`](../PQC-READINESS-CROSSWALK.md) — compliance-framework verification.
- [`../../CHANGELOG.md`](../../CHANGELOG.md) — change/remediation history (the must-fix batch and cross-validation review). The backlog that 02's Partial/Backlog statuses cross-reference now lives in GitHub Issues.
