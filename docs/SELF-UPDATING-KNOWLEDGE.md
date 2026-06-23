# CryptaMap Self-Updating PQC Knowledge — Design

**Status:** design-only (approved 2026-06-08). Build scheduled AFTER the current data-completeness + scalability queue. This document is the contract for that later implementation.

## Problem

CryptaMap's post-quantum knowledge — the per-service PQC support matrix (`internal/pqc/matrix.go`) and the per-scanner "Type-C" documented crypto facts (e.g. "EBS at-rest is AES-256-XTS", "DynamoDB at-rest is always AES-256 and cannot be disabled") — is **compiled into the Go binary**. Each entry already carries `SourceURL` and `Confidence`, and the matrix carries an `AsOf` date.

That is correct and auditable, but **frozen at build time**. As AWS ships new PQC capabilities (new `-PQ-` TLS policies, ML-DSA key specs, new hybrid groups), the baked-in facts go stale until a maintainer edits `matrix.go` and cuts a release. We want the knowledge to **stay current** without that manual loop — while never breaking customers who run with no internet.

## Decisions (locked)

1. **Baked-in baseline is mandatory and always sufficient.** The binary must produce correct (point-in-time) classifications with **zero network/doc access**. Air-gapped targets (Indian BFSI, GovCloud, egress-blocked) are first-class. The refresh layer is **strictly optional** and may never be a precondition for a scan.
2. **Refresh is customer-side**, using the **public** `awslabs.aws-documentation-mcp-server` (installable via `uvx`, no AWS-internal access). When online, the tool can refresh its knowledge; when offline, it falls back to baked-in. Graceful degradation, both modes supported.
3. **Internal AWS documentation tools (maintainer-only).** Any maintainer-only documentation tooling that is unavailable to customers may appear **only** in the build/release path that regenerates the baked-in defaults — **never** in any customer runtime path.

## Architecture

### Knowledge as data, not code (prerequisite refactor)
Today the matrix + Type-C facts are Go literals. Step one is to make the knowledge **loadable**:

- Define a versioned knowledge file (e.g. `pqc-knowledge.json`) holding the matrix rows + Type-C facts, each with `{ value, sourceURL, confidence, asOf }`.
- The binary **embeds** this file (`go:embed`) as the baked-in default — so a no-network binary is unchanged in behavior.
- At startup the loader does: **embedded default → overlay an on-disk/refreshed copy if present and newer** (validated). This single override point is what the refresh writes to.
- `internal/pqc` reads from the loaded knowledge instead of hardcoded literals. (Keep the existing `EffectivePQCStatus` logic; only the data source changes.)

### Refresh flow (customer-side, online-only)
1. A `cryptamap refresh-knowledge` command (or a scheduled Lambda mode) runs **only when explicitly invoked / online**.
2. It connects to the public `awslabs.aws-documentation-mcp-server` (the deploy bundles/auto-installs it via `uvx` for customers who lack it; if the MCP is unreachable, refresh **no-ops with a clear log** and the baked-in knowledge stands).
3. For each refreshable fact, it re-queries the authoritative AWS doc, compares against the current value, and produces a **proposed** updated knowledge file with refreshed `asOf` + `sourceURL` + `confidence`.
4. **Safety gate:** a refresh may only *update values and dates / add new rows*; it must not silently flip a "supported" into "not supported" or downgrade a posture without surfacing a diff. Default posture is **review, not auto-apply** for any change that would alter a classification — write the proposed file + a diff report; apply automatically only for additive/non-classification-changing updates (configurable).
5. The validated file is written to the override location; the next scan loads it.

### Maintainer-side regeneration (release path)
Independently, maintainers regenerate the **embedded default** for each release using the best available AWS documentation sources. This keeps the air-gapped floor fresh per release and is the trusted source of the embedded `pqc-knowledge.json`. Same knowledge-file format → the customer refresh and the maintainer regeneration are the same mechanism pointed at different doc sources.

## Air-gap behavior (explicit)
| Environment | Behavior |
|---|---|
| Online, MCP present | Baked-in default + optional refresh; facts can self-update (review-gated for classification changes). |
| Online, MCP absent | Deploy auto-installs the public MCP via `uvx`; if install blocked, refresh no-ops, baked-in stands. |
| Air-gapped | Baked-in embedded knowledge only. Refresh command no-ops with a clear message. **Scans fully functional.** |

## What this does NOT do
- It does **not** add a runtime doc dependency to *scanning* — only to the *optional refresh* step.
- It does **not** use any AWS-internal tooling in the customer path.
- It does **not** auto-apply classification-altering changes without a surfaced diff (guards against a bad doc-parse becoming a silent misclassification — the exact failure class hardened against elsewhere in this project).

## Implementation checklist (for the later build)
- [ ] Extract matrix + Type-C facts into an embedded `pqc-knowledge.json` (`go:embed`); `internal/pqc` loads it.
- [ ] Loader with embedded-default → validated-override precedence.
- [ ] `cryptamap refresh-knowledge` command + (optional) Lambda mode; public-MCP client; offline no-op.
- [ ] Diff/review gate for classification-changing updates; additive auto-apply path.
- [ ] Deploy: bundle/auto-install `awslabs.aws-documentation-mcp-server` for customer self-update; document the air-gap path.
- [ ] Maintainer regeneration tool (build-time, may use internal docs) emitting the same format.
- [ ] Tests: embedded default loads with no network; override precedence; refresh no-op when offline; review-gate blocks a classification flip.

*Generated 2026-06-08. Prereq: finish the data-completeness (33 gaps) + scalability (§4) queue first.*
