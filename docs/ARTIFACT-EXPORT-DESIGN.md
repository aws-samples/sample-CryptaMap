# Design — Artifact discovery & download in the dashboard

> Status: IMPLEMENTED (serve-mode). The serve-mode download panel + discoverability
> note shipped — surfaced on an Overview teaser (`dashboard/src/components/ReportsTeaser.tsx`)
> and a dedicated Reports page (`dashboard/src/pages/ReportsView.tsx` + `ExportButton.tsx`),
> backed by the `/artifacts/` routes and `/artifacts/manifest.json` in
> `cmd/cryptamap/serve.go`. This doc is retained as the design rationale. A deployed-mode
> (network) download path is intentionally **not** built — CryptaMap is local-first and
> exposes no query API (see §3).

## 1. Problem (verified)

CryptaMap writes a full artifact set natively at scan time, but **nothing in the
dashboard tells a customer these files exist, where they are, or lets them get
them.** A customer who only opens `cryptamap serve` would not know the CycloneDX
CBOM — the actual regulator deliverable — is sitting in their output dir. There is
no export/download UI anywhere today (verified: `rg download|export|cyclonedx` in
dashboard/src returns only JS `export` keywords).

## 2. What the CLI writes, and where (ground truth)

Default dir: **`./dist/scan-output/`** (override `-o <dir>`; `serve --dir <dir>`).
Files (from `cmd/cryptamap/main.go` writeArtifacts/writeRoadmap/writeOrgMerge):

| Suffix | Artifact | Per-scan prefix | Org-merge prefix |
|---|---|---|---|
| `.cbom.json` | CycloneDX 1.7 CBOM | `cryptamap-scan-<acct>-<region>-<ts>` | `cryptamap-org-<ts>` |
| `.asff.json` | Security Hub ASFF | per-scan only | — |
| `.pqcc.xlsx` | MITRE PQCC workbook | per-scan only | — |
| `.report.html` | self-contained offline report | per-scan only | — |
| `.roadmap.json` / `.roadmap.md` | PQC migration roadmap | both | both |
| `.coverage.json` | coverage matrix | — | org only |
| `.scan.json` | raw scan (debug) | per-scan | — |

`<ts>` = `20060102T150405Z` (UTC). So the dir holds per-(account,region) files
plus, when `--org-merge`, a `cryptamap-org-<ts>.*` set.

## 3. How download works per mode (the crux)

### serve mode (LOCAL — the build target) — easy, zero-risk
`serve` already knows `--dir`, already locates files via `findLatest`, and already
serves CBOM + roadmap at `/mock/org-cbom.json` + `/mock/roadmap.json` through a
fixed-path `fileServer()` (`cmd/cryptamap/serve.go`). The files are on the
customer's OWN disk, served over 127.0.0.1 only — no cloud, no auth, no leak risk.
Adding downloads = (a) locate the other artifacts, (b) expose them at routes, (c)
list them in the UI.

### deployed mode (network) — NOT BUILT (by design)
There is no deployed network download path, because CryptaMap is local-first and the
deployment exposes **no query API** at all (`cdk/lib/data-stack.ts:11-23` — DataStack is
an evidence store only; the earlier query Lambda + presigned-URL design was removed). The
org fan-out simply writes the artifact set to the private results bucket; an operator
retrieves it with their own S3/KMS credentials and views it locally via `cryptamap serve`.
The Overview teaser / Reports page therefore target serve-mode only and gracefully hide
download buttons when a (self-hosted) `apiBase` is set but exposes no artifact route.

## 4. Backend changes (serve.go)

1. **Locate all artifacts**, not just CBOM+roadmap. Add a helper that, given
   `--dir`, finds the newest of each: `*.cbom.json` (prefer `*-org-*` if present),
   `*.asff.json`, `*.pqcc.xlsx`, `*.report.html`, `*.roadmap.json`, `*.roadmap.md`,
   `*.coverage.json`. Reuse the existing `findLatest(dir, exact, suffix)` pattern;
   missing artifacts are simply omitted (a CBOM-only dir still works).
2. **Serve them** at stable routes under a new prefix, e.g.
   `/artifacts/cbom.json`, `/artifacts/findings.asff.json`,
   `/artifacts/report.pqcc.xlsx`, `/artifacts/report.html`,
   `/artifacts/roadmap.json`, `/artifacts/roadmap.md`, `/artifacts/coverage.json`.
   Each via the existing fixed-path `fileServer()` (no user-controlled path → no
   traversal). Set `Content-Disposition: attachment; filename="<realname>"` so the
   browser downloads with the real timestamped name.
3. **A manifest route** `/artifacts/manifest.json` returning the list the UI needs:
   `[{ kind, label, route, filename, sizeBytes, contentType }]` — only entries that
   exist on disk. This keeps the UI generic and demo/real agnostic.
4. **Demo mode** (`--demo`): the embedded bundle only has CBOM+roadmap, so the
   manifest lists just those (clearly fine — demo isn't a deliverable).

NO new flags; loopback-only invariant unchanged. `Content-Disposition` is the only
header addition.

## 5. Frontend changes

### 5a. Dedicated "Reports" page (`/reports`, new nav item under … top-level)
- Fetches `/artifacts/manifest.json`.
- A table/cards: each artifact = icon + **what it is in one plain line** (e.g.
  "CycloneDX 1.7 CBOM — the machine-readable cryptographic inventory; the primary
  regulator deliverable"), filename, size, and a **Download** button (anchor to the
  route, `download` attr).
- Honest empty/demo states: in `--demo`, a note "these are sample artifacts"; if a
  kind is absent, omit it; if running deployed without download support, show
  "artifacts are in your scan-output directory / S3 bucket" text instead of buttons.
- A short "Where are these files?" line stating the on-disk path (`--dir`) so even
  without clicking, the customer knows the location.

### 5b. Overview teaser
- A compact panel on Overview: "Download CryptaMap reports" with a primary
  **Download CBOM** button + a "View all artifacts →" link to `/reports`.
- Only shows when the manifest has ≥1 artifact.

### 5c. Reuse
- A small `useArtifacts()` hook (mirrors `useScanData`) fetching the manifest.
- Plain-English descriptions live in a tiny `lib/artifactInfo.ts` map (kind →
  label + description), so copy isn't scattered.

## 6. Discoverability (independent of buttons)

- `serve` startup already prints CBOM + roadmap paths; extend it to print the full
  artifact list it found (one line each) + the dir, so the CLI alone tells the
  customer where everything is.
- README/DEPLOYMENT: a short "Where are my reports?" section.

## 7. Honest notes / non-goals

- This is a **discoverability + convenience** feature, not a new capability — the
  files already exist on the customer's disk and the CLI writes them regardless.
  The dashboard panel just makes them visible + one-click.
- No artifact is generated in the browser; the dashboard only links to files the
  CLI already wrote (single source of truth, no drift).
- Deployed-mode downloads + any presigned-URL work are explicitly out of scope here
  and must respect the secure-by-default hardening if ever built.

## 8. Build checklist (for when this is greenlit)

- [ ] serve.go: `findArtifacts(dir)` + `/artifacts/*` routes + `Content-Disposition`
- [ ] serve.go: extend startup output to list all found artifacts
- [ ] dashboard: `useArtifacts()` hook + `lib/artifactInfo.ts`
- [ ] dashboard: `/reports` page + nav item + route
- [ ] dashboard: Overview teaser panel
- [ ] graceful states: demo, missing-kind, deployed-without-download
- [ ] VERIFY IN A REAL BROWSER (headless render of /reports + Overview) before
      claiming done — build-passing is not sufficient (lesson from the compliance
      redesign `ref`-prop crash).
