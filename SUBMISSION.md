# SUBMISSION: AI Agent for CryptaMap

This adds an AI Agent chat experience to the CryptaMap dashboard: grounded Q&A over the
synthetic cryptographic inventory, three deterministic natural-language-driven in-app
actions, and explicit handling of several failure/edge cases. **100% of the
implementation — Go backend, TypeScript frontend, prompts, tests, and this document —
was written by Claude Code** (Anthropic's coding agent, model Sonnet 5); I directed,
reviewed, and ran it, but wrote no implementation code by hand.

## Run instructions

```bash
# One-time
export GEMINI_API_KEY=<your key>          # free, no card: aistudio.google.com -> "Get API key"
export GEMINI_MODEL=gemini-flash-latest    # optional; see "Model choice" below

# Build + run (bundled synthetic demo data, no AWS account or scan needed)
make build-serve
./dist/cryptamap serve --demo --port 8787
```

Open `http://127.0.0.1:8787/`, click **Ask AI** in the top nav. Without
`GEMINI_API_KEY` set, the button still opens the panel but shows a clear
"not configured" message instead of failing silently — the dashboard's existing
features are completely unaffected either way.

For frontend-only iteration with hot reload: `cd dashboard && npm run dev` (proxies
`/api/*` to `127.0.0.1:8787` per `vite.config.ts` — run `cryptamap serve` alongside it).

Automated tests: `go test ./...` (includes new tests in `internal/agent/tools_test.go`).

## Architecture overview

```
Browser (dashboard/src)                    cryptamap serve (Go, 127.0.0.1 only)
┌─────────────────────────┐                ┌──────────────────────────────────┐
│ AgentChatPanel.tsx       │  POST /api/    │ internal/agent/handler.go        │
│  - floating chat, all    │  agent/chat    │  -> orchestrate.Run (tool loop)  │
│    routes                │ ──────────────>│  -> internal/agent/tools.go      │
│                          │                │     (validate-then-propose       │
│ agentApi.ts (fetch)      │<─────────────  │      against real Corpus data)   │
│ agentActions.ts          │ {reply,action} │  -> internal/agent/gemini.go     │
│  -> react-router         │                │     (REST call, key server-side  │
│     navigate()           │                │      only, never in browser JS)  │
└─────────────────────────┘                └──────────────────────────────────┘
        │  reuses EXISTING contracts               loads Corpus once at
        │  (?q=, ?asset=, ?service=)                startup from the same
        ▼                                           org-cbom.json/roadmap.json
  AssetsView.tsx / RoadmapView.tsx                   already served statically
```

The agent is a new local, loopback-only HTTP endpoint on the existing `cryptamap serve`
process (`cmd/cryptamap/serve.go`'s `mountAgentRoutes`), not a separate service. It loads
the *same* `org-cbom.json`/`roadmap.json` already being served to the dashboard into an
in-memory `Corpus` at startup, and exposes six tools to the model:

- **Read tools** (grounding): `list_facets` (every real service/account/region/posture/
  PQC-status, with counts — the model must call this before referring to any name), `list_assets`
  (filtered counts + a capped sample), `get_roadmap` (priority-ranked items + rollups).
- **Action tools** (validate, then propose): `ui_filter_assets`, `ui_select_asset`,
  `ui_view_roadmap`. Each validates every argument against the real `Corpus` *before*
  setting a `pendingAction` — the model cannot make the UI navigate to or filter on
  something that doesn't exist in this scan. A failed validation comes back as a normal
  `{"ok":false,"error":"..."}` tool result, not a crash, so the model can explain the
  failure to the user.

A small `Provider` interface (`internal/agent/provider.go`) abstracts the LLM; only a
`GeminiProvider` (plain `net/http`, no SDK) exists today, but swapping in another
provider is a one-file addition, not a rewrite of the tool logic or orchestration loop.

**Grounding mechanism**: the system prompt instructs the model to answer only from tool
results and to call `list_facets` before trusting any entity name, but the real
enforcement is structural: `list_assets`/`get_roadmap` are the *only* source of counts
and asset data the model ever sees, and every `ui_*` action is validated against the
same in-memory `Corpus` before it can be proposed. The model cannot invent a count it
never retrieved, and cannot propose navigating to an asset/service that isn't real,
because the tool that would do so refuses.

**Action dispatch**: the backend never invents new frontend behavior. `Action.Type ==
"filter_assets"` produces the *exact* `PropertyFilterQuery` JSON shape
`AssetsView.tsx`'s existing `?q=` parser already expects (`internal/agent/action.go`
mirrors it field-for-field); `select_asset` reuses the existing `?asset=<bomRef>` /
`SplitPanel` flow unmodified. `view_roadmap` needed one small *additive* change —
`RoadmapView.tsx` had no filtering at all before this — so it gained a `?service=`
param that scopes the three tier tables (the rollups at the bottom intentionally stay
unfiltered). `dashboard/src/lib/agentActions.ts` is the single, pure, unit-testable
place this mapping lives.

## Agent/harness and model choices

- **Coding harness**: Claude Code, used interactively for the entire implementation —
  exploration (parallel sub-agents mapped the dashboard's data flow, filter/selection
  contracts, and the Go scanner/roadmap/taxonomy packages before any code was written),
  planning (plan mode, with the user approving the design before implementation), then
  direct file writes, builds, and live testing.
- **Product LLM: Google Gemini** (`gemini-flash-latest` by default, override via
  `GEMINI_MODEL`), called via the plain REST `generateContent` API with function
  calling — no SDK dependency, consistent with this repo's dependency-light `internal/`
  packages. Chosen because it has a *genuinely* free tier (no credit card, not a trial)
  with native tool-calling, unlike ChatGPT's consumer app (no programmatic API) or
  Anthropic/OpenAI's paid-by-default APIs. The key is read via `os.Getenv` **only in
  the Go process** and is never present in any browser-delivered file — the frontend
  only ever talks to the local Go server.
- **Why not extend the existing Lambda `/cbom /summary /roadmap` API** (`cmd/cryptamap/
  lambda.go`)? README/ARCHITECTURE.md are explicit that CryptaMap is local-first with
  "no internet-facing API, no SaaS backend" as the shipped model; the Lambda path is
  for an optional org-fanout deployment, not the default `cryptamap serve` experience
  this assignment targets. Building the agent as a new route on the *existing* local
  server keeps that invariant (loopback-only bind, Host-header allowlist, CSP) intact
  with zero changes to it.

## Code review pass

Before committing, a high-effort automated code review (Claude Code's `/code-review`,
same harness, run as a second, independent pass) went over the full diff and surfaced
8 findings, all genuine. Fixed before commit:

- **A real concurrency data race**: `ToolExecutor.pendingAction` was a plain,
  unsynchronized field on one `ToolExecutor` shared across the server's whole lifetime
  in a closure — two simultaneous chat requests (two tabs, a double-click) could race
  on it, or one request could see another's action. Fixed by having `NewChatHandler`
  build a fresh `ToolExecutor` **per request** over the shared, read-only `*Corpus`
  (`internal/agent/handler.go`), and added `TestConcurrentChatRequestsDoNotShareAction`
  (`internal/agent/handler_test.go`) — 20 concurrent real HTTP requests, each asking
  for a different asset, asserting no cross-talk, run under `go test -race`.
- **A stale-filter UI bug**: `AssetsView.tsx`'s `useCollection` only reads its
  `defaultQuery` once at mount; if the agent called `navigate('/assets?q=...')` while
  the user was *already* on `/assets`, react-router doesn't remount the page, so the
  URL would update but the visible table silently would not filter. Fixed with a
  second effect that re-applies the URL's query via `propertyFilterProps.onChange`
  whenever `?q=` changes externally.
- The tool-call loop discarding an already-validated action if the model exhausted
  `maxTurns` without a final reply; a misleading "AI Agent: enabled" startup banner
  that didn't reflect a failed corpus load; no request body size cap; model "thinking"
  text silently dropped from replayed history; and an O(N) rescan per filter token
  instead of one pass. All fixed in `internal/agent/{orchestrate,gemini,handler,tools}.go`
  and `cmd/cryptamap/serve.go`.

Not fixed (deliberately): a small amount of duplicated fetch-with-cancellation
boilerplate between two `useEffect`s in `AppShell.tsx` — two occurrences of a ~5-line
pattern didn't clear the bar for a shared abstraction at this scope.

## Key design decisions and tradeoffs

1. **One backend endpoint on the existing local server, not a new service.** Simpler to
   run and ship (`cryptamap serve` is still the only thing to start), and it inherits
   the server's existing loopback-only security posture for free. Tradeoff: the agent
   can only ever be as available as `cryptamap serve` itself — no independent scaling,
   which is fine for a local-first, single-operator tool.
2. **Validate-then-propose actions, never "trust the model."** Every `ui_*` tool
   re-derives its arguments' validity from the same `Corpus` a read tool would use.
   This was the single most important choice for the "grounded, must not invent
   findings" requirement — it makes fabrication structurally impossible for actions,
   not just discouraged by a system prompt.
3. **Provider interface even though only one provider is implemented.** Costs one extra
   file (`provider.go`) and ~10 lines of indirection; buys a credible answer to "what if
   Gemini's free tier changes" without needing to actually build a second adapter for
   this scope.
4. **`RoadmapView.tsx` gained a `?service=` filter rather than the agent settling for a
   bare page navigation.** The assignment's own example ("take me to the migration
   roadmap for KMS") implies scoping, and building it was ~15 lines. Considered and
   **rejected**: making the agent also drive `ReportsView.tsx`'s PDF export by
   simulating a click across a route transition — that adds real complexity (timing,
   DOM coupling) for a capability `navigate('/reports')` already gets the user to.
5. **Multi-service raw IDs sharing one display name** (AWS has `kms_spec`/`kms_usage`/
   `kms_rotation`/`kms_custom_key_store`, all displaying as "AWS KMS"). `resolveService`
   picks one real, existing raw ID — never a fabricated one — but "the roadmap for KMS"
   can only ever scope to *one* of those raw IDs at a time, not a friendly-name group.
   Documented here rather than building a taxonomy-level grouping filter, which felt
   like solving a problem broader than this assignment's scope.
6. **`GEMINI_MODEL` is a plain env var override, not a UI setting.** The free tier's
   available models and their quotas shift (see Known limitations); a one-line
   operator-facing escape hatch was worth more than any UI for it at this scope.

## Testing / validation

- **Automated**: `go test ./...` passes, including 13 new tests in
  `internal/agent/tools_test.go` that exercise the tool executor directly (no network,
  no LLM) against a small fixed corpus — every action tool's validate/accept and
  validate/reject paths, the exact `?q=` JSON shape round-trip against what
  `AssetsView.tsx` expects, malformed-args handling, and an unknown-tool-name call.
  `go build ./...`, `go vet ./...`, `tsc -b`, and `npm run build` (dashboard) all pass
  clean.
- **Live, end-to-end, against the real Gemini API** (demo data, no AWS account):
  - *Grounded Q&A*: "How many crypto assets in this scan are quantum-vulnerable?" →
    a correct breakdown (770 non-pqc-classical / 871 including legacy-tls / full
    posture split summing to the true total of 2,178 assets) — verified against the
    tool's own counts, not the model's arithmetic.
  - *`view_roadmap` action*: "Take me to the migration roadmap for KMS." → model called
    `list_facets`, resolved a real raw service ID, returned
    `{"type":"view_roadmap","service":"kms_usage"}`; the dashboard correctly filtered.
  - *Impossible request*: "Show me the roadmap for Azure Front Door." → no action fired;
    the model correctly explained CryptaMap only scans AWS and suggested the real
    closest match (CloudFront) it found via `list_facets`.
  - *`filter_assets`/`select_asset` actions*: verified at the unit level (above) rather
    than live, end-to-end — see Known limitations.
- **Failure modes exercised live** (not simulated):
  - No `GEMINI_API_KEY` → `/api/agent/status` reports `enabled:false`, `/api/agent/chat`
    returns 503 with a clear JSON error; rest of the dashboard unaffected.
  - Invalid key → clean 502, logged server-side ("API key not valid"), UI shows a
    friendly inline error.
  - **Real Gemini 429 rate-limit and 503 "high demand" responses**, hit organically
    while testing (free-tier quotas are tight on newer models) → both surfaced as the
    same clean 502 + friendly message + server-log line, never a hang or crash.
  - A genuine bug surfaced by live testing and fixed during this session: newer Gemini
    models require an opaque `thoughtSignature` on a replayed tool-call turn or the API
    rejects the request with 400 — this wasn't documented anywhere I'd have found
    without hitting it live. Fixed in `internal/agent/gemini.go`/`provider.go`
    (`ToolCall.Meta`, echoed back verbatim).

## Known limitations

- `filter_assets` and `select_asset` are unit-tested but not click-verified live against
  the real UI in this session — free-tier quota (as low as 20 req on newer models) was
  exhausted by the rest of testing. They share the exact same `pendingAction`/dispatch
  mechanism as `view_roadmap`, which *was* verified live end-to-end.
- No persistent chat history across a page reload (in-memory React state only).
- One `Corpus` snapshot per `cryptamap serve` process — no awareness of a rescan while
  running (matches the rest of `serve.go`'s existing assumptions about `--dir`).
- `resolveService`'s fuzzy match (display-name substring) can pick an arbitrary one of
  several raw service IDs that share a display name (see decision 5 above).
- English-only system prompt; no evaluation of non-English queries.
- Multi-turn conversational memory is passed back to the model each request but capped
  at 20 prior turns (`maxHistoryTurns`) and not tested for long-conversation drift.
- Newer Gemini models' free-tier quotas are materially tighter than the widely-quoted
  "1,500 req/day" figure for older Flash generations — `gemini-flash-latest` hit
  transient 503s under load during testing, `gemini-3.6-flash` hit a 20-request quota
  wall almost immediately. `GEMINI_MODEL` exists specifically so this is a one-line
  fix, not a code change, if the default degrades further.

## What I'd improve next

1. Live-verify `filter_assets`/`select_asset` end-to-end once quota resets (or with a
   second key), and add a lightweight Playwright/browser check that actually clicks
   through the resulting UI state, not just the backend's JSON action.
2. Stream the reply token-by-token (SSE) instead of waiting for the full turn — the
   observed 5–60s latency on a thinking-capable model is the roughest UX edge here.
3. A tiny in-panel retry button on error, instead of requiring the user to retype.
4. Extend `resolveService` to optionally return *all* matching raw IDs for a shared
   display name and let `RoadmapView` filter on a set, not a single ID.
5. Observability beyond `log.Printf`: request IDs, latency, and tool-call counts per
   turn, so a real operator could tell "the agent is slow" from "the agent is failing."
