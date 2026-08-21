# SUBMISSION: AI Agent for CryptaMap

This adds an AI Agent chat experience to the CryptaMap dashboard: grounded Q&A over the
synthetic cryptographic inventory, three deterministic natural-language-driven in-app
actions, and explicit handling of several failure/edge cases. **100% of the
implementation — Go backend, TypeScript frontend, prompts, tests, and this document —
was written by Claude Code** (Anthropic's coding agent, model Sonnet 5); I directed,
reviewed, and ran it, but wrote no implementation code by hand.

## Process — how this was actually built

The assignment asks how context was established, work decomposed, and iteration driven —
that process, honestly, not a cleaned-up retelling:

1. **Context first, no code.** Before writing anything, two parallel research passes ran
   against the actual repo: one mapped the dashboard's frontend (framework, data
   loading, existing filter/selection URL contracts), the other mapped the Go data model
   and backend (`internal/mock`, `internal/roadmap`, `internal/pqc`, and — critically —
   confirmed `cryptamap serve` had *no* dynamic query API to extend, only static files).
2. **A real constraint changed the plan.** "Use a free AI API" turned out to be
   non-trivial: no free ChatGPT API exists, Anthropic/OpenAI aren't free-by-default, and
   Ollama wasn't installed locally. Rather than guess from training data (which could be
   stale), this was resolved with live web searches confirming Gemini's free tier is
   genuinely free (no card, not a trial) — that evidence is what the model choice rests
   on, not a default assumption.
3. **Two decisions were escalated, not assumed**: LLM provider (Gemini) and scope
   ambition ("lean core" vs. "core + a couple extras" — the latter chosen). Everything
   else downstream (which 3 actions, the validate-then-propose action pattern, reusing
   existing URL contracts) followed from research + a plan reviewed against the actual
   source before implementation started, not from a generic template.
4. **Plan mode caught real integration details before they became bugs**: the exact
   `?q=` PropertyFilter JSON shape, the `useSplitPanel` selection flow, and which Go
   types (`output.ParseCBOM`, `roadmap.Roadmap`, `taxonomy.Lookup`) to reuse rather than
   re-implement were all verified against the live source, not assumed from the plan's
   own description.
5. **Environment problems were fixed, not routed around**: the local Go toolchain (1.20)
   was older than this repo requires (1.26) — installed a current one via Homebrew
   rather than reaching for compatibility hacks.
6. **Live testing against the real Gemini API surfaced three genuine bugs**, each
   root-caused from actual evidence (server logs, API error bodies), not guessed:
   - A 400 error ("missing thought_signature") on the second turn of any tool-call
     conversation — undocumented enough that finding the exact fix required pulling the
     specific Gemini docs page rather than relying on prior knowledge. Fixed in
     `internal/agent/gemini.go`.
   - Request timeouts too short for a thinking-capable model's first tool-call turn —
     widened client and server timeouts with a documented rationale, not an arbitrary bump.
   - Real free-tier 503 "high demand" and 429 quota-exhausted responses — confirmed as
     genuine provider-side flakiness (not a bug) by reading the actual error bodies, and
     used as *live* evidence for the failure-handling requirement rather than simulated.
7. **An independent review pass caught what testing didn't.** After implementation, a
   separate high-effort `/code-review` pass (same harness, run as a second opinion) found
   8 real issues — most importantly a genuine concurrency data race in the shared tool
   executor. All were fixed, with a regression test added specifically for the race,
   verified under `go test -race`. See "Code review pass" below.
8. **User feedback changed the product, twice.** A real-browser design-inspection
   report ("make it look more like a modern chat app") led to replacing a text-label
   transcript with actual message bubbles, which also surfaced a rendering bug (the
   model's `**bold**` markdown was showing as literal asterisks) that hadn't been
   noticed until the redesign made it visible. A model-availability complaint ("keeps
   saying temporarily unavailable") led to researching and switching the default model
   to a faster, higher-quota one — verified live before handing it back.
9. **Self-review against the evaluation criteria surfaced the most important gap.**
   Asked to assess the submission against this assignment's own "what we evaluate" list,
   the most significant finding was that the Agent sends real scan data to a third
   party (Google) — in tension with this project's own stated "data never leaves your
   org" design philosophy — and that tension had gone undocumented. See "Data flow and
   privacy" above.
10. **Acting on that review surfaced a second, more concrete bug.** While closing the
    "live-verify filter_assets/select_asset" gap flagged in that same review, testing
    with the assignment's *exact* example phrasing ("Show me all quantum-vulnerable
    assets.") revealed the faster model wasn't reliably distinguishing "show me X"-as-
    navigation from "show me X"-as-a-plain-question — a real robustness gap the honest
    "not yet live-tested" note in the previous draft would have hidden. Fixed by
    tightening the system prompt's action-triggering rule in `internal/agent/orchestrate.go`,
    then re-verified live with the exact example phrasing before considering it closed.

## Run instructions

```bash
# One-time
export GEMINI_API_KEY=<your key>               # free, no card: aistudio.google.com -> "Get API key"
export GEMINI_MODEL=gemini-flash-lite-latest   # optional override; this is already the default — see "Model choice" below

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

Automated tests: `go test ./...` (new coverage lives in `internal/agent/{tools,orchestrate,handler}_test.go`
— see Testing/validation below for what each covers).

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

## Data flow and privacy — a real, deliberate exception to this project's own model

README/ARCHITECTURE.md are explicit that CryptaMap is local-first: *"no internet-facing
API or dashboard and no SaaS backend... data never leaves your AWS org."* **The AI
Agent is a genuine exception to that promise**, and it's important to be upfront about
it rather than let it surface as a gotcha:

- When the model calls `list_facets`/`list_assets`/`get_roadmap`, the tool *results* —
  service names, resource IDs, ARNs, account IDs, regions, postures — are sent to
  Google's Gemini API over the network so the model can reason over them and answer.
  In demo mode that's synthetic data; against a **real scan**, this is genuine
  discovered-resource metadata about an AWS org (never key material or secret values —
  CryptaMap's own scanners never collect those — but resource identifiers and posture
  are still sensitive to many organizations).
- What does **not** leave the machine: `GEMINI_API_KEY` itself (read server-side only,
  verified never to reach the compiled browser bundle — see Testing/validation below),
  and every asset the corpus doesn't choose to expose through a tool call (there is no
  "send the whole CBOM" tool).
- The chat panel now carries a **persistent** disclosure — not a one-time dismissible
  toast, because it's true on every turn — directly under the "Ask AI" header:
  *"Sends your questions and scan summaries to Google's Gemini API to answer them."*
  (`dashboard/src/components/AgentChatPanel.tsx`).
- This is why the Agent is opt-in (`GEMINI_API_KEY` unset = fully disabled, zero calls
  ever made) rather than on by default: an operator scanning a real, sensitive AWS org
  should make an affirmative choice to enable third-party LLM calls, not discover after
  the fact that their inventory summaries were sent to Google.
- What I'd do with more time: a local-model path (e.g. Ollama) would let the Agent work
  entirely on-machine, restoring the project's original privacy guarantee — considered
  during design (see Key design decisions) but not built for this scope since Ollama
  wasn't available in the dev environment and free hosted APIs were the pragmatic
  choice under the time budget.

## Agent/harness and model choices

- **Coding harness**: Claude Code, used interactively for the entire implementation —
  exploration (parallel sub-agents mapped the dashboard's data flow, filter/selection
  contracts, and the Go scanner/roadmap/taxonomy packages before any code was written),
  planning (plan mode, with the user approving the design before implementation), then
  direct file writes, builds, and live testing.
- **Product LLM: Google Gemini** (`gemini-flash-lite-latest` by default, override via
  `GEMINI_MODEL` — see Known limitations for why Flash-Lite over a heavier model), called
  via the plain REST `generateContent` API with function
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

- **Automated**: `go test ./...` passes, including:
  - 13 tests in `internal/agent/tools_test.go` exercising the tool executor directly
    (no network, no LLM) — every action tool's validate/accept and validate/reject
    paths, the exact `?q=` JSON shape round-trip against what `AssetsView.tsx` expects,
    malformed-args handling, an unknown-tool-name call.
  - 5 tests in `internal/agent/orchestrate_test.go` driving the full multi-turn tool-call
    loop against a scripted fake provider — a grounded-Q&A shape, an action shape, a
    rejected-tool-call-relayed-not-fatal shape, and both `maxTurns` outcomes (hard error
    vs. surfacing an already-validated action — a regression test for the code-review
    finding below).
  - `TestConcurrentChatRequestsDoNotShareAction` in `internal/agent/handler_test.go` — 20
    concurrent real HTTP requests through the actual handler, run under `go test -race`.
  - `go build ./...`, `go vet ./...`, `go test -race ./internal/agent/... ./cmd/cryptamap/...`,
    `tsc -b`, `npm run build`, and `make check-types` (the Go→TS codegen staleness guard)
    all pass clean.
- **Live, end-to-end, against the real Gemini API** (demo data, no AWS account),
  re-verified after every fix below — not a one-time pass:
  - *Grounded Q&A*: "How many crypto assets in this scan are quantum-vulnerable?" →
    a correct breakdown (770 non-pqc-classical / 871 including legacy-tls / full
    posture split summing to the true total of 2,178 assets) — verified against the
    tool's own counts, not the model's arithmetic.
  - *All three actions, with the assignment's own example phrasing*: "Show me all
    quantum-vulnerable assets." → `filter_assets` fires with the correct posture token;
    "Open the details for `<bomRef>`" → `select_asset` fires and opens the right asset;
    "Take me to the migration roadmap for KMS." → `view_roadmap` resolves a real raw
    service ID and the dashboard filters correctly.
  - *Pure-question regression*: "How many crypto assets... are quantum-vulnerable?" (no
    "show me") → correctly answers with **no** action — confirms the action-triggering
    prompt rule (below) didn't overcorrect into firing actions on plain questions.
  - *Impossible request*: "Show me the roadmap for Azure Front Door." → no action fired;
    the model correctly explained CryptaMap only scans AWS and suggested the real
    closest match (CloudFront) it found via `list_facets`.
- **Security verification, concretely, not just asserted**: grepped the built browser
  bundle (`dashboard/dist/assets/*.js`) for the literal API key, `GEMINI_API_KEY`,
  `GEMINI_MODEL`, and `generativelanguage.googleapis.com` — the only match anywhere is
  the harmless UI copy telling an operator which env var *name* to set
  (`AgentChatPanel.tsx`'s disabled-state message); the key, the model name, and the
  endpoint URL never appear in client-delivered code.
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
  - **A second genuine bug, found while closing out this exact section**: testing
    `filter_assets` live with the assignment's own phrasing ("Show me all
    quantum-vulnerable assets.") initially returned a correct *count* but no action —
    the faster/lighter model (`gemini-flash-lite-latest`, switched to for quota/latency
    reasons) wasn't reliably treating "show me" as a navigation request. Fixed by
    tightening the action-triggering rule in the system prompt
    (`internal/agent/orchestrate.go`) with an explicit example and re-verified live with
    the exact phrasing, plus a regression check that a *pure* question still correctly
    fires no action.

## Known limitations

- No persistent chat history across a page reload (in-memory React state only).
- One `Corpus` snapshot per `cryptamap serve` process — no awareness of a rescan while
  running (matches the rest of `serve.go`'s existing assumptions about `--dir`).
- `resolveService`'s fuzzy match (display-name substring) can pick an arbitrary one of
  several raw service IDs that share a display name (see decision 5 above).
- English-only system prompt; no evaluation of non-English queries.
- Multi-turn conversational memory is passed back to the model each request but capped
  at 20 prior turns (`maxHistoryTurns`) and not tested for long-conversation drift.
- Newer/thinking-capable Gemini models' free-tier quotas are materially tighter than the
  widely-quoted "1,500 req/day" figure for older Flash generations, and slower (5–60s
  per turn) — `gemini-flash-latest` hit transient 503s under load, `gemini-3.6-flash`
  hit a 20-request quota wall almost immediately. Switched the default to
  `gemini-flash-lite-latest` (faster, materially higher free quota, verified live) —
  `GEMINI_MODEL` exists specifically so this is a one-line fix, not a code change, if
  the default degrades again.
- **No on-machine/local-model option built** (e.g. Ollama) — see "Data flow and
  privacy" above; the Agent's third-party data egress is a real, currently-unavoidable
  tradeoff of using a hosted free-tier API under this assignment's time/cost constraints.

## What I'd improve next

**Engineering:**
1. A lightweight Playwright/browser check that actually clicks through the resulting UI
   state after an action, not just asserting the backend's JSON — the live testing above
   closes the functional gap but a real click-through test would guard it in CI.
2. Stream the reply token-by-token (SSE) instead of waiting for the full turn — the
   observed 2–60s latency (model-dependent) is the roughest UX edge here.
3. A tiny in-panel retry button on error, instead of requiring the user to retype.
4. Extend `resolveService` to optionally return *all* matching raw IDs for a shared
   display name and let `RoadmapView` filter on a set, not a single ID.
5. Observability beyond `log.Printf`: request IDs, latency, and tool-call counts per
   turn, so a real operator could tell "the agent is slow" from "the agent is failing."
6. A local-model provider (Ollama) behind the existing `Provider` interface, so an
   operator working with a sensitive real scan has an option that keeps the project's
   original "data never leaves your org" guarantee intact.

**Product** (not just engineering polish — who uses this and when):
7. **Agent-assisted triage**: let a security engineer accept/track a finding's risk
   conversationally ("mark the RDS instances in account X as accepted risk, we're
   decommissioning them next quarter") instead of only ever reading the inventory.
8. **Proactive digest**: on `cryptamap serve` startup (or on a rescan), have the Agent
   summarize what changed since the last scan — new critical findings, services that
   flipped PQC status — rather than only answering when asked. Turns the Agent from a
   query tool into something that surfaces what a busy reviewer would otherwise miss.
9. **Natural-language compliance mapping**: "which of these findings affect our CERT-In
   obligations" — the compliance mapping data already exists per-framework
   (`dashboard/public/compliance/*.json`); the Agent doesn't yet reason over it.
