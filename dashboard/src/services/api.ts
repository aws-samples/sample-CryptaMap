import type { CBOM } from '../types';
import type { Roadmap } from '../types/roadmap';
import { summarizePosture, summarizeMaturity, realComponents } from '../hooks/useScanData';

// API_BASE comes from /config.json deployed alongside the dashboard, or an
// env-baked default. Local dev points at /mock/ for the static mock CBOM +
// roadmap.
const DEFAULT_API_BASE = (import.meta as any).env?.VITE_API_BASE ?? '';
const DEFAULT_MOCK_CBOM = '/mock/org-cbom.json';
const DEFAULT_MOCK_ROADMAP = '/mock/roadmap.json';

interface RuntimeConfig {
  apiBase?: string;
  bucket?: string;
  mockMode?: boolean;
  /** Optional override for the mock roadmap path; defaults to /mock/roadmap.json. */
  roadmapPath?: string;
}

let cachedConfig: RuntimeConfig | null = null;

export async function getRuntimeConfig() {
  if (cachedConfig) return cachedConfig;
  try {
    const res = await fetch('/config.json');
    if (res.ok) {
      cachedConfig = await res.json();
      return cachedConfig!;
    }
  } catch (e) {
    /* fall through */
  }
  cachedConfig = { apiBase: DEFAULT_API_BASE, mockMode: true };
  return cachedConfig!;
}

export async function fetchLatestCBOM(): Promise<CBOM | null> {
  const cfg = await getRuntimeConfig();
  if (cfg.mockMode || !cfg.apiBase) {
    const res = await fetch(DEFAULT_MOCK_CBOM);
    if (!res.ok) return null;
    return res.json();
  }
  // The /cbom route now 302-redirects to a short-lived presigned S3 URL so the
  // (potentially huge) org CBOM streams straight from S3 instead of through the
  // Lambda body limit (SCALING.md §4.3). fetch() follows the 302 transparently —
  // the resolved response is the CycloneDX doc, so the body IS the CBOM
  // (shape-identical to /mock/org-cbom.json), not a /scans metadata envelope.
  // Return it directly. `redirect: 'follow'` is the fetch default but is set
  // explicitly so the behaviour survives any future global fetch wrapping.
  const res = await fetch(`${cfg.apiBase}/cbom`, { redirect: 'follow' });
  if (!res.ok) return null;
  return res.json();
}

// Summary is the precomputed org rollup served at ${apiBase}/summary so the
// Overview KPI band + maturity ladder render WITHOUT downloading the full
// (possibly tens-of-MB) CBOM. It mirrors the backend mergeSummary shape
// (cmd/cryptamap/lambda_merge_core.go): the counts the dashboard needs plus the
// completion-barrier signal. perPosture / the two headline callouts are OPTIONAL —
// when the backend omits the posture rollup, callers fall back to computing it from
// the CBOM (mock mode always derives them; see fetchSummary).
export interface SummaryAccount {
  accountId: string;
  regions: number;
  findings: number;
  critical: number;
  assets: number;
}

/** One dropped/failed (account,region) tuple in the loud-incomplete report. */
export interface FailedShard {
  accountId: string;
  region: string;
  reason: string;
}

export interface Summary {
  totalAssets: number;
  totalCritical: number;
  perAccount: SummaryAccount[];
  /** Per-posture component counts keyed by the cryptamap:posture wire value. */
  perPosture?: Record<string, number>;
  /**
   * Share (0-100) of CLASSIFIABLE assets still on quantum-vulnerable traditional
   * public-key crypto = (legacyTLS+nonPQCClassical)/classifiable (Unknown excluded
   * from the denominator). Matches summarizeMaturity.quantumVulnerablePct and the
   * backend mergeSummary.quantumVulnerablePct.
   */
  quantumVulnerablePct?: number;
  /**
   * Share (0-100) of ALL assets fully migrated to post-quantum cryptography
   * end-to-end = pqcReady/total. Hybrid PQ key exchange with a traditional
   * certificate (pqcHybrid) is EXCLUDED from the numerator, and symmetric-only
   * AES-256 at rest is not PQC. Matches summarizeMaturity.pqcEndToEndPct and the
   * backend mergeSummary.pqcEndToEndPct.
   */
  pqcEndToEndPct?: number;
  // Completion barrier (SCALING.md §4.4): missingShards>0 / complete=false flags a
  // decimated run so the dashboard never reports a clean, silently-smaller result.
  expectedShards: number;
  observedShards: number;
  missingShards: number;
  complete: boolean;
  // Loud-incomplete report (mergeSummary.Incomplete / FailedShards): incomplete is
  // the explicit inverse of complete (a stable positive flag to key a banner off),
  // and failedShards names exactly which (account,region) tuples were dropped and
  // why so the Overview banner can list them. Both OPTIONAL — older /summary
  // artifacts omit them; the banner falls back to the count-only message.
  incomplete?: boolean;
  failedShards?: FailedShard[];
}

// fetchSummary returns the precomputed org rollup. In mock mode (or with no
// apiBase) there is no /summary artifact, so derive an equivalent rollup from the
// mock CBOM exactly as the Overview did before — including the per-posture counts
// and the two headline callouts — and report complete=true (a single local CBOM is, by
// definition, the whole "scan"). The live path GETs ${apiBase}/summary, which —
// like /cbom — may 302-redirect to a presigned S3 URL; fetch() follows it.
export async function fetchSummary(): Promise<Summary | null> {
  const cfg = await getRuntimeConfig();
  if (cfg.mockMode || !cfg.apiBase) {
    const res = await fetch(DEFAULT_MOCK_CBOM);
    if (!res.ok) return null;
    const cbom = (await res.json()) as CBOM;
    return summaryFromCBOM(cbom);
  }
  const res = await fetch(`${cfg.apiBase}/summary`, { redirect: 'follow' });
  if (!res.ok) return null;
  const body = await res.json();
  // Accept either a bare Summary or a { summary: Summary } envelope.
  return (body.summary ?? body ?? null) as Summary | null;
}

// summaryFromCBOM derives the precomputed-rollup shape from a full CBOM, reusing
// the same posture/maturity math the Overview KPI band uses. Used in mock mode
// and as the Overview's fallback when the live /summary omits the posture rollup.
export function summaryFromCBOM(cbom: CBOM): Summary {
  const posture = summarizePosture(cbom);
  const maturity = summarizeMaturity(posture);
  const perPosture: Record<string, number> = {};
  const perAccount = new Map<string, SummaryAccount>();
  let totalCritical = 0;
  // Exclude synthetic algorithm-definition nodes: they are not discovered
  // resources and must not inflate totalAssets / perPosture / perAccount.
  const components = realComponents(cbom);
  for (const c of components) {
    const props = c.properties ?? [];
    const p = props.find((x) => x.name === 'cryptamap:posture')?.value ?? 'unknown';
    const acct = props.find((x) => x.name === 'cryptamap:accountId')?.value ?? '';
    perPosture[p] = (perPosture[p] ?? 0) + 1;
    const isCritical = p === 'no-encryption' || p === 'legacy-tls';
    if (isCritical) totalCritical++;
    const row = perAccount.get(acct) ?? { accountId: acct, regions: 0, findings: 0, critical: 0, assets: 0 };
    row.assets++;
    if (isCritical) row.critical++;
    perAccount.set(acct, row);
  }
  // Coverage barrier: a merged org CBOM carries the completion stamp in its
  // top-level metadata.properties (internal/output/cyclonedx.go coverageProps:
  // cryptamap:incomplete + the shard reconciliation counts). Read it so an
  // incomplete org scan is NEVER surfaced as a clean, silently-smaller result.
  // A true single local scan has NO cryptamap:incomplete stamp, so it falls back
  // to complete=true with a zero shard barrier — behavior unchanged.
  const meta = cbom.metadata?.properties ?? [];
  const metaVal = (name: string) => meta.find((x) => x.name === name)?.value;
  const incompleteStamp = metaVal('cryptamap:incomplete');
  if (incompleteStamp === undefined) {
    return {
      totalAssets: components.length,
      totalCritical,
      perAccount: Array.from(perAccount.values()),
      perPosture,
      quantumVulnerablePct: maturity.quantumVulnerablePct,
      pqcEndToEndPct: maturity.pqcEndToEndPct,
      // A local single CBOM is the whole scan by definition: no shard barrier.
      expectedShards: 0,
      observedShards: 0,
      missingShards: 0,
      complete: true,
      incomplete: false,
      failedShards: [],
    };
  }
  const num = (name: string) => {
    const n = Number(metaVal(name));
    return Number.isFinite(n) ? n : 0;
  };
  const incomplete = incompleteStamp === 'true';
  return {
    totalAssets: components.length,
    totalCritical,
    perAccount: Array.from(perAccount.values()),
    perPosture,
    quantumVulnerablePct: maturity.quantumVulnerablePct,
    pqcEndToEndPct: maturity.pqcEndToEndPct,
    expectedShards: num('cryptamap:expectedShards'),
    observedShards: num('cryptamap:observedShards'),
    missingShards: num('cryptamap:missingShards'),
    complete: !incomplete,
    incomplete,
    // The CBOM stamp carries only the failed-shard COUNT (cryptamap:failedShards),
    // not the per-tuple detail; the detailed list lives in the /summary artifact.
    // Leave the detail list empty here so the banner falls back to the count-only
    // message rather than fabricating tuples.
    failedShards: [],
  };
}

// fetchRoadmap mirrors fetchLatestCBOM: in mock mode (or with no apiBase) it
// loads the static /mock/roadmap.json; the live path GETs ${apiBase}/roadmap.
export async function fetchRoadmap(): Promise<Roadmap | null> {
  const cfg = await getRuntimeConfig();
  if (cfg.mockMode || !cfg.apiBase) {
    const path = cfg.roadmapPath ?? DEFAULT_MOCK_ROADMAP;
    const res = await fetch(path);
    if (!res.ok) return null;
    return res.json();
  }
  // Like /cbom, the live /roadmap route now 302-redirects to a presigned S3 URL;
  // fetch() follows it transparently and .json() parses the resolved S3 body.
  const res = await fetch(`${cfg.apiBase}/roadmap`, { redirect: 'follow' });
  if (!res.ok) return null;
  const body = await res.json();
  // Accept either a bare Roadmap or { roadmap: Roadmap } envelope.
  return body.roadmap ?? body ?? null;
}
