import { useEffect, useState } from 'react';
import type { CBOM, CBOMComponent } from '../types';
import { fetchLatestCBOM, fetchSummary, type Summary } from '../services/api';

// getProp reads a cryptamap:* (or any) property value off a CBOM component.
export function getProp(component: CBOMComponent, name: string): string | undefined {
  return (component.properties ?? []).find((p) => p.name === name)?.value;
}

// isSyntheticComponent reports whether a component is an emitter-synthesized
// algorithm-definition node (cryptamap:synthetic="true"), added by the CBOM
// writer (internal/output/cyclonedx.go linkCryptoAssetGraph) only so the
// CycloneDX refType references (cipherSuites[].algorithms, signatureAlgorithmRef)
// resolve to a real component. These are NOT discovered AWS resources and MUST be
// excluded from every asset/resource count, table, chart, and facet.
export function isSyntheticComponent(component: CBOMComponent): boolean {
  return getProp(component, 'cryptamap:synthetic') === 'true';
}

// realComponents returns only the discovered-AWS-resource components, dropping the
// synthetic algorithm-definition nodes. Use this anywhere components are treated as
// assets (rows, counts, summaries, filters).
export function realComponents(cbom: CBOM | null | undefined): CBOMComponent[] {
  return (cbom?.components ?? []).filter((c) => !isSyntheticComponent(c));
}

// resolveAlgorithmName maps an algorithm bom-ref (the value now stored in the
// CycloneDX refType fields) back to its human-readable algorithm name for display.
// The synthetic algorithm node carries the readable name both as its component
// `name` and as cryptamap:algorithmName. Falls back to the raw ref when no
// matching component exists (older CBOMs, or a non-ref free string).
export function resolveAlgorithmName(cbom: CBOM | null | undefined, ref: string): string {
  if (!ref) return ref;
  const match = (cbom?.components ?? []).find((c) => c['bom-ref'] === ref);
  if (!match) return ref;
  return getProp(match, 'cryptamap:algorithmName') ?? match.name ?? ref;
}

// KnowledgeProvenance mirrors the knowledge:* metadata the scanner stamps on every
// CBOM (internal/output/cyclonedx.go knowledgeProvenanceProps): how fresh the PQC
// knowledge was at scan time. source = "embedded" (baked-in air-gap floor) or
// "override" (a validated newer on-disk knowledge file). minAsOf is the
// conservative "oldest fact" / weakest-link freshness headline.
export interface KnowledgeProvenance {
  source: string;
  version: string;
  asOf: string;
  minAsOf: string;
  maxAsOf: string;
  factCount: number;
  digest: string;
  overridePath?: string;
  overrideError?: string;
}

// knowledgeProvenance extracts the knowledge:* freshness metadata from a CBOM's
// top-level metadata.properties. Returns null when the CBOM predates the freshness
// surface (no knowledge:* keys) so callers can hide the badge rather than render
// blanks.
export function knowledgeProvenance(cbom: CBOM | null): KnowledgeProvenance | null {
  const props = cbom?.metadata?.properties;
  if (!props) return null;
  const get = (name: string) => props.find((p) => p.name === name)?.value;
  const source = get('knowledge:source');
  // No knowledge:* metadata at all → this CBOM predates the freshness surface.
  if (source === undefined) return null;
  const count = Number.parseInt(get('knowledge:factCount') ?? '0', 10);
  return {
    source,
    version: get('knowledge:version') ?? '',
    asOf: get('knowledge:asOf') ?? '',
    minAsOf: get('knowledge:minAsOf') ?? '',
    maxAsOf: get('knowledge:maxAsOf') ?? '',
    factCount: Number.isNaN(count) ? 0 : count,
    digest: get('knowledge:digest') ?? '',
    overridePath: get('knowledge:overridePath') || undefined,
    overrideError: get('knowledge:overrideError') || undefined,
  };
}

// ScanProvenance mirrors the cryptamap:* metadata the scanner stamps on every
// CBOM (internal/output/cyclonedx.go buildCBOM metadata.Properties): the data's
// OWN truthful self-description of how it was produced. `mode` is the canonical
// authenticity signal — "live" (a real single-account AWS scan), "merged" (a real
// org-wide merge), or "mock" (synthetic demo data, NOT a real scan). The dashboard
// drives its data-authenticity banner off THIS (the data's provenance), never off
// config.json's mockMode (which is only a transport flag: static-file vs live-API).
export interface ScanProvenance {
  mode: string; // live | merged | mock | ""
  scanId: string;
  accountId: string;
  region: string;
}

// scanProvenance extracts the cryptamap:* scan metadata from a CBOM's top-level
// metadata.properties. Returns null only when the CBOM carries no metadata at all
// (so callers can fall back gracefully rather than render blanks).
export function scanProvenance(cbom: CBOM | null): ScanProvenance | null {
  const props = cbom?.metadata?.properties;
  if (!props) return null;
  const get = (name: string) => props.find((p) => p.name === name)?.value;
  return {
    mode: get('cryptamap:mode') ?? '',
    scanId: get('cryptamap:scanId') ?? '',
    accountId: get('cryptamap:accountId') ?? '',
    region: get('cryptamap:region') ?? '',
  };
}

// isDemoData is the single authority for "is what I'm looking at synthetic?".
// It trusts the DATA's own mode first (cryptamap:mode === "mock"); only when the
// CBOM carries no mode at all does it fall back to the transport flag. This is
// why a customer's real `cryptamap serve` scan (mode=live/merged) is correctly
// labeled a real scan even though serve sets mockMode=true for its static-file
// transport.
export function isDemoData(cbom: CBOM | null, mockModeTransport: boolean): boolean {
  const mode = scanProvenance(cbom)?.mode;
  if (mode === 'mock') return true;
  if (mode === 'live' || mode === 'merged') return false;
  return mockModeTransport; // no provenance in the data → fall back to the config flag
}

export function useScanData() {
  const [cbom, setCbom] = useState<CBOM | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const data = await fetchLatestCBOM();
        if (!cancelled) setCbom(data);
      } catch (e) {
        if (!cancelled) setError(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return { cbom, loading, error };
}

// useSummary loads the precomputed org rollup (fetchSummary). The Overview prefers
// it for the KPI band + maturity ladder so a large org does NOT have to download
// the full CBOM just to render counts. A null summary (no /summary artifact, or a
// fetch error) is non-fatal — the Overview falls back to deriving counts from the
// CBOM it loads anyway.
export function useSummary() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const data = await fetchSummary();
        if (!cancelled) setSummary(data);
      } catch (e) {
        if (!cancelled) setError(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return { summary, loading, error };
}

export interface PostureSummary {
  noEncryption: number;
  legacyTLS: number;
  nonPQCClassical: number;
  pqcHybrid: number;
  pqcReady: number;
  symmetricOnly: number;
  unknown: number;
}

function emptyPosture(): PostureSummary {
  return {
    noEncryption: 0, legacyTLS: 0, nonPQCClassical: 0, pqcHybrid: 0, pqcReady: 0, symmetricOnly: 0, unknown: 0,
  };
}

// bumpPosture folds one cryptamap:posture wire value into a PostureSummary.
function bumpPosture(out: PostureSummary, posture: string | undefined, n = 1) {
  switch (posture) {
    case 'no-encryption': out.noEncryption += n; break;
    case 'legacy-tls': out.legacyTLS += n; break;
    case 'non-pqc-classical': out.nonPQCClassical += n; break;
    case 'pqc-hybrid': out.pqcHybrid += n; break;
    case 'pqc-ready': out.pqcReady += n; break;
    case 'symmetric-only': out.symmetricOnly += n; break;
    default: out.unknown += n;
  }
}

export function summarizePosture(cbom: CBOM | null): PostureSummary {
  const out = emptyPosture();
  if (!cbom) return out;
  for (const c of realComponents(cbom)) {
    const posture = (c.properties ?? []).find(p => p.name === 'cryptamap:posture')?.value;
    bumpPosture(out, posture);
  }
  return out;
}

// postureFromCounts rebuilds a PostureSummary from a precomputed per-posture count
// map (Summary.perPosture) so the Overview can render its KPI band + maturity
// ladder from /summary alone — no full-CBOM download required.
export function postureFromCounts(perPosture: Record<string, number>): PostureSummary {
  const out = emptyPosture();
  for (const [posture, n] of Object.entries(perPosture)) {
    bumpPosture(out, posture, n);
  }
  return out;
}

// MaturitySummary frames posture counts as a cryptographic MATURITY LADDER:
//
//   stage 0  unencrypted        — no cryptographic baseline (data-hygiene
//                                 prerequisite); PQC is not assessable yet
//   stage 1  encrypted-vulnerable — encrypted but quantum-vulnerable (the prime
//                                 PQC migration target)
//   stage 2  quantum-safe       — symmetric-AES-256 / pqc-hybrid / pqc-ready
//
// The headline "% quantum-safe" is stage2 / (stage1 + stage2): it measures
// progress AMONG ENCRYPTED assets only. Stage 0 (unencrypted) and unknown
// (unassessable) are deliberately EXCLUDED from the denominator — an unencrypted
// resource is a different (data-hygiene) problem, not a quantum-readiness one, so
// counting it as "not quantum-safe" both distorts the percentage and conflates two
// distinct remediation tracks. Stage 0 is surfaced on its own as a prerequisite.
export interface MaturitySummary {
  stage0Unencrypted: number;
  stage1Vulnerable: number;
  stage2QuantumSafe: number;
  unknown: number;
  /** Encrypted + classifiable assets: the PQC-maturity denominator (stage1+stage2). */
  encrypted: number;
  /** stage2 / encrypted, rounded to a whole percent; 0 when no encrypted assets. */
  quantumSafePct: number;
}

export function summarizeMaturity(p: PostureSummary): MaturitySummary {
  const stage0Unencrypted = p.noEncryption;
  const stage1Vulnerable = p.legacyTLS + p.nonPQCClassical;
  const stage2QuantumSafe = p.symmetricOnly + p.pqcHybrid + p.pqcReady;
  const encrypted = stage1Vulnerable + stage2QuantumSafe;
  return {
    stage0Unencrypted,
    stage1Vulnerable,
    stage2QuantumSafe,
    unknown: p.unknown,
    encrypted,
    quantumSafePct: encrypted > 0 ? Math.round((stage2QuantumSafe / encrypted) * 100) : 0,
  };
}

export interface ServiceCount { service: string; count: number; criticalCount: number; }

export function summarizeByService(cbom: CBOM | null): ServiceCount[] {
  if (!cbom) return [];
  const map = new Map<string, ServiceCount>();
  for (const c of realComponents(cbom)) {
    const svc = (c.properties ?? []).find(p => p.name === 'cryptamap:service')?.value ?? 'unknown';
    const posture = (c.properties ?? []).find(p => p.name === 'cryptamap:posture')?.value ?? '';
    const cur = map.get(svc) ?? { service: svc, count: 0, criticalCount: 0 };
    cur.count++;
    if (posture === 'no-encryption' || posture === 'legacy-tls') cur.criticalCount++;
    map.set(svc, cur);
  }
  return Array.from(map.values()).sort((a, b) => b.criticalCount - a.criticalCount || b.count - a.count);
}

export interface CryptoFunctionCount {
  cryptoFunction: string;
  count: number;
  criticalCount: number;
}

// summarizeByCryptoFunction groups components by cryptamap:cryptoFunction (the
// PRIMARY grouping dimension on the Assets view), flagging no-encryption /
// legacy-tls as critical, sorted by criticalCount then count. Components without
// a cryptoFunction property fall back to "unknown".
export function summarizeByCryptoFunction(cbom: CBOM | null): CryptoFunctionCount[] {
  if (!cbom) return [];
  const map = new Map<string, CryptoFunctionCount>();
  for (const c of realComponents(cbom)) {
    const fn = getProp(c, 'cryptamap:cryptoFunction') ?? 'unknown';
    const posture = getProp(c, 'cryptamap:posture') ?? '';
    const cur = map.get(fn) ?? { cryptoFunction: fn, count: 0, criticalCount: 0 };
    cur.count++;
    if (posture === 'no-encryption' || posture === 'legacy-tls') cur.criticalCount++;
    map.set(fn, cur);
  }
  return Array.from(map.values()).sort(
    (a, b) => b.criticalCount - a.criticalCount || b.count - a.count,
  );
}
