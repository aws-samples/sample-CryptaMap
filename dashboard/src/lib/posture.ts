// Pure presentation helpers that map the wire enum strings (CryptoPosture,
// PQCStatus, UpgradeEase, Severity) onto FRIENDLY labels and Cloudscape
// StatusIndicator types. No React, no Cloudscape imports — keep this framework
// agnostic so it can be unit-tested and reused across views.
//
// Source of truth for the enum vocabularies: pkg/models/finding.go (posture,
// severity) and internal/pqc/matrix.go (pqcStatus, upgradeEase, confidence).

import type { CryptoPosture, Severity } from '../types';
import type {
  PQCStatus,
  UpgradeEase,
  Confidence,
  SymmetricStrength,
  RoadmapItem,
} from '../types/roadmap';

/**
 * safeHref guards an href against `javascript:`/`data:` (and other) XSS sinks.
 * Scan-derived URLs (e.g. RoadmapItem.sourceUrl) are attacker-influenced data,
 * so only http(s) URLs are allowed to become a clickable href; anything else
 * (including a malformed or non-web scheme) returns undefined so the consumer
 * omits the link rather than rendering an active javascript: sink.
 */
export function safeHref(url: string | undefined | null): string | undefined {
  if (!url) return undefined;
  try {
    const scheme = new URL(url).protocol;
    return scheme === 'https:' || scheme === 'http:' ? url : undefined;
  } catch {
    // Not a parseable absolute URL (relative, malformed, etc.) — not safe to use
    // as an external href.
    return undefined;
  }
}

/** Cloudscape StatusIndicator `type` values we use. */
export type IndicatorType =
  | 'error'
  | 'warning'
  | 'success'
  | 'info'
  | 'pending'
  | 'in-progress'
  | 'stopped';

export interface PostureView {
  /** Friendly, human label (never a raw scanner/enum id in the UI). */
  label: string;
  /** Cloudscape StatusIndicator type used to colour the cell. */
  indicator: IndicatorType;
  /** Severity bucket this posture maps to (for sorting / KPI grouping). */
  severity: Severity;
}

// POSTURE registry — every CryptoPosture wire value gets a friendly label, an
// indicator colour, and a severity bucket. Order of severity (worst first):
// no-encryption (CRITICAL) > legacy-tls (HIGH) > non-pqc-classical (MEDIUM) >
// symmetric-only / pqc-hybrid / pqc-ready (INFORMATIONAL) > unknown.
const POSTURE: Record<CryptoPosture, PostureView> = {
  'no-encryption': { label: 'No encryption', indicator: 'error', severity: 'CRITICAL' },
  'legacy-tls': { label: 'Legacy TLS', indicator: 'error', severity: 'HIGH' },
  'non-pqc-classical': { label: 'Classical (non-PQC)', indicator: 'warning', severity: 'MEDIUM' },
  'symmetric-only': { label: 'Symmetric only', indicator: 'success', severity: 'INFORMATIONAL' },
  'pqc-hybrid': { label: 'PQC hybrid', indicator: 'success', severity: 'INFORMATIONAL' },
  'pqc-ready': { label: 'PQC ready', indicator: 'success', severity: 'INFORMATIONAL' },
  unknown: { label: 'Unknown', indicator: 'pending', severity: 'INFORMATIONAL' },
};

const UNKNOWN_POSTURE: PostureView = POSTURE.unknown;

/** Resolve a (possibly unrecognised) posture string to its presentation view. */
export function posturePresentation(posture: string | undefined): PostureView {
  if (!posture) return UNKNOWN_POSTURE;
  return POSTURE[posture as CryptoPosture] ?? UNKNOWN_POSTURE;
}

export function postureLabel(posture: string | undefined): string {
  return posturePresentation(posture).label;
}

/** Severity rank used to sort posture columns worst-first. */
const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  INFORMATIONAL: 3,
};

/** Comparator that orders two posture strings worst (CRITICAL) first. */
export function comparePostureSeverity(a: string | undefined, b: string | undefined): number {
  const ra = SEVERITY_RANK[posturePresentation(a).severity];
  const rb = SEVERITY_RANK[posturePresentation(b).severity];
  return ra - rb;
}

export function severityFromPosture(posture: string | undefined): Severity {
  return posturePresentation(posture).severity;
}

const SEVERITY_INDICATOR: Record<Severity, IndicatorType> = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  INFORMATIONAL: 'info',
};

export function severityIndicator(sev: string | undefined): IndicatorType {
  return SEVERITY_INDICATOR[(sev as Severity)] ?? 'info';
}

// --- PQC status ------------------------------------------------------------

export interface PqcStatusView {
  label: string;
  indicator: IndicatorType;
}

// PQC_STATUS registry. NOTE the asset-aware framing: backend EffectivePQCStatus
// (internal/pqc/lookup.go) already promotes a quantum-SAFE asset's "not-yet" to
// "not-applicable", so by the time a row reaches the UI, "not-applicable" means
// "already quantum-safe — no action", NOT a neutral "doesn't apply". We label it
// that way so a safe asset NEVER reads as an alarming gap. "not-yet" is reserved
// for genuinely quantum-vulnerable assets with no shipped PQC fix.
const PQC_STATUS: Record<PQCStatus, PqcStatusView> = {
  available: { label: 'PQC available', indicator: 'success' },
  'hybrid-tls-only': { label: 'PQC hybrid (TLS only)', indicator: 'info' },
  'not-yet': { label: 'Not yet available', indicator: 'warning' },
  'not-applicable': { label: 'Quantum-safe — no action', indicator: 'success' },
  // Maturity stage 0: no cryptographic baseline, so PQC readiness is not
  // assessable. Deliberately NOT 'warning' (that reads as a pending PQC fix) and
  // NOT 'success' (the resource is unencrypted — CRITICAL on the posture axis).
  // 'info' signals "different axis: fix encryption first, then re-assess PQC".
  'not-encrypted': { label: 'N/A — not encrypted', indicator: 'info' },
};

export function pqcStatusPresentation(status: string | undefined): PqcStatusView {
  if (!status) return { label: 'Unknown', indicator: 'pending' };
  return PQC_STATUS[status as PQCStatus] ?? { label: status, indicator: 'pending' };
}

export function pqcStatusLabel(status: string | undefined): string {
  return pqcStatusPresentation(status).label;
}

// Postures that are themselves a positive quantum-safe signal: symmetric-only
// (AES-256 at rest), pqc-hybrid (only auth remains classical), pqc-ready (pure
// PQC). Mirrors internal/pqc/lookup.go isQuantumSafePosture so the UI agrees
// with the backend EffectivePQCStatus rule.
const QUANTUM_SAFE_POSTURES = new Set<CryptoPosture>([
  'symmetric-only',
  'pqc-hybrid',
  'pqc-ready',
]);

/** True when a posture is already quantum-safe (no key-exchange migration needed). */
export function isQuantumSafePosture(posture: string | undefined): boolean {
  return QUANTUM_SAFE_POSTURES.has(posture as CryptoPosture);
}

/**
 * pqcStatusPresentationForAsset is the ASSET-AWARE presentation used by the
 * asset tables / detail panel. It guarantees a quantum-safe asset NEVER shows
 * the alarming "Not yet available": when the posture is itself a quantum-safe
 * signal, a 'not-yet' (or empty/missing) status is presented as
 * "Quantum-safe — no action" instead. This is the UI mirror of the backend
 * EffectivePQCStatus promotion for any row that slipped through unjoined or with
 * a stale status. For a genuine 'available' / 'hybrid-tls-only' / 'not-yet'
 * (vulnerable) status it defers to the plain pqcStatusPresentation.
 */
export function pqcStatusPresentationForAsset(
  status: string | undefined,
  posture: string | undefined,
): PqcStatusView {
  // No-encryption (stage 0) wins regardless of status: PQC is not assessable
  // until a cryptographic baseline exists. Mirrors backend EffectivePQCStatus,
  // which forces StatusNotEncrypted for this posture. Guards against a stale or
  // missing status field reading as the alarming "Not yet available".
  if (posture === 'no-encryption') {
    return PQC_STATUS['not-encrypted'];
  }
  if (isQuantumSafePosture(posture) && (status === 'not-yet' || !status || status === 'not-applicable')) {
    return { label: 'Quantum-safe — no action', indicator: 'success' };
  }
  return pqcStatusPresentation(status);
}

/** True when the asset can move to PQC today (drives the actionable-first split). */
export function isActionablePqc(status: string | undefined): boolean {
  return status === 'available' || status === 'hybrid-tls-only';
}

// --- Symmetric strength tier (additive to PQCStatus) -----------------------
//
// Mirrors internal/pqc/primitives.go SymmetricStrength. The backend stamps each
// roadmap item's `symmetricStrength` from the asset's AlgorithmProperties; these
// labels tier a symmetric cipher by its classical (and Grover-reduced) strength,
// orthogonal to the quantum-vulnerable flag.

export interface StrengthView {
  label: string;
  indicator: IndicatorType;
}

const SYMMETRIC_STRENGTH: Record<SymmetricStrength, StrengthView> = {
  // AES-256 (or stronger): Grover only halves to ~128-bit effective — safe.
  'quantum-safe': { label: 'AES-256 — quantum-safe', indicator: 'success' },
  // AES-128/192: adequate today, smaller Grover margin — review / consider AES-256.
  'adequate-review': { label: 'AES-128/192 — adequate, review', indicator: 'info' },
  // DES/3DES/RC4: classically weak or broken irrespective of quantum — replace now.
  'weak-replace': { label: 'Weak — replace now', indicator: 'warning' },
  // Bare/unsized label whose strength can't be confirmed: not safe, not weak.
  'likely-safe-unconfirmed': { label: 'Strength unconfirmed', indicator: 'pending' },
};

/** Presentation (label + indicator) for a symmetric-strength tier, if present. */
export function strengthPresentation(
  strength: string | undefined,
): StrengthView | undefined {
  if (!strength) return undefined;
  return SYMMETRIC_STRENGTH[strength as SymmetricStrength];
}

/** Friendly symmetric-strength label, or undefined when the tier does not apply. */
export function strengthLabel(strength: string | undefined): string | undefined {
  return strengthPresentation(strength)?.label;
}

// --- Upgrade ease ----------------------------------------------------------

const UPGRADE_EASE: Record<UpgradeEase, string> = {
  'one-flip': 'One flip',
  'config-change': 'Config change',
  'app-change': 'Application change',
  'aws-managed-automatic': 'AWS-managed (automatic)',
  'none-available': 'No upgrade available',
};

export function upgradeEaseLabel(ease: string | undefined): string {
  if (!ease) return '—';
  return UPGRADE_EASE[ease as UpgradeEase] ?? ease;
}

// --- Confidence ------------------------------------------------------------

const CONFIDENCE: Record<Confidence, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export function confidenceLabel(c: string | undefined): string {
  if (!c) return '—';
  return CONFIDENCE[c as Confidence] ?? c;
}

// --- Algorithm primitive ---------------------------------------------------

// CycloneDX 1.7 cryptoProperties.algorithmProperties.primitive enum -> a plain-
// language label. Without this the UI leaked raw codes like "ae" (which a non-
// crypto reader cannot interpret) into the Algorithm/Primitive rows.
const PRIMITIVE: Record<string, string> = {
  ae: 'Authenticated encryption (AES-GCM)',
  'block-cipher': 'Block cipher',
  'stream-cipher': 'Stream cipher',
  kem: 'Key encapsulation (KEM)',
  signature: 'Digital signature',
  hash: 'Hash function',
  'key-agree': 'Key agreement',
  kdf: 'Key derivation (KDF)',
  mac: 'Message authentication (MAC)',
  drbg: 'Random bit generator',
  'public-key-crypto': 'Public-key cryptography',
  other: 'Other',
  unknown: 'Unknown',
};

/**
 * Friendly label for a CycloneDX algorithm primitive code (e.g. "ae" ->
 * "Authenticated encryption (AES-GCM)"). Falls back to the raw value so an
 * unrecognized/future primitive is still shown rather than dropped.
 */
export function primitiveLabel(primitive: string | undefined): string | undefined {
  if (!primitive) return undefined;
  return PRIMITIVE[primitive] ?? primitive;
}

// --- Crypto function -------------------------------------------------------

const CRYPTO_FUNCTION: Record<string, string> = {
  'data-at-rest': 'Data at rest',
  'data-in-transit': 'Data in transit',
  'key-management': 'Key management',
  'certificates-pki': 'Certificates & PKI',
  'sdk-library': 'SDK / library',
};

/** Friendly label for a cryptoFunction wire value (falls back to the raw id). */
export function cryptoFunctionLabel(fn: string | undefined): string {
  if (!fn) return 'Other';
  return CRYPTO_FUNCTION[fn] ?? fn;
}

/** Canonical display order of crypto functions for the grouped Assets view. */
export const CRYPTO_FUNCTION_ORDER = [
  'data-at-rest',
  'data-in-transit',
  'key-management',
  'certificates-pki',
  'sdk-library',
] as const;

// --- Roadmap tier ----------------------------------------------------------
//
// TIER = f(pqcStatus, upgradeEase) ONLY. posture / mosca / exposure NEVER decide
// tier membership — they only feed the priority SCORE (which orders rows WITHIN a
// tier). This is the single source of truth for the tier predicate, reused by
// useRoadmap.ts, RoadmapTable.tsx and the RoadmapView summary band.
//
// Predicates evaluated TOP-DOWN, first match wins:
//   (1) no-action   : pqcStatus === 'not-applicable'        (checked FIRST)
//   (2) act-now     : pqcReady && lowEffort                 (isActNow)
//   (3) plan-watch  : everything else
//
// Order matters: not-applicable is gated FIRST so AES-256 symmetric-at-rest
// (ebs/rds/dynamodb/redshift/elasticache/documentdb/neptune) can never re-enter
// Act-now regardless of posture/score — the Neptune/EBS "ranked near top" bug.

export type RoadmapTier = 'act-now' | 'plan-watch' | 'no-action';

/** PQC is published for this asset (available or hybrid-TLS-only). */
function pqcReady(status: PQCStatus | undefined): boolean {
  return status === 'available' || status === 'hybrid-tls-only';
}

/** Upgrade is a one-flip or config change (low effort). */
function lowEffort(ease: UpgradeEase | undefined): boolean {
  return ease === 'one-flip' || ease === 'config-change';
}

/**
 * roadmapTier classifies a RoadmapItem into exactly one tier from pqcStatus +
 * upgradeEase ONLY. Mirrors useRoadmap.isActNow for the act-now branch so there
 * is one source of truth for the predicate.
 */
export function roadmapTier(
  item: Pick<RoadmapItem, 'pqcStatus' | 'upgradeEase'>,
): RoadmapTier {
  // (1) Already quantum-safe / nothing asymmetric to migrate — checked FIRST.
  if (item.pqcStatus === 'not-applicable') return 'no-action';
  // (2) PQC available today AND a one-flip / config-change fix.
  if (pqcReady(item.pqcStatus) && lowEffort(item.upgradeEase)) return 'act-now';
  // (3) Everything else: no published fix, or PQC needs an app/SDK/managed change.
  return 'plan-watch';
}

/** Plain-English tier label (the badge text). */
export function tierLabel(tier: RoadmapTier): string {
  switch (tier) {
    case 'act-now':
      return 'Act now';
    case 'plan-watch':
      return 'Plan / Watch';
    case 'no-action':
      return 'Safe';
  }
}

/** Cloudscape Badge colours we use for the derived tier badge. */
export type BadgeColor = 'red' | 'blue' | 'green' | 'grey' | 'severity-high';

export interface TierBadgeView {
  label: string;
  color: BadgeColor;
}

/** Derived tier badge {label, color} — replaces the raw priorityScore number. */
export function tierBadge(tier: RoadmapTier): TierBadgeView {
  switch (tier) {
    case 'act-now':
      return { label: 'Act now', color: 'red' };
    case 'plan-watch':
      return { label: 'Plan / Watch', color: 'blue' };
    case 'no-action':
      return { label: 'Safe', color: 'green' };
  }
}

/**
 * tierReason returns the one-line plain-English reason for an item's tier.
 * Plan/Watch branches on pqcStatus === 'not-yet' (no published fix) vs the
 * "PQC exists but high-effort" case.
 */
export function tierReason(item: Pick<RoadmapItem, 'pqcStatus' | 'upgradeEase'>): string {
  const tier = roadmapTier(item);
  switch (tier) {
    case 'no-action':
      return 'AES-256 at rest is already quantum-resistant — no migration needed.';
    case 'act-now':
      return 'PQC is available today and the upgrade is a one-flip or config change — start here.';
    case 'plan-watch':
      if (item.pqcStatus === 'not-encrypted') {
        // Maturity stage 0: encrypt first; PQC is not assessable without a baseline.
        return 'Resource is unencrypted — enable encryption first (stage 0). PQC readiness cannot be assessed until a cryptographic baseline exists.';
      }
      return item.pqcStatus === 'not-yet'
        ? 'No PQC fix is published for this service yet — track AWS announcements.'
        : 'PQC exists but needs an application/SDK change or AWS-managed rollout — plan the work.';
  }
}
