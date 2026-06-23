// Flattens raw CBOM components into FRIENDLY, flat row objects that the
// Cloudscape Table + PropertyFilter + grouping all share. The whole UI works
// off AssetRow — raw scanner ids never reach a column or facet, only the
// friendly displayName / awsCategory / cryptoFunction derived via taxonomy.ts.

import type { CBOM, CBOMComponent } from '../types';
import { getProp, realComponents } from '../hooks/useScanData';
import * as taxonomy from './taxonomy';
import type { Roadmap, RoadmapItem } from '../types/roadmap';

export interface AssetRow {
  /** Stable id: the hyphenated CBOM bom-ref. */
  bomRef: string;
  /** Friendly service name, e.g. "AWS KMS" (never the scanner id). */
  displayName: string;
  /** Resource id parsed from the ARN / name (last path segment). */
  resourceId: string;
  resourceArn: string;
  accountId: string;
  region: string;
  awsCategory: string;
  /** cryptoFunction wire value, e.g. "data-at-rest". */
  cryptoFunction: string;
  subAspect: string;
  /** posture wire value, e.g. "no-encryption". */
  posture: string;
  /** PQC status from the joined roadmap item (or '' if unjoined). */
  pqcStatus: string;
  /** Raw scanner service id — kept for joins only, NEVER displayed. */
  service: string;
  /** The original component (for the detail panel's cryptoProperties). */
  component: CBOMComponent;
  /** The joined roadmap item (for the detail panel's PQC reasoning), if any. */
  roadmapItem?: RoadmapItem;
}

/** Extract a short resource id from an ARN (last path/colon segment). */
function resourceIdFromArn(arn: string, fallback: string): string {
  if (!arn) return fallback;
  const slash = arn.lastIndexOf('/');
  if (slash >= 0 && slash < arn.length - 1) return arn.slice(slash + 1);
  const colon = arn.lastIndexOf(':');
  if (colon >= 0 && colon < arn.length - 1) return arn.slice(colon + 1);
  return fallback;
}

/**
 * Build the flat friendly rows from a CBOM, joining each component to its
 * roadmap item by bom-ref (the roadmap's assetBomRef is a 1:1 match).
 */
export function buildAssetRows(cbom: CBOM | null, roadmap: Roadmap | null): AssetRow[] {
  if (!cbom) return [];
  const byBomRef = new Map<string, RoadmapItem>();
  for (const item of roadmap?.items ?? []) {
    if (item.assetBomRef) byBomRef.set(item.assetBomRef, item);
  }
  return realComponents(cbom).map((c) => {
    const bomRef = c['bom-ref'];
    const arn = getProp(c, 'cryptamap:resourceArn') ?? '';
    const item = byBomRef.get(bomRef);
    // resourceId: prefer the roadmap item's, then derive from the ARN, then name tail.
    const nameTail = c.name?.split('—').pop()?.trim() ?? c.name ?? bomRef;
    const resourceId = item?.resourceId || resourceIdFromArn(arn, nameTail);
    return {
      bomRef,
      displayName: taxonomy.displayName(c),
      resourceId,
      resourceArn: arn,
      accountId: getProp(c, 'cryptamap:accountId') ?? '',
      region: getProp(c, 'cryptamap:region') ?? '',
      awsCategory: taxonomy.awsCategory(c),
      cryptoFunction: taxonomy.cryptoFunction(c),
      subAspect: taxonomy.subAspect(c),
      posture: getProp(c, 'cryptamap:posture') ?? 'unknown',
      pqcStatus: item?.pqcStatus ?? '',
      service: getProp(c, 'cryptamap:service') ?? '',
      component: c,
      roadmapItem: item,
    };
  });
}

/** Distinct, sorted values for a string field across rows (for filter options). */
export function distinctValues(rows: AssetRow[], key: keyof AssetRow): string[] {
  const set = new Set<string>();
  for (const r of rows) {
    const v = r[key];
    if (typeof v === 'string' && v) set.add(v);
  }
  return Array.from(set).sort();
}

const CRITICAL_POSTURES = new Set(['no-encryption', 'legacy-tls']);

export interface GroupCount {
  /** Friendly label (service displayName or crypto-function label). */
  label: string;
  /** Stable key (raw value) for ordering / lookups. */
  key: string;
  count: number;
  critical: number;
}

// summarizeRowsBy groups friendly rows by a string field, counting totals and
// critical (no-encryption / legacy-tls) assets. Used for the Overview charts so
// the bars carry FRIENDLY labels, never raw scanner ids.
export function summarizeRowsBy(
  rows: AssetRow[],
  keyField: 'displayName' | 'cryptoFunction' | 'awsCategory',
  labelOf: (key: string) => string = (k) => k,
): GroupCount[] {
  const map = new Map<string, GroupCount>();
  for (const r of rows) {
    const key = (r[keyField] as string) || 'unknown';
    const cur = map.get(key) ?? { label: labelOf(key), key, count: 0, critical: 0 };
    cur.count++;
    if (CRITICAL_POSTURES.has(r.posture)) cur.critical++;
    map.set(key, cur);
  }
  return Array.from(map.values()).sort(
    (a, b) => b.critical - a.critical || b.count - a.count,
  );
}

export interface Coverage {
  accounts: number;
  regions: number;
}

/** Distinct account and region counts across the rows (Overview coverage KPI). */
export function coverage(rows: AssetRow[]): Coverage {
  return {
    accounts: distinctValues(rows, 'accountId').length,
    regions: distinctValues(rows, 'region').length,
  };
}
