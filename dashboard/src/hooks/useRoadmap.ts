import { useEffect, useState } from 'react';
import type { Roadmap, RoadmapItem } from '../types/roadmap';
import { fetchRoadmap } from '../services/api';
import { roadmapTier } from '../lib/posture';

// useRoadmap loads the PQC migration roadmap (mock or live, via fetchRoadmap).
export function useRoadmap() {
  const [roadmap, setRoadmap] = useState<Roadmap | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const data = await fetchRoadmap();
        if (!cancelled) setRoadmap(data);
      } catch (e) {
        if (!cancelled) setError(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return { roadmap, loading, error };
}

export interface ActionableSplit {
  /** pqcStatus in {available, hybrid-tls-only} — "Move to PQC today". */
  actionable: RoadmapItem[];
  /** pqcStatus in {not-yet, not-applicable} — "No PQC fix yet". */
  deferred: RoadmapItem[];
}

// splitActionableFirst partitions roadmap items into the actionable-first
// "Move to PQC today" set and the deferred "No PQC fix yet" set, each preserving
// the incoming (priority-ranked) ordering.
export function splitActionableFirst(roadmap: Roadmap | null): ActionableSplit {
  const out: ActionableSplit = { actionable: [], deferred: [] };
  if (!roadmap) return out;
  for (const item of roadmap.items ?? []) {
    if (item.pqcStatus === 'available' || item.pqcStatus === 'hybrid-tls-only') {
      out.actionable.push(item);
    } else {
      out.deferred.push(item);
    }
  }
  return out;
}

// quickWinCount returns the number of roadmap items flagged as quick wins.
export function quickWinCount(roadmap: Roadmap | null): number {
  if (!roadmap) return 0;
  return (roadmap.items ?? []).reduce((n, item) => n + (item.quickWin ? 1 : 0), 0);
}

/**
 * isActNow encodes the task's "Act now — PQC available today" rule: PQC status is
 * available OR hybrid-tls-only AND the upgrade is low-effort (one-flip /
 * config-change). These are the items a team can flip on today.
 */
export function isActNow(item: RoadmapItem): boolean {
  const pqcReady = item.pqcStatus === 'available' || item.pqcStatus === 'hybrid-tls-only';
  const lowEffort = item.upgradeEase === 'one-flip' || item.upgradeEase === 'config-change';
  return pqcReady && lowEffort;
}

export interface ActNowSplit {
  /** "Act now" — actionable AND low-effort, ranked by priority then rank. */
  actNow: RoadmapItem[];
  /** Everything else (no PQC fix yet, or needs an app/managed change). */
  watch: RoadmapItem[];
}

/**
 * splitActNow partitions roadmap items into the strict "Act now" set (see
 * isActNow) and the "Watch" remainder. Both lists keep priority-desc / rank-asc
 * order. This is the partition used by the actionable-first Roadmap + Overview
 * teaser; splitActionableFirst (above) is the looser pqcStatus-only partition.
 */
export function splitActNow(roadmap: Roadmap | null): ActNowSplit {
  const out: ActNowSplit = { actNow: [], watch: [] };
  if (!roadmap) return out;
  for (const item of roadmap.items ?? []) {
    if (isActNow(item)) out.actNow.push(item);
    else out.watch.push(item);
  }
  const byPriority = (a: RoadmapItem, b: RoadmapItem) =>
    b.priorityScore - a.priorityScore || a.rank - b.rank;
  out.actNow.sort(byPriority);
  out.watch.sort(byPriority);
  return out;
}

/** Top N "Act now" items for the Overview "migrate first" teaser. */
export function topActNow(roadmap: Roadmap | null, n = 5): RoadmapItem[] {
  return splitActNow(roadmap).actNow.slice(0, n);
}

/** Comparator: priorityScore desc, then rank asc — order WITHIN a tier. */
const byPriority = (a: RoadmapItem, b: RoadmapItem) =>
  b.priorityScore - a.priorityScore || a.rank - b.rank;

export interface TierSplit {
  /** Act now — PQC available today AND a one-flip / config change. */
  actNow: RoadmapItem[];
  /** Plan / Watch — needs work but no low-effort fix published. */
  planWatch: RoadmapItem[];
  /** No action — already quantum-safe (pqcStatus === 'not-applicable'). */
  noAction: RoadmapItem[];
}

/**
 * splitTiers buckets every roadmap item by roadmapTier() (pqcStatus + upgradeEase
 * ONLY — never posture/score) and sorts each bucket by priorityScore desc / rank
 * asc. This is the three-way partition consumed by the reworked Roadmap page;
 * splitActNow / splitActionableFirst stay for the Overview teaser back-compat.
 */
export function splitTiers(roadmap: Roadmap | null): TierSplit {
  const out: TierSplit = { actNow: [], planWatch: [], noAction: [] };
  if (!roadmap) return out;
  for (const item of roadmap.items ?? []) {
    switch (roadmapTier(item)) {
      case 'act-now':
        out.actNow.push(item);
        break;
      case 'plan-watch':
        out.planWatch.push(item);
        break;
      case 'no-action':
        out.noAction.push(item);
        break;
    }
  }
  out.actNow.sort(byPriority);
  out.planWatch.sort(byPriority);
  out.noAction.sort(byPriority);
  return out;
}

export interface TierCounts {
  total: number;
  actNow: number;
  planWatch: number;
  noAction: number;
  quickWins: number;
}

/** tierCounts returns the at-a-glance totals for the summary band. */
export function tierCounts(roadmap: Roadmap | null): TierCounts {
  const { actNow, planWatch, noAction } = splitTiers(roadmap);
  return {
    total: actNow.length + planWatch.length + noAction.length,
    actNow: actNow.length,
    planWatch: planWatch.length,
    noAction: noAction.length,
    quickWins: quickWinCount(roadmap),
  };
}
