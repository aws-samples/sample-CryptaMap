import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import InfoPopover from './InfoPopover';
import type { KnowledgeProvenance } from '../hooks/useScanData';

interface Props {
  provenance: KnowledgeProvenance;
  /**
   * The scan timestamp (cbom.metadata.timestamp). Freshness is measured as the
   * gap between the scan and the OLDEST knowledge fact (minAsOf), so an archived
   * scan reports the freshness it actually had at run time — the colour does not
   * drift with wall-clock time.
   */
  scanTimestamp?: string;
}

type Freshness = { color: 'green' | 'blue' | 'grey'; label: string; stale: boolean };

const DAY_MS = 24 * 60 * 60 * 1000;

// daysBetween returns whole days from a→b, or null if either date is unparseable.
function daysBetween(a: string, b: string): number | null {
  const ta = Date.parse(a);
  const tb = Date.parse(b);
  if (Number.isNaN(ta) || Number.isNaN(tb)) return null;
  return Math.round((tb - ta) / DAY_MS);
}

// freshness grades the knowledge by the age of its OLDEST fact (minAsOf) relative
// to the scan. The headline is intentionally the weakest link, not the newest
// fact — a single stale row is what an auditor cares about.
function freshness(p: KnowledgeProvenance, scanTimestamp?: string): Freshness {
  const ref = scanTimestamp ?? p.maxAsOf; // fall back to newest fact if no scan ts
  const ageDays = ref ? daysBetween(p.minAsOf, ref) : null;
  if (ageDays === null) return { color: 'blue', label: 'Knowledge', stale: false };
  if (ageDays <= 180) return { color: 'green', label: 'Knowledge fresh', stale: false };
  if (ageDays <= 365) return { color: 'blue', label: 'Knowledge aging', stale: false };
  return { color: 'grey', label: 'Knowledge stale', stale: true };
}

// KnowledgeFreshnessBadge surfaces HOW FRESH the PQC knowledge was at scan time
// (the knowledge:* CBOM metadata): the source (embedded air-gap baseline vs. a
// validated newer override), the version, and the conservative "oldest fact"
// headline. The (i) popover explains the basis and lists the full provenance.
export default function KnowledgeFreshnessBadge({ provenance: p, scanTimestamp }: Props) {
  const f = freshness(p, scanTimestamp);
  const sourceLabel =
    p.source === 'embedded'
      ? 'Embedded baseline'
      : p.source === 'override'
        ? 'Refreshed (override)'
        : p.source || 'unknown';

  const items = [
    { label: 'Source', value: sourceLabel },
    { label: 'Knowledge version', value: p.version || '—' },
    { label: 'Oldest fact (weakest link)', value: p.minAsOf || '—' },
    { label: 'Newest fact', value: p.maxAsOf || '—' },
    { label: 'Facts', value: String(p.factCount) },
  ];
  if (p.overrideError) {
    items.push({ label: 'Override NOT applied', value: p.overrideError });
  }

  return (
    <InfoPopover
      header="PQC knowledge freshness"
      topic="aws"
      learnText="About CryptaMap's PQC knowledge"
      content={
        <Box>
          <Box variant="p">
            CryptaMap classifies assets against a baked-in post-quantum knowledge
            set (the AWS PQC support matrix + documented per-service crypto facts),
            each fact dated and sourced. The headline below is the{' '}
            <b>oldest</b> fact — the conservative weakest-link freshness — not the
            newest. An <b>embedded</b> source is the air-gap baseline shipped in the
            binary; an <b>override</b> means a validated, newer knowledge file took
            effect.
          </Box>
          <Box padding={{ top: 's' }}>
            <KeyValuePairs columns={1} items={items} />
          </Box>
          {p.overrideError && (
            <Box padding={{ top: 's' }}>
              <StatusIndicator type="warning">
                A newer knowledge override was found but rejected; the embedded
                baseline is in effect.
              </StatusIndicator>
            </Box>
          )}
        </Box>
      }
    >
      <Badge color={f.color}>
        {sourceLabel} · facts as of {p.minAsOf || '—'}
      </Badge>
    </InfoPopover>
  );
}
