import PieChart from '@cloudscape-design/components/pie-chart';
import Box from '@cloudscape-design/components/box';
import type { PostureSummary } from '../hooks/useScanData';
import { postureLabel } from '../lib/posture';

// Cloudscape semantic-ish colors per severity bucket (worst = red).
const COLOR: Record<string, string> = {
  'no-encryption': '#d63a3a',
  'legacy-tls': '#e07241',
  'non-pqc-classical': '#e0a800',
  'symmetric-only': '#3a7adb',
  'pqc-hybrid': '#1f9d57',
  'pqc-ready': '#0f7d44',
  unknown: '#8a8a8a',
};

interface Datum {
  title: string;
  value: number;
  posture: string;
  color: string;
}

// PostureDonut renders the crypto-posture distribution as a Cloudscape donut.
// Zero-valued postures are dropped (PieChart skips them, and they add noise).
export default function PostureDonut({ posture }: { posture: PostureSummary }) {
  const entries: { key: string; count: number }[] = [
    { key: 'no-encryption', count: posture.noEncryption },
    { key: 'legacy-tls', count: posture.legacyTLS },
    { key: 'non-pqc-classical', count: posture.nonPQCClassical },
    { key: 'symmetric-only', count: posture.symmetricOnly },
    { key: 'pqc-hybrid', count: posture.pqcHybrid },
    { key: 'pqc-ready', count: posture.pqcReady },
    { key: 'unknown', count: posture.unknown },
  ];
  const data: Datum[] = entries
    .filter((e) => e.count > 0)
    .map((e) => ({
      title: postureLabel(e.key),
      value: e.count,
      posture: e.key,
      color: COLOR[e.key] ?? '#8a8a8a',
    }));
  const total = data.reduce((n, d) => n + d.value, 0);

  return (
    <PieChart<Datum>
      data={data}
      variant="donut"
      size="medium"
      hideFilter
      // The donut sits in a narrow 5/12 grid column. Cloudscape draws each
      // segment's title + description as text OUTSIDE the arc on leader lines;
      // with long posture names ('Non-PQC classical', etc.) those overflow the
      // chart box and truncate ('No encr…'/'Classica…'). Drop the outside
      // labels and let the full-width, wrapping legend carry the names. The
      // per-segment counts/percentages remain available via detailPopoverContent.
      hideTitles
      hideDescriptions
      ariaLabel="Crypto posture distribution"
      innerMetricValue={String(total)}
      innerMetricDescription="assets"
      detailPopoverContent={(d) => [
        { key: 'Assets', value: String(d.value) },
        {
          key: 'Share',
          value: total > 0 ? `${((d.value / total) * 100).toFixed(1)}%` : '0%',
        },
      ]}
      empty={
        <Box textAlign="center" color="text-status-inactive">
          No posture data.
        </Box>
      }
    />
  );
}
