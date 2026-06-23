import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Link from '@cloudscape-design/components/link';
import type { PostureSummary, MaturitySummary } from '../hooks/useScanData';

interface Props {
  /** Total cryptographic assets in the CBOM. */
  total: number;
  posture: PostureSummary;
  /** Cryptographic maturity ladder (stage 0/1/2) derived from posture. */
  maturity: MaturitySummary;
  /** PQC-ready or hybrid assets (already quantum-safe key exchange / KEM). */
  pqcReadyOrHybrid: number;
  /** Number of distinct accounts covered. */
  accounts: number;
  /** Number of distinct regions covered. */
  regions: number;
  /** Scan timestamp (CBOM metadata.timestamp) for the coverage caption. */
  scannedAt?: string;
  /** Quick-win count from the roadmap. */
  quickWins: number;
  /**
   * Percentage (0-100) of ENCRYPTED assets that are quantum-safe
   * (stage2 / (stage1+stage2)). Unencrypted (stage 0) and unknown are excluded
   * from the denominator — see summarizeMaturity.
   */
  pqcReadyPct: number;
}

interface KpiProps {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  /** Cloudscape text color token for the metric (e.g. severity coloring). */
  color?: 'text-status-error' | 'text-status-warning' | 'text-status-success' | 'inherit';
}

// A single big-number KPI cell. Uses Box display=block with large strong text to
// read as a console metric tile.
function Kpi({ label, value, sub, color = 'inherit' }: KpiProps) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box
        fontSize="display-l"
        fontWeight="bold"
        color={color === 'inherit' ? undefined : color}
      >
        {value}
      </Box>
      {sub && (
        <Box variant="small" color="text-body-secondary">
          {sub}
        </Box>
      )}
    </div>
  );
}

// KpiCards renders the Overview KPI band. Counts are derived from PostureSummary
// + the roadmap quick-win count; coverage from distinct accounts/regions.
export default function KpiCards({
  total,
  posture,
  maturity,
  pqcReadyOrHybrid,
  accounts,
  regions,
  scannedAt,
  quickWins,
  pqcReadyPct,
}: Props) {
  // Coverage is CONTEXT for the metrics (which accounts/regions these numbers
  // cover), not a metric itself — so it rides in the panel header as a caption
  // rather than as an orphaned 9th tile in the 4-column grid.
  // e.g. "6 accounts · 17 regions · scanned 2026-06-12". The CBOM timestamp is
  // ISO; show just the date (YYYY-MM-DD) for a clean caption.
  const scannedDate = scannedAt ? scannedAt.slice(0, 10) : '';
  const coverage =
    `${accounts} account${accounts === 1 ? '' : 's'} · ${regions} region${regions === 1 ? '' : 's'}` +
    (scannedDate ? ` · scanned ${scannedDate}` : '');
  return (
    <Container
      header={
        <Header variant="h2" description={coverage}>
          Key metrics
        </Header>
      }
    >
      <ColumnLayout columns={4} variant="text-grid">
        <Kpi label="Total assets" value={total} sub="Cryptographic assets inventoried" />
        <Kpi
          label="Unencrypted"
          value={maturity.stage0Unencrypted}
          color={maturity.stage0Unencrypted > 0 ? 'text-status-error' : 'inherit'}
          sub="Stage 0 — encrypt first (excluded from PQC %)"
        />
        <Kpi
          label="Encrypted, quantum-vulnerable"
          value={maturity.stage1Vulnerable}
          color={maturity.stage1Vulnerable > 0 ? 'text-status-warning' : 'inherit'}
          sub="Stage 1 — legacy TLS / classical (non-PQC)"
        />
        <Kpi
          label="Quantum-safe"
          value={maturity.stage2QuantumSafe}
          color="text-status-success"
          sub="Stage 2 — AES-256 / PQC hybrid / PQC ready"
        />
        <Kpi
          label="% quantum-safe"
          value={`${pqcReadyPct}%`}
          color="text-status-success"
          sub={`Stage 2 of ${maturity.encrypted} encrypted (excl. unencrypted & unknown)`}
        />
        <Kpi
          label="PQC-ready / hybrid"
          value={pqcReadyOrHybrid}
          color="text-status-success"
          sub="Already quantum-safe key exchange"
        />
        <Kpi
          label="Unclassified"
          value={maturity.unknown}
          color={maturity.unknown > 0 ? 'text-status-warning' : 'inherit'}
          sub="Posture not assessable — excluded from PQC %"
        />
        <Kpi
          label="Quick-wins available"
          value={quickWins}
          color={quickWins > 0 ? 'text-status-success' : 'inherit'}
          sub={<Link href="/roadmap">One-flip PQC upgrades →</Link>}
        />
      </ColumnLayout>
    </Container>
  );
}
