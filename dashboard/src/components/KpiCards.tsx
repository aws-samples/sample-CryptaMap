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
  /** Honest six-tier crypto breakdown + two derived callouts (see summarizeMaturity). */
  maturity: MaturitySummary;
  /** Number of distinct accounts covered. */
  accounts: number;
  /** Number of distinct regions covered. */
  regions: number;
  /** Scan timestamp (CBOM metadata.timestamp) for the coverage caption. */
  scannedAt?: string;
  /** Quick-win count from the roadmap. */
  quickWins: number;
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
  accounts,
  regions,
  scannedAt,
  quickWins,
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
      {/* Two honest headline callouts that REPLACE the retired single headline
          percentage: the prime migration target (% quantum-vulnerable today) and true
          end-to-end PQC progress (% on PQC end-to-end, hybrid + symmetric-only
          EXCLUDED). */}
      <ColumnLayout columns={3} variant="text-grid" borders="vertical">
        <Kpi label="Total assets" value={total} sub="Cryptographic assets inventoried" />
        <Kpi
          label="% quantum-vulnerable today"
          value={`${maturity.quantumVulnerablePct}%`}
          color={maturity.quantumVulnerablePct > 0 ? 'text-status-warning' : 'inherit'}
          sub={`Traditional public-key crypto — the prime PQC migration target (of ${maturity.totalClassifiable} classifiable; excl. unknown)`}
        />
        <Kpi
          label="% on PQC end-to-end"
          value={`${maturity.pqcEndToEndPct}%`}
          color="text-status-success"
          sub={`Fully migrated to post-quantum cryptography (of ${maturity.total}; hybrid + AES-256-at-rest NOT counted)`}
        />
      </ColumnLayout>

      <Box margin={{ top: 'l' }}>
        <Box variant="awsui-key-label" margin={{ bottom: 'xs' }}>
          Crypto posture breakdown
        </Box>
        {/* The six tiers map 1:1 onto the existing CryptoPosture enum values
            (no new enum values). Worst (data hygiene) first → fully migrated. */}
        <ColumnLayout columns={6} variant="text-grid" borders="vertical">
          <Kpi
            label="No encryption"
            value={maturity.noEncryption}
            color={maturity.noEncryption > 0 ? 'text-status-error' : 'inherit'}
            sub="Encrypt first — PQC not yet assessable"
          />
          <Kpi
            label="Quantum-vulnerable (traditional public-key)"
            value={maturity.quantumVulnerable}
            color={maturity.quantumVulnerable > 0 ? 'text-status-warning' : 'inherit'}
            sub="Legacy TLS / traditional RSA-ECC — migrate to PQC"
          />
          <Kpi
            label="Quantum-resistant at rest (symmetric AES-256)"
            value={maturity.symmetricOnly}
            color="inherit"
            sub="AES-256 at rest — inventory, not a PQC-migration item"
          />
          <Kpi
            label="Hybrid PQ key exchange, traditional certificate"
            value={maturity.pqcHybrid}
            color="text-status-success"
            sub="Hybrid KEX in place; certificate still traditional"
          />
          <Kpi
            label="Migrated to post-quantum cryptography"
            value={maturity.pqcReady}
            color="text-status-success"
            sub="Fully PQC end-to-end"
          />
          <Kpi
            label="Unknown / needs investigation"
            value={maturity.unknown}
            color={maturity.unknown > 0 ? 'text-status-warning' : 'inherit'}
            sub="Posture not assessable — needs investigation"
          />
        </ColumnLayout>
      </Box>

      <Box margin={{ top: 'l' }}>
        <ColumnLayout columns={3} variant="text-grid">
          <Kpi
            label="Quick-wins available"
            value={quickWins}
            color={quickWins > 0 ? 'text-status-success' : 'inherit'}
            sub={<Link href="/roadmap">One-flip PQC upgrades →</Link>}
          />
        </ColumnLayout>
      </Box>
    </Container>
  );
}
