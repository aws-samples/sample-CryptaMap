import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Alert from '@cloudscape-design/components/alert';
import Grid from '@cloudscape-design/components/grid';
import Cards from '@cloudscape-design/components/cards';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Button from '@cloudscape-design/components/button';
import {
  useScanData,
  useSummary,
  summarizePosture,
  summarizeMaturity,
  postureFromCounts,
  knowledgeProvenance,
  realComponents,
} from '../hooks/useScanData';
import { useRoadmap, quickWinCount, topActNow } from '../hooks/useRoadmap';
import {
  buildAssetRows,
  summarizeRowsBy,
  coverage,
  type GroupCount,
} from '../lib/assetRows';
import { cryptoFunctionLabel, posturePresentation, safeHref, upgradeEaseLabel } from '../lib/posture';
import KpiCards from '../components/KpiCards';
import CoveragePanel from '../components/CoveragePanel';
import ReportsTeaser from '../components/ReportsTeaser';
import PostureDonut from '../components/PostureDonut';
import ServiceBar from '../components/ServiceBar';
import KnowledgeFreshnessBadge from '../components/KnowledgeFreshnessBadge';
import type { RoadmapItem } from '../types/roadmap';

const toBarData = (groups: GroupCount[]) =>
  groups.map((g) => ({ label: g.label, critical: g.critical, other: g.count - g.critical }));

export default function Overview() {
  const { cbom, loading, error } = useScanData();
  const { roadmap, loading: roadmapLoading } = useRoadmap();
  // Prefer the precomputed /summary rollup for the KPI band + maturity ladder so a
  // large org doesn't download the full CBOM just for counts. A null summary is
  // non-fatal — we fall back to deriving counts from the CBOM below.
  const { summary } = useSummary();
  const navigate = useNavigate();

  const rows = useMemo(() => buildAssetRows(cbom, roadmap), [cbom, roadmap]);
  const byFunction = useMemo(
    () => summarizeRowsBy(rows, 'cryptoFunction', cryptoFunctionLabel),
    [rows],
  );
  const byService = useMemo(() => summarizeRowsBy(rows, 'displayName'), [rows]);
  // Secondary lens: AWS-category breakdown (compute / storage / database / …).
  // Crypto function stays the PRIMARY organizing principle; this is an
  // alternate "where do my assets live in AWS" view of the same rows.
  const byCategory = useMemo(() => summarizeRowsBy(rows, 'awsCategory'), [rows]);
  const teaser = useMemo(() => topActNow(roadmap, 5), [roadmap]);

  if (loading || roadmapLoading) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" /> <Box variant="span">Loading scan data…</Box>
      </Box>
    );
  }
  if (error) {
    return (
      <Box padding="l">
        <Alert type="error" header="Failed to load scan data">
          {error}
        </Alert>
      </Box>
    );
  }
  if (!cbom) {
    return (
      <Box padding="l">
        <Alert type="warning" header="No scan data available">
          Place a CBOM at <code>/public/mock/org-cbom.json</code> for local development,
          or deploy the stacks and run <code>cryptamap</code> to populate the API.
        </Alert>
      </Box>
    );
  }

  // KPI band + maturity ladder source the per-posture counts from /summary when it
  // carries a posture rollup (perPosture), avoiding a full-CBOM scan; otherwise we
  // derive them from the CBOM exactly as before (mock mode, or a summary that omits
  // the posture breakdown). Charts + coverage below still use the CBOM rows.
  const posture =
    summary?.perPosture ? postureFromCounts(summary.perPosture) : summarizePosture(cbom);
  const total = summary?.totalAssets ?? realComponents(cbom).length;
  const cov = coverage(rows);
  const pqcReadyOrHybrid = posture.pqcReady + posture.pqcHybrid;
  // Maturity ladder: stage0 unencrypted → stage1 encrypted-vulnerable → stage2
  // quantum-safe. "% quantum-safe" is stage2 / encrypted (stage1+stage2), so
  // unencrypted (stage 0) and unknown are excluded from the denominator — they are
  // a data-hygiene / unassessable concern, not a quantum-readiness shortfall.
  const maturity = summarizeMaturity(posture);
  const pqcReadyPct = maturity.quantumSafePct;

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={`Spec ${cbom.specVersion} · ${cbom.metadata.timestamp}`}
          actions={
            <SpaceBetween size="s" direction="horizontal" alignItems="center">
              {(() => {
                const prov = knowledgeProvenance(cbom);
                return prov ? (
                  <KnowledgeFreshnessBadge
                    provenance={prov}
                    scanTimestamp={cbom.metadata.timestamp}
                  />
                ) : null;
              })()}
              <Button onClick={() => navigate('/roadmap')}>View PQC roadmap</Button>
            </SpaceBetween>
          }
        >
          Cryptographic Posture Overview
        </Header>
      }
    >
      <SpaceBetween size="l">
        {summary && (summary.incomplete === true || summary.complete === false) && (
          <Alert type="warning" header="Scan incomplete — inventory understates the true org footprint">
            <SpaceBetween size="s">
              <Box>
                {summary.missingShards > 0 ? (
                  <>
                    {summary.missingShards} of {summary.expectedShards} scan shards
                    are missing from this run.{' '}
                  </>
                ) : null}
                Some accounts or regions did not return results, so the counts below
                are partial. Re-run the scan or check the orchestration logs before
                treating this as a complete inventory.
              </Box>
              {summary.failedShards && summary.failedShards.length > 0 && (
                <Box>
                  <Box variant="strong" margin={{ bottom: 'xxs' }}>
                    Dropped / failed account &amp; region(s):
                  </Box>
                  <ul style={{ margin: 0, paddingInlineStart: '1.2em' }}>
                    {summary.failedShards.map((fs, i) => (
                      <li key={`${fs.accountId}-${fs.region}-${i}`}>
                        <Box variant="code">
                          {fs.accountId}
                          {fs.region && fs.region !== '*' ? ` / ${fs.region}` : ' / (all regions)'}
                        </Box>{' '}
                        — {fs.reason}
                      </li>
                    ))}
                  </ul>
                </Box>
              )}
            </SpaceBetween>
          </Alert>
        )}

        <KpiCards
          total={total}
          posture={posture}
          maturity={maturity}
          pqcReadyOrHybrid={pqcReadyOrHybrid}
          accounts={cov.accounts}
          regions={cov.regions}
          scannedAt={cbom.metadata.timestamp}
          quickWins={quickWinCount(roadmap)}
          pqcReadyPct={pqcReadyPct}
        />

        <ReportsTeaser />

        <CoveragePanel />

        <Grid gridDefinition={[{ colspan: { default: 12, m: 5 } }, { colspan: { default: 12, m: 7 } }]}>
          <Container header={<Header variant="h2">Posture distribution</Header>}>
            <PostureDonut posture={posture} />
          </Container>
          <Container
            header={
              <Header variant="h2" description="Assets per crypto function; red = critical exposure">
                By crypto function
              </Header>
            }
          >
            <ServiceBar
              data={toBarData(byFunction)}
              ariaLabel="Assets by crypto function"
              xTitle="Crypto function"
            />
          </Container>
        </Grid>

        <Grid gridDefinition={[{ colspan: { default: 12, m: 7 } }, { colspan: { default: 12, m: 5 } }]}>
          <Container
            header={
              <Header variant="h2" description="Top services by asset count; red = critical exposure">
                By AWS service
              </Header>
            }
          >
            <ServiceBar
              data={toBarData(byService.slice(0, 15))}
              ariaLabel="Assets by AWS service"
              xTitle="Service"
            />
          </Container>
          <Container
            header={
              <Header
                variant="h2"
                description="Secondary lens: assets by AWS service category; red = critical exposure"
              >
                By AWS category
              </Header>
            }
          >
            <ServiceBar
              data={toBarData(byCategory)}
              ariaLabel="Assets by AWS service category"
              xTitle="AWS category"
            />
          </Container>
        </Grid>

        <Container
          header={
            <Header
              variant="h2"
              counter={`(${teaser.length})`}
              description="Highest-priority assets you can move to PQC today with a one-flip or config change."
              actions={<Link href="/roadmap">Full PQC roadmap →</Link>}
            >
              Migrate first
            </Header>
          }
        >
          {teaser.length === 0 ? (
            <Box textAlign="center" color="text-status-inactive" padding="m">
              No "act now" PQC items in the current scan.
            </Box>
          ) : (
            <Cards<RoadmapItem>
              items={teaser}
              trackBy="assetBomRef"
              cardDefinition={{
                header: (i) => (
                  <SpaceBetween size="xxs" direction="horizontal">
                    <Link
                      fontSize="heading-m"
                      onFollow={() => navigate(`/roadmap?item=${encodeURIComponent(i.assetBomRef ?? '')}`)}
                    >
                      #{i.rank} {i.displayName}
                    </Link>
                    {i.quickWin && <Badge color="green">Quick win</Badge>}
                  </SpaceBetween>
                ),
                sections: [
                  {
                    id: 'posture',
                    content: (i) => {
                      const p = posturePresentation(i.posture);
                      return (
                        <SpaceBetween size="xxs" direction="horizontal">
                          <StatusIndicator type={p.indicator}>{p.label}</StatusIndicator>
                          <Box variant="small" color="text-body-secondary">
                            priority {i.priorityScore.toFixed(1)} · {upgradeEaseLabel(i.upgradeEase)}
                          </Box>
                        </SpaceBetween>
                      );
                    },
                  },
                  {
                    id: 'resource',
                    content: (i) => (
                      <Box variant="small" color="text-body-secondary">
                        {i.resourceId} · {i.accountId} · {i.region}
                      </Box>
                    ),
                  },
                  {
                    id: 'action',
                    header: 'Recommended AWS action',
                    content: (i) => (
                      <SpaceBetween size="xxs">
                        <Box>{i.recommendedAction}</Box>
                        {safeHref(i.sourceUrl) && (
                          <Link href={safeHref(i.sourceUrl)} external target="_blank">
                            AWS guidance
                          </Link>
                        )}
                      </SpaceBetween>
                    ),
                  },
                ],
              }}
              cardsPerRow={[{ cards: 1 }, { minWidth: 700, cards: 2 }]}
            />
          )}
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
