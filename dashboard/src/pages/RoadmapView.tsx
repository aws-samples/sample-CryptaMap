import { useEffect, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Alert from '@cloudscape-design/components/alert';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import { useScanData } from '../hooks/useScanData';
import { useRoadmap, splitTiers, quickWinCount } from '../hooks/useRoadmap';
import { buildAssetRows } from '../lib/assetRows';
import type { AssetRow } from '../lib/assetRows';
import type { RoadmapItem } from '../types/roadmap';
import RoadmapTable from '../components/RoadmapTable';
import RoadmapRollups from '../components/RoadmapRollups';
import AssetDetailPanel from '../components/AssetDetailPanel';
import { useSplitPanel } from '../layout/SplitPanelContext';

const SELECT_PARAM = 'item';
// SERVICE_PARAM scopes the three tier tables + summary counts to one raw
// scanner service id (e.g. ?service=kms_spec). It is additive: the header
// (asOf/generatedFrom) and the byService/byAccount rollups below always stay
// on the FULL roadmap, only the tier tables and "Where to focus" counts
// narrow. This is what makes the AI Agent's "take me to the roadmap for KMS"
// action a real, verifiable filter rather than just a bare page navigation
// (see internal/agent/tools.go ui_view_roadmap + lib/agentActions.ts).
const SERVICE_PARAM = 'service';

// A tiny three-segment proportion bar (red / blue / green) sized by the three
// tier counts. Pure CSS flex, no chart dependency. Segments with a zero count
// render nothing.
function ProportionBar({
  actNow,
  planWatch,
  noAction,
}: {
  actNow: number;
  planWatch: number;
  noAction: number;
}) {
  const total = actNow + planWatch + noAction;
  if (total === 0) return null;
  const segments: Array<{ count: number; color: string; title: string }> = [
    { count: actNow, color: '#d91515', title: `${actNow} need action now` },
    // "needs planned work", NOT "no fix available": plan-watch also holds items
    // whose PQC fix EXISTS but is high-effort, and unencrypted assets whose fix
    // (enable encryption) is available today (see posture.ts roadmapTier).
    { count: planWatch, color: '#0972d3', title: `${planWatch} need planned work` },
    { count: noAction, color: '#037f0c', title: `${noAction} already quantum-resistant` },
  ];
  return (
    <div
      role="img"
      aria-label={`${actNow} need action now, ${planWatch} need planned work, ${noAction} already quantum-resistant`}
      style={{
        display: 'flex',
        width: '100%',
        height: 10,
        borderRadius: 4,
        overflow: 'hidden',
      }}
    >
      {segments
        .filter((s) => s.count > 0)
        .map((s) => (
          <div
            key={s.title}
            title={s.title}
            style={{ flexGrow: s.count, backgroundColor: s.color }}
          />
        ))}
    </div>
  );
}

export default function RoadmapView() {
  const { roadmap, loading, error } = useRoadmap();
  const { cbom, loading: cbomLoading } = useScanData();
  const { openSplitPanel, closeSplitPanel } = useSplitPanel();
  const [searchParams, setSearchParams] = useSearchParams();

  // Asset rows (joined to roadmap items by bom-ref) power the detail SplitPanel,
  // reusing the exact same per-asset detail used on the Assets view.
  const rows = useMemo(() => buildAssetRows(cbom, roadmap), [cbom, roadmap]);
  const rowByBomRef = useMemo(() => {
    const m = new Map<string, AssetRow>();
    for (const r of rows) m.set(r.bomRef, r);
    return m;
  }, [rows]);

  const serviceFilter = searchParams.get(SERVICE_PARAM);
  // Scoped view: only the item list narrows. asOf/generatedFrom (header) and
  // byService/byAccount (RoadmapRollups) intentionally stay on the unfiltered
  // `roadmap` so the rollups keep showing the whole scan even while the tier
  // tables above are focused on one service.
  const filteredRoadmap = useMemo(() => {
    if (!roadmap || !serviceFilter) return roadmap;
    return { ...roadmap, items: roadmap.items.filter((i) => i.service === serviceFilter) };
  }, [roadmap, serviceFilter]);
  const serviceFilterLabel = useMemo(() => {
    if (!serviceFilter) return null;
    return filteredRoadmap?.items[0]?.displayName ?? serviceFilter;
  }, [serviceFilter, filteredRoadmap]);

  const { actNow, planWatch, noAction } = useMemo(() => splitTiers(filteredRoadmap), [filteredRoadmap]);
  const quickWins = useMemo(() => quickWinCount(filteredRoadmap), [filteredRoadmap]);
  const total = actNow.length + planWatch.length + noAction.length;

  const clearServiceFilter = () => {
    const next = new URLSearchParams(searchParams);
    next.delete(SERVICE_PARAM);
    setSearchParams(next, { replace: true });
  };

  const selectedBomRef = searchParams.get(SELECT_PARAM);
  const selectedItem = useMemo<RoadmapItem | null>(() => {
    if (!selectedBomRef || !roadmap) return null;
    return roadmap.items.find((i) => i.assetBomRef === selectedBomRef) ?? null;
  }, [selectedBomRef, roadmap]);

  const handleSelect = (item: RoadmapItem) => {
    const next = new URLSearchParams(searchParams);
    if (item.assetBomRef) next.set(SELECT_PARAM, item.assetBomRef);
    setSearchParams(next, { replace: true });
  };

  // Open / refresh the SplitPanel whenever the selected roadmap item changes.
  // Reuse AssetDetailPanel via the joined AssetRow so the detail view (crypto
  // facts + PQC reasoning) is identical to the Assets view.
  useEffect(() => {
    if (selectedItem && selectedItem.assetBomRef) {
      const row = rowByBomRef.get(selectedItem.assetBomRef);
      if (row) {
        openSplitPanel({
          header: `${row.displayName} — ${row.resourceId}`,
          content: <AssetDetailPanel row={row} />,
        });
        return;
      }
    }
    closeSplitPanel();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedItem, rowByBomRef]);

  if (loading || cbomLoading) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" /> <Box variant="span">Loading roadmap…</Box>
      </Box>
    );
  }
  if (error) {
    return (
      <Box padding="l">
        <Alert type="error" header="Failed to load roadmap">
          {error}
        </Alert>
      </Box>
    );
  }
  if (!roadmap) {
    return (
      <Box padding="l">
        <Alert type="warning" header="No roadmap available">
          Place a roadmap at <code>/public/mock/roadmap.json</code> for local development.
        </Alert>
      </Box>
    );
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={`As of ${roadmap.asOf} · generated from ${roadmap.generatedFrom}`}
        >
          PQC Migration Roadmap
        </Header>
      }
    >
      <SpaceBetween size="l">
        {serviceFilter && (
          <Alert
            type="info"
            header={`Filtered to service: ${serviceFilterLabel}`}
            action={
              <Button variant="inline-link" onClick={clearServiceFilter}>
                Clear filter
              </Button>
            }
          >
            Showing only roadmap items for this service. The rollups below still cover the full scan.
          </Alert>
        )}
        {/* 1) SUMMARY BAND — plain headline + tier counts + proportion bar. */}
        <Container
          header={
            <Header
              variant="h2"
              actions={quickWins > 0 ? <Badge color="green">{quickWins} quick wins</Badge> : undefined}
            >
              Where to focus
            </Header>
          }
        >
          <SpaceBetween size="m">
            <Box variant="p">
              Of {total} assets: <strong>{actNow.length}</strong> need action now ·{' '}
              <strong>{noAction.length}</strong> already quantum-resistant ·{' '}
              <strong>{planWatch.length}</strong> need planned work (no low-effort fix today).
            </Box>
            <ProportionBar
              actNow={actNow.length}
              planWatch={planWatch.length}
              noAction={noAction.length}
            />
            <KeyValuePairs
              columns={4}
              items={[
                { label: 'Total assets', value: String(total) },
                { label: 'Act now', value: String(actNow.length) },
                { label: 'Already quantum-resistant', value: String(noAction.length) },
                { label: 'Plan / Watch', value: String(planWatch.length) },
              ]}
            />
          </SpaceBetween>
        </Container>

        {/* 2) ACT-NOW — primary ranked table. not-applicable can never appear. */}
        <Container
          header={
            <Header
              variant="h2"
              counter={`(${actNow.length})`}
              description="PQC is available today (available or hybrid TLS) AND the upgrade is a one-flip or config change. Start here."
              actions={quickWins > 0 ? <Badge color="green">{quickWins} quick wins</Badge> : undefined}
            >
              Act now — fix available today
            </Header>
          }
        >
          <RoadmapTable
            items={actNow}
            tier="act-now"
            selectedItem={selectedItem}
            onSelect={handleSelect}
            empty={
              <Box textAlign="center" color="text-status-inactive" padding="m">
                No assets can move to PQC today in this scan.
              </Box>
            }
          />
        </Container>

        {/* 3) PLAN / WATCH — secondary, collapsed by default. */}
        <ExpandableSection
          variant="container"
          defaultExpanded={false}
          headerText="Plan / Watch — needs planned work"
          headerCounter={`(${planWatch.length})`}
          headerDescription="No PQC mechanism is published yet, or PQC exists but needs an application/SDK change or AWS-managed rollout. Track these; no one-flip action exists today."
        >
          <RoadmapTable
            items={planWatch}
            tier="plan-watch"
            selectedItem={selectedItem}
            onSelect={handleSelect}
            empty={
              <Box textAlign="center" color="text-status-inactive" padding="m">
                Nothing to plan — every actionable asset has a fix available today.
              </Box>
            }
          />
        </ExpandableSection>

        {/* 4) ALREADY QUANTUM-RESISTANT — demoted, collapsed, informational. */}
        <ExpandableSection
          variant="container"
          defaultExpanded={false}
          headerText="Already quantum-resistant — no action needed"
          headerCounter={`(${noAction.length})`}
          headerDescription="Symmetric encryption at rest is already quantum-resistant — there is no asymmetric exposure to migrate, so no PQC action is required."
        >
          <RoadmapTable
            items={noAction}
            tier="no-action"
            selectedItem={selectedItem}
            onSelect={handleSelect}
            empty={
              <Box textAlign="center" color="text-status-inactive" padding="m">
                No already-quantum-resistant assets in this scan.
              </Box>
            }
          />
        </ExpandableSection>

        <RoadmapRollups byService={roadmap.byService} byAccount={roadmap.byAccount} />
      </SpaceBetween>
    </ContentLayout>
  );
}
