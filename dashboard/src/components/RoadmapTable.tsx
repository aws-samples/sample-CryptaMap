import Table from '@cloudscape-design/components/table';
import type { TableProps } from '@cloudscape-design/components/table';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Badge from '@cloudscape-design/components/badge';
import Box from '@cloudscape-design/components/box';
import Link from '@cloudscape-design/components/link';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Popover from '@cloudscape-design/components/popover';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import CopyToClipboard from '@cloudscape-design/components/copy-to-clipboard';
import { Link as RouterLink } from 'react-router-dom';
import type { RoadmapItem } from '../types/roadmap';
import {
  posturePresentation,
  postureLabel,
  pqcStatusPresentation,
  upgradeEaseLabel,
  cryptoFunctionLabel,
  roadmapTier,
  tierBadge,
  strengthLabel,
  safeHref,
  type RoadmapTier,
} from '../lib/posture';
import InfoPopover from './InfoPopover';
import { PostureLegendContent, MoscaContent, PqcStatusContent } from './infoPopoverContent';

const DASH = '—';

// --- Reusable cells --------------------------------------------------------

// Resource cell: the (often opaque) resourceId rendered as code with a
// copy-to-clipboard affordance, plus a human-readable crypto-function hint so
// ids like "0v2elxh9mb" read as a resource. stopPropagation on the copy button
// keeps clicking copy from selecting the row / opening the detail SplitPanel.
function ResourceCell({ item }: { item: RoadmapItem }) {
  const id = item.resourceId || '';
  return (
    <SpaceBetween size="xxxs">
      {id ? (
        <span
          onClick={(e) => e.stopPropagation()}
          onPointerDown={(e) => e.stopPropagation()}
        >
          <CopyToClipboard
            variant="inline"
            textToCopy={id}
            copyButtonText={id}
            copySuccessText="Resource ID copied"
            copyErrorText="Could not copy resource ID"
          />
        </span>
      ) : (
        <Box variant="code">{DASH}</Box>
      )}
      <Box variant="small" color="text-body-secondary">
        {cryptoFunctionLabel(item.cryptoFunction)}
      </Box>
    </SpaceBetween>
  );
}

// Priority cell: the plain-English tier Badge; the RAW priorityScore + Mosca
// breakdown live ONLY inside the Popover ("Why this priority"), so the visible
// text stays human-readable.
function PriorityCell({ item }: { item: RoadmapItem }) {
  const tier = roadmapTier(item);
  const badge = tierBadge(tier);
  const m = item.mosca;
  return (
    <Popover
      triggerType="custom"
      dismissButton
      header="Why this priority"
      content={
        <SpaceBetween size="s">
          <KeyValuePairs
            columns={1}
            items={[
              { label: 'Priority score', value: item.priorityScore.toFixed(1) },
              {
                label: 'Mosca (X + Y − Z)',
                value: m ? `${m.x} + ${m.y} − ${m.z}  ·  score ${m.score.toFixed(1)}` : DASH,
              },
              { label: 'Severity', value: item.severity },
              { label: 'Posture', value: postureLabel(item.posture) },
              { label: 'Harvest-now-decrypt-later', value: item.hndlExposed ? 'Yes' : 'No' },
            ]}
          />
          <MoscaContent />
          <Box>
            <RouterLink to="/learn?topic=pqc">How CryptaMap scores assets →</RouterLink>
          </Box>
        </SpaceBetween>
      }
    >
      <Badge color={badge.color}>{badge.label}</Badge>
    </Popover>
  );
}

// Recommended-action cell: plain-English action + the cited external AWS
// guidance link + an internal placeholder "Why does this matter?" link to
// /learn (route not built yet — internal react-router Link, no external icon).
function ActionCell({ item }: { item: RoadmapItem }) {
  const sourceHref = safeHref(item.sourceUrl);
  return (
    <SpaceBetween size="xxs">
      {item.recommendedAction ? (
        <Box>{item.recommendedAction}</Box>
      ) : (
        <Box color="text-status-inactive">No managed PQC action available yet</Box>
      )}
      <SpaceBetween size="m" direction="horizontal">
        {sourceHref && (
          <Link href={sourceHref} external target="_blank">
            AWS guidance
          </Link>
        )}
        <RouterLink
          to="/learn?topic=pqc"
          style={{ color: 'inherit' }}
          onClick={(e) => e.stopPropagation()}
          onPointerDown={(e) => e.stopPropagation()}
        >
          Why does this matter?
        </RouterLink>
      </SpaceBetween>
    </SpaceBetween>
  );
}

// --- Column definitions ----------------------------------------------------

const RANK_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'rank',
  header: 'Rank',
  cell: (i) => i.rank,
  sortingField: 'rank',
  width: 70,
};

const SERVICE_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'service',
  header: 'Service',
  cell: (i) => (
    <SpaceBetween size="xxs" direction="horizontal">
      <span>{i.displayName}</span>
      {i.quickWin && <Badge color="green">Quick win</Badge>}
    </SpaceBetween>
  ),
  sortingField: 'displayName',
  isRowHeader: true,
};

const RESOURCE_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'resource',
  header: 'Resource',
  cell: (i) => <ResourceCell item={i} />,
  sortingField: 'resourceId',
  minWidth: 160,
};

const ACCOUNT_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'account',
  header: 'Account',
  cell: (i) => i.accountId || DASH,
  sortingField: 'accountId',
  width: 130,
};

const REGION_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'region',
  header: 'Region',
  cell: (i) => i.region || DASH,
  sortingField: 'region',
  width: 120,
};

const TIER_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'tier',
  header: 'Priority',
  cell: (i) => <PriorityCell item={i} />,
  sortingField: 'priorityScore',
  width: 150,
};

const POSTURE_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'posture',
  header: 'Posture',
  cell: (i) => {
    const p = posturePresentation(i.posture);
    return (
      <InfoPopover header="What does this posture mean?" content={<PostureLegendContent />} topic="pqc">
        <StatusIndicator type={p.indicator}>{p.label}</StatusIndicator>
      </InfoPopover>
    );
  },
  sortingField: 'posture',
};

const PQC_STATUS_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'pqcStatus',
  header: 'PQC status',
  cell: (i) => {
    // Roadmap items are already asset-aware (backend EffectivePQCStatus), so the
    // plain presentation is correct here; the symmetric-strength label is shown
    // as a secondary line when present.
    const s = pqcStatusPresentation(i.pqcStatus);
    const strength = strengthLabel(i.symmetricStrength);
    return (
      <SpaceBetween size="xxxs">
        <InfoPopover header="What does this PQC status mean?" content={<PqcStatusContent />} topic="pqc">
          <StatusIndicator type={s.indicator}>{s.label}</StatusIndicator>
        </InfoPopover>
        {strength && (
          <Box variant="small" color="text-body-secondary">
            {strength}
          </Box>
        )}
      </SpaceBetween>
    );
  },
  sortingField: 'pqcStatus',
};

const UPGRADE_EASE_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'upgradeEase',
  header: 'Effort',
  cell: (i) => upgradeEaseLabel(i.upgradeEase),
  sortingField: 'upgradeEase',
};

const ACTION_COLUMN: TableProps.ColumnDefinition<RoadmapItem> = {
  id: 'action',
  header: 'Recommended action',
  cell: (i) => <ActionCell item={i} />,
  minWidth: 340,
};

// columnsForTier returns the column set for a tier. The no-action ("Safe") table
// is informational — uniformly quantum-safe — so it omits the Rank and Priority
// (tier urgency) columns.
function columnsForTier(tier: RoadmapTier): TableProps.ColumnDefinition<RoadmapItem>[] {
  if (tier === 'no-action') {
    return [
      SERVICE_COLUMN,
      RESOURCE_COLUMN,
      ACCOUNT_COLUMN,
      REGION_COLUMN,
      POSTURE_COLUMN,
      PQC_STATUS_COLUMN,
      UPGRADE_EASE_COLUMN,
      ACTION_COLUMN,
    ];
  }
  return [
    RANK_COLUMN,
    SERVICE_COLUMN,
    RESOURCE_COLUMN,
    ACCOUNT_COLUMN,
    REGION_COLUMN,
    TIER_COLUMN,
    POSTURE_COLUMN,
    PQC_STATUS_COLUMN,
    UPGRADE_EASE_COLUMN,
    ACTION_COLUMN,
  ];
}

interface Props {
  items: ReadonlyArray<RoadmapItem>;
  /** Tier this table renders — selects the column set (no-action hides urgency). */
  tier: RoadmapTier;
  selectedItem: RoadmapItem | null;
  onSelect: (item: RoadmapItem) => void;
  variant?: TableProps.Variant;
  empty?: React.ReactNode;
  header?: React.ReactNode;
}

// RoadmapTable is a presentational ranked table used by all three roadmap tier
// sections (Act now / Plan-Watch / Already quantum-safe). The caller supplies
// the (already-partitioned, already-ranked) item slice plus its tier.
export default function RoadmapTable({
  items,
  tier,
  selectedItem,
  onSelect,
  variant = 'embedded',
  empty,
  header,
}: Props) {
  return (
    <Table<RoadmapItem>
      items={items}
      columnDefinitions={columnsForTier(tier)}
      variant={variant}
      trackBy="assetBomRef"
      selectionType="single"
      selectedItems={selectedItem ? [selectedItem] : []}
      onSelectionChange={({ detail }) => {
        const row = detail.selectedItems[0];
        if (row) onSelect(row);
      }}
      ariaLabels={{
        selectionGroupLabel: 'Roadmap item selection',
        itemSelectionLabel: (_d, i) => `Select ${i.displayName} ${i.resourceId}`,
      }}
      wrapLines
      resizableColumns
      stickyHeader
      header={header}
      empty={
        empty ?? (
          <Box textAlign="center" color="text-status-inactive">
            No roadmap items in this section.
          </Box>
        )
      }
    />
  );
}
