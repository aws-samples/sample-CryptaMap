import Table from '@cloudscape-design/components/table';
import type { TableProps } from '@cloudscape-design/components/table';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Box from '@cloudscape-design/components/box';
import type { AssetRow } from '../lib/assetRows';
import {
  posturePresentation,
  pqcStatusPresentationForAsset,
  cryptoFunctionLabel,
  comparePostureSeverity,
} from '../lib/posture';
import InfoPopover from './InfoPopover';
import { PostureLegendContent, PqcStatusContent } from './infoPopoverContent';

// Column definitions are shared across every AssetTable instance (the single
// table view and each per-crypto-function group). FRIENDLY values only — the
// raw cryptamap:service id is never a column.
export const ASSET_COLUMNS: TableProps.ColumnDefinition<AssetRow>[] = [
  {
    id: 'displayName',
    header: 'Service',
    cell: (r) => r.displayName,
    sortingField: 'displayName',
    isRowHeader: true,
  },
  {
    id: 'resourceId',
    header: 'Resource',
    cell: (r) => r.resourceId || '—',
    sortingField: 'resourceId',
  },
  {
    id: 'awsCategory',
    header: 'AWS category',
    cell: (r) => r.awsCategory || '—',
    sortingField: 'awsCategory',
  },
  {
    id: 'cryptoFunction',
    header: 'Crypto function',
    cell: (r) => cryptoFunctionLabel(r.cryptoFunction),
    sortingField: 'cryptoFunction',
  },
  {
    id: 'account',
    header: 'Account',
    cell: (r) => r.accountId || '—',
    sortingField: 'accountId',
  },
  {
    id: 'region',
    header: 'Region',
    cell: (r) => r.region || '—',
    sortingField: 'region',
  },
  {
    id: 'posture',
    header: 'Posture',
    cell: (r) => {
      const p = posturePresentation(r.posture);
      return (
        <InfoPopover header="What does this posture mean?" content={<PostureLegendContent />} topic="pqc">
          <StatusIndicator type={p.indicator}>{p.label}</StatusIndicator>
        </InfoPopover>
      );
    },
    // Sort posture worst-first by severity bucket, not alphabetically.
    sortingComparator: (a, b) => comparePostureSeverity(a.posture, b.posture),
  },
  {
    id: 'pqcStatus',
    header: 'PQC status',
    cell: (r) => {
      // Asset-aware: a quantum-resistant posture must never read "Not yet available",
      // even for an unjoined row with an empty/stale pqcStatus.
      const s = pqcStatusPresentationForAsset(r.pqcStatus, r.posture);
      // Only fully-unknown (no posture signal, no status) rows show a dash.
      if (!r.pqcStatus && s.label === 'Unknown') {
        return <Box color="text-status-inactive">—</Box>;
      }
      return (
        <InfoPopover header="What does this PQC status mean?" content={<PqcStatusContent />} topic="pqc">
          <StatusIndicator type={s.indicator}>{s.label}</StatusIndicator>
        </InfoPopover>
      );
    },
    sortingField: 'pqcStatus',
  },
];

interface Props {
  items: ReadonlyArray<AssetRow>;
  /** collectionProps (sorting / selection / empty) for the SHARED collection. */
  collectionProps: Partial<TableProps<AssetRow>>;
  selectedItem: AssetRow | null;
  onSelect: (row: AssetRow) => void;
  variant?: TableProps.Variant;
  /** Pagination / preferences slots rendered by the parent (only the single-table view). */
  pagination?: React.ReactNode;
  preferences?: React.ReactNode;
  header?: React.ReactNode;
  /** Optional column subset (e.g. drop the redundant cryptoFunction column in grouped view). */
  columnDefinitions?: TableProps.ColumnDefinition<AssetRow>[];
  /**
   * When true (single-table view) the table is the live collection target: it
   * receives the collection ref + interactive sorting. In grouped view multiple
   * tables share one collection, so only ONE may be managed — the rest display
   * the already-sorted `items` without re-binding the shared ref/sorting state.
   */
  managed?: boolean;
}

// AssetTable is a thin, presentational wrapper around Cloudscape Table. The
// collection logic (filter/sort/paginate) lives in the parent so a single
// PropertyFilter query drives every group simultaneously.
export default function AssetTable({
  items,
  collectionProps,
  selectedItem,
  onSelect,
  variant = 'embedded',
  pagination,
  preferences,
  header,
  columnDefinitions = ASSET_COLUMNS,
  managed = true,
}: Props) {
  // In grouped view the collection ref + sorting handlers must not be bound to
  // more than one table, so strip them for the unmanaged instances. The items
  // are already sorted by the collection upstream, so display order is correct.
  const { ref, onSortingChange, sortingColumn, sortingDescending, ...rest } =
    collectionProps as TableProps<AssetRow> & { ref?: unknown };
  const tableProps = managed
    ? collectionProps
    : (rest as Partial<TableProps<AssetRow>>);
  void ref;
  void onSortingChange;
  void sortingColumn;
  void sortingDescending;

  return (
    <Table<AssetRow>
      {...tableProps}
      variant={variant}
      items={items}
      columnDefinitions={columnDefinitions}
      trackBy="bomRef"
      selectionType="single"
      selectedItems={selectedItem ? [selectedItem] : []}
      onSelectionChange={({ detail }) => {
        const row = detail.selectedItems[0];
        if (row) onSelect(row);
      }}
      ariaLabels={{
        selectionGroupLabel: 'Asset selection',
        itemSelectionLabel: (_data, row) => `Select ${row.displayName} ${row.resourceId}`,
      }}
      stickyHeader
      resizableColumns
      header={header}
      pagination={pagination}
      preferences={preferences}
    />
  );
}
