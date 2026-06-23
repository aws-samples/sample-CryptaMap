import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useCollection } from '@cloudscape-design/collection-hooks';
import type { PropertyFilterProps } from '@cloudscape-design/components/property-filter';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Alert from '@cloudscape-design/components/alert';
import PropertyFilter from '@cloudscape-design/components/property-filter';
import Pagination from '@cloudscape-design/components/pagination';
import CollectionPreferences from '@cloudscape-design/components/collection-preferences';
import SegmentedControl from '@cloudscape-design/components/segmented-control';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import { useScanData } from '../hooks/useScanData';
import { useRoadmap } from '../hooks/useRoadmap';
import { buildAssetRows, distinctValues } from '../lib/assetRows';
import type { AssetRow } from '../lib/assetRows';
import { CRYPTO_FUNCTION_ORDER, cryptoFunctionLabel } from '../lib/posture';
import AssetTable, { ASSET_COLUMNS } from '../components/AssetTable';
import AssetDetailPanel from '../components/AssetDetailPanel';
import { useSplitPanel } from '../layout/SplitPanelContext';

// The six locked facets (design filterFacets). Each maps a PropertyFilter key
// onto a field on AssetRow; options are enumerated from the loaded CBOM.
const FACETS: { key: keyof AssetRow; propertyLabel: string; groupValuesLabel: string }[] = [
  { key: 'accountId', propertyLabel: 'Account', groupValuesLabel: 'AWS Account' },
  { key: 'region', propertyLabel: 'Region', groupValuesLabel: 'Region' },
  { key: 'awsCategory', propertyLabel: 'AWS category', groupValuesLabel: 'AWS category' },
  { key: 'cryptoFunction', propertyLabel: 'Crypto function', groupValuesLabel: 'Crypto function' },
  { key: 'posture', propertyLabel: 'Posture', groupValuesLabel: 'Crypto posture' },
  { key: 'pqcStatus', propertyLabel: 'PQC status', groupValuesLabel: 'PQC status' },
];

const PROPERTY_FILTER_I18N: PropertyFilterProps.I18nStrings = {
  filteringAriaLabel: 'Filter assets',
  filteringPlaceholder: 'Filter assets by property or free text',
  operationAndText: 'and',
  operationOrText: 'or',
  operatorsText: 'Operators',
  operatorContainsText: 'Contains',
  operatorDoesNotContainText: 'Does not contain',
  operatorEqualsText: 'Equals',
  operatorDoesNotEqualText: 'Does not equal',
  clearFiltersText: 'Clear filters',
  applyActionText: 'Apply',
  cancelActionText: 'Cancel',
  editTokenHeader: 'Edit filter',
  propertyText: 'Property',
  operatorText: 'Operator',
  valueText: 'Value',
  allPropertiesLabel: 'All properties',
  tokenLimitShowMore: 'Show more',
  tokenLimitShowFewer: 'Show fewer',
  removeTokenButtonAriaLabel: () => 'Remove filter',
  enteredTextLabel: (text) => `Use: "${text}"`,
};

const QUERY_PARAM = 'q';
const SELECT_PARAM = 'asset';

const EMPTY_QUERY: PropertyFilterProps.Query = { tokens: [], operation: 'and' };

// Validate the shape of a query parsed from the (untrusted) URL ?q= param before
// applying it. A crafted shared link could otherwise put the PropertyFilter into
// a weird state (bad operation, malformed tokens). Returns the validated query,
// or the empty default on any shape mismatch — never throws.
function parseQueryParam(raw: string | null): PropertyFilterProps.Query {
  if (!raw) return EMPTY_QUERY;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return EMPTY_QUERY;
    const { tokens, operation } = parsed as Record<string, unknown>;
    if (operation !== 'and' && operation !== 'or') return EMPTY_QUERY;
    if (!Array.isArray(tokens)) return EMPTY_QUERY;
    const validTokens: PropertyFilterProps.Token[] = [];
    for (const t of tokens) {
      if (typeof t !== 'object' || t === null) return EMPTY_QUERY;
      const { propertyKey, value, operator } = t as Record<string, unknown>;
      // operator is required; propertyKey is optional (free-text tokens omit it).
      if (typeof operator !== 'string') return EMPTY_QUERY;
      if (propertyKey !== undefined && typeof propertyKey !== 'string') return EMPTY_QUERY;
      validTokens.push({
        propertyKey: propertyKey as string | undefined,
        value,
        operator,
      });
    }
    return { tokens: validTokens, operation };
  } catch {
    /* malformed JSON — fall back to the empty default */
    return EMPTY_QUERY;
  }
}

// Postures counted as "critical" for the per-group red badge (mirrors
// CRITICAL_POSTURES in lib/assetRows.ts).
const CRITICAL_POSTURES = new Set(['no-encryption', 'legacy-tls']);

// 'grouped' = by crypto function (PRIMARY lens); 'category' = secondary AWS-category
// lens; 'all' = flat single table.
type ViewMode = 'grouped' | 'category' | 'all';

// Tab-freeze guard (SCALING.md §4.3, dashboard side): the grouped / by-category
// views have NO pagination control — each group renders one Cloudscape <Table>
// row per asset, which freezes the tab at tens of thousands of rows. We have no
// virtualization dep (react-window), so when the FILTERED set crosses this
// threshold we cap each group's initial render to GROUP_CHUNK rows with a
// "showing N of M" note + a "Show more" button that reveals another chunk. Below
// the threshold every group renders in full (the common case). The flat 'all'
// view is already paginated and is left untouched.
const GROUPED_ROW_THRESHOLD = 2000;
const GROUP_CHUNK = 200;

export default function AssetsView() {
  const { cbom, loading: cbomLoading, error: cbomError } = useScanData();
  const { roadmap, loading: roadmapLoading } = useRoadmap();
  const { openSplitPanel, closeSplitPanel } = useSplitPanel();
  const [searchParams, setSearchParams] = useSearchParams();
  const [viewMode, setViewMode] = useState<ViewMode>('grouped');
  // Per-group reveal count (tab-freeze guard). Keyed by group key; absent ⇒ the
  // default GROUP_CHUNK cap. Only consulted when the filtered set is large (see
  // GROUPED_ROW_THRESHOLD); reset whenever the filter changes so a fresh query
  // starts from the capped view again.
  const [revealed, setRevealed] = useState<Record<string, number>>({});

  const rows = useMemo(() => buildAssetRows(cbom, roadmap), [cbom, roadmap]);

  // Build PropertyFilter facets + enumerated options from the loaded rows.
  const filteringProperties = useMemo<PropertyFilterProps.FilteringProperty[]>(
    () =>
      FACETS.map((f) => ({
        key: f.key as string,
        propertyLabel: f.propertyLabel,
        groupValuesLabel: f.groupValuesLabel,
        operators: ['=', '!='],
      })),
    [],
  );
  const filteringOptions = useMemo<PropertyFilterProps.FilteringOption[]>(() => {
    const opts: PropertyFilterProps.FilteringOption[] = [];
    for (const f of FACETS) {
      for (const v of distinctValues(rows, f.key)) {
        // For cryptoFunction / posture / pqcStatus show the friendly label.
        let label = v;
        if (f.key === 'cryptoFunction') label = cryptoFunctionLabel(v);
        opts.push({ propertyKey: f.key as string, value: v, label });
      }
    }
    return opts;
  }, [rows]);

  // Parse the persisted query from the URL once rows are known. The ?q= param is
  // untrusted (shareable link), so its shape is validated before use; any
  // mismatch falls back to the empty default rather than a weird filter state.
  const initialQuery = useMemo<PropertyFilterProps.Query>(() => {
    return parseQueryParam(searchParams.get(QUERY_PARAM));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const { items, allPageItems, collectionProps, propertyFilterProps, paginationProps, filteredItemsCount } =
    useCollection(rows, {
      propertyFiltering: {
        filteringProperties,
        filteringOptions,
        empty: <Box textAlign="center">No crypto assets found.</Box>,
        noMatch: <Box textAlign="center">No assets match the current filter.</Box>,
        defaultQuery: initialQuery,
      },
      sorting: { defaultState: { sortingColumn: ASSET_COLUMNS[6] } }, // posture, worst-first
      pagination: { pageSize: 25 },
      selection: { trackBy: 'bomRef' },
    });

  // Persist the active filter query to the URL search params (deep-linkable).
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (propertyFilterProps.query.tokens.length > 0) {
      next.set(QUERY_PARAM, JSON.stringify(propertyFilterProps.query));
    } else {
      next.delete(QUERY_PARAM);
    }
    setSearchParams(next, { replace: true });
    // A new filter changes group membership/sizes — restart from the capped view.
    setRevealed({});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [propertyFilterProps.query]);

  // Track the selected asset and mirror it to the URL (?asset=<bom-ref>).
  const selectedBomRef = searchParams.get(SELECT_PARAM);
  const selectedItem = useMemo(
    () => rows.find((r) => r.bomRef === selectedBomRef) ?? null,
    [rows, selectedBomRef],
  );

  const handleSelect = (row: AssetRow) => {
    const next = new URLSearchParams(searchParams);
    next.set(SELECT_PARAM, row.bomRef);
    setSearchParams(next, { replace: true });
  };

  // Open / refresh the SplitPanel whenever the selected asset changes.
  useEffect(() => {
    if (selectedItem) {
      openSplitPanel({
        header: `${selectedItem.displayName} — ${selectedItem.resourceId}`,
        content: <AssetDetailPanel row={selectedItem} />,
      });
    } else {
      closeSplitPanel();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedItem]);

  if (cbomLoading || roadmapLoading) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" /> <Box variant="span">Loading assets…</Box>
      </Box>
    );
  }
  if (cbomError) {
    return (
      <Box padding="l">
        <Alert type="error" header="Failed to load assets">
          {cbomError}
        </Alert>
      </Box>
    );
  }

  // Group the FILTERED items for either grouped lens. Crypto function is the
  // PRIMARY organizing principle; AWS category is the secondary lens. Use
  // allPageItems (the full filtered+sorted set) rather than `items` (a single
  // 25-row page): the grouped views have no pagination control, so grouping the
  // paginated slice would silently drop every asset beyond the first page and
  // hide whole segments.
  const groupByCategory = viewMode === 'category';
  const groupKeyOf = (r: AssetRow) =>
    (groupByCategory ? r.awsCategory : r.cryptoFunction) || (groupByCategory ? 'Other' : 'unknown');
  const groupLabelOf = (key: string) => (groupByCategory ? key : cryptoFunctionLabel(key));
  // Drop only the column we are already grouping ON (redundant inside a group).
  const groupedOnColumn = groupByCategory ? 'awsCategory' : 'cryptoFunction';

  const grouped = new Map<string, AssetRow[]>();
  for (const r of allPageItems) {
    const key = groupKeyOf(r);
    const list = grouped.get(key) ?? [];
    list.push(r);
    grouped.set(key, list);
  }
  const orderedGroups = groupByCategory
    ? // AWS category has no canonical order: sort by critical-then-count (largest
      // first) so the riskiest / biggest categories surface at the top.
      Array.from(grouped.entries())
        .sort(
          ([, a], [, b]) =>
            b.filter((r) => CRITICAL_POSTURES.has(r.posture)).length -
              a.filter((r) => CRITICAL_POSTURES.has(r.posture)).length || b.length - a.length,
        )
        .map(([k]) => k)
    : [
        ...CRYPTO_FUNCTION_ORDER.filter((fn) => grouped.has(fn)),
        ...Array.from(grouped.keys()).filter((fn) => !CRYPTO_FUNCTION_ORDER.includes(fn as any)),
      ];

  // Tab-freeze guard: only cap group rendering once the filtered set is large.
  // Below the threshold every group renders in full (the common case).
  const capGroups = allPageItems.length > GROUPED_ROW_THRESHOLD;

  const filterBar = (
    <PropertyFilter
      {...propertyFilterProps}
      i18nStrings={PROPERTY_FILTER_I18N}
      countText={`${filteredItemsCount ?? items.length} matches`}
      expandToViewport
    />
  );

  const preferences = (
    <CollectionPreferences
      title="Preferences"
      confirmLabel="Confirm"
      cancelLabel="Cancel"
      preferences={{ pageSize: 25 }}
      pageSizePreference={{
        title: 'Page size',
        options: [
          { value: 10, label: '10 assets' },
          { value: 25, label: '25 assets' },
          { value: 50, label: '50 assets' },
          { value: 100, label: '100 assets' },
        ],
      }}
    />
  );

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          counter={`(${rows.length})`}
          description="Inventory of cryptographic assets. Group by crypto function (primary) or by AWS category. Select a row for full per-asset detail."
        >
          Crypto Assets
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container>
          <SpaceBetween size="m">
            {filterBar}
            <Box>
              <SegmentedControl
                selectedId={viewMode}
                onChange={({ detail }) => setViewMode(detail.selectedId as ViewMode)}
                label="View mode"
                options={[
                  { id: 'grouped', text: 'Group by crypto function' },
                  { id: 'category', text: 'Group by AWS category' },
                  { id: 'all', text: 'All assets' },
                ]}
              />
            </Box>
          </SpaceBetween>
        </Container>

        {viewMode === 'all' ? (
          <Container>
            <AssetTable
              items={items}
              collectionProps={collectionProps}
              selectedItem={selectedItem}
              onSelect={handleSelect}
              variant="container"
              pagination={<Pagination {...paginationProps} />}
              preferences={preferences}
              header={
                <Header variant="h2" counter={`(${items.length})`}>
                  All assets
                </Header>
              }
            />
          </Container>
        ) : (
          <SpaceBetween size="m">
            {orderedGroups.length === 0 && (
              <Container>
                <Box textAlign="center" padding="l" color="text-status-inactive">
                  No assets match the current filter.
                </Box>
              </Container>
            )}
            {orderedGroups.map((key) => {
              const groupItems = grouped.get(key) ?? [];
              const critical = groupItems.filter((r) => CRITICAL_POSTURES.has(r.posture)).length;
              // When capping, render only the first `shown` rows (default
              // GROUP_CHUNK, grown by "Show more"); the items are already
              // sorted worst-first by the shared collection, so the capped slice
              // surfaces the highest-severity assets.
              const shown = capGroups
                ? Math.min(revealed[key] ?? GROUP_CHUNK, groupItems.length)
                : groupItems.length;
              const visibleItems = shown < groupItems.length ? groupItems.slice(0, shown) : groupItems;
              return (
                <ExpandableSection
                  key={key}
                  variant="container"
                  defaultExpanded
                  headerText={groupLabelOf(key)}
                  headerCounter={`(${groupItems.length})`}
                  headerActions={
                    critical > 0 ? <Badge color="red">{critical} critical</Badge> : undefined
                  }
                >
                  <SpaceBetween size="xs">
                    <AssetTable
                      items={visibleItems}
                      collectionProps={collectionProps}
                      selectedItem={selectedItem}
                      onSelect={handleSelect}
                      variant="embedded"
                      managed={false}
                      // Drop the column we are grouping ON (redundant inside a group).
                      columnDefinitions={ASSET_COLUMNS.filter((c) => c.id !== groupedOnColumn)}
                    />
                    {shown < groupItems.length && (
                      <Box textAlign="center" padding={{ bottom: 's' }}>
                        <SpaceBetween size="xxs">
                          <StatusIndicator type="info">
                            Showing {shown} of {groupItems.length} — capped to keep the
                            tab responsive. Use the filter above to narrow, or switch
                            to the paginated "All assets" view.
                          </StatusIndicator>
                          <Button
                            onClick={() =>
                              setRevealed((prev) => ({
                                ...prev,
                                [key]: Math.min(shown + GROUP_CHUNK, groupItems.length),
                              }))
                            }
                          >
                            Show {Math.min(GROUP_CHUNK, groupItems.length - shown)} more
                          </Button>
                        </SpaceBetween>
                      </Box>
                    )}
                  </SpaceBetween>
                </ExpandableSection>
              );
            })}
          </SpaceBetween>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
