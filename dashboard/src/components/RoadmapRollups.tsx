import Table from '@cloudscape-design/components/table';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Grid from '@cloudscape-design/components/grid';
import SpaceBetween from '@cloudscape-design/components/space-between';
import type { ServiceRollup, AccountRollup } from '../types/roadmap';
import { pqcStatusPresentation } from '../lib/posture';

interface Props {
  byService: ServiceRollup[];
  byAccount: AccountRollup[];
}

// RoadmapRollups shows the roadmap's pre-aggregated By Service and By Account
// summaries. The 'By service' table is typically large (one row per service)
// while 'By account' is small (often a single account), so we weight the Grid
// toward services (8/4) instead of a rigid 50/50 ColumnLayout — and stack
// 'By account' below when there is only one account, to avoid a near-empty
// half-width table sitting next to a 60-row one.
export default function RoadmapRollups({ byService, byAccount }: Props) {
  const services = [...byService].sort((a, b) => b.maxPriority - a.maxPriority);
  const accounts = [...byAccount].sort((a, b) => b.maxPriority - a.maxPriority);
  // Stack vertically when the account table is tiny (e.g. single-account scans);
  // otherwise sit side by side with the service table given the wider column.
  const stack = accounts.length <= 1;

  const serviceContainer = (
      <Container header={<Header variant="h2" counter={`(${services.length})`}>By service</Header>}>
        <Table<ServiceRollup>
          items={services}
          variant="embedded"
          trackBy="service"
          wrapLines
          columnDefinitions={[
            {
              id: 'service',
              header: 'Service',
              cell: (s) => s.displayName,
              isRowHeader: true,
            },
            { id: 'items', header: 'Assets', cell: (s) => s.items, width: 90 },
            {
              id: 'maxPriority',
              header: 'Max priority',
              cell: (s) => s.maxPriority.toFixed(1),
              width: 120,
            },
            {
              id: 'quickWins',
              header: 'Quick wins',
              cell: (s) =>
                s.quickWins > 0 ? <Badge color="green">{s.quickWins}</Badge> : '—',
              width: 110,
            },
            {
              id: 'pqcStatus',
              header: 'PQC status',
              cell: (s) => {
                const p = pqcStatusPresentation(s.pqcStatus);
                return <StatusIndicator type={p.indicator}>{p.label}</StatusIndicator>;
              },
            },
          ]}
          empty={<Box textAlign="center" color="text-status-inactive">No services.</Box>}
        />
      </Container>
  );

  const accountContainer = (
      <Container header={<Header variant="h2" counter={`(${accounts.length})`}>By account</Header>}>
        <Table<AccountRollup>
          items={accounts}
          variant="embedded"
          trackBy="accountId"
          wrapLines
          columnDefinitions={[
            {
              id: 'accountId',
              header: 'Account',
              cell: (a) => a.accountId,
              isRowHeader: true,
            },
            { id: 'items', header: 'Assets', cell: (a) => a.items, width: 90 },
            {
              id: 'critical',
              header: 'Critical',
              cell: (a) =>
                a.critical > 0 ? <Badge color="red">{a.critical}</Badge> : '—',
              width: 100,
            },
            {
              id: 'high',
              header: 'High',
              cell: (a) =>
                a.high > 0 ? <Badge color="severity-high">{a.high}</Badge> : '—',
              width: 90,
            },
            {
              id: 'maxPriority',
              header: 'Max priority',
              cell: (a) => a.maxPriority.toFixed(1),
              width: 120,
            },
          ]}
          empty={<Box textAlign="center" color="text-status-inactive">No accounts.</Box>}
        />
      </Container>
  );

  if (stack) {
    return (
      <SpaceBetween size="l">
        {serviceContainer}
        {accountContainer}
      </SpaceBetween>
    );
  }

  return (
    <Grid
      gridDefinition={[{ colspan: { default: 12, m: 8 } }, { colspan: { default: 12, m: 4 } }]}
    >
      {serviceContainer}
      {accountContainer}
    </Grid>
  );
}
