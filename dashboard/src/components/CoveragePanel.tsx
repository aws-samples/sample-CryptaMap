import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Popover from '@cloudscape-design/components/popover';
import { COVERAGE } from '../lib/coverageData';

// CoveragePanel states CryptaMap's AWS coverage HONESTLY: how many AWS services
// exist, how many CryptaMap scans (the crypto-bearing ones), and why the rest are
// out of scope rather than gaps. It deliberately does NOT make a "100%
// comprehensive" claim — that would be false and, for a compliance tool, a
// credibility risk. The total-services figure is build-time baked (see
// coverageData.ts), not fetched live.
export default function CoveragePanel() {
  const c = COVERAGE;
  return (
    <Container
      header={
        <Header
          variant="h2"
          description="What CryptaMap scans across AWS — and why the rest is out of scope, not missed."
        >
          AWS cryptographic coverage
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Box variant="p">
          AWS publishes{' '}
          <Popover
            dismissButton={false}
            position="top"
            size="small"
            content={
              <Box variant="small">
                Distinct service IDs in the AWS global-infrastructure registry,
                verified {c.asOf}. Source: {c.source}.
              </Box>
            }
          >
            <b>{c.totalAwsServices} services</b>
          </Popover>{' '}
          (as of {c.asOf}). CryptaMap scans the{' '}
          <b>{c.servicesCovered}</b> of them that hold cryptographic assets —{' '}
          <b>{c.resourceTypes} resource types</b> via <b>{c.scanners} scanners</b> —
          covering the services that <i>store or transmit your sensitive data</i>.
          The remaining services have no cryptographic surface of their own to
          assess.
        </Box>

        <ColumnLayout columns={3} variant="text-grid">
          <div>
            <Box variant="awsui-key-label">AWS services (total)</Box>
            <Box variant="h2">{c.totalAwsServices}</Box>
            <Box variant="small" color="text-body-secondary">
              global-infrastructure registry · {c.asOf}
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Crypto-bearing services covered</Box>
            <Box variant="h2">{c.servicesCovered}</Box>
            <Box variant="small" color="text-body-secondary">
              {c.resourceTypes} resource types · {c.scanners} scanners
            </Box>
          </div>
          <div>
            <Box variant="awsui-key-label">Crypto dimensions</Box>
            <Box variant="h2">{c.dimensions.length}</Box>
            <Box variant="small" color="text-body-secondary">
              at-rest · in-transit · keys · certs · runtime
            </Box>
          </div>
        </ColumnLayout>

        <div>
          <Box variant="awsui-key-label" padding={{ bottom: 'xs' }}>
            Coverage by cryptographic dimension
          </Box>
          <ColumnLayout columns={2} variant="text-grid">
            {c.dimensions.map((d) => (
              <div key={d.key}>
                <Box variant="strong">
                  {d.label} · {d.scanners} scanners
                </Box>
                <Box variant="small" color="text-body-secondary">
                  {d.blurb}
                </Box>
              </div>
            ))}
          </ColumnLayout>
        </div>

        <ExpandableSection headerText="Why aren’t all AWS services covered?">
          <SpaceBetween size="s">
            <Box variant="p">{c.outOfScopeRationale}</Box>
            <Box variant="p">
              CryptaMap reports honestly: it never claims to cover a service it does
              not scan, and an absent finding is never treated as a clean
              all-clear. The crypto-bearing services not yet covered are tracked as
              an explicit backlog rather than hidden:
            </Box>
            <ul>
              {c.knownGaps.map((g) => (
                <li key={g}>
                  <Box variant="small">{g}</Box>
                </li>
              ))}
            </ul>
            <Box variant="small" color="text-body-secondary">
              This transparency is the point: comprehensive coverage of the
              cryptographic attack surface, with a documented edge — not a round
              number.
            </Box>
          </SpaceBetween>
        </ExpandableSection>
      </SpaceBetween>
    </Container>
  );
}
