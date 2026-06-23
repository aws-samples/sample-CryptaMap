import { useEffect, useState } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import { getRuntimeConfig, fetchLatestCBOM } from '../services/api';
import { scanProvenance, isDemoData, knowledgeProvenance } from '../hooks/useScanData';
import type { CBOM } from '../types';

const CLI_SNIPPET = `# Mock E2E (what local dev / the committed demo uses)
cryptamap --mock --mock-scale 3 --regions ap-south-1,us-east-1 --org-merge --output-dir ./dist/mock

# Live scan against the current account, then view it locally
cryptamap --regions us-east-1 --output-dir ./out
cryptamap serve ./out        # loopback-only dashboard over your REAL scan

# Org-wide scan (deployed Step Functions fan-out)
cryptamap --org --regions ap-south-1`;

export default function SettingsView() {
  const [cfg, setCfg] = useState<{
    apiBase?: string;
    bucket?: string;
    mockMode?: boolean;
    roadmapPath?: string;
  } | null>(null);
  const [cbom, setCbom] = useState<CBOM | null>(null);

  useEffect(() => {
    getRuntimeConfig().then(setCfg);
    fetchLatestCBOM().then(setCbom).catch(() => setCbom(null));
  }, []);

  // Data authenticity = the DATA's own provenance (cryptamap:mode), not the
  // transport flag. transportMock only describes HOW the data is fetched.
  const transportMock = !!cfg?.mockMode || !cfg?.apiBase;
  const prov = scanProvenance(cbom);
  const demo = isDemoData(cbom, transportMock);
  const know = knowledgeProvenance(cbom);

  const modeIndicator = demo ? (
    <StatusIndicator type="warning">Demo data (synthetic — not a real scan)</StatusIndicator>
  ) : prov?.mode === 'merged' ? (
    <StatusIndicator type="success">Live org scan (merged)</StatusIndicator>
  ) : (
    <StatusIndicator type="success">Live scan</StatusIndicator>
  );

  return (
    <ContentLayout header={<Header variant="h1">Settings & Runtime Configuration</Header>}>
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Data authenticity</Header>}>
          <SpaceBetween size="m">
            <KeyValuePairs
              columns={2}
              items={[
                { label: 'Data', value: modeIndicator },
                { label: 'Scan mode (from CBOM)', value: prov?.mode || '— (no provenance in data)' },
                { label: 'Account(s)', value: prov?.accountId || '—' },
                { label: 'Region(s)', value: prov?.region || '—' },
                { label: 'Scan ID', value: prov?.scanId || '—' },
                {
                  label: 'PQC knowledge',
                  value: know ? `${know.source} v${know.version} (oldest fact ${know.minAsOf})` : '—',
                },
              ]}
            />
            {demo && (
              <Box variant="small" color="text-status-warning">
                You are viewing synthetic demo data. To see your own environment, run a
                CryptaMap scan and open it with <code>cryptamap serve ./out</code> (or, for the
                deployed dashboard, set a real <code>apiBase</code> in <code>config.json</code>).
              </Box>
            )}
          </SpaceBetween>
        </Container>

        <Container header={<Header variant="h2">Transport (how the dashboard fetches data)</Header>}>
          <SpaceBetween size="m">
            <KeyValuePairs
              columns={2}
              items={[
                {
                  label: 'Source',
                  value: transportMock ? 'Static files (local / demo)' : 'Live API',
                },
                { label: 'API base', value: cfg?.apiBase || '— (static-file mode)' },
                { label: 'Bucket', value: cfg?.bucket || '—' },
                {
                  label: 'CBOM endpoint',
                  value: transportMock ? '/mock/org-cbom.json (static)' : `${cfg?.apiBase}/cbom`,
                },
                {
                  label: 'Roadmap endpoint',
                  value: transportMock
                    ? cfg?.roadmapPath ?? '/mock/roadmap.json (static)'
                    : `${cfg?.apiBase}/roadmap`,
                },
              ]}
            />
            <Box variant="small">
              Transport is independent of data authenticity: <code>cryptamap serve</code> uses the
              static-file transport but serves your <strong>real</strong> scan (the banner above
              reflects the data, not the transport). Edit <code>/public/config.json</code> to point
              the deployed dashboard at an API Gateway endpoint.
            </Box>
          </SpaceBetween>
        </Container>

        <Container header={<Header variant="h2">CryptaMap CLI quick reference</Header>}>
          <Box variant="code">
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{CLI_SNIPPET}</pre>
          </Box>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
