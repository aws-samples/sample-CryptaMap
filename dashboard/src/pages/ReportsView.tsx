import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Table from '@cloudscape-design/components/table';
import Button from '@cloudscape-design/components/button';
import { useArtifacts, type Artifact } from '../hooks/useArtifacts';
import { artifactInfoFor } from '../lib/artifactInfo';

// formatBytes renders a byte count in a compact human unit. Returns an em dash for
// an absent/zero size so the column never shows a misleading "0 B".
function formatBytes(n?: number): string {
  if (!n || n <= 0) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

// ReportsView lists the artifacts CryptaMap wrote at scan time (CBOM, ASFF, PQCC
// workbook, offline HTML, roadmap, coverage matrix) and offers each as a one-click
// download. The files already exist on the customer's own disk and are served over
// loopback by `cryptamap serve` — this page only makes them discoverable; it never
// generates anything in the browser (single source of truth, no drift). See
// docs/ARTIFACT-EXPORT-DESIGN.md.
export default function ReportsView() {
  const { artifacts, loading, error } = useArtifacts();

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Download the files CryptaMap wrote at scan time — the CycloneDX CBOM (your primary regulator deliverable), Security Hub findings, the MITRE PQCC workbook, the offline HTML report, the PQC migration roadmap, and the scanner coverage matrix."
        >
          Reports &amp; downloads
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Container header={<Header variant="h2">Where these files live</Header>}>
          <SpaceBetween size="s">
            <Box variant="p">
              These artifacts are served from your own scan-output directory over a
              local (loopback) connection by <code>cryptamap serve</code> — nothing
              leaves your account. The same files also sit on disk in that directory,
              named with the account, region and scan timestamp, so you can copy or
              archive them directly without this page.
            </Box>
            <Box variant="small" color="text-body-secondary">
              Don&apos;t see your files? Run a scan, then serve the output directory:{' '}
              <code>cryptamap serve ./out</code>.
            </Box>
          </SpaceBetween>
        </Container>

        {loading ? (
          <Box padding="xxl" textAlign="center">
            <Spinner size="large" /> <Box variant="span">Loading artifacts…</Box>
          </Box>
        ) : (
          <Container
            header={
              <Header variant="h2" counter={`(${artifacts.length})`}>
                Available artifacts
              </Header>
            }
          >
            <Table<Artifact>
              variant="embedded"
              items={artifacts}
              trackBy="route"
              columnDefinitions={[
                {
                  id: 'artifact',
                  header: 'Artifact',
                  cell: (a) => artifactInfoFor(a.kind).label,
                },
                {
                  id: 'description',
                  header: 'What it is',
                  cell: (a) => (
                    <Box variant="small" color="text-body-secondary">
                      {artifactInfoFor(a.kind).description}
                    </Box>
                  ),
                },
                {
                  id: 'filename',
                  header: 'File',
                  cell: (a) => <code>{a.filename}</code>,
                },
                {
                  id: 'size',
                  header: 'Size',
                  cell: (a) => formatBytes(a.sizeBytes),
                },
                {
                  id: 'download',
                  header: 'Download',
                  cell: (a) => (
                    // Anchor (not a JS handler) so the browser downloads the real
                    // timestamped file directly from the same-origin serve route;
                    // the backend sets Content-Disposition: attachment.
                    <Button
                      variant="inline-link"
                      iconName="download"
                      href={a.route}
                      // download hints the browser to save rather than navigate;
                      // the empty value lets the server's Content-Disposition
                      // filename win.
                      download=""
                      ariaLabel={`Download ${artifactInfoFor(a.kind).label} (${a.filename})`}
                    >
                      Download
                    </Button>
                  ),
                },
              ]}
              empty={
                <Box textAlign="center" color="inherit" padding="m">
                  <SpaceBetween size="s">
                    <Box variant="strong">No downloadable reports here</Box>
                    <Box variant="small" color="text-body-secondary">
                      {error
                        ? 'The artifact manifest could not be read. '
                        : ''}
                      Run a scan, then serve the output directory:{' '}
                      <code>cryptamap serve ./out</code>. In a deployed (hosted) setup
                      your artifacts live in the scan-output S3 bucket instead.
                    </Box>
                  </SpaceBetween>
                </Box>
              }
            />
          </Container>
        )}
      </SpaceBetween>
    </ContentLayout>
  );
}
