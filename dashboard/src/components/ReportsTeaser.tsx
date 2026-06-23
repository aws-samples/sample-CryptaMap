import { useNavigate } from 'react-router-dom';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Button from '@cloudscape-design/components/button';
import Link from '@cloudscape-design/components/link';
import { useArtifacts } from '../hooks/useArtifacts';

// ReportsTeaser is the compact Overview panel that surfaces the downloadable
// artifacts CryptaMap wrote at scan time. It renders ONLY when the manifest has at
// least one artifact (serve mode with files on disk); in demo-with-no-manifest or
// deployed mode it renders nothing, so the Overview stays clean. The full list +
// per-file downloads live on the dedicated /reports page (ReportsView).
export default function ReportsTeaser() {
  const { artifacts } = useArtifacts();
  const navigate = useNavigate();

  // Nothing to offer → render nothing (no empty panel on the Overview).
  if (artifacts.length === 0) return null;

  // The CBOM is the primary regulator deliverable, so it gets the prominent
  // download button when present; if a particular run somehow lacks a CBOM we fall
  // back to pointing at the full Reports page rather than a missing route.
  const cbom = artifacts.find((a) => a.kind === 'cbom');

  return (
    <Container
      header={
        <Header
          variant="h2"
          counter={`(${artifacts.length})`}
          description="The files CryptaMap wrote at scan time — your CycloneDX CBOM and the rest of the report set — ready to download."
        >
          Download CryptaMap reports
        </Header>
      }
    >
      <SpaceBetween size="m" direction="horizontal" alignItems="center">
        {cbom ? (
          <Button
            variant="primary"
            iconName="download"
            href={cbom.route}
            download=""
            ariaLabel={`Download CBOM (${cbom.filename})`}
          >
            Download CBOM
          </Button>
        ) : (
          <Box variant="small" color="text-body-secondary">
            No CBOM in this scan output yet.
          </Box>
        )}
        <Link
          onFollow={(e) => {
            e.preventDefault();
            navigate('/reports');
          }}
        >
          View all reports →
        </Link>
      </SpaceBetween>
    </Container>
  );
}
