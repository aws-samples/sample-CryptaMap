import { useEffect, useState } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Spinner from '@cloudscape-design/components/spinner';
import Alert from '@cloudscape-design/components/alert';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import Table from '@cloudscape-design/components/table';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import { useScanData, summarizePosture, scanProvenance, realComponents } from '../hooks/useScanData';

// ComplianceFramework renders a regulator page from a VERIFIED, dated data file
// (public/compliance/<framework>.json) instead of hardcoded props. Every claim
// carries a verbatim quote from a primary regulator document we hold, its source
// + date, and an honest "how CryptaMap addresses this" level. This is the redesign
// pattern (mockup): claims live in a data layer with provenance, not in TSX.

interface HeldDoc {
  title: string;
  ref: string;
  date: string;
  pages?: number;
  url: string;
  heldCopy?: string;
}
interface Citation {
  sourceFile: string;
  page?: number;
  line?: number;
  section?: string;
  url: string;
}
interface Claim {
  id: string;
  headline: string;
  quote: string;
  where: string;
  citation?: Citation;
  cryptaMapLevel: 'DIRECT' | 'SUPPORTING' | 'OUT-OF-SCOPE';
  cryptaMapNote: string;
}
interface FrameworkData {
  framework: string;
  title: string;
  asOf: string;
  verdict: string;
  summary: string;
  documentsHeld: HeldDoc[];
  claims: Claim[];
  honestCaveats: string[];
}

// hostOf returns the bare hostname of a URL (e.g. "irdai.gov.in") so the Source
// link is LABELED with where it actually points — never a hardcoded site name.
function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return 'source';
  }
}

const LEVEL_COLOR: Record<Claim['cryptaMapLevel'], 'green' | 'blue' | 'grey'> = {
  DIRECT: 'green',
  SUPPORTING: 'blue',
  'OUT-OF-SCOPE': 'grey',
};
const LEVEL_LABEL: Record<Claim['cryptaMapLevel'], string> = {
  DIRECT: 'CryptaMap addresses this directly',
  SUPPORTING: 'CryptaMap supports this (evidence/input)',
  'OUT-OF-SCOPE': 'Out of CryptaMap scope',
};

// citationText renders the precise, independently-verifiable citation: the held
// PDF file name + exact page + line (or section, for HTML-sourced docs) + a link
// to the public source URL. We deliberately do NOT bundle the PDFs — the citation
// is the file name + page/line + URL so anyone can fetch the source and verify.
function CitationLine({ framework, docRef, c }: { framework: string; docRef: string; c?: Citation }) {
  if (!c) return null;
  const loc =
    c.page != null
      ? `p.${c.page}${c.line != null ? `, line ${c.line}` : ''}`
      : c.section ?? '';
  return (
    <Box variant="small" color="text-body-secondary">
      Source: {framework} {docRef} · <code>{c.sourceFile}</code>
      {loc ? ` · ${loc}` : ''} · <Link href={c.url} external>verify at source</Link>
    </Box>
  );
}

export default function ComplianceFramework({ dataPath }: { dataPath: string }) {
  const [data, setData] = useState<FrameworkData | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Live "your scan" posture so each regulator page ties the obligation to the
  // customer's ACTUAL findings, not just abstract regulation text.
  const { cbom } = useScanData();
  const posture = cbom ? summarizePosture(cbom) : null;
  const prov = scanProvenance(cbom);
  const totalAssets = realComponents(cbom).length;

  useEffect(() => {
    let cancelled = false;
    fetch(dataPath)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d) => !cancelled && setData(d))
      .catch((e) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
  }, [dataPath]);

  if (error) {
    return (
      <Box padding="l">
        <Alert type="error" header="Failed to load compliance data">
          {error}
        </Alert>
      </Box>
    );
  }
  if (!data) {
    return (
      <Box padding="xxl" textAlign="center">
        <Spinner size="large" /> <Box variant="span">Loading…</Box>
      </Box>
    );
  }

  return (
    <ContentLayout header={<Header variant="h1" description={data.summary}>{data.title}</Header>}>
      <SpaceBetween size="l">
        {/* Honest provenance banner — what we hold and as-of when. */}
        <Alert type="info" header={`Primary documents held · verified as of ${data.asOf}`}>
          Every claim below is quoted verbatim from an official document we hold a copy of. CryptaMap is
          an evidence tool, not a compliance certification — the obligation and its assessment remain yours.
        </Alert>

        {/* Live "your scan" panel — ties the regulation to the customer's ACTUAL
            findings. Shows nothing alarming on demo data (mode label makes that
            clear); on a real scan it is the evidence the obligations above call for. */}
        {posture && (
          <Container
            header={
              <Header
                variant="h2"
                description={
                  prov?.mode === 'mock'
                    ? 'Demo data — illustrative only, not a real scan.'
                    : 'From your most recent CryptaMap scan — this is the cryptographic-asset inventory the obligations above call for.'
                }
              >
                Your scan — cryptographic-asset evidence
              </Header>
            }
          >
            <KeyValuePairs
              columns={4}
              items={[
                { label: 'Crypto assets inventoried', value: String(totalAssets) },
                { label: 'No encryption', value: String(posture.noEncryption) },
                { label: 'Legacy TLS', value: String(posture.legacyTLS) },
                { label: 'Non-PQC classical (migration targets)', value: String(posture.nonPQCClassical) },
              ]}
            />
          </Container>
        )}

        <Container header={<Header variant="h2" counter={`(${data.documentsHeld.length})`}>Source documents</Header>}>
          <Table
            variant="embedded"
            columnDefinitions={[
              { id: 'title', header: 'Document', cell: (d: HeldDoc) => d.title },
              { id: 'ref', header: 'Reference', cell: (d: HeldDoc) => d.ref },
              { id: 'date', header: 'Date', cell: (d: HeldDoc) => d.date },
              {
                id: 'src',
                header: 'Source',
                cell: (d: HeldDoc) => (
                  <Link href={d.url} external>
                    {hostOf(d.url)}
                  </Link>
                ),
              },
            ]}
            items={data.documentsHeld}
            trackBy="ref"
          />
        </Container>

        <Container header={<Header variant="h2" counter={`(${data.claims.length})`}>Verified obligations & how CryptaMap maps to them</Header>}>
          <SpaceBetween size="l">
            {data.claims.map((c) => (
              <Container
                key={c.id}
                header={
                  <Header variant="h3" actions={<Badge color={LEVEL_COLOR[c.cryptaMapLevel]}>{LEVEL_LABEL[c.cryptaMapLevel]}</Badge>}>
                    {c.headline}
                  </Header>
                }
              >
                <SpaceBetween size="s">
                  <Box variant="p" fontWeight="bold">
                    <Box variant="span" color="text-status-info">“</Box>
                    {c.quote}
                    <Box variant="span" color="text-status-info">”</Box>
                  </Box>
                  <Box variant="small" color="text-body-secondary">— {c.where}</Box>
                  <CitationLine framework={data.framework} docRef={data.documentsHeld[0]?.ref ?? ''} c={c.citation} />
                  <Box variant="p">{c.cryptaMapNote}</Box>
                </SpaceBetween>
              </Container>
            ))}
          </SpaceBetween>
        </Container>

        <Container header={<Header variant="h2">Honest scope & caveats</Header>}>
          <ul>
            {data.honestCaveats.map((c, i) => (
              <li key={i}>
                <Box variant="p">{c}</Box>
              </li>
            ))}
          </ul>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
