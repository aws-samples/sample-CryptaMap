import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Tabs from '@cloudscape-design/components/tabs';
import Alert from '@cloudscape-design/components/alert';
import { LEARN_SECTIONS, sectionById } from '../lib/learnContent';
import CitedBlock from '../components/CitedBlock';

// LearnView is the cited, plain-language explainer for the post-quantum
// migration story. It honours the ?topic=<sectionId> deep-link that the roadmap
// table + inline (i) popovers emit (e.g. /learn?topic=pqc), selecting the
// matching tab on load. Every fact shown carries its official source URL, and
// every AI-authored simplification is flagged per-block — both enforced by the
// learnContent.ts data shape + CitedBlock renderer.
export default function LearnView() {
  const [params, setParams] = useSearchParams();
  const topic = params.get('topic');

  // Resolve the deep-linked tab; default to the first section.
  const activeTabId = useMemo(() => {
    const s = sectionById(topic);
    return s ? s.id : LEARN_SECTIONS[0].id;
  }, [topic]);

  const tabs = LEARN_SECTIONS.map((section) => ({
    id: section.id,
    label: section.title,
    content: (
      <Container
        header={
          <Header variant="h2" description={section.summary}>
            {section.title}
          </Header>
        }
      >
        <SpaceBetween size="l">
          {section.blocks.map((block, i) => (
            <CitedBlock key={`${section.id}-${i}`} block={block} />
          ))}
        </SpaceBetween>
      </Container>
    ),
  }));

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Plain-language, source-cited background on the post-quantum migration — and how to read CryptaMap's scores and labels."
        >
          Learn: post-quantum cryptography
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Alert type="info" header="How to read this page">
          <Box variant="small">
            Every factual statement below links to its official source (NIST,
            CISA, NSA or AWS documentation). Passages marked with a{' '}
            <strong>🤖 AI-simplified</strong> callout are plain-language
            paraphrases written to aid understanding — verify them against the
            cited source. A few NSA pages could not be auto-fetched during the
            build and are marked "source not auto-verified".
          </Box>
        </Alert>

        <Tabs
          tabs={tabs}
          activeTabId={activeTabId}
          onChange={({ detail }) => {
            // Keep the URL in sync so the tab is deep-linkable / shareable.
            const next = new URLSearchParams(params);
            next.set('topic', detail.activeTabId);
            setParams(next, { replace: true });
          }}
        />
      </SpaceBetween>
    </ContentLayout>
  );
}
