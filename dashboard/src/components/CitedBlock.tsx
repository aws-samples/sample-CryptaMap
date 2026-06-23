import Box from '@cloudscape-design/components/box';
import Link from '@cloudscape-design/components/link';
import Alert from '@cloudscape-design/components/alert';
import SpaceBetween from '@cloudscape-design/components/space-between';
import type { FactBlock, Source } from '../lib/learnContent';

// SourceCitation renders one official source as an external link, appending a
// small "source not auto-verified" note for any source whose URL could not be
// fetched + verified during the build (e.g. the NSA CNSA 2.0 pages, which
// returned HTTP 403 to the verification bot). NEVER drop the note — it is the
// honesty signal that distinguishes a fetched-and-checked URL from a
// known-real-but-unfetched one.
function SourceCitation({ source }: { source: Source }) {
  return (
    <Box variant="small">
      <Link href={source.url} external target="_blank" variant="primary">
        {source.label}
      </Link>
      {source.verified === 'not-auto-verified' && (
        <Box variant="small" color="text-status-inactive" display="inline">
          {'  '}· source not auto-verified
        </Box>
      )}
    </Box>
  );
}

// CitedBlock renders one FactBlock: the body text, a per-block "AI-simplified"
// callout when the passage is an AI paraphrase (NOT a near-verbatim claim), and
// the official source citation(s). Enforces the editorial rule that EVERY block
// shows at least one source — a block with no sources renders a visible error
// rather than silently presenting an uncited fact.
export default function CitedBlock({ block }: { block: FactBlock }) {
  const hasSources = block.sources.length > 0;
  const firstSourceLabel = hasSources ? block.sources[0].label : '';
  return (
    <SpaceBetween size="xs">
      <Box variant="p">{block.body}</Box>

      {block.aiSimplified && (
        <Alert type="info" statusIconAriaLabel="AI-simplified passage">
          <Box variant="small">
            🤖 AI-simplified — this passage is a plain-language paraphrase. Verify
            against {hasSources ? firstSourceLabel : 'the cited source'}
            {block.sources.length > 1 ? ' (and the other cited sources below).' : '.'}
          </Box>
        </Alert>
      )}

      {hasSources ? (
        <SpaceBetween size="xxs">
          <Box variant="small" color="text-body-secondary">
            Source{block.sources.length > 1 ? 's' : ''}:
          </Box>
          {block.sources.map((s) => (
            <SourceCitation key={s.url} source={s} />
          ))}
        </SpaceBetween>
      ) : (
        <Alert type="error">
          Missing citation — this block states a fact with no source and must not
          be displayed. (Editorial-rule violation.)
        </Alert>
      )}
    </SpaceBetween>
  );
}
