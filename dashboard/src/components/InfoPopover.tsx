import type { ReactNode } from 'react';
import Popover from '@cloudscape-design/components/popover';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Link from '@cloudscape-design/components/link';
import { Link as RouterLink } from 'react-router-dom';

interface Props {
  /** Popover header, e.g. "What does this posture mean?". */
  header: string;
  /** Popover body — explanatory ReactNode (text, KeyValuePairs, etc.). */
  content: ReactNode;
  /**
   * Optional Learn-page topic id (learnContent.ts section id, e.g. 'pqc').
   * When set, a "Learn more →" link to /learn?topic=<topic> is appended.
   */
  topic?: string;
  /** Override the "Learn more" link text. */
  learnText?: string;
  /** What the (i) trigger sits next to — usually a StatusIndicator/label. */
  children: ReactNode;
}

// InfoPopover renders a label/value (children) followed by an inline "ⓘ"
// affordance that opens an explanatory Popover. The popover optionally deep-links
// into the Learn page (/learn?topic=...). Built on the canonical Cloudscape
// Popover pattern already used by RoadmapTable.PriorityCell (triggerType=custom,
// dismissButton). stopPropagation on the trigger keeps clicking the (i) inside a
// selectable table row from also selecting the row / opening the split panel.
export default function InfoPopover({
  header,
  content,
  topic,
  learnText = 'Learn more',
  children,
}: Props) {
  return (
    <SpaceBetween size="xxs" direction="horizontal">
      {children}
      <span
        onClick={(e) => e.stopPropagation()}
        onPointerDown={(e) => e.stopPropagation()}
      >
        <Popover
          triggerType="custom"
          dismissButton
          size="medium"
          header={header}
          content={
            <SpaceBetween size="s">
              {content}
              {topic && (
                <Box>
                  <RouterLink
                    to={`/learn?topic=${encodeURIComponent(topic)}`}
                    onClick={(e) => e.stopPropagation()}
                    onPointerDown={(e) => e.stopPropagation()}
                  >
                    {learnText} →
                  </RouterLink>
                </Box>
              )}
            </SpaceBetween>
          }
        >
          <Link variant="info" ariaLabel={`More information: ${header}`}>
            Info
          </Link>
        </Popover>
      </span>
    </SpaceBetween>
  );
}
