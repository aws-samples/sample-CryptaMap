import { useNavigate } from 'react-router-dom';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Link from '@cloudscape-design/components/link';

// NotFound is the catch-all panel for unknown / typo / stale URLs. Without it
// such routes render a blank shell (no matching <Route>), which looks like a
// broken app. It mirrors the Cloudscape ContentLayout/Container pattern used by
// the real pages and offers a single way back to the Overview, using the same
// Link + useNavigate convention as Overview's internal links.
export default function NotFound() {
  const navigate = useNavigate();
  return (
    <ContentLayout
      header={<Header variant="h1">Page not found</Header>}
    >
      <Container header={<Header variant="h2">This page does not exist</Header>}>
        <SpaceBetween size="m">
          <Box variant="p" color="text-body-secondary">
            The page you requested could not be found. The link may be out of
            date, or the address may have been typed incorrectly.
          </Box>
          <Link onFollow={() => navigate('/')}>Back to Overview →</Link>
        </SpaceBetween>
      </Container>
    </ContentLayout>
  );
}
