import { useState } from 'react';
import Button from '@cloudscape-design/components/button';
import Alert from '@cloudscape-design/components/alert';
import SpaceBetween from '@cloudscape-design/components/space-between';

interface Props {
  targetId: string;
  filename: string;
}

// ExportButton renders a Cloudscape download button that lazily imports
// html2pdf.js (kept out of the initial bundle / code-split to its own chunk) and
// renders the target DOM subtree to a PDF on click.
export default function ExportButton({ targetId, filename }: Props) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onClick = async () => {
    const el = document.getElementById(targetId);
    if (!el) {
      setError(`Cannot export: report content "${targetId}" was not found on the page.`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const html2pdf = (await import('html2pdf.js')).default as any;
      await html2pdf()
        .set({
          margin: 10,
          filename,
          image: { type: 'jpeg', quality: 0.95 },
          // useCORS:false keeps the render self-contained — no external image
          // fetches — matching CryptaMap's local-first, no-network posture.
          html2canvas: { scale: 2, useCORS: false },
          jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        })
        .from(el)
        .save();
    } catch (e) {
      // Surface the failure instead of silently no-op'ing.
      const message = e instanceof Error ? e.message : String(e);
      console.error('PDF export failed:', e);
      setError(`PDF export failed: ${message}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SpaceBetween size="xs">
      <Button iconName="download" loading={busy} onClick={onClick}>
        Export PDF
      </Button>
      {error && (
        <Alert type="error" dismissible onDismiss={() => setError(null)} statusIconAriaLabel="Error">
          {error}
        </Alert>
      )}
    </SpaceBetween>
  );
}
