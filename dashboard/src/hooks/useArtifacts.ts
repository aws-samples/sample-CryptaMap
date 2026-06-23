import { useEffect, useState } from 'react';

// Artifact mirrors one entry of the serve-mode manifest at /artifacts/manifest.json
// (serve.go findArtifacts; see docs/ARTIFACT-EXPORT-DESIGN.md §4). Only artifacts
// that actually exist on the customer's disk are listed, so the UI is demo/real
// agnostic and never offers a download for a file that isn't there.
export interface Artifact {
  /** Stable kind key shared with lib/artifactInfo.ts (cbom | asff | pqcc | html | roadmap | coverage). */
  kind: string;
  /** Backend-supplied label (the UI prefers lib/artifactInfo for plain-English copy). */
  label?: string;
  /** Same-origin route the file is served at, e.g. /artifacts/cbom.json. */
  route: string;
  /** Real on-disk (timestamped) filename the browser downloads as. */
  filename: string;
  /** File size in bytes, when the backend reports it. */
  sizeBytes?: number;
  /** MIME type, when the backend reports it. */
  contentType?: string;
}

// MANIFEST_PATH is a same-origin, fixed serve-mode route — never a presigned S3
// URL — so there is no cloud call and no path the customer controls.
const MANIFEST_PATH = '/artifacts/manifest.json';

// useArtifacts loads the serve-mode artifact manifest. It is intentionally
// best-effort: deployed mode (apiBase set, no local /artifacts route) and demo
// runs with no manifest both 404 here, and a malformed/empty body is treated the
// same. In every non-serve case it resolves to an empty list so the Reports page
// and the Overview teaser degrade gracefully (honest empty state / hidden teaser)
// instead of crashing. This mirrors the useScanData / useRoadmap hook shape.
export function useArtifacts() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        setLoading(true);
        const res = await fetch(MANIFEST_PATH);
        // 404 / no manifest (deployed mode, or a scan-output dir without one) is a
        // normal, non-error state: there are simply no downloadable artifacts here.
        if (!res.ok) {
          if (!cancelled) setArtifacts([]);
          return;
        }
        const body = await res.json();
        // Accept either a bare array or an { artifacts: [...] } envelope; anything
        // else (object, null) collapses to an empty list rather than a crash.
        const list: Artifact[] = Array.isArray(body)
          ? body
          : Array.isArray(body?.artifacts)
            ? body.artifacts
            : [];
        if (!cancelled) setArtifacts(list);
      } catch (e) {
        // A fetch/parse failure is non-fatal: report it (so the page can note it)
        // but keep artifacts empty so the UI still renders its empty state.
        if (!cancelled) {
          setError(String(e));
          setArtifacts([]);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return { artifacts, loading, error };
}
