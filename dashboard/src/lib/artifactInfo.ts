// Plain-English copy for each downloadable artifact KIND, kept in one place so the
// Reports page + Overview teaser never scatter (or drift on) the descriptions.
//
// The backend manifest (/artifacts/manifest.json) carries a `kind` per entry; the
// UI looks that kind up here for the customer-facing label + one-line description.
// `kind` is the single source of truth shared with serve.go's findArtifacts —
// keep these keys in sync with the suffixes documented in
// docs/ARTIFACT-EXPORT-DESIGN.md §2.

export interface ArtifactInfo {
  /** Short, human label for the artifact (column 1 / button context). */
  label: string;
  /** One plain-English line: what this file IS and why it matters. */
  description: string;
}

// Known artifact kinds the CLI writes. A manifest entry whose kind is absent here
// still renders (see artifactInfoFor's honest fallback) rather than being dropped.
export const ARTIFACT_INFO: Record<string, ArtifactInfo> = {
  cbom: {
    label: 'CBOM',
    description:
      'CycloneDX 1.7 CBOM — machine-readable cryptographic inventory; the primary regulator deliverable',
  },
  asff: {
    label: 'Security Hub findings',
    description: 'AWS Security Hub findings (ASFF)',
  },
  pqcc: {
    label: 'PQCC workbook',
    description: 'MITRE PQCC Excel workbook',
  },
  report: {
    label: 'Offline report',
    description: 'Self-contained offline HTML report (opens with no network)',
  },
  'roadmap-json': {
    label: 'PQC roadmap (JSON)',
    description: 'PQC migration roadmap — machine-readable JSON',
  },
  'roadmap-md': {
    label: 'PQC roadmap (Markdown)',
    description: 'PQC migration roadmap — human-readable Markdown',
  },
  coverage: {
    label: 'Coverage matrix',
    description: 'Scanner coverage matrix (which services/regions were scanned)',
  },
};

// artifactInfoFor returns the plain-English copy for a manifest kind. For an
// unknown kind (e.g. a newer CLI emitting an artifact this dashboard build doesn't
// recognise yet) it falls back to the kind string itself rather than hiding the
// row — honest over silent omission.
export function artifactInfoFor(kind: string): ArtifactInfo {
  return ARTIFACT_INFO[kind] ?? { label: kind, description: kind };
}
