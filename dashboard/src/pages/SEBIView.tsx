import ComplianceFramework from '../components/ComplianceFramework';

// Compliance redesign: SEBI renders from the verified, dated data file
// public/compliance/sebi.json via the ComplianceFramework component — verbatim
// quotes + source (PDF name + page/line + URL) + as-of date + honest
// CryptaMap-maps-to-this levels + a live "your scan" evidence panel.
export default function SEBIView() {
  return <ComplianceFramework dataPath="/compliance/sebi.json" />;
}
