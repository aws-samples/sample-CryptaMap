import ComplianceFramework from '../components/ComplianceFramework';

// Compliance redesign: IRDAI renders from the verified, dated data file
// public/compliance/irdai.json — the REAL 2026 audit-checklist crypto-asset /
// post-quantum-readiness item (row 110, Annexure-III), cited from the full doc.
export default function IRDAIView() {
  return <ComplianceFramework dataPath="/compliance/irdai.json" />;
}
