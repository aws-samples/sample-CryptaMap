import ComplianceFramework from '../components/ComplianceFramework';

// Compliance redesign: RBI renders from the verified, dated data file
// public/compliance/rbi.json — the honest TWO-LAYER framing (binding generic
// crypto rule today + forward-looking Q-SAFE study committee; NO RBI PQC mandate).
export default function RBIView() {
  return <ComplianceFramework dataPath="/compliance/rbi.json" />;
}
