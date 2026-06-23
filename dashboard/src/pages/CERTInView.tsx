import ComplianceFramework from '../components/ComplianceFramework';

// Compliance redesign: the national-umbrella view. CERT-In names the CBOM and
// automated cloud-native cryptographic discovery (CryptaMap's category) in its
// quantum-readiness whitepaper + SBOM/QBOM/CBOM technical guidelines. Advisory
// tier (disclosed); the binding obligations sit with the sector regulators.
export default function CERTInView() {
  return <ComplianceFramework dataPath="/compliance/certin.json" />;
}
