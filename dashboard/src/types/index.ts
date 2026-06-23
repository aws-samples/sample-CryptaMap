// Thin hand-written barrel over the generated single-source-of-truth types.
//
// The Go wire structs + enum vocabularies are generated into ./generated.ts by
// `make generate-types` (cmd/gen-ts). DO NOT hand-edit those generated shapes
// here — change the Go source and regenerate. This file only:
//   1. re-exports the generated types under the names the dashboard already
//      imports (so all existing `import ... from '../types'` sites keep working),
//   2. aliases the CycloneDX CDX* wire shapes to the dashboard's CBOM* names,
//   3. defines the few UI-only / non-Go-struct types (CryptoFunction taxonomy
//      vocabulary, the cryptamap:* property-name union).

export type {
  // Enums (generated from Go consts).
  Severity,
  CryptoPosture,
  Category,
  AssetType,
  AlgorithmPrimitive,
  CryptoState,
  ComplianceStatus,
  // Scan / finding surface.
  MoscaScore,
  ComplianceMapping,
  Finding,
  ScanSummary,
  ServiceScanReport,
  MultiScanResult,
  // cryptoProperties surface.
  AlgorithmProperties,
  CertificateProperties,
  CipherSuite,
  ProtocolProperties,
  RelatedCryptoMaterialProperties,
  CryptoProperties,
  CryptoAsset,
} from './generated';

// ScanResult is re-exported explicitly because its `assets: CryptoAsset[]` and
// `findings: Finding[]` are now the generated typed shapes (was `any[]`).
export type { ScanResult } from './generated';

// --- CycloneDX CBOM aliases ------------------------------------------------
// The dashboard refers to the CycloneDX wire shapes as CBOM / CBOMComponent /
// CBOMProperty; the Go source-of-truth structs are CDXBOM / CDXComponent /
// CDXProperty. Alias them so consumers are unchanged and stay generated.
export type {
  CDXBOM as CBOM,
  CDXComponent as CBOMComponent,
  CDXProperty as CBOMProperty,
  CDXMetadata,
  CDXMetaComp,
  CDXTool,
} from './generated';

// --- UI-only / non-Go-struct types -----------------------------------------

// Stable vocabulary of cryptoFunction values (internal/taxonomy/taxonomy.go
// FuncDataAtRest..FuncSDKLibrary). This is a taxonomy presentation vocabulary,
// not a single Go struct field, so it is maintained here by hand.
export type CryptoFunction =
  | 'data-at-rest'
  | 'data-in-transit'
  | 'key-management'
  | 'certificates-pki'
  | 'sdk-library';

// Known cryptamap:* property names carried in CBOMComponent.properties[].
// These are emitted by internal/output/cyclonedx.go as flat name/value props
// (NOT a Go struct), so the union is maintained here. All VALUES are strings
// (ints stringified, bools as the literal "true").
//
// NOTE: the deeper-detail keys (algorithmName, keySizeBits, kmsKeySpec,
// keyExchangeGroup, pqcHybrid, certSignatureAlgorithm, certKeySizeBits) live
// ONLY here on the wire — the CycloneDX writer's sanitizeForCDX() strips them
// out of cryptoProperties to satisfy CDX 1.7 additionalProperties:false. Read
// them via getProp(component, 'cryptamap:<key>'), never off cryptoProperties.
export type CryptamapProp =
  | 'cryptamap:service'
  | 'cryptamap:category'
  | 'cryptamap:accountId'
  | 'cryptamap:region'
  | 'cryptamap:resourceArn'
  | 'cryptamap:displayName'
  | 'cryptamap:awsCategory'
  | 'cryptamap:cryptoFunction'
  | 'cryptamap:subAspect'
  | 'cryptamap:scope'
  | 'cryptamap:posture'
  | 'cryptamap:algorithmName'
  | 'cryptamap:keySizeBits'
  | 'cryptamap:kmsKeySpec'
  | 'cryptamap:keyExchangeGroup'
  | 'cryptamap:pqcHybrid'
  | 'cryptamap:certSignatureAlgorithm'
  | 'cryptamap:certKeySizeBits'
  | 'cryptamap:tlsMinVersion';
