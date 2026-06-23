import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import KeyValuePairs from '@cloudscape-design/components/key-value-pairs';
import StatusIndicator from '@cloudscape-design/components/status-indicator';
import Badge from '@cloudscape-design/components/badge';
import Link from '@cloudscape-design/components/link';
import Alert from '@cloudscape-design/components/alert';
import ExpandableSection from '@cloudscape-design/components/expandable-section';
import Header from '@cloudscape-design/components/header';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import type { AssetRow } from '../lib/assetRows';
import { getProp, useScanData, resolveAlgorithmName } from '../hooks/useScanData';
import type { ReactNode } from 'react';
import {
  posturePresentation,
  pqcStatusPresentationForAsset,
  isQuantumSafePosture,
  upgradeEaseLabel,
  confidenceLabel,
  cryptoFunctionLabel,
  severityIndicator,
  strengthPresentation,
  primitiveLabel,
  safeHref,
} from '../lib/posture';
import InfoPopover from './InfoPopover';
import { PostureLegendContent, MoscaContent, PqcStatusContent } from './infoPopoverContent';
import { CRYPTO_FIELD_HELP } from './cryptoFieldHelp';

const DASH = '—';
function show(v: string | number | undefined | null): string {
  if (v === undefined || v === null || v === '') return DASH;
  return String(v);
}

// showDate formats a backend RFC3339 timestamp for display, treating "no
// value" as a clean DASH instead of confusing blanks/garbage. Go serializes a
// zero time.Time value (which several collectors emit, and which `omitempty`
// does NOT drop for struct types) as "0001-01-01T00:00:00Z"; that literal and
// any unparseable/epoch date are rendered as DASH. A valid date is shown in the
// viewer's locale (date + UTC time), falling back to the raw string if Intl
// formatting is unavailable.
function showDate(v: string | undefined | null): string {
  if (v === undefined || v === null || v === '') return DASH;
  const s = String(v);
  // Go's zero time and any year <= 1 are "not available".
  if (s.startsWith('0001-01-01') || s.startsWith('0000-')) return DASH;
  const t = Date.parse(s);
  if (Number.isNaN(t)) return DASH;
  const d = new Date(t);
  // Guard against the Unix epoch sentinel (1970-01-01T00:00:00Z) sometimes
  // emitted as a "missing" placeholder.
  if (d.getTime() === 0) return DASH;
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      timeZone: 'UTC',
      timeZoneName: 'short',
    }).format(d);
  } catch {
    return s;
  }
}

// The deeper crypto-detail fields (algorithmName, keySizeBits, kmsKeySpec,
// keyExchangeGroup, pqcHybrid, certSignatureAlgorithm, certKeySizeBits) are
// stripped out of cryptoProperties by the CycloneDX writer's sanitizeForCDX()
// (CDX 1.7 forbids those keys inside algorithm/protocolProperties) and emitted
// ONLY as flat cryptamap:* component properties. Read them from there, falling
// back to the nested object for any non-CDX consumer that populates it.
function deepProp(row: AssetRow, key: string): string | undefined {
  return getProp(row.component, `cryptamap:${key}`);
}

// A KeyValuePairs item shape (label + value + optional info-slot node).
interface KvItem {
  label: ReactNode;
  value: ReactNode;
  info?: ReactNode;
}

/**
 * field builds one "Cryptographic detail" row with a plain-language (i) popover.
 *
 * - helpKey indexes CRYPTO_FIELD_HELP for the popover header/body (omit for no
 *   popover). The (i) is rendered in the KeyValuePairs `info` slot next to the
 *   label, matching the canonical Cloudscape pattern.
 * - value is shown as-is when truthy; when empty, `naReason` (if given) renders a
 *   muted "Not applicable (<reason>)" so a non-expert sees the field is empty BY
 *   DESIGN, not missing data; otherwise it falls back to the usual "—".
 */
function field(
  label: string,
  value: ReactNode,
  helpKey?: keyof typeof CRYPTO_FIELD_HELP | string,
  naReason?: string,
): KvItem {
  const help = helpKey ? CRYPTO_FIELD_HELP[helpKey as string] : undefined;
  const isEmpty =
    value === undefined || value === null || value === '' || value === DASH;
  const rendered: ReactNode =
    isEmpty && naReason ? (
      <Box variant="span" color="text-status-inactive">
        Not applicable ({naReason})
      </Box>
    ) : isEmpty ? (
      DASH
    ) : (
      value
    );
  return {
    label,
    value: rendered,
    info: help ? (
      <InfoPopover header={help.header} content={help.body} topic={help.topic}>
        <></>
      </InfoPopover>
    ) : undefined,
  };
}

/**
 * Per-asset detail rendered inside the AppLayout SplitPanel. Two halves:
 *  1. Crypto detail branched on cryptoProperties.assetType.
 *  2. PQC-readiness reasoning derived from posture + the joined roadmap item.
 */
export default function AssetDetailPanel({ row }: { row: AssetRow }) {
  const cp = row.component.cryptoProperties;
  const posture = posturePresentation(row.posture);

  return (
    <SpaceBetween size="l">
      {/* Identity */}
      <KeyValuePairs
        columns={3}
        items={[
          { label: 'Service', value: row.displayName },
          { label: 'Resource', value: show(row.resourceId) },
          { label: 'Crypto function', value: cryptoFunctionLabel(row.cryptoFunction) },
          { label: 'Sub-aspect', value: show(row.subAspect) },
          { label: 'AWS category', value: show(row.awsCategory) },
          {
            label: 'Posture',
            value: (
              <InfoPopover header="What does this posture mean?" content={<PostureLegendContent />} topic="pqc">
                <StatusIndicator type={posture.indicator}>{posture.label}</StatusIndicator>
              </InfoPopover>
            ),
          },
          { label: 'Account', value: show(row.accountId) },
          { label: 'Region', value: show(row.region) },
          { label: 'bom-ref', value: <Box variant="code">{row.bomRef}</Box> },
          { label: 'ARN', value: <Box variant="code">{show(row.resourceArn)}</Box> },
        ]}
      />

      {/* Crypto detail, branched by assetType */}
      <div>
        <Header variant="h3">Cryptographic detail</Header>
        <Box padding={{ top: 'xs' }}>
          <CryptoDetail row={row} />
        </Box>
      </div>

      {/* PQC readiness reasoning */}
      <div>
        <Header variant="h3">PQC readiness</Header>
        <Box padding={{ top: 'xs' }}>
          <PqcReadiness row={row} />
        </Box>
      </div>

      {/* Raw cryptoProperties */}
      {cp && (
        <ExpandableSection headerText="Raw cryptoProperties (CycloneDX)" variant="footer">
          <Box variant="code">
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
              {JSON.stringify(cp, null, 2)}
            </pre>
          </Box>
        </ExpandableSection>
      )}
    </SpaceBetween>
  );
}

function CryptoDetail({ row }: { row: AssetRow }) {
  const cp = row.component.cryptoProperties;
  if (!cp) {
    return <Box variant="p">No cryptographic properties recorded for this asset.</Box>;
  }
  switch (cp.assetType) {
    case 'protocol':
      return <ProtocolDetail row={row} />;
    case 'certificate':
      return <CertificateDetail row={row} />;
    case 'related-crypto-material':
      return <RelatedMaterialDetail row={row} />;
    case 'algorithm':
    default:
      return <AlgorithmDetail row={row} />;
  }
}

function AlgorithmDetail({ row }: { row: AssetRow }) {
  const a = row.component.cryptoProperties?.algorithmProperties;
  // Deeper-detail fields live on flat cryptamap:* props on the wire (see deepProp).
  const algorithmName = deepProp(row, 'algorithmName') ?? a?.algorithmName;
  const keySizeBits = deepProp(row, 'keySizeBits') ?? a?.keySizeBits;
  const kmsKeySpec = deepProp(row, 'kmsKeySpec') ?? a?.kmsKeySpec;
  const mode = deepProp(row, 'mode') ?? a?.mode;
  // Friendly primitive label (e.g. "ae" -> "Authenticated encryption (AES-GCM)")
  // so the raw CycloneDX code never leaks into the Algorithm / Primitive rows.
  const primitive = a?.primitive;
  const primitiveFriendly = primitiveLabel(primitive);
  // The Algorithm row prefers a concrete algorithm name; fall back to the
  // friendly primitive (NOT the raw "ae" code) when no name was captured.
  const algorithmDisplay = algorithmName ?? primitiveFriendly;
  // Symmetric (AES/HMAC) keys have no elliptic curve and no padding scheme — those
  // are ECC/RSA-only concepts. Flag the empty rows as "Not applicable" so a non-
  // expert reads them as empty-by-design, not missing data.
  const symmetricPrimitives = new Set(['ae', 'block-cipher', 'stream-cipher', 'mac']);
  const isSymmetric =
    symmetricPrimitives.has(String(primitive ?? '')) ||
    /symmetric|aes|hmac/i.test(kmsKeySpec ?? '');
  const symReason = 'symmetric key';
  // Symmetric-strength tier from the joined roadmap item (AES-256 safe /
  // AES-128 review / weak / unconfirmed). Additive to the raw strength fields.
  const strength = strengthPresentation(row.roadmapItem?.symmetricStrength);
  return (
    <KeyValuePairs
      columns={3}
      items={[
        field('Asset type', 'Algorithm (symmetric / at-rest)', 'assetType'),
        field('Algorithm', show(algorithmDisplay), 'algorithm'),
        field('Primitive', show(primitiveFriendly), 'primitive'),
        field('Mode', show(mode), 'mode'),
        field('Key size (bits)', show(keySizeBits ?? a?.parameterSetIdentifier), 'keySizeBits'),
        field('KMS key spec', show(kmsKeySpec), 'kmsKeySpec'),
        field('Curve', show(a?.curve), 'curve', isSymmetric ? symReason : undefined),
        field('Padding', show(a?.padding), 'padding', isSymmetric ? symReason : undefined),
        field('Parameter set', show(a?.parameterSetIdentifier), 'parameterSet'),
        ...(strength
          ? [
              field(
                'Symmetric strength',
                <StatusIndicator type={strength.indicator}>{strength.label}</StatusIndicator>,
                'symmetricStrength',
              ),
            ]
          : []),
        field('Classical security level', show(a?.classicalSecurityLevel), 'classicalSecurityLevel'),
        field('NIST quantum level', show(a?.nistQuantumSecurityLevel), 'nistQuantumLevel'),
      ]}
    />
  );
}

// Friendly framing of an in-transit protocol by its wire `type` (tls, ssh,
// ipsec, ike, mqtt, …). Drives the asset-type sub-heading and whether the
// key-exchange group is labelled as a TLS group or an SSH KEX.
function protocolPresentation(type: string | undefined): {
  assetLabel: string;
  kexLabel: string;
} {
  switch ((type ?? '').toLowerCase()) {
    case 'ssh':
      return { assetLabel: 'Protocol (SSH / in-transit)', kexLabel: 'SSH key exchange (KEX)' };
    case 'ipsec':
      return { assetLabel: 'Protocol (IPsec / in-transit)', kexLabel: 'Key exchange group' };
    case 'ike':
    case 'ikev2':
      return { assetLabel: 'Protocol (IKEv2 / in-transit)', kexLabel: 'Key exchange group' };
    case 'mqtt':
      return { assetLabel: 'Protocol (MQTT / in-transit)', kexLabel: 'Key exchange group' };
    case 'tls':
    default:
      return { assetLabel: 'Protocol (TLS / in-transit)', kexLabel: 'Key exchange group' };
  }
}

function ProtocolDetail({ row }: { row: AssetRow }) {
  const { cbom } = useScanData();
  const p = row.component.cryptoProperties?.protocolProperties;
  const suites = p?.cipherSuites ?? [];
  const transforms = p?.ikev2TransformTypes ?? [];
  const { assetLabel, kexLabel: baseKexLabel } = protocolPresentation(p?.type);
  // Qualify the KEX-group label by PROVENANCE so a config-derived value is not
  // misread as the actually-negotiated group. Only cloudtrail_evidence observes
  // the real negotiated group from a live handshake; every config scanner (ELB/
  // API GW PQ policies, VPN DH groups, Transfer SSH KEXs) reports the SUPPORTED/
  // PERMITTED set the policy allows, not what a given client negotiated.
  const isNegotiated = row.service === 'cloudtrail_evidence';
  // Deeper-detail fields live on flat cryptamap:* props on the wire (see deepProp).
  const keyExchangeGroup = deepProp(row, 'keyExchangeGroup') ?? p?.keyExchangeGroup;
  // Only qualify the label when a value is actually present, so an empty row
  // stays a clean "Key exchange group: —" rather than "...(supported): —".
  const kexLabel = keyExchangeGroup
    ? `${baseKexLabel} (${isNegotiated ? 'negotiated' : 'supported'})`
    : baseKexLabel;
  const certSignatureAlgorithm = deepProp(row, 'certSignatureAlgorithm') ?? p?.certSignatureAlgorithm;
  const certKeySizeBits = deepProp(row, 'certKeySizeBits') ?? p?.certKeySizeBits;
  // pqcHybrid is emitted as the literal string "true" only when true; absent
  // otherwise. Fall back to the nested boolean for non-CDX consumers.
  const pqcHybridProp = deepProp(row, 'pqcHybrid');
  const pqcHybrid = pqcHybridProp === 'true' ? true : pqcHybridProp === undefined ? p?.pqcHybrid : false;
  const tlsMinVersion = deepProp(row, 'tlsMinVersion') ?? p?.tlsMinVersion;
  // PQ evidence tier: 'confirmed' = an observed negotiated PQ handshake (only
  // cloudtrail_evidence); 'capable' = the policy/config PERMITS PQ but real
  // negotiation is client-dependent and was not observed. Surfaced so a PQ-hybrid
  // claim is never read as "proven" when it is only "permitted".
  const pqEvidence = deepProp(row, 'pqEvidence');
  return (
    <SpaceBetween size="s">
      <KeyValuePairs
        columns={3}
        items={[
          field('Asset type', assetLabel, 'assetType'),
          field('Protocol', show(p?.type).toUpperCase(), 'protocol'),
          field('Version', show(p?.version), 'version'),
          field('Minimum TLS version (floor)', show(tlsMinVersion), 'tlsMinVersion'),
          field(kexLabel, show(keyExchangeGroup), 'keyExchangeGroup'),
          field(
            'PQC hybrid key exchange',
            pqcHybrid ? (
              pqEvidence === 'confirmed' ? (
                <Badge color="green">PQC hybrid — confirmed (observed)</Badge>
              ) : (
                <Badge color="blue">PQC hybrid — capable (policy permits)</Badge>
              )
            ) : pqcHybrid === false ? (
              <Badge color="grey">Classical</Badge>
            ) : (
              DASH
            ),
            'pqcHybrid',
          ),
          field('Cert signature algorithm', show(certSignatureAlgorithm), 'certSignatureAlgorithm'),
          field('Cert key size (bits)', show(certKeySizeBits), 'certKeySizeBits'),
        ]}
      />
      {suites.length > 0 && (
        <div>
          <Box variant="awsui-key-label">Cipher suites</Box>
          <Box padding={{ top: 'xxs' }}>
            <SpaceBetween size="xxs">
              {suites.map((s, i) => {
                // cipherSuites[].algorithms are CycloneDX refType bom-refs to
                // synthesized algorithm components; resolve each back to its human
                // algorithm name for display (raw value kept if not a ref).
                const algos = (s.algorithms ?? []).map((r) => resolveAlgorithmName(cbom, r));
                const ids = s.identifiers ?? [];
                const hasDetail = algos.length > 0 || ids.length > 0;
                const badge = (
                  <Badge key={`${s.name}-badge`} color="blue">
                    {s.name ?? '(unnamed suite)'}
                  </Badge>
                );
                if (!hasDetail) {
                  return <div key={`${s.name}-${i}`}>{badge}</div>;
                }
                return (
                  <ExpandableSection
                    key={`${s.name}-${i}`}
                    variant="footer"
                    headerText={s.name ?? '(unnamed suite)'}
                  >
                    <KeyValuePairs
                      columns={1}
                      items={[
                        ...(algos.length > 0
                          ? [{ label: 'Algorithms', value: algos.join(', ') }]
                          : []),
                        ...(ids.length > 0
                          ? [{ label: 'Identifiers', value: ids.join(', ') }]
                          : []),
                      ]}
                    />
                  </ExpandableSection>
                );
              })}
            </SpaceBetween>
          </Box>
        </div>
      )}
      {transforms.length > 0 && (
        <div>
          <Box variant="awsui-key-label">IKEv2 transform types</Box>
          <Box padding={{ top: 'xxs' }}>
            <SpaceBetween size="xxs" direction="horizontal">
              {transforms.map((t, i) => (
                <Badge key={`${t}-${i}`} color="blue">
                  {t}
                </Badge>
              ))}
            </SpaceBetween>
          </Box>
        </div>
      )}
    </SpaceBetween>
  );
}

function CertificateDetail({ row }: { row: AssetRow }) {
  const { cbom } = useScanData();
  const cp = row.component.cryptoProperties;
  const c = cp?.certificateProperties;
  const a = cp?.algorithmProperties;
  // Deeper-detail fields live on flat cryptamap:* props on the wire (see deepProp).
  const algorithmName = deepProp(row, 'algorithmName') ?? a?.algorithmName;
  const keySizeBits = deepProp(row, 'keySizeBits') ?? a?.keySizeBits;
  // certSignatureAlgorithm / certKeySizeBits are emitted from probed TLS chains;
  // use them as a fallback for the certificate's own sig-alg / key-size fields.
  const certSignatureAlgorithm = deepProp(row, 'certSignatureAlgorithm');
  const certKeySizeBits = deepProp(row, 'certKeySizeBits');
  // signatureAlgorithmRef is a CycloneDX refType — a bom-ref to a synthesized
  // algorithm component. Resolve it back to the human algorithm name for display
  // (resolveAlgorithmName returns the raw value unchanged if it isn't a ref).
  const sigAlgoRef = c?.signatureAlgorithmRef
    ? resolveAlgorithmName(cbom, c.signatureAlgorithmRef)
    : undefined;
  // RSA certs have no elliptic curve (curve is ECDSA-only); flag the empty row.
  const sigAlgo = sigAlgoRef ?? certSignatureAlgorithm ?? algorithmName;
  const isRSA = /rsa/i.test(String(sigAlgo ?? '')) && !/ecdsa|ec[_-]/i.test(String(sigAlgo ?? ''));
  return (
    <KeyValuePairs
      columns={3}
      items={[
        field('Asset type', 'Certificate (PKI)', 'assetType'),
        field('Subject', show(c?.subjectName), 'subject'),
        field('Issuer', show(c?.issuerName), 'issuer'),
        field('Signature algorithm', show(sigAlgo), 'signatureAlgorithm'),
        field(
          'Key size (bits)',
          show(keySizeBits ?? certKeySizeBits ?? a?.parameterSetIdentifier),
          'keySizeBits',
        ),
        field('Curve', show(a?.curve), 'curve', isRSA ? 'RSA certificate' : undefined),
        field('Format', show(c?.certificateFormat), 'certFormat'),
        field('Not valid before', showDate(c?.notValidBefore), 'notValidBefore'),
        field('Not valid after', showDate(c?.notValidAfter), 'notValidAfter'),
        field('Classical security level', show(a?.classicalSecurityLevel), 'classicalSecurityLevel'),
        field('Subject public key ref', show(c?.subjectPublicKeyRef), 'subjectPublicKeyRef'),
        field('Extension', show(c?.certificateExtension), 'certExtension'),
      ]}
    />
  );
}

function RelatedMaterialDetail({ row }: { row: AssetRow }) {
  const m = row.component.cryptoProperties?.relatedCryptoMaterialProperties;
  // KMS keys (and similar key-material assets) carry the friendly algorithm name +
  // KMS key spec as flat props; surface them so a real KMS key shows e.g.
  // "AES-256-GCM" / "SYMMETRIC_DEFAULT" rather than only the raw material fields.
  const algorithmName = deepProp(row, 'algorithmName');
  const kmsKeySpec = deepProp(row, 'kmsKeySpec') ?? deepProp(row, 'keySpec');
  // Friendly material type/state: scanners that map to a CycloneDX enum member
  // (e.g. CloudHSM "key", KMS alias "other", Secrets Manager "credential") preserve
  // the original descriptive label as cryptamap:materialType. State that is not a
  // valid CDX enum member (e.g. "unknown") is dropped from the schema field and
  // preserved as cryptamap:materialState. Prefer the friendly props for display.
  const materialType = deepProp(row, 'materialType') ?? m?.type;
  const materialState = m?.state ?? deepProp(row, 'materialState');
  return (
    <KeyValuePairs
      columns={3}
      items={[
        field('Asset type', 'Related key material', 'assetType'),
        ...(algorithmName ? [field('Algorithm', show(algorithmName), 'algorithm')] : []),
        ...(kmsKeySpec ? [field('KMS key spec', show(kmsKeySpec), 'kmsKeySpec')] : []),
        field('Material type', show(materialType), 'materialType'),
        { label: 'Material id', value: show(m?.id) },
        field('State', show(materialState), 'materialState'),
        field('Size (bits)', show(m?.size), 'materialSize'),
        { label: 'Format', value: show(m?.format) },
        { label: 'Algorithm ref', value: show(m?.algorithmRef) },
        field('Secured by', show(m?.securedBy), 'securedBy'),
        { label: 'Value', value: m?.value ? <Box variant="code">{m.value}</Box> : DASH },
        { label: 'Created', value: showDate(m?.creationDate) },
        { label: 'Expires', value: showDate(m?.expirationDate) },
        { label: 'Updated', value: showDate(m?.updateDate) },
      ]}
    />
  );
}

function PqcReadiness({ row }: { row: AssetRow }) {
  const item = row.roadmapItem;
  const posture = posturePresentation(row.posture);

  if (!item) {
    // Unjoined asset: still apply the asset-aware rule so a quantum-safe posture
    // (e.g. symmetric AES-256) reads "Quantum-safe — no action", never a blank
    // or alarming gap.
    const pqcUnjoined = pqcStatusPresentationForAsset(row.pqcStatus, row.posture);
    const safe = isQuantumSafePosture(row.posture);
    return (
      <SpaceBetween size="s">
        <KeyValuePairs
          columns={2}
          items={[
            {
              label: 'Posture',
              value: (
                <InfoPopover header="What does this posture mean?" content={<PostureLegendContent />} topic="pqc">
                  <StatusIndicator type={posture.indicator}>{posture.label}</StatusIndicator>
                </InfoPopover>
              ),
            },
            {
              label: 'PQC status',
              value: safe ? (
                <InfoPopover header="What does this PQC status mean?" content={<PqcStatusContent />} topic="pqc">
                  <StatusIndicator type={pqcUnjoined.indicator}>{pqcUnjoined.label}</StatusIndicator>
                </InfoPopover>
              ) : (
                'No roadmap entry for this asset'
              ),
            },
          ]}
        />
        <Box variant="small" color="text-status-inactive">
          {pqcReasoning(row.posture, '')}
        </Box>
      </SpaceBetween>
    );
  }

  // Asset-aware presentation: a quantum-safe posture never shows "Not yet".
  const pqc = pqcStatusPresentationForAsset(item.pqcStatus, row.posture);
  const actionable = item.pqcStatus === 'available' || item.pqcStatus === 'hybrid-tls-only';
  const strength = strengthPresentation(item.symmetricStrength);

  return (
    <SpaceBetween size="s">
      <ColumnLayout columns={2} variant="text-grid">
        <KeyValuePairs
          columns={1}
          items={[
            {
              label: 'Posture',
              value: (
                <InfoPopover header="What does this posture mean?" content={<PostureLegendContent />} topic="pqc">
                  <StatusIndicator type={posture.indicator}>{posture.label}</StatusIndicator>
                </InfoPopover>
              ),
            },
            {
              label: 'PQC status',
              value: (
                <InfoPopover header="What does this PQC status mean?" content={<PqcStatusContent />} topic="pqc">
                  <StatusIndicator type={pqc.indicator}>{pqc.label}</StatusIndicator>
                </InfoPopover>
              ),
            },
            ...(strength
              ? [
                  {
                    label: 'Symmetric strength',
                    value: <StatusIndicator type={strength.indicator}>{strength.label}</StatusIndicator>,
                  },
                ]
              : []),
            { label: 'Upgrade ease', value: upgradeEaseLabel(item.upgradeEase) },
            {
              label: 'Severity',
              value: (
                <StatusIndicator type={severityIndicator(item.severity)}>
                  {item.severity}
                </StatusIndicator>
              ),
            },
          ]}
        />
        <KeyValuePairs
          columns={1}
          items={[
            {
              label: 'MOSCA score (X + Y − Z)',
              value: (
                <InfoPopover header="What is the Mosca score?" content={<MoscaContent />} topic="pqc">
                  <span>{`${item.mosca.score}  (X=${item.mosca.x}, Y=${item.mosca.y}, Z=${item.mosca.z})`}</span>
                </InfoPopover>
              ),
            },
            {
              label: 'Harvest-now-decrypt-later exposure',
              value: item.hndlExposed ? (
                <StatusIndicator type="warning">Exposed</StatusIndicator>
              ) : (
                <StatusIndicator type="success">Not exposed</StatusIndicator>
              ),
            },
            { label: 'Confidence', value: confidenceLabel(item.confidence) },
            { label: 'As of', value: show(item.asOf) },
          ]}
        />
      </ColumnLayout>

      {actionable ? (
        <Alert type="success" header="This asset can move to PQC today">
          {item.recommendedAction || pqcReasoning(row.posture, item.pqcStatus)}
        </Alert>
      ) : (
        <Alert type="info" header="No PQC fix available yet">
          {item.recommendedAction || pqcReasoning(row.posture, item.pqcStatus)}
        </Alert>
      )}

      {safeHref(item.sourceUrl) && (
        <Box>
          <Link href={safeHref(item.sourceUrl)} external target="_blank">
            AWS guidance for this recommendation
          </Link>
        </Box>
      )}

      {item.mosca.notes && (
        <Box variant="small" color="text-status-inactive">
          {item.mosca.notes}
        </Box>
      )}
    </SpaceBetween>
  );
}

// pqcReasoning is the fallback narrative when the roadmap item carries no
// recommendedAction (or there is no item at all). It explains the posture +
// pqcStatus combination in plain language.
function pqcReasoning(posture: string, pqcStatus: string): string {
  switch (posture) {
    case 'no-encryption':
      return 'Data is unencrypted. Enable encryption first; PQC posture cannot be assessed until a cryptographic baseline exists.';
    case 'legacy-tls':
      return 'Legacy TLS (≤ 1.1) is in use. Upgrade to TLS 1.2/1.3 before considering PQC hybrid key exchange.';
    case 'non-pqc-classical':
      return pqcStatus === 'available' || pqcStatus === 'hybrid-tls-only'
        ? 'Classical (non-PQC) cryptography is in use and a post-quantum option is available for this service.'
        : 'Classical (non-PQC) cryptography is in use; no managed post-quantum option is available yet for this service.';
    case 'symmetric-only':
      return 'Symmetric encryption (e.g. AES-256) is already quantum-resistant; no PQC key-exchange migration is required.';
    case 'pqc-hybrid':
      return 'A hybrid post-quantum key exchange is already negotiated for this asset.';
    case 'pqc-ready':
      return 'This asset already uses post-quantum-ready cryptography.';
    default:
      return 'Posture could not be determined for this asset.';
  }
}
