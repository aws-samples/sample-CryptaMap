import Box from '@cloudscape-design/components/box';
import SpaceBetween from '@cloudscape-design/components/space-between';
import StatusIndicator from '@cloudscape-design/components/status-indicator';

// Shared, plain-language popover bodies for the inline (i) explainers, kept in
// one place so RoadmapTable, AssetTable and AssetDetailPanel show identical
// copy. Each is paired with a Learn-page topic id by the call sites:
//   posture legend     -> topic 'pqc'  (How CryptaMap scores & labels)
//   Mosca score        -> topic 'pqc'
//   PQC status         -> topic 'pqc'
// The wording mirrors learnContent.ts so the popovers and the cited Learn page
// never drift apart.

const DASH = '—';

/** Posture legend — what each posture colour/label means. */
export function PostureLegendContent() {
  return (
    <SpaceBetween size="xs">
      <Box variant="small">
        Posture is the current cryptographic state of the asset, worst-first:
      </Box>
      <SpaceBetween size="xxs">
        <StatusIndicator type="error">No encryption</StatusIndicator>
        <Box variant="small">Unencrypted — fix first, regardless of quantum.</Box>
        <StatusIndicator type="error">Legacy TLS</StatusIndicator>
        <Box variant="small">TLS ≤ 1.1 — upgrade to TLS 1.2/1.3 first.</Box>
        <StatusIndicator type="warning">Classical (non-PQC)</StatusIndicator>
        <Box variant="small">
          Public-key crypto (RSA/ECC) that a quantum computer would break — the
          migration target.
        </Box>
        <StatusIndicator type="success">Symmetric only</StatusIndicator>
        <Box variant="small">
          AES-256 / symmetric — already quantum-safe, no key-exchange migration.
        </Box>
        <StatusIndicator type="success">PQC hybrid / PQC ready</StatusIndicator>
        <Box variant="small">
          Post-quantum key exchange already in use — already safe.
        </Box>
      </SpaceBetween>
    </SpaceBetween>
  );
}

/** Mosca score explainer — what X + Y − Z means and that it is configurable. */
export function MoscaContent() {
  return (
    <SpaceBetween size="xs">
      <Box variant="small">
        The Mosca score is a planning heuristic, <strong>not a measured value</strong>:
      </Box>
      <Box variant="small">
        <strong>X</strong> = how long the data must stay secret (secrecy lifetime)
      </Box>
      <Box variant="small">
        <strong>Y</strong> = how long migrating this asset will take
      </Box>
      <Box variant="small">
        <strong>Z</strong> = estimated years until a quantum computer can break the
        crypto
      </Box>
      <Box variant="small">
        If <strong>X + Y &gt; Z</strong> (score &gt; 0) you are already behind, so the
        asset is flagged exposed to "harvest now, decrypt later".
      </Box>
      <Box variant="small" color="text-status-inactive">
        X, Y and Z are <strong>configurable assumptions</strong> — your
        organization's estimates, not facts. Tune them to match your risk.
      </Box>
    </SpaceBetween>
  );
}

/**
 * PQC status explainer — the load-bearing distinction between "no action"
 * (already safe) and "not yet" (needs PQC, none shipped).
 */
export function PqcStatusContent() {
  return (
    <SpaceBetween size="xs">
      <SpaceBetween size="xxs">
        <StatusIndicator type="success">PQC available / PQC hybrid (TLS only)</StatusIndicator>
        <Box variant="small">
          A post-quantum option exists today — you <strong>should</strong> enable it.
        </Box>
        <StatusIndicator type="success">Quantum-safe — no action</StatusIndicator>
        <Box variant="small">
          The asset is <strong>already</strong> quantum-safe (symmetric AES-256 or PQC
          hybrid/ready). Nothing to do.
        </Box>
        <StatusIndicator type="warning">Not yet available</StatusIndicator>
        <Box variant="small">
          The asset <strong>is</strong> quantum-vulnerable and you <strong>need</strong>{' '}
          PQC here, but no managed AWS fix has shipped yet — track AWS announcements.
        </Box>
      </SpaceBetween>
      <Box variant="small" color="text-status-inactive">
        Do not confuse "no action" (already safe) with "not yet" (needs it, none
        shipped) {DASH} they are opposites.
      </Box>
    </SpaceBetween>
  );
}
