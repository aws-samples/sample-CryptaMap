// Static, build-time-baked AWS coverage facts for the homepage coverage panel.
//
// HONESTY CONTRACT (do not replace with a "100% comprehensive" claim):
// CryptaMap does NOT scan every AWS service, and it should never imply it does.
// It scans the services that hold CRYPTOGRAPHIC ASSETS (encryption at rest, TLS in
// transit, key management, certificates/signing). The large majority of AWS
// services have no cryptographic surface of their own to assess and are correctly
// out of scope — counting them as "missing" would be misleading, and claiming to
// cover them would be a false all-clear. Confidence here comes from transparency,
// not from a round number.
//
// The totalAwsServices figure is sourced at build time from the AWS public SSM
// global-infrastructure registry (/aws/service/global-infrastructure/services),
// NOT fetched live from the shipped dashboard — so no extra outbound call is made
// at runtime and customer data never leaves the account. Refresh it by re-running
// the maintainer query and updating `asOf` below.

export interface CoverageDimension {
  key: string;
  label: string;
  /** What this dimension assesses, in one plain-English line. */
  blurb: string;
  /** Number of CryptaMap scanners contributing to this dimension. */
  scanners: number;
}

export interface CoverageFacts {
  /** Total distinct AWS service IDs in the AWS global-infrastructure registry. */
  totalAwsServices: number;
  /** Date the totalAwsServices figure was verified (YYYY-MM). */
  asOf: string;
  /** Authoritative source for the total. */
  source: string;
  /** Distinct AWS services CryptaMap scans for cryptographic assets. */
  servicesCovered: number;
  /** Distinct AWS::Service::Resource types emitted across all scanners. */
  resourceTypes: number;
  /** Total registered scanners. */
  scanners: number;
  dimensions: CoverageDimension[];
  /** Honest note on why the remaining AWS services are not scanned. */
  outOfScopeRationale: string;
  /** Known crypto-bearing services not yet covered (the honest backlog). */
  knownGaps: string[];
}

export const COVERAGE: CoverageFacts = {
  totalAwsServices: 401,
  asOf: '2026-06',
  source: 'AWS SSM public global-infrastructure registry (/aws/service/global-infrastructure/services)',
  servicesCovered: 78,
  resourceTypes: 92,
  scanners: 99,
  dimensions: [
    {
      key: 'data-at-rest',
      label: 'Data at rest',
      blurb: 'Encryption of stored data (KMS / AES-256) across databases, storage, queues, streams, caches, backups, analytics stores, GenAI model stores and CI/CD artifacts.',
      scanners: 49,
    },
    {
      key: 'data-in-transit',
      label: 'Data in transit',
      blurb: 'TLS posture of load balancers, CDNs, API gateways, VPN/interconnect, service meshes, directories and managed-database endpoints.',
      scanners: 27,
    },
    {
      key: 'key-management',
      label: 'Key & secret management',
      blurb: 'KMS keys, custom key stores (CloudHSM/XKS), HSMs, secrets, payment-cryptography keys, and SSH / token-signing key inventories.',
      scanners: 9,
    },
    {
      key: 'certificates',
      label: 'Certificates & signing',
      blurb: 'X.509 certificates, private CAs, code-signing profiles, signed-URL keys, DKIM email signing and certificate-based workforce-auth trust anchors.',
      scanners: 10,
    },
    {
      key: 'runtime-evidence',
      label: 'Runtime & SDK evidence',
      blurb: 'Observed hybrid post-quantum (ML-KEM) TLS key-exchange / KMS crypto operations from CloudTrail, plus SDK & runtime PQC-readiness signals.',
      scanners: 4,
    },
  ],
  outOfScopeRationale:
    'The remaining AWS services have no cryptographic surface of their own to assess — they delegate encryption to the services above (e.g. to S3, EBS or KMS), or they are control-plane, billing, directory and orchestration services that store no customer data and terminate no customer TLS. They are intentionally out of scope, not gaps.',
  knownGaps: [
    'Cannot scan honestly (10): no API returns the posture, so any verdict would be fabricated — e.g. Nitro Enclaves, IAM Identity Center SAML signing, S3 Glacier vaults, S3 on Outposts, WorkMail, WorkDocs',
    'Deferred to a later version (59): buildable and honest but low PQC leverage / low India-FSI adoption / sunsetting — e.g. Verified Access, the Private CA Connectors, most ML services, IoT Wireless/SiteWise/FleetWise, CodeArtifact/Pipeline/Commit',
    'Out of scope (30): delegates to a covered service or has no crypto surface of its own — e.g. Batch, Lake Formation, PrivateLink, RAM, CodeDeploy; XKS is covered by extending the KMS custom-key-store scanner; RabbitMQ by the Amazon MQ scanner',
    'Amazon Cognito Identity Pools — federated-credential broker with no enumerable encryption/key surface of its own (linked IAM SAML/OIDC signing certs are covered via IAM); and AWS Directory Service Kerberos krbtgt key material (not exposed by any API; LDAPS transit IS covered)',
    'The authoritative, always-current register with per-service reasons is docs/COVERAGE-AND-GAPS.md (last audited 2026-06-15)',
  ],
};
