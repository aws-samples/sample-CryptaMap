// Single source of truth for the cited Learn-page content AND the inline (i)
// popovers. Framework-agnostic data only (no React / no Cloudscape imports) so
// it can be reused, unit-tested and kept honest.
//
// EDITORIAL RULES enforced by the structure of these types (see LearnView.tsx /
// the popovers, which render them):
//   1. EVERY factual statement carries an official source URL. A FactBlock that
//      states a fact MUST list >= 1 source; the renderer asserts this.
//   2. Any passage that is an AI-authored *simplification* of the cited source
//      (not a verbatim claim) is flagged per-block via `aiSimplified: true`,
//      which renders a "AI-simplified — verify against <source>" callout
//      attached to THAT block only.
//   3. A source whose `verified` is 'not-auto-verified' renders with a small
//      "source not auto-verified" note next to the citation.
//
// Source provenance verbatim from the build's VERIFIED SOURCES list. Do not add
// a URL here that is not in that list, and do not change a `verified` flag
// without re-verifying the source.

/** Whether the cited URL was fetched + verified during this build. */
export type SourceVerification = 'verified-this-build' | 'not-auto-verified';

export interface Source {
  /** Short human label for the citing org / document. */
  label: string;
  /** Official source URL (from the build's VERIFIED SOURCES list). */
  url: string;
  /** Verification state — drives the "source not auto-verified" note. */
  verified: SourceVerification;
}

export interface FactBlock {
  /** Plain-English body of the block. */
  body: string;
  /**
   * One or more official sources backing the factual claims in `body`.
   * MUST be non-empty for any block that asserts a fact.
   */
  sources: Source[];
  /**
   * True when `body` is an AI-authored *simplification/paraphrase* of the
   * source rather than a near-verbatim restatement. Renders a per-block
   * "AI-simplified — verify against <source>" callout.
   */
  aiSimplified?: boolean;
}

export interface LearnSection {
  /** Stable id, also the ?topic= deep-link value (e.g. 'threat', 'pqc'). */
  id: string;
  /** Section heading. */
  title: string;
  /** One-line summary shown under the heading. */
  summary: string;
  /** Ordered fact blocks; each is independently cited + AI-flagged. */
  blocks: FactBlock[];
}

// --- Shared source constants (referenced by both Learn + popovers) ----------

const CISA_QR: Source = {
  label: 'CISA / NSA / NIST — Quantum-Readiness factsheet (PDF)',
  url: 'https://www.cisa.gov/sites/default/files/2023-08/Quantum%20Readiness_Final_CLEAR_508c%20%283%29.pdf',
  verified: 'verified-this-build',
};
const CISA_QUANTUM: Source = {
  label: 'CISA — Quantum (post-quantum cryptography) program page',
  url: 'https://www.cisa.gov/quantum',
  verified: 'verified-this-build',
};
const NIST_PQC_PROJECT: Source = {
  label: 'NIST — Post-Quantum Cryptography project',
  url: 'https://csrc.nist.gov/projects/post-quantum-cryptography',
  verified: 'verified-this-build',
};
const NISTIR_8105: Source = {
  label: 'NIST IR 8105 — Report on Post-Quantum Cryptography (PDF)',
  url: 'https://nvlpubs.nist.gov/nistpubs/ir/2016/NIST.IR.8105.pdf',
  verified: 'verified-this-build',
};
const NIST_PQC_FAQ: Source = {
  label: 'NIST — Post-Quantum Cryptography FAQs',
  url: 'https://csrc.nist.gov/projects/post-quantum-cryptography/faqs',
  verified: 'verified-this-build',
};
const FIPS_203: Source = {
  label: 'NIST FIPS 203 — ML-KEM (final)',
  url: 'https://csrc.nist.gov/pubs/fips/203/final',
  verified: 'verified-this-build',
};
const FIPS_204: Source = {
  label: 'NIST FIPS 204 — ML-DSA (final)',
  url: 'https://csrc.nist.gov/pubs/fips/204/final',
  verified: 'verified-this-build',
};
const FIPS_205: Source = {
  label: 'NIST FIPS 205 — SLH-DSA (final)',
  url: 'https://csrc.nist.gov/pubs/fips/205/final',
  verified: 'verified-this-build',
};
const CNSA2_PDF: Source = {
  label: 'NSA — CNSA 2.0 algorithms advisory (PDF)',
  url: 'https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF',
  verified: 'not-auto-verified',
};
const CNSA2_LANDING: Source = {
  label: 'NSA — CNSA 2.0 landing page',
  url: 'https://www.nsa.gov/Cybersecurity/Commercial-National-Security-Algorithm-Suite-2-0/',
  verified: 'not-auto-verified',
};
const CNSA2_NEWS: Source = {
  label: 'NSA — Future QR algorithm requirements (news release)',
  url: 'https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/nsa-releases-future-quantum-resistant-qr-algorithm-requirements-for-national-se/',
  verified: 'not-auto-verified',
};
// AWS upgrade-on-AWS sources (verified this build, from the backend matrix facts).
const AWS_ELB_POLICIES: Source = {
  label: 'AWS — ELB TLS security policies (PQ -2025-09 family)',
  url: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html',
  verified: 'verified-this-build',
};
const AWS_APIGW_POLICIES: Source = {
  label: 'AWS — API Gateway security policies (PQ)',
  url: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html',
  verified: 'verified-this-build',
};
const AWS_KMS_SPECS: Source = {
  label: 'AWS KMS — asymmetric key specs (ML-DSA + AES-256-GCM quantum resistant)',
  url: 'https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html',
  verified: 'verified-this-build',
};
const AWS_PCA_CONFIG: Source = {
  label: 'AWS Private CA — CertificateAuthorityConfiguration (ML-DSA)',
  url: 'https://docs.aws.amazon.com/privateca/latest/APIReference/API_CertificateAuthorityConfiguration.html',
  verified: 'verified-this-build',
};

// Re-export the source constants the popovers reach for directly.
export const SOURCES = {
  CISA_QR,
  CISA_QUANTUM,
  NIST_PQC_PROJECT,
  NISTIR_8105,
  NIST_PQC_FAQ,
  FIPS_203,
  FIPS_204,
  FIPS_205,
  CNSA2_PDF,
  CNSA2_LANDING,
  CNSA2_NEWS,
  AWS_ELB_POLICIES,
  AWS_APIGW_POLICIES,
  AWS_KMS_SPECS,
  AWS_PCA_CONFIG,
};

// --- The six cited Learn sections -------------------------------------------

export const LEARN_SECTIONS: LearnSection[] = [
  {
    id: 'threat',
    title: 'The quantum threat & "harvest now, decrypt later"',
    summary:
      'Why a future quantum computer puts today\'s long-lived data at risk right now.',
    blocks: [
      {
        body:
          'Adversaries can record or steal encrypted data today and decrypt it later, once a cryptographically relevant quantum computer exists. This "harvest now, decrypt later" (also "catch now, break later") operation puts any data with a long secrecy lifetime at risk today — even though the quantum computer does not exist yet.',
        sources: [CISA_QR],
      },
      {
        body:
          'CISA, NSA and NIST urge organizations to begin preparing now: build quantum-readiness roadmaps, take a cryptographic inventory, run risk assessments, and engage vendors. The preparation is needed today precisely because the threat to long-lived data is already present.',
        sources: [CISA_QR],
      },
      {
        body:
          'Quantum computing threatens the cryptographic standards that ensure data confidentiality and integrity and underpin network security. NIST intends to deprecate and remove quantum-vulnerable algorithms from its standards by 2035, so organizations must plan migration to post-quantum cryptography.',
        sources: [CISA_QUANTUM],
      },
      {
        body:
          'The goal of NIST\'s Post-Quantum Cryptography project is to standardize cryptography that is secure against quantum computers — machines that "may be years or decades away but could eventually break many of today\'s widely used cryptographic systems."',
        sources: [NIST_PQC_PROJECT],
      },
      {
        body:
          'Plain-language summary: the danger is not that your data is broken today, but that data you encrypt and transmit today could be stored by an adversary and decrypted years from now. Anything that must stay secret for a long time (financial records, PII, health data, long-lived keys) is the priority to protect first.',
        sources: [CISA_QR, NIST_PQC_PROJECT],
        aiSimplified: true,
      },
    ],
  },
  {
    id: 'symmetric-vs-asymmetric',
    title: 'Symmetric vs. asymmetric: what breaks and what stays safe',
    summary:
      'Shor breaks public-key (RSA/ECC/DH); Grover only weakens symmetric ciphers, so AES-256 stays quantum-safe.',
    blocks: [
      {
        body:
          'Shor\'s algorithm lets a large-scale quantum computer efficiently solve integer factorization and discrete-log problems — the hard problems RSA, elliptic-curve (ECDSA/ECDH) and Diffie-Hellman rely on. NIST IR 8105 lists RSA, ECDSA/ECDH and DSA as "No longer secure" against such a machine. Asymmetric (public-key) cryptography is what breaks.',
        sources: [NISTIR_8105],
      },
      {
        body:
          'If large-scale quantum computers are ever built, they will break many of the public-key cryptosystems currently in use, "seriously compromising the confidentiality and integrity of digital communications on the Internet and elsewhere."',
        sources: [NISTIR_8105],
      },
      {
        body:
          'Grover\'s algorithm gives only a quadratic (square-root) speedup against symmetric / unstructured-search problems. Per NIST IR 8105, "such a speedup does not render cryptographic technologies obsolete" — it merely calls for larger key sizes. Symmetric ciphers are weakened, not broken.',
        sources: [NISTIR_8105],
      },
      {
        body:
          'Because Grover only quadratically speeds up brute-force key search — and is hard to parallelize — NIST states that AES-192 and AES-256 will still be safe against quantum attack, and that AES-128 will likely remain secure too. This is why CryptaMap treats AES-256-at-rest as "quantum-safe — no action".',
        sources: [NIST_PQC_FAQ],
      },
      {
        body:
          'Plain-language summary: think of it as two different locks. Public-key crypto (RSA/ECC) is the lock used to set up keys and sign — Shor picks that lock, so it must be replaced. Symmetric crypto (AES) is the bulk-data lock — Grover only halves its effective strength, so AES-256 (and even AES-128 in practice) stays strong; the fix there is just bigger keys, not a new algorithm.',
        sources: [NISTIR_8105, NIST_PQC_FAQ],
        aiSimplified: true,
      },
    ],
  },
  {
    id: 'standards',
    title: 'The new PQC standards: FIPS 203, 204 and 205',
    summary:
      'NIST published the first three post-quantum standards on August 13, 2024.',
    blocks: [
      {
        body:
          'FIPS 203 — the Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) — was published by NIST on August 13, 2024. ML-KEM is the post-quantum replacement for classical key exchange (ECDH/DH).',
        sources: [FIPS_203],
      },
      {
        body:
          'FIPS 204 — the Module-Lattice-Based Digital Signature Standard (ML-DSA) — was published by NIST on August 13, 2024. ML-DSA is a post-quantum replacement for RSA/ECDSA signatures (e.g. AWS KMS ML_DSA_44/65/87 and AWS Private CA ML-DSA certificates).',
        sources: [FIPS_204, AWS_KMS_SPECS, AWS_PCA_CONFIG],
      },
      {
        body:
          'FIPS 205 — the Stateless Hash-Based Digital Signature Standard (SLH-DSA, based on SPHINCS+) — was published by NIST on August 13, 2024. It provides a conservative, hash-based signature option.',
        sources: [FIPS_205],
      },
      {
        body:
          'Plain-language summary: there are now three finalized, government-standard post-quantum algorithms. ML-KEM handles key exchange (confidentiality); ML-DSA and SLH-DSA handle digital signatures (authentication / integrity). "PQC available" in this tool means an AWS service supports one of these standards for the asset in question.',
        sources: [FIPS_203, FIPS_204, FIPS_205],
        aiSimplified: true,
      },
    ],
  },
  {
    id: 'cnsa',
    title: 'CNSA 2.0 migration timeline (NSA)',
    summary:
      'NSA\'s quantum-resistant requirements for National Security Systems set the de-facto migration clock.',
    blocks: [
      {
        body:
          'NSA\'s CNSA 2.0 advisory specifies the quantum-resistant migration timeline for National Security Systems: software/firmware signing should support and prefer CNSA 2.0 by 2025, with the suite becoming the default/required across most systems and moving toward exclusive use by 2030–2033.',
        sources: [CNSA2_PDF],
      },
      {
        body:
          'NSA announced CNSA 2.0 quantum-resistant algorithm requirements for National Security Systems and published the associated migration timelines on its official CNSA 2.0 page and news release.',
        sources: [CNSA2_LANDING, CNSA2_NEWS],
      },
      {
        body:
          'Plain-language summary: even if you are not a National Security System, CNSA 2.0 is the clearest published timeline for "when" — roughly: start signing with PQC by 2025, expect PQC to be the default by ~2030 and effectively mandatory by 2033. It is useful as a planning horizon. NOTE: the three NSA URLs below could not be auto-fetched during this build (the NSA/defense sites returned HTTP 403 to the verification bot); they are the known-real official NSA pages and are flagged as not-auto-verified — verify the exact dates against the live page.',
        sources: [CNSA2_PDF, CNSA2_LANDING, CNSA2_NEWS],
        aiSimplified: true,
      },
    ],
  },
  {
    id: 'aws',
    title: 'What "upgrade on AWS" actually means',
    summary:
      'For many assets the PQC fix is a managed AWS capability — a security-policy flip or a PQC key spec — not a re-architecture.',
    blocks: [
      {
        body:
          'AWS Application/Network Load Balancers support hybrid ML-KEM post-quantum TLS 1.3 key exchange via the "-PQ-2025-09" security-policy family (e.g. ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09, the console default for new HTTPS listeners). These hybrid policies support SecP256r1MLKEM768, SecP384r1MLKEM1024 and X25519MLKEM768. PQ here covers key exchange / confidentiality only, not authentication. Note the CLI/CloudFormation/CDK default is still the non-PQ ELBSecurityPolicy-2016-08.',
        sources: [AWS_ELB_POLICIES],
      },
      {
        body:
          'Amazon API Gateway offers PQ security policies for Regional and private REST APIs and custom domain names (SecurityPolicy_TLS13_1_2_PQ_2025_09 and PFS/FIPS variants). Policies with "PQ" in the name use post-quantum hybrid key exchange. Edge-optimized APIs have no PQ policy yet.',
        sources: [AWS_APIGW_POLICIES],
      },
      {
        body:
          'AWS KMS provides ML-DSA (FIPS 204) post-quantum signature key specs (ML_DSA_44/65/87) with the ML_DSA_SHAKE_256 signing algorithm. Separately, the symmetric SYMMETRIC_DEFAULT spec is AES-256-GCM, which AWS explicitly describes as quantum resistant — "protected now and in the future." AWS Private CA likewise supports ML-DSA certificate signing (KeyAlgorithm / SigningAlgorithm ML_DSA_44/65/87).',
        sources: [AWS_KMS_SPECS, AWS_PCA_CONFIG],
      },
      {
        body:
          'Plain-language summary: for a lot of AWS assets, "going post-quantum" is not a rewrite. On a load balancer or Regional API Gateway it can be a one-time security-policy change to a PQ policy; in KMS / Private CA it is choosing an ML-DSA key spec; and AES-256 at rest is already quantum-safe and needs no change at all. CryptaMap\'s "Effort" and "PQC status" columns reflect exactly which of these applies to each asset.',
        sources: [AWS_ELB_POLICIES, AWS_APIGW_POLICIES, AWS_KMS_SPECS],
        aiSimplified: true,
      },
    ],
  },
  {
    id: 'pqc',
    title: 'How CryptaMap scores & labels each asset',
    summary:
      'How to read the Mosca score, the posture legend, and the PQC-status badges — and which assumptions are configurable.',
    blocks: [
      {
        body:
          'Mosca score (X + Y − Z): a planning heuristic, not a measured value. X = how long your data must stay secret (secrecy lifetime), Y = how long the migration will take, and Z = the estimated time until a cryptographically relevant quantum computer arrives. If X + Y > Z (score > 0) you are already behind and the asset is flagged as exposed to "harvest now, decrypt later". X, Y and Z are CONFIGURABLE ASSUMPTIONS — they encode your organization\'s estimates, not facts, and can be tuned.',
        sources: [CISA_QR],
        aiSimplified: true,
      },
      {
        body:
          'Posture legend: "No encryption" (critical) and "Legacy TLS" (high) are classical weaknesses to fix regardless of quantum. "Classical (non-PQC)" means public-key crypto that Shor would break — the migration target. "Symmetric only" (AES-256), "PQC hybrid" and "PQC ready" are already quantum-safe and need no key-exchange migration.',
        sources: [NISTIR_8105, NIST_PQC_FAQ],
      },
      {
        body:
          'PQC status — read it carefully. "Quantum-safe — no action" (shown for symmetric-only / PQC-hybrid / PQC-ready assets) means the asset is ALREADY safe; you do not need to do anything. "PQC available" / "PQC hybrid (TLS only)" means a post-quantum option exists today and you SHOULD enable it. "Not yet available" means this asset is quantum-vulnerable AND no managed PQC fix has shipped for it yet — you need PQC here but cannot get it today, so track AWS announcements. Do not confuse "no action" (already safe) with "not yet" (needs it, none shipped).',
        sources: [AWS_KMS_SPECS, NIST_PQC_FAQ],
        aiSimplified: true,
      },
      {
        body:
          'Symmetric strength labels: "AES-256 — quantum-safe" (no action); "AES-128/192 — adequate, review" (fine today, smaller Grover margin, consider AES-256); "weak — replace" (DES/3DES/RC4, classically broken irrespective of quantum); "strength unconfirmed" (a key size could not be determined, so it is conservatively neither labelled safe nor weak). These tier the symmetric primitive and are additive to the quantum-vulnerable flag.',
        sources: [NIST_PQC_FAQ, NISTIR_8105],
        aiSimplified: true,
      },
    ],
  },
];

/** Lookup a section by its ?topic= id. */
export function sectionById(id: string | null | undefined): LearnSection | undefined {
  if (!id) return undefined;
  return LEARN_SECTIONS.find((s) => s.id === id);
}
