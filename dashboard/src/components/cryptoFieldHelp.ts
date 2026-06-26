// Plain-language explanations for every field shown in the "Cryptographic
// detail" panel (AssetDetailPanel.tsx). Written for a reader with NO cryptography
// background: each entry says what the field is and why it matters for post-
// quantum readiness. Rendered as an inline (i) InfoPopover next to the field
// label. Keep these short (1-3 sentences) — the Learn page carries the depth.

export interface FieldHelp {
  /** Popover header. */
  header: string;
  /** Plain-language body. */
  body: string;
  /** Optional Learn-page topic id to deep-link ("Learn more →"). */
  topic?: string;
}

export const CRYPTO_FIELD_HELP: Record<string, FieldHelp> = {
  // --- Common / framing ---
  assetType: {
    header: 'Asset type',
    body: 'What kind of cryptographic object this is — a stored encryption key, a TLS/network connection, a certificate, or raw key material. It determines which detail fields below apply.',
  },

  // --- Algorithm (keys / at-rest encryption) ---
  algorithm: {
    header: 'Algorithm',
    body: 'The specific cipher protecting the data, e.g. AES-256-GCM. Symmetric ciphers like AES-256 are considered quantum-resistant; public-key algorithms like RSA and ECDSA are not.',
    topic: 'pqc',
  },
  primitive: {
    header: 'Primitive',
    body: 'The category of cryptographic operation. "Authenticated encryption (AES-GCM)" both encrypts and tamper-protects data; "Key encapsulation" / "Digital signature" are public-key operations. It is the family the algorithm belongs to.',
  },
  mode: {
    header: 'Mode of operation',
    body: 'How a block cipher is applied to data. GCM (Galois/Counter Mode) adds built-in integrity checking and is the modern default for AES.',
  },
  keySizeBits: {
    header: 'Key size (bits)',
    body: 'The length of the key in bits — larger is stronger. AES-256 means a 256-bit key. A quantum computer effectively halves a symmetric key’s strength, so AES-256 (→128-bit equivalent) stays quantum-resistant while AES-128 (→64-bit) does not.',
    topic: 'pqc',
  },
  kmsKeySpec: {
    header: 'KMS key spec',
    body: 'AWS KMS’s own name for the key type. SYMMETRIC_DEFAULT is a 256-bit AES key (quantum-resistant). RSA_* and ECC_* specs are asymmetric keys that a quantum computer could break.',
  },
  curve: {
    header: 'Elliptic curve',
    body: 'For elliptic-curve keys, the named curve used (e.g. P-256). Applies ONLY to ECC keys/certificates — symmetric keys like AES have no curve.',
  },
  padding: {
    header: 'Padding scheme',
    body: 'For RSA encryption/signatures, the padding method (e.g. OAEP, PSS). Applies ONLY to RSA — symmetric ciphers like AES-GCM do not use padding.',
  },
  parameterSet: {
    header: 'Parameter set',
    body: 'The specific parameter choice for an algorithm — for post-quantum algorithms this names the security level (e.g. ML-KEM-768). For traditional keys it often just restates the key size.',
  },
  symmetricStrength: {
    header: 'Symmetric strength',
    body: 'Our assessment of whether this symmetric key is strong enough to stay strong enough against a future quantum computer: AES-256 is quantum-resistant, AES-128 warrants review.',
    topic: 'pqc',
  },
  classicalSecurityLevel: {
    header: 'Classical security level',
    body: 'Approximate strength in bits against a normal (non-quantum) computer. 128 bits or more is considered strong today.',
  },
  nistQuantumLevel: {
    header: 'NIST quantum level',
    body: 'NIST’s post-quantum security category (1–5). Higher means more resistant to quantum attack. Level 1 ≈ as hard to break as AES-128 on a quantum computer.',
    topic: 'pqc',
  },

  // --- Certificate ---
  subject: {
    header: 'Subject',
    body: 'Who the certificate identifies — typically the domain name or service it secures.',
  },
  issuer: {
    header: 'Issuer',
    body: 'The Certificate Authority that signed and vouches for this certificate (e.g. Amazon, or a private CA).',
  },
  signatureAlgorithm: {
    header: 'Signature algorithm',
    body: 'The algorithm the issuer used to sign the certificate, e.g. SHA256WITHRSA. RSA and ECDSA signatures are not quantum-resistant; today AWS does not yet issue post-quantum (ML-DSA) certificates.',
    topic: 'pqc',
  },
  certFormat: {
    header: 'Certificate format',
    body: 'The encoding standard of the certificate. X.509 is the universal standard used for TLS/HTTPS certificates.',
  },
  notValidBefore: {
    header: 'Not valid before',
    body: 'The start of the certificate’s validity period — it is not trusted before this date.',
  },
  notValidAfter: {
    header: 'Not valid after',
    body: 'The expiry date — the certificate must be renewed before this or connections will fail.',
  },
  subjectPublicKeyRef: {
    header: 'Subject public key',
    body: 'A reference to the public key bound to this certificate (the half that is shared; the matching private key stays secret).',
  },
  certExtension: {
    header: 'Extension',
    body: 'Optional X.509 certificate extensions (e.g. allowed usages, alternate names) carried alongside the core fields.',
  },

  // --- Protocol (TLS / in-transit) ---
  protocol: {
    header: 'Protocol',
    body: 'The secure-transport protocol in use, e.g. TLS (HTTPS), SSH, or IPsec (VPN). It protects data while it travels over the network.',
  },
  version: {
    header: 'Version',
    body: 'The protocol version. TLS 1.2 and 1.3 are current; TLS 1.0/1.1 are legacy and should be upgraded. TLS 1.3 is required for hybrid post-quantum key exchange.',
  },
  tlsMinVersion: {
    header: 'Minimum TLS version (floor)',
    body: 'The OLDEST TLS version this endpoint still accepts — the negotiation floor, distinct from “Version” (the highest it supports). A 1.0/1.1 floor lets legacy clients connect and should be raised. This is a transport-hardening (downgrade-resistance) signal: in NIST terms TLS version is a deprecation/timeline concern, NOT a post-quantum one — only the key exchange determines quantum safety. Shown when the policy exposes a floor; blank when AWS does not report one.',
    topic: 'pqc',
  },
  keyExchangeGroup: {
    header: 'Key exchange group',
    body: 'How the two sides agree on a shared secret to start the encrypted session. A hybrid group like X25519MLKEM768 mixes a traditional and a post-quantum algorithm, protecting against “harvest-now, decrypt-later” attacks. "(negotiated)" = actually observed on a live connection; "(supported)" = the policy permits it.',
    topic: 'pqc',
  },
  pqcHybrid: {
    header: 'PQC hybrid key exchange',
    body: 'Whether this connection uses a hybrid post-quantum key exchange (a traditional algorithm combined with a quantum-resistant one like ML-KEM). "PQC hybrid" is the goal state for the key exchange — but the certificate is still traditional — full end-to-end PQC also requires an ML-DSA certificate. "Traditional" means it is not yet quantum-resistant.',
    topic: 'pqc',
  },
  certSignatureAlgorithm: {
    header: 'Cert signature algorithm',
    body: 'The signature algorithm of the certificate this endpoint presents, e.g. SHA256WITHRSA. Resolved from the bound ACM certificate when one exists; these are traditional (RSA/ECDSA) today.',
  },
  certKeySizeBits: {
    header: 'Cert key size (bits)',
    body: 'The key size of the endpoint’s certificate, e.g. 2048 for an RSA-2048 cert. Larger RSA keys are stronger against classical attack but none are quantum-resistant.',
  },
  cipherSuites: {
    header: 'Cipher suites',
    body: 'The combinations of algorithms the connection can use (key exchange + encryption + integrity). The set the server offers determines how strong each session can be.',
  },

  // --- Related key material ---
  materialType: {
    header: 'Material type',
    body: 'The kind of key material — e.g. a secret (symmetric) key, a private key, or a public key.',
  },
  materialState: {
    header: 'State',
    body: 'The lifecycle state of the key — e.g. active (in use), suspended, or scheduled for deletion.',
  },
  materialSize: {
    header: 'Size (bits)',
    body: 'The size of the key material in bits — larger keys are generally stronger.',
  },
  securedBy: {
    header: 'Secured by',
    body: 'What protects this key material — e.g. an AWS KMS key or a hardware security module (HSM).',
  },
};
