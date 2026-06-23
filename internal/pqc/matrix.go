// Package pqc encodes the web-verified AWS post-quantum cryptography (PQC)
// support matrix and the primitive quantum-vulnerability table as Go data, plus
// safe lookups (PQCSupportFor, PrimitiveReadiness). It is the single source of
// truth for upgrade paths and AWS-doc citations used by the roadmap ranker and
// output writers.
//
// This package is intentionally dependency-light: it imports only stdlib
// (sort) so it can be consumed by internal/roadmap and internal/output without
// dragging in the AWS SDK or creating an import cycle with internal/scanner. It
// MUST NOT import internal/scanner or any AWS SDK package.
//
// All lookups return safe fallbacks rather than panicking on unknown input, so
// the ranker can score unmapped services/primitives conservatively.
//
// Verification as-of date: 2026-06-03 (see AsOf). Every matrix row carries a
// SourceURL and Confidence so consumers can cite and weight each claim.
package pqc

import "sort"

// AsOf is the verification date for the matrix and primitive tables; it is
// cited verbatim in the generated PQC migration roadmap.
const AsOf = "2026-06-03"

// PQCStatus is the post-quantum readiness status of an AWS service/library.
type PQCStatus string

const (
	// StatusAvailable means a real PQC mechanism (ML-KEM/ML-DSA) can be enabled.
	StatusAvailable PQCStatus = "available"
	// StatusHybridTLSOnly means hybrid ML-KEM TLS key exchange is available, but
	// authentication (certificates) remains classical RSA/ECDSA.
	StatusHybridTLSOnly PQCStatus = "hybrid-tls-only"
	// StatusNotYet means no PQC mechanism is published/confirmable yet.
	StatusNotYet PQCStatus = "not-yet"
	// StatusNotApplicable means there is no asymmetric quantum exposure to
	// migrate (e.g. AES-256 symmetric at-rest, quantum resistant).
	StatusNotApplicable PQCStatus = "not-applicable"
	// StatusNotEncrypted is an EFFECTIVE-only status (never a matrix row): it is
	// produced by EffectivePQCStatus for an asset whose posture is no-encryption.
	// PQC readiness is genuinely not assessable until a cryptographic baseline
	// exists, so the asset is NEITHER quantum-safe (not-applicable) NOR an
	// awaiting-fix vulnerable asset (not-yet) — it is a prerequisite / data-hygiene
	// state ("encrypt first"), maturity stage 0. Kept distinct from not-applicable
	// so a CRITICAL unencrypted resource never shares the quantum-safe "no action"
	// label, and so it can be excluded from the quantum-safe KPI denominator.
	StatusNotEncrypted PQCStatus = "not-encrypted"
)

// UpgradeEase describes how much effort enabling PQC takes.
type UpgradeEase string

const (
	// EaseOneFlip: a single security-policy/listener flip.
	EaseOneFlip UpgradeEase = "one-flip"
	// EaseConfigChange: a configuration/client opt-in change.
	EaseConfigChange UpgradeEase = "config-change"
	// EaseAppChange: an application/library rebuild or code change.
	EaseAppChange UpgradeEase = "app-change"
	// EaseAWSManagedAuto: AWS negotiates it automatically, no action needed.
	EaseAWSManagedAuto UpgradeEase = "aws-managed-automatic"
	// EaseNoneAvailable: no PQC action is available.
	EaseNoneAvailable UpgradeEase = "none-available"
)

// Confidence is the verification confidence for a matrix row.
type Confidence string

const (
	// ConfHigh: confirmed verbatim against a live AWS service doc.
	ConfHigh Confidence = "high"
	// ConfMedium: single-source or partially verified.
	ConfMedium Confidence = "medium"
	// ConfLow: absence-based or landing-page-only claim, kept conservative.
	ConfLow Confidence = "low"
)

// SupportEntry is one verified row of the AWS PQC support matrix.
type SupportEntry struct {
	ServiceKey     string      `json:"serviceKey"`
	DisplayName    string      `json:"displayName"`
	CryptoFunction string      `json:"cryptoFunction"`
	PQCStatus      PQCStatus   `json:"pqcStatus"`
	PQCMechanism   string      `json:"pqcMechanism"`
	UpgradeEase    UpgradeEase `json:"upgradeEase"`
	HowToEnable    string      `json:"howToEnable"`
	Confidence     Confidence  `json:"confidence"`
	SourceURL      string      `json:"sourceUrl"`
	Notes          string      `json:"notes,omitempty"`
}

// matrix is the 26-row verified support table keyed by ServiceKey. It is a
// package-level composite literal (no init ordering risk), mirroring
// taxonomy.registry's style.
var matrix = map[string]SupportEntry{
	"kms": {
		ServiceKey:     "kms",
		DisplayName:    "AWS KMS",
		CryptoFunction: "key-management",
		PQCStatus:      StatusAvailable,
		PQCMechanism:   "ML-DSA digital signatures (FIPS 204) via key specs ML_DSA_44/65/87, signing algorithm ML_DSA_SHAKE_256; separately, hybrid ECDH+ML-KEM (X25519MLKEM768) for TLS to the KMS endpoint",
		UpgradeEase:    EaseConfigChange,
		HowToEnable:    "PQ signing: CreateKey with KeySpec=ML_DSA_44|ML_DSA_65|ML_DSA_87, KeyUsage=SIGN_VERIFY; sign with SigningAlgorithm=ML_DSA_SHAKE_256. PQ TLS to endpoint: AwsCrtAsyncHttpClient.builder().postQuantumTlsEnabled(true). NOTE: no ML-KEM *key spec* exists in KMS; data-at-rest under KMS uses AES-256-GCM (SYMMETRIC_DEFAULT), already quantum resistant.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/kms/latest/developerguide/asymmetric-key-specs.html",
		Notes:          "Verified against live AWS KMS docs (2026-06-03): ML_DSA_44/65/87 key specs and ML_DSA_SHAKE_256 GA; RSA_2048/3072/4096, ECC_NIST_P256/P384/P521, ECC_NIST_EDWARDS25519, ECC_SECG_P256K1, SM2 remain classical/quantum-vulnerable. AES-256-GCM explicitly described by AWS as quantum resistant. ML-DSA GA announced 2025-06-13. In CryptaMap taxonomy this maps to the kms_spec/kms_usage/kms_rotation family (alias 'kms').",
	},
	"paymentcryptography": {
		ServiceKey:     "paymentcryptography",
		DisplayName:    "AWS Payment Cryptography",
		CryptoFunction: "key-management",
		PQCStatus:      StatusHybridTLSOnly,
		PQCMechanism:   "Hybrid post-quantum TLS (ML-KEM key exchange) for connections to the AWS Payment Cryptography API ENDPOINT only. The stored payment keys themselves are classical: AES_128/192/256 and HMAC_SHA224/256/384/512 (symmetric), TDES_2KEY/TDES_3KEY (legacy 3DES symmetric), RSA_2048/3072/4096 and ECC_NIST_P256/P384/P521 (asymmetric). There is NO ML-KEM/ML-DSA key algorithm.",
		UpgradeEase:    EaseConfigChange,
		HowToEnable:    "Enable hybrid PQ-TLS to the endpoint by configuring your SDK's HTTP client for post-quantum TLS (e.g. the AWS CRT-based client with post-quantum TLS enabled) when calling AWS Payment Cryptography API endpoints. This protects the CONTROL-PLANE TLS session only; it does NOT change a key's algorithm. To reduce key-algorithm quantum exposure, migrate asymmetric key-exchange/wrapping keys off RSA/ECC where the payment scheme permits, and retire TDES keys in favor of AES.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/payment-cryptography/latest/userguide/data-protection.html",
		Notes:          "Verified 2026-06-09 against the live AWS Payment Cryptography user guide (Data protection): \"All service endpoints support TLS 1.2-1.3 and hybrid post-quantum TLS\" and \"AWS Payment Cryptography also supports a hybrid post-quantum key exchange option for the Transport Layer Security (TLS) network encryption protocol ... when you connect to AWS Payment Cryptography API endpoints.\" CRITICAL DISTINCTION: this is ENDPOINT/TRANSPORT PQ-TLS, NOT a property of the keys. The KeyAlgorithm enum (API_KeyAttributes.html) is TDES_2KEY|TDES_3KEY|AES_128|AES_192|AES_256|HMAC_SHA224/256/384/512|RSA_2048/3072/4096|ECC_NIST_P256/P384/P521 - all classical, no PQC key type. Status is hybrid-tls-only because the only PQC available is transport-layer; key material remains classical/quantum-vulnerable (asymmetric) or weak-legacy (TDES). Do NOT mark a key PQC because the endpoint negotiates PQ-TLS.",
	},
	"acm": {
		ServiceKey:     "acm",
		DisplayName:    "AWS Certificate Manager",
		CryptoFunction: "certificates-pki",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "none (RSA 2048/3072/4096 and ECDSA P-256/P-384/P-521 only); separately ACM service endpoint supports hybrid ECDH+ML-KEM TLS per the PQC landing page",
		UpgradeEase:    EaseNoneAvailable,
		HowToEnable:    "No PQC certificate option in ACM. For ML-DSA certificates use AWS Private CA instead. (ACM API endpoint hybrid PQ-TLS is a transport detail, not a certificate property.)",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/acm/latest/userguide/acm-certificate-characteristics.html",
		Notes:          "Certificate algorithms remain classical. Do NOT conflate the ACM endpoint's hybrid PQ-TLS (transit) with PQC certificates (issuance) - the certificates ACM issues are RSA/ECDSA only.",
	},
	"rolesanywhere": {
		ServiceKey:     "rolesanywhere",
		DisplayName:    "AWS IAM Roles Anywhere",
		CryptoFunction: "certificates-pki",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "Workload X.509 authentication via a trust-anchor CA. PQC readiness is INHERITED from the trust anchor's CA: an AWS_ACM_PCA trust anchor can reference a Private CA whose key algorithm is ML-DSA (FIPS 204) ML_DSA_44/65/87; a CERTIFICATE_BUNDLE (external) trust anchor's posture is whatever the uploaded PEM actually is (classical RSA/ECDSA today). Roles Anywhere itself documents signature validation only for RSA and ECDSA.",
		UpgradeEase:    EaseConfigChange,
		HowToEnable:    "Roles Anywhere has no PQC toggle of its own. To make workload auth post-quantum, back the trust anchor with an AWS Private CA configured for an ML-DSA key algorithm (ML_DSA_44|ML_DSA_65|ML_DSA_87) and issue ML-DSA end-entity certs from it, then create the trust anchor with SourceType=AWS_ACM_PCA pointing at that CA. External CERTIFICATE_BUNDLE anchors carry whatever algorithm the uploaded CA PEM uses.",
		Confidence:     ConfMedium,
		SourceURL:      "https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_Source.html",
		Notes:          "Verified live 2026-06-09 against the rolesanywhere API Reference: Source.sourceType Valid Values = AWS_ACM_PCA | CERTIFICATE_BUNDLE | SELF_SIGNED_REPOSITORY; SourceData is a UNION with acmPcaArn (AWS_ACM_PCA) and x509CertificateData (PEM, CERTIFICATE_BUNDLE). The trust-model doc (Signature validation) enumerates RSA/ECDSA only and documents NO universal ML-DSA guarantee, so PQCStatus=not-yet (Confidence medium): there is no Roles-Anywhere-level PQC switch. PQC is achievable today only by sourcing the trust anchor from an ML-DSA AWS Private CA — Private CA's ML_DSA_44/65/87 support is independently confirmed (see the acmpca matrix row). No dated What's New ML-DSA-for-Roles-Anywhere announcement could be re-confirmed, so no GA date is asserted. Scanner classifies CERTIFICATE_BUNDLE anchors by parsing the inline PEM (observed); AWS_ACM_PCA anchors cross-link to the acmpca asset and are left Unknown here rather than guessed.",
	},
	"acmpca": {
		ServiceKey:     "acmpca",
		DisplayName:    "AWS Private CA",
		CryptoFunction: "certificates-pki",
		PQCStatus:      StatusAvailable,
		PQCMechanism:   "ML-DSA (FIPS 204) certificate signing: key algorithms ML_DSA_44 / ML_DSA_65 / ML_DSA_87 alongside classical RSA and ECDSA",
		UpgradeEase:    EaseConfigChange,
		HowToEnable:    "Create CA / issue certs selecting an ML-DSA key algorithm (ML_DSA_44|ML_DSA_65|ML_DSA_87) via CreateCertificateAuthority / IssueCertificate. KeyAlgorithm and SigningAlgorithm enum strings ML_DSA_44 | ML_DSA_65 | ML_DSA_87 are confirmed verbatim (underscores, not 'ML-DSA-44') against the live acm-pca API Reference.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/privateca/latest/APIReference/API_CertificateAuthorityConfiguration.html",
		Notes:          "ML-DSA digital certificate issuance reconfirmed 2026-06-04 against the live acm-pca API Reference: CertificateAuthorityConfiguration.KeyAlgorithm Valid Values include ML_DSA_44 | ML_DSA_65 | ML_DSA_87 (plus RSA_2048/3072/4096, EC_prime256v1/secp384r1/secp521r1, SM2), and both CertificateAuthorityConfiguration.SigningAlgorithm and IssueCertificate.SigningAlgorithm Valid Values include ML_DSA_44 | ML_DSA_65 | ML_DSA_87. These are production API enum values (shipped/available, not preview), so the exact KeyAlgorithm strings are now confirmed (was medium-confidence). The earlier whats-new GA date ('2025-11-10' / GA) is NOT independently re-confirmed here (no dated What's New page loaded); the live API enums are themselves authoritative that the capability and strings are real and current. See also IssueCertificate API: https://docs.aws.amazon.com/privateca/latest/APIReference/API_IssueCertificate.html",
	},
	"alb": {
		ServiceKey:     "alb",
		DisplayName:    "Application Load Balancer",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusHybridTLSOnly,
		PQCMechanism:   "Hybrid ML-KEM TLS 1.3 key exchange (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024); PQ used for key exchange/confidentiality only, NOT authentication",
		UpgradeEase:    EaseOneFlip,
		HowToEnable:    "Set the HTTPS listener SslPolicy to a '-PQ-2025-09' policy, e.g. ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 (FIPS: ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09). Console-created listeners now default to ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09; CLI/CloudFormation/CDK still default to non-PQ ELBSecurityPolicy-2016-08.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html",
		Notes:          "Verified against live ALB describe-ssl-policies doc (2026-06-03). Confirmed PQ policy names: ELBSecurityPolicy-TLS13-1-3-PQ-2025-09, -1-2-PQ-2025-09, -1-2-Res-PQ-2025-09, -1-2-Ext1-PQ-2025-09, -1-2-Ext2-PQ-2025-09, -1-0-PQ-2025-09 and FIPS variants. Console default = Res-PQ; IaC default = 2016-08 (non-PQ) both confirmed verbatim. RFC9151/CNSA1.0 policies are CLASSICAL, not PQ - do not flag as PQ-ready.",
	},
	"nlb": {
		ServiceKey:     "nlb",
		DisplayName:    "Network Load Balancer",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusHybridTLSOnly,
		PQCMechanism:   "Hybrid ML-KEM TLS 1.3 key exchange (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024) on TLS listeners",
		UpgradeEase:    EaseOneFlip,
		HowToEnable:    "Set the TLS listener SslPolicy to a '-PQ-2025-09' policy (same family as ALB), e.g. ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 or the FIPS variant. Backend (LB-to-target) leg auto-maps to ELBSecurityPolicy-TLS13-1-0-PQ-2025-09 (or -FIPS-PQ) and is not independently configurable.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/about-aws/whats-new/2025/11/network-load-balancers-post-quantum-key-exchange-tls/",
		Notes:          "Announced 2025-11-21. Opt-in: existing listeners are NOT auto-migrated. Shares the ELB PQ policy family verified on the ALB doc. Backend PQ policy is implied by the front-end PQ policy choice.",
	},
	"cloudfront": {
		ServiceKey:     "cloudfront",
		DisplayName:    "Amazon CloudFront",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusHybridTLSOnly,
		PQCMechanism:   "Quantum-safe (hybrid) key exchange X25519MLKEM768 and SecP256r1MLKEM768 for viewer-to-CloudFront TLS; TLS 1.3 only; negotiated automatically, no separate PQ toggle",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No separate PQ knob. Use a CloudFront security policy that allows TLS 1.3 (e.g. TLSv1.2_2021 or TLSv1.3_2025); quantum-safe groups negotiate automatically when the viewer supports them. TLS 1.2-only viewers cannot use PQ.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
		Notes:          "Verified verbatim against live CloudFront doc (2026-06-03): supports X25519MLKEM768 and SecP256r1MLKEM768, 'only supported with TLS 1.3'. NOTE: only two groups (no SecP384r1MLKEM1024, unlike ELB). Signature schemes remain classical RSA/ECDSA (no ML-DSA), so authentication is NOT post-quantum. CryptaMap source comment 'PQC-default since 2024' over-asserts the date; the capability is real but tie it to TLS 1.3 negotiation, not a 2024 default.",
	},
	"apigw_rest": {
		ServiceKey:     "apigw_rest",
		DisplayName:    "Amazon API Gateway (REST)",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusHybridTLSOnly,
		PQCMechanism:   "hybrid ML-KEM TLS key exchange via PQ-enhanced security policies (transport only; certificate auth stays classical)",
		UpgradeEase:    EaseOneFlip,
		HowToEnable:    "Set the custom-domain securityPolicy to a PQ-enhanced policy: SecurityPolicy_TLS13_1_2_PQ_2025_09, SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09, or SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09. Available for Regional and private APIs and custom domains only — NOT edge-optimized APIs.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html",
		Notes:          "Verified 2026-06-03 against the AWS API Gateway security-policies-list doc: policies containing 'PQ' implement hybrid PQC key exchange. SCOPE: Regional/private/custom-domain only; edge-optimized policies (SecurityPolicy_TLS13_2025_EDGE, _TLS12_PFS_2025_EDGE, _TLS12_2018_EDGE, TLS_1_0) have NO PQ variant. (Corrected from a prior stale not-yet entry.)",
	},
	"apigw_http": {
		ServiceKey:     "apigw_http",
		DisplayName:    "Amazon API Gateway (HTTP)",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "none confirmed for HTTP/WebSocket APIs",
		UpgradeEase:    EaseNoneAvailable,
		HowToEnable:    "PQ-enhanced security policies are confirmed for REST (Regional/private) API custom domains; HTTP/WebSocket API PQ support is NOT independently reconfirmed as of 2026-06-03. Kept conservative until verified for HTTP APIs.",
		Confidence:     ConfLow,
		SourceURL:      "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html",
		Notes:          "Deliberately conservative: the verified PQ policy list applies to REST (apigw_rest). HTTP APIs historically expose only TLS_1_2; do not assume PQ for HTTP APIs without confirmation. An inventory tool that overstates PQC readiness is dangerous.",
	},
	"transferfamily": {
		ServiceKey:     "transferfamily",
		DisplayName:    "AWS Transfer Family",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusAvailable,
		PQCMechanism:   "Hybrid ML-KEM SSH key exchange (mlkem768x25519-sha256, mlkem768nistp256-sha256, mlkem1024nistp384-sha384) for SFTP/SSH - NOT general HTTPS/TLS",
		UpgradeEase:    EaseOneFlip,
		HowToEnable:    "Set the Transfer Family server security policy to TransferSecurityPolicy-2025-03 or TransferSecurityPolicy-FIPS-2025-03 (or TransferSecurityPolicy-AS2Restricted-2025-07). Older TransferSecurityPolicy-PQ-SSH-Experimental-2023-04 / -FIPS-Experimental-2023-04 are deprecated.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/transfer/latest/userguide/security-policies.html",
		Notes:          "PQ here is SSH KEX (SFTP), not TLS - distinct mechanism from ELB/CloudFront. An inventory tool must not treat Transfer Family PQ as TLS-hybrid coverage.",
	},
	"secretsmanager": {
		ServiceKey:     "secretsmanager",
		DisplayName:    "AWS Secrets Manager",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusAvailable,
		PQCMechanism:   "Hybrid post-quantum TLS key exchange (ECDH + ML-KEM) for the Secrets Manager API endpoint; at-rest secrets encrypted via KMS AES-256 (quantum resistant)",
		UpgradeEase:    EaseConfigChange,
		HowToEnable:    "Client-side opt-in: AwsCrtAsyncHttpClient.builder().postQuantumTlsEnabled(true) passed to SecretsManagerAsyncClient. Secrets Manager Agent defaults to ML-KEM-preferred. Available in all Regions except China. At-rest AES-256 needs no action.",
		Confidence:     ConfHigh,
		SourceURL:      "https://docs.aws.amazon.com/secretsmanager/latest/userguide/pqtls.html",
		Notes:          "PQ applies to the transport/transit leg (client to endpoint), not to the at-rest secret algorithm. CryptaMap taxonomy places secretsmanager under data-at-rest (secret-encryption) and secrets_rotation under key-management; the PQ capability is a transit property layered on top.",
	},
	"ssm": {
		ServiceKey:     "ssm",
		DisplayName:    "AWS Systems Manager Parameter Store",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "none for SSM API endpoints (no PQTLS/ML-KEM documented); SecureString at-rest uses KMS AES-256 (quantum resistant)",
		UpgradeEase:    EaseNoneAvailable,
		HowToEnable:    "No PQ-TLS option exposed for Systems Manager endpoints. SecureString at-rest encryption already uses KMS AES-256 (no action). No PQ transit action available yet.",
		Confidence:     ConfMedium,
		SourceURL:      "https://docs.aws.amazon.com/systems-manager/latest/userguide/data-protection.html",
		Notes:          "Based on absence of any PQC mention in SSM data-protection docs (only TLS 1.2 required / 1.3 recommended). Kept conservative - reported as not-yet on transit, with the at-rest path already quantum-resistant via AES-256.",
	},
	"s3": {
		ServiceKey:     "s3",
		DisplayName:    "Amazon S3",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "at-rest SSE uses AES-256 (quantum resistant, no migration needed); a hybrid ML-KEM PQ-TLS endpoint is claimed only on the PQC landing page and was NOT confirmable at S3 service-doc level",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "At-rest: S3 SSE (SSE-S3/SSE-KMS) uses AES-256, already quantum resistant - no action. Transit PQ-TLS to S3 endpoints is unverified at the service-doc level; do not assert it as enabled.",
		Confidence:     ConfLow,
		SourceURL:      "https://aws.amazon.com/security/post-quantum-cryptography/",
		Notes:          "Two facets: (1) at-rest AES-256 is quantum resistant and should NOT be flagged as quantum-vulnerable - this is high confidence; (2) S3 endpoint PQ-TLS is a low-confidence landing-page-only claim, kept unverified. The 'not-yet' status here refers specifically to a confirmable PQ-TLS transit capability, not to at-rest security.",
	},
	"ebs": {
		ServiceKey:     "ebs",
		DisplayName:    "Amazon EBS",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256-XTS/GCM volume encryption via KMS - symmetric, quantum resistant (Grover-only); no asymmetric PQC migration required",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest. AES-256 is quantum resistant; ensure volumes are encrypted with a KMS key.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "AWS explicitly states 256-bit symmetric at-rest encryption is quantum resistant and needs no re-encryption. pqcStatus=not-applicable means 'no asymmetric quantum exposure to migrate', not 'insecure'.",
	},
	"rds": {
		ServiceKey:     "rds",
		DisplayName:    "Amazon RDS",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256 storage encryption via KMS - symmetric, quantum resistant",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest. For RDS in-transit TLS (rds_transit), PQ key exchange depends on the database engine TLS stack, which AWS does not document as PQ-hybrid; treat transit as classical.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "At-rest AES-256 quantum resistant. The separate rds_transit channel is classical (no documented PQ-hybrid); do not flag at-rest as quantum-vulnerable.",
	},
	"dynamodb": {
		ServiceKey:     "dynamodb",
		DisplayName:    "Amazon DynamoDB",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256 table encryption via KMS - symmetric, quantum resistant",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest; AES-256 is quantum resistant.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "At-rest symmetric encryption is not quantum-vulnerable. Transit to DynamoDB endpoints (HTTPS) is classical unless a PQ-TLS-aware client is used; not separately documented as PQ-hybrid.",
	},
	"redshift": {
		ServiceKey:     "redshift",
		DisplayName:    "Amazon Redshift",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256 cluster encryption via KMS - symmetric, quantum resistant",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest; AES-256 is quantum resistant.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "redshift_transit (in-transit TLS) is classical; no documented PQ-hybrid.",
	},
	"elasticache": {
		ServiceKey:     "elasticache",
		DisplayName:    "Amazon ElastiCache",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256 at-rest encryption via KMS - symmetric, quantum resistant",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest; AES-256 is quantum resistant.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "elasticache_transit (in-transit TLS) is classical; no documented PQ-hybrid key exchange.",
	},
	"documentdb": {
		ServiceKey:     "documentdb",
		DisplayName:    "Amazon DocumentDB",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256 storage encryption via KMS - symmetric, quantum resistant",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest; AES-256 is quantum resistant.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "documentdb_transit TLS is classical; no documented PQ-hybrid.",
	},
	"neptune": {
		ServiceKey:     "neptune",
		DisplayName:    "Amazon Neptune",
		CryptoFunction: "data-at-rest",
		PQCStatus:      StatusNotApplicable,
		PQCMechanism:   "AES-256 storage encryption via KMS - symmetric, quantum resistant",
		UpgradeEase:    EaseAWSManagedAuto,
		HowToEnable:    "No PQC action for at-rest; AES-256 is quantum resistant.",
		Confidence:     ConfHigh,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "neptune_transit TLS is classical; no documented PQ-hybrid.",
	},
	"s3-transit": {
		ServiceKey:     "s3-transit",
		DisplayName:    "Amazon S3 (in-transit TLS)",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "Hybrid ML-KEM PQ-TLS claimed on PQC landing page only; not confirmed at S3 service-doc level",
		UpgradeEase:    EaseNoneAvailable,
		HowToEnable:    "No confirmable one-flip. A PQ-TLS-capable client (aws-crt/s2n-tls with a PQ policy) could in principle negotiate hybrid groups against S3 endpoints, but AWS does not document an S3-specific PQ-TLS guarantee.",
		Confidence:     ConfLow,
		SourceURL:      "https://aws.amazon.com/security/post-quantum-cryptography/",
		Notes:          "Explicit s3-transit row because the prompt lists it. Landing-page-only claim; treat S3 endpoint PQ-TLS as unconfirmed rather than asserting it.",
	},
	"db_transit": {
		ServiceKey:     "db_transit",
		DisplayName:    "Database in-transit TLS",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "Database engine TLS stacks (RDS/Aurora/Redshift/ElastiCache/DocumentDB/Neptune) are classical RSA/ECDHE; AWS does not document a PQ-hybrid key exchange for these in-transit channels",
		UpgradeEase:    EaseNoneAvailable,
		HowToEnable:    "No PQ-TLS option documented for these database engines' in-transit channels. Track AWS announcements. (At-rest for these services is AES-256 / quantum-resistant — a SEPARATE asset/row; do not conflate.)",
		Confidence:     ConfMedium,
		SourceURL:      "https://aws.amazon.com/blogs/security/aws-post-quantum-cryptography-migration-plan/",
		Notes:          "Dedicated row so the *_transit scanners do NOT inherit their at-rest sibling's not-applicable status (which would FALSE-SAFE a classical TLS endpoint as quantum-safe). The transit channel is classical; the at-rest row stays not-applicable independently.",
	},
	"s2n_tls": {
		ServiceKey:     "s2n_tls",
		DisplayName:    "s2n-tls (AWS open-source TLS)",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusAvailable,
		PQCMechanism:   "Hybrid AND pure ML-KEM key exchange (x25519+mlkem768, secp256r1+mlkem768, secp384r1+mlkem1024; pure ML-KEM-1024 in cnsa_2) plus ML-DSA authentication (ML-DSA-87 in cnsa_2)",
		UpgradeEase:    EaseAppChange,
		HowToEnable:    "Build s2n-tls against AWS-LC; set security policy 'default_pq' (pinned '20250721') for hybrid ML-KEM, or 'cnsa_2' for pure ML-KEM-1024 + ML-DSA-87 (TLS 1.3 PQ-only), or transitional 'cnsa_1_2_interop'. ML-DSA auth requires AWS-LC >= v1.50.0.",
		Confidence:     ConfHigh,
		SourceURL:      "https://github.com/aws/s2n-tls/blob/main/docs/usage-guide/topics/ch16-post-quantum.md",
		Notes:          "Library, not a managed service - included because CryptaMap scans SDK/library posture (sdk-library function). Maps loosely to the sdkpqc family. Server with PQ enabled mandates PQ KEX with any PQ-advertising client (possible HelloRetryRequest). cnsa_2 (pure) differs from AWS managed ELB/CloudFront policies which are HYBRID, not pure CNSA 2.0.",
	},
	"aws_lc": {
		ServiceKey:     "aws_lc",
		DisplayName:    "AWS-LC (AWS libcrypto)",
		CryptoFunction: "data-in-transit",
		PQCStatus:      StatusAvailable,
		PQCMechanism:   "ML-KEM (FIPS 203) and ML-DSA (FIPS 204) inside a FIPS 140-3 validated module",
		UpgradeEase:    EaseAppChange,
		HowToEnable:    "Link against AWS-LC; FIPS PQ TLS uses the AWS-LC FIPS module automatically (e.g. via ELB FIPS-PQ policies). Verify the specific CMVP certificate before claiming FIPS-validated ML-KEM for a given build.",
		Confidence:     ConfMedium,
		SourceURL:      "https://aws.amazon.com/security/post-quantum-cryptography/",
		Notes:          "Underpins ELB FIPS-PQ policies and s2n-tls PQ. AWS states AWS-LC is the first open-source crypto module to include ML-KEM in its FIPS validation; the exact CMVP cert/version is not independently verified here, so kept medium.",
	},
	"signer": {
		ServiceKey:     "signer",
		DisplayName:    "AWS Signer",
		CryptoFunction: "certificates-pki",
		PQCStatus:      StatusNotYet,
		PQCMechanism:   "none (classical RSA/ECDSA code signing only; no ML-DSA/SLH-DSA/LMS/XMSS)",
		UpgradeEase:    EaseNoneAvailable,
		HowToEnable:    "No PQC option in managed AWS Signer. For PQ code signing use the DIY pattern: ML-DSA key in KMS + ML-DSA code-signing cert from Private CA, CMS-wrapped (RFC 9882).",
		Confidence:     ConfMedium,
		SourceURL:      "https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html",
		Notes:          "Based on absence of any PQ signature mention in Signer docs. The DIY KMS+Private CA ML-DSA code-signing pattern (aws-samples, 2025-11-17) is a real alternative but is NOT a feature of the managed Signer service.",
	},
}

// serviceAlias maps CryptaMap scanner Name()s / risk-service keys onto matrix
// ServiceKeys so callers can look up by the asset.Service they actually have.
// It is defined here (not in taxonomy) to keep the taxonomy registry at exactly
// 99 entries. Targets must be keys present in matrix.
var serviceAlias = map[string]string{
	// KMS family heads -> kms
	"kms_spec":     "kms",
	"kms_usage":    "kms",
	"kms_rotation": "kms",
	// Runtime CloudTrail KMS data-plane evidence maps onto the kms PQ row: it
	// observes which KMS signing/encryption algorithms (ML-DSA/ML-KEM vs
	// RSA/ECDSA) are actually in use at runtime, so the same PQ upgrade guidance
	// (the kms ML-DSA / hybrid ML-KEM row) applies. No new matrix row is added,
	// keeping the 26-row invariant intact and reusing the kms SourceURL/Notes.
	"cloudtrail_evidence": "kms",
	// Secrets Manager rotation (key-management subaspect) shares the
	// secretsmanager PQ row.
	"secrets_rotation": "secretsmanager",
	// In-transit DB channels map to the dedicated classical db_transit row — NOT
	// their at-rest sibling (which is not-applicable/quantum-safe AES-256).
	// Inheriting the at-rest row FALSE-SAFED these classical TLS endpoints as
	// "quantum-safe — no action" (a vulnerable posture passing through a
	// not-applicable service status in EffectivePQCStatus).
	"rds_transit":         "db_transit",
	"aurora_transit":      "db_transit",
	"elasticache_transit": "db_transit",
	"documentdb_transit":  "db_transit",
	"redshift_transit":    "db_transit",
	"neptune_transit":     "db_transit",
	// Certificate scanners.
	"iam_certs": "acm",
	// cloudfront_certs is the distribution's VIEWER CERTIFICATE (classical
	// RSA/ECDSA authentication), NOT the hybrid ML-KEM key-exchange channel. Map it
	// to the acm (certificate/PKI, classical) row like the other cert scanners —
	// NOT the cloudfront (transit hybrid-TLS) row, which would bleed an endpoint
	// key-exchange capability onto a certificate asset (the false-safe bug).
	"cloudfront_certs": "acm",
	// SDK/library posture scanners loosely map onto the s2n-tls library row.
	"lambda_runtime":   "s2n_tls",
	"container_images": "s2n_tls",
	"ec2_ssm":          "s2n_tls",
}

// All returns every SupportEntry sorted by ServiceKey, for tests and UI
// enumeration.
func All() []SupportEntry {
	out := make([]SupportEntry, 0, len(matrix))
	for _, e := range matrix {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServiceKey < out[j].ServiceKey })
	return out
}
