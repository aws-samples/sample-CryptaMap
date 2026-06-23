package pqc

import _ "embed"

// embeddedKnowledge is the baked-in default PQC knowledge, generated FROM the
// in-package literals by cmd/gen-knowledge (Phase 3) and committed. It is the
// air-gap floor: the binary classifies correctly with zero network/doc access.
// This is the first go:embed in the repo.
//
//go:embed data/pqc-knowledge.json
var embeddedKnowledge []byte

// scannerDocFacts holds the Type-C documented per-scanner crypto facts, keyed
// {package}/{scanner}/{fact-slug}. Each is a UNIVERSAL AWS-doc guarantee a
// scanner stamps onto an asset (via services.StampDocFactKeyed) as the auditable
// basis for a classification the per-resource API cannot establish. The Value is
// a faithful description of the documented guarantee; SourceURL/Confidence/AsOf
// are the provenance. Migrated from the 21 inline services.StampDocFact call-
// sites + the kms_rotation.go direct prop-write (Phase 1b). This is the maintainer-
// edited source of truth for these facts (projected into the embedded JSON by
// cmd/gen-knowledge; the golden test asserts the round-trip).
var scannerDocFacts = map[string]ScannerDocFact{
	"datarest/dms/at-rest-aes256": {
		Value:      "AWS DMS encrypts the storage used by a replication instance (and endpoint connection information) with an AWS KMS key. If no custom key is specified, DMS uses the account default key aws/dms, which is created when the replication instance is first launched. So a replication instance is always encrypted at rest; an absent KmsKeyId means the aws/dms default key, not no-encryption, and the posture is unconditionally SymmetricOnly.",
		SourceURL:  "https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/keyspaces/at-rest-aes256": {
		Value:      "Server-side encryption at rest is enabled on ALL Amazon Keyspaces tables and CANNOT be disabled; the entire table is encrypted at rest with AES-256. By default Keyspaces uses an AWS-owned key; a customer can instead select a customer-managed key. So a nil/unknown EncryptionSpecification means the AWS-owned default key, not no-encryption, and every table is unconditionally SymmetricOnly.",
		SourceURL:  "https://docs.aws.amazon.com/keyspaces/latest/devguide/encryption.howitworks.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/sagemaker/at-rest-aes256": {
		Value:      "When a SageMaker AI Domain is created, an Amazon EFS volume is created for it and SageMaker uses AWS KMS to encrypt that volume with an AWS managed key by default; a customer-managed key can be specified for more control. So a Domain with an empty KmsKeyId is encrypted at rest under the AWS-managed key, not unencrypted, and the posture is unconditionally SymmetricOnly.",
		SourceURL:  "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sagemaker-domain.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/ssm/at-rest-aes256": {
		Value:      "All AWS Systems Manager Parameter Store parameters — regardless of type (String, StringList, SecureString) — are encrypted both in transit and at rest; standard String/StringList parameters are encrypted at rest with an AWS owned key, while SecureString adds customer-controlled AWS KMS envelope encryption. So a String/StringList parameter is NOT unencrypted; every parameter is unconditionally SymmetricOnly, with SecureString recorded as a higher-assurance key tier.",
		SourceURL:  "https://docs.aws.amazon.com/systems-manager/latest/userguide/data-protection.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/timestream/at-rest-aes256": {
		Value:      "Encryption at rest is turned on by default for a Timestream for LiveAnalytics database and CANNOT be turned off; AES-256 is the default algorithm and AWS KMS is required for encryption at rest. An absent KmsKeyId means the AWS-managed default key (alias/aws/timestream), not no-encryption, so every database is unconditionally SymmetricOnly.",
		SourceURL:  "https://docs.aws.amazon.com/timestream/latest/developerguide/EncryptionAtRest.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/backup/at-rest-aes256": {
		Value:      "An AWS Backup vault is always encrypted: backups are encrypted with either an AWS owned key (default) or a customer-managed KMS key, and AWS Backup encrypts all backups even when the source resource is not encrypted (independent encryption uses AES-256). The EncryptionKeyType distinguishes AWS_OWNED_KMS_KEY from CUSTOMER_MANAGED_KMS_KEY; an empty EncryptionKeyArn means the AWS-owned default key, not no-encryption, so a vault is unconditionally SymmetricOnly.",
		SourceURL:  "https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"keymgmt/cognito/rs256-token-signing": {
		Value:      "Every Amazon Cognito user pool signs its ID and access tokens with RS256 — an RSA-2048 signature with SHA-256. This algorithm is intrinsic to the user pool and cannot be changed, disabled, or upgraded; Cognito offers no post-quantum or hybrid token-signing option. RSA signatures are forgeable by a cryptographically-relevant quantum computer (Shor's algorithm), so the token-signing posture of every user pool is unconditionally classical (NonPQCClassical) — an always-on quantum-migration target, not an 'encryption off' finding.",
		SourceURL:  "https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"certmgmt/acmpca/supported-key-algos": {
		Value:      "AWS Private CA supports a fixed set of CA key algorithms, and CryptaMap maps each to a fixed posture: ML-DSA (FIPS 204) is a pure post-quantum signature algorithm so an ML_DSA_44/65/87 CA key is PQC-ready; RSA and EC keys are classical (non-PQC); there is no ML-KEM CA key algorithm (a CA key signs, it does not encapsulate). This is a universal AWS Private CA capability guarantee, not a per-CA live observation.",
		SourceURL:  "https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html#supported-algorithms",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"certmgmt/rolesanywhere/trust-model-signature-validation": {
		Value:      "IAM Roles Anywhere trust-anchor signature validation uses the validation algorithm required by the certificate's key type (for example RSA or ECDSA); the trust-model doc documents NO universal ML-DSA / post-quantum floor. This provenance therefore backs only the Unknown posture recorded for a trust anchor whose algorithm cannot be observed here (AWS_ACM_PCA source carrying only an ARN, SELF_SIGNED_REPOSITORY, or an unrecognized-OID bundle) — it is the documented basis for *why* the posture is Unknown, never a fabricated safe posture.",
		SourceURL:  "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html",
		Confidence: "low",
		AsOf:       "2026-06-09",
	},
	"datarest/cloudwatchlogs/at-rest-aes256": {
		Value:      "Amazon CloudWatch Logs always encrypts all log groups at rest; by default the service manages the encryption and uses 256-bit AES in Galois/Counter Mode (AES-256-GCM) to encrypt log data at rest. Associating a customer KMS key (LogGroup.KmsKeyId) only upgrades the key tier — its absence means the CloudWatch-Logs-managed key, NOT an unencrypted log group — so every log group is unconditionally SymmetricOnly and a missing KmsKeyId is recorded as the AWS-owned default key, never as no-encryption.",
		SourceURL:  "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/data-protection.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/dynamodb/at-rest-aes256": {
		Value:      "Amazon DynamoDB always encrypts all data at rest with AES-256, and at-rest encryption cannot be turned off. The SSEDescription only distinguishes the key tier: an absent KMSMasterKeyArn (or the SSEDescription's DISABLED status) denotes the AWS-owned default key — which is still AES-256-encrypted, NOT unencrypted — while a present ARN is an AWS-managed aws/dynamodb key or customer CMK. Posture is therefore unconditionally SymmetricOnly, and table Status (e.g. UPDATING during key rotation) never downgrades it.",
		SourceURL:  "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.howitworks.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/ebs/at-rest-aes256-xts": {
		Value:      "Each encrypted Amazon EBS volume is encrypted at rest using AES-256-XTS, which requires two 256-bit volume keys (a 512-bit volume key total) — distinct from the AES-256-GCM block used by other at-rest services. This XTS cipher is the universal AWS-doc guarantee stamped here; only volumes whose Encrypted flag is true are marked SymmetricOnly, and the per-resource KMS key identity and key spec are live observations layered on top of the doc-backed cipher fact.",
		SourceURL:  "https://docs.aws.amazon.com/kms/latest/cryptographic-details/ebs-volume-encryption.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"datarest/fsx/at-rest-aes256-xts": {
		Value:      "Encryption of data at rest is automatically enabled when you create an Amazon FSx file system and cannot be turned off; the data is encrypted using an XTS-AES-256 block cipher. A scratch FSx for Lustre file system reports no KmsKeyId because it is encrypted with keys managed by Amazon FSx, while persistent file systems expose the KMS key; in both cases the file system is encrypted. Every file system is therefore unconditionally SymmetricOnly (AES-256-XTS), and an absent KmsKeyId is the Amazon-FSx-managed key, never no-encryption.",
		SourceURL:  "https://docs.aws.amazon.com/fsx/latest/LustreGuide/encryption-at-rest.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/lightsail/at-rest-aws-managed": {
		Value:      "All Amazon Lightsail attached disks and disk snapshots are encrypted at rest by default using keys that Lightsail manages on your behalf. Lightsail exposes no per-instance encryption configuration via its API, so every instance is classified SymmetricOnly on the basis of this universal AWS-doc guarantee, with the AWS-owned default key sentinel recorded.",
		SourceURL:  "https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-faq-block-storage.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"datarest/msk/at-rest-aes256": {
		Value:      "Amazon MSK always encrypts your data at rest, for both provisioned and serverless clusters. If you don't specify a KMS key, MSK creates an AWS-managed key and uses it on your behalf. Every cluster is therefore SymmetricOnly; provisioned clusters expose the data-volume KMS key via Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId, while serverless clusters expose no EncryptionInfo field so the key id is left unset.",
		SourceURL:  "https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"datarest/memorydb/at-rest-aes256": {
		Value:      "Amazon MemoryDB at-rest encryption is always enabled and cannot be disabled; it protects persistent data with AES-256. A cluster can use either the default service-managed key or a customer-managed KMS key, so the KmsKeyId field selects the key tier only — its absence means the AWS-owned default key, NOT an unencrypted cluster. Every cluster is therefore unconditionally SymmetricOnly, and a missing KmsKeyId is recorded as the AWS-owned default key rather than no-encryption.",
		SourceURL:  "https://docs.aws.amazon.com/memorydb/latest/devguide/at-rest-encryption.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/secretsmanager/at-rest-aes256": {
		Value:      "AWS Secrets Manager always encrypts the protected secret value in every secret version with AES-256 envelope encryption; encryption at rest cannot be disabled. A secret uses either the AWS-managed key aws/secretsmanager (the default when no KmsKeyId is set) or a customer-managed KMS key, so the KmsKeyId field selects the key tier only — its absence means the aws/secretsmanager default key, NOT an unencrypted secret. Every secret is therefore unconditionally SymmetricOnly, and a missing KmsKeyId is recorded as the AWS-managed default key rather than no-encryption.",
		SourceURL:  "https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"datarest/qldb/at-rest-aes256": {
		Value:      "Amazon QLDB always encrypts all ledger data at rest and at-rest encryption cannot be disabled; data is encrypted with AES-256 using AWS KMS. A ledger uses either the default AWS owned key (the default when no KmsKeyArn is set) or a customer-managed KMS key, so the KmsKeyArn field selects the key tier only — its absence means the AWS-owned default key, NOT an unencrypted ledger. Every ledger is therefore unconditionally SymmetricOnly, and a missing KmsKeyArn is recorded as the AWS-owned default key rather than no-encryption.",
		SourceURL:  "https://docs.aws.amazon.com/qldb/latest/developerguide/data-protection.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"keymgmt/cloudhsm/pkcs11-classical-only": {
		Value:      "AWS CloudHSM (CloudHSMv2) exposes a closed, exhaustively-enumerated PKCS#11 mechanism and key-type set limited to classical algorithms (AES, 3DES, RSA, ECDSA, and classical hashes) with no post-quantum mechanisms (no ML-KEM/ML-DSA/SLH-DSA). Consequently any asymmetric key usable in a CloudHSM cluster is classical and quantum-vulnerable. This is a universal guarantee (the supported-algorithm list is exhaustive, not an overridable default), so the cluster posture is fixed at NonPQCClassical.",
		SourceURL:  "https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-mechanisms.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"keymgmt/kms_rotation/rotation-inapplicable": {
		Value:      "Automatic KMS key rotation is supported ONLY on symmetric-default KMS keys (KeySpec SYMMETRIC_DEFAULT) with AWS_KMS origin and no custom key store. For asymmetric, HMAC, imported (EXTERNAL-origin), or custom-key-store keys, rotation status can never report enabled, so it is inapplicable rather than disabled. This guarantee backs the scanner skipping GetKeyRotationStatus and emitting rotationApplicable=false / rotationEnabled=\"inapplicable\" (instead of a misleading rotationEnabled=false) for non-applicable keys. The provenance is written directly (PropSourceURL + PropAsOf only, no separate confidence) as an additive sub-claim that does NOT clobber the StampObserved source=observed/confidence=high posture basis set just above.",
		SourceURL:  "https://docs.aws.amazon.com/kms/latest/APIReference/API_GetKeyRotationStatus.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"keymgmt/kms_usage/aws-managed-symmetric-only": {
		Value:      "Every AWS-managed KMS key (reserved alias prefix \"alias/aws/<service>\", which customers cannot create) is always a symmetric encryption key. AWS KMS automatically rotates AWS-managed keys yearly, and automatic rotation is supported ONLY on symmetric-encryption KMS keys with AWS_KMS origin; therefore an AWS-managed key can never be asymmetric. This lets an alias/aws/* whose target key cannot be resolved via DescribeKey (lazily provisioned, no TargetKeyId) be classified SymmetricOnly rather than a permission/timing-gap Unknown.",
		SourceURL:  "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"sdkpqc/container_images/ecr-at-rest-encryption": {
		Value:      "Amazon ECR encrypts repository contents at rest by default, and the encryption behavior is a definitional guarantee of the ECR EncryptionType enum: AES256 uses SSE-S3 AES-256, and KMS/KMS_DSSE with a symmetric (or AWS-managed/unreadable) key spec is a KMS-backed AES symmetric envelope. Both are symmetric-only and quantum-safe at rest. This provenance is stamped only when the resolved at-rest posture is symmetric-only.",
		SourceURL:  "https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"sdkpqc/ec2_ssm/control-plane-tls-floor": {
		Value:      "The Systems Manager (SSM) control-plane API endpoints require TLS, and the documented minimum protocol version is TLS 1.2, with no AWS-guaranteed named cipher suite. This is a doc-backed floor describing the SSM control-plane tunnel only; it is NOT a determination of the managed instance's own outbound TLS posture, which is not observable from DescribeInstanceInformation and is recorded as Unknown.",
		SourceURL:  "https://docs.aws.amazon.com/systems-manager/latest/userguide/data-protection.html",
		Confidence: "medium",
		AsOf:       "2026-06-09",
	},
	"transit/apigw_http/tls-floor": {
		Value:      "AWS API Gateway enforces a TLS 1.2 minimum (floor) for all HTTP API default endpoints: it accepts TLS 1.2 and TLS 1.3 and rejects TLS 1.0/1.1. This is a genuine universal AWS guarantee, so the recorded TLS 1.2 minimum version is correct but is marked as documented (high confidence) rather than an observed per-endpoint negotiation. Posture is non-PQC classical.",
		SourceURL:  "https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-ciphers.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"transit/apigw_rest/execute-api-tls-floor": {
		Value:      "API Gateway REST APIs' default execute-api endpoint is assigned a default security policy of TLS_1_0 (per the security-policies list, which shows Regional and Edge-optimized APIs defaulting to TLS_1_0); it is not a universal TLS 1.2 guarantee, so the scanner leaves the TLS version UNKNOWN and posture classical (non-PQC) for the bare REST API. TLS 1.2+ is only guaranteed when traffic flows through a custom domain whose SecurityPolicy pins the minimum version.",
		SourceURL:  "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html",
		Confidence: "low",
		AsOf:       "2026-06-10",
	},
	"transit/appsync/aws-tls-policy": {
		Value:      "AWS AppSync documents its own minimum transit-TLS floor on its Infrastructure Security / data-protection pages: clients accessing AppSync's published API endpoints must support TLS 1.2, with TLS 1.3 recommended (\"We require TLS 1.2 and recommend TLS 1.3\"), and perfect-forward-secrecy cipher suites (DHE/ECDHE). This is a documented TLS 1.2 minimum for the served endpoint; the exact version negotiated per connection depends on the client and is not pinned. No post-quantum / quantum-safe transit guarantee is documented. TLS for resolver hops to EC2 or CloudFront origins is the customer's responsibility and outside this floor.",
		SourceURL:  "https://docs.aws.amazon.com/appsync/latest/devguide/infrastructure-security.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"transit/directconnect/macsec": {
		Value:      "Direct Connect MACsec EncryptionMode semantics are a documented universal AWS guarantee: must_encrypt enforces MACsec encryption outright, while should_encrypt (the default for new MACsec-capable connections) PREFERS MACsec but FALLS BACK to unencrypted/cleartext communication if MACsec negotiation fails, so it is only encrypted when proven live (PortEncryptionStatus == 'Encryption Up'). MACsec uses AES-GCM, a symmetric quantum-resistant cipher (classified symmetric-only, not a PQC migration target). Stamped at high confidence whenever EncryptionMode was returned.",
		SourceURL:  "https://docs.aws.amazon.com/directconnect/latest/UserGuide/MACsec.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"transit/documentdb_transit/security-encryption-ssl": {
		Value:      "Amazon DocumentDB in-transit encryption is managed by the 'tls' parameter in the cluster's cluster parameter group. New clusters default to TLS enabled, but TLS can be disabled (at create or later) via a non-default cluster parameter group: tls=enabled/tls1.2+/tls1.3+/fips-140-3 enforce TLS (only secure connections are accepted), while tls=disabled means the cluster does NOT accept secure connections (plaintext). The default cluster parameter group is immutable, so a cluster on a default group cannot have had tls changed and is TLS-enforced. The scanner reads the cluster's parameter group value and downgrades posture to no-encryption (with an enforcement note) only when tls is explicitly 'disabled'; an enforcing value or a default group is reported as enforced classical TLS. If the parameter could not be read, the enforcement state is left undetermined rather than assuming either way.",
		SourceURL:  "https://docs.aws.amazon.com/documentdb/latest/devguide/security.encryption.ssl.html",
		Confidence: "high",
		AsOf:       "2026-06-16",
	},
	"transit/ecs/aws-tls-policy": {
		Value:      "Amazon ECS publishes a service-specific transport-security floor on its Infrastructure Security page: clients calling ECS published API operations must support TLS 1.2 (minimum), AWS recommends TLS 1.3, and perfect-forward-secrecy cipher suites (DHE/ECDHE) are required. The documented minimum is therefore TLS 1.2; the version actually negotiated per connection is decided at handshake time and is not specified, so the served version on any individual session is UNKNOWN beyond the >= 1.2 floor. This floor applies to the ECS API endpoints only and documents no post-quantum/hybrid key exchange; data-plane TLS between tasks is a separate ECS Service Connect / mTLS feature.",
		SourceURL:  "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/infrastructure-security.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"transit/eks/aws-tls-policy": {
		Value:      "Amazon EKS documents its own minimum transport-security posture: clients accessing the EKS-served AWS API / managed Kubernetes API-server endpoint must support TLS, and AWS states \"We require TLS 1.2 and recommend TLS 1.3,\" with perfect-forward-secrecy cipher suites (DHE/ECDHE). This establishes a documented TLS 1.2 floor (1.3 supported) for the control-plane endpoint EKS terminates; the exact version negotiated on a given connection is not pinned, and no post-quantum/hybrid key exchange is documented. The floor covers the EKS API/control-plane endpoint only — not data-plane or in-cluster workload traffic (Pod-to-Pod, ingress/LB, application TLS), which is the customer's responsibility.",
		SourceURL:  "https://docs.aws.amazon.com/eks/latest/userguide/infrastructure-security.html",
		Confidence: "high",
		AsOf:       "2026-06-10",
	},
	"transit/elasticache_transit/in-transit-encryption-enable": {
		Value:      "For ElastiCache replication groups with in-transit encryption enabled, the TransitEncryptionMode determines plaintext acceptance per AWS docs: mode 'required' enforces TLS and refuses unencrypted connections (reported as enforced classical TLS), while mode 'preferred' is a mixed mode that still accepts plaintext alongside TLS (reported as a weakened/legacy-TLS posture, not clean classical TLS). This mode-based plaintext-acceptance semantics is a universal AWS documented guarantee, not an observed cipher; stamped (high confidence) only for the required and preferred modes.",
		SourceURL:  "https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/in-transit-encryption-enable.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"transit/globalaccelerator/aws-tls-policy": {
		Value:      "AWS Global Accelerator is a Layer-4 (TCP/UDP) networking service: its listeners can be configured only for TCP, UDP, or both, with no HTTPS/TLS listener type, and it does NOT terminate TLS. It forwards packets unchanged from its static anycast IPs to the backing endpoints (NLB/ALB/EC2/EIP), so TLS is negotiated end-to-end between the client and the downstream endpoint, not by Global Accelerator. Global Accelerator therefore documents/enforces no TLS version, and the negotiated TLS version is determined entirely by the downstream endpoint and is UNKNOWN from Global Accelerator's perspective. Transit posture should be assessed on the endpoint resource (ALB/NLB/EC2) that actually terminates TLS; any claim that Global Accelerator terminates or forwards 'over TLS' is incorrect.",
		SourceURL:  "https://docs.aws.amazon.com/global-accelerator/latest/dg/introduction-components.html",
		Confidence: "low",
		AsOf:       "2026-06-10",
	},
	"transit/iotcore/iot-endpoints-tls-config": {
		Value:      "When a domain configuration returns no TlsConfig.SecurityPolicy, the documented AWS default for new IoT Core domain configurations is security policy IoTSecurityPolicy_TLS13_1_2_2022_10, which negotiates TLS 1.3 (classical, non-PQC). This is an overridable default for existing configs rather than an observed negotiation, so the TLS 1.3 floor is recorded as a low-confidence documented fallback, not an observed measurement.",
		SourceURL:  "https://docs.aws.amazon.com/iot/latest/developerguide/iot-endpoints-tls-config.html",
		Confidence: "low",
		AsOf:       "2026-06-09",
	},
	"transit/lambda/aws-tls-policy": {
		Value:      "Lambda's data-protection docs state a TLS 1.2 floor (\"We require TLS 1.2 and recommend TLS 1.3\"), but that requirement is for the Lambda control-plane / management API surface, not a served data-plane endpoint version. The docs confirm only that Lambda API endpoints support HTTPS and that management traffic is TLS-encrypted; they do not pin a minimum TLS version for served data-plane endpoints (e.g. Function URLs). The scanner therefore leaves the served-endpoint TLS version UNKNOWN (not asserted) with classical (non-PQC) posture: control-plane comms are HTTPS/TLS-1.2+, but the invoke-path served version is undocumented.",
		SourceURL:  "https://docs.aws.amazon.com/lambda/latest/dg/security-dataprotection.html",
		Confidence: "low",
		AsOf:       "2026-06-10",
	},
	"transit/msk_transit/msk-encryption": {
		Value:      "The MSK in-transit EncryptionInTransit.ClientBroker enum maps deterministically to a documented behavior: TLS enforces TLS encryption for all client-broker traffic, TLS_PLAINTEXT permits both TLS and plaintext (so encryption is not fully enforced), and PLAINTEXT allows only plaintext. This enum-to-behavior mapping plus the broker-to-broker InCluster encryption flag is a universal AWS guarantee (not an observed cipher negotiation), backing the transitEncryptionEnforced classification at high confidence; stamped only for provisioned clusters whose EncryptionInTransit set the enforced flag.",
		SourceURL:  "https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
		Confidence: "high",
		AsOf:       "2026-06-09",
	},
	"transit/neptune_transit/ssl-https-only": {
		Value:      "Amazon Neptune only allows SSL connections through HTTPS to any instance or cluster endpoint, and Neptune endpoints in engine version 1.0.4.0 and above only support HTTPS requests. This is a universal AWS guarantee (plaintext is not accepted), requiring at least TLS 1.2 with strong cipher suites and TLS 1.3 from engine version 1.3.2.0. The negotiated TLS version per connection is not exposed by any API, and the transit cipher family is classical (non-PQC) — no post-quantum / hybrid key exchange is documented for Neptune. The transit posture is therefore enforced classical TLS, stamped at high confidence.",
		SourceURL:  "https://docs.aws.amazon.com/neptune/latest/userguide/security-ssl.html",
		Confidence: "high",
		AsOf:       "2026-06-16",
	},
}

// ScannerDocFactByKey returns the Type-C documented fact for a key (the migrated
// services.StampDocFact provenance), reading the loaded knowledge so a refreshed
// override is honored. ok=false on an unknown key. Never panics.
func ScannerDocFactByKey(key string) (ScannerDocFact, bool) {
	loadKnowledge()
	f, ok := loadedKnow.ScannerDocFacts[key]
	return f, ok
}
