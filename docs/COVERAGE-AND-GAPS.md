# CryptaMap — Coverage & Gap Register (authoritative, current)

> **This is the single source of truth for "what CryptaMap scans, what it doesn't, and why."**
> Keep this file current when scanners are
> added or gaps are closed. The homepage coverage panel
> (`dashboard/src/lib/coverageData.ts`) must agree with the headline numbers here.

_Last updated: 2026-06-18. Registry: **99 scanners**, **92 resource types**,
**78 crypto-bearing services covered**, 5 crypto dimensions._

> The **99** figure is the number of distinct taxonomy scanner IDs
> (`internal/taxonomy/taxonomy.go`). Some scanners share a single Go source file, so the
> raw file count under `internal/services/` is higher — the 99 count is the
> taxonomy-exposed scanner count, not a file count.

> **2026-06-17/18 live-validation pass** (internal-only QA, not shipped in this repo):
> an internally-run create→scan→verify→teardown pass (guaranteed teardown + honest
> orphan sweep) classified **real** AWS resources of known crypto state. This raises
> confidence on the validated scanners from "unit-tested" to "live-proven against real
> AWS responses"; it does **not** change the coverage counts above (no scanners
> added/removed). The resource-provisioning harness is internal-only QA tooling and is
> not part of this public sample; see `docs/VALIDATION.md` for the validation strategy
> (Layers 1–3 ship + run in CI; Layer 4 live-validation is internal-only). See the ✅
> live markers in §2 and the validation register in §7.

---

## 1. The honest denominator (why "78 of 401" is not a 19% coverage story)

AWS publishes ~**401** services (SSM global-infrastructure registry, as-of 2026-06).
The vast majority have **no cryptographic surface of their own to assess** — they
are billing, IAM-policy, orchestration, directory, analytics-control-plane, or
developer-tooling services that store no customer data and terminate no customer
TLS. They **delegate** encryption to the services CryptaMap already scans (S3, EBS,
KMS, …). Scanning them would produce a *fabricated* verdict about a service that
has nothing to verify.

So the meaningful denominator is **crypto-bearing service-surfaces**, not "all AWS
services":

| Universe | Count | Notes |
|---|---|---|
| All AWS services | ~401 | SSM registry, build-time baked |
| …with no crypto surface of their own | ~233 | **Correctly out of scope** — delegate to S3/EBS/KMS or store no data |
| **Crypto-bearing service-surfaces** (the real denominator) | **~168** | counted once per dimension a service appears in |
| …covered by CryptaMap | **~122 (~73%)** | strongest on high-traffic primitives; +13 from the 2026-06-15 audit |
| …genuinely uncovered | **99 entries** (59 deferred + 10 cannot-scan-honestly + 30 out-of-scope) | the backlog in §4 |

**Why we never claim "100% comprehensive":** a false all-clear on a regulator-facing
tool is worse than an admitted gap. The homepage encodes this as a HONESTY CONTRACT
and shows the real number + this rationale + the live `knownGaps` list.

---

## 2. What IS covered (99 scanners, by dimension)

Ground-truth scanner IDs from `internal/services/*/*.go`:

**Data at rest (49):** s3, ebs, efs, fsx, rds, aurora_transit*, dynamodb, documentdb,
documentdb_elastic, neptune, keyspaces, elasticache, memorydb, redshift,
redshiftserverless, opensearch, opensearch_serverless, timestream, qldb, kinesis,
firehose, sqs, sns, msk, backup, container_images (ECR), secretsmanager, ssm,
cloudwatchlogs, glue, lambda, sagemaker, workspaces, lightsail, athena, emr,
emr_serverless, dax, storagegateway, bedrock, quicksight, kinesisanalyticsv2 (Managed
Service for Apache Flink), eventbridge, stepfunctions, customerprofiles (Connect
Customer Profiles), workspacesweb (WorkSpaces Secure Browser), codebuild, xray, mgn
(Application Migration Service), kendra.

> **At-rest classifier notes (no fabrication):**
> - **bedrock** — reads CMK custody for custom models / agents / knowledge-bases /
>   guardrails. `KnowledgeBase` has **no readable CMK field in the SDK**, so it is
>   emitted as always-AES-256 / AWS-managed-default **with a note**, never an invented
>   customer-key verdict.
> - **customerprofiles** — `GetDomain DefaultEncryptionKey` classifies CMK vs
>   AWS-managed. AWS-managed default is **"no customer key custody," not a clean
>   all-clear**.
> - **xray** — `GetEncryptionConfig` is **ALWAYS encrypted**; `Type=NONE` means
>   AWS-default custody, **never no-encryption** (modeled like DynamoDB).
>
> **Live-validation key-custody fixes (2026-06-17/18):** the live pass surfaced two
> genuine scanner defects, both the **same false key-custody positive** — labeling
> the AWS-managed default KMS key as a customer CMK (the BFSI-critical distinction).
> Both are now fixed with regression tests:
> - **codebuild** — with no `EncryptionKey` set, AWS returns the
>   AWS-managed default as the **fully-qualified ARN** `arn:…:alias/aws/s3`, but the
>   scanner matched only the bare alias → mislabeled `customer-cmk`. Fixed
>   `isAWSManagedS3Key()` (ARN-suffix match) + a live-form regression test case.
> - **backup** — recorded the auto-assigned `aws/backup`
>   key as a raw key-id ARN with **no custody tier**. Fixed: `resolveBackupKeyTier()`
>   calls `kms:DescribeKey` and maps `KeyMetadata.KeyManager` (AWS →
>   aws-managed-default, CUSTOMER → customer-cmk); on a `DescribeKey` failure it
>   **stays** `kms-key-custody-undetermined` (never guesses). Covered by
>   `TestBackupKeyTierResolution`; `kms:DescribeKey` was already in the scanner IAM
>   policy.
>
> **BYOK / customer-CMK proven live (2026-06-17/18):** the `kms_byok` fixture (a
> customer symmetric CMK + an RSA-3072 CMK) classified correctly —
> `keyManager=CUSTOMER`, `origin=AWS_KMS`, RSA flagged non-pqc-classical
> (quantum-vulnerable) — contrasted against AWS-managed keys (`keyManager=AWS`) in the
> same scan. The `EXTERNAL` (imported BYOK) and `AWS_CLOUDHSM` origins remain
> **unit-tested only** (`TestKMSSpecKeyTierAndOrigin`), not live.

**Data in transit (27):** alb, nlb, cloudfront, apigw_rest, apigw_http, appsync,
globalaccelerator, vpn, directconnect, rds_transit, aurora_transit,
redshift_transit, elasticache_transit, documentdb_transit, neptune_transit,
opensearch_transit, msk_transit, transferfamily, dms, ecs, eks, iotcore,
classicelb, clientvpn, vpclattice, appmesh, directoryservice (LDAPS).

**Key & secret management (9):** kms_spec, kms_usage, kms_rotation,
kms_custom_key_store, cloudhsm, secretsmanager/secrets_rotation, paymentcryptography,
ec2keypairs, cognito (RS256 token-signing).

**Certificates & signing (10):** acm, acmpca, cloudfront_certs, cloudfront_keygroups,
iam_certs, iot_certs, rolesanywhere, signer, (transferfamily SSH keys), ses_dkim
(SESv2 GetEmailIdentity — traditional RSA DKIM → NonPQCClassical), appstream_certauth
(DescribeDirectoryConfigs CertificateBasedAuthProperties → traditional X.509 trust).

**SDK / library evidence (3):** lambda_runtime, ec2_ssm, and SDK-version inference.

**Runtime evidence (1):** cloudtrail_evidence (observed hybrid PQ-TLS (ML-KEM key exchange) / KMS ops).

_*Some services appear in multiple dimensions (transit + at-rest); counted once per dimension._

_The 13 services promoted in the **2026-06-15 coverage audit** (11 at-rest: bedrock,
quicksight, kinesisanalyticsv2, eventbridge, stepfunctions, customerprofiles,
workspacesweb, codebuild, xray, mgn, kendra; 2 certificates/PKI: ses_dkim,
appstream_certauth) moved here out of §4._

---

## 3. Out of scope — and WHY (not gaps)

These will NOT be scanned. Documenting them so they are never mistaken for an
oversight:

| Category | Examples | Reason |
|---|---|---|
| No crypto surface | Billing, Cost Explorer, Organizations, CloudFormation, IAM policy, Resource Groups, Service Catalog | Store no customer data, terminate no customer TLS; delegate to S3/KMS |
| Control-plane only | Most "Manager"/"Config"/"Insights" services | Configuration metadata, no key/cert/TLS surface of their own |
| Physics-layer / not config-observable | QKD, QRNG entropy quality | Not assessable from AWS config/APIs (out of CIWP scope for a config scanner too) |
| Off-AWS surfaces | On-prem files (.pem/.key), endpoint/IoT-device firmware, network packet capture, source-code crypto-API calls | CryptaMap is an AWS config-plane inventory tool, not a SAST / network sensor / filesystem scanner |

---

## 4. KNOWN GAPS — the honest backlog (the auditable not-scanned set)

The **2026-06-15 coverage audit** evaluated **112** additional crypto-touching
services beyond the previously-covered set and split them into four buckets: **13
promoted to v1** (now in §2), **59 deferred**, **10 cannot-scan-honestly**, and **30
out-of-scope** (13 + 59 + 10 + 30 = 112). The **99 not-scanned** services below are
the union of the latter three buckets (59 + 10 + 30). Every entry has a stated reason.

**Priority key:** ⛔ cannot-scan-honestly · 🕓 deferred (buildable+honest, low
leverage/adoption) · 🔁 out-of-scope (delegates or no own surface).

### ⛔ Cannot scan honestly (10) — no API returns the posture; any verdict would be fabricated
| Service | Crypto surface | Why not covered |
|---|---|---|
| **AWS Nitro Enclaves** | Attestation document / PCRs | Runtime-only; no enumeration API to read posture from the control plane. |
| **Amazon EKS Anywhere** | etcd / cluster PKI | Only a billing/subscription API; etcd and PKI live on customer on-prem hardware. |
| **Amazon S3 Glacier vault** | Vault at-rest | `DescribeVault` returns no encryption field; fixed AWS-managed AES-256, nothing to read. |
| **Amazon S3 on Outposts** | Bucket at-rest | Fixed SSE-S3; SSE-KMS unsupported; no `GetBucketEncryption` equivalent. |
| **AWS IAM Identity Center — SAML assertion signing** | Assertion signing cert | Signing cert is console-download metadata only — **BLOCKED pending an AWS read API**; high adoption. |
| **Amazon WorkMail** | Org CMK | Write-only at create; not returned by any `Describe`. |
| **Amazon Honeycode** | (n/a) | Service shut down 2024. |
| **AWS Elemental on-prem appliances (Live/Server/Conductor/Delta/Link)** | Appliance crypto config | Configured on the on-prem box's local API only; no AWS control plane to read. |
| **Amazon WorkDocs** | At-rest key | Key set at provisioning, not returned by any read API; being wound down. |
| **AWS App2Container** | (n/a) | Local CLI; no AWS control plane. |
| **Directory Service — Kerberos `krbtgt`/account keys** | AD key material | Not exposed by any AWS API. *(LDAPS transit IS covered via the directoryservice scanner — listed here as a cannot-scan note, not double-counted.)* |

### 🕓 Deferred (59) — buildable + honest, but low PQC leverage and/or low India-FSI adoption
| Category | Services |
|---|---|
| **Compute / containers** | AWS App Runner · EC2 Image Builder · AWS Fargate (ECS managed storage) · Amazon Lightsail container certs |
| **Storage** | Amazon File Cache · AWS Elastic Disaster Recovery (DRS) · AWS Snow Family · AWS Backup Gateway |
| **Databases / analytics** | AWS HealthOmics · Amazon AppFlow · Amazon DataZone · AWS Clean Rooms · AWS Entity Resolution · Amazon FinSpace (EOS 2026) |
| **Networking / CDN** | AWS Verified Access · AWS Network Firewall (TLS inspection) · Amazon Route 53 DNSSEC · AWS Transit Gateway (encryption-support state) |
| **Security / identity** | Amazon Macie · Amazon GuardDuty · Amazon Inspector · AWS Audit Manager · Amazon Verified Permissions · AWS Private CA Connector for AD · AWS Private CA Connector for SCEP |
| **App integration** | Amazon EventBridge Pipes · Amazon EventBridge Scheduler · Amazon MWAA · Amazon EventBridge Connections |
| **ML / AI** | Amazon Bedrock AgentCore · Amazon Q Business · Amazon Q Developer · Amazon Comprehend · Amazon HealthLake · Amazon Forecast · Amazon Personalize · Amazon Lex V2 (conversation logs) · Amazon Transcribe (`OutputEncryptionKMSKeyId` is write-only/not on the read path) · Amazon SageMaker Feature Store · Amazon Rekognition (Custom Labels) · Amazon Textract (Custom Queries Adapters) · Amazon Translate |
| **IoT** | AWS IoT Core for LoRaWAN · AWS IoT SiteWise · AWS IoT FleetWise · AWS IoT Greengrass V1 (EOS Oct 2026) |
| **Media** | Amazon Nimble Studio · AWS Elemental MediaConnect · AWS Elemental MediaPackage · Amazon IVS · Amazon Kinesis Video Streams |
| **End-user / business** | Amazon Connect Voice ID · Amazon Chime SDK (voice analytics) |
| **Dev tools / management** | AWS CodeArtifact · AWS CodePipeline · AWS CodeCommit · Amazon Managed Grafana · Amazon Managed Service for Prometheus · AWS Proton (EOS Oct 2026) |

> **IoT Greengrass V1 caveat:** do **NOT** claim complete Greengrass coverage via the
> `iot_certs` scanner. `GetGroupCertificateAuthority` returns a group-managed CA PEM
> that `iot_certs` does not enumerate.

### 🔁 Out of scope (30) — delegates to a covered service or has no own crypto surface
Listed explicitly (not just folded into §3) so the absolute not-scanned set stays auditable.

| Category | Services |
|---|---|
| **Compute / containers** | AWS Batch · AWS Elastic Beanstalk · AWS Outposts · Amazon ECS Anywhere · AWS Wavelength · AWS Local Zones · AWS Serverless Application Repository |
| **Storage** | Amazon S3 Access Points / Object Lambda Access Points |
| **Databases / analytics** | AWS Lake Formation · AWS Data Exchange |
| **Networking / CDN** | AWS Gateway Load Balancer · AWS PrivateLink / VPC Endpoint Services · AWS Cloud WAN · AWS Network Manager · Amazon Route 53 Resolver DNS Firewall |
| **Security / identity** | Amazon Detective · AWS Resource Access Manager (RAM) · AWS KMS External Key Store / XKS *(covered by EXTENDING the existing `kms_custom_key_store` scanner, not a new scanner)* · Amazon Cognito Identity Pools *(no per-pool enumerable surface; linked IAM SAML/OIDC signing certs ARE covered via IAM)* |
| **App integration** | Amazon EventBridge Schema Registry · Amazon MQ for RabbitMQ *(already covered by the engine-agnostic `amazonmq` scanner)* · Amazon SWF · Amazon Pinpoint · Amazon Connect Cases |
| **Media** | AWS Elemental MediaLive · AWS Elemental MediaConvert · AWS Elemental MediaStore (retired Nov 2025) · AWS Elemental MediaTailor |
| **Dev tools / management** | AWS CodeDeploy · AWS Cloud9 |

---

## 5. "Covered but shallow" — internal blind spots inside scanned services

These services are enumerated + classified, but specific SUB-features may not be
fully read. Honest partial-coverage caveats (deepening candidates):

| Service | Confirmed | Possible blind spot |
|---|---|---|
| **FSx** | enumerated (unit-only; not live) | 4 flavors (Windows SMB/Kerberos · Lustre · ONTAP NFS-over-TLS · OpenZFS) use different in-transit mechanisms; one scanner may not classify all. **Could not be live-fixtured** (2026-06-17/18): FSx-OpenZFS failed to reach AVAILABLE on create twice in ap-south-1 and a FAILED filesystem blocks DeleteStack; the unconditional AES-256-XTS posture is unit-covered. See §7. |
| **RDS / Aurora** | at-rest storage | `force_ssl` / `require_secure_transport` param-group check + rds-ca rotation state may not be read |
| **MSK** | at-rest + client-broker | in-cluster encryption + mTLS-via-ACM-PCA are distinct sub-features to confirm |
| **Lambda** | env-var encryption | ephemeral-storage (`/tmp`) KMS is a separate field |
| **DocumentDB** | instance/cluster + elastic | confirm elastic-cluster enumeration parity (documentdb_elastic scanner added; live-verified 2026-06-11). documentdb / documentdb_transit re-confirmed in the 2026-06-17/18 cluster batch (§7). |

**Rule:** "covered" = enumeration + classification, NOT a guarantee of full
PQC-readiness detail. Absence of a per-asset field (KEX/hybrid/cert) is an honest
blank per the protocol-detail rubric, not a silent failure.

---

## 6. Maintenance contract

- When a scanner is **added**: move its service out of §4, add it to §2, bump the
  headline counts here AND in `dashboard/src/lib/coverageData.ts` (they must agree),
  and update `knownGaps` in that file.
- When a **shallow** caveat (§5) is deepened: note it as confirmed.
- Re-derive the AWS total via the SSM global-infrastructure registry; update `asOf`.
- Do **not** introduce a "100% comprehensive" claim anywhere — see §1.
- **2026-06-15 audit:** evaluated 112 additional crypto-touching services → 13
  promoted to v1 (§2), 59 deferred + 10 cannot-scan-honestly + 30 out-of-scope
  (§4). The README's "What CryptaMap does NOT scan (the absolute list)" section and
  the dashboard's `coverageData.ts` `knownGaps` **must be kept in sync with this
  register** — all three were updated together on 2026-06-15.
- **2026-06-17/18 live-validation pass (internal-only QA):** no coverage counts
  changed; this register gained §7 (the validation register), ✅ live markers in §2,
  two key-custody bug-fix notes (codebuild, backup), and
  unit-only/cannot-fixture reasons for iotcore / fsx / connect_customer_profiles. The
  resource-provisioning harness is internal-only QA tooling (Layer 4 in
  `docs/VALIDATION.md`) and is **not** shipped in this public sample. **Live-validated
  status is not a coverage claim** — a scanner stays "covered" whether or not it has
  been live-proven; the §7 register only records *which* covered scanners have been
  exercised against real AWS resources.

## 7. Live-validation register (2026-06-17/18)

This pass was run **internally only** (it is not part of this public sample — see the
Layer 4 note in `docs/VALIDATION.md`). An internally-run create→scan→verify→teardown
pass exercised each fixture against a real AWS resource of known crypto state, with
guaranteed teardown + an honest orphan sweep. This does **not** add or remove scanners
or change the headline counts in §2; it records which covered scanners are now proven
against live AWS responses vs unit-tested only.

**✅ Live-validated — 27 wave-3 bucket-A scanners** (60/60 oracle rows passed on the
clean confirmation run): alb, apigw_http, apigw_rest, appsync, backup, cloudwatchlogs,
codebuild, container_images, ebs, ecs, efs, eventbridge, keyspaces, kinesis, lambda,
lightsail, rolesanywhere, secrets_rotation, secretsmanager, ses_dkim, sns, sqs, ssm,
stepfunctions, transferfamily, vpn, workspaces_web.

**✅ Live-validated — earlier fast + cluster batches:** s3 (Jan-2023 default-SSE
tripwire), dynamodb (key-tier), bedrock; and the cluster scanners rds/aurora/msk/
opensearch/elasticache/neptune/documentdb with their `_transit` variants.

**✅ Live-validated — BYOK/customer-CMK:** `kms_byok` fixture (see §2 note). The
`EXTERNAL` / `AWS_CLOUDHSM` KMS origins remain unit-only.

**Deliberately NOT live-tested — unit-test-only, with documented reasons:**

| Scanner | Why no live fixture | Posture coverage |
|---|---|---|
| **iotcore** | An IoT domain configuration **cannot be deleted for 7 days** → cannot auto-teardown within the harness. | unit-tested |
| **fsx** | FSx-OpenZFS **failed to create twice** in ap-south-1, and a FAILED filesystem **blocks DeleteStack**. | unit-tested (unconditional AES-256-XTS posture) |
| **connect_customer_profiles** | **No CloudFormation resource type** exists for `AWS::CustomerProfiles`. | unit-tested |
| **bucket-B/C set** (CloudHSM, Directory Service, amazonmq, etc.) | Expensive / orphan-prone for ~zero incremental signal. | unit-tested |

> **Scope note:** "not live-tested" ≠ "not covered." Every scanner above is still in §2
> with unit coverage; the live pass simply could not (or chose not to) create-and-teardown
> a real resource for these without leaving orphaned/billable state.

_Related: the broader product backlog now lives in GitHub Issues._
