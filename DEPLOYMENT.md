# Deployment (reference detail)

This companion doc holds the reference-grade deployment detail for CryptaMap's
**deployed org fan-out** (Path 3 in the [README Quick start](./README.md#quick-start)):
the cross-account role and its IAM, the copy-paste JSON, the values you substitute,
the account topology, and the one-time StackSets delegated-admin setup.

The README Quick start is the fast path; everything here is the "review or apply by
hand / understand the model" detail. Region selection, the non-India data-residency
notice, and result retention live in the README under
[Data residency](./README.md#data-residency) and
[Retention (results auto-expire)](./README.md#retention-results-auto-expire).

For the make targets see the [Make targets](./README.md#make-targets) section, and
[ARCHITECTURE](./ARCHITECTURE.md) for the full topology.

---

## The deploy command (correct form)

`make deploy` runs `npx cdk deploy --all --require-approval never` with the
`cdk.json` defaults — and the default is `orgScanningEnabled: false`. That deploys
**only** the single-account scheduled-scan stacks; the `CryptaMap-OrgFanout` stack
is not synthesized. To stand up the org fan-out you must invoke the CDK directly and
turn org scanning on:

```bash
cd cdk && npx cdk deploy CryptaMap-OrgFanout --exclusively \
  -c orgScanningEnabled=true \
  -c organizationId=<ORG_ID> \
  -c orgRootId=<ROOT_ID> \
  -c scannerExternalId=<EXTERNAL_ID>
```

When `orgScanningEnabled=true`, synth **refuses** to proceed with the placeholder
org id (`o-exampleorgid`), the placeholder root id (`r-exam`), or the default
ExternalId (`cryptamap-scanner`), and prints exactly what to pass. **These refusals
only fire when `orgScanningEnabled=true`** — under the default single-account path
nothing is refused because no org scanning happens.

Optional context flags: `-c fanoutRegions=us-east-1,ap-south-1` (default; use
`-c fanoutRegions=all` for every enabled region), `-c stackSetCallAs=SELF` (deploy
from the management account instead of a delegated-admin Audit account — see
[topology](#where-to-deploy-account-topology)), `-c retentionScans=<n>` (default 30).

## Cross-account role prerequisite

**Any** cross-account scan must assume a **read-only role that already exists in each
target account**. CryptaMap is read-only — it cannot create that role for you. The
StackSet in the org deploy creates it org-wide; the role is:

- **Name:** `CryptaMapScannerRole`
- **Permissions:** a **custom least-privilege** inline READ policy
  (`CryptaMapScannerReadActions`) — exactly the `Describe*`/`List*`/`Get*` actions the
  scanners call, **NOT** the broad AWS-managed `ReadOnlyAccess`. The action list is
  the single source of truth in
  [`cdk/policy/scanner-actions.json`](./cdk/policy/scanner-actions.json) (generated
  from `cmd/gen-policy`; CI `make check-policy` fails on drift). **No write access.**
- **Trust:** only the `CryptaMapOrchestratorRole` may assume it, double-gated by
  `aws:PrincipalOrgID` (must be your org) **and** `sts:ExternalId` (default
  `cryptamap-scanner`) — a confused-deputy guard.

Source of truth:
[`cdk/templates/scanner-role-template.json`](./cdk/templates/scanner-role-template.json)
(role + trust) and
[`cdk/policy/scanner-actions.json`](./cdk/policy/scanner-actions.json) (the exact
action list).

If the role is missing in an account, that account is reported **UNCOVERED** — never
silently "clean".

### Does the role already exist? Two cases

| How the account joined the org | Default cross-account role | What you must do |
| --- | --- | --- |
| **Created _from_ the management account** (via AWS Organizations) | `OrganizationAccountAccessRole` exists automatically — **but it is full `AdministratorAccess` and lacks the ExternalId/Org guards, so do NOT use it for scanning.** | Still create the read-only `CryptaMapScannerRole` (StackSet covers it automatically). |
| **Invited** into the org | **None.** AWS does **not** create any cross-account role for invited accounts. | You **must** create `CryptaMapScannerRole` in that account before it can be scanned. |

### Create the role — option 1: StackSet (recommended, covers the whole org)

The org deploy provisions a SERVICE_MANAGED CloudFormation StackSet that auto-creates
`CryptaMapScannerRole` in **every** member account (including future ones via
AutoDeployment). This is the only option that scales to invited + created accounts
uniformly. See [Where to deploy (account topology)](#where-to-deploy-account-topology)
for where the orchestration stacks live and the one-time delegated-admin setup.

### Create the role — option 2: manually in one account (e.g. a single invited account)

Deploy the template directly into the target account (substitute your orchestrator
role ARN, org id, and a chosen ExternalId):

```bash
aws cloudformation deploy \
  --stack-name CryptaMapScannerRole \
  --template-file cdk/templates/scanner-role-template.json \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      OrchestratorRoleArn="arn:aws:iam::<ORCHESTRATOR_ACCT>:role/CryptaMapOrchestratorRole" \
      OrganizationId="o-yourorgid" \
      ExternalId="cryptamap-scanner"
```

This creates exactly the read-only, org-+ExternalId-gated role described above, in
that one account. Repeat per account, or use the StackSet to do it org-wide at once.

## Copy-paste IAM setup

Everything below is generated/templated by the CDK (the org deploy wires it for you).
It is reproduced here so you can review or apply it by hand. **Values must be
substituted** — see [Replace these values](#replace-these-values).

### 1) Member-account scanner role — TRUST policy

This is the `AssumeRolePolicyDocument` on `CryptaMapScannerRole` in each member
account. Only the orchestrator role may assume it, and only when the caller is inside
**your** org (`aws:PrincipalOrgID`) **and** presents the agreed `sts:ExternalId` — a
double-gated confused-deputy guard.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOrchestratorAssumeFromOrg",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ORCHESTRATOR_ACCOUNT_ID>:role/CryptaMapOrchestratorRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "<ORG_ID>",
          "sts:ExternalId": "<EXTERNAL_ID>"
        }
      }
    }
  ]
}
```

### 2) Member-account scanner role — READ-ONLY permissions

The member role carries the **custom least-privilege** inline policy
`CryptaMapScannerReadActions` — **NOT** the AWS-managed `ReadOnlyAccess`. It is
exactly the `Describe*`/`List*`/`Get*` actions the scanners call. **The authoritative
action list is [`cdk/policy/scanner-actions.json`](./cdk/policy/scanner-actions.json)**
(its `readActions` array), generated from `cmd/gen-policy`; CI `make check-policy`
fails on drift. Do not hand-maintain a copy — paste the array from that file into the
`Action` list below. All actions are account-wide read verbs, so `Resource` is `*`.
**No write actions are present.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CryptaMapScannerReads",
      "Effect": "Allow",
      "Action": [ /* the readActions array from cdk/policy/scanner-actions.json */ ],
      "Resource": "*"
    }
  ]
}
```

> The member scanner role gets **reads only**. It never receives any write — the
> three resource-scoped writes below live exclusively on the orchestrator role.

### 3) Orchestrator-role permissions (Audit account only)

The `CryptaMapOrchestratorRole` lives in the Audit/orchestrator account and is the
execution role for the seed/scanner/merge Lambdas + the Step Functions state machine.
It has:

- the **same** custom least-privilege READ list as the member role (it scans the
  Audit/management account's own resources too), plus
- `sts:AssumeRole` scoped to `arn:aws:iam::*:role/CryptaMapScannerRole` (assume the
  member roles), plus
- `organizations:ListAccounts` (enumerate the org), plus
- **exactly three** resource-scoped WRITES (the `orchestratorWrites` block in
  [`cdk/policy/scanner-actions.json`](./cdk/policy/scanner-actions.json)) — and
  nothing else writes anywhere:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeMemberScannerRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/CryptaMapScannerRole"
    },
    {
      "Sid": "ListOrgAccounts",
      "Effect": "Allow",
      "Action": "organizations:ListAccounts",
      "Resource": "*"
    },
    {
      "Sid": "WriteScanResultsToBucket",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::<RESULTS_BUCKET>/*"
    },
    {
      "Sid": "RecordScanInTable",
      "Effect": "Allow",
      "Action": "dynamodb:PutItem",
      "Resource": "arn:aws:dynamodb:<REGION>:<ORCHESTRATOR_ACCOUNT_ID>:table/<SCANS_TABLE>"
    },
    {
      "Sid": "ImportFindingsToSecurityHub",
      "Effect": "Allow",
      "Action": "securityhub:BatchImportFindings",
      "Resource": "arn:aws:securityhub:<REGION>:<ORCHESTRATOR_ACCOUNT_ID>:product/<ORCHESTRATOR_ACCOUNT_ID>/default"
    }
  ]
}
```

The READ statement (`CryptaMapScannerReads`, same as block 2) is attached to the
orchestrator role as well; it is omitted here only to avoid repeating the long action
list.

### Replace these values

| Placeholder | What it is | CDK context flag | Example |
| --- | --- | --- | --- |
| `<ORCHESTRATOR_ACCOUNT_ID>` | The 12-digit Audit/orchestrator account id where `CryptaMapOrchestratorRole` lives | (derived from `CDK_DEFAULT_ACCOUNT`) | `111122223333` |
| `<ORG_ID>` | Your AWS Organizations id (gates the trust via `aws:PrincipalOrgID`) | `-c organizationId=` | `o-ab12cd34ef` |
| `<ROOT_ID>` | Your organization **root** id — required by the org-deploy guard alongside `<ORG_ID>` | `-c orgRootId=` | `r-ab12` |
| `<EXTERNAL_ID>` | A private shared secret the orchestrator passes on assume-role | `-c scannerExternalId=` | `acme-cryptamap-7f3a9` |

> **Why four, not three?** The IAM JSON blocks above substitute three values
> (`<ORCHESTRATOR_ACCOUNT_ID>`, `<ORG_ID>`, `<EXTERNAL_ID>`). The **org deploy
> command** needs a fourth, `<ROOT_ID>` (`-c orgRootId=`): when
> `orgScanningEnabled=true`, synth refuses to deploy if **either** `organizationId`
> is still `o-exampleorgid` **or** `orgRootId` is still `r-exam`. The repo defaults
> (`o-exampleorgid`, `r-exam`, ExternalId `cryptamap-scanner`) are **demo
> placeholders**; you must pass your own for the org path. `<RESULTS_BUCKET>`,
> `<SCANS_TABLE>`, and `<REGION>` in the orchestrator block are filled in
> automatically by the CDK from the Data stack at synth time.

## Where to deploy (account topology)

**Default and recommended: a dedicated Audit / Security-Tooling account.** The
orchestration stacks (`CryptaMap-Data`, `CryptaMap-Security`, `CryptaMap-Scanner`,
`CryptaMap-Alerting`, `CryptaMap-OrgFanout`) deploy into one account that holds the
`CryptaMapOrchestratorRole`, the evidence store (KMS CMK + results bucket + scans
table), and the Step Functions fan-out. That account assumes the read-only
`CryptaMapScannerRole` in every member account to do the scanning. Keeping this out
of the management/payer account follows AWS least-standing-access guidance.

### One-time setup: register the Audit account as a StackSets delegated administrator

Because the scanner-role StackSet is **SERVICE_MANAGED**, deploying it org-wide from
the Audit account (rather than the management account) requires one one-time step,
**run once by a management-account administrator**:

```bash
aws organizations register-delegated-administrator \
  --service-principal member.org.stacksets.cloudformation.amazonaws.com \
  --account-id <AUDIT_ACCOUNT_ID>
```

In plain words:

- **What it does:** tells AWS Organizations "this Audit account is allowed to create
  and manage service-managed CloudFormation StackSets for the whole org." After this,
  the org deploy run *from the Audit account* can roll `CryptaMapScannerRole` out to
  every member account.
- **Account-level and persistent:** you register the **account**, not a person or a
  role — so once registered, **any** StackSet administrator in that Audit account can
  deploy org-wide, and the registration stays in effect until you remove it (it is
  not per-deployment and does not expire).
- **Reversible:** undo it any time with
  `aws organizations deregister-delegated-administrator --service-principal member.org.stacksets.cloudformation.amazonaws.com --account-id <AUDIT_ACCOUNT_ID>`;
  you can re-register later.
- **Limit:** an org may have **at most 5** StackSets delegated administrators at once.
- **Prerequisite:** trusted access for StackSets with AWS Organizations must be
  activated first (the AWS console enables this when you first use service-managed
  StackSets; CLI users activate it explicitly). The CDK uses `CallAs:
  DELEGATED_ADMIN` by default to match this model.

> Verify it took effect:
> `aws organizations list-delegated-administrators --service-principal member.org.stacksets.cloudformation.amazonaws.com`

### Fallback: deploy from the management account

If you do not want a delegated admin (or are evaluating in a single management
account), deploy the stacks directly from the **management/payer account** and pass
`-c stackSetCallAs=SELF`. This skips the `register-delegated-administrator` step
entirely (the management account is always allowed to manage service-managed
StackSets). It works, but it puts CryptaMap's standing access in the payer account —
the dedicated Audit account is preferred for production.

## Teardown / uninstall (ordered procedure)

> ⚠️ **`make destroy` is destructive, and it is deliberately *not* enough.** The
> evidence store is **RETAIN-on-destroy by design** (so a stray `cdk destroy`
> cannot wipe in-window CBOM/scan evidence), and the member-account roles live in a
> **StackSet** that must be emptied before it can be removed. A full uninstall is
> multi-step and partly manual. Do them in this order.

**1) Delete the member-account `CryptaMapScannerRole` (org deployments only).**
The role is rolled out by a **SERVICE_MANAGED** StackSet
(`cdk/lib/security-stack.ts`), so the StackSet's stack instances must be deleted from
every target account/OU **before** the StackSet itself can be removed — otherwise the
`CryptaMap-Security` stack delete fails. Delete the instances first:

```bash
# Find the StackSet name (look for the CryptaMapScannerRole StackSet):
aws cloudformation list-stack-sets --status ACTIVE --call-as DELEGATED_ADMIN

# Delete its instances across the target OU(s) and regions, then confirm none remain:
aws cloudformation delete-stack-instances \
  --stack-set-name <SCANNER_ROLE_STACKSET_NAME> \
  --deployment-targets OrganizationalUnitIds=<ROOT_OR_OU_ID> \
  --regions <HOME_REGION> --no-retain-stacks --call-as DELEGATED_ADMIN
aws cloudformation list-stack-instances \
  --stack-set-name <SCANNER_ROLE_STACKSET_NAME> --call-as DELEGATED_ADMIN
```

(Use `--call-as SELF` instead of `DELEGATED_ADMIN` if you deployed from the
management account with `-c stackSetCallAs=SELF`.)

**2) Destroy the in-account stacks.**

```bash
make destroy        # cdk destroy --all --force  (DESTRUCTIVE)
```

This removes the orchestration stacks and the Audit-account roles
(`CryptaMapOrchestratorRole` and the local `CryptaMapScannerRole`), the scanner
Lambda, the scheduled-scan rule, the seed/merge Lambda log groups, and the
`CryptaMap-Security` stack (which removes the now-empty StackSet from step 1).

**3) Manually clean the RETAINed evidence store.** `cdk destroy` intentionally
leaves these behind (`cdk/lib/data-stack.ts`, `cdk/lib/org-fanout-stack.ts`); delete
them by hand only when you are decommissioning and want the evidence gone:

- the **results S3 bucket** — it is **versioned**, so every object *version* (and any
  delete markers) must be purged before the bucket can be deleted;
- the **results access-logs S3 bucket**;
- the **DynamoDB scans table**;
- the **KMS CMK** (schedule key deletion; it cannot be deleted instantly);
- the **state-machine CloudWatch log group**.

There is no Make target for this step — it is manual on purpose, so that tearing down
the infrastructure never silently destroys collected evidence.

**4) Deregister the StackSets delegated administrator (DELEGATED_ADMIN mode only).**
If you registered the Audit account as a delegated admin during setup, reverse it
from a management-account admin:

```bash
aws organizations deregister-delegated-administrator \
  --service-principal member.org.stacksets.cloudformation.amazonaws.com \
  --account-id <AUDIT_ACCOUNT_ID>
```

In `SELF` mode (deployed from the management account) there is no delegated admin to
deregister, so skip this step.

> `make clean` only removes **local** build artifacts (`dist/`, `cdk/cdk.out`,
> `dashboard/dist`). It touches no cloud resources.

## AWS GovCloud (US) and China partition support

CryptaMap **runs in the GovCloud (US) and China partitions**, with a small number of
documented caveats. It never hard-blocks a non-India region — it emits a loud
stderr **notice** at synth time and proceeds (`cdk/bin/app.ts`).

**What is partition-aware (works correctly):**

- **Security Hub ASFF output.** Both the finding `ProductArn` and each
  `Resources[].Partition` are derived from the finding's own region
  (`us-gov-*` → `aws-us-gov`, `cn-*` → `aws-cn`, else `aws`), so findings import in
  the correct partition (`internal/output/securityhub.go`). The ASFF `ProductArn`
  validator accepts all three partitions.
- **The org fan-out cross-account assume path.** The seed Lambda builds member-role
  ARNs from the CloudFormation `AWS::Partition` pseudo-parameter and the scan Lambda
  assumes the event-supplied `roleArn`, so assumed-role ARNs resolve to the correct
  partition (`cdk/lib/org-fanout-stack.ts`, `cdk/lib/security-stack.ts`).
- **Air-gapped / egress-blocked operation.** A first-class supported environment: the
  baked-in PQC knowledge baseline is mandatory and the optional network refresh is
  never a precondition (`docs/SELF-UPDATING-KNOWLEDGE.md`). Scans are fully functional
  offline.

**Known cosmetic caveat:** the CBOM component `bom-ref` resource ARNs carry an
`arn:aws:` prefix even in GovCloud/China (`internal/services/common.go`,
`internal/services/datarest/s3.go`). This value is an internal **dedup key**, not an
ARN submitted to any AWS API, so it does not affect imports, scanning, or
correctness — it is a display/identity detail only. The ASFF ARNs that *are* sent to
AWS are partition-correct (above).

> Enabling StackSets trusted access and Security Hub in GovCloud/China is subject to
> each partition's own service availability; confirm those services are available in
> your target regions before deploying.
