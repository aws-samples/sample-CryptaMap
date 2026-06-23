#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { ScannerStack } from '../lib/scanner-stack';
import { DataStack } from '../lib/data-stack';
import { SecurityStack } from '../lib/security-stack';
import { AlertingStack } from '../lib/alerting-stack';
import { OrgFanoutStack } from '../lib/org-fanout-stack';

const app = new cdk.App();

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const prefix = (app.node.tryGetContext('stackPrefix') as string) ?? 'CryptaMap';
const orgScanning = (app.node.tryGetContext('orgScanningEnabled') as boolean) ?? false;
const alertEmail = (app.node.tryGetContext('alertEmail') as string) ?? '';
// Cost guardrail: a monthly AWS Budget (region-agnostic) so a runaway / misconfigured
// scan can't silently run up cost. Notifies the same alert email at the configured
// thresholds. Override with `-c monthlyBudgetUSD=<amount>`; 0 disables the budget.
const monthlyBudgetUSD = (app.node.tryGetContext('monthlyBudgetUSD') as number) ?? 100;

// LOCAL-FIRST BY DESIGN: the CryptaMap dashboard + query API would serve the
// org's full crypto-weakness map — a harvest-now-decrypt-later target list — so
// a default deployment ships NO internet-facing web surface at all. The
// supported way to view the map is LOCAL/ARTIFACT-FIRST: run the CLI, then
// `cryptamap serve` to open the signed report on localhost. No public-CloudFront
// dashboard is built by default, so a default deploy has no public dashboard + API
// surface to expose.
const scanSchedule = (app.node.tryGetContext('scanSchedule') as string) ?? 'cron(0 6 ? * SUN *)';
const retentionScans = (app.node.tryGetContext('retentionScans') as number) ?? 30;
// Org fan-out tunables (all default-safe; org stacks only build when orgScanning=true).
const orgRootId = (app.node.tryGetContext('orgRootId') as string) ?? 'r-exam';
const organizationId = (app.node.tryGetContext('organizationId') as string) ?? 'o-exampleorgid';
const scannerExternalId = (app.node.tryGetContext('scannerExternalId') as string) ?? 'cryptamap-scanner';
// How CloudFormation creates the SERVICE_MANAGED scanner-role StackSet. Defaults to
// DELEGATED_ADMIN (the Audit-account model: deploy from the Audit account, which the
// operator must register as a StackSets delegated admin in the management account).
// Override with `-c stackSetCallAs=SELF` to deploy directly from the management
// account. Allowed values mirror CloudFormation's CallAs (SELF | DELEGATED_ADMIN).
const stackSetCallAsCtx = (app.node.tryGetContext('stackSetCallAs') as string) ?? 'DELEGATED_ADMIN';
if (stackSetCallAsCtx !== 'DELEGATED_ADMIN' && stackSetCallAsCtx !== 'SELF') {
  throw new Error(
    `Invalid stackSetCallAs '${stackSetCallAsCtx}' — must be 'DELEGATED_ADMIN' (default) or 'SELF'`,
  );
}
const stackSetCallAs: 'DELEGATED_ADMIN' | 'SELF' = stackSetCallAsCtx;
// Refuse to deploy ORG scanning with the public default ExternalId. The literal
// 'cryptamap-scanner' ships in cdk.json/the StackSet template as a demo value;
// using it for a real org install would weaken the confused-deputy guard on the
// orchestrator -> scanner-role trust (aws:PrincipalOrgID + sts:ExternalId). The
// default stays usable for non-org (single-account demo) synth. (Pairs with the
// placeholder org-id guard below; this owns only the ExternalId check.)
if (orgScanning && (!scannerExternalId || scannerExternalId === 'cryptamap-scanner')) {
  throw new Error(
    'Refusing to deploy org scanning with the public default ExternalId — ' +
      'set -c scannerExternalId=<your-private-value>',
  );
}
// Default to the primary Indian BFSI region (ap-south-1, Mumbai) PLUS us-east-1
// (retained for global / global-endpoint services such as IAM and CloudFront that
// surface there). Operators can still override with `-c fanoutRegions=...`
// (e.g. add ap-south-2 / Hyderabad: `-c fanoutRegions=us-east-1,ap-south-1,ap-south-2`).
//
// OPT-IN "all" mode: `-c fanoutRegions=all` fans out over EVERY region each
// member account has ENABLED (the seed Lambda's all-enabled branch), instead of
// intersecting the discovered-enabled set with a static opt-in list. The literal
// "all" token is passed through as-is (it survives the split/filter as ["all"]
// and joins back to FANOUT_REGIONS="all" in the seed Lambda env, which triggers
// the all-enabled branch). The cdk.json default stays the explicit two-region
// list so the default deploy is unchanged.
const fanoutRegionsCtx = (app.node.tryGetContext('fanoutRegions') as string) ?? 'us-east-1,ap-south-1';
const fanoutRegions = fanoutRegionsCtx.split(',').map((r) => r.trim()).filter(Boolean);

// DATA-RESIDENCY SOFT NUDGE (v1 targets Indian regulators / India-BFSI). We do
// NOT hard-block any region — operators may have legitimate reasons to deploy
// elsewhere. But because the evidence store (DataStack: KMS + results bucket +
// scans table) and the per-region fan-out land data in their respective
// regions, we emit a LOUD synth-time notice on stderr whenever the resolved
// DataStack region — or any fan-out region — falls outside India. The "all"
// token (opt-in all-enabled mode) is not a literal region, so it is excluded
// from the check. Notice only; never throws.
const INDIA_REGIONS = new Set(['ap-south-1', 'ap-south-2']);
const dataStackRegion = env.region; // === CDK_DEFAULT_REGION (may be undefined)
const regionsToCheck = [
  ...(dataStackRegion ? [dataStackRegion] : []),
  ...fanoutRegions.filter((r) => r !== 'all'),
];
for (const region of regionsToCheck) {
  if (!INDIA_REGIONS.has(region)) {
    console.warn(
      `NOTE: deploying CryptaMap outside India (region=${region}) — confirm this ` +
        'meets your data-residency obligations (v1 targets Indian regulators).',
    );
  }
}
// DataStack is the evidence store only (KMS + results bucket + scans table); it
// exposes no query API (local-first model — results are viewed via `cryptamap
// serve` or pulled from the bucket with operator creds). The former public query
// API + its dashboardOrigin CORS knob were removed with the CloudFront dashboard.
const data = new DataStack(app, `${prefix}-Data`, { env, retentionScans });

const security = new SecurityStack(app, `${prefix}-Security`, {
  env,
  resultsBucket: data.resultsBucket,
  scansTable: data.scansTable,
  orgScanning,
  orgRootId,
  organizationId,
  scannerExternalId,
  stackSetCallAs,
});
security.addDependency(data);

const scanner = new ScannerStack(app, `${prefix}-Scanner`, {
  env,
  resultsBucket: data.resultsBucket,
  scansTable: data.scansTable,
  scanSchedule,
  scannerRoleName: security.scannerRoleName,
  dataKey: data.dataKey,
  // Surfaced to the Go writer as RETENTION_DAYS so the scans-table TTL window
  // matches the DataStack results-bucket lifecycle (both default to 30 days).
  retentionScans,
  // Org scanning: the Lambda runs AS the orchestrator role so its assume-role
  // principal matches the scanner-role trust policies. undefined otherwise.
  executionRole: security.orchestratorRole,
});
scanner.addDependency(data);
scanner.addDependency(security);

// No web/dashboard stack is synthesized: CryptaMap ships NO internet-facing
// surface. The crypto map is viewed locally via `cryptamap serve` (signed,
// artifact-first) or a private self-hosted viewer pointed at the query API.

// Org fan-out orchestration (Step Functions Distributed Map). Only built when
// org scanning is enabled; otherwise the single-account scheduled scan applies.
// Built BEFORE the AlertingStack so the operational alarms can watch the org
// seed/merge Lambdas + the state machine (refs passed in below).
let fanout: OrgFanoutStack | undefined;
if (orgScanning) {
  // Refuse to deploy org scanning with the placeholder organization identifiers
  // baked into the defaults above (orgRootId 'r-exam', organizationId
  // 'o-exampleorgid'). Synthesizing with these would wire the StackSet role
  // trust + assume-role scoping to a fictional org, so the operator MUST pass
  // their real ids. Non-org synth is unaffected (this block only runs when
  // orgScanning===true).
  if (orgRootId === 'r-exam' || orgRootId === '' ||
      organizationId === 'o-exampleorgid' || organizationId === '') {
    throw new Error(
      'Refusing to deploy org scanning with placeholder organization identifiers ' +
        '— set -c organizationId=<your-org-id> -c orgRootId=<your-root-id>',
    );
  }
  fanout = new OrgFanoutStack(app, `${prefix}-OrgFanout`, {
    env,
    resultsBucket: data.resultsBucket,
    scansTable: data.scansTable,
    dataKey: data.dataKey,
    scannerFn: scanner.scannerFn,
    scannerRoleName: security.scannerRoleName,
    scannerExternalId,
    fanoutRegions,
    // Seed runs AS the orchestrator role so its per-account assume into the
    // member scanner roles is trusted (fixes the all-regions discovery bug,
    // docs/SCALING.md §6).
    orchestratorRole: security.orchestratorRole,
  });
  fanout.addDependency(data);
  fanout.addDependency(security);
  fanout.addDependency(scanner);
}

// AlertingStack: SecurityHub CRITICAL business-finding route + OPERATIONAL
// alarms (scanner/seed/merge metricErrors, state-machine metricFailed /
// metricTimedOut) routed to the SNS topic, plus the cost budget. The org refs
// are passed only when org scanning built them; the scanner Lambda always
// exists. Constructed after OrgFanout so those refs are available.
const alerting = new AlertingStack(app, `${prefix}-Alerting`, {
  env,
  alertEmail,
  monthlyBudgetUSD,
  scannerFn: scanner.scannerFn,
  seedFn: fanout?.seedFn,
  mergeFn: fanout?.mergeFn,
  stateMachine: fanout?.stateMachine,
});
alerting.addDependency(scanner);
if (fanout) {
  alerting.addDependency(fanout);
}

cdk.Tags.of(app).add('Project', 'CryptaMap');
cdk.Tags.of(app).add('Owner', 'security');
cdk.Tags.of(app).add('CostCenter', 'compliance');

app.synth();
