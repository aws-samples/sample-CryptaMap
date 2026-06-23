import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ddb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';

export interface OrgFanoutStackProps extends cdk.StackProps {
  readonly resultsBucket: s3.IBucket;
  readonly scansTable: ddb.ITable;
  readonly dataKey: kms.IKey;
  /** The per-(account,region) scanner Lambda from ScannerStack. */
  readonly scannerFn: lambda.IFunction;
  /** Member-account role the worker assumes (e.g. CryptaMapScannerRole). */
  readonly scannerRoleName: string;
  /** ExternalId passed on sts:AssumeRole (must match the StackSet template). */
  readonly scannerExternalId?: string;
  /** Default region list to fan out over when an account does not narrow it. */
  readonly fanoutRegions?: string[];
  /**
   * The orchestrator role (from SecurityStack) — the SAME role the scanner Lambda
   * runs as. The seed Lambda MUST run as this role so its per-account
   * sts:AssumeRole into CryptaMapScannerRole succeeds: the member scanner roles
   * trust ONLY the orchestrator principal (confused-deputy guard), so the seed's
   * own default service role would be denied (and silently fall back to one
   * region — the all-regions bug, see docs/SCALING.md §6). Required for `all`-mode
   * region discovery; when absent the seed cannot enumerate regions.
   */
  readonly orchestratorRole?: iam.IRole;
}

/**
 * OrgFanoutStack wires the Step Functions Standard state machine that fans the
 * CryptaMap scan out across the whole organization.
 *
 * Topology:
 *   1. SeedTuples (Lambda): organizations:ListAccounts -> active accounts, then
 *      cross-product with the region list => [{accountId, region, roleArn,
 *      externalId}, ...].
 *   2. ScanFanout (Distributed Map, Standard): one child execution per tuple.
 *      Each child runs InvokeScanner -> the Go scanner Lambda assumes
 *      arn:aws:iam::<accountId>:role/CryptaMapScannerRole (ExternalId guard),
 *      scans that single (account,region), and writes a per-(account,region)
 *      S3 partial (key already encodes account+region+scanId) using the
 *      worker's OWN/central creds. ResultWriter persists the Map manifest +
 *      child results to the central results bucket under scans/_runs/.
 *   3. MergeResults (Lambda): reads the Map result manifest, rolls the partials
 *      into a single run summary, and writes scans/latest/<runId>.json
 *      (runId already carries the "run-" prefix).
 *
 * ====================================================================
 * EVENT CONTRACT (CDK -> Go scanner Lambda) + REQUIRED FOLLOW-UP
 * ====================================================================
 * The Distributed Map invokes the scanner Lambda (cmd/cryptamap/lambda.go)
 * once per (account,region) tuple with this JSON event:
 *
 *   {
 *     "mode":       "lambda",                                  // CRYPTAMAP_MODE
 *     "accountId":  "<member account id>",                     // target account
 *     "region":     "<target region>",                         // single region
 *     "roleArn":    "arn:<partition>:iam::<acct>:role/CryptaMapScannerRole",
 *     "externalId": "<scannerExternalId>"                       // confused-deputy guard
 *   }
 *
 * Go handler (IMPLEMENTED — verified end-to-end against the live org): the
 * scanner Lambda (cmd/cryptamap/lambda.go) reads `roleArn`/`externalId`/
 * `roleSessionName` from LambdaEvent, calls internal/org.AssumeRole to obtain
 * assumed-role creds for the target member account (with an eager STS caller-
 * identity check as a confused-deputy guard), sets the assumed config's Region
 * to `region`, runs the engine against the member account, and writes the
 * per-(account,region,scanId) S3 partial + DynamoDB row using the BASE/central
 * config so partials land in the central RESULTS_BUCKET. The hierarchical
 * streaming merge (below) folds the partials into the org CBOM. (An earlier
 * version of this comment claimed the assume-role path was unimplemented — that
 * is STALE; it has been implemented and proven. See internal/org/assumerole.go.)
 */
export class OrgFanoutStack extends cdk.Stack {
  public readonly stateMachine: sfn.StateMachine;
  /** Seed Lambda (org-account enumeration / tuple build) — exposed so the
   *  AlertingStack can attach an operational metricErrors alarm. */
  public readonly seedFn: lambda.Function;
  /** Merge Lambda (Map-result rollup) — exposed for the operational alarm. */
  public readonly mergeFn: lambda.Function;

  constructor(scope: Construct, id: string, props: OrgFanoutStackProps) {
    super(scope, id, props);

    const externalId = props.scannerExternalId ?? 'cryptamap-scanner';
    const fanoutRegions = props.fanoutRegions ?? ['us-east-1'];

    // ------------------------------------------------------------------
    // Seed Lambda: enumerate org accounts and build (account,region) tuples.
    // ------------------------------------------------------------------
    const seedFn = this.seedFn = new lambda.Function(this, 'SeedTuplesFn', {
      runtime: lambda.Runtime.NODEJS_22_X,
      memorySize: 512,
      // Run AS the orchestrator role (same as the scanner Lambda) so the seed's
      // per-account sts:AssumeRole into CryptaMapScannerRole is accepted by the
      // member roles' trust policy (which trusts ONLY the orchestrator). Without
      // this the assume is denied and region discovery silently collapses to a
      // single region (docs/SCALING.md §6). The orchestrator role already carries
      // AWSLambdaBasicExecutionRole (Logs) + ReadOnlyAccess (DescribeRegions) +
      // sts:AssumeRole on the scanner roles, so no extra grants are needed.
      ...(props.orchestratorRole ? { role: props.orchestratorRole } : {}),
      // Raised from 2m: per-account region-enablement adds an assume-role +
      // DescribeRegions per account (bounded-concurrent), which at hundreds of
      // accounts needs more headroom.
      timeout: cdk.Duration.minutes(5),
      handler: 'index.handler',
      logGroup: new logs.LogGroup(this, 'SeedTuplesFnLogs', {
        retention: logs.RetentionDays.SIX_MONTHS,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
      environment: {
        SCANNER_ROLE_NAME: props.scannerRoleName,
        SCANNER_EXTERNAL_ID: externalId,
        FANOUT_REGIONS: fanoutRegions.join(','),
        PARTITION: cdk.Aws.PARTITION,
        RESULTS_BUCKET: props.resultsBucket.bucketName,
      },
      code: lambda.Code.fromInline(`
const { OrganizationsClient, paginateListAccounts } = require('@aws-sdk/client-organizations');
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');
const { EC2Client, DescribeRegionsCommand } = require('@aws-sdk/client-ec2');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const org = new OrganizationsClient({});
const sts = new STSClient({});
const s3 = new S3Client({});
const PARTITION = process.env.PARTITION || 'aws';
const ROLE = process.env.SCANNER_ROLE_NAME;
const EXTERNAL_ID = process.env.SCANNER_EXTERNAL_ID;
const BUCKET = process.env.RESULTS_BUCKET;
const RAW_REGIONS = (process.env.FANOUT_REGIONS || 'us-east-1').split(',').map(r => r.trim()).filter(Boolean);
// "all" mode (opt-in via -c fanoutRegions=all): fan out over EVERY region each
// member account has enabled, instead of intersecting with a static opt-in list.
// Triggered when the configured list is the literal "all" (or contains it).
const ALL_REGIONS = RAW_REGIONS.some(r => r.toLowerCase() === 'all');
// When NOT in "all" mode, REGIONS is the explicit opt-in list we intersect each
// account's enabled set against. In "all" mode the "all" token is not a real
// region, so strip it; the remaining (if any) explicit regions become the
// FALLBACK list used only when DescribeRegions fails for an account.
const REGIONS = ALL_REGIONS ? RAW_REGIONS.filter(r => r.toLowerCase() !== 'all') : RAW_REGIONS;
// Fallback used on DescribeRegions failure. In "all" mode we have no static
// list to honor, so fall back to a single safe region (us-east-1) rather than
// dropping the account entirely — a transient error must never silently vanish
// an account's regions (data-completeness principle), and the completion barrier
// will still surface the gap relative to a true all-region scan.
const FALLBACK_REGIONS = REGIONS.length > 0 ? REGIONS : ['us-east-1'];

const { randomUUID } = require('crypto');

// enabledRegionsFor returns the regions the given member account has ENABLED,
// by assuming its scanner role and calling ec2 DescribeRegions (account-scoped
// to the assumed creds). In the default (explicit-list) mode it returns the
// SUBSET of the static REGIONS the account has enabled, so opt-in regions a
// member has not enabled are skipped (no dead shards). In "all" mode it returns
// the FULL enabled set for the account (every region the member has opted into),
// not intersected with any static list. On ANY failure it returns null so the
// caller falls back to FALLBACK_REGIONS — a transient/permission error must
// NEVER silently drop an account's regions (honest per the data-completeness
// principle).
async function enabledRegionsFor(accountId, roleArn) {
  try {
    const creds = await sts.send(new AssumeRoleCommand({
      RoleArn: roleArn, RoleSessionName: 'cryptamap-seed', ExternalId: EXTERNAL_ID, DurationSeconds: 900,
    }));
    const c = creds.Credentials;
    const ec2 = new EC2Client({ credentials: { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken } });
    const out = await ec2.send(new DescribeRegionsCommand({})); // AllRegions defaults false => enabled only
    const enabled = (out.Regions || [])
      .filter(r => r.OptInStatus !== 'not-opted-in')
      .map(r => r.RegionName);
    if (ALL_REGIONS) {
      // Full enabled set for this account — NOT intersected with a static list.
      // Still filtered to ENABLED regions, so there are no dead shards.
      return enabled;
    }
    const enabledSet = new Set(enabled);
    return REGIONS.filter(r => enabledSet.has(r));
  } catch (e) {
    console.error('enabledRegionsFor ' + accountId + ' failed, using fallback REGIONS:', e.message);
    return null; // signal fallback
  }
}

exports.handler = async () => {
  // One runId per org-scan execution. Every scan tuple carries it so each
  // member upload lands under scans/raw/<runId>/, and the terminal merge step
  // scopes its aggregation to exactly this run.
  const runId = 'run-' + randomUUID();
  const tuples = [];
  const accounts = []; // distinct active account ids, for the per-account merge tier
  const activeAccounts = [];
  for await (const page of paginateListAccounts({ client: org }, {})) {
    for (const a of (page.Accounts || [])) {
      if (a.Status === 'ACTIVE') activeAccounts.push(a.Id);
    }
  }
  // Per-account region enablement, bounded concurrency to avoid STS throttling.
  const POOL = 10;
  const enabledByAccount = {};
  const regionDiscoveryFailed = []; // accounts whose DescribeRegions assume failed
  for (let i = 0; i < activeAccounts.length; i += POOL) {
    const batch = activeAccounts.slice(i, i + POOL);
    await Promise.all(batch.map(async (id) => {
      const roleArn = \`arn:\${PARTITION}:iam::\${id}:role/\${ROLE}\`;
      const enabled = await enabledRegionsFor(id, roleArn);
      if (enabled === null) {
        // LOUD, not silent (docs/SCALING.md §6 Bug B): in "all" mode a discovery
        // failure means we do NOT know which regions this account has — falling
        // back to one region would report a clean subset for an account we never
        // actually enumerated (false coverage). Record it so the run + coverage
        // surface it as a discovery failure, and still scan FALLBACK_REGIONS so the
        // account is not dropped entirely.
        regionDiscoveryFailed.push(id);
        console.error('REGION-DISCOVERY-FAILED account=' + id + ' mode=' + (ALL_REGIONS ? 'all' : 'list') + ' -> scanning FALLBACK_REGIONS only (' + FALLBACK_REGIONS.join(',') + '); coverage for this account is INCOMPLETE');
        enabledByAccount[id] = FALLBACK_REGIONS;
      } else {
        enabledByAccount[id] = enabled;
      }
    }));
  }
  if (regionDiscoveryFailed.length > 0) {
    console.error('REGION-DISCOVERY SUMMARY: ' + regionDiscoveryFailed.length + ' of ' + activeAccounts.length + ' accounts could not enumerate regions (assume/DescribeRegions failed): ' + regionDiscoveryFailed.join(', ') + '. These were scanned over FALLBACK_REGIONS only — their region coverage is NOT guaranteed complete.');
  }
  for (const id of activeAccounts) {
    accounts.push({ mode: 'lambda', runId, mergeAccount: true, accountId: id });
    for (const region of enabledByAccount[id]) {
      tuples.push({
        mode: 'lambda', runId, accountId: id, region,
        roleArn: \`arn:\${PARTITION}:iam::\${id}:role/\${ROLE}\`,
        externalId: EXTERNAL_ID,
      });
    }
  }

  // Write the item arrays to S3 and reference them via an S3 ItemReader, instead
  // of returning them inline. The inline itemsPath path is capped at the 256KB
  // SFN state-payload quota (~1,219 tuples => DataLimitExceeded before any scan);
  // S3 ItemReader removes that ceiling entirely (SCALING.md §4.2).
  const tuplesKey = \`scans/_seed/\${runId}/tuples.json\`;
  const accountsKey = \`scans/_seed/\${runId}/accounts.json\`;
  await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: tuplesKey, Body: JSON.stringify(tuples), ContentType: 'application/json' }));
  await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: accountsKey, Body: JSON.stringify(accounts), ContentType: 'application/json' }));

  // expectedShards is computed AFTER region filtering, so it equals what we
  // actually fan out — the completion barrier (SCALING.md §4.4) reconciles the
  // merge's observed shard count against this to detect silently-vanished shards.
  return {
    runId, bucket: BUCKET, tuplesKey, accountsKey,
    count: tuples.length, accountCount: accounts.length,
    expectedShards: tuples.length,
    allRegionsMode: ALL_REGIONS,
    // Surfaced (not silent) so the execution output + any consumer can flag that
    // some accounts' region coverage is NOT guaranteed complete (docs/SCALING.md §6 Bug B).
    regionDiscoveryFailedAccounts: regionDiscoveryFailed,
    regionDiscoveryFailedCount: regionDiscoveryFailed.length,
  };
};
      `),
    });
    seedFn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'ListOrgAccounts',
      effect: iam.Effect.ALLOW,
      actions: ['organizations:ListAccounts'],
      resources: ['*'],
    }));
    // Seed assumes each member scanner role to query that account's enabled
    // regions (ec2:DescribeRegions is granted by the assumed member role).
    seedFn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'AssumeMemberScannerRoleForRegionEnablement',
      effect: iam.Effect.ALLOW,
      actions: ['sts:AssumeRole'],
      resources: [`arn:${cdk.Aws.PARTITION}:iam::*:role/${props.scannerRoleName}`],
    }));
    // Seed writes the tuple/account arrays for the S3 ItemReader.
    props.resultsBucket.grantPut(seedFn, 'scans/_seed/*');

    const seedTask = new tasks.LambdaInvoke(this, 'SeedTuples', {
      lambdaFunction: seedFn,
      payloadResponseOnly: true,
      resultPath: '$.seed',
    });

    // ------------------------------------------------------------------
    // Merge Lambda: roll up the Distributed Map results into a run summary.
    // ------------------------------------------------------------------
    const mergeFn = this.mergeFn = new lambda.Function(this, 'MergeResultsFn', {
      runtime: lambda.Runtime.NODEJS_22_X,
      memorySize: 512,
      timeout: cdk.Duration.minutes(5),
      handler: 'index.handler',
      logGroup: new logs.LogGroup(this, 'MergeResultsFnLogs', {
        retention: logs.RetentionDays.SIX_MONTHS,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
      environment: {
        RESULTS_BUCKET: props.resultsBucket.bucketName,
        SCANS_TABLE: props.scansTable.tableName,
      },
      code: lambda.Code.fromInline(`
// Reads the Distributed Map ResultWriter manifest, aggregates child results,
// and writes a single run summary object to the central results bucket.
const { S3Client, GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3');
const s3 = new S3Client({});
const BUCKET = process.env.RESULTS_BUCKET;

const stream2str = async (s) => { const c=[]; for await (const x of s) c.push(x); return Buffer.concat(c).toString('utf-8'); };

const getJson = async (bucket, key) => {
  const out = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  return JSON.parse(await stream2str(out.Body));
};

exports.handler = async (event) => {
  // The Distributed Map ResultWriter passes resultWriterDetails.{Bucket,Key}
  // pointing at manifest.json, which lists the SUCCEEDED_<n>.json / FAILED_<n>.json
  // result files. Each result file is an array of branch executions; each branch's
  // .Output is a JSON STRING (the scanner Lambda's LambdaResponse, lowercase keys:
  // accountId, region, findings, critical, assets).
  const details = event.resultWriterDetails || {};
  const manifestBucket = details.Bucket || BUCKET;
  const runId = event.runId || (event.mapRunArn || '').split(':').pop() || 'unknown';
  let totalFindings = 0, totalCritical = 0, totalAssets = 0, succeeded = 0, failed = 0;
  const perAccount = [];

  let resultKeys = [];
  if (details.Key) {
    const manifest = await getJson(manifestBucket, details.Key);
    const rf = (manifest.ResultFiles) || {};
    resultKeys = [...(rf.SUCCEEDED||[]), ...(rf.PENDING||[])].map(f => f.Key);
    failed += (rf.FAILED||[]).reduce((n,f)=> n + (f.Size>2?1:0), 0);
  }

  for (const key of resultKeys) {
    const branches = await getJson(manifestBucket, key); // array of branch executions
    for (const b of branches) {
      if (b.Status && b.Status !== 'SUCCEEDED') { failed++; continue; }
      let o = {};
      try { o = JSON.parse(b.Output || '{}'); } catch (e) { failed++; continue; }
      totalFindings += o.findings || 0;
      totalCritical += o.critical || 0;
      totalAssets   += o.assets   || 0;
      succeeded++;
      perAccount.push({ accountId: o.accountId, region: o.region, assets: o.assets||0, findings: o.findings||0, critical: o.critical||0, s3Key: o.s3Key });
    }
  }

  const summary = { runId, generatedAt: new Date().toISOString(), accountsRegionsScanned: succeeded + failed, succeeded, failed, totalFindings, totalCritical, totalAssets, perAccount };
  await s3.send(new PutObjectCommand({ Bucket: BUCKET, Key: \`scans/latest/\${runId}.json\`, Body: JSON.stringify(summary), ContentType: 'application/json' }));
  return summary;
};
      `),
    });
    props.resultsBucket.grantReadWrite(mergeFn);
    props.scansTable.grantReadData(mergeFn);
    props.dataKey.grantEncryptDecrypt(mergeFn);

    // ------------------------------------------------------------------
    // Distributed Map child: invoke the scanner Lambda for one tuple.
    // The scanner Lambda assumes the member role (roleArn + externalId) and
    // scans the single (account, region) in the item payload.
    // ------------------------------------------------------------------
    const invokeScanner = new tasks.LambdaInvoke(this, 'InvokeScanner', {
      // props.scannerFn is imported from ScannerStack — its ARN is the Map
      // child's Resource. The Go handler (cmd/cryptamap/lambda.go) reads
      // roleArn/externalId/runId, assumes the member role via internal/org.AssumeRole,
      // scans the (account,region), and uploads BOTH the CBOM and the raw
      // ScanResult under scans/raw/<runId>/ so findings survive for the merge step.
      lambdaFunction: props.scannerFn,
      payloadResponseOnly: true,
      payload: sfn.TaskInput.fromObject({
        mode: 'lambda',
        'runId.$': '$.runId',
        'accountId.$': '$.accountId',
        'region.$': '$.region',
        'roleArn.$': '$.roleArn',
        'externalId.$': '$.externalId',
      }),
    });
    invokeScanner.addRetry({
      errors: ['Lambda.TooManyRequestsException', 'States.TaskFailed'],
      interval: cdk.Duration.seconds(5),
      maxAttempts: 3,
      backoffRate: 2,
    });

    // Distributed Map (Standard) — one child execution per (account,region).
    // ItemReader is the seeded tuple array; ResultWriter persists the manifest
    // + child results to the central results bucket. tolerated failure keeps a
    // single bad account from failing the whole org run.
    const scanFanout = new sfn.DistributedMap(this, 'ScanFanout', {
      maxConcurrency: 20,
      // S3 ItemReader (not inline itemsPath) — removes the 256KB state-payload
      // cap so the org can fan out arbitrarily many (account,region) tuples
      // (SCALING.md §4.2). The seed wrote $.seed.tuplesKey to the results bucket;
      // the reader self-grants s3:GetObject on the SM role.
      itemReader: new sfn.S3JsonItemReader({
        bucket: props.resultsBucket,
        key: sfn.JsonPath.stringAt('$.seed.tuplesKey'),
      }),
      toleratedFailurePercentage: 25,
      mapExecutionType: sfn.StateMachineType.STANDARD,
      resultWriterV2: new sfn.ResultWriterV2({
        bucket: props.resultsBucket,
        prefix: 'scans/_runs/',
        writerConfig: {
          outputType: sfn.OutputType.JSON,
          transformation: sfn.Transformation.NONE,
        },
      }),
      resultSelector: {
        // ResultWriter details flow to the merge step.
        'mapRunArn.$': '$.MapRunArn',
        'resultWriterDetails.$': '$.ResultWriterDetails',
      },
      resultPath: '$.mapResult',
    });
    // NOTE: executionType is required on the processor config for validation in
    // this CDK version (MapBase.validateState checks processorConfig.executionType);
    // mapExecutionType=STANDARD above governs the rendered ExecutionType.
    scanFanout.itemProcessor(invokeScanner, {
      mode: sfn.ProcessorMode.DISTRIBUTED,
      executionType: sfn.ProcessorType.STANDARD,
    });

    // Counts summary (lightweight Node rollup over the Map manifest) — fast,
    // and writes scans/latest/<runId>.json with per-account totals
    // (runId already carries the "run-" prefix).
    const summaryTask = new tasks.LambdaInvoke(this, 'MergeResults', {
      lambdaFunction: mergeFn,
      payloadResponseOnly: true,
      resultPath: '$.summary',
      payload: sfn.TaskInput.fromObject({
        'runId.$': '$.seed.runId',
        'mapRunArn.$': '$.mapResult.mapRunArn',
        'resultWriterDetails.$': '$.mapResult.resultWriterDetails',
      }),
    });

    // ------------------------------------------------------------------
    // HIERARCHICAL MERGE — tier 1: per-account merge Distributed Map.
    // One child execution per DISTINCT account invokes the scanner with
    // mergeAccount:true. Each child streams that account's scans/raw/<runId>/
    // <accountId>-* region shards through the streaming merger and writes ONE
    // per-account merged object to scans/account-merged/<runId>/<accountId>.json.
    // Because each child only ever holds one account's data, it fits a small
    // Lambda regardless of org size — this is what removes the single-merge OOM
    // cliff (docs/SCALING.md §4.1). The final merge (tier 2, BuildOrgCbom below)
    // then streams the far smaller per-account objects.
    // ------------------------------------------------------------------
    const invokeAccountMerge = new tasks.LambdaInvoke(this, 'InvokeAccountMerge', {
      lambdaFunction: props.scannerFn,
      payloadResponseOnly: true,
      payload: sfn.TaskInput.fromObject({
        mode: 'lambda',
        mergeAccount: true,
        'runId.$': '$.runId',
        'accountId.$': '$.accountId',
      }),
    });
    invokeAccountMerge.addRetry({
      errors: ['Lambda.TooManyRequestsException', 'States.TaskFailed'],
      interval: cdk.Duration.seconds(5),
      maxAttempts: 3,
      backoffRate: 2,
    });

    const accountMergeFanout = new sfn.DistributedMap(this, 'AccountMergeFanout', {
      maxConcurrency: 20,
      // accounts[] is one item per distinct account (≤ a few hundred), so the
      // account×region tuples[]). Use the S3 ItemReader for consistency with
      // ScanFanout and to remove any state-size concern entirely.
      itemReader: new sfn.S3JsonItemReader({
        bucket: props.resultsBucket,
        key: sfn.JsonPath.stringAt('$.seed.accountsKey'),
      }),
      toleratedFailurePercentage: 25,
      mapExecutionType: sfn.StateMachineType.STANDARD,
      resultWriterV2: new sfn.ResultWriterV2({
        bucket: props.resultsBucket,
        prefix: 'scans/_account_merge_runs/',
        writerConfig: {
          outputType: sfn.OutputType.JSON,
          transformation: sfn.Transformation.NONE,
        },
      }),
      resultSelector: {
        'mapRunArn.$': '$.MapRunArn',
        'resultWriterDetails.$': '$.ResultWriterDetails',
      },
      resultPath: '$.accountMergeResult',
    });
    accountMergeFanout.itemProcessor(invokeAccountMerge, {
      mode: sfn.ProcessorMode.DISTRIBUTED,
      executionType: sfn.ProcessorType.STANDARD,
    });

    // Real org CBOM + roadmap (tier 2): invoke the SCANNER binary in merge-mode
    // (merge:true). It now STREAMS the per-account merged objects from
    // scans/account-merged/<runId>/ one at a time through the streaming merger
    // (falling back to raw shards if the per-account tier produced nothing),
    // bounding peak memory to the deduped org set. Emits scans/latest/<runId>.*.
    // Reuses the same Lambda (same role/perms) so no new function is needed.
    const orgCbomTask = new tasks.LambdaInvoke(this, 'BuildOrgCbom', {
      lambdaFunction: props.scannerFn,
      payloadResponseOnly: true,
      resultPath: '$.orgCbom',
      payload: sfn.TaskInput.fromObject({
        mode: 'lambda',
        merge: true,
        'runId.$': '$.seed.runId',
        // Completion barrier (SCALING.md §4.4): the merge reconciles the observed
        // shard count against this seed-emitted expected count and surfaces any
        // gap (silently-vanished / tolerated-failed shards) in the coverage output
        // instead of reporting a clean, smaller result.
        'expectedShards.$': '$.seed.expectedShards',
      }),
    });
    orgCbomTask.addRetry({
      errors: ['Lambda.TooManyRequestsException', 'States.TaskFailed'],
      interval: cdk.Duration.seconds(5),
      maxAttempts: 3,
      backoffRate: 2,
    });

    const definition = seedTask
      .next(scanFanout)
      .next(summaryTask)
      .next(accountMergeFanout)
      .next(orgCbomTask);

    const smLogGroup = new logs.LogGroup(this, 'StateMachineLogs', {
      retention: logs.RetentionDays.SIX_MONTHS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.stateMachine = new sfn.StateMachine(this, 'OrgScanStateMachine', {
      stateMachineName: 'CryptaMapOrgScan',
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      timeout: cdk.Duration.hours(2),
      tracingEnabled: true,
      logs: {
        destination: smLogGroup,
        level: sfn.LogLevel.ALL,
        // Include execution data so a failed shard's (account, region) input is
        // diagnosable from the state-machine log (otherwise a tolerated/failed
        // shard logs only a state name, not WHICH account+region it was). The
        // logged account IDs live in CloudWatch in the customer's OWN account
        // (the Audit hub), which is an acceptable disclosure for this evidence map.
        includeExecutionData: true,
      },
    });

    // The Distributed Map runs child executions and writes to S3/KMS on behalf
    // of the state machine role; grant exactly that.
    this.stateMachine.addToRolePolicy(new iam.PolicyStatement({
      sid: 'DistributedMapChildExecutions',
      effect: iam.Effect.ALLOW,
      actions: [
        'states:StartExecution',
        'states:DescribeExecution',
        'states:StopExecution',
      ],
      resources: [
        `arn:${cdk.Aws.PARTITION}:states:${this.region}:${this.account}:stateMachine:CryptaMapOrgScan`,
        `arn:${cdk.Aws.PARTITION}:states:${this.region}:${this.account}:execution:CryptaMapOrgScan/*`,
      ],
    }));
    props.scannerFn.grantInvoke(this.stateMachine);
    seedFn.grantInvoke(this.stateMachine);
    mergeFn.grantInvoke(this.stateMachine);
    props.resultsBucket.grantReadWrite(this.stateMachine);
    props.dataKey.grantEncryptDecrypt(this.stateMachine);

    new cdk.CfnOutput(this, 'OrgScanStateMachineArn', { value: this.stateMachine.stateMachineArn });
  }
}
