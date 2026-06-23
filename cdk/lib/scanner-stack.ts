import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ddb from 'aws-cdk-lib/aws-dynamodb';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as path from 'path';

export interface ScannerStackProps extends cdk.StackProps {
  readonly resultsBucket: s3.IBucket;
  readonly scansTable: ddb.ITable;
  readonly scanSchedule: string;
  readonly scannerRoleName: string;
  /** CMK that encrypts the results bucket + scans table (so the scanner can write). */
  readonly dataKey: kms.IKey;
  /**
   * TTL window (days) stamped onto each scans-table record's `expiresAt`
   * attribute by the Go writer (internal/output/dynamodb_writer.go), surfaced via
   * the RETENTION_DAYS env var. Mirrors the retentionScans context / DataStack
   * lifecycle so metadata and object payloads age out on the same window.
   */
  readonly retentionScans: number;
  /**
   * When org scanning is enabled, the orchestrator role (from SecurityStack) the
   * Lambda runs AS — so its sts:AssumeRole principal matches the scanner-role
   * trust policies. When undefined, the Lambda gets its own default role plus the
   * read-only scan permissions for single-account use.
   */
  readonly executionRole?: iam.IRole;
}

export class ScannerStack extends cdk.Stack {
  public readonly scannerFn: lambda.Function;

  constructor(scope: Construct, id: string, props: ScannerStackProps) {
    super(scope, id, props);

    // Lambda code is the Go binary (`bootstrap`) compiled for linux/arm64.
    // The CDK build script copies it to dist/lambda/bootstrap before synth.
    const codePath = path.join(__dirname, '..', '..', 'dist', 'lambda');

    this.scannerFn = new lambda.Function(this, 'ScannerFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      memorySize: 1024,
      timeout: cdk.Duration.minutes(15),
      logGroup: new logs.LogGroup(this, 'ScannerFnLogs', {
        retention: logs.RetentionDays.SIX_MONTHS,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
      code: lambda.Code.fromAsset(codePath),
      // When org scanning is on, run AS the orchestrator role so the principal
      // calling sts:AssumeRole matches what the scanner roles trust.
      role: props.executionRole,
      environment: {
        RESULTS_BUCKET: props.resultsBucket.bucketName,
        SCANS_TABLE: props.scansTable.tableName,
        SCANNER_ROLE_NAME: props.scannerRoleName,
        CRYPTAMAP_MODE: 'lambda',
        // TTL window for scans-table records; the Go writer stamps expiresAt =
        // now + RETENTION_DAYS days so DynamoDB TTL ages records out on the same
        // window as the results-bucket lifecycle rule (DataStack.retentionScans).
        RETENTION_DAYS: String(props.retentionScans),
      },
    });

    // Central writes + reads — but NOT delete/tamper, to preserve the
    // tamper-evidence of the results bucket. The worker writes per-account
    // partials (PutObject via internal/output/s3_writer.go); the org merge-mode
    // invocation (merge:true) READS them back (GetObject + ListObjectsV2 in
    // cmd/cryptamap/lambda_merge.go) and PUTS the merged org CBOM. Merge
    // overwrites are same-key PutObject. So the scanner needs exactly:
    // PutObject (write/overwrite), s3:Abort* (multipart cleanup the SDK may do
    // for large CBOMs), GetObject* + List* (read-back for merge).
    //
    // We deliberately do NOT use grantReadWrite / grantWrite (which add
    // s3:DeleteObject*) nor grantPut (whose BUCKET_PUT_ACTIONS in aws-cdk-lib
    // still include s3:PutObjectLegalHold and s3:PutObjectRetention). Granting
    // delete OR the legal-hold/retention mutators would let the scanner /
    // orchestrator role erase or alter evidence, weakening tamper-evidence. The
    // scanner performs none of those calls, so an explicit PutObject + Abort
    // statement plus grantRead covers the full scan + merge surface with no
    // tamper capability. CMK encrypt/decrypt is still needed since the bucket
    // is KMS-encrypted.
    this.scannerFn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'CryptaMapResultsWriteNoTamper',
      effect: iam.Effect.ALLOW,
      // PutObject (incl. same-key overwrite for merge output) + multipart abort.
      // NO DeleteObject, NO PutObjectLegalHold / PutObjectRetention.
      actions: ['s3:PutObject', 's3:Abort*'],
      resources: [props.resultsBucket.arnForObjects('*')],
    }));
    props.resultsBucket.grantRead(this.scannerFn);
    props.scansTable.grantReadWriteData(this.scannerFn);
    props.dataKey.grantEncryptDecrypt(this.scannerFn);

    // Read-only discovery permissions.
    //
    // When an orchestrator executionRole is supplied (org scanning), the Lambda
    // ALREADY runs as that role, which carries the custom least-privilege
    // CryptaMapScannerReadActions policy + sts:AssumeRole (see SecurityStack) —
    // and its principal matches the scanner-role trust policies. So we only add
    // the read-only scan surface here for the DEFAULT-role, single-account case.
    if (!props.executionRole) {
      this.scannerFn.role?.addManagedPolicy(
        // ReadOnlyAccess (not SecurityAudit) so the single-account scan path also
        // gets every Describe/Get that carries real crypto detail.
        iam.ManagedPolicy.fromAwsManagedPolicyName('ReadOnlyAccess'),
      );
      this.scannerFn.addToRolePolicy(new iam.PolicyStatement({
        sid: 'CryptaMapInventorySupplement',
        effect: iam.Effect.ALLOW,
        actions: [
          'resource-explorer-2:Search',
          'resource-explorer-2:GetView',
          'resource-explorer-2:ListViews',
          'apigatewayv2:GetDomainNames',
          'apigatewayv2:GetApis',
          'cassandra:Select',
          'cloudhsm:DescribeClusters',
          'timestream:DescribeEndpoints',
          'timestream:ListDatabases',
        ],
        resources: ['*'],
      }));
    }

    // Scheduled scan
    const rule = new events.Rule(this, 'ScheduledScan', {
      schedule: events.Schedule.expression(props.scanSchedule),
    });
    rule.addTarget(new targets.LambdaFunction(this.scannerFn));

    new cdk.CfnOutput(this, 'ScannerFnName', { value: this.scannerFn.functionName });
    new cdk.CfnOutput(this, 'ScannerFnArn', { value: this.scannerFn.functionArn });
  }
}
