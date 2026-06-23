import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as ddb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';

export interface DataStackProps extends cdk.StackProps {
  readonly retentionScans: number;
}

/**
 * DataStack is the evidence store ONLY: the KMS CMK, the results (CBOM/scan)
 * bucket, and the scans metadata table. It deliberately exposes NO query API.
 *
 * LOCAL-FIRST BY DESIGN: this stack deliberately ships NO query API. An
 * internet-reachable LambdaRestApi (`/cbom`, `/roadmap`, `/summary`) that lets a
 * hosted dashboard read results is exactly the wrong shape for an org's full
 * crypto-weakness map — it puts a harvest-now-decrypt-later target list behind an
 * internet front door. The supported model is local-first: results are viewed
 * with `cryptamap serve ./out` (loopback) or pulled from this bucket by an
 * operator with their own credentials — never served from an internet-reachable
 * API. Only the data at rest lives here (all RETAINed + KMS-CMK encrypted).
 */
export class DataStack extends cdk.Stack {
  public readonly resultsBucket: s3.Bucket;
  public readonly scansTable: ddb.Table;
  public readonly dataKey: kms.Key;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    // Customer-managed KMS CMK (with annual rotation) used to encrypt the
    // evidence store (results bucket) and the scans table at rest.
    this.dataKey = new kms.Key(this, 'DataKey', {
      description: 'CryptaMap evidence-store CMK (results bucket + scans table)',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Dedicated server-access-log bucket for the results bucket. RETAINed so
    // access evidence survives a stack teardown.
    const accessLogsBucket = new s3.Bucket(this, 'ResultsAccessLogs', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      lifecycleRules: [
        { id: 'expire-access-logs', expiration: cdk.Duration.days(365) },
      ],
    });

    // Evidence store. RETAINed (NOT autoDeleteObjects) so a CDK destroy cannot
    // wipe collected CBOM/scan evidence. KMS-CMK encrypted with access logging.
    //
    // RETENTION (retentionScans, default 30 days): the local-first / regulator-
    // facing model keeps the org's full crypto-weakness map (a harvest-now-
    // decrypt-later target list) at rest only as long as needed. An S3 lifecycle
    // rule EXPIRES current objects `retentionScans` days after creation, and
    // expires noncurrent versions the same number of days after they become
    // noncurrent — so a versioned bucket does not silently accumulate old scan
    // evidence past the retention window. This pairs with the DynamoDB scans-table
    // TTL below (same window) so both the metadata records and the object payloads
    // age out together.
    this.resultsBucket = new s3.Bucket(this, 'ResultsBucket', {
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.dataKey,
      bucketKeyEnabled: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      enforceSSL: true,
      serverAccessLogsBucket: accessLogsBucket,
      serverAccessLogsPrefix: 'results-access/',
      lifecycleRules: [
        {
          id: 'expire-scan-results',
          enabled: true,
          expiration: cdk.Duration.days(props.retentionScans),
          noncurrentVersionExpiration: cdk.Duration.days(props.retentionScans),
        },
      ],
    });

    // Scans metadata table. RETAINed; encrypted with the same CMK; PITR on via
    // the non-deprecated pointInTimeRecoverySpecification API.
    //
    // RETENTION: DynamoDB TTL auto-deletes old scan records on the `expiresAt`
    // attribute (epoch SECONDS). The writer (internal/output/dynamodb_writer.go)
    // MUST stamp expiresAt = now + retentionScans days as a unix epoch; DynamoDB
    // then deletes the item shortly after that time (typically within 48h — TTL
    // deletion is best-effort, not immediate). This mirrors the results-bucket
    // lifecycle window above so metadata and object payloads age out together.
    // NOTE: retentionScans is not directly readable from the table config at
    // write time, so it is surfaced to the writer via the RETENTION_DAYS env var
    // wired in the scanner/orchestrator stacks (Backend phase).
    this.scansTable = new ddb.Table(this, 'ScansTable', {
      partitionKey: { name: 'PK', type: ddb.AttributeType.STRING },
      sortKey: { name: 'SK', type: ddb.AttributeType.STRING },
      billingMode: ddb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
      encryption: ddb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: this.dataKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
    });
    this.scansTable.addGlobalSecondaryIndex({
      indexName: 'GSI1',
      partitionKey: { name: 'GSI1PK', type: ddb.AttributeType.STRING },
      sortKey: { name: 'GSI1SK', type: ddb.AttributeType.STRING },
    });

    new cdk.CfnOutput(this, 'ResultsBucketName', { value: this.resultsBucket.bucketName });
    new cdk.CfnOutput(this, 'ScansTableName', { value: this.scansTable.tableName });
    new cdk.CfnOutput(this, 'DataKeyArn', { value: this.dataKey.keyArn });
  }
}
