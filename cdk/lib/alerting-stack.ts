import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as snssubs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as budgets from 'aws-cdk-lib/aws-budgets';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwactions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as sqs from 'aws-cdk-lib/aws-sqs';

export interface AlertingStackProps extends cdk.StackProps {
  readonly alertEmail: string;
  /**
   * Monthly cost ceiling (USD) for a region-agnostic AWS Budget that guards
   * against a runaway / misconfigured scan silently running up cost. 0 (or
   * unset) disables the budget. Notifications go to alertEmail.
   */
  readonly monthlyBudgetUSD?: number;
  /**
   * The single-account scheduled-scan Lambda (ScannerStack.scannerFn). Always
   * present — it is also the worker the org Distributed Map invokes. Gets a
   * metricErrors operational alarm so a failed scan is never silent.
   */
  readonly scannerFn: lambda.IFunction;
  /**
   * Org fan-out refs (present only when orgScanning=true). When supplied, the
   * seed/merge Lambdas and the org Step Functions state machine also get
   * operational alarms.
   */
  readonly seedFn?: lambda.IFunction;
  readonly stateMachine?: sfn.IStateMachine;
  /**
   * Optional dead-letter queue (e.g. async-invoke or SFN failure DLQ). When
   * supplied, a queue-depth alarm fires if any message lands in it. None exists
   * in the current topology, so this is wired defensively for forward-compat.
   */
  readonly deadLetterQueue?: sqs.IQueue;
}

export class AlertingStack extends cdk.Stack {
  public readonly topic: sns.Topic;

  constructor(scope: Construct, id: string, props: AlertingStackProps) {
    super(scope, id, props);

    // CMK-encrypted SNS topic (default was AWS-owned / unencrypted at the topic
    // level). EventBridge is granted kms:GenerateDataKey/Decrypt via the topic.
    const topicKey = new kms.Key(this, 'AlertTopicKey', {
      description: 'CryptaMap critical-findings SNS topic CMK',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // CloudWatch is the topic's PRIMARY publisher (the operational alarms below
    // publish via cwactions.SnsAction). Publishing to a CMK-encrypted SNS topic
    // requires the CloudWatch service principal to hold kms:Decrypt +
    // kms:GenerateDataKey* on the topic key — CDK's SnsAction adds NO KMS grant,
    // so without this the alarm still transitions to ALARM but the notification
    // is dropped SILENTLY: every "never silent" operational alarm would deliver
    // nothing. Scope to this account as defence-in-depth.
    topicKey.grantEncryptDecrypt(new iam.ServicePrincipal('cloudwatch.amazonaws.com', {
      conditions: { StringEquals: { 'aws:SourceAccount': cdk.Stack.of(this).account } },
    }));

    this.topic = new sns.Topic(this, 'CriticalFindings', {
      displayName: 'CryptaMap CRITICAL findings',
      masterKey: topicKey,
    });

    if (props.alertEmail) {
      this.topic.addSubscription(new snssubs.EmailSubscription(props.alertEmail));
    }

    // NOTE: a Security Hub CRITICAL-findings EventBridge rule used to live here,
    // routing aws.securityhub "Findings - Imported" events with ProductName
    // "CryptaMap" to this topic. It was DEAD end-to-end and has been removed:
    // nothing in the codebase ever calls securityhub:BatchImportFindings (the Go
    // module does not import the securityhub SDK; ASFF output is written as a
    // local file only), so no matching event is ever produced; and even a manual
    // batch-import of the emitted file uses the account-default product ARN,
    // which Security Hub stamps with ProductName "Default", not "CryptaMap", so
    // the pattern could never match. The operational alarms below (which DO fire)
    // are the topic's real publishers. If a live Security Hub push is added
    // later, reinstate a rule whose pattern matches what Security Hub actually
    // stamps, and restore the orchestrator's securityhub:BatchImportFindings
    // grant at that time.

    new cdk.CfnOutput(this, 'AlertTopicArn', { value: this.topic.topicArn });

    // ------------------------------------------------------------------
    // OPERATIONAL alarms — so a FAILED org scan is never silent.
    //
    // These alarms watch the scan machinery itself (there is no business-finding
    // route — the Security Hub rule that once lived above was removed as dead):
    // if a scanner/seed Lambda errors, or the org Step
    // Functions execution fails or times out, the same on-call SNS topic is
    // notified. Count metrics use Sum over the period (per the Lambda / Step
    // Functions CloudWatch metric guidance — metricErrors / metricFailed /
    // metricTimedOut default to Sum) and treat MISSING data as not breaching,
    // since the absence of invocations is not itself a failure.
    // ------------------------------------------------------------------
    const snsAction = new cwactions.SnsAction(this.topic);

    const errorAlarm = (id: string, fn: lambda.IFunction, label: string): void => {
      const alarm = new cloudwatch.Alarm(this, id, {
        alarmName: `${cdk.Stack.of(this).stackName}-${id}`,
        alarmDescription:
          `CryptaMap operational: ${label} Lambda reported >=1 error in the period ` +
          '(a scan may have failed silently).',
        metric: fn.metricErrors({ period: cdk.Duration.minutes(5) }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      alarm.addAlarmAction(snsAction);
      alarm.addOkAction(snsAction);
    };

    // Scanner Lambda always exists (single-account scan + org worker).
    errorAlarm('ScannerFnErrorsAlarm', props.scannerFn, 'scanner');

    // Org-mode Lambdas, present only when the OrgFanoutStack was synthesized.
    if (props.seedFn) {
      errorAlarm('SeedFnErrorsAlarm', props.seedFn, 'seed (org-account enumeration)');
    }
    // (The merge rollup Lambda was removed; the Go merge runs inside the org
    // state machine, so OrgScanFailedAlarm / OrgScanTimedOutAlarm below cover a
    // failed merge step.)

    // Org Step Functions state machine: a failed or timed-out org scan must page.
    if (props.stateMachine) {
      const sm = props.stateMachine;
      const failedAlarm = new cloudwatch.Alarm(this, 'OrgScanFailedAlarm', {
        alarmName: `${cdk.Stack.of(this).stackName}-OrgScanFailedAlarm`,
        alarmDescription:
          'CryptaMap operational: the org-scan Step Functions state machine had >=1 ' +
          'FAILED execution (the org scan did not complete).',
        metric: sm.metricFailed({ period: cdk.Duration.minutes(5) }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      failedAlarm.addAlarmAction(snsAction);
      failedAlarm.addOkAction(snsAction);

      const timedOutAlarm = new cloudwatch.Alarm(this, 'OrgScanTimedOutAlarm', {
        alarmName: `${cdk.Stack.of(this).stackName}-OrgScanTimedOutAlarm`,
        alarmDescription:
          'CryptaMap operational: the org-scan Step Functions state machine had >=1 ' +
          'TIMED OUT execution (it exceeded its timeout before completing).',
        metric: sm.metricTimedOut({ period: cdk.Duration.minutes(5) }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      timedOutAlarm.addAlarmAction(snsAction);
      timedOutAlarm.addOkAction(snsAction);

      // Silent-incompleteness alarm: a state-machine execution can SUCCEED while
      // the merged org CBOM is incomplete (vanished/errored shards, missing
      // per-account objects). The Failed/TimedOut alarms above never fire then, so
      // this alarm keys off the ScanIncomplete metric the merge Lambda publishes
      // via EMF (cmd/cryptamap/lambda_merge.go emitScanCoverageMetric → namespace
      // "CryptaMap"). ScanIncomplete=1 on any incomplete run, 0 otherwise; Sum over
      // the period so any incomplete run in the window breaches. treatMissingData
      // notBreaching: no merge in the window is not itself a failure.
      const scanIncompleteAlarm = new cloudwatch.Alarm(this, 'OrgScanIncompleteAlarm', {
        alarmName: `${cdk.Stack.of(this).stackName}-OrgScanIncompleteAlarm`,
        alarmDescription:
          'CryptaMap operational: the org scan SUCCEEDED but the merged CBOM is ' +
          'INCOMPLETE (>=1 shard/account was dropped or errored). The result is a ' +
          'silently-smaller inventory — investigate MissingShards/FailedShards.',
        metric: new cloudwatch.Metric({
          namespace: 'CryptaMap',
          metricName: 'ScanIncomplete',
          period: cdk.Duration.minutes(5),
          statistic: cloudwatch.Stats.SUM,
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      scanIncompleteAlarm.addAlarmAction(snsAction);
      scanIncompleteAlarm.addOkAction(snsAction);
    }

    // Optional DLQ depth alarm (defensive — no DLQ exists in the current
    // topology). Any visible message means a scan invocation was abandoned.
    if (props.deadLetterQueue) {
      const dlqAlarm = new cloudwatch.Alarm(this, 'DlqDepthAlarm', {
        alarmName: `${cdk.Stack.of(this).stackName}-DlqDepthAlarm`,
        alarmDescription:
          'CryptaMap operational: messages present in the scan dead-letter queue ' +
          '(a scan invocation was abandoned after retries).',
        metric: props.deadLetterQueue.metricApproximateNumberOfMessagesVisible({
          period: cdk.Duration.minutes(5),
          statistic: cloudwatch.Stats.MAXIMUM,
        }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      dlqAlarm.addAlarmAction(snsAction);
      dlqAlarm.addOkAction(snsAction);
    }

    // COST GUARDRAIL: region-agnostic monthly AWS Budget so a runaway or
    // misconfigured scan can't silently run up cost. Notifies the same operator
    // email at 80% / 100% actual and 100% forecasted spend. We deliberately use
    // EMAIL (not an SNS subscriber to this.topic): AWS Budgets cannot publish to
    // a CMK-encrypted SNS topic, and this topic is intentionally CMK-encrypted.
    // The budget only emits notifications when alertEmail is configured and the
    // ceiling is > 0; otherwise it is skipped entirely.
    const monthlyBudgetUSD = props.monthlyBudgetUSD ?? 0;
    if (monthlyBudgetUSD > 0) {
      const subscribers: budgets.CfnBudget.SubscriberProperty[] = props.alertEmail
        ? [{ subscriptionType: 'EMAIL', address: props.alertEmail }]
        : [];
      const notifyAt = (threshold: number, type: 'ACTUAL' | 'FORECASTED') => ({
        notification: {
          notificationType: type,
          comparisonOperator: 'GREATER_THAN',
          threshold,
          thresholdType: 'PERCENTAGE',
        },
        subscribers,
      });
      new budgets.CfnBudget(this, 'MonthlyCostBudget', {
        budget: {
          budgetName: `${cdk.Stack.of(this).stackName}-monthly-cost`,
          budgetType: 'COST',
          timeUnit: 'MONTHLY',
          budgetLimit: { amount: monthlyBudgetUSD, unit: 'USD' },
        },
        // Notifications require at least one subscriber; only attach them when an
        // alert email is set (the budget+limit still applies otherwise).
        notificationsWithSubscribers: subscribers.length
          ? [notifyAt(80, 'ACTUAL'), notifyAt(100, 'ACTUAL'), notifyAt(100, 'FORECASTED')]
          : undefined,
      });
    }
  }
}
