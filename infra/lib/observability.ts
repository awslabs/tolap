/**
 * Alarms and a dashboard for the policy server.
 *
 * This exists because of a specific failure, not as a checklist item. A quadratic regex
 * in the SQL importer stalled the event loop for ~15 seconds per request, and nothing in
 * the deployment could have reported it: `logger: false` on both apps, no alarms, no
 * dashboard. The first signal available to an operator would have been somebody saying the
 * agent seemed slow.
 *
 * Two properties shape what is alarmed here:
 *
 * 1. **One task serves both listeners.** The admin API and `/v1/resolve` are two Fastify
 *    instances in one Node process (`server/src/index.ts`), so admin-side CPU cost delays
 *    policy resolution for every install. That makes *resolve* latency the signal that
 *    matters most, and it is why resolve gets a tighter threshold than admin: they share a
 *    fate, and resolve is the one with a caller waiting on an enforcement decision.
 *
 * 2. **Failing to resolve is not failing safe.** A TOLAP install that cannot fetch a
 *    policy does not get "no restrictions" -- but it also does not get access, so an
 *    outage here looks like a broad, confusing denial in someone else's service. Alarms
 *    are therefore on the resolve path first.
 *
 * Every alarm sets `treatMissingData` explicitly. The default (`MISSING`) is wrong for
 * most of these: a metric that stops arriving because the service is gone would leave the
 * alarm in INSUFFICIENT_DATA rather than ALARM, which is the failure mode where an alarm
 * is worse than none -- it reads as "fine".
 */

import { Duration } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import type * as ecs from "aws-cdk-lib/aws-ecs";
// Not `import type`: `HttpCodeTarget` is a runtime enum, used below to select the 5xx
// metric.
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import { Construct } from "constructs";

export interface ObservabilityProps {
  readonly service: ecs.FargateService;
  readonly adminLoadBalancer: elbv2.ApplicationLoadBalancer;
  readonly resolveLoadBalancer: elbv2.ApplicationLoadBalancer;
  readonly adminTargets: elbv2.ApplicationTargetGroup;
  readonly resolveTargets: elbv2.ApplicationTargetGroup;
  /**
   * Resolve p99 latency, in seconds, that counts as degraded.
   *
   * Deliberately low. A resolve call is one indexed query plus an HMAC; healthy is single
   * -digit milliseconds. One second means something is badly wrong -- a stalled event
   * loop, a saturated pool -- and an install is waiting on it. The purpose of this alarm
   * is to catch the ReDoS class of defect while it is happening rather than afterwards.
   */
  readonly resolveLatencyP99Seconds?: number;
  /** Admin latency tolerance. Higher: an import or a large list is legitimately slower. */
  readonly adminLatencyP99Seconds?: number;
}

export class Observability extends Construct {
  /** Every alarm, so a deployment can wire them all to one SNS topic. */
  readonly alarms: cloudwatch.Alarm[] = [];

  constructor(scope: Construct, id: string, props: ObservabilityProps) {
    super(scope, id);

    const resolveP99 = props.resolveLatencyP99Seconds ?? 1;
    const adminP99 = props.adminLatencyP99Seconds ?? 5;

    // -- Resolve path: the one with an install waiting on it -------------------

    const resolveLatency = props.resolveTargets.metrics.targetResponseTime({
      statistic: "p99",
      period: Duration.minutes(1),
    });

    this.alarm("ResolveLatencyP99", {
      metric: resolveLatency,
      threshold: resolveP99,
      evaluationPeriods: 3,
      alarmDescription:
        `Resolve p99 above ${resolveP99}s for 3 minutes. A resolve is one indexed query ` +
        "plus an HMAC, so this means a stalled event loop, a saturated connection pool, " +
        "or a slow database -- and installs are waiting on enforcement decisions. Both " +
        "listeners share one Node process, so admin-side work can cause this.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      // NOT_BREACHING: no resolve traffic is a quiet period, not a fault. Task health is
      // covered by RunningTaskCount below, which is the alarm that should fire if the
      // metric is missing because the service is gone.
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    this.alarm("ResolveServerErrors", {
      metric: props.resolveTargets.metrics.httpCodeTarget(
        elbv2.HttpCodeTarget.TARGET_5XX_COUNT,
        { period: Duration.minutes(5), statistic: "Sum" },
      ),
      threshold: 5,
      evaluationPeriods: 1,
      alarmDescription:
        "5xx on the resolve path. These are not authorization failures -- a rejected " +
        "credential is a 401 and a missing identity source is a 503, both deliberate. A " +
        "5xx here is the server failing to produce a signed artifact it should have " +
        "produced, which denies access without explaining why.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    this.alarm("ResolveUnhealthyTargets", {
      metric: props.resolveTargets.metrics.unhealthyHostCount({
        period: Duration.minutes(1),
        statistic: "Maximum",
      }),
      threshold: 0,
      evaluationPeriods: 2,
      alarmDescription:
        "A resolve target is failing its health check. With one task in the service this " +
        "means resolve is down, not degraded.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });

    // -- Admin path -----------------------------------------------------------

    this.alarm("AdminLatencyP99", {
      metric: props.adminTargets.metrics.targetResponseTime({
        statistic: "p99",
        period: Duration.minutes(1),
      }),
      threshold: adminP99,
      evaluationPeriods: 5,
      alarmDescription:
        `Admin p99 above ${adminP99}s for 5 minutes. An OpenAPI or DDL import is ` +
        "legitimately slower than a read, so this is deliberately looser than the resolve " +
        "alarm -- but the same process serves resolve, so sustained admin latency is also " +
        "an early warning for it.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    this.alarm("AdminServerErrors", {
      metric: props.adminTargets.metrics.httpCodeTarget(
        elbv2.HttpCodeTarget.TARGET_5XX_COUNT,
        { period: Duration.minutes(5), statistic: "Sum" },
      ),
      threshold: 5,
      evaluationPeriods: 1,
      alarmDescription:
        "5xx on the admin API. Note that 401 and 403 are excluded by construction: those " +
        "are the guards working, and alarming on them would fire on every expired console " +
        "session.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // -- The service itself ---------------------------------------------------

    // The alarm that catches "there is no server". Everything above can sit quiet while
    // the service is gone, because no metric arrives at all.
    this.alarm("NoRunningTasks", {
      metric: new cloudwatch.Metric({
        namespace: "ECS/ContainerInsights",
        metricName: "RunningTaskCount",
        dimensionsMap: {
          ClusterName: props.service.cluster.clusterName,
          ServiceName: props.service.serviceName,
        },
        period: Duration.minutes(1),
        statistic: "Minimum",
      }),
      threshold: 1,
      evaluationPeriods: 3,
      alarmDescription:
        "Fewer than one running task. The service is down: no policy resolution and no " +
        "console. Requires Container Insights on the cluster.",
      comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
      // BREACHING: if this metric stops arriving, the most likely reason is that there is
      // nothing left to report it.
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    });

    this.alarm("TaskCpuHigh", {
      metric: props.service.metricCpuUtilization({
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: 80,
      evaluationPeriods: 3,
      alarmDescription:
        "Sustained CPU above 80%. On a single-task service this is the shape a runaway " +
        "parser makes -- the SQL importer ReDoS pinned one core for ~15s per request -- " +
        "and it is also the signal to scale out.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    this.alarm("TaskMemoryHigh", {
      metric: props.service.metricMemoryUtilization({
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: 85,
      evaluationPeriods: 3,
      alarmDescription:
        "Sustained memory above 85%. The list endpoints are unpaginated, so a large " +
        "catalog or audit table is read into memory whole.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // -- Dashboard ------------------------------------------------------------

    const dashboard = new cloudwatch.Dashboard(this, "Dashboard", {
      dashboardName: "TolapPolicyServer",
      // A fixed window rather than the console default, so a link to this dashboard shows
      // the same thing to everyone looking at the same incident.
      defaultInterval: Duration.hours(3),
    });

    dashboard.addWidgets(
      new cloudwatch.TextWidget({
        markdown: [
          "# TOLAP policy server",
          "",
          "**Resolve first.** `/v1/resolve` is what remote installs call to get a signed",
          "policy; the admin API is the authoring surface. Both run in **one Node process",
          "on one Fargate task**, so admin-side work delays resolution for every install.",
          "",
          "A resolve failure does not fail open -- installs get no access rather than no",
          "restrictions -- so an outage here surfaces as a broad denial in someone else's",
          "service, not as a security hole.",
        ].join("\n"),
        width: 24,
        height: 4,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: "Resolve latency (p50 / p99)",
        left: [
          props.resolveTargets.metrics.targetResponseTime({
            statistic: "p50",
            label: "p50",
            period: Duration.minutes(1),
          }),
          resolveLatency.with({ label: "p99" }),
        ],
        leftAnnotations: [
          { value: resolveP99, label: `alarm at ${resolveP99}s`, color: cloudwatch.Color.RED },
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: "Resolve requests and errors",
        left: [
          props.resolveTargets.metrics.requestCount({
            label: "requests",
            period: Duration.minutes(1),
          }),
        ],
        right: [
          props.resolveTargets.metrics.httpCodeTarget(
            elbv2.HttpCodeTarget.TARGET_5XX_COUNT,
            { label: "5xx", period: Duration.minutes(1) },
          ),
        ],
        width: 12,
        height: 6,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.GraphWidget({
        title: "Admin latency (p99) and errors",
        left: [
          props.adminTargets.metrics.targetResponseTime({
            statistic: "p99",
            label: "p99",
            period: Duration.minutes(1),
          }),
        ],
        right: [
          props.adminTargets.metrics.httpCodeTarget(
            elbv2.HttpCodeTarget.TARGET_5XX_COUNT,
            { label: "5xx", period: Duration.minutes(1) },
          ),
        ],
        width: 12,
        height: 6,
      }),
      new cloudwatch.GraphWidget({
        title: "Task CPU and memory",
        left: [
          props.service.metricCpuUtilization({ label: "CPU %", period: Duration.minutes(1) }),
          props.service.metricMemoryUtilization({
            label: "Memory %",
            period: Duration.minutes(1),
          }),
        ],
        width: 12,
        height: 6,
      }),
    );

    dashboard.addWidgets(
      new cloudwatch.AlarmStatusWidget({
        title: "Alarms",
        alarms: this.alarms,
        width: 24,
        height: 4,
      }),
    );
  }

  /** Create an alarm and record it, so the dashboard and any SNS wiring see them all. */
  private alarm(id: string, props: cloudwatch.AlarmProps): cloudwatch.Alarm {
    const created = new cloudwatch.Alarm(this, id, props);
    this.alarms.push(created);
    return created;
  }
}
