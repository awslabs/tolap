import { CfnOutput, Stack, type StackProps } from "aws-cdk-lib";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import type { Construct } from "constructs";

export interface WafStackProps extends StackProps {
  /**
   * Requests per 5-minute window from a single IP before it is blocked.
   *
   * Sized for the resolve endpoint's real shape: an install resolves once per user
   * per source and caches the artifact for its TTL, so a legitimate install makes
   * far fewer requests than this. The limit exists to bound how fast a *stolen*
   * install credential can harvest policy, not to shape normal traffic.
   */
  readonly rateLimitPer5Min?: number;
}

/**
 * WAF web ACLs for the two load balancers.
 *
 * WAF is a bound on abuse, not an authentication control: every API route already
 * requires a credential (Cognito JWT on the admin listener, a per-install credential
 * on `/v1/resolve`). What WAF adds is a ceiling on how much damage a *valid* but
 * stolen credential can do, plus the managed rule sets.
 *
 * The rate limit is the rule that matters most here, and for a specific reason: a
 * signed artifact is replayable for its entire TTL (canonical-enforcement-spec.md
 * §13 -- no `jti`, no single-use enforcement), and `/v1/resolve` is the endpoint that
 * mints them. Throttling a single source limits how quickly a leaked install
 * credential can enumerate users and sources to build a library of replayable
 * artifacts.
 *
 * Two separate ACLs rather than one shared: the admin listener carries policy
 * authoring and the resolve listener carries machine traffic, so their rate limits
 * and any future rule exceptions belong to different lifecycles. Sharing one would
 * mean a rule tuned for agents also governs a human clicking through the console.
 */
export class WafStack extends Stack {
  readonly resolveWebAclArn: string;
  readonly adminWebAclArn: string;

  constructor(scope: Construct, id: string, props: WafStackProps = {}) {
    super(scope, id, props);

    const rateLimit = props.rateLimitPer5Min ?? 2000;

    this.resolveWebAclArn = this.buildAcl(
      "ResolveWebAcl",
      "tolap-resolve",
      rateLimit,
    ).attrArn;

    // A lower ceiling for the admin surface. It is operated by a handful of
    // administrators through a browser, so anything approaching the machine-traffic
    // limit is not a human.
    this.adminWebAclArn = this.buildAcl(
      "AdminWebAcl",
      "tolap-admin",
      Math.max(Math.floor(rateLimit / 4), 100),
    ).attrArn;

    new CfnOutput(this, "ResolveWebAclArn", {
      value: this.resolveWebAclArn,
      description: "Web ACL protecting the resolve load balancer",
    });
    new CfnOutput(this, "AdminWebAclArn", {
      value: this.adminWebAclArn,
      description: "Web ACL protecting the admin load balancer",
    });
  }

  private buildAcl(
    id: string,
    namePrefix: string,
    rateLimit: number,
  ): wafv2.CfnWebACL {
    return new wafv2.CfnWebACL(this, id, {
      name: `${namePrefix}-web-acl`,
      // REGIONAL, because these front Application Load Balancers. CLOUDFRONT-scoped
      // ACLs must live in us-east-1 and cannot attach to an ALB.
      scope: "REGIONAL",
      // Default allow with targeted blocks. A default block would require
      // enumerating every legitimate request shape, and the authentication guards --
      // not WAF -- are what decide who may call these APIs.
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: `${namePrefix}-web-acl`,
        sampledRequestsEnabled: true,
      },
      rules: [
        {
          // First, so a flood is shed before it costs anything to evaluate the
          // managed rule sets against it.
          name: "RateLimitPerIp",
          priority: 10,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: rateLimit,
              aggregateKeyType: "IP",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: `${namePrefix}-rate-limit`,
            sampledRequestsEnabled: true,
          },
        },
        {
          name: "AWSManagedRulesCommonRuleSet",
          priority: 20,
          // `none` means the rule group's own actions apply, i.e. it blocks.
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesCommonRuleSet",
              // Policy documents are legitimately large -- a definition can carry
              // hundreds of field names and row filters -- and this rule caps a body
              // at 8KB. Excluded rather than left to reject real policy writes with
              // a WAF block the author cannot interpret. Fastify's own body limit is
              // what bounds request size.
              excludedRules: [{ name: "SizeRestrictions_BODY" }],
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: `${namePrefix}-common`,
            sampledRequestsEnabled: true,
          },
        },
        {
          name: "AWSManagedRulesKnownBadInputsRuleSet",
          priority: 30,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesKnownBadInputsRuleSet",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: `${namePrefix}-known-bad-inputs`,
            sampledRequestsEnabled: true,
          },
        },
        {
          name: "AWSManagedRulesSQLiRuleSet",
          priority: 40,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesSQLiRuleSet",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: `${namePrefix}-sqli`,
            sampledRequestsEnabled: true,
          },
        },
      ],
    });
  }
}
