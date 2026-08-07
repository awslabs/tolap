import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import type * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as iam from "aws-cdk-lib/aws-iam";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import * as cr from "aws-cdk-lib/custom-resources";
import type { Construct } from "constructs";

/**
 * The port both internal ALBs listen on.
 *
 * Distinct from the container ports (8080 admin, 8081 resolve): the listener accepts
 * on 80 and forwards to the container. A VPC origin must name the *listener* port.
 */
const ALB_LISTENER_PORT = 80;

export interface EdgeStackProps extends StackProps {
  readonly adminLoadBalancer: elbv2.IApplicationLoadBalancer;
  readonly resolveLoadBalancer: elbv2.IApplicationLoadBalancer;
  /** Container ports, retained for documentation. Origins use ALB_LISTENER_PORT. */
  readonly adminPort: number;
  readonly resolvePort: number;
  /** Requests per 5 minutes from one IP before blocking. */
  readonly rateLimitPer5Min?: number;
  /** Pool and client to register this distribution's URL on as an OAuth callback. */
  readonly userPoolId?: string;
  readonly userPoolClientId?: string;
}

/**
 * The single public edge: CloudFront in front of the console and both APIs.
 *
 * ## Why this replaced an internet-facing ALB and a self-signed certificate
 *
 * Two problems solved at once. TLS came free -- `*.cloudfront.net` carries an
 * AWS-managed, publicly-trusted certificate that renews itself, so there is no
 * certificate to generate, import, or rotate, and no DNS zone required. The earlier
 * plan was a self-signed certificate imported through a custom resource, which meant
 * an `acm:ImportCertificate` grant on `*` and clients that could not verify the
 * issuer.
 *
 * And nothing in the VPC is internet-reachable: **both** load balancers are internal,
 * and CloudFront reaches them over a **VPC origin** -- a private path from the edge
 * into the subnets, no public IP and no NAT on the request path. Previously the
 * resolve ALB was internet-facing, which is what made its unauthenticated `/health`
 * publicly visible.
 *
 * ## One distribution, routed by path
 *
 * `/` serves the console from S3; `/v1/resolve` goes to the resolve service; every
 * other `/v1/*` goes to the admin service. One hostname means the console calls the
 * API same-origin, so there is no CORS configuration to get wrong -- and a
 * misconfigured CORS policy on a policy-authoring API is a real hazard.
 *
 * ## Caching is disabled on the API paths, deliberately
 *
 * CloudFront is a *cache* in front of an API. A cached `/v1/resolve` response would
 * be a signed artifact -- a bearer credential for its whole TTL (spec §13) -- served
 * to whoever asked next. The server already sends `cache-control: no-store`, but
 * relying on one header for that is thin, so the behaviours below also pin
 * `CACHING_DISABLED` and forward the `Authorization` header, which by itself makes a
 * response uncacheable.
 */
export class EdgeStack extends Stack {
  readonly bucket: s3.Bucket;
  readonly distribution: cloudfront.Distribution;
  readonly url: string;

  constructor(scope: Construct, id: string, props: EdgeStackProps) {
    super(scope, id, props);

    // Access logs for both the distribution and the console bucket. The application
    // audit log records policy changes and resolves; it does not record a request that
    // WAF blocked or that never reached the origin, which is exactly what you want
    // during an incident.
    const logBucket = new s3.Bucket(this, "AccessLogs", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      // CloudFront writes logs with ACLs, which requires this ownership setting.
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
      // Versioned so a delete does not silently remove evidence. Deliberately NOT
      // self-logging: a bucket that logs its own access recurses, writing a log line
      // for every log line.
      versioned: true,
      lifecycleRules: [
        { expiration: Duration.days(90) },
        // Versioning plus a 90-day expiry would otherwise retain noncurrent versions
        // forever.
        { noncurrentVersionExpiration: Duration.days(90) },
      ],
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    this.bucket = new s3.Bucket(this, "ConsoleBucket", {
      serverAccessLogsBucket: logBucket,
      serverAccessLogsPrefix: "console-bucket/",
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      // Static assets, rebuildable from the repository. Unlike the database or the
      // signing key, nothing here is unrecoverable.
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // -- WAF at the edge -----------------------------------------------------
    //
    // CLOUDFRONT scope, so a blocked request never reaches the VPC at all. This is
    // strictly better than the previous regional ACLs on the ALBs, where the ALB was
    // already exposed and absorbing the traffic. CLOUDFRONT-scoped ACLs must live in
    // us-east-1; this stack is deployed there.
    const webAcl = new wafv2.CfnWebACL(this, "WebAcl", {
      name: "tolap-edge",
      scope: "CLOUDFRONT",
      // Default allow with targeted blocks. The authentication guards -- not WAF --
      // decide who may call these APIs; WAF bounds abuse.
      defaultAction: { allow: {} },
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "tolap-edge",
        sampledRequestsEnabled: true,
      },
      rules: [
        {
          // First, so a flood is shed before the managed groups are evaluated.
          //
          // This is the rule that matters most: a signed artifact is replayable for
          // its whole TTL and `/v1/resolve` is what mints them, so throttling one
          // source bounds how fast a stolen install credential can harvest policy.
          name: "RateLimitPerIp",
          priority: 10,
          action: { block: {} },
          statement: {
            rateBasedStatement: {
              limit: props.rateLimitPer5Min ?? 2000,
              aggregateKeyType: "IP",
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "tolap-edge-rate-limit",
            sampledRequestsEnabled: true,
          },
        },
        {
          name: "AWSManagedRulesCommonRuleSet",
          priority: 20,
          overrideAction: { none: {} },
          statement: {
            managedRuleGroupStatement: {
              vendorName: "AWS",
              name: "AWSManagedRulesCommonRuleSet",
              // A policy definition legitimately exceeds the rule's 8KB body cap --
              // hundreds of field names and row filters -- and would be blocked with
              // an error the author cannot interpret. Fastify's own body limit bounds
              // request size instead.
              excludedRules: [{ name: "SizeRestrictions_BODY" }],
            },
          },
          visibilityConfig: {
            cloudWatchMetricsEnabled: true,
            metricName: "tolap-edge-common",
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
            metricName: "tolap-edge-known-bad-inputs",
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
            metricName: "tolap-edge-sqli",
            sampledRequestsEnabled: true,
          },
        },
      ],
    });

    // -- VPC origins ---------------------------------------------------------
    //
    // The private path from the edge into the subnets. This is what lets both load
    // balancers stay internal while remaining reachable.
    const adminOrigin = origins.VpcOrigin.withApplicationLoadBalancer(
      props.adminLoadBalancer,
      {
        // HTTP between CloudFront and the ALB, inside the VPC. TLS terminates at the
        // edge. Encrypting this hop as well would need a certificate on the internal
        // ALB -- the exact problem this design removed -- and the traffic never
        // leaves the VPC.
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
        // The ALB **listener** port, not the container port. Passing 8080 here (the
        // port the task listens on) produced a 504 from CloudFront: the VPC origin
        // connected to a port the load balancer has no listener on, so nothing
        // answered. The listener forwards 80 -> 8080 itself.
        httpPort: ALB_LISTENER_PORT,
        readTimeout: Duration.seconds(30),
      },
    );

    const resolveOrigin = origins.VpcOrigin.withApplicationLoadBalancer(
      props.resolveLoadBalancer,
      {
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
        // Same: the resolve ALB also listens on 80 and forwards to 8081.
        httpPort: ALB_LISTENER_PORT,
        readTimeout: Duration.seconds(30),
      },
    );

    const securityHeaders = new cloudfront.ResponseHeadersPolicy(
      this,
      "SecurityHeaders",
      {
        securityHeadersBehavior: {
          contentTypeOptions: { override: true },
          frameOptions: {
            frameOption: cloudfront.HeadersFrameOption.DENY,
            override: true,
          },
          // `frame-ancestors` cannot be delivered in a `<meta>` element -- browsers
          // ignore it there, which made the console's meta-tag version look like
          // clickjacking protection while providing none. As a response header it is
          // enforced. Set alongside X-Frame-Options because the two cover different
          // browser generations.
          contentSecurityPolicy: {
            contentSecurityPolicy: "frame-ancestors 'none'",
            // Always set. The origin sends no CSP header of its own -- the page's
            // policy lives in a meta tag, which is not a header -- so there is nothing
            // to preserve, and `false` would leave this depending on that staying true.
            override: true,
          },
          referrerPolicy: {
            referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER,
            override: true,
          },
          strictTransportSecurity: {
            accessControlMaxAge: Duration.days(365),
            includeSubdomains: true,
            override: true,
          },
        },
      },
    );

    /**
     * Behaviour for an API path.
     *
     * Caching disabled and `Authorization` forwarded. Either alone would make a
     * response uncacheable; both are set because caching a signed artifact and
     * serving it to the next caller is the worst failure available here.
     */
    const apiBehavior = (
      origin: cloudfront.IOrigin,
    ): cloudfront.BehaviorOptions => ({
      origin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
      allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
      // Forwards Authorization and every query string, which the resolve endpoint
      // needs: userId, tenantId and sourceConnectionId all arrive that way.
      originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER,
      responseHeadersPolicy: securityHeaders,
    });

    this.distribution = new cloudfront.Distribution(this, "Distribution", {
      // Default behaviour: the console, from S3 with origin access control so the
      // bucket stays private.
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.bucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: securityHeaders,
      },
      additionalBehaviors: {
        // Most specific first. CloudFront evaluates path patterns in order of
        // specificity, so `/v1/resolve` wins over `/v1/*` -- but it is written
        // explicitly rather than relying on that, because a resolve request reaching
        // the admin service would 401 in a way that looks like a credential problem.
        "/v1/resolve": apiBehavior(resolveOrigin),
        "/v1/*": apiBehavior(adminOrigin),
        // Health checks the operator may want from outside. Routed to the admin
        // origin; it returns only {"status":"ok"}.
        "/health": apiBehavior(adminOrigin),
      },
      defaultRootObject: "index.html",
      // The console keeps view state client-side, so a deep link must return
      // index.html rather than S3's 403/404.
      errorResponses: [
        {
          httpStatus: 403,
          responseHttpStatus: 200,
          responsePagePath: "/index.html",
          ttl: Duration.minutes(5),
        },
        {
          httpStatus: 404,
          responseHttpStatus: 200,
          responsePagePath: "/index.html",
          ttl: Duration.minutes(5),
        },
      ],
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      webAclId: webAcl.attrArn,
      enableLogging: true,
      logBucket,
      logFilePrefix: "cloudfront/",
      // Query strings carry userId/tenantId/sourceConnectionId on resolve calls, which
      // is what makes a log line attributable to a request. They carry no credential --
      // that is in the Authorization header, which CloudFront does not log.
      logIncludesCookies: false,
      comment: "TOLAP policy server and console",
    });

    this.url = `https://${this.distribution.distributionDomainName}`;

    // Register this distribution as an OAuth callback on the console client.
    //
    // Done from here rather than by passing the URL into IdentityStack, because that
    // direction is circular: identity -> edge -> server -> identity. A custom resource
    // updating the existing client keeps the stack graph one-directional while still
    // configuring the callback automatically -- the alternative is a manual step in a
    // runbook, and a missing callback URL fails at sign-in with an opaque Cognito
    // error.
    if (props.userPoolId !== undefined && props.userPoolClientId !== undefined) {
      new cr.AwsCustomResource(this, "RegisterCallbackUrl", {
        onUpdate: {
          service: "CognitoIdentityServiceProvider",
          action: "updateUserPoolClient",
          parameters: {
            UserPoolId: props.userPoolId,
            ClientId: props.userPoolClientId,
            // updateUserPoolClient REPLACES the client configuration, so every field
            // that must survive has to be restated. Omitting AllowedOAuthFlows or the
            // scopes would silently disable the hosted UI.
            CallbackURLs: [`${this.url}/`, "http://localhost:5173/"],
            LogoutURLs: [`${this.url}/`, "http://localhost:5173/"],
            AllowedOAuthFlows: ["code"],
            AllowedOAuthScopes: ["openid", "email", "profile"],
            AllowedOAuthFlowsUserPoolClient: true,
            SupportedIdentityProviders: ["COGNITO"],
            ExplicitAuthFlows: ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            PreventUserExistenceErrors: "ENABLED",
          },
          physicalResourceId: cr.PhysicalResourceId.of(
            `callback-${this.distribution.distributionId}`,
          ),
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({
            actions: ["cognito-idp:UpdateUserPoolClient"],
            // Scoped to the one pool. A wildcard here would let this reconfigure any
            // client in the account, including ones governing other applications.
            resources: [
              Stack.of(this).formatArn({
                service: "cognito-idp",
                resource: "userpool",
                resourceName: props.userPoolId,
              }),
            ],
          }),
        ]),
        installLatestAwsSdk: false,
      });
    }

    new CfnOutput(this, "Url", {
      value: this.url,
      description:
        "Console, admin API and /v1/resolve. AWS-managed TLS; nothing in the VPC is internet-facing.",
    });
    new CfnOutput(this, "ResolveEndpoint", {
      value: `${this.url}/v1/resolve`,
      description: "What remote installs call",
    });
    new CfnOutput(this, "ConsoleBucketName", {
      value: this.bucket.bucketName,
      description: "aws s3 sync console/dist s3://<name>",
    });
    new CfnOutput(this, "DistributionId", {
      value: this.distribution.distributionId,
      description: "For cache invalidation after a console deploy",
    });
    new CfnOutput(this, "WebAclArn", {
      value: webAcl.attrArn,
      description: "Edge WAF web ACL (CLOUDFRONT scope)",
    });
  }
}
