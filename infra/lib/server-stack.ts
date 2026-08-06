import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecs from "aws-cdk-lib/aws-ecs";
import * as elbv2 from "aws-cdk-lib/aws-elasticloadbalancingv2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as logs from "aws-cdk-lib/aws-logs";
import type * as rds from "aws-cdk-lib/aws-rds";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import type * as cognito from "aws-cdk-lib/aws-cognito";
import type { Construct } from "constructs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "../..");

export interface ServerStackProps extends StackProps {
  readonly vpc: ec2.IVpc;
  readonly cluster: rds.IDatabaseCluster & { readonly secret?: secretsmanager.ISecret };
  readonly databaseName: string;
  readonly userPool: cognito.IUserPool;
  readonly userPoolClient: cognito.IUserPoolClient;
  readonly adminGroupName: string;
  readonly auditorGroupName: string;
  /** Artifact lifetime. Capped at 3600 by the server itself. */
  readonly ttlSeconds?: number;
  /** Web ACL for the resolve load balancer. */
  readonly resolveWebAclArn?: string;
  /** Web ACL for the admin load balancer. */
  readonly adminWebAclArn?: string;
}

/**
 * The policy server on Fargate, behind two load balancers.
 *
 * The split is the point: the admin API is on an **internal** ALB, so the surface
 * that authors policy is reachable only from inside the VPC or a connected network,
 * while `/v1/resolve` is public because remote installs are remote.
 * `canonical-enforcement-spec.md` §13 says policy authors are trusted
 * administrators; keeping that surface off the internet is what makes the deployment
 * match the assumption.
 */
export class ServerStack extends Stack {
  readonly signingSecret: secretsmanager.Secret;
  readonly resolveUrl: string;
  readonly adminUrl: string;

  constructor(scope: Construct, id: string, props: ServerStackProps) {
    super(scope, id, props);

    const adminPort = 8080;
    const resolvePort = 8081;

    // -- Signing key ---------------------------------------------------------

    this.signingSecret = new secretsmanager.Secret(this, "SigningKey", {
      secretName: "tolap/signing-key",
      description:
        "HMAC signing key for TOLAP policy artifacts. Rotate by adding a second kid -- see docs/policy-server.md.",
      generateSecretString: {
        // The value is consumed as TOLAP_SIGNING_KEYS in `kid:secret` form, so the
        // secret holds only the secret half and the kid is composed below. Excluding
        // `:` matters: a colon in the secret would be read as a kid separator and
        // silently truncate the key.
        passwordLength: 48,
        excludeCharacters: ":,\"'\\$`|&;<>()[]{} ",
        excludePunctuation: false,
        requireEachIncludedType: false,
      },
      // A lost signing key invalidates every artifact in flight and cannot be
      // recovered. Losing it to a stack delete would be a self-inflicted outage.
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // -- Cluster and task ----------------------------------------------------

    const cluster = new ecs.Cluster(this, "Cluster", {
      vpc: props.vpc,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });

    const taskDefinition = new ecs.FargateTaskDefinition(this, "TaskDef", {
      cpu: 512,
      memoryLimitMiB: 1024,
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    // Group membership is what makes a group-scoped assignment resolve. `/v1/resolve`
    // is called by an install on behalf of a user, so there is no user token to read
    // `cognito:groups` from and the server must ask the pool. One read-only action,
    // scoped to this pool.
    taskDefinition.addToTaskRolePolicy(
      new iam.PolicyStatement({
        actions: ["cognito-idp:AdminListGroupsForUser"],
        resources: [props.userPool.userPoolArn],
      }),
    );

    const container = taskDefinition.addContainer("Server", {
      image: ecs.ContainerImage.fromAsset(REPO_ROOT, {
        file: "infra/docker/Dockerfile",
        // The build context is the repository root because the server imports
        // @tolap/core and @tolap/store from sdk/typescript through file: links, and
        // a context scoped to server/ cannot see them.
        exclude: [
          "**/node_modules",
          "**/dist",
          "**/coverage",
          ".git",
          "infra/cdk.out",
          // Load-bearing. `tsc --build` treats a .tsbuildinfo as proof the project is
          // already built: with a stale one copied in from the developer's tree it
          // exits 0 and emits **no dist/** at all, and the next package then fails
          // with TS6305 pointing at a file that was never written. Excluding it
          // forces a real build inside the image, and makes the build independent of
          // whatever state happens to be on the machine that runs `cdk deploy`.
          "**/*.tsbuildinfo",
        ],
      }),
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: "tolap",
        logRetention: logs.RetentionDays.THREE_MONTHS,
      }),
      environment: {
        PORT: String(adminPort),
        RESOLVE_PORT: String(resolvePort),
        // Bind all interfaces inside the task: the ALB security groups and the
        // internal/public split are what restrict reachability, not the bind
        // address. Loopback would make the container unreachable from the ALB.
        HOST: "0.0.0.0",
        TOLAP_TTL_SECONDS: String(props.ttlSeconds ?? 900),
        COGNITO_ISSUER: `https://cognito-idp.${this.region}.amazonaws.com/${props.userPool.userPoolId}`,
        COGNITO_AUDIENCE: props.userPoolClient.userPoolClientId,
        COGNITO_USER_POOL_ID: props.userPool.userPoolId,
        // Explicit rather than relying on the default, so the running
        // configuration is readable in the task definition.
        TOLAP_IDENTITY_SOURCE: "cognito",
        TOLAP_ADMIN_GROUP: props.adminGroupName,
        TOLAP_AUDITOR_GROUP: props.auditorGroupName,
        DATABASE_NAME: props.databaseName,
        // The server reads the database credential from Secrets Manager **itself**,
        // per connection, rather than receiving the password as an injected
        // environment variable.
        //
        // ECS secret injection is a snapshot taken when the task starts. The moment
        // the credential rotates, the running task is holding a password the database
        // no longer accepts -- and nothing fails at rotation time. It fails at the
        // next new connection, as an authentication error that reads like a
        // misconfiguration. Passing the ARN and letting the server read it means a
        // rotation is picked up by the next connection, with no restart.
        //
        // It also keeps the password out of the task's environment, where it would
        // sit in /proc/<pid>/environ for the process lifetime and be inherited by
        // anything it spawns.
        DATABASE_SECRET_ID: props.cluster.secret!.secretArn,
        DATABASE_SSL_MODE: "verify-full",
        DATABASE_SSL_ROOT_CERT: "/app/certs/rds-global-bundle.pem",
        NODE_ENV: "production",
      },
      secrets: {
        // The signing key is still injected: unlike the database credential it has no
        // rotation path that the server could react to on its own -- rotating means
        // adding a second kid and flipping the active one, which is a deliberate
        // configuration change and therefore a new task definition anyway.
        TOLAP_SIGNING_SECRET: ecs.Secret.fromSecretsManager(this.signingSecret),
      },
      // The image entrypoint composes DATABASE_URL and TOLAP_SIGNING_KEYS from the
      // parts above, then runs the migration and starts the server.
      healthCheck: {
        command: [
          "CMD-SHELL",
          `node -e "fetch('http://127.0.0.1:${adminPort}/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`,
        ],
        interval: Duration.seconds(30),
        timeout: Duration.seconds(5),
        retries: 3,
        startPeriod: Duration.seconds(60),
      },
    });

    // The server reads this itself at connection time, so the grant is on the **task
    // role** (what the application uses) rather than only the execution role (what
    // the ECS agent uses to inject `secrets:` above). Granting just the execution
    // role would leave the container able to start and then fail every connection.
    props.cluster.secret!.grantRead(taskDefinition.taskRole);

    container.addPortMappings(
      { containerPort: adminPort, protocol: ecs.Protocol.TCP },
      { containerPort: resolvePort, protocol: ecs.Protocol.TCP },
    );

    const service = new ecs.FargateService(this, "Service", {
      cluster,
      taskDefinition,
      desiredCount: 1,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      // Rolling deploys with a circuit breaker: a task that cannot reach the
      // database or fails its health check rolls back rather than leaving the
      // service down while an operator notices.
      circuitBreaker: { rollback: true },
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      enableExecuteCommand: false,
    });

    // Direction matters here. `cluster.connections.allowDefaultPortFrom(service)`
    // creates the ingress rule inside the *database* stack referencing the service's
    // security group, which makes TolapDatabase depend on TolapServer -- and since
    // this stack already consumes the database secret, that is a cycle CDK refuses to
    // synthesize.
    //
    // Expressing it from the service side puts the egress/ingress rule in this stack
    // instead, so the dependency runs one way: TolapServer -> TolapDatabase.
    //
    // The port is named explicitly rather than using `allowToDefaultPort`. Aurora's
    // "default port" is a cross-stack token here, which CloudFormation renders as an
    // ingress rule with no FromPort/ToPort -- valid enough to deploy, but it opens
    // the rule wider than intended and template validation flags it (E3687).
    service.connections.allowTo(
      props.cluster,
      ec2.Port.tcp(5432),
      "policy server to Aurora",
    );

    // -- Admin ALB (internal) ------------------------------------------------

    const adminLb = new elbv2.ApplicationLoadBalancer(this, "AdminAlb", {
      vpc: props.vpc,
      // The whole point of the two-listener design. Reachable from the VPC and
      // anything peered to it; not from the internet.
      internetFacing: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    const adminListener = adminLb.addListener("AdminListener", {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
    });
    adminListener.addTargets("AdminTarget", {
      port: adminPort,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [service.loadBalancerTarget({ containerName: "Server", containerPort: adminPort })],
      healthCheck: {
        path: "/health",
        interval: Duration.seconds(30),
        healthyThresholdCount: 2,
      },
      deregistrationDelay: Duration.seconds(15),
    });

    // -- Resolve ALB (internet-facing) ---------------------------------------

    const resolveLb = new elbv2.ApplicationLoadBalancer(this, "ResolveAlb", {
      vpc: props.vpc,
      internetFacing: true,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
    });

    const resolveListener = resolveLb.addListener("ResolveListener", {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
    });
    resolveListener.addTargets("ResolveTarget", {
      port: resolvePort,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targets: [
        service.loadBalancerTarget({ containerName: "Server", containerPort: resolvePort }),
      ],
      healthCheck: {
        path: "/health",
        interval: Duration.seconds(30),
        healthyThresholdCount: 2,
      },
      deregistrationDelay: Duration.seconds(15),
    });

    // WAF is a bound on abuse, not an authentication control -- every route already
    // requires a credential. Its job is to cap how much a *stolen* credential can
    // extract, which matters because a signed artifact is replayable for its whole
    // TTL (spec section 13) and /v1/resolve is what mints them.
    if (props.adminWebAclArn !== undefined) {
      new wafv2.CfnWebACLAssociation(this, "AdminWafAssociation", {
        resourceArn: adminLb.loadBalancerArn,
        webAclArn: props.adminWebAclArn,
      });
    }
    if (props.resolveWebAclArn !== undefined) {
      new wafv2.CfnWebACLAssociation(this, "ResolveWafAssociation", {
        resourceArn: resolveLb.loadBalancerArn,
        webAclArn: props.resolveWebAclArn,
      });
    }

    this.adminUrl = `http://${adminLb.loadBalancerDnsName}`;
    this.resolveUrl = `http://${resolveLb.loadBalancerDnsName}`;

    // -- Outputs -------------------------------------------------------------

    new CfnOutput(this, "AdminApiUrl", {
      value: this.adminUrl,
      description:
        "Admin API (internal ALB). Reachable from the VPC or a connected network only.",
    });
    new CfnOutput(this, "ResolveApiUrl", {
      value: this.resolveUrl,
      description: "GET /v1/resolve -- the endpoint remote installs call",
    });
    new CfnOutput(this, "SigningKeySecretArn", {
      value: this.signingSecret.secretArn,
      description: "Secrets Manager ARN of the artifact signing key",
    });
    new CfnOutput(this, "TlsReminder", {
      value:
        "Both listeners are HTTP. Attach an ACM certificate and an HTTPS listener before carrying real policy: a signed artifact is a bearer credential for its whole TTL.",
      description: "Action required before production use",
    });
  }
}
