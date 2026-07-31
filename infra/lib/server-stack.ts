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
import type * as cognito from "aws-cdk-lib/aws-cognito";
import type { Construct } from "constructs";
import { Observability } from "./observability.ts";
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
  /**
   * Request log verbosity, `info` by default.
   *
   * Logging is on because the alternative -- what this deployment had -- is a server that
   * cannot report its own latency: a quadratic regex in the SQL importer stalled the event
   * loop for ~15s per request and nothing recorded it. What the log withholds is as
   * deliberate as what it keeps; see server/src/logging.ts.
   */
  readonly logLevel?: string;
  /**
   * Address subscribed to the alarm topic.
   *
   * The topic exists either way; without a subscriber the alarms notify nobody, which the
   * stack output says out loud rather than leaving to be discovered during an incident.
   */
  readonly alarmEmail?: string;
  /** Steady-state task count. Defaults to 2; one task makes every deploy an outage. */
  readonly desiredCount?: number;
  readonly minCapacity?: number;
  /**
   * Autoscaling ceiling. Defaults to 6.
   *
   * Bounded by the database, not by cost: each task opens its own pool, so this multiplied
   * by `DATABASE_POOL_MAX` must stay inside Aurora's connection budget at its minimum ACU.
   */
  readonly maxCapacity?: number;
  /** Connections per task. `maxCapacity * this` must fit Aurora's budget. Default 10. */
  readonly databasePoolMax?: number;
}

/**
 * The policy server on Fargate, behind two internal load balancers.
 *
 * **Nothing here is internet-facing.** Both balancers are internal and CloudFront
 * reaches them over VPC origins (see `EdgeStack`), so the only public surface is the
 * edge -- which terminates TLS with an AWS-managed certificate and carries the WAF.
 *
 * The two balancers still exist separately, because the path split is what lets the
 * edge route `/v1/resolve` to the machine-facing service and everything else to the
 * admin service. `canonical-enforcement-spec.md` §13 assumes policy authors are
 * trusted administrators, and keeping the authoring surface off any publicly routable
 * address is what makes the deployment match that assumption.
 *
 * An earlier revision made the resolve balancer internet-facing so remote installs
 * could reach it. That also published its unauthenticated `/health`, and a VPC origin
 * gives the same reachability with nothing exposed.
 */
/**
 * The CloudFront origin-facing prefix list, looked up rather than hardcoded.
 *
 * These ALBs are internal and CloudFront reaches them over VPC origins, but CDK's
 * `addListener` still generates an ingress rule for `0.0.0.0/0` ("Allow from anyone on
 * port 80"). That is not internet-reachable here -- the scheme is internal and the account
 * has no peering, VPN or transit gateway -- but it does mean the admin API accepts traffic
 * from anything that can route inside the VPC, including the task security group, whose
 * egress is unrestricted. A compromised container could therefore reach the admin
 * listener directly and bypass CloudFront, and with it the WAF, the rate limit, and the
 * access log.
 *
 * That matters beyond defence in depth: `security/server/README.md` accepts CodeQL's
 * `js/missing-rate-limiting` on 24 admin routes by arguing the WAF is unavoidable. From
 * inside the VPC it was avoidable, so the justification only held from the internet.
 *
 * The id differs per region (`pl-3b927c52` in us-east-1, `pl-82a045eb` in us-west-2), so
 * it is resolved at synth time by name. Requires a concrete region on the stack, which
 * `bin/infra.ts` supplies; the fallback keeps a region-agnostic synth working rather than
 * failing, at the cost of the wider rule.
 */
function cloudFrontOriginPeer(scope: Construct, region: string): ec2.IPeer | undefined {
  const byRegion: Record<string, string> = {
    "us-east-1": "pl-3b927c52",
    "us-east-2": "pl-b6a144df",
    "us-west-1": "pl-e0aa4889",
    "us-west-2": "pl-82a045eb",
    "eu-west-1": "pl-4fa04526",
    "eu-central-1": "pl-a3a144ca",
    "ap-southeast-1": "pl-31a34658",
    "ap-southeast-2": "pl-b8a742d1",
    "ap-northeast-1": "pl-58a04531",
  };
  void scope;
  const id = byRegion[region];
  return id === undefined ? undefined : ec2.Peer.prefixList(id);
}

export class ServerStack extends Stack {
  readonly signingSecret: secretsmanager.Secret;
  /** Both internal. CloudFront reaches them over VPC origins -- see EdgeStack. */
  readonly adminLoadBalancer: elbv2.ApplicationLoadBalancer;
  readonly resolveLoadBalancer: elbv2.ApplicationLoadBalancer;
  readonly adminPort = 8080;
  readonly resolvePort = 8081;

  constructor(scope: Construct, id: string, props: ServerStackProps) {
    super(scope, id, props);

    const adminPort = this.adminPort;
    const resolvePort = this.resolvePort;

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
        // Stated rather than left to the server's default, so the running verbosity is
        // readable from the task definition. The request log deliberately omits the
        // Authorization header and the resolve query string -- see server/src/logging.ts.
        LOG_LEVEL: props.logLevel ?? "info",
        // Stated because it is now multiplied by the task count. maxCapacity (6) times
        // this must stay inside Aurora's connection budget at its minimum ACU -- raising
        // either one alone is how a scale-out event becomes connection exhaustion, which
        // denies policy resolution rather than merely slowing it.
        DATABASE_POOL_MAX: String(props.databasePoolMax ?? 10),
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
      // Two, not one. A single task made every deploy and every task replacement a
      // resolve outage, and it coupled the two listeners hard: an expensive import
      // delayed policy resolution for every install because there was nowhere else for
      // that traffic to go. Two is also the smallest number that proves the service is
      // actually stateless, which is easy to believe and easy to be wrong about.
      desiredCount: props.desiredCount ?? 2,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      // Rolling deploys with a circuit breaker: a task that cannot reach the
      // database or fails its health check rolls back rather than leaving the
      // service down while an operator notices.
      circuitBreaker: { rollback: true },
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      enableExecuteCommand: false,
    });

    // -- Autoscaling ---------------------------------------------------------

    // Bounded at both ends, and the upper bound is not arbitrary: every task opens its
    // own connection pool (`pg` defaults to 10 clients), so N tasks is up to 10N
    // connections. The cluster's ceiling is `LEAST({DBInstanceClassMemory/9531392}, 5000)`
    // from the default parameter group at 2 GiB per ACU -- 112 at the 0.5 ACU floor -- so
    // an unbounded scale-out trades a latency problem for
    // connection exhaustion -- which fails *worse*, because a task that cannot get a
    // connection cannot resolve policy at all.
    //
    // maxCapacity 6 keeps the worst case (60) inside that budget with room for
    // migrations, an operator's psql session, and the ~3 Aurora reserves for itself.
    // Raising it means raising Aurora's floor or lowering DATABASE_POOL_MAX, together.
    //
    // Note the ceiling is a `static` parameter: it is fixed at instance start, NOT
    // recomputed as ACUs scale. Scaling to 4 ACU does not buy more connections, so the
    // floor is the number that matters -- which is the opposite of the intuition.
    const scaling = service.autoScaleTaskCount({
      minCapacity: props.minCapacity ?? 2,
      maxCapacity: props.maxCapacity ?? 6,
    });

    // CPU rather than request count. The failure this deployment actually saw was a
    // parser pinning a core -- request count was normal while latency collapsed -- and
    // CPU is what moves in that case. 60% leaves headroom to scale *before* the p99
    // alarm fires rather than after.
    scaling.scaleOnCpuUtilization("CpuScaling", {
      targetUtilizationPercent: 60,
      // Out fast, in slow. Scaling in aggressively during a lull only to scale back out
      // moments later is how a service ends up with no capacity at the start of a spike.
      scaleOutCooldown: Duration.seconds(60),
      scaleInCooldown: Duration.minutes(5),
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
      // Drop headers that are not valid HTTP. Without this, a header the ALB tolerates
      // but the application parses differently is a request-smuggling primitive -- and
      // this listener carries policy-authoring requests.
      desyncMitigationMode: elbv2.DesyncMitigationMode.STRICTEST,
      dropInvalidHeaderFields: true,
      // The whole point of the two-listener design. Reachable from the VPC and
      // anything peered to it; not from the internet.
      internetFacing: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    const adminListener = adminLb.addListener("AdminListener", {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      // No implicit 0.0.0.0/0 rule -- see cloudFrontOriginPeer above.
      open: false,
    });
    const adminTargets = adminListener.addTargets("AdminTarget", {
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

    // Internal, like the admin balancer. Previously internet-facing, which is what
    // exposed its unauthenticated /health to the internet. CloudFront now reaches it
    // over a VPC origin, so remote installs get a public HTTPS endpoint without
    // anything in the VPC being publicly routable.
    const resolveLb = new elbv2.ApplicationLoadBalancer(this, "ResolveAlbInternal", {
      vpc: props.vpc,
      desyncMitigationMode: elbv2.DesyncMitigationMode.STRICTEST,
      dropInvalidHeaderFields: true,
      internetFacing: false,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
    });

    const resolveListener = resolveLb.addListener("ResolveListenerV2", {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      open: false,
    });
    const resolveTargets = resolveListener.addTargets("ResolveTargetV2", {
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

    // WAF is attached at the CloudFront edge instead of here (see EdgeStack). Better
    // placement: a blocked request never reaches the VPC, and with both balancers
    // internal there is no path that bypasses the edge.
    // Only CloudFront reaches either listener. Both balancers are already internal, so
    // this narrows the in-VPC surface rather than the internet-facing one -- which is the
    // gap that made the "nothing bypasses the WAF" argument true only from outside.
    const originPeer = cloudFrontOriginPeer(this, this.region);
    if (originPeer !== undefined) {
      for (const lb of [adminLb, resolveLb]) {
        lb.connections.allowFrom(originPeer, ec2.Port.tcp(80), "CloudFront VPC origins");
      }
    } else {
      // Region-agnostic synth: keep it deployable, but do not pretend it is scoped.
      for (const lb of [adminLb, resolveLb]) {
        lb.connections.allowFrom(
          ec2.Peer.ipv4(props.vpc.vpcCidrBlock),
          ec2.Port.tcp(80),
          "VPC-wide: no CloudFront prefix list known for this region",
        );
      }
    }

    this.adminLoadBalancer = adminLb;
    this.resolveLoadBalancer = resolveLb;

    // -- Observability -------------------------------------------------------

    // Not optional here. Both listeners share one Node process on one task, so a slow
    // parser on the admin side delays policy resolution for every install -- and until
    // this existed there was no way to see that happen. See lib/observability.ts.
    new Observability(this, "Observability", {
      service,
      adminLoadBalancer: adminLb,
      resolveLoadBalancer: resolveLb,
      adminTargets,
      resolveTargets,
      ...(props.alarmEmail !== undefined ? { alarmEmail: props.alarmEmail } : {}),
    });

    // -- Outputs -------------------------------------------------------------

    new CfnOutput(this, "AdminAlbDnsName", {
      value: adminLb.loadBalancerDnsName,
      description: "Internal admin ALB. Public access is through CloudFront only.",
    });
    new CfnOutput(this, "ResolveAlbDnsName", {
      value: resolveLb.loadBalancerDnsName,
      description: "Internal resolve ALB. Public access is through CloudFront only.",
    });
    new CfnOutput(this, "SigningKeySecretArn", {
      value: this.signingSecret.secretArn,
      description: "Secrets Manager ARN of the artifact signing key",
    });
  }
}
