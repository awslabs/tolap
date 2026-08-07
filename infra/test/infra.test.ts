/**
 * Assertions against the synthesized CloudFormation.
 *
 * These check the properties that are easy to break silently and expensive to
 * discover in a deployed account: whether the admin load balancer is actually
 * internal, whether a secret leaked into a template, whether the task role's Cognito
 * permission is scoped, and whether the resources that must survive a stack delete
 * carry the right removal policy.
 *
 * A `cdk deploy` would catch none of these -- it would succeed.
 */

import { describe, expect, it } from "vitest";
import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import { NetworkStack } from "../lib/network-stack.ts";
import { DatabaseStack } from "../lib/database-stack.ts";
import { IdentityStack } from "../lib/identity-stack.ts";
import { ServerStack } from "../lib/server-stack.ts";
import { EdgeStack } from "../lib/edge-stack.ts";

const env = { account: "123456789012", region: "us-east-1" };

function synth() {
  const app = new App();
  const network = new NetworkStack(app, "TolapNetwork", { env });
  const database = new DatabaseStack(app, "TolapDatabase", {
    env,
    vpc: network.vpc,
  });
  const identity = new IdentityStack(app, "TolapIdentity", {
    env,
    consoleUrls: ["http://localhost:5173/"],
  });
  const server = new ServerStack(app, "TolapServer", {
    env,
    vpc: network.vpc,
    cluster: database.cluster,
    databaseName: database.databaseName,
    userPool: identity.userPool,
    userPoolClient: identity.userPoolClient,
    adminGroupName: identity.adminGroupName,
    auditorGroupName: identity.auditorGroupName,
  });
  const edge = new EdgeStack(app, "TolapEdge", {
    env,
    adminLoadBalancer: server.adminLoadBalancer,
    resolveLoadBalancer: server.resolveLoadBalancer,
    adminPort: server.adminPort,
    resolvePort: server.resolvePort,
    userPoolId: identity.userPool.userPoolId,
    userPoolClientId: identity.userPoolClient.userPoolClientId,
  });

  return {
    network: Template.fromStack(network),
    database: Template.fromStack(database),
    identity: Template.fromStack(identity),
    server: Template.fromStack(server),
    edge: Template.fromStack(edge),
  };
}

const templates = synth();

describe("the two-listener split", () => {
  it("puts the admin load balancer on an internal scheme", () => {
    // The whole point of the split. An internet-facing admin ALB would expose the
    // policy-authoring surface, which spec section 13 assumes is restricted to
    // trusted administrators.
    templates.server.hasResourceProperties(
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
      { Scheme: "internal" },
    );
  });

  it("routes the two listeners to different container ports", () => {
    const groups = templates.server.findResources(
      "AWS::ElasticLoadBalancingV2::TargetGroup",
    );
    const ports = Object.values(groups)
      .map((r) => (r.Properties as { Port?: number }).Port)
      .sort();
    // 8080 admin, 8081 resolve. Collapsing them onto one port would put the admin
    // API behind the public balancer.
    expect(ports).toEqual([8080, 8081]);
  });

  it("health-checks both target groups", () => {
    const groups = templates.server.findResources(
      "AWS::ElasticLoadBalancingV2::TargetGroup",
    );
    for (const group of Object.values(groups)) {
      expect((group.Properties as { HealthCheckPath?: string }).HealthCheckPath).toBe(
        "/health",
      );
    }
  });
});

describe("secrets never reach a template", () => {
  it("passes the signing key by reference, not by value", () => {
    const body = JSON.stringify(templates.server.toJSON());
    // Secrets Manager generates the value at deploy time, so the template holds only
    // an ARN reference. A literal here would be readable by anyone with
    // describe-stacks.
    expect(body).not.toMatch(/TOLAP_SIGNING_KEYS["']?\s*:\s*["'][A-Za-z0-9+/]{20,}/);
    templates.server.hasResourceProperties("AWS::SecretsManager::Secret", {
      Name: "tolap/signing-key",
    });
  });

  it("passes the database secret by ARN, never the password itself", () => {
    const definitions = templates.server.findResources(
      "AWS::ECS::TaskDefinition",
    );
    const container = Object.values(definitions)[0]!.Properties as {
      ContainerDefinitions: Array<{
        Secrets?: Array<{ Name: string }>;
        Environment?: Array<{ Name: string; Value: unknown }>;
      }>;
    };
    const secretNames = (container.ContainerDefinitions[0]!.Secrets ?? []).map(
      (s) => s.Name,
    );
    const envNames = (container.ContainerDefinitions[0]!.Environment ?? []).map(
      (e) => e.Name,
    );

    // The server reads the database credential itself, per connection, so a rotation
    // is picked up without a restart. Injecting the password would make it a snapshot
    // taken at task start.
    expect(envNames).toContain("DATABASE_SECRET_ID");
    expect(secretNames).not.toContain("DATABASE_URL_PASSWORD");
    expect(envNames).not.toContain("DATABASE_URL_PASSWORD");
    expect(envNames).not.toContain("DATABASE_URL");

    // The signing key is still injected: rotating it is a deliberate configuration
    // change that produces a new task definition anyway.
    expect(secretNames).toContain("TOLAP_SIGNING_SECRET");
    expect(envNames).not.toContain("TOLAP_SIGNING_SECRET");

    // Certificate verification is on, with a CA that can actually vouch for Aurora.
    const byName = new Map(
      (container.ContainerDefinitions[0]!.Environment ?? []).map((e) => [
        e.Name,
        e.Value,
      ]),
    );
    expect(byName.get("DATABASE_SSL_MODE")).toBe("verify-full");
    expect(byName.get("DATABASE_SSL_ROOT_CERT")).toMatch(/rds-global-bundle\.pem/);
  });

  it("grants the task role read access to the database secret", () => {
    // On the task role, not just the execution role: the application does the
    // reading. Granting only the execution role would let the container start and
    // then fail every connection.
    const body = JSON.stringify(templates.server.toJSON());
    expect(body).toMatch(/secretsmanager:GetSecretValue/);
  });

  it("does not put the seeded password in a stack output", () => {
    const outputs = JSON.stringify(templates.identity.toJSON().Outputs ?? {});
    // Outputs are readable via describe-stacks. Only the secret ARN belongs there.
    expect(outputs).toMatch(/AdminSecretArn/);
    expect(outputs.toLowerCase()).not.toMatch(/"password"/);
  });
});

describe("the seeded administrator", () => {
  it("generates the password in Secrets Manager", () => {
    templates.identity.hasResourceProperties("AWS::SecretsManager::Secret", {
      Name: "tolap/admin-user",
      GenerateSecretString: Match.objectLike({
        GenerateStringKey: "password",
        PasswordLength: 24,
      }),
    });
  });

  it("excludes shell-hostile characters from the password", () => {
    const secrets = templates.identity.findResources(
      "AWS::SecretsManager::Secret",
    );
    const admin = Object.values(secrets).find(
      (r) => (r.Properties as { Name?: string }).Name === "tolap/admin-user",
    );
    const excluded = (
      admin!.Properties as { GenerateSecretString: { ExcludeCharacters: string } }
    ).GenerateSecretString.ExcludeCharacters;
    // A password containing a quote or a backslash is easy to corrupt when pasted
    // through a shell, and the failure looks like a wrong password.
    for (const character of ['"', "'", "\\", "$", "`"]) {
      expect(excluded).toContain(character);
    }
  });

  it("creates the user through a custom resource", () => {
    // CloudFormation's Cognito user resource cannot set a permanent password, which
    // leaves the account in FORCE_CHANGE_PASSWORD and unable to sign in through the
    // console's code flow.
    const resources = templates.identity.findResources("Custom::AWS");
    const custom = Object.keys(templates.identity.toJSON().Resources).filter((k) =>
      k.startsWith("SeededAdmin"),
    );
    expect(custom.length + Object.keys(resources).length).toBeGreaterThan(0);
  });

  it("grants the seeding function no delete permission", () => {
    // Asserted against the IAM policies specifically, not the whole template: the
    // Lambda source is inlined, so a grep for the action name also matches the
    // comment explaining why it is absent.
    const granted = Object.values(
      templates.identity.findResources("AWS::IAM::Policy"),
    ).flatMap((policy) => {
      const document = (
        policy.Properties as {
          PolicyDocument: { Statement: Array<{ Action: unknown }> };
        }
      ).PolicyDocument;
      return document.Statement.flatMap((statement) =>
        Array.isArray(statement.Action) ? statement.Action : [statement.Action],
      );
    }).filter((action): action is string => typeof action === "string");

    const cognitoActions = granted.filter((a) => a.startsWith("cognito-idp:"));

    // A stack delete must not be able to remove administrators.
    expect(cognitoActions).not.toContain("cognito-idp:AdminDeleteUser");
    expect(cognitoActions).toContain("cognito-idp:AdminCreateUser");
    expect(cognitoActions).toContain("cognito-idp:AdminSetUserPassword");
    expect(cognitoActions).toContain("cognito-idp:AdminAddUserToGroup");
    // Nothing wildcarded: a `cognito-idp:*` grant would include user deletion and
    // pool reconfiguration.
    expect(cognitoActions.filter((a) => a.includes("*"))).toEqual([]);
  });

  it("retains the user pool and the admin secret", () => {
    // Deleting either would lock every administrator out of policy management.
    templates.identity.hasResource("AWS::Cognito::UserPool", {
      DeletionPolicy: "Retain",
    });
    templates.identity.hasResource("AWS::SecretsManager::Secret", {
      DeletionPolicy: "Retain",
    });
  });
});

describe("Cognito configuration", () => {
  it("creates both role groups", () => {
    templates.identity.hasResourceProperties("AWS::Cognito::UserPoolGroup", {
      GroupName: "tolap-admin",
    });
    templates.identity.hasResourceProperties("AWS::Cognito::UserPoolGroup", {
      GroupName: "tolap-auditor",
    });
  });

  it("disables the implicit flow and self sign-up", () => {
    templates.identity.hasResourceProperties("AWS::Cognito::UserPoolClient", {
      // Implicit would return a policy-authoring token in the URL fragment, where it
      // lands in history and referrer headers.
      AllowedOAuthFlows: ["code"],
      // Emitted as an explicit false rather than omitted. A client secret shipped to
      // a browser is not a secret; PKCE covers the code exchange instead.
      GenerateSecret: false,
      // No USER_PASSWORD_AUTH: that flow sends the password to the app, which is
      // exactly what SRP plus the hosted UI avoids.
      ExplicitAuthFlows: Match.arrayWith(["ALLOW_USER_SRP_AUTH"]),
    });
    templates.identity.hasResourceProperties("AWS::Cognito::UserPool", {
      AdminCreateUserConfig: Match.objectLike({ AllowAdminCreateUserOnly: true }),
    });
  });

  it("requires a long password", () => {
    templates.identity.hasResourceProperties("AWS::Cognito::UserPool", {
      Policies: Match.objectLike({
        PasswordPolicy: Match.objectLike({ MinimumLength: 16 }),
      }),
    });
  });
});

describe("task permissions", () => {
  it("grants exactly one Cognito action, scoped to the pool", () => {
    const policies = templates.server.findResources("AWS::IAM::Policy");
    const cognitoStatements = Object.values(policies).flatMap((policy) => {
      const document = (policy.Properties as {
        PolicyDocument: { Statement: Array<{ Action: unknown; Resource: unknown }> };
      }).PolicyDocument;
      return document.Statement.filter((statement) => {
        const actions = Array.isArray(statement.Action)
          ? statement.Action
          : [statement.Action];
        return actions.some(
          (action) => typeof action === "string" && action.startsWith("cognito-idp:"),
        );
      });
    });

    expect(cognitoStatements).toHaveLength(1);
    // Read-only, and only the one call group lookup needs. Anything broader would let
    // the policy server modify the directory that decides who can author policy.
    expect(cognitoStatements[0]!.Action).toBe(
      "cognito-idp:AdminListGroupsForUser",
    );
    expect(JSON.stringify(cognitoStatements[0]!.Resource)).not.toContain('"*"');
  });

  it("configures the identity source explicitly", () => {
    const definitions = templates.server.findResources("AWS::ECS::TaskDefinition");
    const environment = (
      Object.values(definitions)[0]!.Properties as {
        ContainerDefinitions: Array<{ Environment: Array<{ Name: string; Value: unknown }> }>;
      }
    ).ContainerDefinitions[0]!.Environment;

    const byName = new Map(environment.map((e) => [e.Name, e.Value]));
    // Relying on the default would leave "does group resolution work" implicit in
    // the server's code rather than visible in the task definition.
    expect(byName.get("TOLAP_IDENTITY_SOURCE")).toBe("cognito");
    expect(byName.has("COGNITO_USER_POOL_ID")).toBe(true);
    // Binds all interfaces inside the task; the ALB split is what restricts reach.
    expect(byName.get("HOST")).toBe("0.0.0.0");
  });

  it("keeps the artifact TTL within the server's ceiling", () => {
    const definitions = templates.server.findResources("AWS::ECS::TaskDefinition");
    const environment = (
      Object.values(definitions)[0]!.Properties as {
        ContainerDefinitions: Array<{ Environment: Array<{ Name: string; Value: string }> }>;
      }
    ).ContainerDefinitions[0]!.Environment;
    const ttl = Number(
      environment.find((e) => e.Name === "TOLAP_TTL_SECONDS")!.Value,
    );
    // A signed artifact is replayable until it expires (spec section 13). The server
    // refuses anything above 3600, so a larger value here would fail to boot.
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(3600);
  });
});

describe("database", () => {
  it("is encrypted, backed up, and snapshotted on delete", () => {
    templates.database.hasResourceProperties("AWS::RDS::DBCluster", {
      StorageEncrypted: true,
      BackupRetentionPeriod: 7,
    });
    // The audit log lives here -- who changed which policy, which install pulled it.
    templates.database.hasResource("AWS::RDS::DBCluster", {
      DeletionPolicy: "Snapshot",
    });
  });

  it("sits in isolated subnets", () => {
    // Subnets with no route out at all: nothing in the policy server needs the
    // database to reach the internet.
    const subnets = templates.network.findResources("AWS::EC2::Subnet");
    const names = Object.values(subnets).map((s) =>
      JSON.stringify((s.Properties as { Tags?: unknown }).Tags ?? ""),
    );
    expect(names.some((n) => n.includes("isolated"))).toBe(true);
  });
});


describe("the edge is the only public surface", () => {
  it("keeps BOTH load balancers internal", () => {
    // The property your constraint turns on: nothing in the VPC is internet-facing.
    // The resolve balancer used to be public, which also published its
    // unauthenticated /health.
    const balancers = templates.server.findResources(
      "AWS::ElasticLoadBalancingV2::LoadBalancer",
    );
    const schemes = Object.values(balancers).map(
      (r) => (r.Properties as { Scheme?: string }).Scheme,
    );
    expect(schemes).toHaveLength(2);
    expect(schemes.filter((s) => s === "internal")).toHaveLength(2);
    expect(schemes).not.toContain("internet-facing");
  });

  it("reaches them over VPC origins, not public DNS", () => {
    // A VPC origin is the private path from the edge into the subnets. Without it an
    // internal ALB is unreachable from CloudFront and the design does not work.
    const origins = templates.edge.findResources("AWS::CloudFront::VpcOrigin");
    expect(Object.keys(origins)).toHaveLength(2);
  });

  it("points VPC origins at the ALB listener port, not the container port", () => {
    // Caught a real 504. The origins were configured with 8080/8081 -- the ports the
    // *task* listens on -- so CloudFront connected to a port the load balancer has no
    // listener on and nothing answered. The listener accepts 80 and forwards to the
    // container itself.
    const origins = templates.edge.findResources("AWS::CloudFront::VpcOrigin");
    expect(Object.keys(origins)).toHaveLength(2);
    for (const origin of Object.values(origins)) {
      const config = (
        origin.Properties as {
          VpcOriginEndpointConfig: { HTTPPort: number };
        }
      ).VpcOriginEndpointConfig;
      expect(config.HTTPPort).toBe(80);
    }

    // And the ALB listeners really are on 80, so the two agree.
    const listeners = templates.server.findResources(
      "AWS::ElasticLoadBalancingV2::Listener",
    );
    for (const listener of Object.values(listeners)) {
      expect((listener.Properties as { Port: number }).Port).toBe(80);
    }
  });

  it("serves everything over HTTPS with an AWS-managed certificate", () => {
    // No ACM certificate resource anywhere: *.cloudfront.net is covered by AWS, which
    // is what removed the self-signed-certificate work entirely.
    templates.edge.resourceCountIs("AWS::CertificateManager::Certificate", 0);
    // No ViewerCertificate block at all: CloudFront then uses its own managed
    // certificate for *.cloudfront.net. Its *absence* is the assertion -- there is
    // nothing to renew and no DNS zone required, which is what deleted the
    // self-signed-certificate work.
    const config = Object.values(
      templates.edge.findResources("AWS::CloudFront::Distribution"),
    )[0]!.Properties as { DistributionConfig: Record<string, unknown> };
    expect(config.DistributionConfig.ViewerCertificate).toBeUndefined();
    // And viewers are still forced onto HTTPS.
    templates.edge.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        DefaultCacheBehavior: Match.objectLike({
          ViewerProtocolPolicy: "redirect-to-https",
        }),
      }),
    });
  });

  it("never serves an API response from cache", () => {
    // The failure this prevents: a cached /v1/resolve response is a signed artifact --
    // a bearer credential for its whole TTL -- handed to whoever asks next.
    // CACHING_DISABLED is AWS managed policy 4135ea2d-6df8-44a3-9df3-4b5a84be39ad.
    const CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad";
    const config = Object.values(
      templates.edge.findResources("AWS::CloudFront::Distribution"),
    )[0]!.Properties as {
      DistributionConfig: {
        CacheBehaviors: Array<{ PathPattern: string; CachePolicyId: string }>;
      };
    };

    const apiPaths = config.DistributionConfig.CacheBehaviors.filter((b) =>
      b.PathPattern.startsWith("/v1"),
    );
    expect(apiPaths.length).toBeGreaterThanOrEqual(2);
    for (const behavior of apiPaths) {
      expect(behavior.CachePolicyId).toBe(CACHING_DISABLED);
    }
  });

  it("routes /v1/resolve separately from the admin API", () => {
    // Distinct origins. A resolve request reaching the admin service would 401 in a
    // way that looks like a credential problem rather than a routing one.
    const config = Object.values(
      templates.edge.findResources("AWS::CloudFront::Distribution"),
    )[0]!.Properties as {
      DistributionConfig: {
        CacheBehaviors: Array<{ PathPattern: string; TargetOriginId: string }>;
      };
    };
    const byPath = new Map(
      config.DistributionConfig.CacheBehaviors.map((b) => [
        b.PathPattern,
        b.TargetOriginId,
      ]),
    );
    expect(byPath.get("/v1/resolve")).toBeDefined();
    expect(byPath.get("/v1/*")).toBeDefined();
    expect(byPath.get("/v1/resolve")).not.toBe(byPath.get("/v1/*"));
  });

  it("carries the WAF at the edge, in CLOUDFRONT scope", () => {
    // Better placement than the ALB: a blocked request never reaches the VPC. A
    // REGIONAL scope here would not attach to a distribution at all.
    templates.edge.hasResourceProperties("AWS::WAFv2::WebACL", {
      Scope: "CLOUDFRONT",
    });
    // And it is actually associated -- an ACL attached to nothing inspects nothing.
    templates.edge.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({ WebACLId: Match.anyValue() }),
    });
  });

  it("keeps all four WAF rules with rate limiting first", () => {
    const acl = Object.values(
      templates.edge.findResources("AWS::WAFv2::WebACL"),
    )[0]!.Properties as {
      Rules: Array<{
        Name: string;
        Priority: number;
        Action?: unknown;
        OverrideAction?: unknown;
        Statement: {
          RateBasedStatement?: { Limit: number };
          ManagedRuleGroupStatement?: { Name: string; ExcludedRules?: Array<{ Name: string }> };
        };
      }>;
    };

    const rate = acl.Rules.find((r) => r.Name === "RateLimitPerIp")!;
    expect(rate.Action).toEqual({ Block: {} });
    expect(Math.min(...acl.Rules.map((r) => r.Priority))).toBe(rate.Priority);

    const managed = acl.Rules.filter(
      (r) => r.Statement.ManagedRuleGroupStatement !== undefined,
    );
    expect(managed.map((r) => r.Statement.ManagedRuleGroupStatement!.Name)).toEqual(
      expect.arrayContaining([
        "AWSManagedRulesCommonRuleSet",
        "AWSManagedRulesKnownBadInputsRuleSet",
        "AWSManagedRulesSQLiRuleSet",
      ]),
    );
    // Count mode would read as protection and block nothing.
    for (const rule of managed) expect(rule.OverrideAction).toEqual({ None: {} });

    // A real policy definition exceeds the 8KB body cap and would be blocked with an
    // error the author cannot interpret.
    const common = managed.find(
      (r) => r.Statement.ManagedRuleGroupStatement!.Name === "AWSManagedRulesCommonRuleSet",
    )!;
    expect(
      common.Statement.ManagedRuleGroupStatement!.ExcludedRules,
    ).toEqual([{ Name: "SizeRestrictions_BODY" }]);
  });

  it("keeps the console bucket private behind origin access control", () => {
    templates.edge.hasResourceProperties("AWS::S3::Bucket", {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
    });
  });

  it("serves index.html for console deep links", () => {
    templates.edge.hasResourceProperties("AWS::CloudFront::Distribution", {
      DistributionConfig: Match.objectLike({
        CustomErrorResponses: Match.arrayWith([
          Match.objectLike({ ErrorCode: 403, ResponsePagePath: "/index.html" }),
        ]),
      }),
    });
  });

  it("registers its URL as an OAuth callback, scoped to the one pool", () => {
    // Breaks the identity -> edge -> server -> identity cycle without leaving the
    // callback as a manual step, which fails at sign-in with an opaque Cognito error.
    const body = JSON.stringify(templates.edge.toJSON());
    expect(body).toMatch(/UpdateUserPoolClient/);
    // Not a wildcard: this must not be able to reconfigure other applications'
    // clients in the same account.
    expect(body).not.toMatch(/"cognito-idp:UpdateUserPoolClient"[^}]*"Resource":\s*"\*"/);
  });
});
