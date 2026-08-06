import {
  CfnOutput,
  CustomResource,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from "aws-cdk-lib";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as cr from "aws-cdk-lib/custom-resources";
import type { Construct } from "constructs";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export interface IdentityStackProps extends StackProps {
  /** Where the console is served from, for the OAuth callback URLs. */
  readonly consoleUrls?: string[];
}

/**
 * Cognito user pool, the two role groups, and a seeded administrator.
 *
 * The seeding exists because of a genuine chicken-and-egg: the console is unusable
 * until some user is in the `tolap-admin` group, and an operator who has just run
 * `cdk deploy` has no such user. Rather than leaving them to work that out from the
 * AWS console, the deployment creates one and writes its credentials to Secrets
 * Manager.
 */
export class IdentityStack extends Stack {
  readonly userPool: cognito.UserPool;
  readonly userPoolClient: cognito.UserPoolClient;
  readonly adminSecret: secretsmanager.Secret;
  readonly adminGroupName = "tolap-admin";
  readonly auditorGroupName = "tolap-auditor";

  constructor(scope: Construct, id: string, props: IdentityStackProps = {}) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, "UserPool", {
      userPoolName: "tolap-policy-server",
      selfSignUpEnabled: false, // Administrators are invited, never self-registered.
      signInAliases: { email: true, username: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      passwordPolicy: {
        minLength: 16,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(3),
      },
      // Optional rather than required so federating a corporate IdP (which brings
      // its own MFA) does not force a second factor twice. The README tells the
      // operator to enrol the seeded account, because it can author policy over
      // regulated data.
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      advancedSecurityMode: cognito.AdvancedSecurityMode.AUDIT,
      // The pool is the only record of who may author policy. Deleting a stack must
      // not silently take it, and its absence would lock everyone out.
      removalPolicy: RemovalPolicy.RETAIN,
    });

    new cognito.CfnUserPoolGroup(this, "AdminGroup", {
      userPoolId: this.userPool.userPoolId,
      groupName: this.adminGroupName,
      description: "Author, assign, publish and roll back policy; manage installs",
      precedence: 1,
    });
    new cognito.CfnUserPoolGroup(this, "AuditorGroup", {
      userPoolId: this.userPool.userPoolId,
      groupName: this.auditorGroupName,
      description: "Read policies, previews and the audit log. No writes",
      precedence: 10,
    });

    const domain = this.userPool.addDomain("Domain", {
      cognitoDomain: {
        // Account-scoped so two deployments in one account do not collide on a
        // globally-unique prefix.
        domainPrefix: `tolap-${this.account}`,
      },
    });

    this.userPoolClient = this.userPool.addClient("ConsoleClient", {
      userPoolClientName: "tolap-console",
      // No secret: the console is a browser app, and a secret shipped to a browser
      // is not a secret. PKCE covers the code exchange instead.
      generateSecret: false,
      authFlows: { userSrp: true, userPassword: false },
      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          // Never implicit: it returns tokens in the URL fragment, where they land
          // in history and referrer headers.
          implicitCodeGrant: false,
        },
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
        callbackUrls: props.consoleUrls ?? ["http://localhost:5173/"],
        logoutUrls: props.consoleUrls ?? ["http://localhost:5173/"],
      },
      // Short-lived id tokens: the console holds one in memory and re-acquires it
      // silently, so there is no reason to issue a long-lived credential that can
      // author policy.
      idTokenValidity: Duration.hours(1),
      accessTokenValidity: Duration.hours(1),
      refreshTokenValidity: Duration.days(1),
      preventUserExistenceErrors: true,
    });

    // -- Seeded administrator ------------------------------------------------

    this.adminSecret = new secretsmanager.Secret(this, "AdminSecret", {
      secretName: "tolap/admin-user",
      description:
        "Seeded TOLAP policy-server administrator. Break-glass account: enable MFA and add real users.",
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          username: "tolap-admin",
          email: "tolap-admin@example.invalid",
        }),
        generateStringKey: "password",
        passwordLength: 24,
        // Cognito's password policy wants symbols, but quotes, backslashes and `$`
        // make a password painful to paste through a shell and easy to corrupt.
        // Excluding them costs a little entropy; 24 characters from the remaining
        // set is far beyond what a Cognito-throttled login can be attacked with.
        excludeCharacters: "\"'\\$`|&;<>()[]{}",
        requireEachIncludedType: true,
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // A custom resource, because CloudFormation's Cognito support cannot create a
    // user with a *permanent* password. Without that the account lands in
    // FORCE_CHANGE_PASSWORD, and the console's token flow cannot complete a
    // password-reset challenge -- the operator would be stuck at sign-in with no
    // obvious cause.
    const seedFunction = new lambda.Function(this, "SeedAdminFunction", {
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: "index.handler",
      timeout: Duration.minutes(2),
      logRetention: logs.RetentionDays.ONE_MONTH,
      code: lambda.Code.fromInline(
        readFileSync(path.join(HERE, "../lambda/seed-admin.js"), "utf8"),
      ),
      description: "Creates the seeded TOLAP administrator in the user pool",
    });

    seedFunction.addToRolePolicy(
      new iam.PolicyStatement({
        // Scoped to this pool, and to exactly the calls seeding needs. No
        // AdminDeleteUser: a stack delete must not be able to remove
        // administrators, and the pool is RETAIN for the same reason.
        actions: [
          "cognito-idp:AdminCreateUser",
          "cognito-idp:AdminSetUserPassword",
          "cognito-idp:AdminAddUserToGroup",
          "cognito-idp:AdminGetUser",
        ],
        resources: [this.userPool.userPoolArn],
      }),
    );
    this.adminSecret.grantRead(seedFunction);

    const provider = new cr.Provider(this, "SeedAdminProvider", {
      onEventHandler: seedFunction,
      logRetention: logs.RetentionDays.ONE_MONTH,
    });

    const seeded = new CustomResource(this, "SeededAdmin", {
      serviceToken: provider.serviceToken,
      properties: {
        UserPoolId: this.userPool.userPoolId,
        SecretArn: this.adminSecret.secretArn,
        GroupName: this.adminGroupName,
      },
    });
    // The groups are raw CFN resources, so nothing else orders them before the
    // seeding call. Without this the AdminAddUserToGroup can race the group's
    // creation and fail the deployment.
    seeded.node.addDependency(this.userPool);

    // -- Outputs -------------------------------------------------------------

    new CfnOutput(this, "UserPoolId", { value: this.userPool.userPoolId });
    new CfnOutput(this, "UserPoolClientId", {
      value: this.userPoolClient.userPoolClientId,
    });
    new CfnOutput(this, "CognitoIssuer", {
      value: `https://cognito-idp.${this.region}.amazonaws.com/${this.userPool.userPoolId}`,
      description: "COGNITO_ISSUER for the server",
    });
    new CfnOutput(this, "CognitoDomain", {
      value: domain.baseUrl(),
      description: "VITE_COGNITO_DOMAIN for the console",
    });
    new CfnOutput(this, "AdminSecretArn", {
      value: this.adminSecret.secretArn,
      description:
        "Seeded administrator credentials. Retrieve with: aws secretsmanager get-secret-value --secret-id tolap/admin-user",
    });
  }
}
