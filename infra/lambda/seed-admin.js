/**
 * Create the seeded TOLAP administrator in the Cognito user pool.
 *
 * A custom resource rather than plain CloudFormation, because `AWS::Cognito::User`
 * cannot set a *permanent* password. A user created the ordinary way lands in
 * FORCE_CHANGE_PASSWORD, and the console's authorization-code flow has no way to
 * answer a NEW_PASSWORD_REQUIRED challenge -- the operator reaches the sign-in page,
 * is refused, and nothing says why.
 *
 * Written as inline JS rather than bundled TypeScript so it stays readable in the
 * CloudFormation template an approver reviews, and so it needs no build step.
 *
 * Idempotent: re-running a deployment must not fail because the user exists, and
 * must not reset a password an operator has already rotated.
 */

const {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  UsernameExistsException,
} = require("@aws-sdk/client-cognito-identity-provider");
const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

const cognito = new CognitoIdentityProviderClient({});
const secrets = new SecretsManagerClient({});

exports.handler = async (event) => {
  const { RequestType, ResourceProperties } = event;
  const { UserPoolId, SecretArn, GroupName } = ResourceProperties;

  // Deleting the stack must not delete administrators. The pool is RETAIN and the
  // Lambda has no AdminDeleteUser permission, so this is belt and braces -- but an
  // explicit no-op is clearer than relying on a missing permission.
  if (RequestType === "Delete") {
    return { PhysicalResourceId: event.PhysicalResourceId ?? "seeded-admin" };
  }

  const secret = await secrets.send(
    new GetSecretValueCommand({ SecretId: SecretArn }),
  );
  const { username, email, password } = JSON.parse(secret.SecretString);

  if (!username || !password) {
    throw new Error("admin secret is missing username or password");
  }

  let created = false;
  try {
    await cognito.send(
      new AdminCreateUserCommand({
        UserPoolId,
        Username: username,
        UserAttributes: [
          { Name: "email", Value: email },
          // Marked verified because there is no mailbox behind the placeholder
          // address; an unverified user cannot complete account recovery, and the
          // operator would hit that only later, while locked out.
          { Name: "email_verified", Value: "true" },
        ],
        // No invitation email: the address is a placeholder and the credentials are
        // in Secrets Manager, so a message would either bounce or leak.
        MessageAction: "SUPPRESS",
      }),
    );
    created = true;
  } catch (error) {
    if (!(error instanceof UsernameExistsException)) throw error;
    // Already present, from an earlier deployment.
  }

  if (created) {
    // Permanent, so there is no forced-reset challenge the console cannot answer.
    // Only on creation: an operator who has rotated this password must not have it
    // silently reset to the secret's value by the next `cdk deploy`.
    await cognito.send(
      new AdminSetUserPasswordCommand({
        UserPoolId,
        Username: username,
        Password: password,
        Permanent: true,
      }),
    );
  }

  // Group membership is asserted every time. This is the one part worth repairing on
  // update: a user outside `tolap-admin` cannot use the console at all, and the call
  // is a no-op when they are already a member.
  await cognito.send(
    new AdminAddUserToGroupCommand({
      UserPoolId,
      Username: username,
      GroupName,
    }),
  );

  // Read back rather than trusting the writes. A user who exists but is not
  // CONFIRMED cannot sign in, and finding that out now beats finding it out at the
  // sign-in page with no diagnostic.
  const user = await cognito.send(
    new AdminGetUserCommand({ UserPoolId, Username: username }),
  );
  if (user.UserStatus !== "CONFIRMED") {
    throw new Error(
      `seeded administrator is ${user.UserStatus}, expected CONFIRMED; the console cannot sign in with this account`,
    );
  }

  return {
    PhysicalResourceId: `seeded-admin-${username}`,
    Data: {
      Username: username,
      // Deliberately no password here: Data lands in the CloudFormation template's
      // resource metadata and in `describe-stacks` output, both of which are widely
      // readable. The secret is the only place it belongs.
      Created: String(created),
    },
  };
};
