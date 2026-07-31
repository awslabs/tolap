#!/usr/bin/env node
/**
 * CDK app for the TOLAP Policy Server.
 *
 * Five stacks rather than one, so pieces with different lifetimes can be managed
 * separately: the user pool and the signing key are RETAIN and must outlive a redeploy
 * of the service, while the edge is disposable.
 *
 * ## Ordering, and the cycle that had to be broken
 *
 * The natural wiring is circular. The server needs the Cognito pool (to verify admin
 * tokens); the edge needs the server's load balancers (as VPC origins); and Cognito
 * needs the edge's URL (as an OAuth callback). CDK refuses to synthesize that.
 *
 * It is broken at the cheapest link: identity does **not** take the edge URL as a
 * construct reference. Instead the edge stack registers itself as a callback URL on
 * the existing client, through a small custom resource. That keeps the dependency
 * one-directional -- identity, then server, then edge -- and means the callback is
 * still configured automatically rather than becoming a manual step someone forgets.
 */

import { App, Tags } from "aws-cdk-lib";
import { NetworkStack } from "../lib/network-stack.ts";
import { DatabaseStack } from "../lib/database-stack.ts";
import { IdentityStack } from "../lib/identity-stack.ts";
import { ServerStack } from "../lib/server-stack.ts";
import { EdgeStack } from "../lib/edge-stack.ts";

const app = new App();

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION ?? "us-east-1",
};

const network = new NetworkStack(app, "TolapNetwork", { env });

const database = new DatabaseStack(app, "TolapDatabase", {
  env,
  vpc: network.vpc,
});

// localhost only, for running the console against a deployed pool during development.
// The edge adds its own URL below, once it exists.
const identity = new IdentityStack(app, "TolapIdentity", {
  env,
  consoleUrls: ["http://localhost:5173/"],
});

const server = new ServerStack(app, "TolapServer", {
  env,
  // Where alarms go. Set it at deploy time -- `cdk deploy -c alarmEmail=ops@example.com`
  // -- rather than committing an address to a public repository. Unset is a valid, and
  // visible, choice: the topic is still created and its ARN is a stack output, so
  // subscribing later needs no redeploy of the service.
  ...(() => {
    const email = app.node.tryGetContext("alarmEmail");
    return typeof email === "string" && email.length > 0 ? { alarmEmail: email } : {};
  })(),
  vpc: network.vpc,
  cluster: database.cluster,
  databaseName: database.databaseName,
  userPool: identity.userPool,
  userPoolClient: identity.userPoolClient,
  adminGroupName: identity.adminGroupName,
  auditorGroupName: identity.auditorGroupName,
});

// The only public surface. CloudFront terminates TLS with an AWS-managed certificate,
// carries the WAF at the edge, and reaches both internal balancers over VPC origins --
// so nothing in the VPC is internet-facing.
const edge = new EdgeStack(app, "TolapEdge", {
  env,
  adminLoadBalancer: server.adminLoadBalancer,
  resolveLoadBalancer: server.resolveLoadBalancer,
  adminPort: server.adminPort,
  resolvePort: server.resolvePort,
  // Registers `<distribution>/` as an OAuth callback on the console client. Done from
  // this side to keep the stack dependency one-directional.
  userPoolId: identity.userPool.userPoolId,
  userPoolClientId: identity.userPoolClient.userPoolClientId,
});

// The service reads the pool's groups at runtime, so the pool must exist first. CDK
// infers this from the cross-stack references anyway; stated explicitly because the
// runtime dependency is not visible in the template.
server.addStackDependency(identity);

// No explicit dependency on the database stack. The security-group rule allowing the
// service to reach Aurora is created *in* the database stack and references the
// service's security group, so TolapDatabase already depends on TolapServer -- adding
// the reverse makes a cycle CDK refuses to synthesize. CDK orders these correctly on
// its own; an "obvious" ordering hint here was wrong.

for (const stack of [network, database, identity, server, edge]) {
  Tags.of(stack).add("Application", "tolap-policy-server");
}

app.synth();
