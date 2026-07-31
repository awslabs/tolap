import { CfnOutput, Duration, RemovalPolicy, Stack, type StackProps } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as rds from "aws-cdk-lib/aws-rds";
import type { Construct } from "constructs";

export interface DatabaseStackProps extends StackProps {
  readonly vpc: ec2.IVpc;
}

/**
 * Aurora PostgreSQL Serverless v2 holding policy definitions, assignments,
 * versions, the source catalog, installs, and the audit log.
 *
 * Serverless v2 rather than a fixed instance: policy resolution is bursty (agents
 * resolve on demand, administrators author occasionally), and scaling to 0.5 ACU
 * when idle costs less than sizing for peak. It also removes the instance-class
 * decision from an operator who just wants the thing running.
 */
export class DatabaseStack extends Stack {
  readonly cluster: rds.DatabaseCluster;
  readonly databaseName = "tolap";

  constructor(scope: Construct, id: string, props: DatabaseStackProps) {
    super(scope, id, props);

    this.cluster = new rds.DatabaseCluster(this, "Cluster", {
      engine: rds.DatabaseClusterEngine.auroraPostgres({
        // Pinned to a version that exists in both the CDK enum and the RDS API.
        // An earlier value (16.6) type-checked and synthesized fine, then failed at
        // deploy with "Cannot find version 16.6 for aurora-postgresql" -- the enum
        // carries versions that have since been retired, so `cdk synth` cannot catch
        // this. Verify against the account before changing:
        //
        //   aws rds describe-db-engine-versions --engine aurora-postgresql \
        //     --query 'DBEngineVersions[].EngineVersion'
        version: rds.AuroraPostgresEngineVersion.VER_16_13,
      }),
      vpc: props.vpc,
      // Isolated subnets: the database has no route to the internet.
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      writer: rds.ClusterInstance.serverlessV2("writer", {
        // Set here, not on the cluster: a cluster-level enablePerformanceInsights is
        // silently ignored for Serverless v2 writers, so the flag looked applied while
        // the template carried nothing.
        enablePerformanceInsights: true,
      }),
      serverlessV2MinCapacity: 0.5,
      serverlessV2MaxCapacity: 4,
      defaultDatabaseName: this.databaseName,
      // Credentials are generated and stored in Secrets Manager; no password is
      // ever written into a template, a parameter, or this repository.
      credentials: rds.Credentials.fromGeneratedSecret("tolap_admin", {
        secretName: "tolap/database",
      }),
      storageEncrypted: true,
      // The audit log lives here -- who changed which policy, which install pulled it.
      // Deletion protection is a second gate on top of RemovalPolicy.SNAPSHOT, because
      // a snapshot is only useful if someone remembers it exists.
      deletionProtection: true,
      backup: {
        retention: Duration.days(7),
        preferredWindow: "03:00-04:00",
      },
      // The audit log is the record of who changed which policy and which install
      // pulled it. Dropping the cluster on a stack delete would destroy that, so a
      // final snapshot is taken instead. It is billed until deleted -- called out in
      // the README rather than left as a surprise.
      removalPolicy: RemovalPolicy.SNAPSHOT,
      // Surfaces slow policy-resolution queries without attaching a debugger to
      // production.
      cloudwatchLogsExports: ["postgresql"],
    });

    new CfnOutput(this, "ClusterEndpoint", {
      value: this.cluster.clusterEndpoint.hostname,
      description: "Aurora writer endpoint",
    });
    new CfnOutput(this, "DatabaseSecretArn", {
      value: this.cluster.secret!.secretArn,
      description: "Secrets Manager ARN for the database credentials",
    });
  }
}
