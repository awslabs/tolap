import { Stack, type StackProps } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import type { Construct } from "constructs";

/**
 * Network for the policy server.
 *
 * Two AZs because Aurora requires a subnet group spanning at least two, and because
 * a single-AZ policy server means a zone outage stops every agent from resolving
 * policy.
 */
export class NetworkStack extends Stack {
  readonly vpc: ec2.Vpc;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.vpc = new ec2.Vpc(this, "Vpc", {
      maxAzs: 2,
      // One NAT gateway rather than one per AZ. This is the deliberate cost/
      // resilience trade: losing the NAT's AZ costs the tasks their outbound
      // internet, but the ALBs, tasks and database stay up across both zones, and
      // nothing on the resolve path needs egress -- Secrets Manager and ECR are
      // reached through the endpoints below.
      natGateways: 1,
      subnetConfiguration: [
        {
          name: "public",
          subnetType: ec2.SubnetType.PUBLIC,
          cidrMask: 24,
        },
        {
          name: "private",
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
          cidrMask: 24,
        },
        {
          // The database sits in subnets with no route out at all. Nothing in the
          // policy server needs the database to reach the internet, and an isolated
          // subnet makes that structural rather than a security-group convention.
          name: "isolated",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 24,
        },
      ],
      // Interface endpoints below are addressed by DNS name.
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    // Keep secret retrieval and image pulls inside the VPC. Aside from removing a
    // NAT dependency from task startup, it means the signing key is never fetched
    // over a path that leaves AWS's network.
    this.vpc.addInterfaceEndpoint("SecretsManagerEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
    });
    this.vpc.addInterfaceEndpoint("EcrEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.ECR,
    });
    this.vpc.addInterfaceEndpoint("EcrDockerEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
    });
    this.vpc.addInterfaceEndpoint("CloudWatchLogsEndpoint", {
      service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
    });
    // Gateway endpoint: ECR stores layers in S3, so image pulls need it.
    this.vpc.addGatewayEndpoint("S3Endpoint", {
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });
  }
}
