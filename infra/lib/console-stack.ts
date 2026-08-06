import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3 from "aws-cdk-lib/aws-s3";
import type { Construct } from "constructs";

/**
 * The console: static files on S3, served through CloudFront.
 *
 * Deliberately *not* deployed with a bucket-deployment of built assets. The build
 * needs the Cognito domain, client id and admin API URL baked in as Vite
 * environment variables, and those are outputs of the other stacks -- so the build
 * cannot run before this stack exists. The README's two-step (deploy, then build and
 * sync) is honest about that rather than hiding a circular dependency behind a
 * custom resource.
 *
 * The console calls the admin API directly, which is on an internal ALB. So the
 * browser needs the same network reachability as any other admin client: VPN,
 * Direct Connect, or a bastion. CloudFront serves the *files*, not the API.
 */
export class ConsoleStack extends Stack {
  readonly bucket: s3.Bucket;
  readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.bucket = new s3.Bucket(this, "ConsoleBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      // Static assets, rebuildable from the repository, so a stack delete may take
      // them. Unlike the database or the signing key, nothing here is unrecoverable.
      removalPolicy: RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    this.distribution = new cloudfront.Distribution(this, "Distribution", {
      defaultBehavior: {
        // Origin access control: the bucket stays private and only CloudFront can
        // read it.
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.bucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: new cloudfront.ResponseHeadersPolicy(
          this,
          "SecurityHeaders",
          {
            securityHeadersBehavior: {
              // The console holds a token that can author policy governing regulated
              // data, so the usual headers are not decoration here.
              contentTypeOptions: { override: true },
              frameOptions: {
                frameOption: cloudfront.HeadersFrameOption.DENY,
                override: true,
              },
              referrerPolicy: {
                referrerPolicy:
                  cloudfront.HeadersReferrerPolicy.NO_REFERRER,
                override: true,
              },
              strictTransportSecurity: {
                accessControlMaxAge: Duration.days(365),
                includeSubdomains: true,
                override: true,
              },
            },
          },
        ),
      },
      defaultRootObject: "index.html",
      // The console is a single-page app with client-side view state, so a deep link
      // must return index.html rather than S3's 403/404.
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
      minimumProtocolVersion:
        cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      comment: "TOLAP policy console",
    });

    new CfnOutput(this, "ConsoleUrl", {
      value: `https://${this.distribution.distributionDomainName}`,
      description: "Console URL. Add this to the Cognito client's callback URLs.",
    });
    new CfnOutput(this, "ConsoleBucketName", {
      value: this.bucket.bucketName,
      description: "Sync the built console here: aws s3 sync console/dist s3://<name>",
    });
    new CfnOutput(this, "DistributionId", {
      value: this.distribution.distributionId,
      description: "For cache invalidation after a console deploy",
    });
  }
}
