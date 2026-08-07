# Security scan results — policy server, console, and infrastructure

Tool output for the `server/`, `console/`, and `infra/` trees, captured **2026-08-07**.

Raw output is committed rather than summarised away, so a reviewer can check the
summary below against what the tools actually said. This mirrors the SDK evidence in
[`../README.md`](../README.md).

## Result

| Scope | Tool | Purpose | Result |
| --- | --- | --- | --- |
| all three | [Semgrep](semgrep.txt) | SAST — `security-audit`, `secrets`, `owasp-top-ten` | **0 findings** across 60 files, 142 rules |
| all three | Trivy `--scanners secret` | hardcoded credentials | **0** |
| all three | [`npm audit --omit=dev`](npm-audit-production.txt) | dependency vulns, production posture | **0 vulnerabilities** in all three |
| all three | [`npm audit`](npm-audit-full.txt) | full tree, incl. build tooling | **1 High**, unfixable upstream — see below |
| `infra/` | [Trivy IaC](trivy-iac.txt) | CloudFormation + Dockerfile misconfiguration | 11 accepted or false-positive — see below |
| `infra/docker` | Trivy Dockerfile checks | container image hardening | **0 findings** after fixes |
| `infra/docker/entrypoint.sh` | manual review | shell injection surface | `eval` removed — see below |

No new Python or .NET code, so Bandit, pip-audit and the `dotnet` scanners are
unchanged from the SDK evidence.

## Fixed as a result of this scan

| Finding | Severity | Action |
| --- | --- | --- |
| `DS-0013` — `RUN cd server && npm ci` | Medium | Replaced with `WORKDIR`. Verified the image still builds. |
| `DS-0026` — no `HEALTHCHECK` | Low | Added, mirroring the ECS task definition's check. The ECS one only applies when ECS configures it; an image that reports nothing when run any other way is harder to debug locally. |
| `AWS-0052` — ALB does not drop invalid headers | High | `dropInvalidHeaderFields` and `DesyncMitigationMode.STRICTEST` on both balancers. A header the ALB tolerates but the app parses differently is a request-smuggling primitive, and one of these listeners carries policy authoring. |
| `AWS-0343` — no cluster deletion protection | Medium | Enabled. A second gate on top of `RemovalPolicy.SNAPSHOT`, because a snapshot only helps if someone remembers it exists. |
| `AWS-0178` — no VPC flow logs | Medium | Enabled, 1-month retention. The application audit log answers "which install resolved a policy"; it cannot answer "what else talked to the database subnet". |
| `AWS-0010` / `AWS-0089` — no CloudFront or S3 access logs | Medium / Low | Added a dedicated log bucket. The audit log does not record a request WAF blocked or that never reached the origin, which is what you want during an incident. |
| `AWS-0090` — log bucket not versioned | Medium | Versioned, with a noncurrent-version expiry so it does not grow without bound. |
| `AWS-0133` — no Performance Insights | Low | Enabled. Worth recording *how*: setting `enablePerformanceInsights` on the **cluster** is silently ignored for a Serverless v2 writer, so the first fix looked applied and emitted nothing. It has to be set on the instance. Caught by re-reading the synthesized template rather than trusting the code. |
| `eval` in `entrypoint.sh` | — | Not a vulnerability: one call site, a literal variable name, no external input. Removed anyway — a shell script with no `eval` is a shorter thing to audit. |

## Remaining, with justification

### False positives

| Finding | Severity | Why it is not real |
| --- | --- | --- |
| `AWS-0036` — "sensitive value in environment variable name `DATABASE_SECRET_ID`" | Critical | The value is a **Secrets Manager ARN**, not a credential. Passing the ARN and having the server read the secret per connection is the deliberate design: an injected password is a snapshot taken at task start and goes stale the moment the credential rotates. See `server/src/db/credentials.ts`. |
| `AWS-0054` — "ALB listener does not use HTTPS" | Critical | Correct observation, wrong conclusion. **Both ALBs are internal** and unreachable from the internet (verified: both hostnames time out publicly). TLS terminates at CloudFront, which reaches them over VPC origins. Encrypting this hop would require a certificate on an internal ALB — the problem the CloudFront design removed. |
| `AWS-0013` — "distribution uses an insecure minimum TLS version" | High | The distribution has **no `ViewerCertificate` block at all**, which is how CloudFront selects its own managed certificate for `*.cloudfront.net`. Trivy reads the absent block as absent configuration. `MinimumProtocolVersion` is set to `TLSv1.2_2021` in the CDK and applies once a custom certificate is attached. |
| `AWS-0164` — "subnet associates public IP address" | High | The public subnets exist for the NAT gateway. Nothing else is placed in them: the service, both ALBs and the database are all in private or isolated subnets. |
| `AWS-0104` — "unrestricted egress" | Critical | Default security-group egress. The tasks need outbound access to Cognito and Secrets Manager; Secrets Manager, ECR, S3 and CloudWatch Logs already go through VPC endpoints rather than the internet. Narrowing egress to AWS service prefix lists is worthwhile hardening and is tracked, not silently accepted. |

### Accepted, and why

| Finding | Severity | Why it stands |
| --- | --- | --- |
| `AWS-0079`, `AWS-0132`, `AWS-0098`, `AWS-0017`, `AWS-0078` — no customer-managed KMS key for Aurora storage, S3, Secrets Manager, log groups, Performance Insights | High / Low | Everything is encrypted at rest with AWS-managed keys. Customer-managed keys add key policy, rotation and cross-account grant management, which is a real deployment decision rather than a default a reference implementation should make for an adopter. Documented as a hardening step. |
| `AWS-0066` — Lambda tracing disabled | Low | The two Lambdas are one-shot custom resources — admin seeding and OAuth callback registration — that run at deploy time. X-Ray on a resource that runs once per deployment buys little. |
| `brace-expansion` via `minimatch` (GHSA-rgw5-rvv9-x895) | High | `aws-cdk-lib` ships `minimatch` as a **bundled** dependency, inside the published tarball, so an `overrides` entry cannot replace it and no available `aws-cdk-lib` version carries a patched copy (checked through 2.263.0). CDK is build-time tooling that emits CloudFormation and ships nothing into the deployed artifact, which is why it is in `devDependencies` and why `npm audit --omit=dev` is the meaningful check. Revisit when CDK updates its bundle. |

## Known gaps, tracked rather than hidden

These are not scanner findings — no tool flagged them — but they are real and worth
stating next to the scan results:

- **Both ALB listeners are HTTP behind CloudFront.** Encrypted from the viewer to the
  edge; plaintext from the edge to the ALB, inside the VPC.
- **The audit log lives only in Aurora**, with 7-day backups. An operator with database
  access can delete rows and there is no tamper-evident copy.
- **A signed artifact is replayable for its full TTL.** TOLAP has no `jti` and no
  single-use enforcement (canonical-enforcement-spec §13); expiry is the only bound,
  which is why the server caps TTL at one hour.
- **One Fargate task, no autoscaling.** A single point of failure for policy resolution.
- **Single tenant by design.** Any authenticated administrator sees every policy — see
  [`../../docs/policy-server.md`](../../docs/policy-server.md#single-tenant-by-design).

### Cleared rather than annotated: JSON Pointer resolution in the OpenAPI importer

Semgrep flags `prototype-pollution-loop` on the `$ref` resolver, where a segment of a
caller-supplied JSON Pointer indexes into the uploaded document.

It was not exploitable, and both halves of that were checked rather than assumed:
`JSON.parse` keeps a literal `"__proto__"` as an ordinary own key instead of setting the
prototype, so a request body cannot produce an object with inherited members; and the
`isRecord` guard rejected the prototype itself. Nothing is written in the loop either, so
"pollution" was never the right name — the concern is the read walking out of the document
and into the runtime.

Changed anyway. The safety rested on the shape of a type guard and on the parser upstream,
neither of which is visible at that call site, so it would not survive a caller that hands
the resolver a hand-built object — a YAML loader that honours `__proto__`, or a test
fixture. Resolution now goes through own enumerable keys only. The regression test pins the
case that actually distinguishes the two (a schema reachable by inheritance), and is
mutation-verified: the earlier version of that test passed against both implementations,
which is worth recording as its own lesson.

### Found by hand, not by a scanner: the SPA fallback masked API errors

Worth recording because it is the class of bug this scan set does not cover. The
distribution carried the conventional single-page-app fallback — rewrite 403 and 404 to
`/index.html` with a `200` — to keep console deep links working.

`CustomErrorResponses` is **distribution-wide, not per-behavior**. It therefore rewrote
errors from the admin API too. Observed against the deployed stack: a request the API
rejected came back as `200 text/html` served from S3, cached for five minutes. An
authorization failure reached the console looking like a success, and the only visible
symptom was `response.json()` failing on markup — no status code to act on, no error to
log, and a five-minute cache making it look intermittent.

Every scanner passed the configuration: it is a valid, extremely common CloudFront
setup. Nothing in Semgrep, Trivy or `cdk-nag` models "this distribution also fronts an
API, so an error-page rewrite is a correctness and security problem." It was found by
sending real authenticated requests to the deployed endpoint and reading the response
headers, which is why that step is in the verification routine and not optional.

The fallback is now removed rather than narrowed — the console keeps view state in React
and is served only from `/`, so there were no deep links to rescue in the first place.
`infra/test/infra.test.ts` asserts no distribution-wide error responses exist.

## Reproducing

```bash
# SAST
semgrep scan --config p/security-audit --config p/secrets --config p/owasp-top-ten \
  --exclude node_modules --exclude dist --exclude cdk.out --exclude coverage \
  server/ console/ infra/

# Dependencies — production posture is the meaningful one
for d in server console infra; do (cd $d && npm audit --omit=dev); done

# Infrastructure as code. Synthesize first: Trivy reads the emitted templates, and a
# stale cdk.out reports findings for resources that no longer exist.
cd infra && rm -rf cdk.out && npx cdk synth --quiet
trivy config cdk.out
trivy config docker/Dockerfile
```

If `trivy` fails with `docker-credential-desktop: executable file not found`, a stale
`credsStore` in `~/.docker/config.json` is blocking its database download. Run with
`DOCKER_CONFIG` pointed at a directory containing `{"auths":{}}`.
