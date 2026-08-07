# The policy server image.
#
# Build context is the REPOSITORY ROOT, not server/: the server imports
# @tolap/core and @tolap/store through `file:` links into sdk/typescript, and a
# context scoped to server/ cannot see them.

FROM public.ecr.aws/docker/library/node:22-alpine AS base
WORKDIR /app

# The RDS root CA bundle, so the connection can use sslmode=verify-full instead of
# encrypting without checking who is on the other end. Aurora's certificate chains to
# an Amazon CA that is not in the image's default trust store, so without this the
# only options are "verify nothing" or "fail to connect".
#
# Downloaded at build time and pinned by nothing but the URL, which is the practical
# state of the art for this bundle; AWS rotates it in place and publishes no digest.
ADD https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /app/certs/rds-global-bundle.pem
RUN chmod 0444 /app/certs/rds-global-bundle.pem

# The SDK packages first, because the server's node_modules symlinks point at them
# and npm ci needs the targets present.
COPY sdk/typescript/package.json sdk/typescript/package-lock.json ./sdk/typescript/
COPY sdk/typescript/tsconfig.base.json ./sdk/typescript/
COPY sdk/typescript/packages ./sdk/typescript/packages

# @tolap/core and @tolap/store resolve through their dist/ directories, so build
# them before the server can run against them.
#
# `tsc --build`, not `tsc -p`. `core` is a **composite** project and `store` declares
# a project reference to it, so a plain `-p` build of `store` checks whether core's
# emitted .d.ts is up to date with core's sources -- and decides it is not, because the
# build context carries no .tsbuildinfo. That fails with TS6305 ("has not been built
# from source file") plus a cascade of implicit-any errors from the missing types.
#
# It only shows up in a clean context: a developer's tree has stale .tsbuildinfo lying
# around that makes `-p` appear to work. `--build` builds the reference graph in
# dependency order and writes the build info the check wants, so it behaves the same
# in both places.
WORKDIR /app/sdk/typescript
RUN npm ci --ignore-scripts \
 && npx tsc --build packages/core/tsconfig.json \
 && npx tsc --build packages/store/tsconfig.json

WORKDIR /app/server
COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY server/src ./src
COPY server/tsconfig.json ./

WORKDIR /app
# The schemas are read at runtime by the validator, from ../../schema relative to
# server/src. They are the normative artifact, so they are copied rather than
# vendored into the server package.
COPY schema ./schema

COPY infra/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Run unprivileged. The node image ships a `node` user; the app needs no write
# access anywhere in the image.
USER node

EXPOSE 8080 8081

# Mirrors the check in the ECS task definition, so the image is self-describing: run it
# outside ECS and it still reports whether it is serving. Hits the admin listener on
# loopback, which requires no credential (/health is the one unauthenticated route).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
