#!/bin/sh
# Apply the schema, then run the server.
#
# Deliberately thin. An earlier version of this script assembled a DATABASE_URL from
# individually-injected secret parts, which meant the password passed through the
# task environment and was fixed for the task's lifetime -- so a rotated credential
# was not picked up until a restart. The server now reads the database secret from
# Secrets Manager itself, per connection (see server/src/db/credentials.ts), and this
# script only needs to name it.
#
# The signing key is still injected, because rotating it is a deliberate
# configuration change (add a kid, flip the active one) that produces a new task
# definition anyway.

set -eu

# Either the deployed form (a secret the server reads) or the local one (a full
# connection string). Requiring one of the two, rather than defaulting, keeps a
# misconfigured task from starting and then failing every connection.
if [ -z "${DATABASE_SECRET_ID:-}" ] && [ -z "${DATABASE_URL:-}" ]; then
  echo "entrypoint: set DATABASE_SECRET_ID (deployed) or DATABASE_URL (local); refusing to start" >&2
  exit 1
fi

# Checked directly rather than through an indirect-expansion helper. The helper used
# `eval` to dereference a variable name; with exactly one call site and a literal name
# it was never reachable by external input, but a shell script with no `eval` at all is
# a shorter thing to audit.
if [ -z "${TOLAP_SIGNING_SECRET:-}" ]; then
  echo "entrypoint: TOLAP_SIGNING_SECRET is empty; refusing to start" >&2
  exit 1
fi

# The keyring form is `kid:secret`. `initial` is the kid the first deployment signs
# with; rotating means adding a second pair and flipping TOLAP_ACTIVE_KID, which the
# server reads directly -- see docs/policy-server.md.
if [ -z "${TOLAP_SIGNING_KEYS:-}" ]; then
  export TOLAP_SIGNING_KEYS="initial:${TOLAP_SIGNING_SECRET}"
fi

# Unset the raw value so it is not in the environment of the server process or
# anything it spawns. The composed keyring above is what the server reads.
unset TOLAP_SIGNING_SECRET

cd /app/server

# Idempotent: schema.sql is CREATE ... IF NOT EXISTS throughout, so every task start
# converges rather than needing a separate migration job. Applied inside a
# transaction, so a partial schema is never left behind. Uses the same pool builder as
# the server, so it reads the same secret the same way.
echo "entrypoint: applying schema"
node --experimental-strip-types src/db/migrate.ts

echo "entrypoint: starting server"
exec node --experimental-strip-types src/index.ts
