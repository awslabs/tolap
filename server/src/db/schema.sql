-- TOLAP Policy Server schema.
--
-- Column names for tolap_policies and tolap_assignments deliberately match the
-- shape already published in docs/architecture.md and README.md. Those tables are
-- documented public API for anyone who wrote a store against the docs, so the
-- names are kept even where a fresh design would pick differently.
--
-- Policy bodies are stored as jsonb and never decomposed into columns. That is a
-- correctness requirement, not a convenience: canonical-enforcement-spec.md
-- section 3 makes `[]` and `null` mean opposite things for an allow-list --
-- `null`/absent is unrestricted, `[]` denies everything -- and a normalized child
-- table cannot represent "empty list" distinctly from "no rows". Collapsing them
-- turns the most restrictive policy expressible into no restriction at all.
-- Verified: jsonb round-trips absent, null, and [] as three distinct states.

CREATE TABLE IF NOT EXISTS tolap_policies (
    name        TEXT PRIMARY KEY,
    version     TEXT        NOT NULL DEFAULT '1.0',
    description TEXT,
    priority    INTEGER     NOT NULL DEFAULT 100,
    policy_json JSONB       NOT NULL,
    -- Which row of tolap_policy_versions is currently live. Not a foreign key:
    -- the version rows reference this table, and a circular FK pair would make
    -- both inserts require a deferred constraint for no benefit.
    version_no  INTEGER     NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE tolap_policies IS
    'Currently published policy definitions. One row per policy name; history lives in tolap_policy_versions.';

-- Immutable version history. Rows are never updated in place: publishing an
-- older version appends a new version_no rather than mutating the old row, so the
-- table is an append-only record of what was published when and by whom. That is
-- what makes rollback auditable rather than a silent overwrite.
CREATE TABLE IF NOT EXISTS tolap_policy_versions (
    name        TEXT        NOT NULL,
    version_no  INTEGER     NOT NULL,
    policy_json JSONB       NOT NULL,
    state       TEXT        NOT NULL
                CHECK (state IN ('draft', 'published', 'superseded')),
    note        TEXT,
    created_by  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (name, version_no)
);

-- At most one published version per policy. A second published row would make
-- "which policy is live" ambiguous, and resolution would depend on row order.
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_versions_one_published
    ON tolap_policy_versions (name)
    WHERE state = 'published';

CREATE INDEX IF NOT EXISTS idx_policy_versions_name
    ON tolap_policy_versions (name, version_no DESC);

CREATE TABLE IF NOT EXISTS tolap_assignments (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name          TEXT NOT NULL REFERENCES tolap_policies(name) ON DELETE CASCADE,
    -- Matches the schema's assignee.type enum.
    assignee_type        TEXT NOT NULL
                         CHECK (assignee_type IN ('user', 'group', 'role', 'serviceAccount')),
    assignee_id          TEXT NOT NULL,
    tenant_id            TEXT,
    source_connection_id TEXT,
    active               BOOLEAN NOT NULL DEFAULT true,
    expires_at           TIMESTAMPTZ,
    -- Revocation is a tombstone so the audit trail survives, but resolution
    -- filters on it. Spec section 12: revoking MUST make the assignment stop
    -- resolving -- recording a revocation while still resolving the assignment is
    -- a fail-open control with a misleading audit trail.
    revoked_at           TIMESTAMPTZ,
    granted_by           TEXT NOT NULL,
    granted_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason               TEXT
);

-- One live assignment per (policy, assignee, scope). Partial so that revoked rows
-- accumulate as history without blocking a later re-grant of the same triple.
-- COALESCE because NULL never equals NULL in a unique index, which would
-- otherwise let unlimited duplicate tenant-wide assignments through.
CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_unique_live
    ON tolap_assignments (
        policy_name, assignee_type, assignee_id,
        COALESCE(tenant_id, ''), COALESCE(source_connection_id, '')
    )
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_assignments_lookup
    ON tolap_assignments (assignee_id, assignee_type)
    WHERE revoked_at IS NULL AND active = true;

CREATE INDEX IF NOT EXISTS idx_assignments_policy
    ON tolap_assignments (policy_name);

-- Source catalog: the structure of a data source, used to populate the console's
-- pickers so an administrator selects a real column instead of typing one.
--
-- Authoring convenience ONLY. Enforcement reads the signed policy and never this
-- table -- a catalog that could influence an access decision would be a new trust
-- dependency, and a stale catalog would then silently change what a policy means.
CREATE TABLE IF NOT EXISTS tolap_sources (
    source_connection_id TEXT PRIMARY KEY,
    -- Parsed from the id and stored for filtering. Constrained to the four
    -- connector categories (connector-spec section 1); adding one is a breaking
    -- change there, so it is a CHECK here rather than free text.
    category             TEXT NOT NULL CHECK (category IN ('db', 'api', 'kb', 'storage')),
    display_name         TEXT,
    manifest_json        JSONB NOT NULL,
    imported_from        TEXT,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Registered remote installs. Each holds one credential so the audit log can name
-- which install pulled a policy, and so one can be revoked alone.
CREATE TABLE IF NOT EXISTS tolap_installs (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    -- SHA-256 of the issued credential. The credential itself is shown once at
    -- registration and never stored, so a database disclosure yields nothing
    -- usable against the resolve port.
    credential_hash TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ
);

-- Append-only audit log. No UPDATE or DELETE path exists in the server.
CREATE TABLE IF NOT EXISTS tolap_audit (
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Cognito sub for an administrator, install id for a remote install.
    actor       TEXT NOT NULL,
    actor_kind  TEXT NOT NULL CHECK (actor_kind IN ('admin', 'install', 'system')),
    action      TEXT NOT NULL,
    target_kind TEXT,
    target_id   TEXT,
    detail      JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON tolap_audit (at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target ON tolap_audit (target_kind, target_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON tolap_audit (actor, at DESC);
