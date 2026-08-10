/**
 * PostgreSQL-backed policy store.
 *
 * Implements the `PolicyStore` interface from `@tolap/store`, so it is a drop-in
 * replacement for `InMemoryPolicyStore` and the SDK's own `resolve()` does the
 * merging. The server does **not** reimplement resolution or merge order: those
 * rules are normative (canonical-enforcement-spec.md, merge table in
 * docs/architecture.md) and a second implementation would be a second thing that
 * can disagree with the spec.
 *
 * Two properties this file exists to protect:
 *
 * 1. **`[]` is not `null`.** Section 3: for an allow-list, absent/`null` means
 *    unrestricted and `[]` means deny everything. Policy bodies therefore go in
 *    and out of a single `jsonb` column untouched -- no column mapping, no
 *    normalization, no "helpful" emptiness coercion anywhere on the path.
 * 2. **Revocation denies.** Section 12: a revoked assignment MUST stop resolving.
 *    Every read path filters `revoked_at IS NULL`, and `toAssignment` also carries
 *    `revokedAt` to the SDK, whose resolver rejects a revoked assignment on its own.
 *    Two independent layers, so neither is the single point of failure it once was.
 *    Revocation is a tombstone only because the audit trail needs the history -- not
 *    because the row stays live.
 *
 * Every listing an HTTP route can reach is paginated (`page*` below) rather than
 * returning the table. One Node process serves both this admin API and
 * `/v1/resolve`, so a listing that materializes an unbounded result set stalls
 * policy resolution for every install -- see `pagination.ts` for the reasoning and
 * the chosen bounds.
 */

import type {
  EffectivePolicy,
  PolicyAssignment,
  PolicyDefinition,
} from "@tolap/core";
import { resolve } from "@tolap/core";
import type {
  IdentityResolver,
  PolicyAuditEvent,
  PolicyStore,
} from "@tolap/store";
import type { Pool } from "pg";
import type { InstallRecord } from "../auth/guards.ts";
import type { SourceManifest } from "../catalog/manifest.ts";
import {
  cursorInteger,
  MAX_INT4,
  cursorTimestamp,
  cursorUuid,
  decodeCursor,
  encodeCursor,
  normalizeLimit,
  timestampCursorSql,
  toPage,
  type Page,
  type PageRequest,
} from "./pagination.ts";

/** Who performed a write, for the audit log. */
export interface Actor {
  readonly id: string;
  readonly kind: "admin" | "install" | "system";
}

const SYSTEM: Actor = { id: "system", kind: "system" };

export interface PolicyVersion {
  readonly name: string;
  readonly versionNo: number;
  readonly policy: PolicyDefinition;
  readonly state: "draft" | "published" | "superseded";
  readonly note: string | null;
  readonly createdBy: string;
  readonly createdAt: Date;
}

/**
 * What the admin API may say about a registered install.
 *
 * Named rather than inlined so the absence of `credentialHash` is a stated shape
 * one place, not a property of one query's projection. The credential is stored
 * only as a hash and must not appear in a listing an auditor can read.
 */
export interface InstallSummary {
  readonly id: string;
  readonly name: string;
  readonly createdAt: Date;
  readonly revokedAt: Date | null;
  readonly lastSeenAt: Date | null;
}

export interface AuditEntry {
  readonly at: Date;
  readonly actor: string;
  readonly actorKind: string;
  readonly action: string;
  readonly targetKind: string | null;
  readonly targetId: string | null;
  readonly detail: unknown;
}

export interface AssignmentRow {
  id: string;
  policy_name: string;
  assignee_type: PolicyAssignment["assignee"]["type"];
  assignee_id: string;
  tenant_id: string | null;
  source_connection_id: string | null;
  active: boolean;
  expires_at: Date | null;
  revoked_at: Date | null;
  granted_by: string;
  granted_at: Date;
  reason: string | null;
}

/**
 * Rebuild the schema-shaped assignment the SDK resolver expects.
 *
 * `expiresAt` is emitted only when set, because the SDK reads absence as "no
 * expiry" and an explicit `undefined` would serialize differently downstream.
 */
export function toAssignment(row: AssignmentRow): PolicyAssignment {
  return {
    version: "1.0",
    policyName: row.policy_name,
    assignee: { type: row.assignee_type, identifier: row.assignee_id },
    scope: {
      ...(row.tenant_id !== null ? { tenantId: row.tenant_id } : {}),
      ...(row.source_connection_id !== null
        ? { sourceConnectionId: row.source_connection_id }
        : {}),
    },
    active: row.active,
    ...(row.expires_at !== null
      ? { expiresAt: row.expires_at.toISOString() }
      : {}),
    // Carried through so the SDK resolver can enforce section 12 itself. The
    // `revoked_at IS NULL` filter on every read path still does the work; this makes
    // the SQL clause defense in depth rather than the only thing standing between a
    // revoked grant and a resolved policy.
    ...(row.revoked_at !== null && row.revoked_at !== undefined
      ? { revokedAt: row.revoked_at.toISOString() }
      : {}),
    audit: {
      grantedBy: row.granted_by,
      grantedAt: row.granted_at.toISOString(),
      reason: row.reason ?? "",
    },
  } as PolicyAssignment;
}

export class PostgresPolicyStore implements PolicyStore {
  private readonly pool: Pool;
  private readonly identityResolver: IdentityResolver;
  private readonly auditListeners: Array<(event: PolicyAuditEvent) => void> = [];

  constructor(pool: Pool, identityResolver: IdentityResolver) {
    this.pool = pool;
    this.identityResolver = identityResolver;
  }

  onAudit(listener: (event: PolicyAuditEvent) => void): void {
    this.auditListeners.push(listener);
  }

  private emit(
    action: PolicyAuditEvent["action"],
    details: Record<string, string>,
  ): void {
    const event: PolicyAuditEvent = {
      timestamp: new Date().toISOString(),
      action,
      details,
    };
    for (const listener of this.auditListeners) listener(event);
  }

  // -- Audit ---------------------------------------------------------------

  /**
   * Append to the durable audit log.
   *
   * Separate from `emit`, which drives the SDK's in-process listener contract.
   * This is the row a compliance reviewer reads months later, so it carries an
   * actor -- something the SDK's own event shape has no field for.
   */
  async record(
    actor: Actor,
    action: string,
    target?: { kind: string; id: string },
    detail?: unknown,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO tolap_audit (actor, actor_kind, action, target_kind, target_id, detail)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
      [
        actor.id,
        actor.kind,
        action,
        target?.kind ?? null,
        target?.id ?? null,
        detail === undefined ? null : JSON.stringify(detail),
      ],
    );
  }

  /**
   * One page of the audit log, newest first.
   *
   * Ordered by `(at DESC, id DESC)` because `at` alone is not unique -- several
   * rows land in the same instant on any write that records more than one event --
   * and a keyset comparison on a non-unique key either skips or repeats the tied
   * rows. `idx_audit_at` covers the ordering; the `id` tiebreak comes free from the
   * primary key.
   *
   * Keyset rather than OFFSET, and here the reason is stronger than performance:
   * this table is append-only and written to constantly, so every insert during a
   * paged walk would shift an OFFSET window and silently drop an entry. Losing an
   * audit entry from a compliance export is not a cosmetic defect.
   */
  async pageAudit(request: PageRequest = {}): Promise<Page<AuditEntry>> {
    const limit = normalizeLimit(request.limit);
    const cursor = decodeCursor(request.cursor, 2);
    const at = timestampCursorSql("at");

    // limit + 1: the extra row is how "there is a next page" is known, rather than
    // inferred from a full page (which hands out a cursor to an empty page).
    const { rows } = await this.pool.query(
      `SELECT at, actor, actor_kind, action, target_kind, target_id, detail,
              ${at} AS cursor_at, id::text AS cursor_id
       FROM tolap_audit
       WHERE $1::timestamptz IS NULL
          OR (at, id) < ($1::timestamptz, $2::bigint)
       ORDER BY at DESC, id DESC
       LIMIT $3`,
      cursor
        ? [cursorTimestamp(cursor[0]!), cursorInteger(cursor[1]!), limit + 1]
        : [null, null, limit + 1],
    );

    return toPage(
      rows,
      limit,
      (r) => ({
        at: r.at,
        actor: r.actor,
        actorKind: r.actor_kind,
        action: r.action,
        targetKind: r.target_kind,
        targetId: r.target_id,
        detail: r.detail,
      }),
      (r) => encodeCursor([r.cursor_at, r.cursor_id]),
    );
  }

  /**
   * The newest `limit` audit entries, without a cursor.
   *
   * A convenience over {@link pageAudit} for in-process callers that want the tail
   * of the log; the HTTP route uses the paged form so a caller can reach older
   * entries. Bounded by the same ceiling -- a helper that could materialize the
   * whole table would reintroduce exactly the failure pagination is here to
   * prevent.
   */
  async listAudit(limit = 200): Promise<AuditEntry[]> {
    return (await this.pageAudit({ limit })).items;
  }

  // -- Definitions ---------------------------------------------------------

  /**
   * Upsert the published definition.
   *
   * Satisfies the SDK interface. Version history is not touched here -- callers
   * that want a version trail use {@link saveDraft} and {@link publish}, which is
   * what the console does.
   */
  async putDefinition(definition: PolicyDefinition): Promise<void> {
    await this.putDefinitionAs(definition, SYSTEM);
  }

  async putDefinitionAs(
    definition: PolicyDefinition,
    actor: Actor,
  ): Promise<void> {
    // policy_json is the whole definition verbatim. The scalar columns beside it
    // exist for listing and ordering only; policy_json is the source of truth, so
    // a mismatch can never change what a policy means.
    await this.pool.query(
      `INSERT INTO tolap_policies (name, version, description, priority, policy_json)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       ON CONFLICT (name) DO UPDATE SET
         version = EXCLUDED.version,
         description = EXCLUDED.description,
         priority = EXCLUDED.priority,
         policy_json = EXCLUDED.policy_json,
         updated_at = now()`,
      [
        definition.name,
        definition.version,
        definition.description ?? null,
        definition.priority ?? 100,
        JSON.stringify(definition),
      ],
    );
    this.emit("definition.put", { name: definition.name });
    await this.record(actor, "definition.put", {
      kind: "policy",
      id: definition.name,
    });
  }

  async getDefinition(name: string): Promise<PolicyDefinition | undefined> {
    const { rows } = await this.pool.query(
      "SELECT policy_json FROM tolap_policies WHERE name = $1",
      [name],
    );
    // pg parses jsonb into a JS value already, so the body is returned as stored.
    // Round-tripping it through JSON.stringify/parse here would be a no-op at
    // best and a place for a coercion bug at worst.
    return rows.length ? (rows[0].policy_json as PolicyDefinition) : undefined;
  }

  /**
   * Every definition, unpaginated. Satisfies the SDK's `PolicyStore` interface,
   * whose signature has no room for a bound.
   *
   * Not reachable from HTTP: `GET /v1/policies` goes through
   * {@link pageDefinitions}. Kept because the interface requires it and an
   * in-process caller that genuinely wants all policies (a bulk export) should not
   * have to loop -- but adding a route that calls this would put an unbounded read
   * back on the request path that also serves policy resolution.
   */
  async listDefinitions(): Promise<PolicyDefinition[]> {
    const { rows } = await this.pool.query(
      "SELECT policy_json FROM tolap_policies ORDER BY name",
    );
    return rows.map((r) => r.policy_json as PolicyDefinition);
  }

  /**
   * One page of definitions, ordered by name.
   *
   * `name` is the primary key, so it is unique and the keyset comparison needs no
   * tiebreaker. The comparison uses the same collation as the `ORDER BY`, which is
   * what makes "everything after this name" and "the next rows in order" the same
   * set -- a cursor compared under a different collation would skip rows.
   *
   * `policy_json` is selected and returned exactly as stored. Nothing on this path
   * inspects, rebuilds or normalizes the body: section 3 makes `[]` and `null`
   * opposites for an allow-list, so a page that "tidied" an empty array would turn
   * deny-everything into unrestricted.
   */
  async pageDefinitions(request: PageRequest = {}): Promise<Page<PolicyDefinition>> {
    const limit = normalizeLimit(request.limit);
    const cursor = decodeCursor(request.cursor, 1);

    const { rows } = await this.pool.query(
      `SELECT name, policy_json FROM tolap_policies
       WHERE $1::text IS NULL OR name > $1::text
       ORDER BY name
       LIMIT $2`,
      [cursor ? cursor[0] : null, limit + 1],
    );

    return toPage(
      rows,
      limit,
      (r) => r.policy_json as PolicyDefinition,
      (r) => encodeCursor([r.name]),
    );
  }

  async deleteDefinition(name: string): Promise<boolean> {
    return this.deleteDefinitionAs(name, SYSTEM);
  }

  async deleteDefinitionAs(name: string, actor: Actor): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      "DELETE FROM tolap_policies WHERE name = $1",
      [name],
    );
    const deleted = (rowCount ?? 0) > 0;
    if (deleted) {
      this.emit("definition.delete", { name });
      await this.record(actor, "definition.delete", {
        kind: "policy",
        id: name,
      });
    }
    return deleted;
  }

  // -- Versioning ----------------------------------------------------------

  /** Append a draft version without changing what is live. */
  async saveDraft(
    definition: PolicyDefinition,
    actor: Actor,
    note?: string,
  ): Promise<number> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const { rows } = await client.query(
        `SELECT COALESCE(MAX(version_no), 0) + 1 AS next
         FROM tolap_policy_versions WHERE name = $1`,
        [definition.name],
      );
      const versionNo = Number(rows[0].next);
      await client.query(
        `INSERT INTO tolap_policy_versions
           (name, version_no, policy_json, state, note, created_by)
         VALUES ($1, $2, $3::jsonb, 'draft', $4, $5)`,
        [
          definition.name,
          versionNo,
          JSON.stringify(definition),
          note ?? null,
          actor.id,
        ],
      );
      await client.query("COMMIT");
      await this.record(
        actor,
        "version.draft",
        { kind: "policy", id: definition.name },
        { versionNo },
      );
      return versionNo;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Publish a version: it becomes live and the previous live one is superseded.
   *
   * One transaction, because a half-applied publish would leave either two
   * published versions (which the unique index refuses) or none.
   */
  async publish(
    name: string,
    versionNo: number,
    actor: Actor,
  ): Promise<PolicyDefinition> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      const { rows } = await client.query(
        `SELECT policy_json FROM tolap_policy_versions
         WHERE name = $1 AND version_no = $2 FOR UPDATE`,
        [name, versionNo],
      );
      if (rows.length === 0) {
        throw new Error(`policy '${name}' has no version ${versionNo}`);
      }
      const policy = rows[0].policy_json as PolicyDefinition;

      await client.query(
        `UPDATE tolap_policy_versions SET state = 'superseded'
         WHERE name = $1 AND state = 'published'`,
        [name],
      );
      await client.query(
        `UPDATE tolap_policy_versions SET state = 'published'
         WHERE name = $1 AND version_no = $2`,
        [name, versionNo],
      );
      await client.query(
        `INSERT INTO tolap_policies
           (name, version, description, priority, policy_json, version_no)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6)
         ON CONFLICT (name) DO UPDATE SET
           version = EXCLUDED.version,
           description = EXCLUDED.description,
           priority = EXCLUDED.priority,
           policy_json = EXCLUDED.policy_json,
           version_no = EXCLUDED.version_no,
           updated_at = now()`,
        [
          name,
          policy.version,
          policy.description ?? null,
          policy.priority ?? 100,
          JSON.stringify(policy),
          versionNo,
        ],
      );

      await client.query("COMMIT");
      await this.record(
        actor,
        "version.publish",
        { kind: "policy", id: name },
        { versionNo },
      );
      return policy;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Roll back by re-publishing an earlier version's body as a **new** version.
   *
   * Deliberately not a state flip on the old row: history stays append-only, so
   * "we rolled back to what version 3 said" is visible as its own event rather
   * than looking like version 3 was live all along.
   */
  async rollback(
    name: string,
    toVersionNo: number,
    actor: Actor,
  ): Promise<number> {
    const { rows } = await this.pool.query(
      `SELECT policy_json FROM tolap_policy_versions
       WHERE name = $1 AND version_no = $2`,
      [name, toVersionNo],
    );
    if (rows.length === 0) {
      throw new Error(`policy '${name}' has no version ${toVersionNo}`);
    }
    const policy = rows[0].policy_json as PolicyDefinition;

    const newVersion = await this.saveDraft(
      policy,
      actor,
      `rollback to version ${toVersionNo}`,
    );
    await this.publish(name, newVersion, actor);
    await this.record(
      actor,
      "version.rollback",
      { kind: "policy", id: name },
      { from: toVersionNo, newVersionNo: newVersion },
    );
    return newVersion;
  }

  /**
   * One page of a policy's version history, newest first.
   *
   * Bounded even though this is scoped to a single policy. The table is
   * append-only and every publish, rollback and saved draft adds a row carrying a
   * full policy body, so an actively edited policy's history is one of the largest
   * payloads this API can produce -- unbounded by anything except how often someone
   * pressed save.
   *
   * `(name, version_no)` is the primary key, so within one name `version_no` is
   * unique and needs no tiebreaker. `idx_policy_versions_name` matches the
   * ordering.
   */
  async pageVersions(
    name: string,
    request: PageRequest = {},
  ): Promise<Page<PolicyVersion>> {
    const limit = normalizeLimit(request.limit);
    const cursor = decodeCursor(request.cursor, 1);

    const { rows } = await this.pool.query(
      `SELECT name, version_no, policy_json, state, note, created_by, created_at
       FROM tolap_policy_versions
       WHERE name = $1
         AND ($2::int IS NULL OR version_no < $2::int)
       ORDER BY version_no DESC
       LIMIT $3`,
      // int4, not bigint: `version_no` is an `integer` column, so a value above 2^31-1
      // would still overflow its cast even though it fits a bigint.
      [name, cursor ? cursorInteger(cursor[0]!, MAX_INT4) : null, limit + 1],
    );

    return toPage(
      rows,
      limit,
      (r) => ({
        name: r.name,
        versionNo: r.version_no,
        policy: r.policy_json as PolicyDefinition,
        state: r.state,
        note: r.note,
        createdBy: r.created_by,
        createdAt: r.created_at,
      }),
      (r) => encodeCursor([String(r.version_no)]),
    );
  }

  /** The newest page of versions. See {@link pageVersions} for the bound. */
  async listVersions(name: string, limit?: number): Promise<PolicyVersion[]> {
    return (await this.pageVersions(name, { ...(limit !== undefined ? { limit } : {}) })).items;
  }

  // -- Assignments ---------------------------------------------------------

  async putAssignment(assignment: PolicyAssignment): Promise<void> {
    await this.putAssignmentAs(assignment, SYSTEM);
  }

  async putAssignmentAs(
    assignment: PolicyAssignment,
    actor: Actor,
  ): Promise<void> {
    const scope = assignment.scope ?? {};
    // Replace the live row for this (policy, assignee, scope) rather than
    // accumulating duplicates, matching InMemoryPolicyStore's behavior. The
    // partial unique index is what makes ON CONFLICT well defined here.
    await this.pool.query(
      `INSERT INTO tolap_assignments
         (policy_name, assignee_type, assignee_id, tenant_id, source_connection_id,
          active, expires_at, granted_by, reason)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (policy_name, assignee_type, assignee_id,
                    COALESCE(tenant_id, ''), COALESCE(source_connection_id, ''))
         WHERE revoked_at IS NULL
         DO UPDATE SET
           active = EXCLUDED.active,
           expires_at = EXCLUDED.expires_at,
           granted_by = EXCLUDED.granted_by,
           granted_at = now(),
           reason = EXCLUDED.reason`,
      [
        assignment.policyName,
        assignment.assignee.type,
        assignment.assignee.identifier,
        scope.tenantId ?? null,
        scope.sourceConnectionId ?? null,
        assignment.active,
        assignment.expiresAt ?? null,
        assignment.audit?.grantedBy ?? actor.id,
        assignment.audit?.reason ?? null,
      ],
    );
    this.emit("assignment.put", {
      policyName: assignment.policyName,
      assignee: assignment.assignee.identifier,
    });
    await this.record(
      actor,
      "assignment.put",
      { kind: "assignment", id: assignment.policyName },
      { assignee: assignment.assignee.identifier },
    );
  }

  /**
   * Every live assignment, unpaginated. Required by the SDK's `PolicyStore`
   * interface, which has no parameter for a bound.
   *
   * Not reachable from HTTP -- `GET /v1/assignments` uses
   * {@link pageAssignments}. Assignments are the table most likely to grow without
   * anyone watching (one row per grant, per assignee, per scope), so this is the
   * one to keep off the request path.
   */
  async listAssignments(
    assigneeIdentifier?: string,
  ): Promise<PolicyAssignment[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM tolap_assignments
       WHERE revoked_at IS NULL
         AND ($1::text IS NULL OR assignee_id = $1)
       ORDER BY granted_at DESC`,
      [assigneeIdentifier ?? null],
    );
    return (rows as AssignmentRow[]).map(toAssignment);
  }

  /**
   * One page of live assignments, newest grant first.
   *
   * `revoked_at IS NULL` is on this path as it is on every other read path. Spec
   * section 12 requires a revoked assignment to stop resolving, and a listing that
   * showed revoked rows as live would make an administrator believe access exists
   * that does not -- or, worse, re-grant around it.
   *
   * Keyset on `(granted_at, id)`: `granted_at` is not unique (a bulk grant script
   * writes many rows in one instant) and `id` is the primary key, so the pair is.
   * One honest caveat: `granted_at` is *rewritten* when an existing grant is
   * updated in place (see `putAssignmentAs`), so a row edited mid-walk can move
   * ahead of the cursor and be missed on this pass. That is a property of the
   * ordering, not of keyset -- an OFFSET walk would shift every later row instead,
   * which is worse -- and the row is not lost, it appears on the next walk.
   */
  async pageAssignments(
    assigneeIdentifier: string | undefined,
    request: PageRequest = {},
  ): Promise<Page<PolicyAssignment>> {
    const limit = normalizeLimit(request.limit);
    const cursor = decodeCursor(request.cursor, 2);
    const grantedAt = timestampCursorSql("granted_at");

    const { rows } = await this.pool.query(
      `SELECT *, ${grantedAt} AS cursor_granted_at, id::text AS cursor_id
       FROM tolap_assignments
       WHERE revoked_at IS NULL
         AND ($1::text IS NULL OR assignee_id = $1)
         AND ($2::timestamptz IS NULL
              OR (granted_at, id) < ($2::timestamptz, $3::uuid))
       ORDER BY granted_at DESC, id DESC
       LIMIT $4`,
      [
        assigneeIdentifier ?? null,
        cursor ? cursorTimestamp(cursor[0]!) : null,
        cursor ? cursorUuid(cursor[1]!) : null,
        limit + 1,
      ],
    );

    return toPage(
      rows as Array<AssignmentRow & { cursor_granted_at: string; cursor_id: string }>,
      limit,
      toAssignment,
      (r) => encodeCursor([r.cursor_granted_at, r.cursor_id]),
    );
  }

  async deleteAssignment(
    policyName: string,
    assigneeIdentifier: string,
  ): Promise<boolean> {
    return this.revokeAssignment(policyName, assigneeIdentifier, SYSTEM);
  }

  /**
   * Revoke every live assignment of a policy to an assignee.
   *
   * A tombstone, so the grant remains in the record -- but every resolution path
   * filters `revoked_at IS NULL`, so the assignment genuinely stops applying.
   * Spec section 12 calls the alternative (recording the revocation while still
   * resolving it) a fail-open control with a misleading audit trail.
   */
  async revokeAssignment(
    policyName: string,
    assigneeIdentifier: string,
    actor: Actor,
  ): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      `UPDATE tolap_assignments SET revoked_at = now()
       WHERE policy_name = $1 AND assignee_id = $2 AND revoked_at IS NULL`,
      [policyName, assigneeIdentifier],
    );
    const revoked = (rowCount ?? 0) > 0;
    if (revoked) {
      this.emit("assignment.delete", {
        policyName,
        assignee: assigneeIdentifier,
      });
      await this.record(
        actor,
        "assignment.revoke",
        { kind: "assignment", id: policyName },
        { assignee: assigneeIdentifier },
      );
    }
    return revoked;
  }

  // -- Resolution ----------------------------------------------------------

  /**
   * Resolve the effective policy for a user, tenant and source.
   *
   * Loads the candidate assignments and definitions, then hands them to the
   * SDK's `resolve()`. Assignment filtering by expiry, scope and source pattern,
   * and the whole merge, happen there -- deliberately not in SQL. A WHERE clause
   * that reimplemented `sourcePatterns` globbing (section 10: `*` must not cross
   * `:`, matching is case-insensitive, and an empty list means *every* source)
   * would be a second implementation of a normative rule.
   */
  async resolvePolicy(
    userId: string,
    tenantId: string,
    sourceConnectionId: string,
  ): Promise<EffectivePolicy> {
    const groups = await this.identityResolver.getGroups(userId);
    const roles = await this.identityResolver.getRoles(userId);

    // Narrow to assignments that could possibly apply to this principal. Group
    // and role membership is expanded here because the SDK resolver takes
    // callbacks; passing the whole table instead would work but scales badly.
    //
    // `revoked_at IS NULL` narrows the read, and `toAssignment` also carries
    // `revokedAt` through to the SDK, whose resolver rejects a revoked assignment
    // independently. Both layers implement spec section 12, so dropping either one
    // alone no longer fails open -- which is why a mutation removing this clause is
    // correctly not caught by a behavioral test. It stays because filtering in SQL
    // is cheaper than resolving rows that cannot apply.
    //
    // `active = true` is the same shape of defense in depth: the SDK resolver already
    // rejects an inactive assignment.
    const { rows } = await this.pool.query(
      `SELECT a.* FROM tolap_assignments a
       WHERE a.revoked_at IS NULL
         AND a.active = true
         AND (
           (a.assignee_type IN ('user', 'serviceAccount') AND a.assignee_id = $1)
           OR (a.assignee_type = 'group' AND a.assignee_id = ANY($2::text[]))
           OR (a.assignee_type = 'role'  AND a.assignee_id = ANY($3::text[]))
         )`,
      [userId, groups, roles],
    );

    const assignments = (rows as AssignmentRow[]).map(toAssignment);

    const definitions = new Map<string, PolicyDefinition>();
    if (assignments.length > 0) {
      const names = [...new Set(assignments.map((a) => a.policyName))];
      const { rows: policyRows } = await this.pool.query(
        "SELECT name, policy_json FROM tolap_policies WHERE name = ANY($1::text[])",
        [names],
      );
      for (const row of policyRows) {
        definitions.set(row.name, row.policy_json as PolicyDefinition);
      }
    }

    this.emit("policy.resolve", { userId, tenantId, sourceConnectionId });

    return resolve(
      userId,
      tenantId,
      sourceConnectionId,
      assignments,
      definitions,
      () => groups,
      () => roles,
    );
  }

  // -- Source catalog ------------------------------------------------------
  //
  // Authoring convenience only. Nothing here is read at resolve time, so a stale
  // or wrong catalog cannot change what a policy permits -- it can only mislead
  // the person authoring one.

  async putSourceAs(
    manifest: SourceManifest,
    importedFrom: string,
    actor: Actor,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO tolap_sources
         (source_connection_id, category, display_name, manifest_json, imported_from)
       VALUES ($1, $2, $3, $4::jsonb, $5)
       ON CONFLICT (source_connection_id) DO UPDATE SET
         category = EXCLUDED.category,
         display_name = EXCLUDED.display_name,
         manifest_json = EXCLUDED.manifest_json,
         imported_from = EXCLUDED.imported_from,
         updated_at = now()`,
      [
        manifest.sourceConnectionId,
        manifest.category,
        manifest.displayName ?? null,
        JSON.stringify(manifest),
        importedFrom,
      ],
    );
    await this.record(
      actor,
      "catalog.put",
      { kind: "source", id: manifest.sourceConnectionId },
      {
        importedFrom,
        objects: manifest.objects.length,
        endpoints: manifest.endpoints.length,
      },
    );
  }

  async getSource(id: string): Promise<SourceManifest | undefined> {
    const { rows } = await this.pool.query(
      "SELECT manifest_json FROM tolap_sources WHERE source_connection_id = $1",
      [id],
    );
    return rows.length ? (rows[0].manifest_json as SourceManifest) : undefined;
  }

  /**
   * One page of source manifests, ordered by connection id (the primary key, so
   * unique -- no tiebreaker needed).
   *
   * The row count here is small; the *payload* is not. A manifest holds every
   * object, field, endpoint and tag of a data source, and an imported `pg_dump` of
   * a wide schema is megabytes on its own. Twenty of those serialized into one
   * response is the memory cliff this bound exists for, which is why the ceiling is
   * a row count on this endpoint too rather than being skipped as unnecessary.
   */
  async pageSources(request: PageRequest = {}): Promise<Page<SourceManifest>> {
    const limit = normalizeLimit(request.limit);
    const cursor = decodeCursor(request.cursor, 1);

    const { rows } = await this.pool.query(
      `SELECT source_connection_id, manifest_json FROM tolap_sources
       WHERE $1::text IS NULL OR source_connection_id > $1::text
       ORDER BY source_connection_id
       LIMIT $2`,
      [cursor ? cursor[0] : null, limit + 1],
    );

    return toPage(
      rows,
      limit,
      (r) => r.manifest_json as SourceManifest,
      (r) => encodeCursor([r.source_connection_id]),
    );
  }

  /** Every source manifest. In-process callers only; the route pages. */
  async listSources(): Promise<SourceManifest[]> {
    const { rows } = await this.pool.query(
      "SELECT manifest_json FROM tolap_sources ORDER BY source_connection_id",
    );
    return rows.map((r) => r.manifest_json as SourceManifest);
  }

  async deleteSourceAs(id: string, actor: Actor): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      "DELETE FROM tolap_sources WHERE source_connection_id = $1",
      [id],
    );
    const deleted = (rowCount ?? 0) > 0;
    if (deleted) {
      await this.record(actor, "catalog.delete", { kind: "source", id });
    }
    return deleted;
  }

  // -- Installs ------------------------------------------------------------

  async getInstall(id: string): Promise<InstallRecord | undefined> {
    const { rows } = await this.pool.query(
      "SELECT id, credential_hash, revoked_at FROM tolap_installs WHERE id = $1",
      [id],
    );
    if (rows.length === 0) return undefined;
    return {
      id: rows[0].id,
      credentialHash: rows[0].credential_hash,
      revokedAt: rows[0].revoked_at,
    };
  }

  async createInstall(
    id: string,
    name: string,
    credentialHash: string,
    actor: Actor,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO tolap_installs (id, name, credential_hash, created_by)
       VALUES ($1, $2, $3, $4)`,
      [id, name, credentialHash, actor.id],
    );
    await this.record(actor, "install.register", { kind: "install", id }, { name });
  }

  async revokeInstall(id: string, actor: Actor): Promise<boolean> {
    const { rowCount } = await this.pool.query(
      "UPDATE tolap_installs SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
      [id],
    );
    const revoked = (rowCount ?? 0) > 0;
    if (revoked) {
      await this.record(actor, "install.revoke", { kind: "install", id });
    }
    return revoked;
  }

  /**
   * One page of registered installs, newest first.
   *
   * Never selects `credential_hash`. The column is deliberately absent from the
   * projection rather than dropped in the mapping below, so a later `SELECT *`
   * refactor cannot leak it into a response an auditor can read -- the listing is
   * asserted not to contain it.
   *
   * Keyset on `(created_at, id)`: `created_at` defaults to `now()` and a seeding
   * script registers several installs in one transaction, all sharing an instant,
   * so the `id` primary key is the tiebreaker that makes the key unique.
   */
  async pageInstalls(request: PageRequest = {}): Promise<Page<InstallSummary>> {
    const limit = normalizeLimit(request.limit);
    const cursor = decodeCursor(request.cursor, 2);
    const createdAt = timestampCursorSql("created_at");

    const { rows } = await this.pool.query(
      `SELECT id, name, created_at, revoked_at, last_seen_at,
              ${createdAt} AS cursor_created_at
       FROM tolap_installs
       WHERE $1::timestamptz IS NULL
          OR (created_at, id) < ($1::timestamptz, $2::text)
       ORDER BY created_at DESC, id DESC
       LIMIT $3`,
      cursor
        ? [cursorTimestamp(cursor[0]!), cursor[1], limit + 1]
        : [null, null, limit + 1],
    );

    return toPage(
      rows,
      limit,
      (r) => ({
        id: r.id,
        name: r.name,
        createdAt: r.created_at,
        revokedAt: r.revoked_at,
        lastSeenAt: r.last_seen_at,
      }),
      (r) => encodeCursor([r.cursor_created_at, r.id]),
    );
  }

  /** The newest page of installs. See {@link pageInstalls} for the bound. */
  async listInstalls(limit?: number): Promise<InstallSummary[]> {
    return (await this.pageInstalls({ ...(limit !== undefined ? { limit } : {}) })).items;
  }

  async touchInstall(id: string): Promise<void> {
    await this.pool.query(
      "UPDATE tolap_installs SET last_seen_at = now() WHERE id = $1",
      [id],
    );
  }
}
