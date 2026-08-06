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
 *    Every read path filters `revoked_at IS NULL`, and revocation is a tombstone
 *    only because the audit trail needs the history -- not because the row stays
 *    live.
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

export interface AuditEntry {
  readonly at: Date;
  readonly actor: string;
  readonly actorKind: string;
  readonly action: string;
  readonly targetKind: string | null;
  readonly targetId: string | null;
  readonly detail: unknown;
}

interface AssignmentRow {
  id: string;
  policy_name: string;
  assignee_type: PolicyAssignment["assignee"]["type"];
  assignee_id: string;
  tenant_id: string | null;
  source_connection_id: string | null;
  active: boolean;
  expires_at: Date | null;
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
function toAssignment(row: AssignmentRow): PolicyAssignment {
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

  async listAudit(limit = 200): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      `SELECT at, actor, actor_kind, action, target_kind, target_id, detail
       FROM tolap_audit ORDER BY at DESC, id DESC LIMIT $1`,
      [Math.min(Math.max(limit, 1), 1000)],
    );
    return rows.map((r) => ({
      at: r.at,
      actor: r.actor,
      actorKind: r.actor_kind,
      action: r.action,
      targetKind: r.target_kind,
      targetId: r.target_id,
      detail: r.detail,
    }));
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

  async listDefinitions(): Promise<PolicyDefinition[]> {
    const { rows } = await this.pool.query(
      "SELECT policy_json FROM tolap_policies ORDER BY name",
    );
    return rows.map((r) => r.policy_json as PolicyDefinition);
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

  async listVersions(name: string): Promise<PolicyVersion[]> {
    const { rows } = await this.pool.query(
      `SELECT name, version_no, policy_json, state, note, created_by, created_at
       FROM tolap_policy_versions WHERE name = $1 ORDER BY version_no DESC`,
      [name],
    );
    return rows.map((r) => ({
      name: r.name,
      versionNo: r.version_no,
      policy: r.policy_json as PolicyDefinition,
      state: r.state,
      note: r.note,
      createdBy: r.created_by,
      createdAt: r.created_at,
    }));
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
    // `revoked_at IS NULL` is load-bearing and has no backstop. Revocation is a
    // server-only concept -- `PolicyAssignment` has no such field and the SDK
    // resolver has never heard of it -- so this clause is the *only* thing
    // implementing spec section 12. Removing it fails open silently: the audit log
    // would still show the revocation while the assignment kept resolving, which
    // is the exact fail-open section 12 calls out by name.
    //
    // `active = true` is different: the SDK resolver already rejects an inactive
    // assignment (resolution.ts:238), so this is defense in depth and a mutation
    // that drops it is correctly not caught by a behavioral test.
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

  async listInstalls(): Promise<
    Array<{
      id: string;
      name: string;
      createdAt: Date;
      revokedAt: Date | null;
      lastSeenAt: Date | null;
    }>
  > {
    const { rows } = await this.pool.query(
      `SELECT id, name, created_at, revoked_at, last_seen_at
       FROM tolap_installs ORDER BY created_at DESC`,
    );
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      createdAt: r.created_at,
      revokedAt: r.revoked_at,
      lastSeenAt: r.last_seen_at,
    }));
  }

  async touchInstall(id: string): Promise<void> {
    await this.pool.query(
      "UPDATE tolap_installs SET last_seen_at = now() WHERE id = $1",
      [id],
    );
  }
}
