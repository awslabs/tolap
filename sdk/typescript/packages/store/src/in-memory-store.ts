/**
 * TOLAP In-Memory Policy Store
 *
 * A simple Map-based implementation for testing and development.
 */

import type {
  PolicyDefinition,
  PolicyAssignment,
  EffectivePolicy,
} from "@aws/tolap-core";
import { resolve } from "@aws/tolap-core";
import type {
  PolicyStore,
  IdentityResolver,
  PolicyAuditEvent,
} from "./types.js";

export class InMemoryPolicyStore implements PolicyStore {
  private definitions = new Map<string, PolicyDefinition>();
  private assignments: PolicyAssignment[] = [];
  private auditListeners: Array<(event: PolicyAuditEvent) => void> = [];
  private identityResolver: IdentityResolver;

  constructor(identityResolver?: IdentityResolver) {
    this.identityResolver = identityResolver ?? {
      getGroups: async () => [],
      getRoles: async () => [],
    };
  }

  // -----------------------------------------------------------------------
  // Audit
  // -----------------------------------------------------------------------

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
    for (const listener of this.auditListeners) {
      listener(event);
    }
  }

  // -----------------------------------------------------------------------
  // Definitions
  // -----------------------------------------------------------------------

  async putDefinition(definition: PolicyDefinition): Promise<void> {
    this.definitions.set(definition.name, definition);
    this.emit("definition.put", { name: definition.name });
  }

  async getDefinition(name: string): Promise<PolicyDefinition | undefined> {
    return this.definitions.get(name);
  }

  async listDefinitions(): Promise<PolicyDefinition[]> {
    return [...this.definitions.values()];
  }

  async deleteDefinition(name: string): Promise<boolean> {
    const existed = this.definitions.delete(name);
    if (existed) {
      this.emit("definition.delete", { name });
    }
    return existed;
  }

  // -----------------------------------------------------------------------
  // Assignments
  // -----------------------------------------------------------------------

  async putAssignment(assignment: PolicyAssignment): Promise<void> {
    // Replace existing assignment for same policy + assignee, or add new
    const idx = this.assignments.findIndex(
      (a) =>
        a.policyName === assignment.policyName &&
        a.assignee.identifier === assignment.assignee.identifier,
    );
    if (idx >= 0) {
      this.assignments[idx] = assignment;
    } else {
      this.assignments.push(assignment);
    }
    this.emit("assignment.put", {
      policyName: assignment.policyName,
      assignee: assignment.assignee.identifier,
    });
  }

  async listAssignments(
    assigneeIdentifier?: string,
  ): Promise<PolicyAssignment[]> {
    if (assigneeIdentifier === undefined) {
      return [...this.assignments];
    }
    return this.assignments.filter(
      (a) => a.assignee.identifier === assigneeIdentifier,
    );
  }

  async deleteAssignment(
    policyName: string,
    assigneeIdentifier: string,
  ): Promise<boolean> {
    const initialLength = this.assignments.length;
    this.assignments = this.assignments.filter(
      (a) =>
        !(
          a.policyName === policyName &&
          a.assignee.identifier === assigneeIdentifier
        ),
    );
    const deleted = this.assignments.length < initialLength;
    if (deleted) {
      this.emit("assignment.delete", { policyName, assignee: assigneeIdentifier });
    }
    return deleted;
  }

  // -----------------------------------------------------------------------
  // Resolution
  // -----------------------------------------------------------------------

  async resolvePolicy(
    userId: string,
    tenantId: string,
    sourceConnectionId: string,
    declaredPurpose?: string,
  ): Promise<EffectivePolicy> {
    this.emit("policy.resolve", {
      userId,
      tenantId,
      sourceConnectionId,
      // Recorded in the audit trail because "which purpose was this resolved for"
      // is the question a reviewer asks of a purpose-bound grant, and the resolved
      // policy alone cannot answer it: a purpose-agnostic result looks identical
      // whether no purpose was declared or a non-matching one was. Omitted rather
      // than emitted as an empty string when absent, so a pre-purpose event's
      // details are unchanged.
      ...(declaredPurpose === undefined ? {} : { declaredPurpose }),
    });
    return resolve(
      userId,
      tenantId,
      sourceConnectionId,
      this.assignments,
      this.definitions,
      (uid) => this.identityResolver.getGroups(uid),
      (uid) => this.identityResolver.getRoles(uid),
      // `ttlMs` is spelled out because `declaredPurpose` follows it positionally;
      // the value is `resolve`'s own documented default.
      3_600_000,
      declaredPurpose,
    );
  }
}
