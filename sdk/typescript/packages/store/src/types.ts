/**
 * TOLAP Store Types
 *
 * Interfaces for policy storage and identity resolution.
 */

import type {
  PolicyDefinition,
  PolicyAssignment,
  EffectivePolicy,
} from "@aws/tolap-core";

// ---------------------------------------------------------------------------
// Policy Store
// ---------------------------------------------------------------------------

export interface PolicyStore {
  /** Store or update a policy definition. */
  putDefinition(definition: PolicyDefinition): Promise<void>;

  /** Retrieve a policy definition by name. */
  getDefinition(name: string): Promise<PolicyDefinition | undefined>;

  /** List all stored policy definitions. */
  listDefinitions(): Promise<PolicyDefinition[]>;

  /** Delete a policy definition by name. */
  deleteDefinition(name: string): Promise<boolean>;

  /** Store or update a policy assignment. */
  putAssignment(assignment: PolicyAssignment): Promise<void>;

  /** List assignments, optionally filtered by assignee identifier. */
  listAssignments(assigneeIdentifier?: string): Promise<PolicyAssignment[]>;

  /** Delete assignments matching a policy name and assignee identifier. */
  deleteAssignment(
    policyName: string,
    assigneeIdentifier: string,
  ): Promise<boolean>;

  /**
   * Resolve an effective policy for a user, tenant, and source.
   *
   * @param declaredPurpose
   * The purpose the caller declares, or omitted to declare none. Omitted resolves
   * exactly the policies it did before purpose binding existed (canonical spec §15.1).
   *
   * Threaded through rather than left to the caller to apply afterwards, because
   * purpose filtering has to happen **before** the merge: a policy scoped to a purpose
   * the caller did not declare must not fold its rules into the effective policy at
   * all, and there is no later point at which to undo that. A store that dropped the
   * parameter would resolve a policy nobody asked for.
   *
   * Optional with no default so every existing call site keeps compiling and keeps its
   * meaning. An external implementor of this interface does have to accept the
   * parameter; there is no way to extend a resolution contract without that, and
   * silently ignoring a declared purpose is the outcome worth breaking a build over.
   */
  resolvePolicy(
    userId: string,
    tenantId: string,
    sourceConnectionId: string,
    declaredPurpose?: string,
  ): Promise<EffectivePolicy>;

  /** Register a listener for audit events. */
  onAudit(listener: (event: PolicyAuditEvent) => void): void;
}

// ---------------------------------------------------------------------------
// Identity Resolver
// ---------------------------------------------------------------------------

export interface IdentityResolver {
  /** Return group identifiers the user belongs to. */
  getGroups(userId: string): Promise<string[]>;

  /** Return role identifiers the user holds. */
  getRoles(userId: string): Promise<string[]>;
}

// ---------------------------------------------------------------------------
// Audit Event
// ---------------------------------------------------------------------------

export interface PolicyAuditEvent {
  timestamp: string;
  action:
    | "definition.put"
    | "definition.delete"
    | "assignment.put"
    | "assignment.delete"
    | "policy.resolve";
  details: Record<string, string>;
}
