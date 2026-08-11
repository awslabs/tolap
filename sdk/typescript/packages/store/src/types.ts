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

  /** Resolve an effective policy for a user, tenant, and source. */
  resolvePolicy(
    userId: string,
    tenantId: string,
    sourceConnectionId: string,
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
