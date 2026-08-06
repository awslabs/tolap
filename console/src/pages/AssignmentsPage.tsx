/**
 * Assignments: who a policy applies to.
 *
 * Worth remembering while reading this page: adding an assignment can only ever
 * *restrict*. Merge is most-restrictive-wins, so granting someone an extra policy
 * never widens their access -- which is why there is no ordering an administrator
 * has to get right, and no way to escalate by adding one.
 */

import { useCallback, useEffect, useState } from "react";
import { api, type PolicyAssignment, type PolicyDefinition } from "../api.ts";

const ASSIGNEE_TYPES = ["user", "group", "role", "serviceAccount"] as const;

export function AssignmentsPage({ readOnly }: { readonly readOnly: boolean }) {
  const [assignments, setAssignments] = useState<PolicyAssignment[]>([]);
  const [policies, setPolicies] = useState<PolicyDefinition[]>([]);
  const [policyName, setPolicyName] = useState("");
  const [assigneeType, setAssigneeType] =
    useState<(typeof ASSIGNEE_TYPES)[number]>("user");
  const [identifier, setIdentifier] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [sourceConnectionId, setSourceConnectionId] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [reason, setReason] = useState("");
  const [failure, setFailure] = useState<string | undefined>();
  const [status, setStatus] = useState<string | undefined>();

  const refresh = useCallback(async () => {
    try {
      const [{ assignments: list }, { policies: available }] = await Promise.all([
        api.listAssignments(),
        api.listPolicies(),
      ]);
      setAssignments(list);
      setPolicies(available);
      setFailure(undefined);
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const create = async () => {
    setFailure(undefined);
    setStatus(undefined);
    try {
      await api.createAssignment({
        version: "1.0",
        policyName,
        assignee: { type: assigneeType, identifier },
        scope: {
          ...(tenantId !== "" ? { tenantId } : {}),
          ...(sourceConnectionId !== "" ? { sourceConnectionId } : {}),
        },
        active: true,
        ...(expiresAt !== ""
          ? { expiresAt: new Date(expiresAt).toISOString() }
          : {}),
        audit: {
          // grantedBy is overwritten server-side with the authenticated subject, so
          // the audit trail cannot be forged from here.
          grantedBy: "console",
          grantedAt: new Date().toISOString(),
          reason,
        },
      });
      setStatus(`Assigned ${policyName} to ${identifier}.`);
      setIdentifier("");
      setReason("");
      await refresh();
    } catch (caught) {
      setFailure((caught as Error).message);
    }
  };

  return (
    <section className="page page--single">
      <h2>Assignments</h2>
      <p className="hint">
        Every assignment reaching a user is merged, most-restrictive-wins. Adding one
        can only narrow access, never widen it.
      </p>

      {failure ? (
        <p className="banner banner--error" role="alert">
          {failure}
        </p>
      ) : null}
      {status ? (
        <p className="banner banner--success" role="status">
          {status}
        </p>
      ) : null}

      {assignments.length === 0 ? (
        <p className="muted">No live assignments.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Policy</th>
              <th>Assignee</th>
              <th>Scope</th>
              <th>Expires</th>
              <th>Granted by</th>
              {!readOnly ? <th /> : null}
            </tr>
          </thead>
          <tbody>
            {assignments.map((assignment) => (
              <tr key={`${assignment.policyName}-${assignment.assignee.identifier}`}>
                <td>
                  <code>{assignment.policyName}</code>
                </td>
                <td>
                  <span className="badge">{assignment.assignee.type}</span>{" "}
                  {assignment.assignee.identifier}
                </td>
                <td>
                  {assignment.scope.tenantId ? (
                    <div>tenant: {assignment.scope.tenantId}</div>
                  ) : null}
                  {assignment.scope.sourceConnectionId ? (
                    <div>
                      source: <code>{assignment.scope.sourceConnectionId}</code>
                    </div>
                  ) : null}
                  {!assignment.scope.tenantId &&
                  !assignment.scope.sourceConnectionId ? (
                    <span className="muted">unscoped</span>
                  ) : null}
                </td>
                <td>
                  {assignment.expiresAt
                    ? new Date(assignment.expiresAt).toLocaleString()
                    : "never"}
                </td>
                <td>{assignment.audit.grantedBy}</td>
                {!readOnly ? (
                  <td>
                    <button
                      type="button"
                      onClick={() =>
                        void api
                          .revokeAssignment(
                            assignment.policyName,
                            assignment.assignee.identifier,
                          )
                          .then(refresh)
                          .catch((caught: Error) => setFailure(caught.message))
                      }
                    >
                      Revoke
                    </button>
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {!readOnly ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void create();
          }}
        >
          <h3>Assign a policy</h3>

          <label htmlFor="assignment-policy">Policy</label>
          <select
            id="assignment-policy"
            value={policyName}
            onChange={(event) => setPolicyName(event.target.value)}
            required
          >
            <option value="">— select —</option>
            {policies.map((policy) => (
              <option key={policy.name} value={policy.name}>
                {policy.name}
              </option>
            ))}
          </select>

          <label htmlFor="assignment-type">Assignee type</label>
          <select
            id="assignment-type"
            value={assigneeType}
            onChange={(event) =>
              setAssigneeType(event.target.value as (typeof ASSIGNEE_TYPES)[number])
            }
          >
            {ASSIGNEE_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>

          <label htmlFor="assignment-identifier">Assignee identifier</label>
          <input
            id="assignment-identifier"
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
            required
          />

          <label htmlFor="assignment-tenant">Tenant (optional)</label>
          <input
            id="assignment-tenant"
            value={tenantId}
            onChange={(event) => setTenantId(event.target.value)}
            placeholder="all tenants"
          />

          <label htmlFor="assignment-source">Source (optional)</label>
          <input
            id="assignment-source"
            value={sourceConnectionId}
            onChange={(event) => setSourceConnectionId(event.target.value)}
            placeholder="every source the policy's patterns match"
          />

          <label htmlFor="assignment-expires">Expires (optional)</label>
          <input
            id="assignment-expires"
            type="datetime-local"
            value={expiresAt}
            onChange={(event) => setExpiresAt(event.target.value)}
          />

          <label htmlFor="assignment-reason">Reason</label>
          <input
            id="assignment-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Why this access was granted"
            required
          />

          <button type="submit">Assign</button>
        </form>
      ) : null}
    </section>
  );
}
