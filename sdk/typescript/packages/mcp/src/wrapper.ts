/**
 * TOLAP Secure MCP Tool Wrapper
 *
 * Wraps MCP tool calls with TOLAP policy enforcement:
 * - Pre-execution: validate access, field access, endpoint access
 * - Post-execution: the canonical pipeline (row filters -> tag filters ->
 *   hidden fields -> allowed fields -> masking -> result limit)
 */

import {
  validateAccess,
  validateFieldAccess,
  validateEndpoint,
  applyResultPipeline,
  classifyResultShape,
  describeResultShape,
  validatePolicy,
  type EffectivePolicy,
} from "@tolap/core";
import {
  EnforcementMode,
  type SecureMcpServerOptions,
  type McpToolDefinition,
  type McpRequestContext,
  type EnforcementDecision,
} from "./types.js";

/**
 * Emit the startup warning when a non-denying enforcement mode is active
 * (threat-model R-6).
 *
 * Exported so the context wrapper shares one message, and so the warning is
 * testable without constructing a full MCP wrapper.
 */
export function warnIfEnforcementDisabled(mode: EnforcementMode): void {
  if (mode === EnforcementMode.Strict) return;

  const detail =
    mode === EnforcementMode.Disabled
      ? "enforcement is skipped entirely and tool results are returned unfiltered"
      : "policy violations are logged but access is allowed";

  console.warn(
    `TOLAP enforcement is NOT enforcing: mode "${mode}" means ${detail}. ` +
      "This is intended for migration only and MUST NOT be used in production. " +
      "Set EnforcementMode.Strict to enforce policy.",
  );
}

export class SecureMcpToolWrapper {
  private tools = new Map<string, McpToolDefinition>();
  private options: Required<
    Pick<SecureMcpServerOptions, "mode">
  > &
    SecureMcpServerOptions;

  /**
   * Construct the wrapper, warning loudly when configured in a mode that cannot
   * deny.
   *
   * Threat-model remediation R-6: {@link EnforcementMode.Disabled} skips
   * enforcement entirely and {@link EnforcementMode.AuditOnly} is documented as
   * "log violations but allow access", so a deployment that reaches production
   * still carrying either has no enforcement at all while continuing to look
   * configured. The warning fires at construction rather than on the first
   * denial, because a service whose policies happen not to deny anything during a
   * smoke test would otherwise ship silently. `allowUnenforceableShapes` already
   * warns on the same channel when it passes a result through.
   */
  constructor(options: SecureMcpServerOptions = {}) {
    this.options = {
      mode: EnforcementMode.Strict,
      ...options,
    };
    warnIfEnforcementDisabled(this.options.mode);
  }

  /** Register a tool for secure wrapping. */
  registerTool(tool: McpToolDefinition): void {
    this.tools.set(tool.name, tool);
  }

  /** List registered tools. */
  listTools(): McpToolDefinition[] {
    return [...this.tools.values()];
  }

  /** Execute a tool call with enforcement applied. */
  async executeTool(
    request: McpRequestContext,
  ): Promise<unknown> {
    const tool = this.tools.get(request.toolName);
    if (!tool) {
      throw new Error(`Unknown tool: ${request.toolName}`);
    }

    if (this.options.mode === EnforcementMode.Disabled) {
      return tool.execute(request.arguments ?? {});
    }

    // Resolve identity
    const userId = this.options.identityExtractor?.extractUserId(request);
    const tenantId = this.options.identityExtractor?.extractTenantId(request);

    if (!userId || !tenantId) {
      return this.handleDecision(request, false, "missing identity context");
    }

    // Resolve policy
    if (!this.options.resolvePolicy) {
      throw new Error("resolvePolicy function must be provided");
    }

    const sourceConnectionId = request.sourceConnectionId ?? "";
    const policy = await this.options.resolvePolicy(
      userId,
      tenantId,
      sourceConnectionId,
    );

    // Validate policy signature if signing key is provided
    if (this.options.signingKey) {
      if (!validatePolicy(policy, this.options.signingKey)) {
        return this.handleDecision(
          request,
          false,
          "policy signature validation failed",
          userId,
          tenantId,
        );
      }
    }

    // Check expiry
    if (new Date(policy.expiresAt) <= new Date()) {
      return this.handleDecision(
        request,
        false,
        "policy has expired",
        userId,
        tenantId,
      );
    }

    // Pre-execution enforcement
    const preResult = this.enforcePreExecution(tool, policy);
    if (!preResult.allowed) {
      return this.handleDecision(
        request,
        false,
        preResult.reason,
        userId,
        tenantId,
      );
    }

    // Record successful pre-enforcement
    this.emitDecision(request, true, undefined, userId, tenantId);

    // Execute tool
    const rawResult = await tool.execute(request.arguments ?? {});

    // Post-execution enforcement
    return this.enforcePostExecution(rawResult, policy);
  }

  // -----------------------------------------------------------------------
  // Pre-execution checks
  // -----------------------------------------------------------------------

  private enforcePreExecution(
    tool: McpToolDefinition,
    policy: EffectivePolicy,
  ): { allowed: boolean; reason?: string } {
    // Object access check
    if (tool.objectName) {
      const result = validateAccess(tool.objectName, policy);
      if (!result.allowed) return result;
    }

    // Field access check
    if (tool.accessedFields && tool.accessedFields.length > 0) {
      const result = validateFieldAccess(tool.accessedFields, policy);
      if (result.denied.length > 0) {
        return {
          allowed: false,
          reason: `denied fields: ${result.denied.join(", ")}`,
        };
      }
    }

    // Endpoint access check
    if (tool.endpointPath) {
      const method = tool.endpointMethod ?? "GET";
      const result = validateEndpoint(tool.endpointPath, method, policy);
      if (!result.allowed) return result;
    }

    return { allowed: true };
  }

  // -----------------------------------------------------------------------
  // Post-execution enforcement
  // -----------------------------------------------------------------------

  /**
   * Run the canonical post-execution pipeline over a tool result.
   *
   * Delegates to the shared core implementation so the MCP, context, and HTTP
   * wrappers cannot drift: all three run row filters -> tag filters -> hidden
   * fields -> allowed fields -> masking -> result limit, over a single record
   * and an array of records alike.
   *
   * A shape the policy cannot be applied to is denied rather than returned
   * unfiltered (canonical spec §5), unless the wrapper opted out explicitly.
   */
  private enforcePostExecution(
    result: unknown,
    policy: EffectivePolicy,
  ): unknown {
    if (
      classifyResultShape(result) === undefined &&
      this.options.allowUnenforceableShapes
    ) {
      console.warn(
        "TOLAP enforcement bypassed: allowUnenforceableShapes is enabled and " +
          `the tool returned ${describeResultShape(result)}, which is passed ` +
          "through unfiltered.",
      );
      return result;
    }

    return applyResultPipeline(result, policy);
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private handleDecision(
    request: McpRequestContext,
    allowed: boolean,
    reason?: string,
    userId?: string,
    tenantId?: string,
  ): never {
    this.emitDecision(request, allowed, reason, userId, tenantId);

    if (this.options.mode === EnforcementMode.AuditOnly) {
      // In audit mode we still throw, but the caller can catch it
    }

    throw new Error(
      `Access denied for tool "${request.toolName}": ${reason ?? "unknown reason"}`,
    );
  }

  private emitDecision(
    request: McpRequestContext,
    allowed: boolean,
    reason?: string,
    userId?: string,
    tenantId?: string,
  ): void {
    if (this.options.onEnforcementDecision) {
      const decision: EnforcementDecision = {
        timestamp: new Date().toISOString(),
        toolName: request.toolName,
        userId,
        tenantId,
        allowed,
        reason,
        mode: this.options.mode,
      };
      this.options.onEnforcementDecision(decision);
    }
  }
}
