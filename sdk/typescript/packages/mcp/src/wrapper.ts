/**
 * TOLAP Secure MCP Tool Wrapper
 *
 * Wraps MCP tool calls with TOLAP policy enforcement:
 * - Pre-execution: validate access, field access, endpoint access
 * - Post-execution: apply field masking, result limits, tag filtering
 */

import {
  validateAccess,
  validateFieldAccess,
  validateEndpoint,
  applyFieldMasking,
  applyResultLimit,
  applyRowFilters,
  filterByTags,
  validatePolicy,
  validateContext,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";
import {
  EnforcementMode,
  type SecureMcpServerOptions,
  type McpToolDefinition,
  type McpRequestContext,
  type EnforcementDecision,
} from "./types.js";

export class SecureMcpToolWrapper {
  private tools = new Map<string, McpToolDefinition>();
  private options: Required<
    Pick<SecureMcpServerOptions, "mode">
  > &
    SecureMcpServerOptions;

  constructor(options: SecureMcpServerOptions = {}) {
    this.options = {
      mode: EnforcementMode.Strict,
      ...options,
    };
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

  private enforcePostExecution(
    result: unknown,
    policy: EffectivePolicy,
  ): unknown {
    if (result === null || result === undefined) return result;

    // If result is an array of records, apply row filters, tag filtering,
    // masking, then result limits (mirrors Python ordering exactly).
    if (Array.isArray(result)) {
      let filtered: unknown[] = result;

      if (policy.objectRules?.rowFilters && this.isRecordArray(filtered)) {
        filtered = applyRowFilters(
          filtered as Array<Record<string, unknown>>,
          policy,
        );
      }

      if (policy.objectRules?.tagRules && this.isRecordArray(filtered)) {
        filtered = filterByTags(
          filtered as Array<Record<string, unknown>>,
          policy,
        );
      }

      if (
        policy.objectRules?.fieldRules?.maskedFields &&
        this.isRecordArray(filtered)
      ) {
        filtered = (filtered as Array<Record<string, unknown>>).map((record) =>
          applyFieldMasking(record, policy),
        );
      }

      filtered = applyResultLimit(filtered, policy);
      return filtered;
    }

    // If result is a single record, apply field masking
    if (typeof result === "object" && !Array.isArray(result)) {
      if (policy.objectRules?.fieldRules?.maskedFields) {
        return applyFieldMasking(
          result as Record<string, unknown>,
          policy,
        );
      }
    }

    return result;
  }

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  private isRecordArray(
    value: unknown[],
  ): value is Array<Record<string, unknown>> {
    return value.length > 0 && typeof value[0] === "object" && value[0] !== null;
  }

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
