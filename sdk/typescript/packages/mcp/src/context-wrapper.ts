/**
 * Context-driven secure tool wrapper.
 *
 * Direct counterpart to Python's SecureMcpToolWrapper.execute_with_enforcement.
 * The MCP-flavored SecureMcpToolWrapper in wrapper.ts handles tool discovery
 * and identity extraction; this class is for callers who already hold a signed
 * SecurityContext and want pre/post enforcement around an arbitrary tool function.
 *
 * Used by the cross-SDK integration tests so all three SDKs share the same
 * surface area: pre-execute checks, run, post-execute filter+mask+limit.
 */

import {
  applyFieldMasking,
  applyResultLimit,
  applyRowFilters,
  filterByTags,
  validateAccess,
  validateContext,
  validateEndpoint,
  validateFieldAccess,
  type AccessResult,
  type EffectivePolicy,
  type SecurityContext,
} from "@tolap/core";

export interface SecureContextWrapperOptions {
  signingKey: string;
  enforceSignatures?: boolean;
  enforceExpiry?: boolean;
  allowedTools?: string[];
}

export interface PreExecuteArgs {
  toolName: string;
  objectName?: string;
  fields?: string[];
  endpointPath?: string;
  endpointMethod?: string;
}

export class SecureContextToolWrapper {
  private options: Required<
    Pick<SecureContextWrapperOptions, "enforceSignatures" | "enforceExpiry">
  > &
    SecureContextWrapperOptions;

  constructor(options: SecureContextWrapperOptions) {
    this.options = {
      enforceSignatures: true,
      enforceExpiry: true,
      ...options,
    };
  }

  validateSecurityContext(context: SecurityContext): AccessResult {
    if (this.options.enforceSignatures) {
      if (!validateContext(context, this.options.signingKey)) {
        return { allowed: false, reason: "invalid signature" };
      }
    }
    if (this.options.enforceExpiry && context.expiresAt) {
      const expiry = new Date(context.expiresAt);
      if (expiry.getTime() < Date.now()) {
        return { allowed: false, reason: "security context expired" };
      }
    }
    return { allowed: true };
  }

  preExecute(context: SecurityContext, args: PreExecuteArgs): AccessResult {
    const ctxResult = this.validateSecurityContext(context);
    if (!ctxResult.allowed) return ctxResult;

    const policy = context.effectivePolicy;
    const allowedTools = this.options.allowedTools;
    if (allowedTools && allowedTools.length > 0 && !allowedTools.includes(args.toolName)) {
      return { allowed: false, reason: "tool not in allowed list" };
    }
    if (!policy.permissions.canQuery) {
      return { allowed: false, reason: "query not permitted" };
    }

    if (args.objectName) {
      const r = validateAccess(args.objectName, policy);
      if (!r.allowed) return r;
    }
    if (args.fields && args.fields.length > 0) {
      const r = validateFieldAccess(args.fields, policy);
      if (r.denied.length > 0) {
        return { allowed: false, reason: `denied fields: ${r.denied.join(", ")}` };
      }
    }
    if (args.endpointPath) {
      const method = args.endpointMethod ?? "GET";
      const r = validateEndpoint(args.endpointPath, method, policy);
      if (!r.allowed) return r;
    }
    return { allowed: true };
  }

  postExecute(
    context: SecurityContext,
    results: Array<Record<string, unknown>>,
  ): Array<Record<string, unknown>> {
    const policy: EffectivePolicy = context.effectivePolicy;
    let out: Array<Record<string, unknown>> = applyRowFilters(results, policy);
    out = filterByTags(out, policy);
    out = out.map((row) => applyFieldMasking(row, policy));
    return applyResultLimit(out, policy);
  }

  async executeWithEnforcement(
    context: SecurityContext,
    args: PreExecuteArgs,
    toolFn: () => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>,
  ): Promise<Array<Record<string, unknown>>> {
    const pre = this.preExecute(context, args);
    if (!pre.allowed) {
      throw new Error(`Access denied: ${pre.reason ?? "unknown reason"}`);
    }
    const raw = await toolFn();
    return this.postExecute(context, raw);
  }
}
