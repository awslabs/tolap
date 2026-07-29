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
  applyResultPipeline,
  classifyResultShape,
  describeResultShape,
  validateAccess,
  validateContext,
  validateEndpoint,
  validateExpiry,
  validateFieldAccess,
  type AccessResult,
  type SecurityContext,
} from "@tolap/core";

export interface SecureContextWrapperOptions {
  signingKey: string;
  enforceSignatures?: boolean;
  enforceExpiry?: boolean;
  allowedTools?: string[];
  /**
   * Pass through tool results the policy cannot be applied to.
   *
   * Off by default: a scalar, null, or an arbitrary object is denied rather than
   * returned unfiltered (canonical spec §5). Integrators mid-migration may opt
   * in per wrapper, which is logged every time it lets a result through.
   */
  allowUnenforceableShapes?: boolean;
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
    Pick<
      SecureContextWrapperOptions,
      "enforceSignatures" | "enforceExpiry" | "allowUnenforceableShapes"
    >
  > &
    SecureContextWrapperOptions;

  constructor(options: SecureContextWrapperOptions) {
    this.options = {
      enforceSignatures: true,
      enforceExpiry: true,
      allowUnenforceableShapes: false,
      ...options,
    };
  }

  /**
   * Validate signature then expiry.
   *
   * Signature first: a tampered context must report a signature failure rather
   * than reveal whether a valid context had merely expired. A missing or
   * unparseable expiry is a denial, never a skipped check.
   */
  validateSecurityContext(context: SecurityContext): AccessResult {
    if (this.options.enforceSignatures) {
      if (!validateContext(context, this.options.signingKey)) {
        return { allowed: false, reason: "invalid signature" };
      }
    }
    if (this.options.enforceExpiry) {
      const expiryReason = validateExpiry(context);
      if (expiryReason !== undefined) {
        return { allowed: false, reason: expiryReason };
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

  /**
   * Post-execution enforcement over a tool result.
   *
   * Applies the canonical pipeline in order (spec §4): row filters -> tag
   * filters -> hidden fields -> allowed fields -> masking -> result limit.
   *
   * Accepts a single record or an array of records; a single record runs the
   * identical pipeline. Any other shape is denied unless the wrapper was
   * configured with `allowUnenforceableShapes`.
   */
  postExecute(
    context: SecurityContext,
    results: Array<Record<string, unknown>>,
  ): Array<Record<string, unknown>>;
  postExecute(context: SecurityContext, results: unknown): unknown;
  postExecute(context: SecurityContext, results: unknown): unknown {
    if (
      classifyResultShape(results) === undefined &&
      this.options.allowUnenforceableShapes
    ) {
      console.warn(
        "TOLAP enforcement bypassed: allowUnenforceableShapes is enabled and " +
          `the tool returned ${describeResultShape(results)}, which is passed ` +
          "through unfiltered.",
      );
      return results;
    }
    return applyResultPipeline(results, context.effectivePolicy);
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
