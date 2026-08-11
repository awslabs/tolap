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
  validateWrite,
  SqlQueryRewriter,
  SqlDialect,
  type AccessResult,
  type RowFilter,
  type SecurityContext,
  type ValidateWriteOptions,
  type WriteOperation,
} from "@aws/tolap-core";

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
  /**
   * Secret salt for `hash` masking, turning the digest into a keyed HMAC.
   *
   * Unset by default, which preserves the plain-digest pseudonym (and so existing
   * join keys). Set it and `hash` becomes a confidentiality control: an unsalted
   * digest of a low-entropy value — an SSN, a date of birth, a small enumeration —
   * is recoverable by brute force or a rainbow table, because the input space is
   * small enough to enumerate.
   *
   * Treat it as a secret on a par with `signingKey`: store it in a secrets manager
   * or KMS, never in the policy JSON (policies are visible to every admin and
   * auditor who can read them). The same salt must be configured everywhere the
   * pseudonym is joined, since changing it changes every masked value.
   */
  hashSalt?: string | Buffer;
  allowUnenforceableShapes?: boolean;
}

export interface PreExecuteArgs {
  toolName: string;
  objectName?: string;
  fields?: string[];
  endpointPath?: string;
  endpointMethod?: string;
}

/**
 * The outcome of preparing a SQL query for execution under a policy.
 *
 * Mirrors .NET's `SqlQueryPreparation` so an integrator reads the same fields in
 * either SDK.
 */
export interface SqlQueryPreparation {
  /**
   * Whether the query may be executed at all. When false, {@link query} is the
   * caller's original text and MUST NOT be executed.
   */
  allowed: boolean;
  /** Why the query was refused, or undefined when it was allowed. */
  denialReason?: string;
  /**
   * The query to execute: rewritten to carry the policy's field restrictions, row
   * filters, and result limit. Identical to the caller's query when nothing could be
   * pushed down.
   */
  query: string;
  /** Whether {@link query} differs from the caller's original. */
  rewritten: boolean;
  /**
   * Row filters that could not be expressed in portable SQL and are therefore
   * enforced only by the post-execution pipeline. Non-empty means the database will
   * return rows that {@link SecureContextToolWrapper.postExecute} still has to
   * discard.
   */
  unpushableFilters: RowFilter[];
  /**
   * Whether every row filter in the policy reached the database.
   *
   * Useful as an assertion for an integrator whose result sets are large enough that
   * post-fetch filtering is not an acceptable fallback.
   */
  fullyPushedDown: boolean;
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
   * Validate a write before it is issued (connector spec §4).
   *
   * The write counterpart to {@link preExecute}. Validates the context, then runs
   * the four required pre-write checks: the operation's permission and the
   * `readOnly` ceiling, the target object, every field in the payload, and the
   * policy's row filters against `options.targetRow`.
   *
   * Fails closed on the whole write: one unwritable field denies the operation
   * rather than being stripped so the rest can proceed (§4.4).
   *
   * Omitting `options.targetRow` on an update or delete while the policy carries row
   * filters yields `write target unverifiable`, never an allow — read the row first
   * and pass it here, or push the filters into the statement's `WHERE`.
   *
   * A permitted write that returns data is a *read* of that data: pass the response
   * through {@link postExecute} (§4.5).
   */
  preWrite(
    context: SecurityContext,
    operation: WriteOperation | string,
    objectName?: string,
    payload?: unknown,
    options: ValidateWriteOptions = {},
  ): AccessResult {
    const ctxResult = this.validateSecurityContext(context);
    if (!ctxResult.allowed) return ctxResult;

    return validateWrite(
      operation,
      objectName,
      payload,
      context.effectivePolicy,
      options,
    );
  }

  /**
   * Validate a write, issue it, and enforce the policy on anything it returns.
   *
   * Throws before `writeFn` is called if the write is denied, so a refused write
   * never reaches the source.
   *
   * Whatever the write returns is treated as a read of that data and goes through
   * the full post-execution pipeline (§4.5) — a masked field comes back masked even
   * though the caller just wrote it, and a hidden field does not appear at all. A
   * write that returns nothing (`undefined` or `null`) is passed through as-is rather
   * than denied as an unenforceable shape: there is no data to enforce a policy over.
   */
  async executeWriteWithEnforcement(
    context: SecurityContext,
    operation: WriteOperation | string,
    writeFn: () => Promise<unknown> | unknown,
    objectName?: string,
    payload?: unknown,
    options: ValidateWriteOptions = {},
  ): Promise<unknown> {
    const pre = this.preWrite(context, operation, objectName, payload, options);
    if (!pre.allowed) {
      throw new Error(`Access denied: ${pre.reason}`);
    }

    const result = await writeFn();
    if (result === undefined || result === null) return result;
    return this.postExecute(context, result);
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
    return applyResultPipeline(
      results,
      context.effectivePolicy,
      this.options.hashSalt,
    );
  }

  /**
   * Check a SQL query against the policy and push what can be pushed into it.
   *
   * ```ts
   * const prep = wrapper.prepareSqlQuery(
   *   ctx, { toolName: "pg-query" }, sql, undefined, SqlDialect.Postgres,
   * );
   * if (!prep.allowed) throw new Error(`Access denied: ${prep.denialReason}`);
   * const rows = await db.query(prep.query);
   * return wrapper.postExecute(ctx, rows);   // STILL REQUIRED
   * ```
   *
   * The rewrite is a resource optimization; {@link postExecute} remains the
   * enforcement boundary and is never optional (canonical spec §4). This method
   * deliberately does NOT execute or post-process, so the two halves stay visible at
   * the call site — see {@link executeSqlWithEnforcement} for the combined form.
   *
   * @param dialect
   * The engine `sql` will run against (connector spec §5.1) — yours to supply, since
   * only you know which connection this is for. Omitted selects the `rewriter`'s own
   * dialect, or `ansi` if it has none. An unrecognized value rewrites nothing and
   * reports every filter in {@link SqlQueryPreparation.unpushableFilters}; the
   * pre-execution checks below still run either way, so declining to rewrite never
   * relaxes a denial.
   */
  prepareSqlQuery(
    context: SecurityContext,
    args: PreExecuteArgs,
    sql: string,
    rewriter: SqlQueryRewriter = new SqlQueryRewriter(),
    dialect?: SqlDialect | string,
  ): SqlQueryPreparation {
    const denied = (reason: string): SqlQueryPreparation => ({
      allowed: false,
      denialReason: reason,
      query: sql,
      rewritten: false,
      unpushableFilters: [],
      fullyPushedDown: false,
    });

    if (typeof sql !== "string" || sql.trim() === "") {
      return denied("query is empty");
    }

    // Resolve the object from the query itself when the caller did not name one: an
    // allowedObjects rule must apply to the table being READ, not to a declaration
    // the query is free to contradict.
    const effectiveArgs: PreExecuteArgs =
      args.objectName === undefined
        ? { ...args, objectName: rewriter.extractTableName(sql) }
        : args;

    const pre = this.preExecute(context, effectiveArgs);
    if (!pre.allowed) {
      /* c8 ignore next -- every denial preExecute returns carries a reason; the
         fallback exists so a future denial path that forgets one still produces an
         actionable message rather than "undefined". */
      return denied(pre.reason ?? "access denied");
    }

    const policy = context.effectivePolicy;

    // Refuse rather than silently narrow: an agent that asked for a field it cannot
    // read should be told, not handed a result that quietly omits the column.
    if (!rewriter.validateQuery(sql, policy)) {
      return denied("query references fields you do not have permission to access");
    }

    const result = rewriter.rewriteQuery(sql, policy, dialect);

    return {
      allowed: true,
      query: result.query,
      rewritten: result.rewritten,
      unpushableFilters: result.unpushableFilters,
      fullyPushedDown: result.unpushableFilters.length === 0,
    };
  }

  /**
   * Prepare a SQL query, execute it, and apply the post-execution pipeline.
   *
   * Both halves of enforcement in one call. The callback receives the REWRITTEN
   * query; the pipeline still runs over whatever it returns, so a filter that could
   * not be pushed down is still enforced.
   *
   * @throws when the query is refused. The callback is not invoked in that case.
   *
   * @param dialect
   * The engine the callback will run `sql` against (connector spec §5.1). Omitted
   * selects the `rewriter`'s dialect, or `ansi`.
   */
  async executeSqlWithEnforcement(
    context: SecurityContext,
    args: PreExecuteArgs,
    sql: string,
    run: (
      query: string,
    ) => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>,
    rewriter?: SqlQueryRewriter,
    dialect?: SqlDialect | string,
  ): Promise<Array<Record<string, unknown>>> {
    const prep = this.prepareSqlQuery(context, args, sql, rewriter, dialect);
    if (!prep.allowed) {
      throw new Error(`Access denied: ${prep.denialReason}`);
    }
    return this.postExecute(context, await run(prep.query));
  }

  async executeWithEnforcement(
    context: SecurityContext,
    args: PreExecuteArgs,
    toolFn: () => Promise<Array<Record<string, unknown>>> | Array<Record<string, unknown>>,
  ): Promise<Array<Record<string, unknown>>> {
    const pre = this.preExecute(context, args);
    if (!pre.allowed) {
      /* c8 ignore next 3 -- the `?? "unknown reason"` fallback is unreachable:
         every denial preExecute can return carries a reason (either a literal here
         or one from validateContext/validateExpiry/validateAccess/
         validateFieldAccess/validateEndpoint). Retained so a future denial path
         that forgets a reason still produces an actionable message rather than
         "Access denied: undefined". */
      throw new Error(`Access denied: ${pre.reason ?? "unknown reason"}`);
    }
    const raw = await toolFn();
    return this.postExecute(context, raw);
  }
}
