/**
 * Secure Tool Factory — the composition root for policy-enforced tools
 * (architecture.md §5).
 *
 * ## What this exists for
 *
 * Enforcement is only non-bypassable if the wrapper is the *sole* path to the data
 * source (architecture.md §4). A factory is how that becomes structural rather than a
 * convention: an agent receives its tools from here and never constructs one, so
 * there is no code path that reaches a source unwrapped. Wiring each tool by hand at
 * call sites works right up until one site forgets, and a forgotten wrapper is
 * indistinguishable from an enforced one until someone audits it.
 *
 * ## What it deliberately does NOT do
 *
 * The reference implementation's factory also brokered credentials and pinned
 * connection configuration. Neither belongs here, because **this SDK never holds a
 * connection**: `SecureContextToolWrapper` hands back rewritten SQL for the caller to
 * execute, and `SecureHttpToolWrapper` is given the transport (`FetchLike`) by the
 * caller. Nothing on the enforcement path — validate, rewrite, filter, mask, limit —
 * takes a secret as input, so accepting one would add secret-handling surface to a
 * security library that has no use for it. It is the same reasoning that removed
 * `limits.maxQueryTimeSeconds` from the schema (connector-spec §9): the SDK cannot
 * enforce what it does not own. Credentials belong to the layer that opens the
 * connection.
 *
 * Nor does it hold a user's `SecurityContext`. The documented API in the
 * implementation guides showed a `setSecurityContext()` call that made a wrapper
 * stateful; the shipped wrappers take the context **per call** instead. That is a
 * safety property, not an oversight — a context stored on a shared instance can
 * outlive the request that supplied it and be reused for the next caller, who may be
 * a different user. Factory-produced wrappers are stateless and reusable for exactly
 * that reason.
 *
 * ## Dispatch is on the signed category
 *
 * The wrapper a source needs is decided by the `category` segment of its
 * `sourceConnectionId` (connector-spec §1), read from the **signed** policy rather
 * than from unsigned configuration. A category taken from a side channel could
 * disagree with the policy the context carries: flipping `db` to `api` would select
 * the wrapper that enforces the other category's rules, and `endpointRules` do not
 * constrain a SQL query. Inside the signed bytes, changing it breaks the signature.
 */

import {
  SourceCategory,
  sourceCategory,
  validateContext,
  validateExpiry,
  type SecurityContext,
} from "@tolap/core";

import {
  SecureContextToolWrapper,
  type SecureContextWrapperOptions,
} from "./context-wrapper.js";
import {
  SecureHttpToolWrapper,
  type FetchLike,
  type SecureHttpWrapperOptions,
} from "./http-wrapper.js";

/**
 * Raised when a tool cannot be produced. Never carries policy contents — the reason
 * names the rule or the configuration gap, not the data (connector-spec §3.3).
 */
export class ToolCreationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolCreationError";
  }
}

/** A tool the factory can produce. */
export type SecureTool = SecureContextToolWrapper | SecureHttpToolWrapper;

export interface SecureToolFactoryOptions {
  /** Key the context signature is verified against. */
  signingKey: string;
  /**
   * Verify the signature before producing a tool. On by default, and turning it off
   * means an unsigned or forged context yields a working tool.
   */
  enforceSignatures?: boolean;
  /** Reject an expired context. On by default. */
  enforceExpiry?: boolean;
  /**
   * Transport for `api` sources. Required only to produce an `api` tool: the factory
   * never opens a connection of its own, so the caller supplies `fetch` (or a
   * client that wraps it). Requesting an `api` tool without this is a
   * {@link ToolCreationError} rather than a silent fallback to global `fetch`,
   * which would quietly bypass a caller's proxy, timeout, and retry policy.
   */
  fetchFn?: FetchLike;
  /** Base URL for `api` sources, forwarded to {@link SecureHttpToolWrapper}. */
  baseUrl?: string;
  /**
   * Restrict which tool names the record-shaped wrapper will run, forwarded to
   * {@link SecureContextToolWrapper}.
   */
  allowedTools?: string[];
  /**
   * Forwarded to {@link SecureContextToolWrapper}. Off by default: a result the
   * policy cannot be applied to is denied rather than returned unfiltered.
   */
  allowUnenforceableShapes?: boolean;
}

/**
 * Creates policy-enforced tools from a signed {@link SecurityContext}.
 *
 * One context governs one data source (architecture.md §1), so this produces one
 * tool per call rather than the multi-source tool *set* the guides once described.
 * A caller holding contexts for several sources calls {@link createTool} per context.
 */
export class SecureToolFactory {
  private readonly options: Required<
    Pick<SecureToolFactoryOptions, "enforceSignatures" | "enforceExpiry">
  > &
    SecureToolFactoryOptions;

  constructor(options: SecureToolFactoryOptions) {
    this.options = {
      enforceSignatures: true,
      enforceExpiry: true,
      ...options,
    };
  }

  /**
   * Produce the enforcing tool for the source this context governs.
   *
   * Throws {@link ToolCreationError} when the context is not usable. Every rejection
   * below is a *refusal to hand back a tool at all*, which is the fail-closed
   * outcome: returning an unenforced tool for a context that failed validation would
   * defeat the point of the factory.
   *
   * The context is validated here even though every wrapper re-validates it on each
   * call. That is intentional redundancy: it turns "this context is forged" into an
   * error at composition time, where it is attributable, rather than a denial on some
   * later tool call. The per-call check remains the one that actually gates access,
   * since a wrapper is reusable and the context arrives again with every request.
   */
  createTool(context: SecurityContext): SecureTool {
    this.assertUsableContext(context);

    const policy = context.effectivePolicy;

    // canQuery is the top-level read gate. A source the user cannot read produces no
    // tool: handing back a wrapper that denies every call invites a caller to treat
    // the denial as a transient error and retry.
    if (!policy.permissions.canQuery) {
      throw new ToolCreationError("query not permitted");
    }

    const category = sourceCategory(policy.sourceConnectionId);
    if (category === undefined) {
      // Unparseable identifier -> no category -> no way to know which rules apply.
      // Guessing a wrapper here would enforce the wrong category's rules.
      throw new ToolCreationError(
        "sourceConnectionId is not category:namespace:name (connector-spec §1)",
      );
    }

    switch (category) {
      case SourceCategory.Api:
        return this.createHttpTool();

      // db, kb and storage all return records (rows, chunks, listing entries) and
      // are enforced by the record-shaped pipeline. They differ in which policy
      // fields are meaningful, and that is decided by the policy itself rather than
      // by the wrapper type -- an inert field is simply never consulted
      // (connector-spec §2).
      case SourceCategory.Db:
      case SourceCategory.Kb:
      case SourceCategory.Storage:
        return this.createContextTool();
    }
  }

  /**
   * The record-shaped wrapper for `db`, `kb` and `storage`, without requiring a
   * context. Use when composing tools ahead of a request; the context is still
   * supplied per call and still validated there.
   */
  createContextTool(): SecureContextToolWrapper {
    const options: SecureContextWrapperOptions = {
      signingKey: this.options.signingKey,
      enforceSignatures: this.options.enforceSignatures,
      enforceExpiry: this.options.enforceExpiry,
      ...(this.options.allowedTools !== undefined
        ? { allowedTools: this.options.allowedTools }
        : {}),
      ...(this.options.allowUnenforceableShapes !== undefined
        ? { allowUnenforceableShapes: this.options.allowUnenforceableShapes }
        : {}),
    };
    return new SecureContextToolWrapper(options);
  }

  /** The HTTP wrapper for `api` sources. Requires `fetchFn`. */
  createHttpTool(): SecureHttpToolWrapper {
    const fetchFn = this.options.fetchFn;
    if (fetchFn === undefined) {
      throw new ToolCreationError(
        "an api source needs options.fetchFn; the factory does not open connections",
      );
    }

    const options: SecureHttpWrapperOptions = {
      signingKey: this.options.signingKey,
      enforceSignatures: this.options.enforceSignatures,
      enforceExpiry: this.options.enforceExpiry,
      ...(this.options.baseUrl !== undefined ? { baseUrl: this.options.baseUrl } : {}),
    };
    return new SecureHttpToolWrapper(options, fetchFn);
  }

  /**
   * The category this context's source belongs to, or `undefined` when the
   * identifier is unparseable. Lets a caller branch before requesting a tool.
   */
  categoryOf(context: SecurityContext): SourceCategory | undefined {
    return sourceCategory(context.effectivePolicy?.sourceConnectionId);
  }

  private assertUsableContext(context: SecurityContext): void {
    // Signature before expiry, matching the wrappers: a tampered context must report
    // a signature failure rather than disclose that an otherwise-valid context had
    // merely expired.
    if (this.options.enforceSignatures && !validateContext(context, this.options.signingKey)) {
      throw new ToolCreationError("invalid signature");
    }

    if (this.options.enforceExpiry) {
      const expiryReason = validateExpiry(context);
      if (expiryReason !== undefined) {
        throw new ToolCreationError(expiryReason);
      }
    }

    if (context.effectivePolicy === undefined || context.effectivePolicy === null) {
      throw new ToolCreationError("context carries no effective policy");
    }
  }
}
