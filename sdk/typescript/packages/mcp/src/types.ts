/**
 * TOLAP MCP Types
 *
 * Types for MCP (Model Context Protocol) tool wrapping with TOLAP enforcement.
 */

import type { EffectivePolicy } from "@tolap/core";

// ---------------------------------------------------------------------------
// Enforcement Mode
// ---------------------------------------------------------------------------

export enum EnforcementMode {
  /** Enforce policies strictly -- deny access on any violation. */
  Strict = "strict",
  /**
   * Deny exactly like {@link Strict}, and additionally surface the decision for
   * auditing.
   *
   * This does **NOT** grant access. A violation is denied -- `executeTool` throws --
   * and the only difference from `Strict` is observability: the mode is reported on
   * the {@link EnforcementDecision} passed to `onEnforcementDecision`, and the
   * wrapper warns at construction. It is not a soft-launch or observe-only mode and
   * must not be shipped as one.
   *
   * This comment previously described the mode as logging violations while granting
   * access, which the implementation has never done. Making the code match that
   * description would turn every denial into an allow -- a data leak -- so the comment
   * was corrected instead. If an observe-but-permit capability is genuinely wanted it
   * is a design change, not a doc fix, and no such mode exists today.
   */
  AuditOnly = "audit-only",
  /**
   * Disable enforcement entirely: the tool runs and its result is returned
   * unfiltered, with no policy resolution, masking, or filtering.
   *
   * The only mode that actually grants unpoliced access. Intended for migration
   * only; the wrapper warns loudly at construction.
   */
  Disabled = "disabled",
}

// ---------------------------------------------------------------------------
// Request Identity Extractor
// ---------------------------------------------------------------------------

/**
 * Extracts user identity from an incoming MCP request.
 */
export interface RequestIdentityExtractor {
  /** Extract user ID from request context. */
  extractUserId(request: McpRequestContext): string | undefined;

  /** Extract tenant ID from request context. */
  extractTenantId(request: McpRequestContext): string | undefined;
}

// ---------------------------------------------------------------------------
// MCP Request Context
// ---------------------------------------------------------------------------

/**
 * Represents the context of an incoming MCP tool call.
 */
export interface McpRequestContext {
  /** HTTP headers or transport-level metadata. */
  headers?: Record<string, string>;
  /** The tool name being called. */
  toolName: string;
  /** Arguments passed to the tool. */
  arguments?: Record<string, unknown>;
  /** Source connection ID for policy resolution. */
  sourceConnectionId?: string;
}

// ---------------------------------------------------------------------------
// Tool Definition
// ---------------------------------------------------------------------------

/**
 * A wrapped MCP tool with its execution function and metadata.
 */
export interface McpToolDefinition {
  /** Tool name. */
  name: string;
  /** Human-readable description. */
  description?: string;
  /** The object/resource name this tool operates on (for access control). */
  objectName?: string;
  /** Fields this tool accesses (for field-level control). */
  accessedFields?: string[];
  /** Endpoint path this tool represents (for endpoint-level control). */
  endpointPath?: string;
  /** HTTP method this tool represents. */
  endpointMethod?: string;
  /** The actual tool execution function. */
  execute: (args: Record<string, unknown>) => Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Server Options
// ---------------------------------------------------------------------------

/**
 * Options for configuring the SecureMcpToolWrapper.
 */
export interface SecureMcpServerOptions {
  /** Enforcement mode. Defaults to Strict. */
  mode?: EnforcementMode;
  /** Secret key for validating policy signatures. */
  signingKey?: string;
  /** Function to resolve effective policy for a request. */
  resolvePolicy?: (
    userId: string,
    tenantId: string,
    sourceConnectionId: string,
  ) => Promise<EffectivePolicy>;
  /** Identity extractor. */
  identityExtractor?: RequestIdentityExtractor;
  /** Callback invoked on enforcement decisions (for logging/audit). */
  onEnforcementDecision?: (decision: EnforcementDecision) => void;
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

// ---------------------------------------------------------------------------
// Enforcement Decision
// ---------------------------------------------------------------------------

export interface EnforcementDecision {
  timestamp: string;
  toolName: string;
  userId?: string;
  tenantId?: string;
  allowed: boolean;
  reason?: string;
  mode: EnforcementMode;
}
