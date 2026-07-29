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
  /** Log violations but allow access (audit mode). */
  AuditOnly = "audit-only",
  /** Disable enforcement entirely. */
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
