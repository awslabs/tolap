/**
 * @tolap/mcp - TOLAP MCP Tool Wrapper Package
 *
 * Provides secure wrapping for MCP tool calls with TOLAP policy enforcement.
 */

export {
  EnforcementMode,
  type RequestIdentityExtractor,
  type McpRequestContext,
  type McpToolDefinition,
  type SecureMcpServerOptions,
  type EnforcementDecision,
} from "./types.js";

export { SecureMcpToolWrapper } from "./wrapper.js";
export {
  HeaderIdentityExtractor,
  IdentityExtractionError,
  JwtIdentityExtractor,
  type JwtExtractorOptions,
} from "./extractors.js";
export {
  SecureContextToolWrapper,
  type SecureContextWrapperOptions,
  type PreExecuteArgs,
  type SqlQueryPreparation,
} from "./context-wrapper.js";
export {
  MAX_REDIRECTS,
  SecureHttpToolWrapper,
  UpstreamHttpError,
  type SecureHttpWrapperOptions,
  type RequestArgs,
  type FetchLike,
} from "./http-wrapper.js";
export {
  SecureToolFactory,
  ToolCreationError,
  type SecureToolFactoryOptions,
  type SecureTool,
} from "./factory.js";
