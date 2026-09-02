/**
 * @aws/tolap-mcp - TOLAP MCP Tool Wrapper Package
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
// Semantic judge over Bedrock Converse (canonical spec §15.4).
//
// The AWS SDK is deliberately NOT a dependency of this package: the transport is a
// one-method seam the integrator implements, and the prompt, parsing, timeout and
// fail-closed mapping live here where they can be tested.
export {
  BedrockJudge,
  DEFAULT_JUDGE_SYSTEM_PROMPT,
  JUDGE_UNAVAILABLE_FLAG,
  buildJudgeUserPrompt,
  parseJudgeResponse,
  type BedrockConverseClient,
} from "./bedrock-judge.js";
export {
  SecureToolFactory,
  ToolCreationError,
  type SecureToolFactoryOptions,
  type SecureTool,
} from "./factory.js";
