"""TOLAP MCP - Secure MCP tool wrapper with policy enforcement."""

from tolap_core.enforced_result import EnforcedResult
from tolap_mcp.interfaces import RequestIdentityExtractor
from tolap_mcp.options import SecureMcpServerOptions
from tolap_mcp.wrapper import SecureMcpToolWrapper
from tolap_mcp.extractors import (
    HeaderIdentityExtractor,
    JwtIdentityExtractor,
    TolapIdentityError,
)
from tolap_mcp.http_wrapper import (
    MAX_REDIRECTS,
    SecureHttpToolWrapper,
    UpstreamHttpError,
)
from tolap_mcp.factory import (
    SecureTool,
    SecureToolFactory,
    ToolCreationError,
)
from tolap_mcp.bedrock_judge import (
    DEFAULT_SYSTEM_PROMPT,
    UNAVAILABLE_FLAG,
    BedrockConverseClient,
    BedrockJudge,
    build_user_prompt,
    parse_judge_response,
)

__all__ = [
    # Re-exported so a tool built against the MCP wrapper can declare its result
    # already enforced without importing tolap-core directly.
    "EnforcedResult",
    "RequestIdentityExtractor",
    "SecureMcpServerOptions",
    "SecureMcpToolWrapper",
    "HeaderIdentityExtractor",
    "JwtIdentityExtractor",
    "TolapIdentityError",
    "MAX_REDIRECTS",
    "SecureHttpToolWrapper",
    "UpstreamHttpError",
    "SecureTool",
    "SecureToolFactory",
    "ToolCreationError",
    # The optional Bedrock-backed semantic judge (canonical spec section 15.4). The
    # transport is a Protocol the integrator implements, so this package keeps its two
    # runtime dependencies and boto3 stays out of everyone's enforcement path.
    "DEFAULT_SYSTEM_PROMPT",
    "UNAVAILABLE_FLAG",
    "BedrockConverseClient",
    "BedrockJudge",
    "build_user_prompt",
    "parse_judge_response",
]
