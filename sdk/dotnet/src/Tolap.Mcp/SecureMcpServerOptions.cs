using Tolap.Store;

namespace Tolap.Mcp;

/// <summary>
/// Enforcement mode for the secure MCP server wrapper.
/// </summary>
/// <remarks>
/// The members deliberately do not mirror the TypeScript SDK's <c>EnforcementMode</c>,
/// which has <c>Strict</c>, <c>AuditOnly</c>, and <c>Disabled</c>. Only <c>Strict</c> is
/// common to both. <see cref="Permissive"/> has no TypeScript counterpart -- TypeScript's
/// <c>AuditOnly</c> is named as though it were one but still denies -- and TypeScript's
/// <c>Disabled</c> has no counterpart here. There is no audit-only mode in this SDK.
/// </remarks>
public enum EnforcementMode
{
    /// <summary>
    /// Strict mode: all policy violations result in denied access. The default.
    /// </summary>
    Strict,

    /// <summary>
    /// Permissive mode: policy violations are logged and access is <b>granted anyway</b>.
    /// </summary>
    /// <remarks>
    /// This genuinely grants access. Every pre-execution denial -- <c>canQuery</c> false, a
    /// hidden object, an object outside the allowed set -- becomes an allow whose
    /// <see cref="ToolExecutionResult.DenialReason"/> is prefixed <c>[permissive]</c> while
    /// <see cref="ToolExecutionResult.Allowed"/> is <c>true</c>. There is no enforcement
    /// left to speak of, so it MUST NOT be used in production; it exists for migration.
    /// <see cref="SecureMcpToolWrapper"/> warns at construction whenever it is set
    /// (threat-model remediation R-6).
    /// <para>
    /// Note this is a genuine allow, unlike TypeScript's <c>AuditOnly</c>, whose name and
    /// former doc-comment suggested the same thing but which denies exactly like
    /// <see cref="Strict"/>. Do not treat the two as equivalent when porting a
    /// configuration between SDKs.
    /// </para>
    /// </remarks>
    Permissive
}

/// <summary>
/// Configuration options for the secure MCP server wrapper.
/// </summary>
/// <param name="AllowUnenforceableShapes">
/// Pass through tool results the policy cannot be applied to.
/// <para>
/// Off by default: a POCO/DTO, a scalar, a stream, or an unmaterialized iterator is
/// denied rather than returned unfiltered (canonical-enforcement-spec.md section 5).
/// Integrators mid-migration may opt in per wrapper, which is logged every time it
/// lets a result through.
/// </para>
/// </param>
/// <param name="HashSalt">
/// Secret salt for <c>hash</c> masking, turning the digest into a keyed HMAC.
/// <para>
/// Unset by default, which preserves the plain-digest pseudonym (and so existing join
/// keys). Set it and <c>hash</c> becomes a confidentiality control: an unsalted digest of
/// a low-entropy value — an SSN, a date of birth, a small enumeration — is recoverable by
/// brute force or a rainbow table, because the input space is small enough to enumerate.
/// </para>
/// <para>
/// Treat it as a secret on a par with <c>SigningKey</c>: store it in a secrets manager or
/// KMS, never in the policy JSON (policies are visible to every admin and auditor who can
/// read them). The same salt must be configured everywhere the pseudonym is joined, since
/// changing it changes every masked value.
/// </para>
/// </param>
public sealed record SecureMcpServerOptions(
    IPolicyStore PolicyStore,
    IIdentityResolver IdentityResolver,
    IRequestIdentityExtractor IdentityExtractor,
    string SigningKey,
    TimeSpan? ContextTtl = null,
    Dictionary<string, string>? SourceMapping = null,
    EnforcementMode EnforcementMode = EnforcementMode.Strict,
    bool AllowUnenforceableShapes = false,
    string? HashSalt = null);
