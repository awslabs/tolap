using Tolap.Core;

namespace Tolap.Mcp;

/// <summary>
/// Raised when a tool cannot be produced.
/// </summary>
/// <remarks>
/// Never carries policy contents — the message names the rule or the configuration gap, not
/// the data (connector-spec.md section 3.3).
/// </remarks>
public sealed class ToolCreationException : InvalidOperationException
{
    public ToolCreationException(string message) : base(message) { }
}

/// <summary>
/// The tool produced for a source: exactly one of the two wrappers is non-null, chosen by the
/// source's category.
/// </summary>
/// <remarks>
/// <para>
/// A discriminated result rather than a common interface or a bare <c>object</c>. The two
/// wrappers do genuinely different things — one prepares SQL for the caller to execute, the
/// other performs an HTTP request — so a shared interface would either be empty or force one
/// wrapper to carry the other's vocabulary. Returning <c>object</c> would push the cast onto
/// every caller and lose the compiler's help.
/// </para>
/// <para>
/// <see cref="Category"/> is carried so a caller can switch on it rather than null-testing,
/// and it is the category read from the <i>signed</i> identifier.
/// </para>
/// </remarks>
public sealed record SecureTool(
    SourceCategory Category,
    SecureContextToolWrapper? RecordTool = null,
    SecureHttpToolWrapper? HttpTool = null);

/// <summary>
/// Options for <see cref="SecureToolFactory"/>, forwarded to the produced wrapper.
/// </summary>
/// <param name="SigningKey">Key the context signature is verified against.</param>
/// <param name="EnforceSignatures">
/// Verify the signature before producing a tool. On by default; turning it off means an
/// unsigned or forged context yields a working tool.
/// </param>
/// <param name="EnforceExpiry">Reject an expired context. On by default.</param>
/// <param name="AllowedTools">
/// Restrict which tool names the record-shaped wrapper will run.
/// </param>
/// <param name="AllowUnenforceableShapes">
/// Off by default: a result the policy cannot be applied to is denied rather than returned
/// unfiltered.
/// </param>
public sealed record SecureToolFactoryOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true,
    string[]? AllowedTools = null,
    bool AllowUnenforceableShapes = false);

/// <summary>
/// Secure Tool Factory — the composition root for policy-enforced tools
/// (architecture.md section 5).
/// </summary>
/// <remarks>
/// <para>
/// <b>What this exists for.</b> Enforcement is only non-bypassable if the wrapper is the
/// <i>sole</i> path to the data source (architecture.md section 4). A factory is how that
/// becomes structural rather than a convention: an agent receives its tools from here and
/// never constructs one, so there is no code path that reaches a source unwrapped. Wiring
/// each tool by hand at call sites works right up until one site forgets, and a forgotten
/// wrapper is indistinguishable from an enforced one until someone audits it.
/// </para>
/// <para>
/// <b>What it deliberately does NOT do.</b> The reference implementation's factory also
/// brokered credentials and pinned connection configuration. Neither belongs here, because
/// <b>this SDK never holds a connection</b>: <see cref="SecureContextToolWrapper"/> hands
/// back rewritten SQL for the caller to execute, and <see cref="SecureHttpToolWrapper"/> is
/// given its <see cref="HttpClient"/> by the caller. Nothing on the enforcement path —
/// validate, rewrite, filter, mask, limit — takes a secret as input, so accepting one would
/// add secret-handling surface to a security library that has no use for it. It is the same
/// reasoning that removed <c>limits.maxQueryTimeSeconds</c> from the schema (connector-spec
/// section 9): the SDK cannot enforce what it does not own. Credentials belong to the layer
/// that opens the connection.
/// </para>
/// <para>
/// Nor does it hold a user's <see cref="SecurityContext"/>. The documented API in the
/// implementation guides showed a <c>SetSecurityContext()</c> call that made a wrapper
/// stateful; the shipped wrappers take the context <b>per call</b> instead. That is a safety
/// property, not an oversight — a context stored on a shared instance can outlive the request
/// that supplied it and be reused for the next caller, who may be a different user.
/// Factory-produced wrappers are stateless and reusable for exactly that reason.
/// </para>
/// <para>
/// <b>Dispatch is on the signed category.</b> The wrapper a source needs is decided by the
/// <c>category</c> segment of its <c>SourceConnectionId</c> (connector-spec section 1), read
/// from the <b>signed</b> policy rather than from unsigned configuration. A category taken
/// from a side channel could disagree with the policy the context carries: flipping
/// <c>db</c> to <c>api</c> would select the wrapper that enforces the other category's rules,
/// and <c>endpointRules</c> do not constrain a SQL query. Inside the signed bytes, changing
/// it breaks the signature.
/// </para>
/// <para>
/// Mirrors <c>factory.ts</c> and <c>factory.py</c>.
/// </para>
/// </remarks>
public sealed class SecureToolFactory
{
    private readonly SecureToolFactoryOptions _options;
    private readonly HttpClient? _client;

    /// <param name="options">Forwarded to the produced wrapper.</param>
    /// <param name="client">
    /// Transport for <c>api</c> sources. Required only to produce an <c>api</c> tool: the
    /// factory never opens a connection of its own, so the caller supplies the client.
    /// Requesting an <c>api</c> tool without one throws <see cref="ToolCreationException"/>
    /// rather than constructing a default <see cref="HttpClient"/>, which would quietly
    /// bypass the caller's handler chain, proxy, and timeout configuration.
    /// </param>
    public SecureToolFactory(SecureToolFactoryOptions options, HttpClient? client = null)
    {
        _options = options;
        _client = client;
    }

    /// <summary>
    /// Produce the enforcing tool for the source this context governs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Throws <see cref="ToolCreationException"/> when the context is not usable. Every
    /// rejection below is a <i>refusal to hand back a tool at all</i>, which is the
    /// fail-closed outcome: returning an unenforced tool for a context that failed
    /// validation would defeat the point of the factory.
    /// </para>
    /// <para>
    /// The context is validated here even though every wrapper re-validates it on each call.
    /// That is intentional redundancy: it turns "this context is forged" into an error at
    /// composition time, where it is attributable, rather than a denial on some later tool
    /// call. The per-call check remains the one that actually gates access, since a wrapper
    /// is reusable and the context arrives again with every request.
    /// </para>
    /// <para>
    /// One context governs one data source (architecture.md section 1), so this returns one
    /// tool rather than the multi-source tool <i>set</i> the guides once described. A caller
    /// holding contexts for several sources calls this per context.
    /// </para>
    /// </remarks>
    public SecureTool CreateTool(SecurityContext context)
    {
        AssertUsableContext(context);

        var policy = context.Policies.FirstOrDefault()
            ?? throw new ToolCreationException("context carries no effective policy");

        // CanQuery is the top-level read gate. A source the user cannot read produces no
        // tool: handing back a wrapper that denies every call invites a caller to treat the
        // denial as a transient error and retry.
        if (!policy.Permissions.CanQuery)
            throw new ToolCreationException("query not permitted");

        var category = SourceIdentityParser.CategoryOf(policy.SourceConnectionId);
        if (category is null)
        {
            // Unparseable identifier -> no category -> no way to know which rules apply.
            // Guessing a wrapper here would enforce the wrong category's rules.
            throw new ToolCreationException(
                "SourceConnectionId is not category:namespace:name (connector-spec section 1)");
        }

        // db, kb and storage all return records (rows, chunks, listing entries) and are
        // enforced by the record-shaped pipeline. They differ in which policy fields are
        // meaningful, and that is decided by the policy itself rather than by the wrapper
        // type — an inert field is simply never consulted (connector-spec section 2).
        return category switch
        {
            SourceCategory.Api => new SecureTool(SourceCategory.Api, HttpTool: CreateHttpTool()),
            _ => new SecureTool(category.Value, RecordTool: CreateRecordTool())
        };
    }

    /// <summary>
    /// The record-shaped wrapper for <c>db</c>, <c>kb</c> and <c>storage</c>. Takes no
    /// context: the context is supplied per call and validated there.
    /// </summary>
    public SecureContextToolWrapper CreateRecordTool()
        => new(new SecureContextWrapperOptions(
            SigningKey: _options.SigningKey,
            EnforceSignatures: _options.EnforceSignatures,
            EnforceExpiry: _options.EnforceExpiry,
            AllowedTools: _options.AllowedTools,
            AllowUnenforceableShapes: _options.AllowUnenforceableShapes));

    /// <summary>
    /// The HTTP wrapper for <c>api</c> sources. Requires a client.
    /// </summary>
    public SecureHttpToolWrapper CreateHttpTool()
    {
        if (_client is null)
        {
            throw new ToolCreationException(
                "an api source needs an HttpClient; the factory does not open connections");
        }

        return new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(
                SigningKey: _options.SigningKey,
                EnforceSignatures: _options.EnforceSignatures,
                EnforceExpiry: _options.EnforceExpiry),
            _client);
    }

    /// <summary>
    /// The category this context's source belongs to, or null when the identifier is
    /// unparseable. Lets a caller branch before requesting a tool.
    /// </summary>
    public SourceCategory? CategoryOf(SecurityContext context)
        => SourceIdentityParser.CategoryOf(context.Policies.FirstOrDefault()?.SourceConnectionId);

    private void AssertUsableContext(SecurityContext context)
    {
        // Signature before expiry, matching the wrappers: a tampered context must report a
        // signature failure rather than disclose that an otherwise-valid context had merely
        // expired.
        if (_options.EnforceSignatures
            && !SecurityContextSigner.Validate(context, _options.SigningKey))
        {
            throw new ToolCreationException("invalid signature");
        }

        if (_options.EnforceExpiry)
        {
            var expiryReason = SecurityContextSigner.ValidateExpiry(context);
            if (expiryReason is not null)
                throw new ToolCreationException(expiryReason);
        }
    }
}
