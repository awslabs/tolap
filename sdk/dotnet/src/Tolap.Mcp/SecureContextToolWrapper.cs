using System.Diagnostics;
using Tolap.Core;

namespace Tolap.Mcp;

/// <summary>
/// Configuration for the context-driven secure tool wrapper.
/// </summary>
/// <param name="AllowUnenforceableShapes">
/// Pass through tool results the policy cannot be applied to. Off by default; see
/// canonical-enforcement-spec.md section 5.
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
/// <param name="ToolActionCategories">
/// Tool name to semantic action category, for purpose-bound action validation
/// (canonical-enforcement-spec.md section 15.2). Set this alongside
/// <paramref name="AllowedTools"/> whenever any policy the wrapper may resolve carries a
/// <c>purposeProfile</c> that constrains actions.
/// <para>
/// Configuration rather than a caller argument, deliberately: an agent that can name its own
/// action category can name a permitted one, which reduces the check to a formality. Unset,
/// a purpose-agnostic policy behaves exactly as before — and a purpose-bound one that
/// constrains actions denies every call, because a tool the map does not classify cannot be
/// shown to serve the purpose.
/// </para>
/// </param>
/// <param name="Judge">
/// The semantic judge, enabling <see cref="SecureContextToolWrapper.PreExecuteAsync"/> to
/// apply a policy's <c>purposeProfile.judge</c> block (spec section 15.4).
/// <para>
/// Unset, <c>PreExecuteAsync</c> behaves exactly as <c>PreExecute</c> — a policy that asks for
/// a judge with none configured is <b>not</b> an error, because the deterministic checks have
/// already run and the judge can only subtract. Set it and the policy's <c>model</c>,
/// <c>historyWindow</c>, thresholds and <c>maxLatencyMs</c> take effect without any glue of
/// yours; a mismatch between the policy's model and <see cref="IJudge.ModelId"/> escalates
/// before the call is issued.
/// </para>
/// </param>
/// <param name="ToolCallHistory">
/// The trajectory the judge reasons over. <b>You</b> own the instance, and therefore its
/// retention: tool calls can carry the arguments a caller passed, so how long they live and
/// where they are stored is a decision the wrapper must not make for you. Trimmed to the
/// policy's <c>historyWindow</c> on each call regardless of how large it grows.
/// <para>Unset, the judge sees only the current call — which is enough for an obviously
/// off-purpose request and not enough for drift, where each step is individually defensible
/// and the sequence is not.</para>
/// </param>
/// <param name="EscalationHandler">
/// Where an ambiguous verdict goes for review. Receives the outcome and returns whether the
/// call may proceed.
/// <para>
/// Unset, <c>Escalate</c> is a <b>denial</b>. That is the whole point of the disposition: if
/// escalation defaulted to permitting, "escalate to human review" would silently mean "allow"
/// in every deployment that never built a review path — a fail-open on exactly the cases the
/// judge exists to surface.
/// </para>
/// </param>
public sealed record SecureContextWrapperOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true,
    string[]? AllowedTools = null,
    bool AllowUnenforceableShapes = false,
    string? HashSalt = null,
    IReadOnlyDictionary<string, string>? ToolActionCategories = null,
    IJudge? Judge = null,
    ToolCallHistory? ToolCallHistory = null,
    Func<JudgeOutcome, Task<bool>>? EscalationHandler = null);

/// <summary>
/// Pre-execution arguments describing what the tool is about to do.
/// </summary>
public sealed record PreExecuteArgs(
    string ToolName,
    string? ObjectName = null,
    string[]? Fields = null,
    string? EndpointPath = null,
    string? EndpointMethod = null);

/// <summary>
/// Context-driven secure tool wrapper. Mirrors Python's
/// SecureMcpToolWrapper.execute_with_enforcement and TypeScript's
/// SecureContextToolWrapper.
///
/// Use this when you already hold a signed SecurityContext (rather than the
/// MCP-style SecureMcpToolWrapper which resolves identity to a policy via
/// IdentityExtractor + PolicyStore).
/// </summary>
public sealed class SecureContextToolWrapper
{
    private readonly SecureContextWrapperOptions _options;

    public SecureContextToolWrapper(SecureContextWrapperOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Validates signature then expiry. Signature first, so a tampered context reports a
    /// signature failure rather than revealing whether a valid context merely expired.
    /// </summary>
    public AccessResult ValidateSecurityContext(SecurityContext context)
    {
        if (_options.EnforceSignatures
            && !SecurityContextSigner.Validate(context, _options.SigningKey))
        {
            return new AccessResult(false, "invalid signature");
        }

        if (_options.EnforceExpiry)
        {
            // A missing expiry is a denial, never a skipped check.
            var expiryReason = SecurityContextSigner.ValidateExpiry(context);
            if (expiryReason is not null)
            {
                return new AccessResult(false, expiryReason);
            }
        }

        // The delegation chain, if the context carries one (spec section 15.3).
        //
        // Validated here rather than left to the integrator, and here rather than in
        // `SecurityContextBuilder`, for two reasons that pull the same way. A builder that
        // validated would have to either throw -- making issuing brittle -- or drop the chain,
        // which emits a context that looks delegated and is not; so the builder records and
        // this side checks. And the check is only meaningful *after* the signature: the
        // signature proves the chain was not modified in transit, which is a different and
        // weaker claim than the chain being valid, and an unsigned chain can be rewritten by
        // the principal it constrains.
        //
        // Backward compatible: a context with no chain, or a single hop, is allowed, so a
        // caller that does not delegate is unaffected.
        var chainResult = DelegationChainValidator.Validate(context.DelegationChain);
        if (!chainResult.Allowed)
        {
            return chainResult;
        }

        return new AccessResult(true);
    }

    public AccessResult PreExecute(SecurityContext context, PreExecuteArgs args)
    {
        var ctxResult = ValidateSecurityContext(context);
        if (!ctxResult.Allowed) return ctxResult;

        if (_options.AllowedTools is not null
            && _options.AllowedTools.Length > 0
            && !_options.AllowedTools.Contains(args.ToolName))
        {
            return new AccessResult(false, "tool not in allowed list");
        }

        var policy = context.Policies.FirstOrDefault();
        if (policy is null)
        {
            return new AccessResult(false, "no policy in context");
        }

        if (!policy.Permissions.CanQuery)
        {
            return new AccessResult(false, "query not permitted");
        }

        // Purpose-bound action validation, after the read gate and before the object rules.
        // The ordering matters in both directions: after canQuery, because a policy that
        // grants no reads should say so rather than complain about a category; before the
        // object rules, because "this action does not serve the declared purpose" is the more
        // specific answer when both would deny, and it is the one that tells an operator what
        // actually went wrong.
        var actionResult = PurposeActionResolver.ValidateTool(
            policy, args.ToolName, _options.ToolActionCategories);
        if (!actionResult.Allowed) return actionResult;

        if (args.ObjectName is not null)
        {
            var r = EnforcementEngine.ValidateAccess(args.ObjectName, policy);
            if (!r.Allowed) return r;
        }

        if (args.Fields is not null && args.Fields.Length > 0)
        {
            var r = EnforcementEngine.ValidateFieldAccess(args.Fields, policy);
            if (r.Denied.Length > 0)
            {
                return new AccessResult(false, $"denied fields: {string.Join(", ", r.Denied)}");
            }
        }

        if (args.EndpointPath is not null)
        {
            var method = args.EndpointMethod ?? "GET";
            var r = EnforcementEngine.ValidateEndpoint(args.EndpointPath, method, policy);
            if (!r.Allowed) return r;
        }

        return new AccessResult(true);
    }

    /// <summary>
    /// The deterministic checks, then the semantic judge (spec sections 15.1-15.4).
    /// </summary>
    /// <remarks>
    /// <para>Separate from <see cref="PreExecute"/> rather than replacing it, because a judge
    /// makes a network call and <c>PreExecute</c> is synchronous. Both are supported: a
    /// deployment with no judge keeps the synchronous path and pays nothing.</para>
    /// <para>Order is not negotiable. The deterministic checks run first and the judge is
    /// consulted only if they <i>allowed</i> the call, so the judge can only ever withdraw an
    /// allowance. It is never asked to permit something the rules refused. This is what makes
    /// prompt injection through the tool call survivable rather than critical: the worst a
    /// manipulated verdict achieves is an allow that was already granted.</para>
    /// <para>The call is recorded in <see cref="SecureContextWrapperOptions.ToolCallHistory"/>
    /// whether or not it is permitted. A refused call is part of the trajectory — an agent
    /// probing for what it can reach is precisely the pattern the judge is meant to notice, and
    /// a history that kept only successes would hide it.</para>
    /// </remarks>
    public async Task<AccessResult> PreExecuteAsync(
        SecurityContext context,
        PreExecuteArgs args,
        CancellationToken ct = default)
    {
        var deterministic = PreExecute(context, args);

        var rendered = RenderToolCall(args);
        _options.ToolCallHistory?.Record(rendered);

        if (!deterministic.Allowed) return deterministic;
        if (_options.Judge is null) return deterministic;

        var policy = context.Policies.FirstOrDefault();
        if (policy is null) return new AccessResult(false, "no policy in context");

        var outcome = await JudgeGate.EvaluateAsync(
            policy, _options.Judge, rendered, _options.ToolCallHistory, ct);

        if (outcome.Disposition == JudgeDisposition.Allow) return new AccessResult(true);

        if (outcome.Disposition == JudgeDisposition.Escalate
            && _options.EscalationHandler is not null)
        {
            // A review path exists, so the ambiguous case is its decision rather than a flat
            // denial. Everything else about the outcome is still reported to it.
            return await _options.EscalationHandler(outcome)
                ? new AccessResult(true)
                : new AccessResult(false, outcome.Reason);
        }

        return new AccessResult(false, outcome.Reason);
    }

    /// <summary>
    /// Renders a call as the one line the judge reasons over.
    /// </summary>
    /// <remarks>
    /// Deterministic and includes only what the wrapper was given: the tool name, and the
    /// object, fields and endpoint when present. Field <i>names</i> appear because "which
    /// columns" is most of what makes a read on-purpose or not; field <i>values</i> never reach
    /// here, so no row data is sent to a model by this path.
    /// </remarks>
    /// <remarks>
    /// Public because it is what a deployment sees in its judge's audit trail, and because an
    /// integrator wiring <see cref="JudgeGate"/> directly needs the same rendering the wrapper
    /// uses — two renderings of one call would make the wrapper's history and a hand-rolled
    /// one incomparable.
    /// </remarks>
    public static string RenderToolCall(PreExecuteArgs args)
    {
        var parts = new List<string>();
        if (args.ObjectName is { Length: > 0 }) parts.Add($"object={args.ObjectName}");
        if (args.Fields is { Length: > 0 }) parts.Add($"fields=[{string.Join(",", args.Fields)}]");
        if (args.EndpointPath is { Length: > 0 })
            parts.Add($"endpoint={args.EndpointMethod ?? "GET"} {args.EndpointPath}");

        return parts.Count == 0
            ? $"{args.ToolName}()"
            : $"{args.ToolName}({string.Join(" ", parts)})";
    }

    /// <summary>
    /// Validates a write before it is issued (connector-spec.md section 4).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The write counterpart to <see cref="PreExecute"/>. Validates the context, then runs the
    /// four required pre-write checks: the operation's permission and the <c>readOnly</c>
    /// ceiling, the target object, every field in the payload, and the policy's row filters
    /// against <see cref="WriteValidationOptions.TargetRow"/>.
    /// </para>
    /// <para>
    /// Fails closed on the whole write: one unwritable field denies the operation rather than
    /// being stripped so the rest can proceed (section 4.4).
    /// </para>
    /// <para>
    /// Omitting the target row on an update or delete while the policy carries row filters
    /// yields <c>write target unverifiable</c>, never an allow — read the row first and pass
    /// it here, or push the filters into the statement's <c>WHERE</c>.
    /// </para>
    /// <para>
    /// A permitted write that returns data is a <i>read</i> of that data: pass the response
    /// through <see cref="PostExecuteResult"/> (section 4.5).
    /// </para>
    /// </remarks>
    public AccessResult PreWrite(
        SecurityContext context,
        WriteOperation operation,
        string? objectName = null,
        IReadOnlyDictionary<string, object?>? payload = null,
        WriteValidationOptions? options = null)
    {
        var ctxResult = ValidateSecurityContext(context);
        if (!ctxResult.Allowed) return ctxResult;

        var policy = context.Policies.FirstOrDefault();
        if (policy is null)
        {
            return new AccessResult(false, "no policy in context");
        }

        return EnforcementEngine.ValidateWrite(operation, objectName, payload, policy, options);
    }

    /// <summary>
    /// Validates a write, issues it, and enforces the policy on anything it returns.
    /// </summary>
    /// <remarks>
    /// The delegate is not invoked when the write is denied, so a refused write never reaches
    /// the source. Whatever the write returns is treated as a read of that data and goes
    /// through the full post-execution pipeline (connector-spec.md section 4.5) — a masked
    /// field comes back masked even though the caller just wrote it, and a hidden field does
    /// not appear at all. A write that returns nothing (<c>null</c>) is passed through as-is
    /// rather than denied as an unenforceable shape: there is no data to enforce a policy over.
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">Thrown when the write is denied.</exception>
    public async Task<object?> ExecuteWriteWithEnforcementAsync(
        SecurityContext context,
        WriteOperation operation,
        Func<Task<object?>> writeFn,
        string? objectName = null,
        IReadOnlyDictionary<string, object?>? payload = null,
        WriteValidationOptions? options = null)
    {
        var pre = PreWrite(context, operation, objectName, payload, options);
        if (!pre.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {pre.Reason}");
        }

        var result = await writeFn().ConfigureAwait(false);
        return result is null ? null : PostExecuteResult(context, result);
    }

    /// <summary>
    /// Runs the pre-execution checks and rewrites a SQL query so the policy's restrictions
    /// reach the database.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An optional step, and never a replacement for <see cref="PostExecute"/>: the
    /// post-execution pipeline stays mandatory and stays the enforcement point
    /// (canonical-enforcement-spec.md section 4). What this adds is that a row the policy
    /// excludes is not fetched and materialized before being discarded (threat-model D2). A
    /// caller that skips this method loses the resource saving and nothing else.
    /// </para>
    /// <para>
    /// The object name is taken from the query's own <c>FROM</c> clause when
    /// <see cref="PreExecuteArgs.ObjectName"/> is null, so an <c>allowedObjects</c> rule
    /// applies to the table the query actually reads rather than to whatever the caller
    /// declared. Typical use:
    /// </para>
    /// <code>
    /// var prep = wrapper.PrepareSqlQuery(ctx, new PreExecuteArgs("pg-query"), sql);
    /// if (!prep.Allowed) throw new UnauthorizedAccessException(prep.DenialReason);
    /// var rows = await RunAsync(prep.Query);
    /// return wrapper.PostExecute(ctx, rows);   // still required
    /// </code>
    /// </remarks>
    /// <param name="context">The signed security context.</param>
    /// <param name="args">
    /// What the call is about to do. A null <see cref="PreExecuteArgs.ObjectName"/> is filled
    /// in from the query.
    /// </param>
    /// <param name="sql">The query to check and rewrite.</param>
    /// <param name="rewriter">
    /// The rewriter to use, or null for a default instance. Supply one to receive its
    /// diagnostics.
    /// </param>
    /// <param name="dialect">
    /// The engine <paramref name="sql"/> will run against (connector-spec.md section 5.1) —
    /// yours to supply, since only you know which connection this is for. Null selects the
    /// rewriter's own dialect, or <see cref="SqlDialect.Ansi"/>. An unrecognized value rewrites
    /// nothing and reports every filter in
    /// <see cref="SqlQueryPreparation.UnpushableFilters"/>; the pre-execution checks still run
    /// either way, so declining to rewrite never relaxes a denial.
    /// </param>
    public SqlQueryPreparation PrepareSqlQuery(
        SecurityContext context,
        PreExecuteArgs args,
        string sql,
        ISqlQueryRewriter? rewriter = null,
        SqlDialect? dialect = null,
        SqlEnforcementMode? mode = null)
    {
        // Resolved before any work so an out-of-range mode throws rather than rewriting a
        // query the caller asked not to be touched.
        var resolvedMode = SqlEnforcementModes.Resolve(mode);
        rewriter ??= new SqlQueryRewriter();

        if (string.IsNullOrWhiteSpace(sql))
        {
            return SqlQueryPreparation.Denied("query is empty", sql);
        }

        // Resolve the object from the query itself when the caller did not name one: an
        // allowedObjects rule must apply to the table being read, not to a declaration the
        // query is free to contradict.
        var effectiveArgs = args.ObjectName is null
            ? args with { ObjectName = rewriter.ExtractTableName(sql) }
            : args;

        var pre = PreExecute(context, effectiveArgs);
        if (!pre.Allowed)
        {
            return SqlQueryPreparation.Denied(pre.Reason ?? "access denied", sql);
        }

        // Non-null: PreExecute above denies a context with no policy, so this is only reached
        // once one is present.
        var policy = context.Policies[0];

        // Refuse rather than silently narrow: an agent that asked for a field it cannot read
        // should be told, not handed a result that quietly omits the column.
        if (!rewriter.ValidateQuery(sql, policy))
        {
            return SqlQueryPreparation.Denied(
                "query references fields you do not have permission to access", sql);
        }

        // Every check above runs in both modes. Only the rewrite below is optional.
        if (resolvedMode == SqlEnforcementMode.PostOnly)
        {
            // The caller's query, byte for byte. UnpushableFilters reports EVERY filter
            // rather than the subset the rewriter could not express, because in this mode
            // none of them reached the database -- a caller checking FullyPushedDown before
            // executing a large query must get false here.
            return new SqlQueryPreparation(
                Allowed: true,
                DenialReason: null,
                Query: sql,
                Rewritten: false,
                UnpushableFilters: policy.ObjectRules?.RowFilters ?? []);
        }

        var rewritten = rewriter.RewriteQuery(sql, policy, dialect);

        return new SqlQueryPreparation(
            Allowed: true,
            DenialReason: null,
            Query: rewritten,
            Rewritten: !string.Equals(rewritten, sql, StringComparison.Ordinal),
            UnpushableFilters: rewriter.UnpushableFilters(policy, dialect));
    }

    /// <summary>
    /// Prepares a SQL query, executes it, and applies the post-execution pipeline.
    /// </summary>
    /// <remarks>
    /// The pushed-down and post-fetch halves of enforcement in one call. The delegate receives
    /// the rewritten query; the pipeline still runs over whatever it returns, so a filter that
    /// could not be pushed down is still enforced.
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">
    /// Thrown when the query is refused. The delegate is not invoked in that case.
    /// </exception>
    /// <param name="context">The signed security context.</param>
    /// <param name="args">What the call is about to do.</param>
    /// <param name="sql">The query to check, rewrite, and execute.</param>
    /// <param name="execute">Runs the rewritten query and returns its rows.</param>
    /// <param name="rewriter">The rewriter to use, or null for a default instance.</param>
    /// <param name="dialect">
    /// The engine <paramref name="execute"/> will run the query against (connector-spec.md
    /// section 5.1). Null selects the rewriter's own dialect, or <see cref="SqlDialect.Ansi"/>.
    /// </param>
    public async Task<IReadOnlyList<Dictionary<string, object?>>> ExecuteSqlWithEnforcementAsync(
        SecurityContext context,
        PreExecuteArgs args,
        string sql,
        Func<string, Task<IReadOnlyList<Dictionary<string, object?>>>> execute,
        ISqlQueryRewriter? rewriter = null,
        SqlDialect? dialect = null,
        SqlEnforcementMode? mode = null)
    {
        var prep = PrepareSqlQuery(context, args, sql, rewriter, dialect, mode);
        if (!prep.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {prep.DenialReason}");
        }

        var raw = await execute(prep.Query).ConfigureAwait(false);
        return PostExecute(context, raw);
    }

    /// <summary>
    /// Applies the canonical post-execution pipeline to a result set.
    /// </summary>
    /// <remarks>
    /// Order (canonical-enforcement-spec.md section 4): row filters -> tag filters ->
    /// hidden fields -> allowed fields -> masking -> result limit. Hidden-field removal
    /// and allowed-field projection are mandatory here: the pre-execution field check
    /// only inspects the fields a caller volunteers, so a tool returning undeclared
    /// columns (<c>SELECT *</c>) would otherwise leak them.
    /// </remarks>
    public IReadOnlyList<Dictionary<string, object?>> PostExecute(
        SecurityContext context,
        IReadOnlyList<Dictionary<string, object?>> rows)
    {
        var policy = context.Policies.FirstOrDefault()
                     ?? throw new InvalidOperationException("no policy in context");

        return EnforcementEngine.ApplyRecordPipeline(rows, policy, _options.HashSalt);
    }

    /// <summary>
    /// Applies the canonical post-execution pipeline to an arbitrary tool result.
    /// </summary>
    /// <remarks>
    /// A single record runs the identical pipeline (a get-by-id tool must not skip row
    /// or tag filters). Any other shape is denied unless the wrapper was configured with
    /// <see cref="SecureContextWrapperOptions.AllowUnenforceableShapes"/>.
    /// </remarks>
    /// <exception cref="UnenforceableResultException">
    /// Thrown for a shape the policy cannot be applied to.
    /// </exception>
    public object? PostExecuteResult(SecurityContext context, object? result)
    {
        var policy = context.Policies.FirstOrDefault()
                     ?? throw new InvalidOperationException("no policy in context");

        if (EnforcementEngine.ClassifyResultShape(result) == ResultShape.Unenforceable
            && _options.AllowUnenforceableShapes)
        {
            Trace.TraceWarning(
                "TOLAP enforcement bypassed: AllowUnenforceableShapes is enabled and the tool "
                + $"returned {EnforcementEngine.DescribeResultShape(result)}, which is passed "
                + "through unfiltered.");
            return result;
        }

        return EnforcementEngine.ApplyResultPipeline(result, policy, _options.HashSalt);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> ExecuteWithEnforcementAsync(
        SecurityContext context,
        PreExecuteArgs args,
        Func<Task<IReadOnlyList<Dictionary<string, object?>>>> toolFn)
    {
        var pre = PreExecute(context, args);
        if (!pre.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {pre.Reason}");
        }
        var raw = await toolFn().ConfigureAwait(false);
        return PostExecute(context, raw);
    }

    /// <summary>
    /// Executes a tool whose result shape is not statically known and applies full
    /// pre/post enforcement.
    /// </summary>
    /// <exception cref="UnauthorizedAccessException">
    /// Thrown when the pre-execution check denies the call, or when the tool returns a
    /// shape the policy cannot be applied to.
    /// </exception>
    public async Task<object?> ExecuteWithEnforcementAsync(
        SecurityContext context,
        PreExecuteArgs args,
        Func<Task<object?>> toolFn)
    {
        var pre = PreExecute(context, args);
        if (!pre.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {pre.Reason}");
        }
        var raw = await toolFn().ConfigureAwait(false);
        return PostExecuteResult(context, raw);
    }
}
