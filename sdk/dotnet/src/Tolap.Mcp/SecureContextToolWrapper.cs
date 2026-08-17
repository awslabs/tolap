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
public sealed record SecureContextWrapperOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true,
    string[]? AllowedTools = null,
    bool AllowUnenforceableShapes = false,
    string? HashSalt = null);

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
