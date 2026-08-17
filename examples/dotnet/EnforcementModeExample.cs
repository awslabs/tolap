using System.Text.Json;
using System.Text.RegularExpressions;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Examples;

/// <summary>
/// Choosing where a database policy is applied: in the SQL, or only in the results.
/// </summary>
/// <remarks>
/// <para>
/// The other examples here wrap a framework's tool call. This one is about SQL specifically, and
/// shows the one knob an integrator has over <i>where</i> enforcement happens:
/// </para>
/// <list type="bullet">
///   <item><c>RewriteAndPost</c> (the default) — TOLAP edits the query so the database returns
///   less data, then enforces on what comes back.</item>
///   <item><c>PostOnly</c> — your query runs byte for byte as written, and enforcement happens
///   entirely on the rows returned.</item>
/// </list>
/// <para>
/// <b>Both print the same rows.</b> That is the point, and it is why the choice is safe to offer:
/// the mode is a resource decision, not an access-control one. If it changed what the caller saw
/// it would be a security setting wearing a performance setting's clothes.
/// </para>
/// <para>
/// Deliberately mirrors <c>examples/python/enforcement_mode_example.py</c> and
/// <c>examples/typescript/enforcement-mode-example.ts</c> — same policy, same rows, same printed
/// conclusion. A divergence between the languages then shows up as a different result rather than
/// hiding behind separately-written expectations.
/// </para>
/// <para>
/// There is no third "rewrite only" mode. Masking has no SQL form (no <c>SELECT</c> returns
/// <c>[REDACTED]</c>) and <c>contains</c> / <c>startsWith</c> / <c>matches</c> are not portably
/// expressible, so skipping the post pass would return unmasked values <i>and</i> rows the policy
/// excludes.
/// </para>
/// </remarks>
public static class EnforcementModeExample
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    public const string Query = "SELECT id, name, region, dob FROM patients ORDER BY id";

    /// <summary>What the "database" holds: more rows and more columns than the policy permits.</summary>
    public static List<Dictionary<string, object?>> FakeRows() =>
    [
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["dob"] = "1980-04-01", ["ssn"] = "111-22-3333" },
        new() { ["id"] = 2, ["name"] = "Bruno Sato", ["region"] = "us-east", ["dob"] = "1975-09-12", ["ssn"] = "222-33-4444" },
        new() { ["id"] = 3, ["name"] = "Chidi Okonkwo", ["region"] = "us-east", ["dob"] = "1990-01-30", ["ssn"] = "333-44-5555" },
        new() { ["id"] = 4, ["name"] = "Dana Petrova", ["region"] = "eu-west", ["dob"] = "1988-07-19", ["ssn"] = "444-55-6666" },
    ];

    /// <summary>
    /// A policy whose every rule is observable in the output.
    /// </summary>
    /// <remarks>
    /// Note the mix on purpose: <c>region</c> is an <c>Equals</c> filter the rewriter CAN push into
    /// SQL, while <c>name</c> is a <c>StartsWith</c> it cannot. So even in <c>RewriteAndPost</c> the
    /// post pass is doing real work — which is the whole reason it is never optional.
    /// </remarks>
    public static EffectivePolicy BuildPolicy()
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "user-123",
            TenantId: "tenant-acme",
            SourceConnectionId: "db:analytics:patients",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: ["enforcement-mode-example"],
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: new ObjectRules(
                AllowedObjects: ["patients"],
                FieldRules: new FieldRules(
                    HiddenFields: ["ssn"],
                    MaskedFields: [new MaskingRule("dob", MaskType.Redact)]),
                RowFilters:
                [
                    // Pushable: becomes WHERE "region" = 'us-east'.
                    new RowFilter("region", FilterOperator.Equals, Value: "us-east"),
                    // NOT pushable: no portable SQL form, so the post pass enforces it.
                    new RowFilter("name", FilterOperator.StartsWith, Value: "A"),
                ]),
            Limits: new PolicyLimits(MaxResults: 2));
    }

    public static SecurityContext BuildContext() =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("user-123", "tenant-acme", [BuildPolicy()]), SigningKey);

    /// <summary>
    /// Stand in for an engine: honour a pushed WHERE and LIMIT, ignore the rest.
    /// </summary>
    /// <remarks>
    /// Crude, and that is the point — it responds differently to the two modes, so the equality of
    /// the final output below is a real result rather than a coincidence.
    /// </remarks>
    public static Task<IReadOnlyList<Dictionary<string, object?>>> FakeDatabase(string query)
    {
        IEnumerable<Dictionary<string, object?>> rows = FakeRows();

        var eq = Regex.Match(query, "\"(\\w+)\" = '([^']*)'");
        if (eq.Success)
            rows = rows.Where(r => Convert.ToString(r[eq.Groups[1].Value]) == eq.Groups[2].Value);

        var limit = Regex.Match(query, "LIMIT (\\d+)", RegexOptions.IgnoreCase);
        if (limit.Success)
            rows = rows.Take(int.Parse(limit.Groups[1].Value));

        return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(rows.ToList());
    }

    public record ModeRun(
        SqlQueryPreparation Prep,
        IReadOnlyList<Dictionary<string, object?>> FromDatabase,
        IReadOnlyList<Dictionary<string, object?>> Final);

    /// <summary>Prepare in <paramref name="mode"/>, execute, then run the mandatory post pass.</summary>
    public static async Task<ModeRun> RunAsync(SqlEnforcementMode mode)
    {
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var context = BuildContext();
        var args = new PreExecuteArgs("pg-query");

        var prep = wrapper.PrepareSqlQuery(context, args, Query, dialect: SqlDialect.Postgres, mode: mode);
        if (!prep.Allowed)
            throw new UnauthorizedAccessException($"Access denied: {prep.DenialReason}");

        var fromDatabase = await FakeDatabase(prep.Query).ConfigureAwait(false);
        // Mandatory in BOTH modes. This is the enforcement boundary.
        var final = wrapper.PostExecute(context, fromDatabase);

        return new ModeRun(prep, fromDatabase, final);
    }

    public static async Task RunExampleAsync()
    {
        Console.WriteLine("The query the agent asked for:");
        Console.WriteLine($"  {Query}");
        Console.WriteLine($"\nThe database holds {FakeRows().Count} rows and 5 columns.\n");

        var results = new Dictionary<SqlEnforcementMode, IReadOnlyList<Dictionary<string, object?>>>();

        foreach (var mode in new[] { SqlEnforcementMode.RewriteAndPost, SqlEnforcementMode.PostOnly })
        {
            var run = await RunAsync(mode).ConfigureAwait(false);
            results[mode] = run.Final;

            var label = mode == SqlEnforcementMode.RewriteAndPost ? "rewriteAndPost" : "postOnly";
            Console.WriteLine($"--- mode: {label} {new string('-', Math.Max(0, 52 - label.Length))}");
            Console.WriteLine("  SQL sent to the database:");
            Console.WriteLine($"    {run.Prep.Query}");
            Console.WriteLine($"  query was edited: {run.Prep.Rewritten.ToString().ToLowerInvariant()}");
            Console.WriteLine($"  rows the database returned: {run.FromDatabase.Count}");
            Console.WriteLine($"  filters the database did NOT apply: [{string.Join(", ", run.Prep.UnpushableFilters.Select(f => f.Field))}]");
            Console.WriteLine($"  rows after enforcement: {run.Final.Count}");
            foreach (var row in run.Final)
                Console.WriteLine($"    {JsonSerializer.Serialize(row)}");
            Console.WriteLine();
        }

        var rewritten = results[SqlEnforcementMode.RewriteAndPost];
        var postOnly = results[SqlEnforcementMode.PostOnly];

        Console.WriteLine(new string('=', 70));
        if (JsonSerializer.Serialize(rewritten) != JsonSerializer.Serialize(postOnly))
        {
            throw new InvalidOperationException(
                "MODES DISAGREED. Rewriting is a resource optimization and must never change the result.");
        }

        var pushed = await RunAsync(SqlEnforcementMode.RewriteAndPost).ConfigureAwait(false);
        Console.WriteLine("Both modes returned the SAME rows, as they must.");
        Console.WriteLine(
            $"The mode changed how much data the database produced — {pushed.FromDatabase.Count} rows " +
            $"versus {FakeRows().Count} — and nothing about what the caller may see.");
        Console.WriteLine();
        Console.WriteLine("Note what enforcement did that no SQL could have:");
        Console.WriteLine("  * `ssn` is absent, though the database returned it");
        Console.WriteLine("  * `dob` reads [REDACTED] — there is no SELECT that produces that");
        Console.WriteLine("  * the `name startsWith A` filter was applied after the fetch, because it has");
        Console.WriteLine("    no portable SQL form — which is why the post pass is never optional");
    }
}
