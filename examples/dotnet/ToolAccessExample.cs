using System.Globalization;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Examples;

/// <summary>
/// Gating which MCP tools an identity may call, not just what those tools return.
/// </summary>
/// <remarks>
/// <para>
/// Your MCP host or gateway already decides whether an agent may reach a server, and it decides
/// once, for everyone behind that agent: every user sees the same tool list. The other examples
/// here are about the second question — what a permitted call may return. This one is about the
/// layer in between. A policy that carries <c>objectRules.toolRules</c> gives each identity its
/// own answer to "which of these tools may I call at all?":
/// </para>
/// <list type="bullet">
///   <item><c>AllowedTools</c> — the only tools this identity may call. Matched exactly.</item>
///   <item><c>HiddenTools</c> — tools this identity may never call. Matched case-insensitively,
///   so a mis-cased name cannot slip past a hide.</item>
/// </list>
/// <para>
/// One server registers four tools. Three identities hold three signed policies, and for each the
/// example prints what a <c>tools/list</c> handler would show, what happens when a client calls
/// every tool anyway, and what a permitted call returns — because the data rules still apply to it.
/// </para>
/// <para>
/// There is no switch in the code. The same wrapper and the same calls run for all three
/// identities; the policy alone decides, and a policy without <c>ToolRules</c> leaves tool gating
/// with the host exactly as before. Specified in docs/canonical-enforcement-spec.md section 16.
/// </para>
/// <para>
/// Deliberately mirrors <c>examples/python/tool_access_example.py</c> and
/// <c>examples/typescript/tool-access-example.ts</c> — same tools, same policies, same rows,
/// byte-identical printed output. A divergence between the languages then shows up as a different
/// result rather than hiding behind separately-written expectations.
/// </para>
/// </remarks>
public static class ToolAccessExample
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    public const string Tenant = "hospital-001";

    /// <summary>What the agent server registers. The host shows this list to every user.</summary>
    public static readonly string[] Tools =
        ["query_patients", "count_patients", "export_segment_csv", "delete_patient"];

    /// <summary>What the "database" holds: more rows and more columns than the data rules permit.</summary>
    public static List<Dictionary<string, object?>> FakeRows() =>
    [
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["ssn"] = "111-22-3333", ["dob"] = "1979-04-12" },
        new() { ["id"] = 2, ["name"] = "Bruno Sato", ["region"] = "us-east", ["ssn"] = "222-33-4444", ["dob"] = "1985-11-02" },
        new() { ["id"] = 3, ["name"] = "Carol Diaz", ["region"] = "us-east", ["ssn"] = "333-44-5555", ["dob"] = "1990-01-30" },
        new() { ["id"] = 4, ["name"] = "Dan Meyer", ["region"] = "eu-west", ["ssn"] = "444-55-6666", ["dob"] = "1972-08-19" },
    ];

    /// <summary>The order columns are printed in, so the output does not depend on map ordering.</summary>
    private static readonly string[] Columns = ["id", "name", "region", "ssn", "dob"];

    /// <param name="UserId">The identity.</param>
    /// <param name="Profile">The policy name it resolves to.</param>
    /// <param name="ToolRules"><c>null</c> is the data-only case: no tool gating in the policy at all.</param>
    /// <param name="MisCased">A mis-cased name to try as well, or <c>null</c>.</param>
    public sealed record Identity(string UserId, string Profile, ToolRules? ToolRules, string? MisCased);

    public static readonly Identity[] Identities =
    [
        new("analyst-001", "patients-analyst",
            new ToolRules(AllowedTools: ["query_patients", "count_patients"]), "Query_Patients"),
        new("support-001", "patients-support",
            new ToolRules(HiddenTools: ["export_segment_csv", "delete_patient"]), "Delete_Patient"),
        new("auditor-001", "patients-data-only", null, null),
    ];

    /// <summary>
    /// The same data rules for everyone; only <c>ToolRules</c> differs.
    /// </summary>
    /// <remarks>
    /// Holding the data rules constant is what makes the tool layer the only variable: every
    /// difference in the output is <c>ToolRules</c> at work. In a real deployment each policy comes
    /// from the store's resolver; it is written inline here so the rules under test are visible in
    /// one place.
    /// </remarks>
    public static EffectivePolicy BuildPolicy(Identity identity)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: identity.UserId,
            TenantId: Tenant,
            SourceConnectionId: "db:analytics:patients",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: [identity.Profile],
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: new ObjectRules(
                AllowedObjects: ["patients"],
                FieldRules: new FieldRules(
                    HiddenFields: ["ssn"],
                    MaskedFields: [new MaskingRule("dob", MaskType.Redact)]),
                RowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")],
                ToolRules: identity.ToolRules),
            Limits: new PolicyLimits(MaxResults: 2));
    }

    /// <summary>Signed, so the tool rules cannot be edited in transit by the agent they constrain.</summary>
    public static SecurityContext SignedContext(Identity identity) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(identity.UserId, Tenant, [BuildPolicy(identity)]), SigningKey);

    /// <summary>One wrapper for every identity. There is no tool-rules option to set on it.</summary>
    public static SecureContextToolWrapper Wrapper() =>
        new(new SecureContextWrapperOptions(SigningKey));

    public record ToolCall(AccessResult Decision, IReadOnlyList<Dictionary<string, object?>>? Rows);

    /// <summary>
    /// What a <c>tools/call</c> handler does: check the tool, then fetch, then enforce on the rows.
    /// </summary>
    /// <remarks>
    /// The tool check runs before <c>CanQuery</c> and every data check, so a refused tool never
    /// reaches the source. Every tool reads <c>patients</c> here; that keeps the demo about the tool
    /// name rather than about which table each tool happens to touch.
    /// </remarks>
    public static ToolCall CallTool(SecurityContext context, string toolName)
    {
        var decision = Wrapper().PreExecute(context, new PreExecuteArgs(toolName, ObjectName: "patients"));
        if (!decision.Allowed) return new ToolCall(decision, null);
        return new ToolCall(decision, Wrapper().PostExecute(context, FakeRows()));
    }

    // ------------------------------------------------------------------------------------------
    // Printing. Every line below is byte-identical to the Python and TypeScript examples.
    // ------------------------------------------------------------------------------------------

    private const int LabelWidth = 22;
    private const int VerdictWidth = 8;

    private static string Access(string label, bool allowed, string detail = "") =>
        $"  {label.PadRight(LabelWidth)}{(allowed ? "ALLOW" : "DENY").PadRight(VerdictWidth)}{detail}".TrimEnd();

    private static string Rule(string title) =>
        $"--- {title} " + new string('-', Math.Max(0, 70 - 5 - title.Length));

    private static string Describe(ToolRules? rules)
    {
        if (rules is null) return "no toolRules";
        if (rules.AllowedTools is not null) return $"allowedTools [{string.Join(", ", rules.AllowedTools)}]";
        return $"hiddenTools [{string.Join(", ", rules.HiddenTools ?? [])}]";
    }

    private static string FormatRow(Dictionary<string, object?> row) =>
        string.Join("  ", Columns
            .Where(row.ContainsKey)
            .Select(c => $"{c}={Convert.ToString(row[c], CultureInfo.InvariantCulture)}"));

    private static readonly Dictionary<string, string[]> Notes = new()
    {
        ["analyst-001"] =
        [
            "An allow-list: two tools listed, the other two refused when called anyway. The",
            "match is exact, so 'Query_Patients' is not 'query_patients' and is refused too.",
        ],
        ["support-001"] =
        [
            "A deny-list, landing on the analyst's list from the other side. The difference shows",
            "when the server adds a tool: an allow-list will not list it, a deny-list will. The",
            "hide is case-insensitive, so 'Delete_Patient' is refused rather than slipping past.",
        ],
        ["auditor-001"] =
        [
            "No toolRules, so TOLAP does not gate tools at all: every tool is listed and",
            "callable, and the decision stays with the host, exactly as before. The data rules",
            "still apply, which is all this policy asks for.",
        ],
    };

    public static Task RunExampleAsync()
    {
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Tool access: one server, one tool list, a different answer per identity");
        Console.WriteLine(new string('=', 70));
        Console.WriteLine();
        Console.WriteLine("The server registers four tools, and the host shows every user the same list:");
        Console.WriteLine("    " + string.Join(", ", Tools));
        Console.WriteLine();
        Console.WriteLine($"The database holds {FakeRows().Count} rows. Every policy below carries the same data rules -- ssn");
        Console.WriteLine("hidden, dob redacted, region us-east, at most 2 rows -- so the only thing that");
        Console.WriteLine("differs between the three identities is objectRules.toolRules.");

        foreach (var identity in Identities)
        {
            var context = SignedContext(identity);
            var listed = Wrapper().FilterTools(context, Tools);

            Console.WriteLine();
            Console.WriteLine(Rule($"{identity.UserId}  {Describe(identity.ToolRules)}"));
            Console.WriteLine("tools/list shows: " + string.Join(", ", listed));
            Console.WriteLine();
            Console.WriteLine("Every tool called anyway, as a client that ignores the list might:");

            var calledThrough = new List<string>();
            string[] probes = identity.MisCased is null ? Tools : [.. Tools, identity.MisCased];
            foreach (var tool in probes)
            {
                var decision = CallTool(context, tool).Decision;
                Console.WriteLine(Access(tool, decision.Allowed, decision.Reason ?? ""));
                if (decision.Allowed && Tools.Contains(tool)) calledThrough.Add(tool);
            }

            if (!calledThrough.SequenceEqual(listed))
            {
                throw new InvalidOperationException(
                    "THE LIST AND THE CALLS DISAGREED. A tools/list handler must show exactly the tools " +
                    $"a call would not refuse by name.\n  listed: {string.Join(", ", listed)}\n" +
                    $"  callable: {string.Join(", ", calledThrough)}");
            }

            var rows = CallTool(context, "query_patients").Rows
                       ?? throw new InvalidOperationException("query_patients was refused");
            if (rows.Any(r => r.ContainsKey("ssn")))
                throw new InvalidOperationException("ssn LEAKED. A permitted tool must still meet the data rules.");

            Console.WriteLine();
            Console.WriteLine("query_patients is permitted, and still meets the data rules:");
            foreach (var row in rows)
                Console.WriteLine("    " + FormatRow(row));
            Console.WriteLine();
            foreach (var line in Notes[identity.UserId])
                Console.WriteLine(line);
        }

        Console.WriteLine();
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Three identities, one server, one wrapper, no code change between them.");
        Console.WriteLine("The policy alone picks the combination:");
        Console.WriteLine("  no toolRules              data access only; tool gating stays with the host");
        Console.WriteLine("  toolRules and data rules  both layers narrow (the analyst and support above)");
        Console.WriteLine("  toolRules, no data rules  tool access only");
        Console.WriteLine();
        Console.WriteLine("Listing is not permission. Every call is re-checked, which is why the tools the");
        Console.WriteLine("list never showed were refused when called, before any query was built. And");
        Console.WriteLine("allowedTools [] is not 'unrestricted': it denies every tool.");
        Console.WriteLine(new string('=', 70));

        return Task.CompletedTask;
    }
}
