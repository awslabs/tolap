using System.Globalization;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Examples;

/// <summary>
/// What 1.2.0 changed about queries that span tables, and about results enforced twice.
/// </summary>
/// <remarks>
/// <para>
/// The other examples read one table through one tool. Real agents join, and real data layers
/// sometimes enforce before TOLAP sees the rows. Three things behave differently from 1.1.0, and
/// each section of the output shows one of them with the SDK's own decisions:
/// </para>
/// <list type="number">
///   <item><b>The SQL pre-check reads every table.</b> A joined, comma-joined or derived table is
///   checked against <c>AllowedObjects</c>/<c>HiddenObjects</c> like the <c>FROM</c> table, every
///   column is resolved through its alias to the table it belongs to, and a construct the check
///   cannot resolve is refused rather than guessed at. A refused query never reaches the
///   source.</item>
///   <item><b>Qualified names stay with their object.</b> A row filter on
///   <c>patients.region</c> reads <c>patients.region</c>, never <c>encounters.region</c>, and
///   <c>AllowedFields</c> entry <c>patients.name</c> no longer lets <c>encounters.name</c>
///   through.</item>
///   <item><b>A tool can declare its result already enforced.</b> A data layer that already ran
///   the result pipeline returns <c>EnforcedResult.For(rows, context)</c>, and the wrapper stops
///   hashing hashed fields a second time. Only a marker bound to this exact signed context is
///   honoured.</item>
/// </list>
/// <para>
/// One identity, one signed policy, one wrapper. Specified in docs/canonical-enforcement-spec.md
/// sections 4 and 7 and docs/connector-spec.md section 5.
/// </para>
/// <para>
/// Deliberately mirrors <c>examples/python/query_safety_example.py</c> and
/// <c>examples/typescript/query-safety-example.ts</c> — same policy, same queries, same rows,
/// byte-identical printed output. A divergence between the languages then shows up as a different
/// result rather than hiding behind separately-written expectations.
/// </para>
/// </remarks>
public static class QuerySafetyExample
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    /// <summary>
    /// The salt <c>Hash</c> masking uses. The data layer in section 3 must use the wrapper's salt,
    /// or its hashes would not match the wrapper's and the marker would be a lie.
    /// </summary>
    public const string HashSalt = "example-hash-salt-do-not-use-in-production";

    public const string Tenant = "hospital-001";

    public const string User = "analyst-001";

    public sealed record Query(string Label, string Sql);

    /// <summary>Section 1. The first query is the one the policy permits; every other one is refused.</summary>
    public static readonly Query[] Queries =
    [
        new("join an allowed table",
            "SELECT p.id, p.name, e.code FROM patients p JOIN encounters e ON e.patient_id = p.id"),
        new("join a hidden table",
            "SELECT p.id, b.amount FROM patients p JOIN billing_internal b ON b.patient_id = p.id"),
        new("comma join", "SELECT p.id FROM patients p, billing_internal b"),
        new("derived table", "SELECT x.id FROM (SELECT patient_id AS id FROM billing_internal) x"),
        new("subquery in WHERE",
            "SELECT p.id FROM patients p WHERE p.id IN (SELECT patient_id FROM billing_internal)"),
        new("hidden field via alias",
            "SELECT p.ssn FROM patients p JOIN encounters e ON e.patient_id = p.id"),
        new("other object's column",
            "SELECT e.name FROM patients p JOIN encounters e ON e.patient_id = p.id"),
        new("bare column in a join",
            "SELECT id FROM patients p JOIN encounters e ON e.patient_id = p.id"),
    ];

    /// <summary>
    /// Section 2. What the join returns, keyed by object. Each row carries two <c>region</c>
    /// columns and two <c>name</c> columns, one per table, so a rule that ignores the qualifier
    /// reads the wrong one.
    /// </summary>
    public static List<Dictionary<string, object?>> JoinRows() =>
    [
        new()
        {
            ["patients.id"] = 1,
            ["patients.name"] = "Alice Nguyen",
            ["patients.region"] = "eu-west",
            ["patients.ssn"] = "111-22-3333",
            ["encounters.region"] = "us-east",
            ["encounters.name"] = "Dr Okafor",
            ["encounters.code"] = "E11.9",
        },
        new()
        {
            ["patients.id"] = 2,
            ["patients.name"] = "Bruno Sato",
            ["patients.region"] = "us-east",
            ["patients.ssn"] = "222-33-4444",
            ["encounters.region"] = "eu-west",
            ["encounters.name"] = "Dr Lindqvist",
            ["encounters.code"] = "I10",
        },
    ];

    private static readonly string[] JoinColumns =
    [
        "patients.id",
        "patients.name",
        "patients.region",
        "patients.ssn",
        "encounters.region",
        "encounters.name",
        "encounters.code",
    ];

    /// <summary>Section 2. The field pre-check, told which object a bare field belongs to.</summary>
    public static readonly (string ObjectName, string Field)[] FieldChecks =
        [("patients", "name"), ("encounters", "name"), ("encounters", "code")];

    /// <summary>Section 3. What the <c>patients</c> table holds.</summary>
    public static List<Dictionary<string, object?>> PatientRows() =>
    [
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["email"] = "alice@example.com", ["region"] = "us-east", ["ssn"] = "111-22-3333" },
        new() { ["id"] = 2, ["name"] = "Dan Meyer", ["email"] = "dan@example.com", ["region"] = "eu-west", ["ssn"] = "444-55-6666" },
    ];

    private static readonly string[] PatientColumns = ["id", "name", "email", "region", "ssn"];

    /// <summary>
    /// Two objects the analyst may read, one they may not, and field rules on both.
    /// </summary>
    /// <remarks>
    /// <c>AllowedFields</c> names each object's columns with its qualifier, which is what makes the
    /// qualifier matter: <c>patients.name</c> is listed, <c>encounters.name</c> is not. In a real
    /// deployment this comes from the store's resolver; it is written inline here so the rules under
    /// test are visible in one place.
    /// </remarks>
    public static EffectivePolicy BuildPolicy(string userId)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: userId,
            TenantId: Tenant,
            SourceConnectionId: "db:analytics:clinical",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: ["clinical-analyst"],
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: new ObjectRules(
                AllowedObjects: ["patients", "encounters"],
                HiddenObjects: ["billing_internal"],
                FieldRules: new FieldRules(
                    HiddenFields: ["ssn"],
                    AllowedFields:
                    [
                        "patients.id",
                        "patients.name",
                        "patients.email",
                        "patients.region",
                        "encounters.id",
                        "encounters.patient_id",
                        "encounters.code",
                    ],
                    MaskedFields: [new MaskingRule("email", MaskType.Hash)]),
                RowFilters: [new RowFilter("patients.region", FilterOperator.Equals, Value: "us-east")]),
            Limits: new PolicyLimits(MaxResults: 10));
    }

    public static SecurityContext SignedContext(string userId = User) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(userId, Tenant, [BuildPolicy(userId)]), SigningKey);

    public static SecureContextToolWrapper Wrapper() =>
        new(new SecureContextWrapperOptions(SigningKey, HashSalt: HashSalt));

    /// <param name="Reason"><c>null</c> when the query ran.</param>
    /// <param name="Reached">Whether the source was called.</param>
    public sealed record QueryOutcome(string? Reason, bool Reached);

    /// <summary>
    /// Section 1: run one query through the SQL path. Returns the denial reason, and whether the
    /// source was reached. The fake source records the call and returns the join's rows.
    /// </summary>
    public static async Task<QueryOutcome> RunQueryAsync(SecurityContext context, string sql)
    {
        var reached = new List<string>();
        Task<IReadOnlyList<Dictionary<string, object?>>> Source(string query)
        {
            reached.Add(query);
            return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(JoinRows());
        }

        try
        {
            await Wrapper().ExecuteSqlWithEnforcementAsync(
                context, new PreExecuteArgs("query_patients"), sql, Source);
        }
        catch (UnauthorizedAccessException denied)
        {
            const string prefix = "Access denied: ";
            var reason = denied.Message.StartsWith(prefix, StringComparison.Ordinal)
                ? denied.Message[prefix.Length..]
                : denied.Message;
            return new QueryOutcome(reason, reached.Count > 0);
        }
        return new QueryOutcome(null, reached.Count > 0);
    }

    /// <param name="Label">What the tool returns.</param>
    /// <param name="Note">What the wrapper does with it.</param>
    /// <param name="Returns">Builds the tool's return value from the signed context of the call.</param>
    public sealed record Tool(string Label, string Note, Func<SecurityContext, object?> Returns);

    /// <summary>An ORM adapter that runs the result pipeline itself, with the wrapper's salt.</summary>
    public static object? DataLayerRows(SecurityContext context) =>
        EnforcementEngine.ApplyResultPipeline(PatientRows(), context.Policies[0], HashSalt);

    /// <summary>Section 3. Five tools, one call each through <c>ExecuteWithEnforcementAsync</c>.</summary>
    public static readonly Tool[] Tools =
    [
        new("plain rows", "the wrapper enforces", _ => PatientRows()),
        new("enforced, unmarked", "hashed twice", DataLayerRows),
        new("enforced, marked", "marker honoured",
            ctx => EnforcedResult.For(DataLayerRows(ctx), ctx)),
        new("marked for another user", "marker ignored",
            _ => EnforcedResult.For(PatientRows(), SignedContext("analyst-002"))),
        new("marked, not enforced", "a false claim",
            ctx => EnforcedResult.For(PatientRows(), ctx)),
    ];

    public static async Task<List<Dictionary<string, object?>>> CallToolAsync(
        SecurityContext context, Tool tool)
    {
        var result = await Wrapper().ExecuteWithEnforcementAsync(
            context,
            new PreExecuteArgs("query_patients", ObjectName: "patients"),
            () => Task.FromResult(tool.Returns(context)));
        return ((IEnumerable<Dictionary<string, object?>>)result!).ToList();
    }

    // ------------------------------------------------------------------------------------------
    // Printing. Every line below is byte-identical to the Python and TypeScript examples.
    // ------------------------------------------------------------------------------------------

    private const int LabelWidth = 25;
    private const int VerdictWidth = 8;

    private static string Access(string label, bool allowed, string detail = "") =>
        $"  {label.PadRight(LabelWidth)}{(allowed ? "ALLOW" : "DENY").PadRight(VerdictWidth)}{detail}".TrimEnd();

    private static string Rule(string title) =>
        $"--- {title} " + new string('-', Math.Max(0, 70 - 5 - title.Length));

    private static string FormatRow(Dictionary<string, object?> row, string[] columns) =>
        string.Join("  ", columns
            .Where(row.ContainsKey)
            .Select(c => $"{c}={Convert.ToString(row[c], CultureInfo.InvariantCulture)}"));

    private static string Fingerprint(IEnumerable<Dictionary<string, object?>> rows) =>
        string.Join("\n", rows.Select(r => FormatRow(r, PatientColumns)));

    public static async Task RunExampleAsync()
    {
        var context = SignedContext();
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Query safety: every table checked, every name resolved, one enforcement");
        Console.WriteLine(new string('=', 70));
        Console.WriteLine();
        Console.WriteLine("One analyst, one signed policy:");
        Console.WriteLine("    allowedObjects  patients, encounters      hiddenObjects  billing_internal");
        Console.WriteLine("    allowedFields   patients.{id,name,email,region}, encounters.{id,patient_id,code}");
        Console.WriteLine("    hiddenFields    ssn        maskedFields  email (hash)");
        Console.WriteLine("    rowFilters      patients.region = us-east");

        // 1. ------------------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("1. the SQL pre-check reads every table"));
        Console.WriteLine("Each query goes through the wrapper's SQL path. The source records whether it was");
        Console.WriteLine("reached; a refused query never is.");
        Console.WriteLine();
        foreach (var query in Queries)
        {
            var (reason, reached) = await RunQueryAsync(context, query.Sql);
            if (reason is not null && reached)
                throw new InvalidOperationException($"A REFUSED QUERY REACHED THE SOURCE: {query.Sql}");
            Console.WriteLine("    " + query.Sql);
            Console.WriteLine(Access(query.Label, reason is null, reason ?? "the source ran"));
        }
        Console.WriteLine();
        Console.WriteLine("Before 1.2.0 the check did not resolve joined, comma-joined or derived tables, so");
        Console.WriteLine("the three queries that reach billing_internal that way were not refused by it.");

        // 2. ------------------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("2. qualified names stay with their object"));
        Console.WriteLine("The allowed join returns both tables' columns, keyed by object:");
        foreach (var row in JoinRows())
            Console.WriteLine("    " + FormatRow(row, JoinColumns));
        Console.WriteLine();
        Console.WriteLine("After the result pipeline:");
        var enforced = Wrapper().PostExecute(context, JoinRows());
        foreach (var row in enforced)
            Console.WriteLine("    " + FormatRow(row, JoinColumns));
        if (enforced.Any(r => r.ContainsKey("patients.ssn") || r.ContainsKey("encounters.name")))
            throw new InvalidOperationException("A COLUMN THE POLICY DOES NOT ALLOW CAME BACK.");
        Console.WriteLine();
        Console.WriteLine("Alice's row is dropped: her patients.region is eu-west. The filter no longer falls");
        Console.WriteLine("back to encounters.region, whose us-east used to keep her row. encounters.name and");
        Console.WriteLine("encounters.region are projected out: patients.name does not allow encounters.name.");
        Console.WriteLine();
        Console.WriteLine("The field pre-check, told which object a bare field is read from:");
        foreach (var (objectName, field) in FieldChecks)
        {
            var decision = Wrapper().PreExecute(
                context, new PreExecuteArgs("query_patients", ObjectName: objectName, Fields: [field]));
            Console.WriteLine(Access($"{field} from {objectName}", decision.Allowed, decision.Reason ?? ""));
        }

        // 3. ------------------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("3. a tool can declare its result already enforced"));
        Console.WriteLine("Each tool is called through the wrapper's tool path. email is hash-masked, and hash");
        Console.WriteLine("masking is not idempotent: enforce twice and the value is hashed twice.");
        Console.WriteLine();
        var reference = await CallToolAsync(context, Tools[0]);
        foreach (var tool in Tools)
        {
            var rows = await CallToolAsync(context, tool);
            Console.WriteLine($"  {tool.Label.PadRight(LabelWidth)}{tool.Note}");
            foreach (var row in rows)
                Console.WriteLine("    " + FormatRow(row, PatientColumns));
            if (rows.Any(r => r.ContainsKey("ssn")))
                throw new InvalidOperationException("ssn LEAKED. Hidden-field removal runs even for an honoured marker.");
        }
        if (Fingerprint(await CallToolAsync(context, Tools[2])) != Fingerprint(reference))
            throw new InvalidOperationException("AN HONOURED MARKER DID NOT MATCH THE WRAPPER'S OWN ENFORCEMENT.");
        Console.WriteLine();
        Console.WriteLine("An honoured marker skips masking and the size ceiling, nothing else: ssn is still");
        Console.WriteLine("removed and the region filter still runs, which is why the last tool's raw email");
        Console.WriteLine("comes back while its ssn and Dan's eu-west row do not. The marker is the tool's");
        Console.WriteLine("claim, not proof, so return one only when the data layer really ran this context's");
        Console.WriteLine("pipeline. A marker bound to another context is unwrapped and its rows get the full");
        Console.WriteLine("pipeline, as before 1.2.0. Only the tool path honours a marker; the SQL path and a");
        Console.WriteLine("direct post-execute call unwrap it and enforce in full.");

        Console.WriteLine();
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Every decision above is the SDK's. A refused query never reached the source, a");
        Console.WriteLine("qualified rule read only its own object, and a result was enforced exactly once.");
        Console.WriteLine(new string('=', 70));
    }
}
