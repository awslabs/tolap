using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Examples;

/// <summary>
/// HTTP endpoints and knowledge bases: the two non-SQL sources, and policies scoped to a source.
/// </summary>
/// <remarks>
/// <para>
/// The framework examples all read a table. Two other kinds of source get their own rules, and
/// this example shows both, enforced by the SDK rather than described:
/// </para>
/// <list type="bullet">
///   <item><b>An HTTP API</b>, called through <c>SecureHttpToolWrapper</c>.
///   <c>objectRules.endpointRules</c> decides which paths and methods may be requested,
///   <i>before</i> the request leaves the process, and the field and row rules still apply to the
///   JSON that comes back.</item>
///   <item><b>A knowledge base.</b> <c>tagRules</c> are turned into a metadata filter the provider
///   applies at retrieval (<c>KbFilter.Build</c> / <c>KbProviders.Render</c>), and the post pass
///   then re-applies them, together with <c>minSimilarityScore</c>, over whatever the provider
///   returned. The pushdown is an optimisation; the post pass is the enforcement.</item>
/// </list>
/// <para>
/// Both policies carry <c>sourcePatterns</c>, so each applies only to the sources it names. One
/// identity holds both, and resolution picks per source: the API policy for the API, the KB policy
/// for the KB, and nothing at all — deny-all — for a source neither names.
/// </para>
/// <para>
/// Deliberately mirrors <c>examples/python/http_and_kb_example.py</c> and
/// <c>examples/typescript/http-and-kb-example.ts</c> — same policies, same fake API, same chunks,
/// byte-identical printed output. A divergence between the languages then shows up as a different
/// result rather than hiding behind separately-written expectations.
/// </para>
/// </remarks>
public static class HttpAndKbExample
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    public const string User = "analyst-001";

    public const string Tenant = "hospital-001";

    public const string ApiSource = "api:clinical:patients";

    public const string KbSource = "kb:clinical:guidelines";

    /// <summary>An API source neither policy names. Same category, same endpoint, different namespace.</summary>
    public const string UnmatchedSource = "api:research:patients";

    public const string BaseUrl = "https://clinical-api.example";

    /// <summary>What the API returns for <c>GET /patients</c>: more rows and more fields than the policy permits.</summary>
    public static List<Dictionary<string, object?>> FakeRows() =>
    [
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["ssn"] = "111-22-3333", ["dob"] = "1979-04-12" },
        new() { ["id"] = 2, ["name"] = "Bruno Sato", ["region"] = "us-east", ["ssn"] = "222-33-4444", ["dob"] = "1985-11-02" },
        new() { ["id"] = 3, ["name"] = "Carol Diaz", ["region"] = "us-east", ["ssn"] = "333-44-5555", ["dob"] = "1990-01-30" },
        new() { ["id"] = 4, ["name"] = "Dan Meyer", ["region"] = "eu-west", ["ssn"] = "444-55-6666", ["dob"] = "1972-08-19" },
    ];

    /// <summary>The order columns are printed in, so the output does not depend on map ordering.</summary>
    private static readonly string[] Columns = ["id", "name", "region", "ssn", "dob"];

    /// <param name="Classification">A second classification the provider does not index; <c>null</c> when absent.</param>
    public sealed record Chunk(string Id, string Title, string[] Tags, string? Classification, double Score);

    /// <summary>
    /// What the knowledge base holds. The provider indexes <c>tags</c> only; <c>classification</c>
    /// is metadata it stores but was never asked to filter on.
    /// </summary>
    public static readonly Chunk[] Chunks =
    [
        new("doc-1", "Sepsis screening protocol", ["clinical"], null, 0.91),
        new("doc-2", "Ward 4 incident review", ["clinical", "restricted"], null, 0.88),
        new("doc-3", "Visitor hours", ["public"], null, 0.42),
        new("doc-4", "Staff rota, week 39", ["hr"], null, 0.80),
        new("doc-5", "Medication error log", ["clinical"], "restricted", 0.86),
        new("doc-6", "Hand hygiene guideline", ["public"], null, 0.77),
    ];

    /// <summary>The API policy. Applies only to <c>api:clinical:*</c>.</summary>
    /// <remarks>
    /// <c>AllowedMethods</c> admits GET and POST, and <c>ReadOnly</c> is false, so a POST passes the
    /// endpoint check — and is still refused, because no <c>CanInsert</c> is granted. An endpoint
    /// allow-list is not a write grant.
    /// </remarks>
    public static PolicyDefinition ApiDefinition() => new(
        Version: "1.0",
        Name: "patients-api-reader",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: false),
        Priority: 10,
        SourcePatterns: ["api:clinical:*"],
        ObjectRules: new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: ["/patients", "/patients/*"],
                HiddenEndpoints: ["/patients/*/notes"],
                AllowedMethods: ["GET", "POST"]),
            FieldRules: new FieldRules(
                HiddenFields: ["ssn"],
                MaskedFields: [new MaskingRule("dob", MaskType.Redact)]),
            RowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")]),
        Limits: new PolicyLimits(MaxResults: 2));

    /// <summary>The KB policy. Applies only to <c>kb:clinical:*</c>.</summary>
    public static PolicyDefinition KbDefinition() => new(
        Version: "1.0",
        Name: "clinical-kb-reader",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 10,
        SourcePatterns: ["kb:clinical:*"],
        ObjectRules: new ObjectRules(
            TagRules: new TagRules(AllowedTags: ["clinical", "public"], DeniedTags: ["restricted"])),
        Limits: new PolicyLimits(MaxResults: 5, MinSimilarityScore: 0.5));

    public static readonly PolicyDefinition[] Definitions = [ApiDefinition(), KbDefinition()];

    /// <summary>Resolve exactly as a store would: the same identity and assignments, one source.</summary>
    /// <remarks>
    /// <c>SourcePatterns</c> is applied before the merge, so a definition that does not name the
    /// source contributes nothing. When none does, the set is empty and resolution returns deny-all.
    /// </remarks>
    public static EffectivePolicy ResolveFor(string source) =>
        PolicyResolutionEngine.Resolve(
            userId: User,
            tenantId: Tenant,
            sourceConnectionId: source,
            assignments: Definitions.Select(d => new PolicyAssignment(
                Version: "1.0",
                PolicyName: d.Name,
                Assignee: new Assignee(AssigneeType.User, User),
                Scope: new AssignmentScope(TenantId: Tenant),
                Active: true,
                Audit: new AuditInfo(
                    "admin-jane-doe",
                    DateTimeOffset.Parse("2026-09-01T09:00:00Z", CultureInfo.InvariantCulture),
                    $"granted for the HTTP and KB example: {d.Name}"))).ToArray(),
            definitions: Definitions,
            getGroups: _ => [],
            getRoles: _ => []);

    public static SecurityContext SignedContext(string source) =>
        SecurityContextSigner.Sign(SecurityContextBuilder.Build(User, Tenant, [ResolveFor(source)]), SigningKey);

    // ------------------------------------------------------------------------------------------
    // The HTTP API.
    // ------------------------------------------------------------------------------------------

    /// <summary>Stands in for the clinical API. Returns everything, and counts what reached it.</summary>
    public sealed class FakeApi : HttpMessageHandler
    {
        public List<string> Hits { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            Hits.Add($"{request.Method} {path}");
            var results = request.Method == HttpMethod.Get && path == "/patients"
                ? FakeRows()
                : [];
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    JsonSerializer.Serialize(new Dictionary<string, object> { ["results"] = results }),
                    Encoding.UTF8,
                    "application/json"),
            });
        }

        /// <summary>A client over this handler. It never redirects, so there is nothing to follow.</summary>
        public HttpClient Client() => new(this, disposeHandler: false) { BaseAddress = new Uri(BaseUrl) };
    }

    public sealed record HttpCall(bool Allowed, string Reason, List<Dictionary<string, object?>>? Rows);

    /// <summary>One request through the wrapper. A refusal is raised before the request is sent.</summary>
    public static async Task<HttpCall> CallApiAsync(
        FakeApi api, SecurityContext context, string method, string path)
    {
        using var client = api.Client();
        var http = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), client);
        object? body = method == "POST"
            ? new Dictionary<string, object> { ["name"] = "Eve Park", ["region"] = "us-east" }
            : null;
        try
        {
            var response = await http.RequestAsync(
                context, new HttpRequestArgs(method, path, CollectionPath: "results", Body: body));
            var rows = response.GetProperty("results").EnumerateArray().Select(ToRow).ToList();
            return new HttpCall(true, "", rows);
        }
        catch (UnauthorizedAccessException denied) when (denied.Message.StartsWith("Access denied: ", StringComparison.Ordinal))
        {
            return new HttpCall(false, denied.Message["Access denied: ".Length..], null);
        }
    }

    private static Dictionary<string, object?> ToRow(JsonElement record) =>
        record.EnumerateObject().ToDictionary(
            p => p.Name,
            p => (object?)(p.Value.ValueKind == JsonValueKind.String ? p.Value.GetString() : p.Value.GetRawText()));

    /// <summary>The requests the agent makes, in order.</summary>
    public static readonly (string Method, string Path)[] Requests =
    [
        ("GET", "/patients"),
        ("GET", "/patients/1/notes"),
        ("GET", "/billing/invoices"),
        ("DELETE", "/patients/1"),
        ("POST", "/patients"),
    ];

    // ------------------------------------------------------------------------------------------
    // The knowledge base.
    // ------------------------------------------------------------------------------------------

    /// <summary>
    /// Stands in for the provider. Applies the pushed-down clauses to <c>tags</c>, and only there.
    /// </summary>
    /// <remarks>
    /// A chunk passes <c>NotIn</c> when none of its tags is listed, and <c>In</c> when at least one
    /// is — the list-attribute semantics of the providers the renderers target. It never looks at
    /// <c>classification</c>, because it was never asked to.
    /// </remarks>
    public static List<Dictionary<string, object?>> FakeKbRetrieve(IEnumerable<KbFilterClause> clauses)
    {
        var clauseList = clauses.ToList();
        var retrieved = new List<Dictionary<string, object?>>();
        foreach (var chunk in Chunks)
        {
            var tags = chunk.Tags.Select(t => t.ToLowerInvariant()).ToList();
            var keep = true;
            foreach (var clause in clauseList)
            {
                var listed = tags.Any(clause.Values.Contains);
                if ((clause.Op == KbFilterOp.In && !listed) || (clause.Op == KbFilterOp.NotIn && listed))
                    keep = false;
            }
            if (!keep) continue;

            var record = new Dictionary<string, object?>
            {
                ["id"] = chunk.Id,
                ["title"] = chunk.Title,
                ["tags"] = chunk.Tags.ToList(),
            };
            if (chunk.Classification is not null) record["classification"] = chunk.Classification;
            record["score"] = chunk.Score;
            retrieved.Add(record);
        }
        return retrieved;
    }

    /// <summary>Compact JSON, written out by hand so every language prints the same bytes.</summary>
    public static string ToJson(object? value) => value switch
    {
        IDictionary<string, object> map =>
            "{" + string.Join(",", map.Select(kv => $"\"{kv.Key}\":{ToJson(kv.Value)}")) + "}",
        string text => $"\"{text}\"",
        System.Collections.IEnumerable items =>
            "[" + string.Join(",", items.Cast<object?>().Select(ToJson)) + "]",
        _ => $"\"{Convert.ToString(value, CultureInfo.InvariantCulture)}\"",
    };

    // ------------------------------------------------------------------------------------------
    // Printing. Every line below is byte-identical to the Python and TypeScript examples.
    // ------------------------------------------------------------------------------------------

    private const int LabelWidth = 24;
    private const int VerdictWidth = 8;
    private const int SourceWidth = 26;
    private const int ProfileWidth = 22;

    private static string Access(string label, bool allowed, string detail = "") =>
        $"  {label.PadRight(LabelWidth)}{(allowed ? "ALLOW" : "DENY").PadRight(VerdictWidth)}{detail}".TrimEnd();

    private static string Rule(string title) =>
        $"--- {title} " + new string('-', Math.Max(0, 70 - 5 - title.Length));

    private static string FormatRow(Dictionary<string, object?> row) =>
        string.Join("  ", Columns
            .Where(row.ContainsKey)
            .Select(c => $"{c}={Convert.ToString(row[c], CultureInfo.InvariantCulture)}"));

    private static string Op(KbFilterOp op) => op == KbFilterOp.In ? "in" : "notIn";

    /// <summary>
    /// Why the post pass dropped a chunk the provider returned. Printed only for a chunk the SDK
    /// actually dropped; <see cref="RunExampleAsync"/> refuses to run if the SDK's drops differ.
    /// </summary>
    public static readonly Dictionary<string, string> PostPassDrops = new()
    {
        ["doc-3"] = "score 0.42 is below minSimilarityScore 0.5",
        ["doc-5"] = "classification restricted, a key the provider never saw",
    };

    public static async Task RunExampleAsync()
    {
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("HTTP endpoints and knowledge bases: one identity, three sources");
        Console.WriteLine(new string('=', 70));
        Console.WriteLine();
        Console.WriteLine($"{User} holds two policy definitions. Each carries sourcePatterns, so it");
        Console.WriteLine("applies only to the sources it names:");
        foreach (var definition in Definitions)
        {
            var patterns = string.Join(", ", definition.SourcePatterns ?? []);
            Console.WriteLine($"    {definition.Name.PadRight(ProfileWidth)}sourcePatterns [{patterns}]");
        }

        // ------------------------------------------------------------ sourcePatterns
        Console.WriteLine();
        Console.WriteLine(Rule("sourcePatterns: one identity resolved for three sources"));
        foreach (var source in new[] { ApiSource, KbSource, UnmatchedSource })
        {
            var policy = ResolveFor(source);
            var profiles = policy.SourceProfiles.Length > 0 ? string.Join(", ", policy.SourceProfiles) : "(none)";
            var canQuery = policy.Permissions.CanQuery ? "true" : "false";
            Console.WriteLine($"  {source.PadRight(SourceWidth)}{profiles.PadRight(ProfileWidth)}canQuery={canQuery}");
        }
        Console.WriteLine();
        Console.WriteLine($"{UnmatchedSource} matches neither pattern, so nothing resolves and the");
        Console.WriteLine("result is deny-all -- not the API policy borrowed from a similar name.");

        // ------------------------------------------------------------ HTTP
        using var api = new FakeApi();
        var context = SignedContext(ApiSource);

        Console.WriteLine();
        Console.WriteLine(Rule($"endpointRules through the HTTP wrapper ({ApiSource})"));
        Console.WriteLine($"The fake API returns all {FakeRows().Count} patients, with ssn and dob, for GET /patients.");
        Console.WriteLine("allowedEndpoints [/patients, /patients/*], hiddenEndpoints [/patients/*/notes],");
        Console.WriteLine("allowedMethods [GET, POST], no canInsert:");
        Console.WriteLine();

        List<Dictionary<string, object?>>? rows = null;
        foreach (var (method, path) in Requests)
        {
            var call = await CallApiAsync(api, context, method, path);
            Console.WriteLine(Access($"{method} {path}", call.Allowed, call.Reason));
            if (call.Allowed) rows = call.Rows;
        }

        if (api.Hits.Count != 1 || api.Hits[0] != "GET /patients")
            throw new InvalidOperationException(
                $"A REFUSED REQUEST REACHED THE API. It saw: {string.Join(", ", api.Hits)}");
        if (rows is null || rows.Any(r => r.ContainsKey("ssn")))
            throw new InvalidOperationException("ssn LEAKED. A permitted request must still meet the field rules.");

        Console.WriteLine();
        Console.WriteLine($"The fake API was reached {api.Hits.Count} time. The four refused requests never");
        Console.WriteLine("left the process. POST passed the endpoint rules and was refused by the");
        Console.WriteLine("missing canInsert: an endpoint allow-list is not a write grant.");
        Console.WriteLine();
        Console.WriteLine("GET /patients, after the row, field and limit rules:");
        foreach (var row in rows)
            Console.WriteLine("    " + FormatRow(row));

        Console.WriteLine();
        Console.WriteLine($"The same GET /patients under a context resolved for {UnmatchedSource}:");
        var unmatched = await CallApiAsync(api, SignedContext(UnmatchedSource), "GET", "/patients");
        Console.WriteLine(Access("GET /patients", unmatched.Allowed, unmatched.Reason));
        if (unmatched.Allowed || api.Hits.Count != 1)
            throw new InvalidOperationException("THE UNMATCHED SOURCE WAS SERVED. sourcePatterns must scope the policy.");

        // ------------------------------------------------------------ KB
        var kbPolicy = ResolveFor(KbSource);
        var kbFilter = KbFilter.Build(kbPolicy, ["tags"]);
        var rendered = KbProviders.Render(kbFilter, KbProvider.Bedrock);

        Console.WriteLine();
        Console.WriteLine(Rule($"tagRules on a knowledge base ({KbSource})"));
        Console.WriteLine("allowedTags [clinical, public], deniedTags [restricted], minSimilarityScore 0.5.");
        Console.WriteLine();
        Console.WriteLine("The filter built from the policy for the metadata key \"tags\":");
        foreach (var clause in kbFilter.Clauses)
            Console.WriteLine($"    {clause.Key} {Op(clause.Op)} [{string.Join(", ", clause.Values)}]");
        Console.WriteLine("Rendered for Bedrock:");
        Console.WriteLine("    " + ToJson(rendered.Filter));
        var unpushed = kbFilter.UnpushedRules.Length > 0
            ? string.Join(", ", kbFilter.UnpushedRules.Select(r => r.Rule))
            : "none";
        Console.WriteLine($"Unpushed rules: {unpushed}");

        Console.WriteLine();
        Console.WriteLine($"The fake KB holds {Chunks.Length} chunks and filters on tags only:");
        foreach (var chunk in Chunks)
        {
            var extra = chunk.Classification is not null ? $"  classification={chunk.Classification}" : "";
            Console.WriteLine(
                $"  {chunk.Id}  {chunk.Title.PadRight(28)}score={chunk.Score.ToString("0.00", CultureInfo.InvariantCulture)}  tags={string.Join(",", chunk.Tags)}{extra}");
        }

        var retrieved = FakeKbRetrieve(kbFilter.Clauses);
        var retrievedIds = retrieved.Select(r => (string)r["id"]!).ToList();
        Console.WriteLine();
        Console.WriteLine($"The provider returned {retrieved.Count} of {Chunks.Length}: {string.Join(", ", retrievedIds)}");

        var kbContext = SignedContext(KbSource);
        var wrapper = new SecureContextToolWrapper(new SecureContextWrapperOptions(SigningKey));
        var decision = wrapper.PreExecute(kbContext, new PreExecuteArgs("search_guidelines"));
        if (!decision.Allowed)
            throw new InvalidOperationException($"THE KB SEARCH WAS REFUSED: {decision.Reason}");
        var keptIds = wrapper.PostExecute(kbContext, retrieved).Select(r => (string)r["id"]!).ToList();

        var dropped = retrievedIds.Where(id => !keptIds.Contains(id)).ToList();
        if (!dropped.Order(StringComparer.Ordinal).SequenceEqual(PostPassDrops.Keys.Order(StringComparer.Ordinal)))
            throw new InvalidOperationException(
                $"THE POST PASS DROPPED {string.Join(", ", dropped)}, expected {string.Join(", ", PostPassDrops.Keys)}.");

        Console.WriteLine("The post pass, over what the provider returned:");
        foreach (var id in retrievedIds)
            Console.WriteLine(keptIds.Contains(id) ? $"  {id}  KEEP" : $"  {id}  DROP  {PostPassDrops[id]}");

        Console.WriteLine();
        Console.WriteLine("The pushdown removed doc-2 (restricted) and doc-4 (hr) at the provider, so");
        Console.WriteLine("they were never retrieved. doc-5 carries restricted under a key the provider");
        Console.WriteLine("does not filter on, and the post pass caught it. The pushdown is an");
        Console.WriteLine("optimisation; the post pass is the enforcement.");

        Console.WriteLine();
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("One identity, one set of assignments. sourcePatterns picked the policy per");
        Console.WriteLine("source, endpointRules refused requests before they were sent, and tagRules");
        Console.WriteLine("filtered the knowledge base twice: at the provider, then in the SDK.");
        Console.WriteLine(new string('=', 70));
    }
}
