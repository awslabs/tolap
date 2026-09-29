using System.Globalization;
using System.Text.Json;
using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Examples;

/// <summary>
/// A tour of every policy rule the SDK enforces, one section per rule.
/// </summary>
/// <remarks>
/// <para>
/// The framework examples all hold the same small policy, because their point is the
/// integration. This one holds the integration constant instead and changes the policy, so each
/// rule is seen on its own against data that shows what it did:
/// </para>
/// <list type="bullet">
///   <item><b>Masks</b> — <c>Full</c>, <c>Partial</c> (<c>ShowFirst</c>/<c>ShowLast</c>/<c>MaskChar</c>),
///   <c>Hash</c> (<c>sha256</c>, <c>sha512</c>, <c>blake2b</c>), <c>Null</c> and <c>Redact</c>, raw value
///   next to masked value.</item>
///   <item><b>Fields</b> — <c>AllowedFields</c> (keep only these) next to <c>HiddenFields</c> (drop only
///   these).</item>
///   <item><b>Objects</b> — <c>AllowedObjects</c> next to <c>HiddenObjects</c>, and a refused call for
///   each.</item>
///   <item><b>Row filters</b> — every operator family, each on its own, over the same six rows.</item>
///   <item><b>Permissions</b> — <c>CanQuery: false</c>, <c>ReadOnly: true</c> refusing a write, and the
///   write checks that still run once writes are granted.</item>
///   <item><b>Limits</b> — <c>MinSimilarityScore</c>, <c>MaxObjectSizeBytes</c> and <c>MaxResults</c>.</item>
///   <item><b>Merging</b> — a user policy and a group policy resolved into one, where the most
///   restrictive rule wins.</item>
/// </list>
/// <para>
/// Every verdict and every masked value below comes from the SDK; the example only prints. Where a
/// rule refuses something, the reason is the SDK's own string.
/// </para>
/// <para>
/// Deliberately mirrors <c>examples/python/policy_tour_example.py</c> and
/// <c>examples/typescript/policy-tour-example.ts</c> — same policies, same rows, byte-identical
/// printed output. A divergence between the languages then shows up as a different result rather
/// than hiding behind separately-written expectations.
/// </para>
/// </remarks>
public static class PolicyTourExample
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    public const string Tenant = "hospital-001";

    public const string Source = "db:clinical:patients";

    public const string User = "analyst-001";

    // ------------------------------------------------------------------------------------------
    // The data. Each "database" returns more than any policy below permits.
    // ------------------------------------------------------------------------------------------

    /// <summary>One patient, with a column for every mask type.</summary>
    public static Dictionary<string, object?> Patient() => new()
    {
        ["id"] = 7,
        ["name"] = "Alice Nguyen",
        ["phone"] = "555-867-5309",
        ["card"] = "4111111111111111",
        ["address"] = "12 Elm Street",
        ["email"] = "alice@example.com",
        ["mrn"] = "MRN-00417",
        ["member_id"] = "M-99812",
        ["notes"] = "allergic to penicillin",
        ["dob"] = "1979-04-12",
        ["ssn"] = "111-22-3333",
    };

    /// <summary>Rows for the row-filter section. Row 6 has no <c>discharged_at</c> key at all.</summary>
    public static List<Dictionary<string, object?>> Rows() =>
    [
        new() { ["id"] = 1, ["region"] = "us-east", ["age"] = 34, ["ward"] = "cardiology", ["email"] = "alice@clinic.org", ["code"] = "PT-101", ["discharged_at"] = null },
        new() { ["id"] = 2, ["region"] = "us-west", ["age"] = 17, ["ward"] = "pediatrics", ["email"] = "bruno@clinic.org", ["code"] = "PT-102", ["discharged_at"] = "2026-08-01" },
        new() { ["id"] = 3, ["region"] = "eu-west", ["age"] = 52, ["ward"] = "cardiology", ["email"] = "carol@partner.net", ["code"] = "PT-10A", ["discharged_at"] = null },
        new() { ["id"] = 4, ["region"] = "us-east", ["age"] = 65, ["ward"] = "oncology", ["email"] = "dan@clinic.org", ["code"] = "XX-104", ["discharged_at"] = "2026-07-15" },
        new() { ["id"] = 5, ["region"] = "ap-south", ["age"] = 41, ["ward"] = "neurology", ["email"] = "erin@partner.net", ["code"] = "PT-105", ["discharged_at"] = null },
        new() { ["id"] = 6, ["region"] = "us-east", ["age"] = 29, ["ward"] = "cardiology-icu", ["email"] = "fay@clinic.org", ["code"] = "pt-106" },
    ];

    /// <summary>Search hits for the limits section. d5 carries no size and d6 no score.</summary>
    public static List<Dictionary<string, object?>> Documents() =>
    [
        new() { ["id"] = "d1", ["score"] = 0.92, ["size"] = 1200 },
        new() { ["id"] = "d2", ["score"] = 0.75, ["size"] = 4096 },
        new() { ["id"] = "d3", ["score"] = 0.60, ["size"] = 800 },
        new() { ["id"] = "d4", ["score"] = 0.88, ["size"] = 2048 },
        new() { ["id"] = "d5", ["score"] = 0.81 },
        new() { ["id"] = "d6", ["size"] = 500 },
        new() { ["id"] = "d7", ["score"] = 0.99, ["size"] = 100 },
    ];

    /// <summary>Rows for the merge section.</summary>
    public static List<Dictionary<string, object?>> MergeRows() =>
    [
        new() { ["id"] = 1, ["region"] = "us-east", ["age"] = 34, ["phone"] = "555-867-5309", ["ssn"] = "111-22-3333", ["notes"] = "stable" },
        new() { ["id"] = 2, ["region"] = "us-west", ["age"] = 17, ["phone"] = "555-201-4471", ["ssn"] = "222-33-4444", ["notes"] = "minor" },
        new() { ["id"] = 3, ["region"] = "eu-west", ["age"] = 52, ["phone"] = "555-310-9920", ["ssn"] = "333-44-5555", ["notes"] = "transfer" },
        new() { ["id"] = 4, ["region"] = "us-east", ["age"] = 65, ["phone"] = "555-448-1062", ["ssn"] = "444-55-6666", ["notes"] = "follow-up" },
    ];

    /// <summary>The order columns are printed in, so the output does not depend on map ordering.</summary>
    private static readonly string[] PatientColumns =
        ["id", "name", "phone", "card", "address", "email", "mrn", "member_id", "notes", "dob", "ssn"];
    private static readonly string[] FieldColumns = ["id", "name", "region", "dob", "notes", "ssn"];
    private static readonly string[] MergeColumns = ["id", "region", "age", "phone", "notes", "ssn"];

    // ------------------------------------------------------------------------------------------
    // Policies. Each one is written inline so the rule under test is visible where it is used; in
    // a real deployment they come from the store's resolver.
    // ------------------------------------------------------------------------------------------

    /// <summary>An effective policy holding only the rule a section is about.</summary>
    public static EffectivePolicy Policy(
        PolicyPermissions? permissions = null, ObjectRules? objectRules = null, PolicyLimits? limits = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: User,
            TenantId: Tenant,
            SourceConnectionId: Source,
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: ["policy-tour"],
            Permissions: permissions ?? new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: objectRules,
            Limits: limits);
    }

    /// <summary>One rule per mask type, and <c>ssn</c> hidden outright for contrast.</summary>
    public static EffectivePolicy MaskPolicy() => Policy(objectRules: new ObjectRules(
        FieldRules: new FieldRules(
            HiddenFields: ["ssn"],
            MaskedFields:
            [
                new MaskingRule("name", MaskType.Partial, new MaskingParameters(ShowFirst: 1)),
                new MaskingRule("phone", MaskType.Partial, new MaskingParameters(ShowLast: 4, MaskChar: '#')),
                new MaskingRule("card", MaskType.Partial, new MaskingParameters(ShowFirst: 4, ShowLast: 4)),
                new MaskingRule("address", MaskType.Full),
                new MaskingRule("email", MaskType.Hash, new MaskingParameters(Algorithm: "sha256")),
                new MaskingRule("mrn", MaskType.Hash, new MaskingParameters(Algorithm: "sha512")),
                new MaskingRule("member_id", MaskType.Hash, new MaskingParameters(Algorithm: "blake2b")),
                new MaskingRule("notes", MaskType.Null),
                new MaskingRule("dob", MaskType.Redact),
            ])));

    /// <summary>Label shown for each mask rule, in <see cref="PatientColumns"/> order.</summary>
    private static readonly Dictionary<string, string> MaskLabels = new()
    {
        ["id"] = "no rule",
        ["name"] = "partial showFirst 1",
        ["phone"] = "partial showLast 4 '#'",
        ["card"] = "partial first 4 last 4",
        ["address"] = "full",
        ["email"] = "hash sha256",
        ["mrn"] = "hash sha512",
        ["member_id"] = "hash blake2b",
        ["notes"] = "null",
        ["dob"] = "redact",
        ["ssn"] = "hiddenFields",
    };

    /// <summary>An allow-list of fields: anything not named is dropped, including columns added later.</summary>
    public static EffectivePolicy AllowedFieldsPolicy() =>
        Policy(objectRules: new ObjectRules(FieldRules: new FieldRules(AllowedFields: ["id", "name", "region"])));

    /// <summary>A deny-list of fields: only the named ones are dropped.</summary>
    public static EffectivePolicy HiddenFieldsPolicy() =>
        Policy(objectRules: new ObjectRules(FieldRules: new FieldRules(HiddenFields: ["ssn", "notes"])));

    /// <summary><c>billing_*</c> is allowed, and <c>billing_internal</c> is hidden anyway: hidden wins.</summary>
    public static EffectivePolicy ObjectPolicy() => Policy(objectRules: new ObjectRules(
        AllowedObjects: ["patients", "encounters", "billing_*"],
        HiddenObjects: ["billing_internal"]));

    public static readonly string[] ObjectProbes =
        ["patients", "encounters", "billing_invoices", "billing_internal", "audit_log"];

    public sealed record Filter(string Label, RowFilter Rule);

    public static readonly Filter[] Filters =
    [
        new("region equals us-east", new RowFilter("region", FilterOperator.Equals, Value: "us-east")),
        new("region notEquals us-east", new RowFilter("region", FilterOperator.NotEquals, Value: "us-east")),
        new("region in [us-east, us-west]", new RowFilter("region", FilterOperator.In, Values: ["us-east", "us-west"])),
        new("region notIn [us-east, us-west]", new RowFilter("region", FilterOperator.NotIn, Values: ["us-east", "us-west"])),
        new("age greaterThan 40", new RowFilter("age", FilterOperator.GreaterThan, Value: 40)),
        new("age lessThanOrEqual 29", new RowFilter("age", FilterOperator.LessThanOrEqual, Value: 29)),
        new("age between [30, 52]", new RowFilter("age", FilterOperator.Between, Values: [30, 52])),
        new("email contains @clinic.", new RowFilter("email", FilterOperator.Contains, Value: "@clinic.")),
        new("ward startsWith cardio", new RowFilter("ward", FilterOperator.StartsWith, Value: "cardio")),
        new("email like %@partner.net", new RowFilter("email", FilterOperator.Like, Value: "%@partner.net")),
        new("code matches PT-[0-9]{3}", new RowFilter("code", FilterOperator.Matches, Value: "PT-[0-9]{3}")),
        new("discharged_at isNull", new RowFilter("discharged_at", FilterOperator.IsNull)),
        new("discharged_at isNotNull", new RowFilter("discharged_at", FilterOperator.IsNotNull)),
    ];

    public static EffectivePolicy FilterPolicy(RowFilter rule) =>
        Policy(objectRules: new ObjectRules(RowFilters: [rule]));

    /// <summary>Holds object rules, but no reads at all: <c>CanQuery</c> is checked before any of them.</summary>
    public static EffectivePolicy QueryDeniedPolicy() => Policy(
        permissions: new PolicyPermissions(CanQuery: false),
        objectRules: new ObjectRules(AllowedObjects: ["patients"]));

    /// <summary>Grants inserts, and is read-only anyway: <c>ReadOnly</c> is a ceiling over the grants.</summary>
    public static EffectivePolicy ReadOnlyPolicy() =>
        Policy(permissions: new PolicyPermissions(CanQuery: true, CanInsert: true, ReadOnly: true));

    /// <summary>Inserts and updates granted, but only on us-east rows and never to <c>mrn</c>.</summary>
    public static EffectivePolicy WriterPolicy() => Policy(
        permissions: new PolicyPermissions(CanQuery: true, CanInsert: true, CanUpdate: true, ReadOnly: false),
        objectRules: new ObjectRules(
            FieldRules: new FieldRules(ReadOnlyFields: ["mrn"]),
            RowFilters: [new RowFilter("region", FilterOperator.Equals, Value: "us-east")]));

    public sealed record Limit(string Label, PolicyLimits Limits);

    public static readonly Limit[] Limits =
    [
        new("minSimilarityScore 0.75", new PolicyLimits(MinSimilarityScore: 0.75)),
        new("maxObjectSizeBytes 2048", new PolicyLimits(MaxObjectSizeBytes: 2048)),
        new("maxResults 2", new PolicyLimits(MaxResults: 2)),
        new("all three", new PolicyLimits(MaxResults: 2, MinSimilarityScore: 0.75, MaxObjectSizeBytes: 2048)),
    ];

    // ------------------------------------------------------------------------------------------
    // Merging: two policy definitions, one granted to the user and one to a group they belong to.
    // ------------------------------------------------------------------------------------------

    public const string Group = "clinicians";

    private static AuditInfo Audit(string reason) =>
        new("admin-jane-doe", DateTimeOffset.Parse("2026-09-01T09:00:00Z", CultureInfo.InvariantCulture), reason);

    /// <summary>Assigned to the analyst directly. Read-only, the wider row cap, a partial phone mask.</summary>
    public static PolicyDefinition UserDefinition() => new(
        Version: "1.0",
        Name: "analyst-direct",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 10,
        SourcePatterns: ["db:clinical:*"],
        ObjectRules: new ObjectRules(
            AllowedObjects: ["patients", "encounters", "labs"],
            FieldRules: new FieldRules(
                HiddenFields: ["ssn"],
                MaskedFields: [new MaskingRule("phone", MaskType.Partial, new MaskingParameters(ShowLast: 4))]),
            RowFilters: [new RowFilter("region", FilterOperator.In, Values: ["us-east", "us-west"])]),
        Limits: new PolicyLimits(MaxResults: 100));

    /// <summary>Assigned to the clinicians group. Grants inserts, a lower row cap, redacts the phone.</summary>
    public static PolicyDefinition GroupDefinition() => new(
        Version: "1.0",
        Name: "clinicians-group",
        Permissions: new PolicyPermissions(CanQuery: true, CanInsert: true, ReadOnly: false),
        Priority: 50,
        SourcePatterns: ["db:clinical:*"],
        ObjectRules: new ObjectRules(
            AllowedObjects: ["patients", "encounters", "billing"],
            FieldRules: new FieldRules(
                HiddenFields: ["notes"],
                MaskedFields: [new MaskingRule("phone", MaskType.Redact)]),
            RowFilters: [new RowFilter("age", FilterOperator.GreaterThanOrEqual, Value: 18)]),
        Limits: new PolicyLimits(MaxResults: 25));

    public static PolicyAssignment[] MergeAssignments() =>
    [
        new("1.0", "analyst-direct", new Assignee(AssigneeType.User, User),
            new AssignmentScope(TenantId: Tenant), Active: true, Audit("policy tour: the user's own grant")),
        new("1.0", "clinicians-group", new Assignee(AssigneeType.Group, Group),
            new AssignmentScope(TenantId: Tenant), Active: true, Audit("policy tour: the group's grant")),
    ];

    /// <summary>Resolved exactly as a store would: both assignments match, so both definitions merge.</summary>
    public static EffectivePolicy MergedPolicy() => PolicyResolutionEngine.Resolve(
        User,
        Tenant,
        Source,
        MergeAssignments(),
        [UserDefinition(), GroupDefinition()],
        _ => [Group],
        _ => []);

    // ------------------------------------------------------------------------------------------
    // Enforcement. The same wrapper and the same three calls for every section.
    // ------------------------------------------------------------------------------------------

    /// <summary>Signed, so the policy cannot be edited in transit by the agent it constrains.</summary>
    public static SecurityContext SignedContext(EffectivePolicy effective) =>
        SecurityContextSigner.Sign(SecurityContextBuilder.Build(User, Tenant, [effective]), SigningKey);

    public static SecureContextToolWrapper Wrapper() => new(new SecureContextWrapperOptions(SigningKey));

    /// <summary>The post-execution pipeline over copies of <paramref name="rows"/>, so the source data is never touched.</summary>
    public static IReadOnlyList<Dictionary<string, object?>> Enforce(
        EffectivePolicy effective, IEnumerable<Dictionary<string, object?>> rows) =>
        Wrapper().PostExecute(SignedContext(effective), rows.Select(r => new Dictionary<string, object?>(r)).ToList());

    public static AccessResult Check(EffectivePolicy effective, string? objectName = null, string[]? fields = null) =>
        Wrapper().PreExecute(SignedContext(effective), new PreExecuteArgs("query_patients", ObjectName: objectName, Fields: fields));

    public static AccessResult CheckWrite(
        EffectivePolicy effective,
        WriteOperation operation,
        Dictionary<string, object?> payload,
        Dictionary<string, object?>? targetRow = null) =>
        Wrapper().PreWrite(
            SignedContext(effective),
            operation,
            "patients",
            payload,
            targetRow is null ? null : new WriteValidationOptions(TargetRow: targetRow));

    // ------------------------------------------------------------------------------------------
    // Printing. Every line below is byte-identical to the Python and TypeScript examples.
    // ------------------------------------------------------------------------------------------

    private const int LabelWidth = 34;
    private const int VerdictWidth = 8;

    private static string Access(string label, AccessResult result) =>
        $"  {label.PadRight(LabelWidth)}{(result.Allowed ? "ALLOW" : "DENY").PadRight(VerdictWidth)}{result.Reason ?? ""}".TrimEnd();

    private static string Rule(string title) =>
        $"--- {title} " + new string('-', Math.Max(0, 70 - 5 - title.Length));

    private static string Value(object? value) =>
        value is null ? "null" : Convert.ToString(value, CultureInfo.InvariantCulture) ?? "null";

    private static string Columns(IReadOnlyDictionary<string, object?> row, string[] order) =>
        string.Join(", ", order.Where(row.ContainsKey));

    private static string FormatRow(IReadOnlyDictionary<string, object?> row, string[] order) =>
        string.Join("  ", order.Where(row.ContainsKey).Select(c => $"{c}={Value(row[c])}"));

    private static string Ids(IEnumerable<IReadOnlyDictionary<string, object?>> rows)
    {
        var joined = string.Join(", ", rows.Select(r => Value(r["id"])));
        return joined.Length == 0 ? "(none)" : joined;
    }

    /// <summary>The schema's spelling of an enum member: <c>GreaterThanOrEqual</c> is <c>greaterThanOrEqual</c>.</summary>
    private static string Wire<T>(T member) where T : Enum => JsonNamingPolicy.CamelCase.ConvertName(member.ToString());

    private static string Yes(bool? flag) => flag == true ? "yes" : "no";

    private static string Sorted(string[]? values) =>
        string.Join(", ", (values ?? []).OrderBy(v => v, StringComparer.Ordinal));

    /// <summary>The rules and limits both a definition and an effective policy carry.</summary>
    private sealed record RuleSource(string Name, PolicyPermissions Permissions, ObjectRules? ObjectRules, PolicyLimits? Limits)
    {
        public ObjectRules Rules => ObjectRules ?? new ObjectRules();
        public FieldRules Fields => Rules.FieldRules ?? new FieldRules();
    }

    /// <summary>
    /// Each merged rule, how the merge combines it, and how to read it off a definition or a policy.
    /// Lists are printed sorted, so the output does not depend on the order a merge emits them in.
    /// </summary>
    private static readonly (string Title, string How, Func<RuleSource, string> Pick)[] MergeTable =
    [
        ("allowedObjects", "intersected", s => Sorted(s.Rules.AllowedObjects)),
        ("hiddenFields", "unioned", s => Sorted(s.Fields.HiddenFields)),
        ("phone mask", "the most restrictive",
            s => string.Join(", ", (s.Fields.MaskedFields ?? []).Where(m => m.Field == "phone").Select(m => Wire(m.MaskType)))),
        ("rowFilters", "all of them apply",
            s => string.Join(", ", (s.Rules.RowFilters ?? []).Select(f => $"{f.Field} {Wire(f.Operator)}"))),
        ("maxResults", "the lowest", s => Value(s.Limits?.MaxResults)),
        ("canInsert", "only if every policy grants it", s => Yes(s.Permissions.CanInsert)),
        ("readOnly", "if any policy sets it", s => Yes(s.Permissions.ReadOnly)),
    ];

    public static Task RunExampleAsync()
    {
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Policy tour: every rule the SDK enforces, one section each");
        Console.WriteLine(new string('=', 70));
        Console.WriteLine();
        Console.WriteLine("Every section below uses the same signed context, the same wrapper and the same");
        Console.WriteLine("calls. Only the policy changes, and the source returns everything each time, so");
        Console.WriteLine("what is missing or masked in the output is enforcement.");

        // -- Masks -------------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Masks: one rule per mask type"));
        var patient = Patient();
        var masked = Enforce(MaskPolicy(), [patient])[0];
        foreach (var column in PatientColumns)
        {
            var after = masked.TryGetValue(column, out var v) ? Value(v) : "(dropped)";
            Console.WriteLine($"  {column,-11}{MaskLabels[column],-24}{Value(patient[column]),-24}{after}");
        }
        if (masked.ContainsKey("ssn") || !Equals(masked["dob"], "[REDACTED]"))
            throw new InvalidOperationException("MASKING FAILED. ssn must be dropped and dob redacted.");
        Console.WriteLine();
        Console.WriteLine("Hashes are the first 16 hex characters of the digest, so the same input always");
        Console.WriteLine("gives the same token: rows still join and group on email without revealing it.");

        // -- Fields ------------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Fields: allowedFields next to hiddenFields"));
        var source = new Dictionary<string, object?>
        {
            ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["dob"] = "1979-04-12", ["notes"] = "stable", ["ssn"] = "111-22-3333",
        };
        Console.WriteLine("  the source returns    " + Columns(source, FieldColumns));
        foreach (var (label, effective) in new[]
                 {
                     ("allowedFields [id, name, region]", AllowedFieldsPolicy()),
                     ("hiddenFields [ssn, notes]", HiddenFieldsPolicy()),
                 })
        {
            var kept = Enforce(effective, [source])[0];
            Console.WriteLine();
            Console.WriteLine($"  {label}");
            Console.WriteLine("    returns             " + Columns(kept, FieldColumns));
            Console.WriteLine(Access("    asks for [id, ssn]", Check(effective, fields: ["id", "ssn"])));
        }
        Console.WriteLine();
        Console.WriteLine("An allow-list also drops a column the source adds tomorrow; a deny-list keeps it.");

        // -- Objects -----------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Objects: allowedObjects [patients, encounters, billing_*]"));
        Console.WriteLine("                       hiddenObjects [billing_internal]");
        foreach (var name in ObjectProbes)
            Console.WriteLine(Access(name, Check(ObjectPolicy(), objectName: name)));
        Console.WriteLine();
        Console.WriteLine("billing_internal matches the billing_* allow and is refused anyway: a hide wins.");

        // -- Row filters -------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Row filters: one operator at a time over rows 1-6"));
        foreach (var entry in Filters)
            Console.WriteLine($"  {entry.Label.PadRight(LabelWidth)}ids {Ids(Enforce(FilterPolicy(entry.Rule), Rows()))}");
        Console.WriteLine();
        Console.WriteLine("Row 6 has no discharged_at key, so it fails isNull and isNotNull alike: a missing");
        Console.WriteLine("field never passes a filter. matches is anchored and case-sensitive, so PT-10A");
        Console.WriteLine("and pt-106 fail it; between is inclusive, so age 52 is kept.");

        // -- Permissions -------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Permissions"));
        Console.WriteLine("  canQuery false");
        Console.WriteLine(Access("    query patients", Check(QueryDeniedPolicy(), objectName: "patients")));
        Console.WriteLine("  canInsert true, readOnly true");
        Console.WriteLine(Access("    insert", CheckWrite(ReadOnlyPolicy(), WriteOperation.Insert, new() { ["name"] = "Bo" })));
        Console.WriteLine("  canInsert, canUpdate, readOnly false; mrn read-only; region us-east");
        var writer = WriterPolicy();
        var east = new Dictionary<string, object?> { ["id"] = 1, ["region"] = "us-east" };
        var west = new Dictionary<string, object?> { ["id"] = 3, ["region"] = "eu-west" };
        Console.WriteLine(Access("    insert", CheckWrite(writer, WriteOperation.Insert, new() { ["name"] = "Bo", ["region"] = "us-east" })));
        Console.WriteLine(Access("    insert setting mrn", CheckWrite(writer, WriteOperation.Insert, new() { ["name"] = "Bo", ["mrn"] = "MRN-1" })));
        Console.WriteLine(Access("    update a us-east row", CheckWrite(writer, WriteOperation.Update, new() { ["name"] = "Bo" }, east)));
        Console.WriteLine(Access("    update an eu-west row", CheckWrite(writer, WriteOperation.Update, new() { ["name"] = "Bo" }, west)));
        Console.WriteLine(Access("    delete", CheckWrite(writer, WriteOperation.Delete, new(), east)));
        Console.WriteLine();
        Console.WriteLine("readOnly is a ceiling over the grants, not a default beside them. Once writes are");
        Console.WriteLine("granted, the field and row rules still apply to what a write touches.");

        // -- Limits ------------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Limits over seven search hits"));
        Console.WriteLine("  scores  d1 0.92  d2 0.75  d3 0.60  d4 0.88  d5 0.81  d6 none  d7 0.99");
        Console.WriteLine("  sizes   d1 1200  d2 4096  d3 800   d4 2048  d5 none  d6 500   d7 100");
        Console.WriteLine();
        foreach (var limit in Limits)
            Console.WriteLine($"  {limit.Label.PadRight(LabelWidth)}{Ids(Enforce(Policy(limits: limit.Limits), Documents()))}");
        Console.WriteLine();
        Console.WriteLine("Both bounds are inclusive, and a hit with no score or no size is dropped rather");
        Console.WriteLine("than let through. maxResults applies last, to what the other rules kept.");

        // -- Merging -----------------------------------------------------------------------------
        Console.WriteLine();
        Console.WriteLine(Rule("Merging: a user policy and a group policy"));
        var merged = MergedPolicy();
        Console.WriteLine("  resolved from    " + string.Join(", ", merged.SourceProfiles));
        var user = UserDefinition();
        var group = GroupDefinition();
        RuleSource[] sources =
        [
            new(user.Name, user.Permissions, user.ObjectRules, user.Limits),
            new(group.Name, group.Permissions, group.ObjectRules, group.Limits),
            new("merged", merged.Permissions, merged.ObjectRules, merged.Limits),
        ];
        foreach (var (title, how, pick) in MergeTable)
        {
            Console.WriteLine();
            Console.WriteLine($"  {title,-17}{how}");
            foreach (var from in sources)
                Console.WriteLine($"    {from.Name,-19}{pick(from)}");
        }
        Console.WriteLine();
        Console.WriteLine("The merged policy, enforced:");
        var mergedRows = Enforce(merged, MergeRows());
        if (mergedRows.Any(r => r.ContainsKey("ssn") || r.ContainsKey("notes")))
            throw new InvalidOperationException("A HIDDEN FIELD LEAKED. The merge must union both policies' hidden fields.");
        foreach (var row in mergedRows)
            Console.WriteLine("    " + FormatRow(row, MergeColumns));
        Console.WriteLine(Access("labs", Check(merged, objectName: "labs")));
        Console.WriteLine(Access("billing", Check(merged, objectName: "billing")));
        Console.WriteLine(Access("insert", CheckWrite(merged, WriteOperation.Insert, new() { ["name"] = "Bo" })));
        Console.WriteLine();
        Console.WriteLine("Most restrictive wins: allowed sets intersect, hidden fields union, the stronger");
        Console.WriteLine("mask and the lower cap apply, every row filter holds, and a grant survives only if");
        Console.WriteLine("every policy makes it. The group's insert grant is outvoted by the user's policy.");

        Console.WriteLine();
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("One wrapper, one set of calls; the policy alone decided every line above.");
        Console.WriteLine(new string('=', 70));

        return Task.CompletedTask;
    }
}
