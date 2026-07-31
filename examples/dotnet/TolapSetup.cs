using Tolap.Core;

namespace Tolap.Examples;

/// <summary>
/// Shared TOLAP setup for the .NET framework examples: one policy, one signed context.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately mirrors <c>examples/python/tolap_setup.py</c> and
/// <c>examples/typescript/tolap-setup.ts</c> — same policy, same rows, same expected output. That
/// is not duplication for its own sake: it means the examples across all three languages make the
/// <i>same</i> claim, so a divergence between SDKs shows up as a different enforced result rather
/// than hiding behind separately-written expectations.
/// </para>
/// <para>
/// Each example registers a tool with a different framework and routes data access through
/// <see cref="EnforcedQuery"/>. The enforcement code is identical regardless of framework, because
/// TOLAP wraps the function the framework calls rather than integrating with the framework itself.
/// </para>
/// </remarks>
public static class TolapSetup
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    /// <summary>
    /// What the "database" returns: more rows and more columns than the policy permits, so the
    /// difference between raw and enforced output is observable rather than asserted.
    /// </summary>
    public static readonly List<Dictionary<string, object?>> FakeRows = new()
    {
        new() { ["id"] = 1, ["name"] = "Alice Nguyen", ["region"] = "us-east", ["ssn"] = "111-22-3333", ["dob"] = "1979-04-12" },
        new() { ["id"] = 2, ["name"] = "Bruno Sato", ["region"] = "us-east", ["ssn"] = "222-33-4444", ["dob"] = "1985-11-02" },
        new() { ["id"] = 3, ["name"] = "Carol Diaz", ["region"] = "us-east", ["ssn"] = "333-44-5555", ["dob"] = "1990-01-30" },
        new() { ["id"] = 4, ["name"] = "Dan Meyer", ["region"] = "eu-west", ["ssn"] = "444-55-6666", ["dob"] = "1972-08-19" },
    };

    /// <summary>
    /// The effective policy the agent's user holds for this source.
    /// </summary>
    /// <remarks>
    /// In a real deployment this comes from <c>store.ResolveEffectivePolicyAsync(...)</c>, which
    /// merges every assignment the user holds — see docs/architecture.md. Constructed inline here
    /// so the examples need no database and the rules under test are visible in one place.
    /// </remarks>
    public static EffectivePolicy BuildPolicy()
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "analyst-001",
            TenantId: "hospital-001",
            SourceConnectionId: "db:analytics:patients",
            ResolvedAt: now,
            // Inside the signature, so it is the only bound on how long a captured context stays
            // usable (canonical-enforcement-spec.md §13).
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "example-analyst" },
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
            ObjectRules: new ObjectRules(
                AllowedObjects: new[] { "patients" },
                FieldRules: new FieldRules(
                    HiddenFields: new[] { "ssn" },
                    MaskedFields: new[] { new MaskingRule("dob", MaskType.Redact) }),
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, Value: "us-east") }),
            Limits: new PolicyLimits(MaxResults: 2));
    }

    /// <summary>A signed context for the policy above.</summary>
    /// <remarks>
    /// Signing is not decoration: the enforcement path verifies signature and expiry, so a
    /// tampered policy is refused rather than applied — which is what stops an agent editing its
    /// own permissions in transit.
    /// </remarks>
    public static SecurityContext SignedContext()
        => SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("analyst-001", "hospital-001", new[] { BuildPolicy() }),
            SigningKey);

    /// <summary>
    /// Stands in for the code that really talks to your data source.
    /// </summary>
    /// <remarks>
    /// Deliberately returns everything: TOLAP is handed the <i>result</i>, so a fake source that
    /// pre-filtered would prove nothing. Swap this for Npgsql, the AWS SDK or an HttpClient call —
    /// the enforcement above it does not change, and it never sees your credentials.
    /// </remarks>
    public static List<Dictionary<string, object?>> QueryPatientsUnsafe(string table)
        => FakeRows.Select(r => new Dictionary<string, object?>(r)).ToList();

    /// <summary>
    /// The one method every framework example calls. This is the whole integration.
    /// </summary>
    /// <remarks>
    /// The object check runs first and separately, because a result-filtering pass cannot express
    /// "this table is not yours" — by the time rows exist, the unauthorized query has already been
    /// issued and logged as though it were authorized.
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">
    /// When the policy refuses the call. Each framework surfaces this to the model as a tool
    /// error: an agent must be able to tell "no rows matched" from "you may not read this", and
    /// returning an empty list for a denial makes those indistinguishable.
    /// </exception>
    public static List<Dictionary<string, object?>> EnforcedQuery(string table)
    {
        var policy = BuildPolicy();

        // Verify before enforcing. A context whose signature does not check out grants nothing.
        var context = SignedContext();
        if (!SecurityContextSigner.Validate(context, SigningKey))
            throw new UnauthorizedAccessException("security context failed verification");

        var decision = EnforcementEngine.ValidateAccess(table, policy);
        if (!decision.Allowed)
            throw new UnauthorizedAccessException($"Access denied: {decision.Reason}");

        var rows = QueryPatientsUnsafe(table);
        return (List<Dictionary<string, object?>>)EnforcementEngine.ApplyResultPipeline(rows, policy)!;
    }
}
