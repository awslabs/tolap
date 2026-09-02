using Tolap.Core;
using Tolap.Mcp;

namespace Tolap.Examples;

/// <summary>
/// Binding a policy to a <i>reason</i>, not just an identity.
/// </summary>
/// <remarks>
/// <para>
/// Every other example here answers "what may this identity see?". This one answers "and for
/// what?". A signed context binds identity, tenant, source and expiry — but not the reason the
/// data is being read. So an agent holding a perfectly legitimate context may use it for anything
/// its policy happens to permit, and an agent that has drifted off-task is indistinguishable from
/// one that has not.
/// </para>
/// <para>
/// Purpose binding makes the declared reason an input to resolution and part of the signed bytes.
/// It is specified in <c>docs/canonical-enforcement-spec.md</c> §15, as four controls. This example
/// walks them in the order a call meets them, and shows each one <b>both allowing and denying</b>:
/// </para>
/// <list type="number">
///   <item><i>Resolution filtering</i> (§15.1) — the purpose selects which policies resolve at all.</item>
///   <item><i>Delegation chain</i> (§15.3) — authority may narrow at every hop and never widen.</item>
///   <item><i>Action validation</i> (§15.2) — a semantic action category, supplied by configuration.</item>
///   <item><i>The judge</i> (§15.4) — an optional model check that can only subtract.</item>
/// </list>
/// <para>
/// A demo that shows only denials teaches nothing about whether legitimate work still passes, so
/// every control below is paired. The last section shows the property the whole thing rests on:
/// the purpose and the chain are inside the signature, so a captured context is not repurposable.
/// </para>
/// <para>
/// Deliberately mirrors <c>examples/python/purpose_binding_example.py</c> and
/// <c>examples/typescript/purpose-binding-example.ts</c> — same policies, same chain, same stub
/// verdicts, byte-identical printed output. A divergence between the languages then shows up as a
/// different result rather than hiding behind separately-written expectations.
/// </para>
/// <para>
/// The policies match <c>fixtures/policies/purpose-*.json</c>, which is what the conformance
/// suites pin. They are written inline so the rules under test are visible in one place.
/// </para>
/// <para>
/// One asymmetry worth naming, because it bites when porting: the action-category map lives on
/// <see cref="SecureContextToolWrapper"/> here and in TypeScript, but on Python's
/// <c>SecureMcpToolWrapper</c>. The printed output is identical; only the wrapper the map hangs
/// off differs.
/// </para>
/// </remarks>
public static class PurposeBindingExample
{
    public const string SigningKey = "example-signing-key-do-not-use-in-production";

    public const string User = "user-marketing-001";
    public const string Tenant = "tenant-acme-retail";
    public const string Source = "db:marketing:customer_segments";

    public const string CampaignPurpose = "campaign-x-overlap";
    public const string FraudPurpose = "fraud-detection";

    /// <summary>
    /// The purpose the campaign policy serves, and the actions it will and will not admit.
    /// </summary>
    /// <remarks>
    /// <c>AllowedActions</c> absent would mean <i>unrestricted</i> (§3); naming it is what makes
    /// <c>inspect_account</c> — a category no prohibition mentions — still a denial below.
    /// </remarks>
    public static readonly PurposeProfile CampaignProfile = new(
        PurposeId: CampaignPurpose,
        Description: "Identify overlapping opted-in customer segments for Campaign X.",
        AllowedActions: ["aggregate_overlap", "count_segments"],
        ProhibitedActions: ["export_pii", "enumerate_individuals", "join_external_data"]);

    public static readonly PurposeProfile FraudProfile = new(
        PurposeId: FraudPurpose,
        Description: "Review flagged accounts for payment fraud.",
        AllowedActions: ["inspect_account", "enumerate_individuals"],
        ProhibitedActions: ["export_pii"]);

    /// <summary>
    /// The wrapper's action-category map: <b>deployment configuration</b>, supplied where the
    /// wrapper is constructed, keyed by tool name and matched exactly.
    /// </summary>
    /// <remarks>
    /// It is deliberately not a caller argument. An agent that can name its own action category
    /// names a permitted one, and the check reduces to a formality. <c>join_external</c> is absent
    /// on purpose — an unclassified tool under a constraining purpose is a configuration fault,
    /// and fails closed. Held as an ordered list as well as a dictionary so the printed order is
    /// the authored order rather than whatever the hash buckets produce.
    /// </remarks>
    public static readonly (string Tool, string Category)[] ToolCategoryList =
    [
        ("segment_overlap", "aggregate_overlap"),
        ("count_segments", "count_segments"),
        ("export_customers", "export_pii"),
        ("inspect_account", "inspect_account"),
    ];

    public static readonly IReadOnlyDictionary<string, string> ToolActionCategories =
        ToolCategoryList.ToDictionary(entry => entry.Tool, entry => entry.Category);

    /// <summary>Purpose-scoped: resolves only for a caller declaring <c>campaign-x-overlap</c>.</summary>
    public static PolicyDefinition CampaignDefinition() => new(
        Version: "1.0",
        Name: "campaign-x-overlap-agent",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 10,
        SourcePatterns: ["db:marketing:*"],
        ObjectRules: new ObjectRules(
            AllowedObjects: ["customer_segments", "campaign_assignments"],
            FieldRules: new FieldRules(
                HiddenFields: ["customer_segments.ssn"],
                MaskedFields: [new MaskingRule("customer_segments.email", MaskType.Hash)]),
            RowFilters: [new RowFilter("consent_status", FilterOperator.Equals, Value: "opted_in")]),
        Limits: new PolicyLimits(MaxResults: 10000),
        PurposeProfile: CampaignProfile);

    /// <summary>
    /// The same sources, a different purpose. Granted to the same user, so a purpose mismatch —
    /// not a missing grant — is what excludes it.
    /// </summary>
    public static PolicyDefinition FraudDefinition() => new(
        Version: "1.0",
        Name: "fraud-detection-agent",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 10,
        SourcePatterns: ["db:marketing:*"],
        ObjectRules: new ObjectRules(AllowedObjects: ["flagged_accounts", "campaign_assignments"]),
        Limits: new PolicyLimits(MaxResults: 500),
        PurposeProfile: FraudProfile);

    /// <summary>
    /// No <c>purposeProfile</c> at all — the backward-compatibility half of every scenario here.
    /// </summary>
    /// <remarks>
    /// Purpose binding is opt-in and additive: a policy carrying no profile resolves whether or
    /// not a purpose is declared, down to the signed bytes it produced before §15 existed.
    /// </remarks>
    public static PolicyDefinition BaselineDefinition() => new(
        Version: "1.0",
        Name: "marketing-baseline",
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        Priority: 50,
        SourcePatterns: ["db:marketing:*"],
        ObjectRules: new ObjectRules(
            FieldRules: new FieldRules(
                HiddenFields: ["customer_segments.ssn", "customer_segments.date_of_birth"])),
        Limits: new PolicyLimits(MaxResults: 2000));

    private static PolicyAssignment[] Assignments(IReadOnlyList<PolicyDefinition> definitions) =>
        definitions.Select(d => new PolicyAssignment(
            Version: "1.0",
            PolicyName: d.Name,
            Assignee: new Assignee(AssigneeType.User, User),
            Scope: new AssignmentScope(TenantId: Tenant),
            Active: true,
            Audit: new AuditInfo(
                "admin-jane-doe",
                DateTimeOffset.Parse("2026-09-01T09:00:00Z"),
                $"granted for the purpose-binding example: {d.Name}"))).ToArray();

    /// <summary>Resolve exactly as a store would, with the purpose as a filter (§15.1).</summary>
    /// <remarks>
    /// The filter runs <i>before</i> the merge, alongside the <c>SourcePatterns</c> filter and for
    /// the same reason: a definition that does not apply must not fold its rules into the effective
    /// policy at all. When every candidate is purpose-scoped and no matching purpose is declared
    /// the filtered set is empty, and resolution returns the same deny-all it returns for any empty
    /// set — there is no separate deny path to drift.
    /// </remarks>
    public static EffectivePolicy ResolveFor(
        IReadOnlyList<PolicyDefinition> definitions, string? declaredPurpose) =>
        PolicyResolutionEngine.Resolve(
            userId: User,
            tenantId: Tenant,
            sourceConnectionId: Source,
            assignments: Assignments(definitions),
            definitions: definitions,
            getGroups: _ => [],
            getRoles: _ => [],
            declaredPurpose: declaredPurpose);

    // -----------------------------------------------------------------------------------------
    // The delegation chain: a human delegates to an orchestrator, which delegates to an agent.
    // -----------------------------------------------------------------------------------------

    /// <summary>Three hops, each narrower than its parent, in both purpose and scope.</summary>
    public static DelegationHop[] NarrowingChain() =>
    [
        new(User, PrincipalType.User,
            DeclaredPurpose: "campaign-*",
            ScopeNarrowing: ["read", "aggregate", "export"]),
        new("orchestrator-01", PrincipalType.Service,
            DeclaredPurpose: "campaign-x-*",
            ScopeNarrowing: ["read", "aggregate"]),
        new("agent-overlap", PrincipalType.Agent,
            DeclaredPurpose: CampaignPurpose,
            ScopeNarrowing: ["read"]),
    ];

    /// <summary>A fourth hop that steps sideways out of the family it was delegated within.</summary>
    public static DelegationHop WideningHop() =>
        new("agent-exfil", PrincipalType.Agent, DeclaredPurpose: "campaign-y-export");

    public static DelegationHop[] TwoHop(string parent, string child) =>
    [
        new(User, PrincipalType.User, DeclaredPurpose: parent),
        new("agent-overlap", PrincipalType.Agent, DeclaredPurpose: child),
    ];

    public static DelegationHop[] ScopeHops(string[] parent, string[] child) =>
    [
        new(User, PrincipalType.User, ScopeNarrowing: parent),
        new("agent-overlap", PrincipalType.Agent, ScopeNarrowing: child),
    ];

    // -----------------------------------------------------------------------------------------
    // The judge: stubbed on purpose. An example must not make a live model call.
    // -----------------------------------------------------------------------------------------

    /// <summary>A judge with a fixed verdict, so the <i>mapping</i> is what this section shows.</summary>
    /// <remarks>
    /// A real judge's answer is not a function of its input, which is why the conformance corpus
    /// pins the verdict-to-disposition mapping rather than the verdict. An example that called a
    /// model would be untestable and would need a credential to run.
    /// </remarks>
    public sealed class StubJudge(JudgeResult result, string modelId = "example-judge-model") : IJudge
    {
        public string ModelId { get; } = modelId;

        public Task<JudgeResult> EvaluateAsync(JudgeRequest request, CancellationToken ct = default)
            => Task.FromResult(result);
    }

    /// <summary>
    /// The campaign policy with semantic review switched on, and the thresholds named.
    /// </summary>
    /// <remarks>
    /// Every judge field must be read from the resolved policy. Left to each integrator's glue, the
    /// predictable outcome is a judge running with thresholds nobody chose while the policy's
    /// <c>Model</c> is quietly ignored — configuration implying a control that never runs.
    /// </remarks>
    public static EffectivePolicy JudgedPolicy() =>
        ResolveFor([CampaignDefinition()], CampaignPurpose) with
        {
            PurposeProfile = new PurposeProfile(
                PurposeId: CampaignPurpose,
                AllowedActions: CampaignProfile.AllowedActions,
                ProhibitedActions: CampaignProfile.ProhibitedActions,
                Judge: new JudgeConfig(
                    Enabled: true,
                    Model: "example-judge-model",
                    ConfidenceThreshold: 0.85,
                    EscalationThreshold: 0.60)),
        };

    // -----------------------------------------------------------------------------------------
    // Signing: the purpose and the chain are inside the signature.
    // -----------------------------------------------------------------------------------------

    /// <summary>A context carrying the declared purpose and the chain, then signed.</summary>
    /// <remarks>
    /// <see cref="SecurityContextBuilder.Build"/> records the chain; it does not validate it.
    /// Validation is a separate call, because a chain arriving over the wire must be checked by the
    /// party that enforces rather than by the party that assembled it.
    /// </remarks>
    public static SecurityContext SignedContext() =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build(
                User,
                Tenant,
                [ResolveFor([CampaignDefinition(), FraudDefinition()], CampaignPurpose)],
                declaredPurpose: CampaignPurpose,
                delegationChain: NarrowingChain()),
            SigningKey);

    // -----------------------------------------------------------------------------------------
    // Printing. Every line below is byte-identical to the Python and TypeScript examples.
    // -----------------------------------------------------------------------------------------

    private const int LabelWidth = 34;
    private const int VerdictWidth = 10;

    private static string Row(string label, string verdict, string detail = "") =>
        $"  {label.PadRight(LabelWidth)}{verdict.PadRight(VerdictWidth)}{detail}".TrimEnd();

    private static string Access(string label, bool allowed, string detail = "") =>
        Row(label, allowed ? "ALLOW" : "DENY", detail);

    private static string Rule(string title) =>
        $"--- {title} " + new string('-', Math.Max(0, 70 - 5 - title.Length));

    private static string Describe(EffectivePolicy policy) =>
        policy.SourceProfiles.Length == 0
            ? "deny-all: 0 policies resolved, canQuery=false"
            : $"{string.Join(", ", policy.SourceProfiles)} (maxResults={policy.Limits?.MaxResults})";

    public static async Task RunExampleAsync()
    {
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Purpose binding: four controls, in the order a call meets them");
        Console.WriteLine(new string('=', 70));

        // ---------------------------------------------------------- 1. resolution filtering
        Console.WriteLine();
        Console.WriteLine(Rule("1. resolution filtering (spec 15.1)"));
        Console.WriteLine("Two policies are granted to the same user over the same sources, and both are");
        Console.WriteLine("purpose-scoped:");
        Console.WriteLine("    campaign-x-overlap-agent  purposeId 'campaign-x-overlap'");
        Console.WriteLine("    fraud-detection-agent     purposeId 'fraud-detection'");
        Console.WriteLine();

        PolicyDefinition[] scoped = [CampaignDefinition(), FraudDefinition()];
        (string Label, string? Declared)[] scopedCases =
        [
            ("(no purpose)", null),
            ($"'{CampaignPurpose}'", CampaignPurpose),
            ($"'{FraudPurpose}'", FraudPurpose),
            ("'Campaign-X-Overlap'", "Campaign-X-Overlap"),
        ];
        foreach (var (label, declared) in scopedCases)
        {
            var resolved = ResolveFor(scoped, declared);
            Console.WriteLine(Access(label, resolved.SourceProfiles.Length > 0, Describe(resolved)));
        }

        Console.WriteLine();
        Console.WriteLine("The purpose selects the policy. Declaring none resolves nothing, because a");
        Console.WriteLine("purpose-scoped policy is not a default grant; declaring one resolves that policy");
        Console.WriteLine("and never the other's rules. The comparison is exact and case-sensitive, so");
        Console.WriteLine("'Campaign-X-Overlap' resolves no more than a purpose nobody authored would.");
        Console.WriteLine();
        Console.WriteLine("Purpose binding is additive, though. Add a policy carrying no purposeProfile and");
        Console.WriteLine("the no-purpose caller resolves again, exactly as it did before section 15 existed:");

        PolicyDefinition[] withBaseline = [CampaignDefinition(), FraudDefinition(), BaselineDefinition()];
        (string Label, string? Declared)[] baselineCases =
        [
            ("(no purpose)", null),
            ($"'{CampaignPurpose}'", CampaignPurpose),
        ];
        foreach (var (label, declared) in baselineCases)
        {
            var resolved = ResolveFor(withBaseline, declared);
            Console.WriteLine(Access(label, resolved.SourceProfiles.Length > 0, Describe(resolved)));
        }

        // --------------------------------------------------------------- 2. delegation chain
        Console.WriteLine();
        Console.WriteLine(Rule("2. delegation chain (spec 15.3)"));
        Console.WriteLine("Authority reaches the agent through three hops, narrowing at each one:");
        Console.WriteLine("    user-marketing-001  user     'campaign-*'          scopes [read, aggregate, export]");
        Console.WriteLine("    orchestrator-01     service  'campaign-x-*'        scopes [read, aggregate]");
        Console.WriteLine("    agent-overlap       agent    'campaign-x-overlap'  scopes [read]");
        Console.WriteLine();

        var chain = NarrowingChain();
        var ok = DelegationChainValidator.Validate(chain);
        Console.WriteLine(Access("three narrowing hops", ok.Allowed, ok.Reason ?? ""));

        var widened = DelegationChainValidator.Validate([.. chain, WideningHop()]);
        Console.WriteLine(Access("+ a fourth, wider hop", widened.Allowed, widened.Reason ?? ""));

        Console.WriteLine();
        Console.WriteLine("Now the case a plain prefix test gets wrong. Both children begin with the parent's");
        Console.WriteLine("characters; only one of them is a narrowing:");
        foreach (var child in new[] { "campaign-x-overlap", "campaign-xyz-evil" })
        {
            var result = DelegationChainValidator.Validate(TwoHop("campaign-x", child));
            var note = result.Allowed ? "extends on a '-' segment boundary" : result.Reason ?? "";
            Console.WriteLine(Access($"campaign-x -> {child}", result.Allowed, note));
        }

        Console.WriteLine();
        Console.WriteLine("'campaign-x' and 'campaign-xyz-evil' are unrelated purposes; one merely begins with");
        Console.WriteLine("the other's characters. Requiring the segment boundary makes the prefix mean what a");
        Console.WriteLine("reader assumes it means.");
        Console.WriteLine();
        Console.WriteLine("Scopes narrow the same way. scopeNarrowing lists what is still IN FORCE at a hop,");
        Console.WriteLine("not what the hop removed, so each set must be a subset of its parent's:");
        (string[] Parent, string[] Child)[] scopeCases =
        [
            (["read", "aggregate"], ["read"]),
            (["read"], ["read", "write"]),
        ];
        foreach (var (parentScopes, childScopes) in scopeCases)
        {
            var result = DelegationChainValidator.Validate(ScopeHops(parentScopes, childScopes));
            var label = $"[{string.Join(", ", parentScopes)}] -> [{string.Join(", ", childScopes)}]";
            Console.WriteLine(Access(label, result.Allowed, result.Reason ?? "a subset of the parent"));
        }

        // -------------------------------------------------------------- 3. action validation
        Console.WriteLine();
        Console.WriteLine(Rule("3. action validation (spec 15.2)"));
        Console.WriteLine("The action category comes from the wrapper's map -- deployment configuration, fixed");
        Console.WriteLine("where the wrapper is constructed, keyed by tool name and matched exactly:");
        foreach (var (tool, category) in ToolCategoryList)
        {
            Console.WriteLine($"    {tool.PadRight(18)} -> {category}");
        }
        Console.WriteLine("    join_external      -> (deliberately not in the map)");
        Console.WriteLine();
        Console.WriteLine("It is never a caller argument. An agent that can name its own action category names a");
        Console.WriteLine("permitted one, and the check reduces to a formality.");
        Console.WriteLine();
        Console.WriteLine("Under purpose 'campaign-x-overlap':");
        Console.WriteLine("    allowedActions     [aggregate_overlap, count_segments]");
        Console.WriteLine("    prohibitedActions  [export_pii, enumerate_individuals, join_external_data]");
        Console.WriteLine();

        var wrapper = new SecureContextToolWrapper(
            new SecureContextWrapperOptions(SigningKey, ToolActionCategories: ToolActionCategories));
        var context = SignedContext();
        foreach (var toolName in new[]
                 {
                     "segment_overlap", "export_customers", "inspect_account", "join_external",
                 })
        {
            var result = wrapper.PreExecute(context, new PreExecuteArgs(toolName));
            Console.WriteLine(Access(
                toolName, result.Allowed, result.Reason ?? "category 'aggregate_overlap' is allowed"));
        }

        Console.WriteLine();
        Console.WriteLine("Three different denials, and the third is the one worth dwelling on. An unclassified");
        Console.WriteLine("tool under a purpose that constrains actions at all is refused, because a purpose");
        Console.WriteLine("declaring only prohibitedActions means 'anything but these' -- and an unclassified");
        Console.WriteLine("tool might be exactly one of them. The reason names a configuration fault because");
        Console.WriteLine("that is what it is: the fix is to classify the tool, not to widen the policy.");

        // ------------------------------------------------------------------------ 4. the judge
        Console.WriteLine();
        Console.WriteLine(Rule("4. the semantic judge (spec 15.4)"));
        Console.WriteLine("Optional, and stubbed here: an example must not make a live model call. Three fixed");
        Console.WriteLine("verdicts through the real gate, with the policy's own thresholds --");
        Console.WriteLine("confidenceThreshold 0.85, escalationThreshold 0.60:");
        Console.WriteLine();

        var judged = JudgedPolicy();
        (string Label, JudgeResult Result, string Note)[] verdicts =
        [
            ("aligned, confidence 0.95",
             new JudgeResult(Aligned: true, Confidence: 0.95, Reasoning: "counts only"),
             "the deterministic allowance stands"),
            ("misaligned, confidence 0.95",
             new JudgeResult(Aligned: false, Confidence: 0.95, Reasoning: "row-level export"),
             "the allowance is withdrawn"),
            ("aligned, confidence 0.70",
             new JudgeResult(Aligned: true, Confidence: 0.70, Reasoning: "probably fine"),
             "a DENIAL unless a review handler is wired"),
        ];
        foreach (var (label, result, note) in verdicts)
        {
            // JudgeGate takes the *policy*, not loose thresholds: every judge field is read from
            // the resolved profile, including the model, which is checked before any call is
            // issued. It returns the disposition together with a reason, because escalate covers
            // both "the judge could not tell" and "this deployment wired the wrong model".
            var outcome = await JudgeGate
                .EvaluateAsync(judged, new StubJudge(result), "segment_overlap(campaign_x)")
                .ConfigureAwait(false);
            Console.WriteLine(Row(label, outcome.Disposition.ToString().ToLowerInvariant(), note));
        }

        Console.WriteLine();
        Console.WriteLine("escalate is a DENIAL unless an escalation handler is wired. Otherwise 'escalate to");
        Console.WriteLine("human review' silently means 'permit' in every deployment that never built the review");
        Console.WriteLine("step -- a fail-open on precisely the ambiguous cases the judge exists to surface.");
        Console.WriteLine();
        Console.WriteLine("And the judge is strictly subtractive. It runs only after the three deterministic");
        Console.WriteLine("checks have already allowed the call, and can only take that allowance away; it is");
        Console.WriteLine("never consulted to permit something they denied. That is what makes a prompt");
        Console.WriteLine("injection survivable rather than critical -- the worst a manipulated verdict achieves");
        Console.WriteLine("is an allow the deterministic rules had already granted.");

        // ----------------------------------------------- the purpose is inside the signature
        Console.WriteLine();
        Console.WriteLine(Rule("the purpose and the chain are inside the signature"));
        Console.WriteLine("None of the above is worth running on a context the caller can rewrite. An unsigned");
        Console.WriteLine("chain can be edited by the principal it constrains, so a validator would be checking");
        Console.WriteLine("the attacker's own arithmetic.");
        Console.WriteLine();

        Console.WriteLine(Verify("as signed", SignedContext(), "purpose 'campaign-x-overlap', 3 hops"));

        var repurposed = Repurposed();
        Console.WriteLine(Verify("declared purpose swapped", repurposed, "to 'fraud-detection'"));

        var rechained = Rechained();
        Console.WriteLine(Verify("last hop repurposed", rechained, "to 'campaign-y-export'"));

        Console.WriteLine(Verify(
            "a fourth hop appended", Appended(), "agent-exfil, 'campaign-y-export'"));

        Console.WriteLine(Verify(
            "hops reordered", Reordered(), "hop 0 is the delegator; reversing inverts it"));

        if (SecurityContextSigner.Validate(repurposed, SigningKey)
            || SecurityContextSigner.Validate(rechained, SigningKey))
        {
            throw new InvalidOperationException(
                "A MUTATED CONTEXT STILL VERIFIED. The purpose and the chain must be inside the " +
                "signed bytes, or nothing above constrains anything.");
        }

        // -------------------------------------------------------------------------- conclusion
        Console.WriteLine();
        Console.WriteLine(new string('=', 70));
        Console.WriteLine("Four controls, each shown allowing legitimate work and refusing the rest:");
        Console.WriteLine("  * the declared purpose selects which policies resolve at all");
        Console.WriteLine("  * a delegation chain may narrow at every hop and never widen");
        Console.WriteLine("  * the action category is configuration, so a caller cannot name its own");
        Console.WriteLine("  * the judge can only withdraw an allowance, never grant one");
        Console.WriteLine();
        Console.WriteLine("What this does NOT do: purpose is *asserted* by the caller. TOLAP checks that the");
        Console.WriteLine("assertion matches a policy and that a chain is internally consistent. It cannot");
        Console.WriteLine("check that the caller was honest. This constrains a cooperative agent that drifts,");
        Console.WriteLine("not an integrator that lies.");
        Console.WriteLine(new string('=', 70));
    }

    private static string Verify(string label, SecurityContext context, string detail) =>
        Row(label, SecurityContextSigner.Validate(context, SigningKey) ? "VALID" : "BROKEN", detail);

    /// <summary>The signed context with its declared purpose rewritten.</summary>
    public static SecurityContext Repurposed() =>
        SignedContext() with { DeclaredPurpose = FraudPurpose };

    /// <summary>The signed context with the last hop's purpose rewritten.</summary>
    public static SecurityContext Rechained()
    {
        var context = SignedContext();
        var chain = context.DelegationChain!.ToArray();
        chain[^1] = chain[^1] with { DeclaredPurpose = "campaign-y-export" };
        return context with { DelegationChain = chain };
    }

    /// <summary>The signed context with a fourth hop appended.</summary>
    public static SecurityContext Appended()
    {
        var context = SignedContext();
        return context with { DelegationChain = [.. context.DelegationChain!, WideningHop()] };
    }

    /// <summary>The signed context with its hops reversed — hop 0 is the delegator.</summary>
    public static SecurityContext Reordered()
    {
        var context = SignedContext();
        return context with { DelegationChain = [.. context.DelegationChain!.Reverse()] };
    }
}
