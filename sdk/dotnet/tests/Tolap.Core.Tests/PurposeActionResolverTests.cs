using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Resolving a call's action category from wrapper configuration (spec section 15.2).
/// </summary>
/// <remarks>
/// <para>Two lookups, because the two wrapper families identify a call differently. A named tool
/// has a name; an HTTP request has a method and a path and nothing else. A single name-keyed map
/// would have left action validation permanently inert for API sources — a control the
/// configuration implies and that never runs, which is worse than no control at all.</para>
/// <para>The most important behaviour here is the unclassified case: what happens to a call no
/// map entry covers. Both directions are asserted, because getting it wrong in either produces a
/// silent failure — deny-everything looks like a broken deployment, allow-everything looks like
/// a working one.</para>
/// </remarks>
public class PurposeActionResolverTests
{
    private static EffectivePolicy Policy(PurposeProfile? profile) => new(
        Version: "1.0",
        UserId: "user-1",
        TenantId: "tenant-1",
        SourceConnectionId: "db:marketing:customer_segments",
        ResolvedAt: DateTimeOffset.UtcNow,
        ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
        SourceProfiles: new[] { "p" },
        Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: true),
        PurposeProfile: profile);

    private static readonly PurposeProfile Constrained = new(
        "campaign-x-overlap",
        AllowedActions: new[] { "aggregate_overlap", "count_segments" },
        ProhibitedActions: new[] { "export_pii" });

    private static readonly Dictionary<string, string> ToolMap = new()
    {
        ["segment_overlap"] = "aggregate_overlap",
        ["segment_count"] = "count_segments",
        ["export_csv"] = "export_pii"
    };

    private static readonly Dictionary<string, string> HttpMap = new()
    {
        ["GET /segments/overlap"] = "aggregate_overlap",
        ["GET /segments/count"] = "count_segments",
        ["POST /export/*"] = "export_pii"
    };

    // -- Purpose-agnostic policies are untouched ---------------------------

    [Fact]
    public void ValidateTool_NoPurposeProfile_AllowsWithoutConsultingTheMap()
    {
        // The backward-compatibility guarantee. A deployment that has not configured a map, and
        // whose policies carry no purpose, must behave exactly as it did before this feature --
        // which is why the check short-circuits on the profile rather than on the map.
        PurposeActionResolver.ValidateTool(Policy(null), "anything", null)
            .Allowed.Should().BeTrue();
        PurposeActionResolver.ValidateTool(Policy(null), "export_csv", ToolMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateHttpRequest_NoPurposeProfile_AllowsWithoutConsultingTheMap()
    {
        PurposeActionResolver.ValidateHttpRequest(Policy(null), "POST", "/export/all.csv", null)
            .Allowed.Should().BeTrue();
        PurposeActionResolver.ValidateHttpRequest(Policy(null), "POST", "/export/all.csv", HttpMap)
            .Allowed.Should().BeTrue();
    }

    // -- The tool-name lookup ---------------------------------------------

    [Fact]
    public void ValidateTool_MappedAndPermitted_Allows()
    {
        PurposeActionResolver.ValidateTool(Policy(Constrained), "segment_overlap", ToolMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateTool_MappedAndProhibited_Denies()
    {
        var result = PurposeActionResolver.ValidateTool(Policy(Constrained), "export_csv", ToolMap);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'",
            "the reason names the category, which is what the policy forbids -- not the tool, "
            + "which is a deployment detail the policy author never saw");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("unmapped_tool")]
    public void ValidateTool_Unclassified_DeniesUnderAConstrainingPurpose(string? toolName)
    {
        // Fail closed. A tool the administrator did not classify cannot be shown to serve the
        // purpose, and the fix is to classify it rather than to widen the policy -- which is why
        // the reason is phrased as a configuration problem.
        var map = toolName is null ? null : ToolMap;
        var result = PurposeActionResolver.ValidateTool(
            Policy(Constrained), toolName ?? "segment_overlap", map);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void ValidateTool_ToolNameMatchingIsCaseSensitive()
    {
        // A tool name is an identifier, matched as AllowedTools matches it. Two casings are two
        // tools, and the fail-closed consequence is a denial rather than a surprise grant.
        PurposeActionResolver.ValidateTool(Policy(Constrained), "Segment_Overlap", ToolMap)
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void ValidateTool_UnconstrainedPurpose_AllowsAnUnclassifiedTool()
    {
        // A purpose that constrains no actions has nothing for a category to violate, so an
        // unclassified tool is not a problem. Without this, every purpose-bound policy would
        // require a complete tool map before anything worked.
        var unconstrained = new PurposeProfile("campaign-x-overlap");

        PurposeActionResolver.ValidateTool(Policy(unconstrained), "unmapped_tool", ToolMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateTool_EmptyProhibitedListDoesNotMakeACallUnclassifiable()
    {
        // [] on a deny-list forbids nothing, so it does not constrain actions. The mirror of the
        // allow-list rule, where [] denies everything (spec section 3) -- the two arrays read in
        // opposite directions and this is the case that pins it.
        var emptyDenyList = new PurposeProfile(
            "campaign-x-overlap", ProhibitedActions: Array.Empty<string>());

        PurposeActionResolver.ValidateTool(Policy(emptyDenyList), "unmapped_tool", ToolMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateTool_ProhibitionOnlyPurpose_StillDeniesAnUnclassifiedTool()
    {
        // The less obvious half of fail-closed, and the more important one. A purpose declaring
        // only prohibitedActions means "anything but this", and an unclassified tool might be
        // exactly the thing. Permitting the unclassified while forbidding the classified cannot
        // be what the author meant.
        var denyOnly = new PurposeProfile(
            "campaign-x-overlap", ProhibitedActions: new[] { "export_pii" });

        PurposeActionResolver.ValidateTool(Policy(denyOnly), "unmapped_tool", ToolMap)
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void ValidateTool_EmptyAllowListDeniesEvenAMappedTool()
    {
        var noneAllowed = new PurposeProfile(
            "campaign-x-overlap", AllowedActions: Array.Empty<string>());

        PurposeActionResolver.ValidateTool(Policy(noneAllowed), "segment_overlap", ToolMap)
            .Allowed.Should().BeFalse();
    }

    // -- The HTTP method/path lookup --------------------------------------

    [Fact]
    public void ValidateHttpRequest_MappedAndPermitted_Allows()
    {
        PurposeActionResolver.ValidateHttpRequest(
            Policy(Constrained), "GET", "/segments/overlap", HttpMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateHttpRequest_MappedAndProhibited_Denies()
    {
        var result = PurposeActionResolver.ValidateHttpRequest(
            Policy(Constrained), "POST", "/export/all.csv", HttpMap);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(
            "action 'export_pii' is prohibited under purpose 'campaign-x-overlap'");
    }

    [Theory]
    [InlineData("get")]
    [InlineData("GET")]
    [InlineData("Get")]
    public void ValidateHttpRequest_MethodMatchingIsCaseInsensitive(string method)
    {
        // Matching how allowedMethods is compared. An HTTP method is a protocol token, not an
        // identifier, and a deployment should not be able to bypass a category by lower-casing
        // one.
        PurposeActionResolver.ValidateHttpRequest(
            Policy(Constrained), method, "/segments/overlap", HttpMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateHttpRequest_MethodIsPartOfTheKey()
    {
        // GET /export/all.csv is not covered by "POST /export/*". The path alone is not the key,
        // because reading a report and generating one are different actions.
        PurposeActionResolver.ValidateHttpRequest(
            Policy(Constrained), "GET", "/export/all.csv", HttpMap)
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Theory]
    [InlineData("/export/all.csv")]
    [InlineData("/export/nested/deep.csv")]
    public void ValidateHttpRequest_PathGlobUsesTheEndpointDialect(string path)
    {
        // The same dialect allowedEndpoints uses, where * crosses '/'. A deployment writes one
        // kind of endpoint pattern rather than two, and a pattern that behaved differently here
        // than in allowedEndpoints would be a trap.
        PurposeActionResolver.ValidateHttpRequest(Policy(Constrained), "POST", path, HttpMap)
            .Allowed.Should().BeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("/segments/unmapped")]
    public void ValidateHttpRequest_Unclassified_DeniesUnderAConstrainingPurpose(string? path)
    {
        var map = path is null ? null : HttpMap;
        var result = PurposeActionResolver.ValidateHttpRequest(
            Policy(Constrained), "GET", path ?? "/segments/overlap", map);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void ValidateHttpRequest_EveryMatchingEntryIsValidated()
    {
        // Overlapping entries are not resolved by specificity. Any specificity rule can be gamed
        // by adding a broader entry, so all matches are checked and the denial wins -- making the
        // outcome independent of how the map happens to be written.
        var overlapping = new Dictionary<string, string>
        {
            ["GET /segments/*"] = "aggregate_overlap",
            ["GET /segments/individuals"] = "enumerate_individuals"
        };
        var profile = new PurposeProfile(
            "campaign-x-overlap",
            ProhibitedActions: new[] { "enumerate_individuals" });

        var denied = PurposeActionResolver.ValidateHttpRequest(
            Policy(profile), "GET", "/segments/individuals", overlapping);
        var allowed = PurposeActionResolver.ValidateHttpRequest(
            Policy(profile), "GET", "/segments/overlap", overlapping);

        denied.Allowed.Should().BeFalse(
            "the narrow entry forbids this path even though the broad entry permits it");
        allowed.Allowed.Should().BeTrue("the paired control: the broad entry still works");
    }

    [Fact]
    public void ValidateHttpRequest_DenialIsIndependentOfMapOrdering()
    {
        // Same two entries, inserted the other way round. Dictionary enumeration order is not a
        // security boundary, so the resolver sorts before iterating.
        var profile = new PurposeProfile(
            "campaign-x-overlap", ProhibitedActions: new[] { "enumerate_individuals" });

        var forward = new Dictionary<string, string>
        {
            ["GET /segments/*"] = "aggregate_overlap",
            ["GET /segments/individuals"] = "enumerate_individuals"
        };
        var reverse = new Dictionary<string, string>
        {
            ["GET /segments/individuals"] = "enumerate_individuals",
            ["GET /segments/*"] = "aggregate_overlap"
        };

        PurposeActionResolver.ValidateHttpRequest(Policy(profile), "GET", "/segments/individuals", forward)
            .Should().BeEquivalentTo(
                PurposeActionResolver.ValidateHttpRequest(Policy(profile), "GET", "/segments/individuals", reverse));
    }

    [Theory]
    [InlineData("GET")]                  // no space, so no pattern
    [InlineData("GET ")]                 // empty pattern
    [InlineData(" /segments/overlap")]   // empty method
    [InlineData("")]
    public void ValidateHttpRequest_AMalformedKeyMatchesNothing(string key)
    {
        // A misconfigured key that silently matched everything would be the worst possible
        // reading of one: the map exists to narrow. Matching nothing means the request falls
        // through to the unclassified rule and is denied.
        var malformed = new Dictionary<string, string> { [key] = "aggregate_overlap" };

        PurposeActionResolver.ValidateHttpRequest(
            Policy(Constrained), "GET", "/segments/overlap", malformed)
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void ValidateHttpRequest_EmptyMap_IsTreatedAsUnclassifiedNotAsUnrestricted()
    {
        // An empty map is a deployment that configured nothing, not one that permitted
        // everything. Same outcome as a null map, asserted separately because a truthiness check
        // on the dictionary would be the natural way to get one of these two wrong.
        var empty = new Dictionary<string, string>();

        PurposeActionResolver.ValidateHttpRequest(Policy(Constrained), "GET", "/x", empty)
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
        PurposeActionResolver.ValidateTool(Policy(Constrained), "x", empty)
            .Reason.Should().Be(PurposeActionResolver.UndeclaredCategoryReason);
    }

    [Fact]
    public void ValidateHttpRequest_UnconstrainedPurpose_AllowsAnUnclassifiedPath()
    {
        PurposeActionResolver.ValidateHttpRequest(
            Policy(new PurposeProfile("campaign-x-overlap")), "GET", "/anything", HttpMap)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void TheUndeclaredReasonNamesTheConfigurationNotTheAccess()
    {
        // Pinned as a literal because integrators branch on it, and because the phrasing is the
        // fix: the operator needs to add the tool to the map, not widen the policy.
        PurposeActionResolver.UndeclaredCategoryReason
            .Should().Be("action category not declared for tool");
    }
}
