using System.Diagnostics;
using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Covers the <see cref="PolicyMerger"/>, <see cref="PolicyResolutionEngine"/>,
/// <see cref="CanonicalJson"/>, <see cref="SecurityContextSigner"/>, serialization and
/// model surface that the behavioural suites leave one-sided.
/// </summary>
public class CoreApiCoverageTests
{
    // -- PolicyMerger: spec section 3 (null vs empty) and section 8 (permission folding) --

    [Fact]
    public void Merge_DisjointAllowLists_YieldsEmptyArrayNotNull()
    {
        // Spec section 3: intersecting two disjoint allow-lists yields [] — deny
        // everything — and an implementation that treats [] as falsy and discards the
        // rule converts the most restrictive possible outcome into no restriction at all.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", new ObjectRules(AllowedObjects: new[] { "patients" })),
            Definition("b", new ObjectRules(AllowedObjects: new[] { "invoices" }))
        });

        merged.ObjectRules!.AllowedObjects.Should().NotBeNull().And.BeEmpty();

        // And the empty allow-list must actually deny, not be ignored downstream.
        EnforcementEngine.ValidateAccess("patients", merged).Allowed.Should().BeFalse();
    }

    [Fact]
    public void Merge_DisjointAllowedFields_YieldsEmptyArrayThatDeniesEveryField()
    {
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", new ObjectRules(FieldRules: new FieldRules(AllowedFields: new[] { "name" }))),
            Definition("b", new ObjectRules(FieldRules: new FieldRules(AllowedFields: new[] { "age" })))
        });

        merged.ObjectRules!.FieldRules!.AllowedFields.Should().NotBeNull().And.BeEmpty();
        EnforcementEngine.ValidateFieldAccess(new[] { "name", "age" }, merged)
            .Allowed.Should().BeEmpty();
    }

    [Fact]
    public void Merge_OneNullAndOneConstrainedAllowList_TakesTheConstraint()
    {
        // A policy silent on an allow-list adds no restriction, so the other policy's
        // list survives intact rather than widening to unrestricted.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("silent", new ObjectRules(HiddenObjects: new[] { "audit" })),
            Definition("constrained", new ObjectRules(AllowedObjects: new[] { "patients" }))
        });

        merged.ObjectRules!.AllowedObjects.Should().BeEquivalentTo("patients");
    }

    [Fact]
    public void Merge_AllPoliciesSilentOnAllowList_StaysUnrestricted()
    {
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", new ObjectRules(HiddenObjects: new[] { "x" })),
            Definition("b", new ObjectRules(HiddenObjects: new[] { "y" }))
        });

        merged.ObjectRules!.AllowedObjects.Should().BeNull();
        merged.ObjectRules.HiddenObjects.Should().BeEquivalentTo("x", "y");
    }

    [Fact]
    public void Merge_ReadOnlyOrsAndCanQueryCanExportAnd()
    {
        // Spec section 8: canQuery AND, canExport AND, readOnly OR.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("permissive", permissions: new PolicyPermissions(CanQuery: true, CanExport: true, ReadOnly: false)),
            Definition("restrictive", permissions: new PolicyPermissions(CanQuery: true, CanExport: false, ReadOnly: true))
        });

        merged.Permissions.CanQuery.Should().BeTrue();
        merged.Permissions.CanExport.Should().BeFalse("canExport folds with AND");
        merged.Permissions.ReadOnly.Should().BeTrue("readOnly folds with OR, so the restrictive policy wins");
    }

    [Fact]
    public void Merge_PolicySilentOnReadOnly_DefaultsToRestrictiveBeforeFolding()
    {
        // Spec section 8: an absent boolean takes its schema default *before* the fold.
        // A policy silent on readOnly plus a policy with readOnly:false must yield true.
        // Deserialized from JSON rather than constructed, because the absence is only
        // representable on the transport shape.
        var silent = TolapJsonOptions.Deserialize<PolicyDefinition>(
            """{"version":"1.0","name":"silent","permissions":{"canQuery":true}}""");
        var explicitlyWritable = TolapJsonOptions.Deserialize<PolicyDefinition>(
            """{"version":"1.0","name":"writable","permissions":{"canQuery":true,"readOnly":false}}""");

        silent.Permissions.ReadOnly.Should().BeTrue("an absent readOnly defaults to true");

        PolicyMerger.Merge(new[] { silent, explicitlyWritable })
            .Permissions.ReadOnly.Should().BeTrue();
    }

    [Fact]
    public void Merge_AbsentCanExport_DefaultsToFalse()
    {
        var silent = TolapJsonOptions.Deserialize<PolicyDefinition>(
            """{"version":"1.0","name":"silent","permissions":{"canQuery":true}}""");

        silent.Permissions.CanExport.Should().BeFalse();
        PolicyMerger.Merge(new[] { silent }).Permissions.CanExport.Should().BeFalse();
    }

    [Fact]
    public void Merge_UnknownMaskTypeOutranksEveryKnownType()
    {
        // Spec section 6: an unknown maskType ranks most-restrictive so it cannot be
        // beaten by a weaker known type. Merging it against `partial` must not yield
        // partial, which would disclose real characters.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("unknown", new ObjectRules(FieldRules: new FieldRules(
                MaskedFields: new[] { new MaskingRule("ssn", (MaskType)9999) }))),
            Definition("partial", new ObjectRules(FieldRules: new FieldRules(
                MaskedFields: new[] { new MaskingRule("ssn", MaskType.Partial, new MaskingParameters(ShowLast: 4)) })))
        });

        var rule = merged.ObjectRules!.FieldRules!.MaskedFields.Should().ContainSingle().Subject;
        rule.MaskType.Should().Be((MaskType)9999);

        // And applying it redacts rather than returning the raw value.
        EnforcementEngine.ApplyMask("111-22-3333", rule).Should().Be("[REDACTED]");
    }

    [Fact]
    public void Merge_NullMaskBeatsPartial()
    {
        // The pre-spec ranking placed null/redact lowest, so merging ssn:null with
        // ssn:partial produced partial — disclosing digits one policy demanded be erased.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("erase", new ObjectRules(FieldRules: new FieldRules(
                MaskedFields: new[] { new MaskingRule("ssn", MaskType.Null) }))),
            Definition("partial", new ObjectRules(FieldRules: new FieldRules(
                MaskedFields: new[] { new MaskingRule("ssn", MaskType.Partial) })))
        });

        merged.ObjectRules!.FieldRules!.MaskedFields.Should().ContainSingle()
            .Which.MaskType.Should().Be(MaskType.Null);
    }

    [Fact]
    public void Merge_ObjectRulesPresentButAllPropertiesNull_CollapsesToNull()
    {
        // An ObjectRules carrying nothing must not survive as a non-null object: a
        // downstream null check would then take the "rules present" path with nothing in
        // it. Same for FieldRules, TagRules, EndpointRules and Limits.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("empty", new ObjectRules(FieldRules: new FieldRules(), TagRules: new TagRules(),
                EndpointRules: new EndpointRules()), limits: new PolicyLimits())
        });

        merged.ObjectRules.Should().BeNull();
        merged.Limits.Should().BeNull();
    }

    [Fact]
    public void Merge_NoPolicyCarriesRulesOrLimits_LeavesBothNull()
    {
        var merged = PolicyMerger.Merge(new[] { Definition("plain") });

        merged.ObjectRules.Should().BeNull();
        merged.Limits.Should().BeNull();
    }

    [Fact]
    public void Merge_EndpointRules_IntersectsAllowsAndUnionsHidden()
    {
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/drug/*", "/food/*" },
                HiddenEndpoints: new[] { "/admin/*" },
                AllowedMethods: new[] { "GET", "POST" }))),
            Definition("b", new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/drug/*" },
                HiddenEndpoints: new[] { "/internal/*" },
                AllowedMethods: new[] { "GET" })))
        });

        var rules = merged.ObjectRules!.EndpointRules!;
        rules.AllowedEndpoints.Should().BeEquivalentTo("/drug/*");
        rules.HiddenEndpoints.Should().BeEquivalentTo("/admin/*", "/internal/*");
        rules.AllowedMethods.Should().BeEquivalentTo("GET");
    }

    [Fact]
    public void Merge_TagRules_IntersectsAllowedAndUnionsDenied()
    {
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", new ObjectRules(TagRules: new TagRules(
                AllowedTags: new[] { "public", "research" }, DeniedTags: new[] { "secret" }))),
            Definition("b", new ObjectRules(TagRules: new TagRules(
                AllowedTags: new[] { "public" }, DeniedTags: new[] { "pii" })))
        });

        merged.ObjectRules!.TagRules!.AllowedTags.Should().BeEquivalentTo("public");
        merged.ObjectRules.TagRules.DeniedTags.Should().BeEquivalentTo("secret", "pii");
    }

    [Fact]
    public void Merge_ReadOnlyFields_AreUnioned()
    {
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", new ObjectRules(FieldRules: new FieldRules(ReadOnlyFields: new[] { "id" }))),
            Definition("b", new ObjectRules(FieldRules: new FieldRules(ReadOnlyFields: new[] { "created_at" })))
        });

        merged.ObjectRules!.FieldRules!.ReadOnlyFields
            .Should().BeEquivalentTo("id", "created_at");
    }

    [Fact]
    public void Merge_Limits_TakeMinimumExceptMinSimilarityScore()
    {
        // Most-restrictive-wins in both directions: the smallest ceiling, but the
        // *largest* similarity floor.
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("a", limits: new PolicyLimits(MaxResults: 100, MaxQueryTimeSeconds: 30,
                MinSimilarityScore: 0.5, MaxObjectSizeBytes: 1000)),
            Definition("b", limits: new PolicyLimits(MaxResults: 10, MaxQueryTimeSeconds: 60,
                MinSimilarityScore: 0.8, MaxObjectSizeBytes: 500))
        });

        merged.Limits!.MaxResults.Should().Be(10);
        merged.Limits.MaxQueryTimeSeconds.Should().Be(30);
        merged.Limits.MinSimilarityScore.Should().Be(0.8);
        merged.Limits.MaxObjectSizeBytes.Should().Be(500);
    }

    [Fact]
    public void Merge_LimitsWhereOnePolicyIsSilent_TakesTheOtherValue()
    {
        var merged = PolicyMerger.Merge(new[]
        {
            Definition("silent", limits: new PolicyLimits(MaxResults: null)),
            Definition("bounded", limits: new PolicyLimits(MaxResults: 25, MinSimilarityScore: 0.4))
        });

        merged.Limits!.MaxResults.Should().Be(25);
        merged.Limits.MinSimilarityScore.Should().Be(0.4);
        merged.Limits.MaxQueryTimeSeconds.Should().BeNull();
    }

    [Fact]
    public void Merge_RecordsEverySourceProfileName()
    {
        PolicyMerger.Merge(new[] { Definition("a"), Definition("b") })
            .SourceProfiles.Should().Equal("a", "b");
    }

    // -- PolicyResolutionEngine --

    [Fact]
    public void Resolve_GroupAndRoleAndServiceAccountAssignees_AllMatch()
    {
        var definition = Definition("shared", new ObjectRules(AllowedObjects: new[] { "patients" }));

        foreach (var (type, identifier, groups, roles) in new[]
                 {
                     (AssigneeType.User, "alice", Array.Empty<string>(), Array.Empty<string>()),
                     (AssigneeType.Group, "analysts", new[] { "analysts" }, Array.Empty<string>()),
                     (AssigneeType.Role, "auditor", Array.Empty<string>(), new[] { "auditor" }),
                     (AssigneeType.ServiceAccount, "alice", Array.Empty<string>(), Array.Empty<string>())
                 })
        {
            var resolved = PolicyResolutionEngine.Resolve(
                "alice", "t", "db:prod",
                new[] { Assignment("shared", new Assignee(type, identifier)) },
                new[] { definition },
                _ => groups, _ => roles);

            resolved.Permissions.CanQuery.Should().BeTrue($"{type} assignment should match");
        }
    }

    [Fact]
    public void Resolve_UnknownAssigneeType_DoesNotMatch()
    {
        // An assignee type from a newer schema version must not resolve to a grant.
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod",
            new[] { Assignment("shared", new Assignee((AssigneeType)9999, "alice")) },
            new[] { Definition("shared") },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.Permissions.CanQuery.Should().BeFalse();
        resolved.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_GroupOrRoleAssignmentForADifferentPrincipal_DoesNotMatch()
    {
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod",
            new[] { Assignment("shared", new Assignee(AssigneeType.Group, "admins")) },
            new[] { Definition("shared") },
            _ => new[] { "analysts" }, _ => Array.Empty<string>());

        resolved.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_InactiveAssignment_IsIgnored()
    {
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod",
            new[] { Assignment("shared", active: false) },
            new[] { Definition("shared") },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.Permissions.CanQuery.Should().BeFalse();
    }

    [Fact]
    public void Resolve_ExpiredAssignmentIsIgnoredAndFutureExpiryIsHonoured()
    {
        var expired = Assignment("shared", expiresAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        var future = Assignment("shared", expiresAt: DateTimeOffset.UtcNow.AddHours(1));
        var definitions = new[] { Definition("shared") };

        Resolve(expired).Permissions.CanQuery.Should().BeFalse("an expired assignment must stop resolving");
        Resolve(future).Permissions.CanQuery.Should().BeTrue();

        EffectivePolicy Resolve(PolicyAssignment assignment) => PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod", new[] { assignment }, definitions,
            _ => Array.Empty<string>(), _ => Array.Empty<string>());
    }

    [Fact]
    public void Resolve_ScopeNarrowsByTenantAndSourceConnection()
    {
        var definitions = new[] { Definition("shared") };

        // A scope naming a different tenant or a different source must not match, while
        // a matching scope and an unscoped assignment both must.
        Resolve(new AssignmentScope(TenantId: "other")).Permissions.CanQuery.Should().BeFalse();
        Resolve(new AssignmentScope(SourceConnectionId: "db:dev")).Permissions.CanQuery.Should().BeFalse();
        Resolve(new AssignmentScope(TenantId: "t", SourceConnectionId: "db:prod")).Permissions.CanQuery.Should().BeTrue();
        Resolve(new AssignmentScope()).Permissions.CanQuery.Should().BeTrue();

        EffectivePolicy Resolve(AssignmentScope scope) => PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod",
            new[] { Assignment("shared", scope: scope) }, definitions,
            _ => Array.Empty<string>(), _ => Array.Empty<string>());
    }

    [Fact]
    public void Resolve_AssignmentReferencingAMissingDefinition_YieldsDenyAll()
    {
        // A dangling policy name must not resolve to a grant, and must not throw.
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod",
            new[] { Assignment("does-not-exist") },
            new[] { Definition("something-else") },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.Permissions.CanQuery.Should().BeFalse();
        resolved.SourceProfiles.Should().BeEmpty();
    }

    [Fact]
    public void Resolve_SourcePatternsGateTheDefinitionUnlessAppliesToAll()
    {
        // Three distinct paths: appliesToAll short-circuits the pattern check; a matching
        // pattern admits the definition; a non-matching one excludes it.
        Check(Definition("p", appliesToAll: true, sourcePatterns: new[] { "db:other:*" }), true);
        Check(Definition("p", sourcePatterns: new[] { "db:prod:*" }), true);
        Check(Definition("p", sourcePatterns: new[] { "db:dev:*" }), false);
        Check(Definition("p", sourcePatterns: Array.Empty<string>()), true);
        Check(Definition("p", sourcePatterns: null), true);

        void Check(PolicyDefinition definition, bool expected) =>
            PolicyResolutionEngine.Resolve(
                "alice", "t", "db:prod:patients",
                new[] { Assignment("p") }, new[] { definition },
                _ => Array.Empty<string>(), _ => Array.Empty<string>())
            .Permissions.CanQuery.Should().Be(expected);
    }

    [Fact]
    public void Resolve_StampsIdentityAndResolutionTimeOntoTheResult()
    {
        var before = DateTimeOffset.UtcNow;

        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "tenant-1", "db:prod",
            new[] { Assignment("p") }, new[] { Definition("p") },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.UserId.Should().Be("alice");
        resolved.TenantId.Should().Be("tenant-1");
        resolved.SourceConnectionId.Should().Be("db:prod");
        resolved.ResolvedAt.Should().NotBeNull().And.BeOnOrAfter(before);
    }

    [Fact]
    public void Resolve_MergesLowerPriorityDefinitionsFirst()
    {
        // Priority determines fold order, and both definitions must reach the merge.
        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", "db:prod",
            new[] { Assignment("high"), Assignment("low") },
            new[]
            {
                Definition("high", priority: 200),
                Definition("low", priority: 1)
            },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        resolved.SourceProfiles.Should().Equal("low", "high");
    }

    [Fact]
    public void GlobMatch_StopsAtSegmentSeparatorAndIsCaseInsensitive()
    {
        PolicyResolutionEngine.GlobMatch("db:prod:*", "db:prod:patients").Should().BeTrue();
        PolicyResolutionEngine.GlobMatch("db:prod:*", "DB:PROD:patients").Should().BeTrue();

        // '*' does not cross a ':' separator, so a pattern scoped to one segment cannot
        // reach into another.
        PolicyResolutionEngine.GlobMatch("db:*", "db:prod:patients").Should().BeFalse();
        PolicyResolutionEngine.GlobMatch("db:prod", "db:dev").Should().BeFalse();
    }

    [Fact]
    public void GlobMatch_PathologicalPatternIsBoundedAndReturnsNonMatch()
    {
        // Spec sections 7 and 11: .NET's ReDoS mitigation is a regex match timeout, and a
        // timeout is a non-match rather than a stall. Resolution runs before every policy
        // decision, so an unbounded evaluation here stalls the allow/deny itself.
        // Regression: this method previously called Regex.IsMatch with no timeout, and a
        // source pattern of ~20 wildcards did not terminate.
        var pattern = string.Concat(Enumerable.Repeat("*a", 20)) + "*b";
        var value = new string('a', 40);

        var stopwatch = Stopwatch.StartNew();
        var matched = PolicyResolutionEngine.GlobMatch(pattern, value);
        stopwatch.Stop();

        matched.Should().BeFalse();
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Resolve_PathologicalSourcePatternDoesNotStallResolution()
    {
        var pattern = string.Concat(Enumerable.Repeat("*a", 20)) + "*b";
        var stopwatch = Stopwatch.StartNew();

        var resolved = PolicyResolutionEngine.Resolve(
            "alice", "t", new string('a', 40),
            new[] { Assignment("p") },
            new[] { Definition("p", sourcePatterns: new[] { pattern }) },
            _ => Array.Empty<string>(), _ => Array.Empty<string>());

        stopwatch.Stop();
        // A pattern that cannot be evaluated excludes its policy rather than granting it.
        resolved.Permissions.CanQuery.Should().BeFalse();
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));
    }

    // -- CanonicalJson (spec sections 1 and 2) --

    [Theory]
    [InlineData("2026-01-15T10:00:00Z", "2026-01-15T10:00:00Z")]
    [InlineData("2026-01-15T10:00:00+00:00", "2026-01-15T10:00:00Z")]
    [InlineData("2026-01-15T10:00:00.000Z", "2026-01-15T10:00:00Z")]
    [InlineData("2026-01-15T10:00:00.123Z", "2026-01-15T10:00:00.123Z")]
    [InlineData("2026-01-15T10:00:00.123456Z", "2026-01-15T10:00:00.123Z")]
    [InlineData("2026-01-15T10:00:00.1239Z", "2026-01-15T10:00:00.123Z")]
    [InlineData("2026-01-15T12:00:00+02:00", "2026-01-15T10:00:00Z")]
    public void NormalizeTimestamp_MatchesTheSpecTable(string input, string expected)
    {
        // The exact table from spec section 2 rule 5. Sub-second digits are truncated,
        // never rounded, so an expiry can never move later than the issuer intended.
        CanonicalJson.NormalizeTimestamp(DateTimeOffset.Parse(input)).Should().Be(expected);
    }

    [Fact]
    public void Canonicalize_SortsKeysOmitsNullsAndPreservesEmptyArrays()
    {
        var element = JsonDocument.Parse(
            """{"b":1,"a":{"z":true,"y":null},"empty":[],"nested":[{"d":2,"c":3}],"gone":null}""")
            .RootElement;

        CanonicalJson.Canonicalize(element)
            .Should().Be("""{"a":{"z":true},"b":1,"empty":[],"nested":[{"c":3,"d":2}]}""");
    }

    [Fact]
    public void Canonicalize_EmitsRawUtf8WithoutEscaping()
    {
        // Spec section 1: the default .NET encoder escapes '<', '&', '+' and non-ASCII,
        // which would make these bytes differ from Python's ensure_ascii=False output.
        var element = JsonDocument.Parse("""{"name":"Ünïcode <&+> 日本語"}""").RootElement;

        CanonicalJson.Canonicalize(element).Should().Be("""{"name":"Ünïcode <&+> 日本語"}""");
    }

    [Fact]
    public void Serialize_WritesMaskCharEvenWhenItEqualsTheTypeDefault()
    {
        // Spec section 1: no default-value elision in the signed form. The transport
        // converter omits maskChar when it is '*'; the canonical writer must not, or the
        // signed bytes depend on a C# default the other SDKs do not share.
        var rule = new MaskingRule("ssn", MaskType.Partial, new MaskingParameters(ShowLast: 4));

        CanonicalJson.Serialize(rule).Should().Contain("\"maskChar\":\"*\"");
        TolapJsonOptions.Serialize(rule).Should().NotContain("maskChar");
    }

    [Fact]
    public void Serialize_WritesEveryExplicitlyPresentMaskingParameter()
    {
        var parameters = new MaskingParameters(ShowFirst: 1, ShowLast: 2, MaskChar: '#', Algorithm: "sha256");

        CanonicalJson.Serialize(parameters).Should().Be(
            """{"algorithm":"sha256","maskChar":"#","showFirst":1,"showLast":2}""");
    }

    [Fact]
    public void Serialize_NullableTimestampProperty_IsNormalizedAndNullsAreOmitted()
    {
        // Exercises the nullable timestamp converter from both sides on a real model.
        var withTimestamps = new EffectivePolicy(
            Version: "1.0", UserId: "u", TenantId: "t", SourceConnectionId: "s",
            ResolvedAt: DateTimeOffset.Parse("2026-01-15T12:00:00.123456+02:00"),
            ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true));

        var json = CanonicalJson.Serialize(withTimestamps);

        json.Should().Contain("\"resolvedAt\":\"2026-01-15T10:00:00.123Z\"");
        json.Should().NotContain("expiresAt");
    }

    [Fact]
    public void CanonicalConverters_RoundTripThroughRead()
    {
        // The canonical options are used for reading as well as writing, so the Read side
        // of each converter must accept what the Write side produced.
        var context = SecurityContextBuilder.Build("u", "t", new[]
        {
            EffectivePolicy.DenyAll() with
            {
                ObjectRules = new ObjectRules(FieldRules: new FieldRules(
                    MaskedFields: new[]
                    {
                        new MaskingRule("ssn", MaskType.Partial, new MaskingParameters(ShowLast: 4, MaskChar: '#'))
                    })),
                ResolvedAt = DateTimeOffset.Parse("2026-01-15T10:00:00Z")
            }
        });

        var payload = SecurityContextSigner.BuildCanonicalPayload(context);
        var reparsed = TolapJsonOptions.Deserialize<JsonElement>(payload);

        reparsed.GetProperty("policies")[0]
            .GetProperty("objectRules").GetProperty("fieldRules")
            .GetProperty("maskedFields")[0].GetProperty("parameters")
            .GetProperty("maskChar").GetString().Should().Be("#");
    }

    // -- SecurityContextSigner --

    [Fact]
    public void Sign_HmacSha512_ProducesADistinctVerifiableSignature()
    {
        // The 512 arm is a separate switch case from the 256 default and must both sign
        // and validate; a signature that verifies under the wrong algorithm would mean
        // the algorithm field is unauthenticated.
        var context = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() });

        var sha256 = SecurityContextSigner.Sign(context, "key", SigningAlgorithm.HmacSha256);
        var sha512 = SecurityContextSigner.Sign(context, "key", SigningAlgorithm.HmacSha512);

        sha512.Integrity!.Algorithm.Should().Be(SigningAlgorithm.HmacSha512);
        sha512.Integrity.Signature.Should().NotBe(sha256.Integrity!.Signature);
        SecurityContextSigner.Validate(sha512, "key").Should().BeTrue();
        SecurityContextSigner.Validate(sha512, "wrong-key").Should().BeFalse();
    }

    [Fact]
    public void Sign_Ed25519_ThrowsNotSupportedRatherThanSigningWithAFallback()
    {
        // Spec-relevant fail-closed: an unimplemented algorithm must refuse, never
        // silently downgrade to HMAC, which would produce a signature the field claims
        // is Ed25519.
        var context = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() });

        var act = () => SecurityContextSigner.Sign(context, "key", SigningAlgorithm.Ed25519);

        act.Should().Throw<NotSupportedException>().WithMessage("*Ed25519*");
    }

    [Fact]
    public void Sign_UnknownAlgorithm_ThrowsArgumentOutOfRange()
    {
        var context = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() });

        var act = () => SecurityContextSigner.Sign(context, "key", (SigningAlgorithm)9999);

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Validate_ContextWithNoIntegrityBlock_IsInvalid()
    {
        var unsigned = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() });

        SecurityContextSigner.Validate(unsigned, "key").Should().BeFalse();
    }

    [Fact]
    public void Validate_SignatureThatIsNotBase64_IsInvalidRatherThanThrowing()
    {
        // The provided signature is attacker-controlled, so malformed Base64 must be an
        // invalid signature rather than a FormatException escaping to the caller.
        var context = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() })
            with { Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "not!base64!") };

        SecurityContextSigner.Validate(context, "key").Should().BeFalse();
    }

    [Fact]
    public void Validate_SignatureOfTheWrongLength_IsInvalid()
    {
        // Valid Base64 but the wrong digest length: FixedTimeEquals must reject rather
        // than throw on a length mismatch.
        var context = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() })
            with { Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, Convert.ToBase64String(new byte[8])) };

        SecurityContextSigner.Validate(context, "key").Should().BeFalse();
    }

    [Fact]
    public void BuildCanonicalPayload_StripsIntegrityFromEnvelopeAndFromEveryPolicy()
    {
        // Spec section 2 rule 1: a signature cannot cover itself, so the integrity block
        // is removed from the envelope *and* from every policy inside it. A policy
        // arriving with its own integrity block must not change the signed bytes.
        var policy = EffectivePolicy.DenyAll();
        var context = SecurityContextBuilder.Build("u", "t", new[] { policy });
        var withPolicyIntegrity = context with
        {
            Policies = new[] { policy with { Integrity = new IntegrityBlock(SigningAlgorithm.HmacSha256, "AAAA") } }
        };

        SecurityContextSigner.BuildCanonicalPayload(withPolicyIntegrity)
            .Should().Be(SecurityContextSigner.BuildCanonicalPayload(context))
            .And.NotContain("integrity");
    }

    [Fact]
    public void BuildCanonicalPayload_NullPoliciesArray_ProjectsToAnEmptyArray()
    {
        // Defensive: a context deserialized without a policies key must still produce
        // signable bytes rather than dereferencing null.
        var context = new SecurityContext("1.0", "u", "t",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1), null!);

        SecurityContextSigner.BuildCanonicalPayload(context).Should().Contain("\"policies\":[]");
    }

    [Fact]
    public void BuildCanonicalPayload_RewritingExpiryChangesTheSignedBytes()
    {
        // Spec section 2 rule 2: issuedAt and expiresAt are inside the payload, so
        // rewriting an expiry on a captured context invalidates the signature rather
        // than extending its life.
        var context = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() });
        var signed = SecurityContextSigner.Sign(context, "key");

        var extended = signed with { ExpiresAt = signed.ExpiresAt.AddYears(1) };

        SecurityContextSigner.BuildCanonicalPayload(extended)
            .Should().NotBe(SecurityContextSigner.BuildCanonicalPayload(signed));
        SecurityContextSigner.Validate(extended, "key").Should().BeFalse();
    }

    [Fact]
    public void ValidateExpiry_MissingExpiryIsRejectedAndNotTreatedAsNeverExpires()
    {
        // Spec section 2: a context whose expiresAt was absent from the transport JSON
        // deserializes to DateTimeOffset.MinValue and must be rejected.
        var noExpiry = new SecurityContext("1.0", "u", "t",
            DateTimeOffset.UtcNow, default, Array.Empty<EffectivePolicy>());

        SecurityContextSigner.ValidateExpiry(noExpiry).Should().Be("security context has no expiry");
    }

    [Fact]
    public void ValidateExpiry_ExpiredAndValidContexts()
    {
        var expired = SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>(), TimeSpan.FromHours(-1));
        var valid = SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>(), TimeSpan.FromHours(1));

        SecurityContextSigner.ValidateExpiry(expired).Should().Be("security context has expired");
        SecurityContextSigner.ValidateExpiry(valid).Should().BeNull();
    }

    [Fact]
    public void Deserialize_RejectsNonBase64Input()
    {
        var act = () => SecurityContextSigner.Deserialize("not base64 at all!!", "key");

        act.Should().Throw<SecurityException>().WithMessage("*not valid Base64*");
    }

    [Fact]
    public void Deserialize_ReportsSignatureFailureBeforeExpiry()
    {
        // Spec section 2: signature is verified first, so a tampered context reports a
        // signature failure rather than leaking whether a valid context merely expired.
        var expired = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() }, TimeSpan.FromHours(-1));
        var signedWithOtherKey = SecurityContextSigner.Sign(expired, "other-key");

        var act = () => SecurityContextSigner.Deserialize(
            SecurityContextSigner.Serialize(signedWithOtherKey), "key");

        act.Should().Throw<SecurityException>().WithMessage("*Invalid signature*");
    }

    [Fact]
    public void Deserialize_ValidlySignedButExpiredContext_ReportsExpiry()
    {
        var expired = SecurityContextBuilder.Build("u", "t", new[] { EffectivePolicy.DenyAll() }, TimeSpan.FromHours(-1));
        var signed = SecurityContextSigner.Sign(expired, "key");

        var act = () => SecurityContextSigner.Deserialize(SecurityContextSigner.Serialize(signed), "key");

        act.Should().Throw<SecurityException>().WithMessage("*expired*");
    }

    [Fact]
    public void SerializeThenDeserialize_RoundTripsAValidContext()
    {
        var signed = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("alice", "tenant-1", new[] { EffectivePolicy.DenyAll() }), "key");

        var restored = SecurityContextSigner.Deserialize(SecurityContextSigner.Serialize(signed), "key");

        restored.UserId.Should().Be("alice");
        restored.TenantId.Should().Be("tenant-1");
        restored.Integrity!.Signature.Should().Be(signed.Integrity!.Signature);
    }

    [Fact]
    public void SecurityException_CarriesAnInnerExceptionWhenGivenOne()
    {
        var inner = new InvalidOperationException("cause");

        new SecurityException("outer", inner).InnerException.Should().BeSameAs(inner);
    }

    // -- SecurityContextBuilder --

    [Fact]
    public void Build_DefaultsToAOneHourTtlAndHonoursAnExplicitOne()
    {
        // Spec section 11 names the one-hour default TTL as the only replay bound, so the
        // default is a security parameter rather than a convenience.
        var now = DateTimeOffset.UtcNow;

        var defaulted = SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>());
        defaulted.ExpiresAt.Should().BeCloseTo(now.AddHours(1), TimeSpan.FromSeconds(5));
        defaulted.Version.Should().Be("1.0");
        defaulted.Integrity.Should().BeNull("Build returns an unsigned context ready for signing");

        var custom = SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>(), TimeSpan.FromMinutes(5));
        custom.ExpiresAt.Should().BeCloseTo(now.AddMinutes(5), TimeSpan.FromSeconds(5));
    }

    // -- Enums and models --

    [Fact]
    public void MaskTypeRestrictiveness_RanksByDisclosureWithUnknownHighest()
    {
        MaskType.Partial.Restrictiveness().Should().Be(1);
        MaskType.Hash.Restrictiveness().Should().Be(2);
        MaskType.Full.Restrictiveness().Should().Be(3);
        MaskType.Redact.Restrictiveness().Should().Be(4);
        MaskType.Null.Restrictiveness().Should().Be(5);
        ((MaskType)9999).Restrictiveness().Should().Be(6, "an unknown mask type ranks most restrictive");
    }

    [Fact]
    public void DenyAll_GrantsNothing()
    {
        var deny = EffectivePolicy.DenyAll();

        deny.Permissions.CanQuery.Should().BeFalse();
        deny.Permissions.CanExport.Should().BeFalse();
        deny.Permissions.ReadOnly.Should().BeTrue();
        deny.SourceProfiles.Should().BeEmpty();
        deny.ObjectRules.Should().BeNull();
        deny.Limits.Should().BeNull();
    }

    [Fact]
    public void AuditInfoAndPolicyAssignment_ExposeTheirMembers()
    {
        var granted = DateTimeOffset.Parse("2026-01-15T10:00:00Z");
        var audit = new AuditInfo("admin@example.com", granted, "onboarding ticket 42");
        var assignment = new PolicyAssignment("1.0", "analyst",
            new Assignee(AssigneeType.Group, "analysts"),
            new AssignmentScope(TenantId: "t", SourceConnectionId: "db:prod"),
            Active: true, Audit: audit, ExpiresAt: granted.AddDays(30));

        audit.GrantedBy.Should().Be("admin@example.com");
        audit.GrantedAt.Should().Be(granted);
        audit.Reason.Should().Be("onboarding ticket 42");

        assignment.Version.Should().Be("1.0");
        assignment.PolicyName.Should().Be("analyst");
        assignment.Assignee.Type.Should().Be(AssigneeType.Group);
        assignment.Assignee.Identifier.Should().Be("analysts");
        assignment.Scope.TenantId.Should().Be("t");
        assignment.Scope.SourceConnectionId.Should().Be("db:prod");
        assignment.Active.Should().BeTrue();
        assignment.Audit.Should().BeSameAs(audit);
        assignment.ExpiresAt.Should().Be(granted.AddDays(30));
    }

    [Fact]
    public void PolicyDefinition_DefaultsMatchTheSchema()
    {
        var definition = new PolicyDefinition("1.0", "p", new PolicyPermissions(CanQuery: true));

        definition.Description.Should().BeNull();
        definition.Priority.Should().Be(100);
        definition.AppliesToAll.Should().BeFalse();
        definition.SourcePatterns.Should().BeNull();
    }

    // -- Serialization converters --

    [Theory]
    [InlineData("equals", FilterOperator.Equals)]
    [InlineData("notEquals", FilterOperator.NotEquals)]
    [InlineData("in", FilterOperator.In)]
    [InlineData("notIn", FilterOperator.NotIn)]
    [InlineData("greaterThan", FilterOperator.GreaterThan)]
    [InlineData("lessThan", FilterOperator.LessThan)]
    [InlineData("contains", FilterOperator.Contains)]
    [InlineData("startsWith", FilterOperator.StartsWith)]
    [InlineData("matches", FilterOperator.Matches)]
    public void FilterOperator_RoundTripsEveryWireValue(string wire, FilterOperator expected)
    {
        TolapJsonOptions.Deserialize<FilterOperator>($"\"{wire}\"").Should().Be(expected);
        TolapJsonOptions.Serialize(expected).Should().Be($"\"{wire}\"");
    }

    [Theory]
    [InlineData("full", MaskType.Full)]
    [InlineData("partial", MaskType.Partial)]
    [InlineData("hash", MaskType.Hash)]
    [InlineData("null", MaskType.Null)]
    [InlineData("redact", MaskType.Redact)]
    public void MaskType_RoundTripsEveryWireValue(string wire, MaskType expected)
    {
        TolapJsonOptions.Deserialize<MaskType>($"\"{wire}\"").Should().Be(expected);
        TolapJsonOptions.Serialize(expected).Should().Be($"\"{wire}\"");
    }

    [Theory]
    [InlineData("hmac-sha256", SigningAlgorithm.HmacSha256)]
    [InlineData("hmac-sha512", SigningAlgorithm.HmacSha512)]
    [InlineData("ed25519", SigningAlgorithm.Ed25519)]
    public void SigningAlgorithm_RoundTripsEveryWireValue(string wire, SigningAlgorithm expected)
    {
        TolapJsonOptions.Deserialize<SigningAlgorithm>($"\"{wire}\"").Should().Be(expected);
        TolapJsonOptions.Serialize(expected).Should().Be($"\"{wire}\"");
    }

    [Theory]
    [InlineData("user", AssigneeType.User)]
    [InlineData("group", AssigneeType.Group)]
    [InlineData("role", AssigneeType.Role)]
    [InlineData("serviceAccount", AssigneeType.ServiceAccount)]
    public void AssigneeType_RoundTripsEveryWireValue(string wire, AssigneeType expected)
    {
        TolapJsonOptions.Deserialize<AssigneeType>($"\"{wire}\"").Should().Be(expected);
        TolapJsonOptions.Serialize(expected).Should().Be($"\"{wire}\"");
    }

    [Fact]
    public void EnumConverters_RejectUnknownWireValues()
    {
        // A value from a newer schema version must fail loudly at the boundary rather
        // than defaulting to whatever enum member happens to be zero — for
        // FilterOperator that would be `equals`, silently rewriting the policy.
        Reject<FilterOperator>("\"betweenish\"");
        Reject<MaskType>("\"scramble\"");
        Reject<SigningAlgorithm>("\"rsa-pss\"");
        Reject<AssigneeType>("\"device\"");

        static void Reject<T>(string json) =>
            FluentActions.Invoking(() => TolapJsonOptions.Deserialize<T>(json))
                .Should().Throw<JsonException>();
    }

    [Fact]
    public void EnumConverters_RejectNonStringTokens()
    {
        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<FilterOperator>("0"))
            .Should().Throw<Exception>();
        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<MaskType>("0"))
            .Should().Throw<Exception>();
        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<SigningAlgorithm>("0"))
            .Should().Throw<Exception>();
        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<AssigneeType>("0"))
            .Should().Throw<Exception>();
    }

    [Fact]
    public void EnumConverters_RejectOutOfRangeValuesOnWrite()
    {
        // The write side guards separately from the read side; an out-of-range value
        // reaching serialization must not emit a number the other SDKs cannot parse.
        FluentActions.Invoking(() => TolapJsonOptions.Serialize((FilterOperator)9999))
            .Should().Throw<JsonException>();
        FluentActions.Invoking(() => TolapJsonOptions.Serialize((MaskType)9999))
            .Should().Throw<JsonException>();
        FluentActions.Invoking(() => TolapJsonOptions.Serialize((SigningAlgorithm)9999))
            .Should().Throw<JsonException>();
        FluentActions.Invoking(() => TolapJsonOptions.Serialize((AssigneeType)9999))
            .Should().Throw<JsonException>();
    }

    [Fact]
    public void MaskingParameters_ReadEveryFieldAndSkipUnknownOnes()
    {
        var parameters = TolapJsonOptions.Deserialize<MaskingParameters>(
            """{"showFirst":1,"showLast":2,"maskChar":"#","algorithm":"sha256","futureField":{"nested":[1,2]}}""");

        parameters.ShowFirst.Should().Be(1);
        parameters.ShowLast.Should().Be(2);
        parameters.MaskChar.Should().Be('#');
        parameters.Algorithm.Should().Be("sha256");
    }

    [Fact]
    public void MaskingParameters_EmptyMaskCharFallsBackToTheDefault()
    {
        TolapJsonOptions.Deserialize<MaskingParameters>("""{"maskChar":""}""")
            .MaskChar.Should().Be('*');
    }

    [Fact]
    public void MaskingParameters_OmitsAbsentValuesOnWrite()
    {
        TolapJsonOptions.Serialize(new MaskingParameters()).Should().Be("{}");
        TolapJsonOptions.Serialize(new MaskingParameters(ShowFirst: 2, MaskChar: '#'))
            .Should().Be("""{"showFirst":2,"maskChar":"#"}""");
    }

    [Fact]
    public void MaskingParameters_RejectMalformedInput()
    {
        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<MaskingParameters>("[]"))
            .Should().Throw<JsonException>();
        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<MaskingParameters>("""{"showFirst":1"""))
            .Should().Throw<JsonException>();
    }

    [Fact]
    public void TolapJsonOptions_ExposesSharedOptionsAndFailsOnUndeserializableJson()
    {
        TolapJsonOptions.Default.PropertyNameCaseInsensitive.Should().BeTrue();
        TolapJsonOptions.Default.PropertyNamingPolicy.Should().Be(JsonNamingPolicy.CamelCase);

        FluentActions.Invoking(() => TolapJsonOptions.Deserialize<PolicyDefinition>("null"))
            .Should().Throw<JsonException>();
    }

    [Fact]
    public void TolapJsonOptions_DeserializesPropertyNamesCaseInsensitively()
    {
        TolapJsonOptions.Deserialize<PolicyDefinition>(
            """{"Version":"1.0","NAME":"p","permissions":{"CanQuery":true}}""")
            .Name.Should().Be("p");
    }

    // -- Helpers --

    private static PolicyDefinition Definition(
        string name,
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null,
        PolicyPermissions? permissions = null,
        bool appliesToAll = false,
        string[]? sourcePatterns = null,
        int priority = 100) =>
        new(Version: "1.0",
            Name: name,
            Permissions: permissions ?? new PolicyPermissions(CanQuery: true),
            Priority: priority,
            AppliesToAll: appliesToAll,
            SourcePatterns: sourcePatterns,
            ObjectRules: objectRules,
            Limits: limits);

    private static PolicyAssignment Assignment(
        string policyName,
        Assignee? assignee = null,
        AssignmentScope? scope = null,
        bool active = true,
        DateTimeOffset? expiresAt = null) =>
        new(Version: "1.0",
            PolicyName: policyName,
            Assignee: assignee ?? new Assignee(AssigneeType.User, "alice"),
            Scope: scope ?? new AssignmentScope(),
            Active: active,
            Audit: new AuditInfo("admin", DateTimeOffset.UtcNow, "test"),
            ExpiresAt: expiresAt);
}
