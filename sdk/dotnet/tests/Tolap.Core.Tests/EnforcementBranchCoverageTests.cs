using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Exercises both outcomes of every conditional in <see cref="EnforcementEngine"/> that
/// the behavioural suites reach from one side only.
/// </summary>
/// <remarks>
/// Branch coverage, not statement coverage, is what these tests are for. Every recent
/// critical defect in this library lived on the unexercised side of a conditional that
/// statement coverage already counted as covered — an unknown <c>MaskType</c> that fell
/// through to the raw value, negative row-filter operators that failed open on a missing
/// field. So each test names the specific spec rule it pins rather than simply reaching
/// the line.
/// </remarks>
public class EnforcementBranchCoverageTests
{
    // -- Spec section 3: null (unrestricted) vs empty array (deny everything) --
    //
    // The distinction is load-bearing and must not be collapsed by a truthiness check.
    // Each pair below asserts *both* sides, because an implementation that treats []
    // as falsy passes the null case and silently converts the most restrictive possible
    // outcome into no restriction at all.

    [Fact]
    public void ValidateAccess_EmptyAllowedObjects_DeniesEveryObject()
    {
        var policy = Policy(new ObjectRules(AllowedObjects: Array.Empty<string>()));

        var result = EnforcementEngine.ValidateAccess("patients", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("object not in allowed set");
    }

    [Fact]
    public void ValidateAccess_NullAllowedObjects_IsUnrestricted()
    {
        var policy = Policy(new ObjectRules(AllowedObjects: null, HiddenObjects: null));

        EnforcementEngine.ValidateAccess("patients", policy).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateAccess_NoObjectRulesAtAll_IsUnrestricted()
    {
        var policy = Policy(objectRules: null);

        EnforcementEngine.ValidateAccess("patients", policy).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateAccess_HiddenTakesPrecedenceOverAllowed()
    {
        // An object named in both lists is denied: hidden wins, or a policy author could
        // re-grant a hidden object by also allowing it.
        var policy = Policy(new ObjectRules(
            AllowedObjects: new[] { "patients" },
            HiddenObjects: new[] { "patients" }));

        var result = EnforcementEngine.ValidateAccess("patients", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("object is hidden");
    }

    [Fact]
    public void ValidateFieldAccess_EmptyAllowedFields_DeniesEveryField()
    {
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: Array.Empty<string>())));

        var result = EnforcementEngine.ValidateFieldAccess(new[] { "name", "age" }, policy);

        result.Allowed.Should().BeEmpty();
        result.Denied.Should().BeEquivalentTo("name", "age");
    }

    [Fact]
    public void ValidateFieldAccess_NoFieldRules_AllowsEveryField()
    {
        var policy = Policy(new ObjectRules(FieldRules: null));

        var result = EnforcementEngine.ValidateFieldAccess(new[] { "name", "ssn" }, policy);

        result.Allowed.Should().BeEquivalentTo("name", "ssn");
        result.Denied.Should().BeEmpty();
    }

    [Fact]
    public void ValidateFieldAccess_HiddenTakesPrecedenceOverAllowed()
    {
        var policy = Policy(new ObjectRules(FieldRules: new FieldRules(
            AllowedFields: new[] { "ssn", "name" },
            HiddenFields: new[] { "ssn" })));

        var result = EnforcementEngine.ValidateFieldAccess(new[] { "ssn", "name" }, policy);

        result.Allowed.Should().BeEquivalentTo("name");
        result.Denied.Should().BeEquivalentTo("ssn");
    }

    [Fact]
    public void ValidateEndpoint_EmptyAllowedEndpoints_DeniesEveryPath()
    {
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(AllowedEndpoints: Array.Empty<string>())));

        var result = EnforcementEngine.ValidateEndpoint("/drug/event.json", "GET", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("endpoint not in allowed set");
    }

    [Fact]
    public void ValidateEndpoint_EmptyAllowedMethods_DeniesEveryMethod()
    {
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(AllowedMethods: Array.Empty<string>())));

        var result = EnforcementEngine.ValidateEndpoint("/x", "GET", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("method not allowed");
    }

    [Fact]
    public void ValidateEndpoint_NoEndpointRules_PermitsReadsAndDeniesWrites()
    {
        // Corrected: this previously asserted DELETE was allowed with no endpointRules at
        // all, which is exactly the fail-open spec section 9 forbids. An absent
        // allowedMethods defaults to the read methods, so the path being unconstrained does
        // not make the method unconstrained.
        var policy = Policy(objectRules: null, readOnly: false);

        EnforcementEngine.ValidateEndpoint("/anything", "GET", policy).Allowed.Should().BeTrue();

        var write = EnforcementEngine.ValidateEndpoint("/anything", "DELETE", policy);
        write.Allowed.Should().BeFalse();
        write.Reason.Should().Be("method not allowed");
    }

    [Fact]
    public void ValidateEndpoint_MethodMatchIsCaseInsensitive()
    {
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(AllowedMethods: new[] { "GET" })));

        EnforcementEngine.ValidateEndpoint("/x", "get", policy).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateEndpoint_HiddenTakesPrecedenceOverAllowed()
    {
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/admin/*" },
            HiddenEndpoints: new[] { "/admin/*" })));

        var result = EnforcementEngine.ValidateEndpoint("/admin/audit", "GET", policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("endpoint is hidden");
    }

    // -- Spec section 9: write protection. Both controls previously failed OPEN. --

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public void ValidateEndpoint_OmittedAllowedMethods_PermitsReadMethods(string method)
    {
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(AllowedEndpoints: new[] { "/api/*" })),
            readOnly: false);

        EnforcementEngine.ValidateEndpoint("/api/x", method, policy).Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public void ValidateEndpoint_OmittedAllowedMethods_DeniesWriteMethods(string method)
    {
        // The schema documents the default: "If omitted, defaults to read-only methods:
        // GET, HEAD, OPTIONS". Treating omitted as unrestricted told a policy author writes
        // were already blocked while permitting every one of them.
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(AllowedEndpoints: new[] { "/api/*" })),
            readOnly: false);

        var result = EnforcementEngine.ValidateEndpoint("/api/x", method, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("method not allowed");
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    public void ValidateEndpoint_ReadOnly_DeniesAWriteMethodItWasGranted(string method)
    {
        // ReadOnly was OR-folded during merge and then never consulted by any decision, so
        // an administrator could set it, watch it survive resolution, and still have DELETE
        // permitted. ReadOnly is a ceiling: AllowedMethods cannot lift it.
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedMethods: new[] { "GET", "POST", "PUT", "PATCH", "DELETE" })));

        var result = EnforcementEngine.ValidateEndpoint("/api/x", method, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("method not allowed on a read-only policy");
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public void ValidateEndpoint_ReadOnly_StillPermitsEveryReadMethod(string method)
    {
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedMethods: new[] { "GET", "HEAD", "OPTIONS", "DELETE" })));

        EnforcementEngine.ValidateEndpoint("/api/x", method, policy).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateEndpoint_AllowedMethodsDenial_KeepsItsOwnDistinctReason()
    {
        // The two reasons must be distinguishable so an integrator can tell which rule
        // denied them: widening AllowedMethods fixes one and not the other.
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(AllowedMethods: new[] { "GET" })));

        EnforcementEngine.ValidateEndpoint("/api/x", "DELETE", policy)
            .Reason.Should().Be("method not allowed");
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("POST")]
    [InlineData("DELETE")]
    public void ValidateEndpoint_EmptyAllowedMethods_DeniesEvenWhenWritable(string method)
    {
        // Spec section 3: [] is deny-all for an allow-list, and that is unaffected by
        // ReadOnly. GET is denied too.
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedMethods: Array.Empty<string>())),
            readOnly: false);

        var result = EnforcementEngine.ValidateEndpoint("/api/x", method, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("method not allowed");
    }

    [Fact]
    public void ValidateEndpoint_CaseInsensitiveOnBothSidesOfThePair()
    {
        var writable = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(AllowedMethods: new[] { "delete" })),
            readOnly: false);

        // Lower-case policy entry, upper-case request, and the reverse.
        EnforcementEngine.ValidateEndpoint("/api/x", "DELETE", writable).Allowed.Should().BeTrue();
        EnforcementEngine.ValidateEndpoint("/api/x", "delete", writable).Allowed.Should().BeTrue();

        // The ReadOnly ceiling is likewise case-insensitive: a lower-case "delete" must not
        // slip past a read-method set spelled in upper case.
        var readOnly = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(AllowedMethods: new[] { "delete" })));

        EnforcementEngine.ValidateEndpoint("/api/x", "delete", readOnly)
            .Reason.Should().Be("method not allowed on a read-only policy");
    }

    [Fact]
    public void FilterByTags_EmptyAllowedTags_DropsEveryRecord()
    {
        // Spec section 3: an empty allow-list is deny-all, including for a record that
        // does carry tags.
        var policy = Policy(new ObjectRules(TagRules: new TagRules(AllowedTags: Array.Empty<string>())));
        var rows = Rows(new Dictionary<string, object?>() { ["tags"] = new[] { "public" } });

        EnforcementEngine.FilterByTags(rows, policy).Should().BeEmpty();
    }

    [Fact]
    public void FilterByTags_NoTagRules_KeepsEveryRecord()
    {
        var rows = Rows(new Dictionary<string, object?>() { ["tags"] = new[] { "confidential" } });

        EnforcementEngine.FilterByTags(rows, Policy(new ObjectRules(TagRules: null)))
            .Should().HaveCount(1);
    }

    [Fact]
    public void FilterByTags_UntaggedRecord_DroppedUnderAllowListKeptUnderDenyList()
    {
        // The two rules treat a record with no tags differently and both directions
        // matter: an allow-list requires at least one allowed tag (an untagged record
        // has none), while a deny-list only excludes records carrying a denied tag.
        var untagged = Rows(new Dictionary<string, object?>() { ["id"] = 1 });

        EnforcementEngine.FilterByTags(
            untagged,
            Policy(new ObjectRules(TagRules: new TagRules(AllowedTags: new[] { "public" }))))
            .Should().BeEmpty();

        EnforcementEngine.FilterByTags(
            untagged,
            Policy(new ObjectRules(TagRules: new TagRules(DeniedTags: new[] { "secret" }))))
            .Should().HaveCount(1);
    }

    [Fact]
    public void FilterByTags_DeniedTakesPrecedenceOverAllowed()
    {
        var policy = Policy(new ObjectRules(TagRules: new TagRules(
            AllowedTags: new[] { "public" },
            DeniedTags: new[] { "confidential" })));
        var rows = Rows(new Dictionary<string, object?>() { ["tags"] = new[] { "public", "confidential" } });

        EnforcementEngine.FilterByTags(rows, policy).Should().BeEmpty();
    }

    [Fact]
    public void FilterByTags_NullTagsValue_IsTreatedAsUntagged()
    {
        var policy = Policy(new ObjectRules(TagRules: new TagRules(AllowedTags: new[] { "public" })));
        var rows = Rows(new Dictionary<string, object?>() { ["tags"] = null });

        EnforcementEngine.FilterByTags(rows, policy).Should().BeEmpty();
    }

    [Fact]
    public void FilterByTags_TagsAsJsonArrayAndObjectList_AreBothRead()
    {
        // Tags arrive as string[] from a scenario file, List<object?> from a JSON body,
        // and JsonElement from a raw HTTP response. All three must be read, or a policy
        // silently stops filtering depending only on which source produced the row.
        var policy = Policy(new ObjectRules(TagRules: new TagRules(DeniedTags: new[] { "secret" })));

        var jsonTags = JsonDocument.Parse("""{"tags":["secret"]}""").RootElement.GetProperty("tags");
        EnforcementEngine.FilterByTags(Rows(new Dictionary<string, object?>() { ["tags"] = jsonTags }), policy).Should().BeEmpty();

        EnforcementEngine.FilterByTags(
            Rows(new Dictionary<string, object?>() { ["tags"] = new List<object?> { "secret" } }), policy).Should().BeEmpty();

        EnforcementEngine.FilterByTags(
            Rows(new Dictionary<string, object?>() { ["tags"] = new[] { "secret" } }), policy).Should().BeEmpty();
    }

    [Fact]
    public void FilterByTags_TagsInAnUnreadableShape_IsTreatedAsUntagged()
    {
        // A scalar in the tags slot yields no tags, so an allow-list drops the row.
        // Fails closed rather than throwing on malformed data.
        var policy = Policy(new ObjectRules(TagRules: new TagRules(AllowedTags: new[] { "public" })));

        EnforcementEngine.FilterByTags(Rows(new Dictionary<string, object?>() { ["tags"] = 42 }), policy).Should().BeEmpty();
    }

    // -- Spec section 7: row filters fail closed --

    [Fact]
    public void ApplyRowFilters_NoFiltersOrEmptyFilterArray_ReturnsEveryRow()
    {
        var rows = Rows(new Dictionary<string, object?>() { ["a"] = 1 });

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: null)))
            .Should().HaveCount(1);
        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: Array.Empty<RowFilter>())))
            .Should().HaveCount(1);
    }

    [Fact]
    public void ApplyRowFilters_UnknownOperator_DropsTheRow()
    {
        // An operator from a newer schema version must not silently disable the filter.
        // A filter the engine cannot evaluate is a filter it cannot claim to satisfy, so
        // the row is dropped (spec section 7 fail-closed).
        var policy = Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("region", (FilterOperator)9999, "us-east")
        }));

        EnforcementEngine.ApplyRowFilters(Rows(new Dictionary<string, object?>() { ["region"] = "us-east" }), policy)
            .Should().BeEmpty();
    }

    [Theory]
    [InlineData(FilterOperator.In)]
    [InlineData(FilterOperator.NotIn)]
    public void ApplyRowFilters_InOperatorsWithNullValues_DropTheRow(FilterOperator op)
    {
        // A set-membership filter with no set is unevaluable. Both the positive and the
        // negative form drop the row; letting notIn pass would retain exactly the rows
        // the policy author meant to exclude.
        var policy = Policy(new ObjectRules(RowFilters: new[] { new RowFilter("region", op, Values: null) }));

        EnforcementEngine.ApplyRowFilters(Rows(new Dictionary<string, object?>() { ["region"] = "us-east" }), policy)
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_InAndNotIn_BothOutcomesAreExercised()
    {
        var rows = Rows(
            new Dictionary<string, object?> { ["region"] = "us-east" },
            new Dictionary<string, object?> { ["region"] = "eu-west" });

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("region", FilterOperator.In, Values: new object[] { "us-east" })
        }))).Should().ContainSingle().Which["region"].Should().Be("us-east");

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("region", FilterOperator.NotIn, Values: new object[] { "us-east" })
        }))).Should().ContainSingle().Which["region"].Should().Be("eu-west");
    }

    [Theory]
    [InlineData(FilterOperator.Contains)]
    [InlineData(FilterOperator.StartsWith)]
    [InlineData(FilterOperator.Matches)]
    public void ApplyRowFilters_StringOperatorsAgainstNullOperands_DropTheRow(FilterOperator op)
    {
        // A present-but-null field and a filter with no comparison value are both
        // unevaluable; neither may pass.
        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["name"] = null }),
            Policy(new ObjectRules(RowFilters: new[] { new RowFilter("name", op, "x") })))
            .Should().BeEmpty();

        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["name"] = "anything" }),
            Policy(new ObjectRules(RowFilters: new[] { new RowFilter("name", op, Value: null) })))
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_ContainsAndStartsWith_BothOutcomesAreExercised()
    {
        var rows = Rows(
            new Dictionary<string, object?> { ["name"] = "alpha-one" },
            new Dictionary<string, object?> { ["name"] = "beta-two" });

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("name", FilterOperator.Contains, "alpha")
        }))).Should().ContainSingle().Which["name"].Should().Be("alpha-one");

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("name", FilterOperator.StartsWith, "beta")
        }))).Should().ContainSingle().Which["name"].Should().Be("beta-two");
    }

    [Fact]
    public void ApplyRowFilters_GreaterThanAndLessThan_BothOutcomesAreExercised()
    {
        var rows = Rows(
            new Dictionary<string, object?> { ["age"] = 20 },
            new Dictionary<string, object?> { ["age"] = 40 });

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("age", FilterOperator.GreaterThan, 30)
        }))).Should().ContainSingle().Which["age"].Should().Be(40);

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("age", FilterOperator.LessThan, 30)
        }))).Should().ContainSingle().Which["age"].Should().Be(20);
    }

    [Fact]
    public void ApplyRowFilters_LessThanWithNonComparableOperands_DropsRowWithoutThrowing()
    {
        // The greaterThan counterpart is already covered; lessThan shares the comparison
        // helper but not the call site, and a raised exception would abort the whole
        // result pass rather than dropping one row (spec section 7).
        var policy = Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("age", FilterOperator.LessThan, 30)
        }));

        EnforcementEngine.ApplyRowFilters(Rows(new Dictionary<string, object?>() { ["age"] = "notanumber" }), policy)
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_ComparisonAgainstNullOrBoolean_IsNotOrdered()
    {
        // null and booleans have no ordering, so an ordered comparison is a non-match
        // rather than an exception or an accidental pass.
        foreach (var value in new object?[] { null, true })
        {
            EnforcementEngine.ApplyRowFilters(
                Rows(new Dictionary<string, object?>() { ["v"] = value }),
                Policy(new ObjectRules(RowFilters: new[]
                {
                    new RowFilter("v", FilterOperator.GreaterThan, 1)
                })))
                .Should().BeEmpty();
        }

        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["v"] = 5 }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("v", FilterOperator.GreaterThan, Value: true)
            })))
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_ComparableSameTypeNonNumeric_IsOrdered()
    {
        // Strings are IComparable and same-typed, so they order; this is the only path
        // that reaches the CompareTo branch for a non-numeric type.
        var rows = Rows(
            new Dictionary<string, object?> { ["name"] = "alpha" },
            new Dictionary<string, object?> { ["name"] = "zulu" });

        EnforcementEngine.ApplyRowFilters(rows, Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("name", FilterOperator.GreaterThan, "m")
        }))).Should().ContainSingle().Which["name"].Should().Be("zulu");
    }

    [Fact]
    public void ApplyRowFilters_EqualsDoesNotConflateBooleansWithNumbers()
    {
        // Spec section 7: 1 != true. Both directions, because the guard is symmetric and
        // a one-sided check would let the other orientation through.
        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["flag"] = 1 }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("flag", FilterOperator.Equals, true)
            })))
            .Should().BeEmpty();

        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["flag"] = true }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("flag", FilterOperator.Equals, 1)
            })))
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_EqualsAcrossNumericTypes_Matches()
    {
        // A DB driver yields long, a scenario file yields int, a JSON body yields double.
        // The same policy must behave identically across all three.
        foreach (var rowValue in new object[] { 30, 30L, 30.0, (decimal)30 })
        {
            EnforcementEngine.ApplyRowFilters(
                Rows(new Dictionary<string, object?>() { ["age"] = rowValue }),
                Policy(new ObjectRules(RowFilters: new[]
                {
                    new RowFilter("age", FilterOperator.Equals, 30)
                })))
                .Should().HaveCount(1, $"row value {rowValue} ({rowValue.GetType().Name}) equals 30");
        }
    }

    [Fact]
    public void ApplyRowFilters_EqualsBothNull_Matches()
    {
        // A present-but-null field compared against a null filter value matches; this is
        // distinct from the field being absent, which fails closed.
        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["v"] = null }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("v", FilterOperator.Equals, Value: null)
            })))
            .Should().HaveCount(1);
    }

    [Fact]
    public void ApplyRowFilters_EqualsNullAgainstNonNull_DoesNotMatch()
    {
        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["v"] = null }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("v", FilterOperator.Equals, "x")
            })))
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_NumberComparedToNonNumericString_DoesNotMatch()
    {
        // "30" and 30 are different values on the equals path: coercing them would make
        // a policy's type discipline depend on the driver that produced the row.
        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["age"] = 30 }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("age", FilterOperator.Equals, "thirty")
            })))
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyRowFilters_JsonElementValues_AreUnwrappedForComparison()
    {
        // A raw HTTP body yields JsonElement values. Each JsonValueKind must normalize to
        // the primitive the filter compares against, or a policy stops matching purely
        // because the row came off a socket instead of a driver.
        var doc = JsonDocument.Parse(
            """{"s":"us-east","n":30,"big":1.5,"t":true,"f":false,"nul":null,"obj":{"k":1}}""");
        var root = doc.RootElement;

        AssertKeeps("s", root.GetProperty("s"), FilterOperator.Equals, "us-east");
        AssertKeeps("n", root.GetProperty("n"), FilterOperator.Equals, 30);
        AssertKeeps("big", root.GetProperty("big"), FilterOperator.GreaterThan, 1);
        AssertKeeps("t", root.GetProperty("t"), FilterOperator.Equals, true);
        AssertKeeps("f", root.GetProperty("f"), FilterOperator.Equals, false);
        AssertKeeps("nul", root.GetProperty("nul"), FilterOperator.Equals, null);

        // A JsonElement object has no primitive form; it falls back to its text, which
        // still compares deterministically rather than throwing.
        AssertKeeps("obj", root.GetProperty("obj"), FilterOperator.Equals, """{"k":1}""");

        static void AssertKeeps(string field, JsonElement value, FilterOperator op, object? expected)
        {
            EnforcementEngine.ApplyRowFilters(
                Rows(new Dictionary<string, object?>() { [field] = value }),
                Policy(new ObjectRules(RowFilters: new[] { new RowFilter(field, op, expected) })))
                .Should().HaveCount(1, $"JsonElement {field} normalizes for comparison");
        }
    }

    [Fact]
    public void ApplyRowFilters_FieldReferenceMatchesQualifiedAndBareKeys()
    {
        // Spec section 4: a rule "patients.region" must reach a bare "region" key and a
        // rule "region" must reach a qualified "patients.region" key.
        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["region"] = "eu-west" }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("patients.region", FilterOperator.Equals, "eu-west")
            })))
            .Should().HaveCount(1);

        EnforcementEngine.ApplyRowFilters(
            Rows(new Dictionary<string, object?>() { ["patients.region"] = "eu-west" }),
            Policy(new ObjectRules(RowFilters: new[]
            {
                new RowFilter("region", FilterOperator.Equals, "eu-west")
            })))
            .Should().HaveCount(1);
    }

    [Fact]
    public void ApplyRowFilters_MultipleFiltersAndTogether()
    {
        // Most-restrictive-wins: a row must satisfy every filter. A row passing only one
        // is dropped, which is what distinguishes AND from OR.
        var policy = Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Equals, "us-east"),
            new RowFilter("status", FilterOperator.Equals, "active")
        }));
        var rows = Rows(
            new Dictionary<string, object?> { ["region"] = "us-east", ["status"] = "active" },
            new Dictionary<string, object?> { ["region"] = "us-east", ["status"] = "deleted" });

        EnforcementEngine.ApplyRowFilters(rows, policy)
            .Should().ContainSingle().Which["status"].Should().Be("active");
    }

    // -- Result shapes (spec section 5) --

    [Fact]
    public void ClassifyResultShape_ReadOnlyDictionary_IsARecord()
    {
        IReadOnlyDictionary<string, object?> record =
            new Dictionary<string, object?> { ["a"] = 1 };

        EnforcementEngine.ClassifyResultShape(record).Should().Be(ResultShape.Record);
    }

    [Fact]
    public void ApplyResultPipeline_ReadOnlyDictionary_IsEnforcedAsARecord()
    {
        // A genuine ReadOnlyDictionary, not a Dictionary typed as IReadOnlyDictionary: the
        // latter satisfies the `is Dictionary` check first and never reaches the read-only
        // conversion. A tool handing back an immutable view of its rows is an ordinary
        // shape and must still be masked.
        var record = new System.Collections.ObjectModel.ReadOnlyDictionary<string, object?>(
            new Dictionary<string, object?> { ["ssn"] = "111-22-3333", ["name"] = "Alice" });
        var policy = Policy(new ObjectRules(FieldRules: new FieldRules(
            MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) })));

        EnforcementEngine.ClassifyResultShape(record).Should().Be(ResultShape.Record);

        var result = EnforcementEngine.ApplyResultPipeline(record, policy);

        result.Should().BeOfType<Dictionary<string, object?>>()
            .Which["ssn"].Should().Be("[REDACTED]");
        ((Dictionary<string, object?>)result!)["name"].Should().Be("Alice");
    }

    [Fact]
    public void ClassifyResultShape_EmptyObjectList_IsARecordList()
    {
        // Vacuously "all items are records", and an empty result set must stay
        // enforceable rather than being denied as an unknown shape.
        EnforcementEngine.ClassifyResultShape(new List<object?>())
            .Should().Be(ResultShape.RecordList);
    }

    [Fact]
    public void ClassifyResultShape_MixedList_IsUnenforceable()
    {
        var mixed = new List<object?> { new Dictionary<string, object?>(), "scalar" };

        EnforcementEngine.ClassifyResultShape(mixed).Should().Be(ResultShape.Unenforceable);
    }

    [Fact]
    public void ApplyResultPipeline_SingleRecordDroppedByFilters_ReturnsNullNotAnEmptyRecord()
    {
        // Returning {} would imply the row existed but had no fields; null says the
        // policy excluded it.
        var policy = Policy(new ObjectRules(RowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Equals, "us-east")
        }));

        EnforcementEngine.ApplyResultPipeline(
            new Dictionary<string, object?> { ["region"] = "eu-west" }, policy)
            .Should().BeNull();
    }

    [Fact]
    public void DescribeResultShape_NamesEachObservedShape()
    {
        // The denial message must name the shape, or an integrator cannot tell which of
        // their tools is returning something unenforceable (spec section 5).
        EnforcementEngine.DescribeResultShape(null).Should().Be("null");
        EnforcementEngine.DescribeResultShape("s").Should().Contain("scalar");
        EnforcementEngine.DescribeResultShape(42).Should().Contain("scalar");
        EnforcementEngine.DescribeResultShape(true).Should().Contain("scalar");
        EnforcementEngine.DescribeResultShape(1.5m).Should().Contain("scalar");

        EnforcementEngine.DescribeResultShape(
            JsonDocument.Parse("""{"a":1}""").RootElement)
            .Should().Be("JsonElement (Object)");

        EnforcementEngine.DescribeResultShape(LazyRows())
            .Should().Contain("unmaterialized sequence");

        EnforcementEngine.DescribeResultShape(new List<object?> { 1, "two" })
            .Should().Contain("not records").And.Contain("Int32").And.Contain("String");

        EnforcementEngine.DescribeResultShape(
            new List<object?> { new Dictionary<string, object?>() })
            .Should().Contain("list of records");

        EnforcementEngine.DescribeResultShape(new object())
            .Should().Contain("not a record or list of records");
    }

    [Fact]
    public void DescribeResultShape_ListContainingNull_NamesNullAsTheOffender()
    {
        EnforcementEngine.DescribeResultShape(new List<object?> { null })
            .Should().Contain("null").And.Contain("not records");
    }

    // -- Masking (spec section 6) --

    [Fact]
    public void ApplyMask_NullValue_IsHandledByEveryMaskType()
    {
        // A null column must not throw, and must not leak "null" as a value.
        EnforcementEngine.ApplyMask(null, new MaskingRule("f", MaskType.Null)).Should().BeNull();
        EnforcementEngine.ApplyMask(null, new MaskingRule("f", MaskType.Redact)).Should().Be("[REDACTED]");
        EnforcementEngine.ApplyMask(null, new MaskingRule("f", MaskType.Full)).Should().Be("");
        EnforcementEngine.ApplyMask(null, new MaskingRule("f", MaskType.Partial)).Should().Be("");

        // The hash of the empty string: stable, and not the literal value.
        EnforcementEngine.ApplyMask(null, new MaskingRule("f", MaskType.Hash))
            .Should().BeOfType<string>().Which.Should().HaveLength(16);
    }

    [Fact]
    public void ApplyMask_FullMaskHonoursCustomMaskChar()
    {
        EnforcementEngine.ApplyMask("abcd",
            new MaskingRule("f", MaskType.Full, new MaskingParameters(MaskChar: '#')))
            .Should().Be("####");
    }

    [Fact]
    public void ApplyMask_FullMaskLeaksOnlyLength()
    {
        // Spec section 6 ranks `full` as disclosing the length and nothing else.
        EnforcementEngine.ApplyMask("111-22-3333", new MaskingRule("ssn", MaskType.Full))
            .Should().Be("***********");
    }

    [Fact]
    public void ApplyMask_PartialShowsOnlyTheRequestedEdges()
    {
        EnforcementEngine.ApplyMask("123456789",
            new MaskingRule("f", MaskType.Partial, new MaskingParameters(ShowFirst: 2, ShowLast: 3)))
            .Should().Be("12****789");

        // showFirst alone and showLast alone are separate branches.
        EnforcementEngine.ApplyMask("123456789",
            new MaskingRule("f", MaskType.Partial, new MaskingParameters(ShowFirst: 3)))
            .Should().Be("123******");
        EnforcementEngine.ApplyMask("123456789",
            new MaskingRule("f", MaskType.Partial, new MaskingParameters(ShowLast: 4)))
            .Should().Be("*****6789");
    }

    [Fact]
    public void ApplyMask_PartialWithNegativeCounts_DegradesToFullMask()
    {
        // A negative count would index out of range or reveal the value; it degrades to
        // a full mask rather than throwing or disclosing (spec section 6).
        foreach (var parameters in new[]
                 {
                     new MaskingParameters(ShowFirst: -1, ShowLast: 2),
                     new MaskingParameters(ShowFirst: 2, ShowLast: -1)
                 })
        {
            EnforcementEngine.ApplyMask("123456789", new MaskingRule("f", MaskType.Partial, parameters))
                .Should().Be("*********");
        }
    }

    [Fact]
    public void ApplyMask_PartialWithNoParameters_MasksEverything()
    {
        // Absent parameters mean showFirst/showLast of zero, so nothing is revealed.
        EnforcementEngine.ApplyMask("123456789", new MaskingRule("f", MaskType.Partial))
            .Should().Be("*********");
    }

    [Fact]
    public void ApplyMask_HashIsStableAcrossCallsAndDiffersByValue()
    {
        // Spec section 11: hash is a pseudonymous join key, so stability is the point —
        // and a non-injective implementation would silently break that property.
        var a1 = EnforcementEngine.ApplyMask("111-22-3333", new MaskingRule("ssn", MaskType.Hash));
        var a2 = EnforcementEngine.ApplyMask("111-22-3333", new MaskingRule("ssn", MaskType.Hash));
        var b = EnforcementEngine.ApplyMask("222-33-4444", new MaskingRule("ssn", MaskType.Hash));

        a1.Should().Be(a2);
        a1.Should().NotBe(b);
        a1.Should().BeOfType<string>().Which.Should().HaveLength(16).And.MatchRegex("^[0-9a-f]{16}$");
    }

    // -- Hash algorithm: the cross-language join key (spec section 6) --
    //
    // The `algorithm` parameter used to be ignored here (SHA-256 was hardcoded), so a
    // policy asking for sha512 got a SHA-256 digest -- a different pseudonym than
    // TypeScript computed for the same value, so every cross-service join on the masked
    // column silently failed while both sides looked correct in isolation.

    /// <summary>
    /// Masked value of "123-45-6789" per algorithm: known-answers shared with the Python
    /// and TypeScript suites.
    /// </summary>
    /// <remarks>
    /// The same literals appear in test_enforcement_branches.py and
    /// enforcement-branches.test.ts, so a change that makes one SDK disagree fails in that
    /// SDK's own suite rather than only in a cross-language test nobody runs.
    /// </remarks>
    public static TheoryData<string, string> HashKnownAnswers() => new()
    {
        { "sha256", "01a54629efb95228" },
        { "sha512", "fbe47783b1d59d46" },
        { "blake2b", "ddefd0f544edbef0" }
    };

    private static object? HashMask(object? value, string? algorithm) =>
        EnforcementEngine.ApplyMask(
            value,
            new MaskingRule("ssn", MaskType.Hash,
                algorithm is null ? null : new MaskingParameters(Algorithm: algorithm)));

    [Theory]
    [MemberData(nameof(HashKnownAnswers))]
    public void ApplyMask_HashMatchesTheCrossSdkKnownAnswer(string algorithm, string expected)
    {
        HashMask("123-45-6789", algorithm).Should().Be(expected);
    }

    [Fact]
    public void ApplyMask_HashDefaultsToSha256WhenAlgorithmIsAbsent()
    {
        HashMask("123-45-6789", null).Should().Be("01a54629efb95228");
        // An explicitly null Algorithm on a present parameters object takes the same path.
        EnforcementEngine.ApplyMask("123-45-6789",
            new MaskingRule("ssn", MaskType.Hash, new MaskingParameters(MaskChar: '#')))
            .Should().Be("01a54629efb95228");
    }

    [Fact]
    public void ApplyMask_EachAlgorithmYieldsADistinctDigest()
    {
        // Guards the defect directly: the parameter must actually be read. Ignoring it
        // produced three identical digests, which is what the known-answer table would
        // look like if `algorithm` were dropped again and the expectations regenerated
        // from the broken implementation.
        new[] { "sha256", "sha512", "blake2b" }
            .Select(a => HashMask("123-45-6789", a))
            .Distinct()
            .Should().HaveCount(3);
    }

    [Theory]
    [InlineData("md5")]        // available to the runtime, but not permitted by the schema
    [InlineData("sha1")]
    [InlineData("blake2b512")] // Node's spelling; not the schema value
    [InlineData("SHA256")]     // wrong case
    [InlineData("sha-256")]
    [InlineData("not-a-real-algorithm")]
    [InlineData("")]
    [InlineData(" sha256")]
    public void ApplyMask_AnUnpermittedAlgorithm_RedactsRatherThanLeaking(string algorithm)
    {
        // Fails closed as `redact` (spec section 6): it must not throw (that would abort
        // the whole result pass), must not return the original, and must not silently
        // substitute sha256 -- a substituted digest looks like a valid pseudonym while
        // failing to join. md5 and sha1 are rejected despite being available to the
        // runtime; a general algorithm lookup would have accepted both.
        HashMask("123-45-6789", algorithm).Should().Be("[REDACTED]");
    }

    [Fact]
    public void ApplyMask_HashOfANonStringCoercesBeforeHashing()
    {
        foreach (var algorithm in new[] { "sha256", "sha512", "blake2b" })
        {
            HashMask(12345, algorithm)
                .Should().BeOfType<string>()
                .Which.Should().MatchRegex("^[0-9a-f]{16}$");
        }
    }

    // -- BLAKE2b-512 (RFC 7693) --
    //
    // System.Security.Cryptography does not provide BLAKE2b (it has SHA-3 and SHAKE, but
    // not BLAKE2) and Tolap.Core ships zero runtime dependencies, so it is implemented
    // in-tree. These vectors are the reason that is safe: a hand-rolled hash that is
    // subtly wrong would produce stable, plausible-looking 16-hex pseudonyms that simply
    // never match the other SDKs. Exercised through the public ApplyMask surface, which is
    // the only way the digest is ever reached in production.

    [Theory]
    // The RFC 7693 appendix-A vector ("abc") and the empty input, truncated to the 16
    // hex chars the mask emits.
    [InlineData("abc", "ba80a53f981c4d0d")]
    [InlineData("", "786a02f742015903")]
    public void ApplyMask_Blake2bMatchesTheRfc7693Vectors(string input, string expectedPrefix)
    {
        HashMask(input, "blake2b").Should().Be(expectedPrefix);
    }

    [Theory]
    // Exact digest prefixes for single-character repeats, produced by Node's blake2b512
    // and confirmed byte-identical under Python's hashlib.blake2b(digest_size=64). These
    // pin the multi-block path across runtimes rather than merely against itself.
    //
    // 128 is the case a naive "compress every full block, then finalize" loop gets wrong:
    // the trailing block of an exact multiple of the block size must be the FINAL one,
    // not compressed early with an empty block finalized after it. 129 and 300 cover the
    // multi-block path either side of it.
    [InlineData('x', 128, "082b91ea2e15d155")]
    [InlineData('y', 129, "b5a49bd30a88f4b0")]
    [InlineData('z', 300, "b06b62e122549946")]
    public void ApplyMask_Blake2bAgreesWithTheOtherSdksAtTheBlockBoundary(
        char fill, int length, string expectedPrefix)
    {
        HashMask(new string(fill, length), "blake2b").Should().Be(expectedPrefix);
    }

    [Fact]
    public void ApplyMask_NonStringValues_AreStringifiedBeforeMasking()
    {
        // A numeric SSN or a DateTime must still be masked; masking must not silently
        // pass through anything that is not already a string.
        EnforcementEngine.ApplyMask(12345, new MaskingRule("f", MaskType.Full)).Should().Be("*****");
        EnforcementEngine.ApplyMask(true, new MaskingRule("f", MaskType.Full)).Should().Be("****");
    }

    [Fact]
    public void ApplyFieldMasking_NullMaskedFieldsAndEmptyArray_BothLeaveTheRecordIntact()
    {
        var record = new Dictionary<string, object?> { ["ssn"] = "111-22-3333" };

        EnforcementEngine.ApplyFieldMasking(record,
            Policy(new ObjectRules(FieldRules: new FieldRules(MaskedFields: null))))
            ["ssn"].Should().Be("111-22-3333");

        EnforcementEngine.ApplyFieldMasking(record,
            Policy(new ObjectRules(FieldRules: new FieldRules(MaskedFields: Array.Empty<MaskingRule>()))))
            ["ssn"].Should().Be("111-22-3333");
    }

    [Fact]
    public void ApplyFieldMasking_DoesNotMutateTheCallersRecord()
    {
        // The caller may hold the original for its own logging; masking returns a copy.
        var original = new Dictionary<string, object?> { ["ssn"] = "111-22-3333" };
        var policy = Policy(new ObjectRules(FieldRules: new FieldRules(
            MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) })));

        var masked = EnforcementEngine.ApplyFieldMasking(original, policy);

        masked["ssn"].Should().Be("[REDACTED]");
        original["ssn"].Should().Be("111-22-3333");
    }

    [Fact]
    public void ApplyFieldMasking_RecursesThroughListsAndNestedObjectArrays()
    {
        // Nested records reached via List<object?>, object[], and a typed list of records
        // are three separate clone paths; a rule must reach the leaf through all of them.
        var policy = Policy(new ObjectRules(FieldRules: new FieldRules(
            MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) })));

        var record = new Dictionary<string, object?>
        {
            ["viaList"] = new List<object?> { new Dictionary<string, object?> { ["ssn"] = "a" } },
            ["viaArray"] = new object[] { new Dictionary<string, object?> { ["ssn"] = "b" } },
            ["viaTypedList"] = new List<Dictionary<string, object?>>
            {
                new Dictionary<string, object?> { ["ssn"] = "c" }
            },
            ["scalar"] = "left alone"
        };

        var masked = EnforcementEngine.ApplyFieldMasking(record, policy);

        Leaf(masked["viaList"]).Should().Be("[REDACTED]");
        Leaf(masked["viaArray"]).Should().Be("[REDACTED]");
        Leaf(masked["viaTypedList"]).Should().Be("[REDACTED]");
        masked["scalar"].Should().Be("left alone");

        static object? Leaf(object? node) =>
            ((Dictionary<string, object?>)((List<object?>)node!)[0]!)["ssn"];
    }

    [Fact]
    public void StripHiddenFields_NullAndEmptyHiddenList_BothLeaveTheRecordIntact()
    {
        var record = new Dictionary<string, object?> { ["ssn"] = "x" };

        EnforcementEngine.StripHiddenFields(record,
            Policy(new ObjectRules(FieldRules: new FieldRules(HiddenFields: null))))
            .Should().ContainKey("ssn");

        EnforcementEngine.StripHiddenFields(record,
            Policy(new ObjectRules(FieldRules: new FieldRules(HiddenFields: Array.Empty<string>()))))
            .Should().ContainKey("ssn");
    }

    [Fact]
    public void StripHiddenFields_RecordList_ReturnsInputUnchangedWhenNoRulesApply()
    {
        IReadOnlyList<Dictionary<string, object?>> rows = Rows(new Dictionary<string, object?>() { ["ssn"] = "x" });

        EnforcementEngine.StripHiddenFields(rows, Policy(new ObjectRules(FieldRules: null)))
            .Should().BeSameAs(rows);
    }

    [Fact]
    public void StripHiddenFieldsFromTree_NullAndEmptyRules_ReturnTheNodeUnchanged()
    {
        var node = new Dictionary<string, object?> { ["ssn"] = "x" };

        EnforcementEngine.StripHiddenFieldsFromTree(node, Policy(new ObjectRules(FieldRules: null)))
            .Should().BeSameAs(node);
        EnforcementEngine.StripHiddenFieldsFromTree(node,
            Policy(new ObjectRules(FieldRules: new FieldRules(HiddenFields: Array.Empty<string>()))))
            .Should().BeSameAs(node);
    }

    [Fact]
    public void StripHiddenFieldsFromTree_ScalarAndListRoots_AreWalked()
    {
        var policy = Policy(new ObjectRules(FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        // A scalar root has no keys to remove and must pass through rather than throw.
        EnforcementEngine.StripHiddenFieldsFromTree("scalar", policy).Should().Be("scalar");
        EnforcementEngine.StripHiddenFieldsFromTree(null, policy).Should().BeNull();

        var list = new List<object?> { new Dictionary<string, object?> { ["ssn"] = "x", ["id"] = 1 } };
        var stripped = (List<object?>)EnforcementEngine.StripHiddenFieldsFromTree(list, policy)!;
        ((Dictionary<string, object?>)stripped[0]!).Should().NotContainKey("ssn").And.ContainKey("id");
    }

    [Fact]
    public void ProjectAllowedFields_RecordList_ReturnsInputUnchangedWhenAllowListIsNull()
    {
        IReadOnlyList<Dictionary<string, object?>> rows = Rows(new Dictionary<string, object?>() { ["a"] = 1 });

        EnforcementEngine.ProjectAllowedFields(rows,
            Policy(new ObjectRules(FieldRules: new FieldRules(AllowedFields: null))))
            .Should().BeSameAs(rows);
    }

    [Fact]
    public void ProjectAllowedFields_RecordList_EmptyAllowListStripsEveryField()
    {
        IReadOnlyList<Dictionary<string, object?>> rows = Rows(new Dictionary<string, object?>() { ["a"] = 1, ["b"] = 2 });

        EnforcementEngine.ProjectAllowedFields(rows,
            Policy(new ObjectRules(FieldRules: new FieldRules(AllowedFields: Array.Empty<string>()))))
            .Should().ContainSingle().Which.Should().BeEmpty();
    }

    [Fact]
    public void ApplyResultLimit_NullLimit_ReturnsEveryResult()
    {
        IReadOnlyList<string> results = new List<string> { "a", "b" };

        EnforcementEngine.ApplyResultLimit(results, Policy(objectRules: null, limits: null))
            .Should().BeSameAs(results);
    }

    [Fact]
    public void ApplyResultLimit_ZeroLimit_ReturnsNothing()
    {
        IReadOnlyList<string> results = new List<string> { "a", "b" };

        EnforcementEngine.ApplyResultLimit(results, Policy(null, new PolicyLimits(MaxResults: 0)))
            .Should().BeEmpty();
    }

    [Fact]
    public void ApplyResultLimit_ExactlyAtLimit_ReturnsEveryResult()
    {
        // The boundary is <=, so a result set exactly at the limit is not truncated.
        IReadOnlyList<string> results = new List<string> { "a", "b" };

        EnforcementEngine.ApplyResultLimit(results, Policy(null, new PolicyLimits(MaxResults: 2)))
            .Should().HaveCount(2);
    }

    // -- Field-name matching (spec section 4) --

    [Fact]
    public void GlobMatch_PathologicalPatternIsBoundedAndDeniesAccess()
    {
        // Object/field/endpoint globs run under the same bounded timeout as row-filter
        // regexes (spec sections 7 and 11). A pattern with many wildcards expands to nested
        // quantifiers, and the timeout must make it a non-match rather than a stall — which
        // for an allow-list means the object is denied, the fail-closed outcome.
        var pathological = string.Concat(Enumerable.Repeat("*a", 20)) + "*b";
        var policy = Policy(new ObjectRules(AllowedObjects: new[] { pathological }));

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var result = EnforcementEngine.ValidateAccess(new string('a', 40), policy);
        stopwatch.Stop();

        result.Allowed.Should().BeFalse("a regex timeout is a non-match, so the allow-list denies");
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void GlobMatch_RegexMetacharactersInAPatternAreLiteral()
    {
        // The pattern is escaped before '*' is expanded, so regex syntax in a policy is
        // matched literally rather than compiled. This is also why an invalid-regex path
        // cannot arise from a glob: every escaped pattern is a valid regex.
        var policy = Policy(new ObjectRules(AllowedObjects: new[] { "patients[1]" }));

        EnforcementEngine.ValidateAccess("patients[1]", policy).Allowed.Should().BeTrue();
        EnforcementEngine.ValidateAccess("patients1", policy).Allowed.Should().BeFalse();
    }

    [Fact]
    public void FieldNameMatches_CoversBothDirectionsCaseAndGlobs()
    {
        EnforcementEngine.FieldNameMatches("patients.ssn", "ssn").Should().BeTrue();
        EnforcementEngine.FieldNameMatches("ssn", "patients.ssn").Should().BeTrue();
        EnforcementEngine.FieldNameMatches("SSN", "ssn").Should().BeTrue();
        EnforcementEngine.FieldNameMatches("patients.*", "ssn").Should().BeTrue();
        EnforcementEngine.FieldNameMatches("schema.patients.ssn", "ssn").Should().BeTrue();

        EnforcementEngine.FieldNameMatches("ssn", "name").Should().BeFalse();
        EnforcementEngine.FieldNameMatches("ssn_suffix", "ssn").Should().BeFalse();
    }

    [Fact]
    public void ApplyRecordPipeline_RunsEveryStepInTheCanonicalOrder()
    {
        // One policy exercising all six steps at once: the row filter drops a row, the
        // tag rule drops another, the hidden field is removed, the allow-list projects,
        // masking applies, and the limit truncates. Asserted together because the
        // *order* is the contract (spec section 4) -- a field that is both hidden and
        // masked must be removed, not returned masked.
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(
                AllowedFields: new[] { "id", "ssn", "email", "tags", "status", "region" },
                HiddenFields: new[] { "email" },
                MaskedFields: new[]
                {
                    new MaskingRule("ssn", MaskType.Redact),
                    new MaskingRule("email", MaskType.Partial)
                }),
            RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
            TagRules: new TagRules(DeniedTags: new[] { "confidential" })),
            new PolicyLimits(MaxResults: 2));

        var rows = Rows(
            new Dictionary<string, object?> { ["id"] = 1, ["ssn"] = "a", ["email"] = "a@x", ["status"] = "active", ["tags"] = new[] { "public" }, ["secret"] = "leak" },
            new Dictionary<string, object?> { ["id"] = 2, ["ssn"] = "b", ["email"] = "b@x", ["status"] = "deleted", ["tags"] = new[] { "public" } },
            new Dictionary<string, object?> { ["id"] = 3, ["ssn"] = "c", ["email"] = "c@x", ["status"] = "active", ["tags"] = new[] { "confidential" } },
            new Dictionary<string, object?> { ["id"] = 4, ["ssn"] = "d", ["email"] = "d@x", ["status"] = "active", ["tags"] = new[] { "public" } },
            new Dictionary<string, object?> { ["id"] = 5, ["ssn"] = "e", ["email"] = "e@x", ["status"] = "active", ["tags"] = new[] { "public" } });

        var result = EnforcementEngine.ApplyRecordPipeline(rows, policy);

        // ids 2 (row filter) and 3 (tag filter) dropped; 1, 4, 5 survive and the limit
        // truncates to the first two.
        result.Should().HaveCount(2);
        result.Select(r => r["id"]).Should().Equal(1, 4);

        // Hidden beats masked: email is gone rather than partially masked.
        result[0].Should().NotContainKey("email");
        // The allow-list dropped an undeclared column the tool volunteered.
        result[0].Should().NotContainKey("secret");
        result[0]["ssn"].Should().Be("[REDACTED]");
    }

    // -- Helpers --

    private static EffectivePolicy Policy(
        ObjectRules? objectRules,
        PolicyLimits? limits = null,
        bool readOnly = true) =>
        new(Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "s",
            ResolvedAt: null,
            ExpiresAt: null,
            SourceProfiles: Array.Empty<string>(),
            Permissions: new PolicyPermissions(CanQuery: true, ReadOnly: readOnly),
            ObjectRules: objectRules,
            Limits: limits);

    /// <summary>
    /// Builds a mutable record list from record literals.
    /// </summary>
    private static List<Dictionary<string, object?>> Rows(
        params Dictionary<string, object?>[] rows) => rows.ToList();

    private static IEnumerable<Dictionary<string, object?>> LazyRows()
    {
        yield return new Dictionary<string, object?> { ["ssn"] = "x" };
    }
}
