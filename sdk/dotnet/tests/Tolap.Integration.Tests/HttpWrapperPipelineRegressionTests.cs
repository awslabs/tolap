using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;
using Xunit;

namespace Tolap.Integration.Tests;

/// <summary>
/// Regression tests for the HTTP wrapper's post-execution pipeline, over a real socket.
/// </summary>
/// <remarks>
/// <para>
/// Two defects are pinned here, both of which made a policy that filtered correctly
/// through the MCP/database wrappers a silent no-op over HTTP:
/// </para>
/// <list type="number">
///   <item><description>
///     Steps 1 and 2 of the canonical pipeline (row filters, tag filters) were never
///     applied to an HTTP response body, so <c>rowFilters</c>, <c>deniedTags</c> and
///     <c>allowedTags</c> did nothing (spec section 4).
///   </description></item>
///   <item><description>
///     Masking walked a literal dotted path from the body root instead of using the
///     shared field-name matcher, so a bare rule such as <c>ssn</c> never reached a
///     nested <c>demographics.ssn</c> key and matching was case-sensitive — while
///     hidden-field removal, which already delegated to the core, matched correctly
///     (spec section 4).
///   </description></item>
/// </list>
/// <para>
/// Each test asserts against the live test API rather than a transport mock, because a
/// mock's fabricated body cannot demonstrate that a real nested document off a socket is
/// reached.
/// </para>
/// </remarks>
[Collection(TestApiCollection.Name)]
public sealed class HttpWrapperPipelineRegressionTests
{
    private const string SigningKey = "pipeline-regression-key";

    private readonly TestApiFixture _api;

    public HttpWrapperPipelineRegressionTests(TestApiFixture api) => _api = api;

    // -- Spec section 4 step 1: row filters --

    [Fact]
    public async Task RowFilters_ExcludeRecordsFromAnHttpResponseBody()
    {
        // /patients returns one record with status "deleted". A policy excluding it must
        // drop that record; before the fix every record came back.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("status", FilterOperator.NotEquals, "deleted") },
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().NotBeEmpty();
        records.Should().OnlyContain(r => Status(r) != "deleted");
        records.Should().NotContain(r => Name(r) == "Dmitri Volkov");
    }

    [Fact]
    public async Task RowFilters_DropRecordsMissingTheReferencedField()
    {
        // Spec section 7: a row lacking the referenced field is dropped, for every
        // operator including the negative ones. Record 5 has no `tags` key, and the
        // negative operator must not retain it.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("nonexistent_column", FilterOperator.NotEquals, "x") },
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().BeEmpty("no record carries the referenced field, so all fail closed");
    }

    [Fact]
    public async Task RowFilters_CompositeFiltersAndTogether()
    {
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            RowFilters: new[]
            {
                new RowFilter("status", FilterOperator.Equals, "active"),
                new RowFilter("region", FilterOperator.Equals, "us-east")
            },
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().ContainSingle().Which.Should().Contain(
            new KeyValuePair<string, object?>("full_name", "Alice Nguyen"));
    }

    [Fact]
    public async Task RowFilters_ApplyToAnEnvelopeCollectionPath()
    {
        // The collection is under "items" here rather than "results", so the filter must
        // follow CollectionPath the way the limit and projection already do.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "deleted") },
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients/envelope", "items");

        records.Should().ContainSingle().Which.Should().Contain(
            new KeyValuePair<string, object?>("full_name", "Dmitri Volkov"));
    }

    // -- Spec section 4 step 2: tag filters --

    [Fact]
    public async Task DeniedTags_ExcludeRecordsFromAnHttpResponseBody()
    {
        // Chloe Adeyemi carries the "confidential" tag and must not be disclosed.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            TagRules: new TagRules(DeniedTags: new[] { "confidential" }),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().NotBeEmpty();
        records.Should().NotContain(r => Name(r) == "Chloe Adeyemi");
        // A record with no tags key at all is kept under a denylist-only policy.
        records.Should().Contain(r => Name(r) == "Elena Rossi");
    }

    [Fact]
    public async Task AllowedTags_KeepOnlyMatchingRecordsAndDropUntaggedOnes()
    {
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            TagRules: new TagRules(AllowedTags: new[] { "research" }),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().ContainSingle().Which.Should().Contain(
            new KeyValuePair<string, object?>("full_name", "Bruno Sato"));
    }

    [Fact]
    public async Task EmptyAllowedTags_DenyEveryRecord()
    {
        // Spec section 3: an empty allow-list is deny-everything. Before the fix this
        // returned every record — the most restrictive possible policy became the least.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            TagRules: new TagRules(AllowedTags: Array.Empty<string>()),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().BeEmpty();
    }

    [Fact]
    public async Task DeniedTagsTakePrecedenceOverAllowedTags()
    {
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            TagRules: new TagRules(
                AllowedTags: new[] { "public", "confidential" },
                DeniedTags: new[] { "confidential" }),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().NotBeEmpty();
        records.Should().NotContain(r => Name(r) == "Chloe Adeyemi");
    }

    [Fact]
    public async Task NoRowOrTagRules_LeaveEveryRecordInPlace()
    {
        // The other side of both conditionals: a policy that filters nothing must not
        // drop anything.
        if (!_api.Ready)
        {
            return;
        }
        var records = await Records(Policy(new ObjectRules(EndpointRules: AllowPatients())),
            "/patients", "results");

        records.Should().HaveCount(5);
    }

    // -- Pipeline ordering (spec section 4) --

    [Fact]
    public async Task RowAndTagFiltersRunBeforeTheResultLimit()
    {
        // The limit is last so that filtering never yields fewer rows than maxResults when
        // more qualifying rows exist. Filters drop 2 of 5, leaving 3, and the limit of 2
        // then truncates to 2 — not "take 2 first, then filter down to 1".
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(
            new ObjectRules(
                RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
                TagRules: new TagRules(DeniedTags: new[] { "confidential" }),
                EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 2));

        var records = await Records(policy, "/patients", "results");

        records.Should().HaveCount(2);
        records.Should().OnlyContain(r => Status(r) == "active");
    }

    [Fact]
    public async Task RowFiltersRunBeforeFieldsAreHiddenOrProjectedAway()
    {
        // A filter referencing a field the policy also hides must still work: filtering is
        // step 1 and hidden-field removal is step 3, so the field is present when the
        // filter reads it. Reversing the order would make the filter fail closed on every
        // row and return nothing.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "status" }),
            RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().HaveCount(4, "four records are active");
        records.Should().OnlyContain(r => !r.ContainsKey("status"));
    }

    [Fact]
    public async Task TagFiltersRunBeforeTheTagsFieldItselfIsProjectedAway()
    {
        // Same ordering point for tags: an allowedFields list omitting `tags` must not
        // stop the tag rule from working.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: new[] { "id", "full_name" }),
            TagRules: new TagRules(DeniedTags: new[] { "confidential" }),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().NotContain(r => Name(r) == "Chloe Adeyemi");
        records.Should().OnlyContain(r => !r.ContainsKey("tags"));
    }

    // -- Masking must use the shared field-name matcher --

    [Fact]
    public async Task BareMaskRuleReachesANestedKey()
    {
        // A rule `ssn` must reach demographics.ssn, exactly as the same rule does through
        // the MCP wrapper and as hidden-field removal already did here. Before the fix
        // masking walked a literal dotted path from the root, so a bare rule matched only
        // a top-level key and the nested SSN was returned in cleartext.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }),
            EndpointRules: AllowPatients()));

        var body = await Body(policy, "/patients/nested", "results");

        body.Should().NotContain("111-22-3333").And.NotContain("222-33-4444");
        body.Should().Contain("[REDACTED]");
    }

    [Fact]
    public async Task TableQualifiedMaskRuleReachesABareKey()
    {
        // Spec section 4 requires matching in both directions: a rule `patients.ssn` must
        // reach a bare `ssn` key.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(
                MaskedFields: new[] { new MaskingRule("patients.ssn", MaskType.Redact) }),
            EndpointRules: AllowPatients()));

        var body = await Body(policy, "/patients", "results");

        body.Should().NotContain("111-22-3333");
        body.Should().Contain("[REDACTED]");
    }

    [Fact]
    public async Task MaskRuleMatchingIsCaseInsensitive()
    {
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[] { new MaskingRule("SSN", MaskType.Redact) }),
            EndpointRules: AllowPatients()));

        var body = await Body(policy, "/patients", "results");

        body.Should().NotContain("111-22-3333");
    }

    [Fact]
    public async Task DottedPathMaskRuleStillWorks()
    {
        // The dotted-path form is how API responses were already being addressed, so the
        // matcher change must not regress it.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("results.demographics.contact.email", MaskType.Redact)
            }),
            EndpointRules: AllowPatients()));

        var body = await Body(policy, "/patients/nested", "results");

        body.Should().NotContain("alice@example.com");
        body.Should().Contain("555-0100", "a sibling the rule did not name survives");
    }

    [Fact]
    public async Task MaskingDoesNotTouchFieldsNoRuleNames()
    {
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().Contain(r => Name(r) == "Alice Nguyen");
        records.Should().OnlyContain(r => (string?)r["email"] != "[REDACTED]");
    }

    [Fact]
    public async Task MostRestrictiveOverlappingMaskRuleWins()
    {
        // Two rules matching the same key: the more restrictive must win (spec section 6),
        // which is the core matcher's behaviour rather than "last rule applied".
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("ssn", MaskType.Partial, new MaskingParameters(ShowLast: 4)),
                new MaskingRule("ssn", MaskType.Redact)
            }),
            EndpointRules: AllowPatients()));

        var records = await Records(policy, "/patients", "results");

        records.Should().OnlyContain(r => (string?)r["ssn"] == "[REDACTED]");
    }

    // -- The whole pipeline over one real response --

    [Fact]
    public async Task EveryPipelineStepAppliesToOneRealResponse()
    {
        // All six steps at once, so their composition is pinned and not just each in
        // isolation: filters drop records, tags drop another, the hidden field goes, the
        // allow-list projects, masking applies, and the limit truncates.
        if (!_api.Ready)
        {
            return;
        }
        var policy = Policy(
            new ObjectRules(
                FieldRules: new FieldRules(
                    AllowedFields: new[] { "id", "full_name", "ssn", "email", "region" },
                    HiddenFields: new[] { "email" },
                    MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }),
                RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
                TagRules: new TagRules(DeniedTags: new[] { "confidential" }),
                EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 2));

        var records = await Records(policy, "/patients", "results");

        records.Should().HaveCount(2);
        foreach (var record in records)
        {
            record.Should().NotContainKey("email", "hidden beats masked and beats the allow-list");
            record.Should().NotContainKey("status", "an undeclared field is projected away");
            record.Should().NotContainKey("tags");
            record["ssn"].Should().Be("[REDACTED]");
            record.Should().ContainKey("full_name");
        }
    }

    // -- Body shapes the live endpoints cannot produce --
    //
    // These use an in-process handler on purpose: the test API serves realistic shapes,
    // and a multi-level collection path, a bare top-level array and a heterogeneous array
    // are shapes a real API can return but this server does not. The socket-level paths are
    // already covered above; what is left to pin here is the tree-walking itself.

    [Fact]
    public async Task MultiLevelCollectionPath_IsWalkedForFiltersProjectionAndLimit()
    {
        // A two-segment path ("data.rows") exercises the intermediate-cursor loop that a
        // single-segment path skips entirely, in all three walkers.
        var policy = Policy(
            new ObjectRules(
                FieldRules: new FieldRules(AllowedFields: new[] { "id", "status" }),
                RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
                EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 2));

        var body = await Stubbed(policy, """
            {"data":{"rows":[
              {"id":1,"status":"active","secret":"a"},
              {"id":2,"status":"deleted","secret":"b"},
              {"id":3,"status":"active","secret":"c"},
              {"id":4,"status":"active","secret":"d"}]},
             "meta":{"page":1}}
            """, "data.rows");

        var rows = body.GetProperty("data").GetProperty("rows");
        rows.GetArrayLength().Should().Be(2, "one row filtered out, then the limit truncates");
        foreach (var row in rows.EnumerateArray())
        {
            row.GetProperty("status").GetString().Should().Be("active");
            row.TryGetProperty("secret", out _).Should().BeFalse();
        }
        body.GetProperty("meta").GetProperty("page").GetInt32().Should().Be(1);
    }

    [Fact]
    public async Task BareTopLevelArrayBody_IsFilteredProjectedAndLimited()
    {
        // Many APIs return a bare array rather than an envelope. With no CollectionPath the
        // body itself is the collection, which is a separate branch in each walker.
        var policy = Policy(
            new ObjectRules(
                FieldRules: new FieldRules(
                    AllowedFields: new[] { "id", "status" },
                    MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }),
                RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
                EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 2));

        var body = await Stubbed(policy, """
            [{"id":1,"status":"active","ssn":"111-22-3333"},
             {"id":2,"status":"deleted","ssn":"222-33-4444"},
             {"id":3,"status":"active","ssn":"333-44-5555"},
             {"id":4,"status":"active","ssn":"444-55-6666"}]
            """, collectionPath: null);

        body.ValueKind.Should().Be(System.Text.Json.JsonValueKind.Array);
        body.GetArrayLength().Should().Be(2);
        body.GetRawText().Should().NotContain("111-22-3333").And.NotContain("deleted");
    }

    [Fact]
    public async Task BareArrayShorterThanTheLimit_IsLeftAlone()
    {
        var policy = Policy(
            new ObjectRules(EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 10));

        var body = await Stubbed(policy, """[{"id":1},{"id":2}]""", collectionPath: null);

        body.GetArrayLength().Should().Be(2);
    }

    [Fact]
    public async Task HeterogeneousArray_KeepsNonRecordEntriesAndStillFiltersRecords()
    {
        // A rule cannot address a scalar, so a scalar must be preserved rather than dropped:
        // silently truncating entries a policy could not evaluate would corrupt the payload
        // rather than restrict it.
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
            EndpointRules: AllowPatients()));

        var body = await Stubbed(policy, """
            {"results":[{"id":1,"status":"active"},"a-scalar",{"id":2,"status":"deleted"},42]}
            """, "results");

        var raw = body.GetProperty("results").GetRawText();
        raw.Should().Contain("a-scalar").And.Contain("42");
        raw.Should().NotContain("deleted");
    }

    [Fact]
    public async Task ArrayOfNonRecordsOnly_IsLeftUntouched()
    {
        // No records to filter, so the collection passes through rather than being emptied.
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
            EndpointRules: AllowPatients()));

        var body = await Stubbed(policy, """{"results":["a","b","c"]}""", "results");

        body.GetProperty("results").GetArrayLength().Should().Be(3);
    }

    [Fact]
    public async Task CollectionPathPointingAtANonCollection_LeavesFiltersInert()
    {
        var policy = Policy(new ObjectRules(
            RowFilters: new[] { new RowFilter("status", FilterOperator.Equals, "active") },
            EndpointRules: AllowPatients()));

        var body = await Stubbed(policy, """{"results":{"id":1,"status":"deleted"}}""", "results");

        body.GetProperty("results").GetProperty("status").GetString().Should().Be("deleted",
            "a single object is not a collection, so the row filter has nothing to drop");
    }

    [Fact]
    public async Task ScalarAndBooleanAndFloatBodyValues_SurviveTheRoundTrip()
    {
        // The JSON-to-node conversion has a branch per JsonValueKind; a float, a bool and a
        // null must all round-trip rather than being coerced or dropped.
        var policy = Policy(new ObjectRules(EndpointRules: AllowPatients()));

        var body = await Stubbed(policy, """
            {"results":[{"id":1,"score":1.5,"active":true,"inactive":false,"missing":null}]}
            """, "results");

        var record = body.GetProperty("results")[0];
        record.GetProperty("score").GetDouble().Should().Be(1.5);
        record.GetProperty("active").GetBoolean().Should().BeTrue();
        record.GetProperty("inactive").GetBoolean().Should().BeFalse();
        record.GetProperty("missing").ValueKind.Should().Be(System.Text.Json.JsonValueKind.Null);
    }

    /// <summary>
    /// Runs the wrapper against a fixed response body, for shapes the live server does not
    /// serve.
    /// </summary>
    private async Task<System.Text.Json.JsonElement> Stubbed(
        EffectivePolicy policy, string json, string? collectionPath)
    {
        using var http = new HttpClient(new FixedBodyHandler(json))
        {
            BaseAddress = new Uri("http://stub.local/")
        };
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);
        return await wrapper.RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: collectionPath));
    }

    private sealed class FixedBodyHandler : HttpMessageHandler
    {
        private readonly string _json;

        public FixedBodyHandler(string json) => _json = json;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(_json, System.Text.Encoding.UTF8, "application/json")
            });
    }

    // -- Helpers --

    private static string? Name(Dictionary<string, object?> record) => record.GetValueOrDefault("full_name") as string;

    private static string? Status(Dictionary<string, object?> record) => record.GetValueOrDefault("status") as string;

    private async Task<string> Body(EffectivePolicy policy, string path, string? collectionPath)
    {
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), _api.CreateClient());
        var element = await wrapper.RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", path, CollectionPath: collectionPath));
        return element.GetRawText();
    }

    private async Task<List<Dictionary<string, object?>>> Records(
        EffectivePolicy policy, string path, string collectionPath)
    {
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), _api.CreateClient());
        var element = await wrapper.RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", path, CollectionPath: collectionPath));

        return element.GetProperty(collectionPath).EnumerateArray()
            .Select(record => record.EnumerateObject()
                .ToDictionary(p => p.Name, p => (object?)(p.Value.ValueKind switch
                {
                    System.Text.Json.JsonValueKind.String => p.Value.GetString(),
                    System.Text.Json.JsonValueKind.Number => p.Value.GetInt64(),
                    System.Text.Json.JsonValueKind.True => true,
                    System.Text.Json.JsonValueKind.False => false,
                    _ => p.Value.GetRawText()
                })))
            .ToList();
    }

    private static EndpointRules AllowPatients() => new(
        AllowedEndpoints: new[] { "/patients", "/patients/*" },
        AllowedMethods: new[] { "GET" });

    private static EffectivePolicy Policy(ObjectRules? objectRules = null, PolicyLimits? limits = null) =>
        new(Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "live-api",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "pipeline-regression" },
            Permissions: new PolicyPermissions(CanQuery: true),
            ObjectRules: objectRules,
            Limits: limits);

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { policy }), SigningKey);
}
