using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Tolap.Mcp;
using Xunit;

namespace Tolap.Integration.Tests;

/// <summary>
/// Exercises <see cref="SecureHttpToolWrapper"/> against the local test API over a real
/// socket.
/// </summary>
/// <remarks>
/// The in-process handler mocks in the sibling suites can fabricate a body but not a real
/// status line, real response headers, a real chunked transfer, or a genuinely nested
/// document parsed by System.Text.Json from bytes off a socket. Those are exactly the
/// paths where a wrapper silently passes data through, so they are worth a real server.
/// Every test short-circuits when the fixture could not bind.
/// </remarks>
[Collection(TestApiCollection.Name)]
public sealed class HttpWrapperLiveApiTests
{
    private const string SigningKey = "live-api-key";

    private readonly TestApiFixture _api;

    public HttpWrapperLiveApiTests(TestApiFixture api) => _api = api;

    // -- Pre-call enforcement over a real transport --

    [Fact]
    public async Task HiddenEndpoint_IsDeniedAndNeverReachesTheServer()
    {
        // /admin/audit is deliberately reachable on the server: the point is that the
        // policy denies it, not that the server hides it.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var wrapper = Wrapper();

        var act = () => wrapper.RequestAsync(
            SignedContext(EndpointPolicy()), new HttpRequestArgs("GET", "/admin/audit"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*endpoint is hidden*");

        // The endpoint really would have returned data had the policy allowed it, so the
        // denial is enforcement rather than a 404.
        using var raw = _api.CreateClient();
        (await raw.GetAsync("/admin/audit")).IsSuccessStatusCode.Should().BeTrue();
    }

    [Fact]
    public async Task ReadOnlyPolicy_DeniesAPostTheServerWouldHaveAccepted()
    {
        // POST /patients succeeds by design on the server, so a test asserting denial is
        // testing the policy's method restriction rather than the server's routing.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var wrapper = Wrapper();

        var act = () => wrapper.RequestAsync(
            SignedContext(EndpointPolicy()),
            new HttpRequestArgs("POST", "/patients", Body: new { full_name = "Mallory" }));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*method not allowed*");

        using var raw = _api.CreateClient();
        var direct = await raw.PostAsync("/patients",
            new StringContent("""{"full_name":"Mallory"}""", System.Text.Encoding.UTF8, "application/json"));
        direct.StatusCode.Should().Be(System.Net.HttpStatusCode.Created);
    }

    [Fact]
    public async Task AllowedMethodWithABody_ReachesTheServerAndTheBodyIsTransmitted()
    {
        // The request-body branch is only reached on an allowed write; /echo reflects what
        // arrived, so this asserts the payload really crossed the socket.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        // Permitting a write takes AllowedMethods, ReadOnly: false, AND CanInsert. Three
        // independent gates (canonical-enforcement-spec.md section 9, connector-spec.md
        // sections 4 and 6): AllowedMethods makes the verb reachable on the path, ReadOnly is
        // the ceiling over every write, and CanInsert is the permission for the operation POST
        // performs. None of the three implies another, and CanInsert defaults to false when
        // absent, so it has to be stated.
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/echo" },
                AllowedMethods: new[] { "POST" })),
            readOnly: false,
            canInsert: true);

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("POST", "/echo", Body: new { full_name = "Mallory", count = 3 }));

        body.GetProperty("created").GetBoolean().Should().BeTrue();
        var received = body.GetProperty("received");
        received.GetProperty("full_name").GetString().Should().Be("Mallory");
        received.GetProperty("count").GetInt32().Should().Be(3);
    }

    [Fact]
    public async Task PostIsDeniedWhenCanInsertIsAbsent()
    {
        // The method is allowed and the policy is not read-only, so both of the older gates
        // open -- the only thing refusing this POST is the absent write permission. Absent
        // defaults to false (connector-spec.md section 4.1), deliberately opposite to
        // CanQuery, so a policy authored before writes existed does not silently acquire them.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/echo" },
                AllowedMethods: new[] { "POST" })),
            readOnly: false);

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("POST", "/echo", Body: new { full_name = "Mallory" }));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*insert not permitted*");

        // /echo really would have echoed the body, so the denial is enforcement's work.
        using var raw = _api.CreateClient();
        var direct = await raw.PostAsync("/echo",
            new StringContent("""{"full_name":"Mallory"}""", System.Text.Encoding.UTF8, "application/json"));
        direct.IsSuccessStatusCode.Should().BeTrue();
    }

    [Fact]
    public async Task QueryStringIsStrippedBeforePolicyEvaluationButSentToTheServer()
    {
        // Policy patterns are written against paths. The wrapper must evaluate the path
        // alone yet still transmit the query, or ?limit= would be silently dropped.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/echo" },
            AllowedMethods: new[] { "GET" })));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/echo?limit=3&region=us-east"));

        body.GetProperty("query").GetProperty("limit")[0].GetString().Should().Be("3");
        body.GetProperty("query").GetProperty("region")[0].GetString().Should().Be("us-east");
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(429)]
    [InlineData(500)]
    [InlineData(503)]
    public async Task RealErrorStatus_IsRaisedRatherThanReturnedAsABody(int status)
    {
        // A real status line, not a fabricated one. An error body must never be handed
        // back as though it were a successful result: the enforcement pipeline would then
        // run over an error document and return it as data.
        //
        // The exception is UpstreamHttpException rather than HttpRequestException: the
        // latter came from EnsureSuccessStatusCode, which raised *before* enforcement ran,
        // so the error payload was never put through the pipeline at all
        // (connector-spec.md section 6, "error bodies are enforced").
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/status/*" },
            AllowedMethods: new[] { "GET" })));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", $"/status/{status}"));

        (await act.Should().ThrowAsync<UpstreamHttpException>())
            .Which.Status.Should().Be(status);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(401)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(429)]
    [InlineData(500)]
    [InlineData(503)]
    public async Task ErrorBody_RunsTheSamePipelineAsASuccessBody(int status)
    {
        // LEAK: /status/<code> returns {"error": {"code": .., "message": ..}}, so
        // hiddenFields: ["error"] must empty it. EnsureSuccessStatusCode previously ran
        // before the pipeline, so the error payload reached the caller unenforced.
        // connector-spec.md section 6: "A 4xx/5xx payload carries the same fields as a
        // success payload; a validation error echoing a rejected value is a common leak."
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/status/*" },
                AllowedMethods: new[] { "GET" }),
            FieldRules: new FieldRules(HiddenFields: new[] { "error" })));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", $"/status/{status}"));

        var exception = (await act.Should().ThrowAsync<UpstreamHttpException>()).Which;
        exception.Status.Should().Be(status);
        exception.Body.Should().NotBeNull();
        exception.Body!.Value.EnumerateObject().Should().BeEmpty(
            "the hidden field is removed from the error body");
        exception.Message.Should().NotContain("synthetic");
    }

    [Fact]
    public async Task ErrorBody_IsMaskedRatherThanReturnedInCleartext()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/status/*" },
                AllowedMethods: new[] { "GET" }),
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("message", MaskType.Redact)
            })));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/status/400"));

        var exception = (await act.Should().ThrowAsync<UpstreamHttpException>()).Which;
        exception.Body!.Value.GetProperty("error").GetProperty("message").GetString()
            .Should().Be("[REDACTED]");
    }

    [Fact]
    public async Task ErrorBody_AlsoRunsTheRecordDroppingSteps()
    {
        // The body {"error": {...}} is a single record (canonical-enforcement-spec.md
        // section 4, "Single records"), and a filter on a field it does not carry fails
        // closed and drops it, so the enforced body is null. That is the fail-closed
        // direction and it is only observable if the record-dropping pass really ran — a
        // wrapper that merely stripped fields from an error body would return the record.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/status/*" },
                AllowedMethods: new[] { "GET" }),
            RowFilters: new[]
            {
                new RowFilter("account", FilterOperator.NotEquals, "other")
            }));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/status/404"));

        var exception = (await act.Should().ThrowAsync<UpstreamHttpException>()).Which;
        exception.Status.Should().Be(404);
        // A dropped single record is JSON null, not an empty object: an empty object would
        // imply the record existed but had no visible fields (spec section 4).
        exception.Body!.Value.ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public async Task TheRaisedError_ExposesNoRouteToTheUnenforcedBody()
    {
        // The point of enforcing an error body is defeated if the exception also ships a
        // handle on the raw one. UpstreamHttpException carries a status, an enforced body
        // and a URL, and nothing else — no HttpResponseMessage, no raw string.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/status/*" },
                AllowedMethods: new[] { "GET" }),
            FieldRules: new FieldRules(HiddenFields: new[] { "error" })));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/status/500"));

        var exception = (await act.Should().ThrowAsync<UpstreamHttpException>()).Which;
        typeof(UpstreamHttpException).GetProperties()
            .Select(p => p.PropertyType)
            .Should().NotContain(typeof(HttpResponseMessage));
        exception.Body!.Value.GetRawText().Should().NotContain("synthetic");
        exception.ToString().Should().NotContain("synthetic");
    }

    [Fact]
    public async Task InvalidSignatureAndExpiredContext_AreBothDeniedBeforeAnyRequest()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var wrapper = Wrapper();

        // Signed with the wrong key.
        var forged = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { EndpointPolicy() }), "wrong-key");
        (await FluentActions.Awaiting(() => wrapper.RequestAsync(
                forged, new HttpRequestArgs("GET", "/patients")))
            .Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*invalid signature*");

        // Correctly signed but expired.
        var expired = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { EndpointPolicy() }, TimeSpan.FromHours(-1)),
            SigningKey);
        (await FluentActions.Awaiting(() => wrapper.RequestAsync(
                expired, new HttpRequestArgs("GET", "/patients")))
            .Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*expired*");
    }

    [Fact]
    public async Task ContextWithNoPolicy_Throws()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>()), SigningKey);

        await FluentActions.Awaiting(() => Wrapper().RequestAsync(
                context, new HttpRequestArgs("GET", "/patients")))
            .Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task QueryPermissionDenied_IsRefusedBeforeAnyRequest()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(canQuery: false);

        await FluentActions.Awaiting(() => Wrapper().RequestAsync(
                SignedContext(policy), new HttpRequestArgs("GET", "/patients")))
            .Should().ThrowAsync<UnauthorizedAccessException>();
    }

    [Fact]
    public async Task SignatureAndExpiryEnforcementCanBeDisabled()
    {
        // The opt-outs exist for integrators terminating trust upstream; both must work
        // over a real transport, not just against a mock.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var unsignedExpired = SecurityContextBuilder.Build(
            "u", "t", new[] { EndpointPolicy() }, TimeSpan.FromHours(-1));

        var wrapper = new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(SigningKey, EnforceSignatures: false, EnforceExpiry: false),
            _api.CreateClient());

        var body = await wrapper.RequestAsync(unsignedExpired, new HttpRequestArgs("GET", "/patients"));

        body.GetProperty("results").GetArrayLength().Should().BeGreaterThan(0);
    }

    // -- Post-call enforcement over real response bodies --

    [Fact]
    public async Task HiddenFieldsAreStrippedFromEveryRecordInARealResponse()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn", "date_of_birth" }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        var records = body.GetProperty("results").EnumerateArray().ToList();
        records.Should().NotBeEmpty();
        foreach (var record in records)
        {
            record.TryGetProperty("ssn", out _).Should().BeFalse();
            record.TryGetProperty("date_of_birth", out _).Should().BeFalse();
            record.TryGetProperty("full_name", out _).Should().BeTrue("unlisted fields survive");
        }
    }

    [Fact]
    public async Task HiddenFieldsAreStrippedFromDeeplyNestedRealBodies()
    {
        // The nested endpoint puts ssn under demographics and email under
        // demographics.contact, so a wrapper that only walks the first level is caught.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn", "email" }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients/nested", CollectionPath: "results"));

        var raw = body.GetRawText();
        raw.Should().NotContain("111-22-3333").And.NotContain("alice@example.com");
        raw.Should().Contain("555-0100", "a sibling field the policy did not name survives");

        var demographics = body.GetProperty("results")[0].GetProperty("demographics");
        demographics.TryGetProperty("ssn", out _).Should().BeFalse();
        demographics.GetProperty("contact").TryGetProperty("email", out _).Should().BeFalse();
        demographics.GetProperty("contact").TryGetProperty("phone", out _).Should().BeTrue();
    }

    [Fact]
    public async Task MaskingAppliesToDottedPathsInARealNestedBody()
    {
        // The HTTP path masks by dotted path from the body root, which is how an API
        // response is addressed (as distinct from the DB path's table.column matching).
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("results.demographics.ssn", MaskType.Redact),
                new MaskingRule("results.demographics.contact.email", MaskType.Hash)
            }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients/nested", CollectionPath: "results"));

        var demographics = body.GetProperty("results")[0].GetProperty("demographics");
        demographics.GetProperty("ssn").GetString().Should().Be("[REDACTED]");
        demographics.GetProperty("contact").GetProperty("email").GetString()
            .Should().HaveLength(16).And.NotContain("alice");
    }

    [Fact]
    public async Task UnknownMaskTypeRedactsRatherThanReturningTheRealValue()
    {
        // Spec section 6, over a real body: a maskType from a newer schema version must
        // not silently disable masking. This is the shape of a shipped critical defect.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("results.ssn", (MaskType)9999)
            }),
            EndpointRules: AllowPatients()));

        // Signature enforcement is disabled here only because an unknown MaskType cannot
        // be serialized at all (MaskTypeJsonConverter rejects it on write), so such a
        // policy cannot be signed. That is itself the outer fail-closed layer: an unknown
        // maskType cannot arrive over the wire in .NET. This test covers the inner layer —
        // a value reaching the masker by a direct cast in integrator code must still
        // redact rather than pass the raw value through.
        var wrapper = new SecureHttpToolWrapper(
            new SecureHttpWrapperOptions(SigningKey, EnforceSignatures: false),
            _api.CreateClient());
        var context = SecurityContextBuilder.Build("u", "t", new[] { policy });

        var body = await wrapper.RequestAsync(
            context, new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        body.GetRawText().Should().NotContain("111-22-3333");
        body.GetProperty("results")[0].GetProperty("ssn").GetString().Should().Be("[REDACTED]");
    }

    [Fact]
    public async Task PartialMaskThatWouldRevealTheWholeValueDegradesToAFullMask()
    {
        // Spec section 6: showFirst + showLast >= len(value) must not return the value.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("results.ssn", MaskType.Partial, new MaskingParameters(ShowFirst: 20, ShowLast: 20))
            }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        body.GetProperty("results")[0].GetProperty("ssn").GetString()
            .Should().Be("***********").And.NotContain("1");
    }

    [Fact]
    public async Task AllowedFieldsProjectTheRecordsButPreserveTheEnvelope()
    {
        // Projection targets the records at CollectionPath, not the transport envelope,
        // so an API's paging block survives while undeclared columns are trimmed.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: new[] { "id", "region" }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients/envelope", CollectionPath: "items"));

        body.TryGetProperty("total", out var total).Should().BeTrue("the envelope's paging block survives");
        total.GetInt32().Should().Be(5);

        foreach (var record in body.GetProperty("items").EnumerateArray())
        {
            record.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo("id", "region");
        }
    }

    [Fact]
    public async Task EmptyAllowedFieldsDeniesEveryFieldOfEveryRecord()
    {
        // Spec section 3: [] is deny-everything, not "unrestricted".
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: Array.Empty<string>()),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        var records = body.GetProperty("results").EnumerateArray().ToList();
        records.Should().NotBeEmpty();
        records.Should().OnlyContain(r => r.EnumerateObject().Count() == 0);
    }

    [Fact]
    public async Task NullAllowedFieldsLeavesTheBodyUnprojected()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: null),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        body.GetProperty("results")[0].TryGetProperty("full_name", out _).Should().BeTrue();
    }

    [Fact]
    public async Task ResultLimitTruncatesTheCollectionAtItsPath()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(
            new ObjectRules(EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 2));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        body.GetProperty("results").GetArrayLength().Should().Be(2);
    }

    [Fact]
    public async Task ResultLimitLeavesAShorterCollectionAlone()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(
            new ObjectRules(EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 500));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        body.GetProperty("results").GetArrayLength().Should().Be(5);
    }

    [Fact]
    public async Task ServerSideLimitAndPolicyLimitCompose()
    {
        // ?limit= truncates server-side; maxResults truncates in the wrapper. The tighter
        // of the two must win, in either order.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/drug/*" }, AllowedMethods: new[] { "GET" })),
            new PolicyLimits(MaxResults: 1));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/drug/event.json?limit=3", CollectionPath: "results"));

        body.GetProperty("results").GetArrayLength().Should().Be(1);
    }

    [Fact]
    public async Task CollectionPathThatDoesNotExist_LeavesTheBodyUntouched()
    {
        // A misconfigured CollectionPath must be inert rather than throwing or silently
        // dropping the body: the limit and projection simply do not find a collection.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(
            new ObjectRules(
                FieldRules: new FieldRules(AllowedFields: new[] { "id" }),
                EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 1));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/patients", CollectionPath: "data.rows.missing"));

        body.GetProperty("results").GetArrayLength().Should().Be(5);
    }

    [Fact]
    public async Task CollectionPathPointingAtANonArray_LeavesTheBodyUntouched()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(
            new ObjectRules(EndpointRules: AllowPatients()),
            new PolicyLimits(MaxResults: 1));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/patients/envelope", CollectionPath: "total"));

        body.GetProperty("items").GetArrayLength().Should().Be(5);
    }

    [Fact]
    public async Task NullCollectionPath_AppliesProjectionToTheWholeBody()
    {
        // With no CollectionPath the body itself is treated as the record, so the
        // envelope's own keys are projected.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(AllowedFields: new[] { "total" }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients/envelope"));

        body.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo("total");
    }

    [Fact]
    public async Task MaskingAndHidingComposeSoAHiddenFieldIsRemovedNotMasked()
    {
        // Spec section 4 ordering, over a real body: hidden removal precedes masking, so a
        // field that is both must be gone rather than present-and-masked.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(
                HiddenFields: new[] { "ssn" },
                MaskedFields: new[] { new MaskingRule("results.ssn", MaskType.Redact) }),
            EndpointRules: AllowPatients()));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        var record = body.GetProperty("results")[0];
        record.TryGetProperty("ssn", out _).Should().BeFalse();
        body.GetRawText().Should().NotContain("[REDACTED]").And.NotContain("111-22-3333");
    }

    [Fact]
    public async Task RecordedOpenFdaBodyIsEnforcedOverARealSocket()
    {
        // The recorded openFDA payload is a deeply nested real-world shape; masking a
        // dotted path inside it must reach the leaf.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[]
            {
                new MaskingRule("results.patient.patientonsetage", MaskType.Redact)
            }),
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/drug/*" }, AllowedMethods: new[] { "GET" })));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/drug/event.json?limit=3", CollectionPath: "results"));

        var results = body.GetProperty("results");
        results.GetArrayLength().Should().BeGreaterThan(0);

        // Only assert on records that actually carry the field; the recording is real
        // data and the claim is "wherever present, it is masked".
        var seen = 0;
        foreach (var record in results.EnumerateArray())
        {
            if (record.TryGetProperty("patient", out var patient)
                && patient.TryGetProperty("patientonsetage", out var age))
            {
                age.GetString().Should().Be("[REDACTED]");
                seen++;
            }
        }
        seen.Should().BeGreaterThan(0, "the recorded payload should carry at least one patientonsetage");
    }

    [Fact]
    public async Task SlowResponseWithinTheClientTimeout_Succeeds()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/slow" }, AllowedMethods: new[] { "GET" })));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/slow?ms=100"));

        body.GetProperty("delayedMs").GetInt32().Should().Be(100);
    }

    [Fact]
    public async Task ResponseSlowerThanTheClientTimeout_Fails()
    {
        // A timeout must surface as a failure rather than as an empty-but-successful
        // result that the pipeline would then hand back as data.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/slow" }, AllowedMethods: new[] { "GET" })));
        using var client = _api.CreateClient();
        client.Timeout = TimeSpan.FromMilliseconds(300);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), client);

        var act = () => wrapper.RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/slow?ms=3000"));

        await act.Should().ThrowAsync<TaskCanceledException>();
    }

    // -- Redirects (connector-spec.md section 6) --

    // HttpClient follows redirects by default, so this SDK was exposed right now: a
    // permitted endpoint that 302s to a denied one bypassed the endpoint check entirely and
    // the wrapper never saw the hop. Nothing in the wrapper configured redirect behavior at
    // all — it inherited the handler's. These run over a real socket on purpose: a mock
    // cannot reproduce the actual failure mode, which is a handler that follows a redirect
    // before the wrapper's code sees it.

    private static EffectivePolicy RedirectAndAdminPolicy() => Policy(new ObjectRules(
        EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect/*" },
            HiddenEndpoints: new[] { "/admin/*" },
            AllowedMethods: new[] { "GET" })));

    [Fact]
    public async Task RedirectToADeniedEndpoint_IsRefusedRatherThanFollowed()
    {
        // The server really serves /admin/audit, so a wrapper that followed the 302 handed
        // back data the policy denies by name.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(RedirectAndAdminPolicy()), new HttpRequestArgs("GET", "/redirect/302"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*redirect target rejected: endpoint is hidden*");
    }

    [Fact]
    public async Task RedirectDenial_NamesTheEndpointRuleThatRefusedTheHop()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect/*" }, AllowedMethods: new[] { "GET" })));

        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/redirect/302"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*endpoint not in allowed set*");
    }

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(307)]
    [InlineData(308)]
    public async Task EveryRedirectCode_IsReValidated(int code)
    {
        // 307/308 preserve the method and body; 301/302 downgrade to GET. Both re-check, so
        // neither shape is a way past the rules.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(RedirectAndAdminPolicy()),
            new HttpRequestArgs("GET", $"/redirect/{code}"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*endpoint is hidden*");
    }

    [Fact]
    public async Task RedirectToAPermittedEndpoint_IsFollowedAndTheBodyEnforced()
    {
        // Re-validating is not refusing. And the followed hop's body still runs the full
        // pipeline, so a redirect is not a way around field rules either.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/redirect/*", "/patients" },
                AllowedMethods: new[] { "GET" }),
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var body = await NonFollowingWrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/redirect/302?to=%2Fpatients", CollectionPath: "results"));

        var records = body.GetProperty("results").EnumerateArray().ToList();
        records.Should().NotBeEmpty("the redirect was followed to the real collection");
        foreach (var record in records)
        {
            record.TryGetProperty("ssn", out _).Should()
                .BeFalse("the followed hop's body is still enforced");
        }
    }

    [Fact]
    public async Task CrossHostRedirect_IsRefusedRatherThanReGlobbed()
    {
        // allowedEndpoints: ["/*"] describes paths on the source this policy was resolved
        // for. Matching that glob against a path on another host would "permit" an origin
        // the author never considered, so the hop is refused on the host change rather than
        // re-globbed on the path.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/*", "/**" }, AllowedMethods: new[] { "GET" })));

        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/redirect/302?to=http%3A%2F%2F127.0.0.1%3A9%2Fblocked"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*redirect crosses origin*");
    }

    [Fact]
    public async Task RedirectLoop_IsBoundedRatherThanFollowedForever()
    {
        // /redirect-loop points at itself. The hop budget has to be ours, not the handler's:
        // every client's own limit differs (HttpClientHandler 50, httpx 20, fetch 20). The
        // target is permitted at every hop, which makes this the bound's test rather than
        // the endpoint rules'.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect-loop" }, AllowedMethods: new[] { "GET" })));

        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/redirect-loop"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*too many redirects (limit 5)*");
    }

    [Fact]
    public async Task HopBudget_PermitsAChainUpToTheLimitAndDeniesOnePastIt()
    {
        // Pins the number rather than merely "some bound exists", so the three SDKs can be
        // asserted identical.
        SecureHttpToolWrapper.MaxRedirects.Should().Be(5);

        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/redirect/*", "/patients" },
            AllowedMethods: new[] { "GET" })));

        var atLimit = await NonFollowingWrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs(
                "GET", RedirectChain(SecureHttpToolWrapper.MaxRedirects),
                CollectionPath: "results"));
        atLimit.GetProperty("results").EnumerateArray().Should().NotBeEmpty();

        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", RedirectChain(SecureHttpToolWrapper.MaxRedirects + 1)));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*too many redirects*");
    }

    [Fact]
    public async Task AHandlerThatFollowsARedirectAnyway_IsRefusedRatherThanEnforced()
    {
        // The specific inheritance section 6 forbids relying on. .NET fixes redirect
        // behavior on the handler at construction and offers no per-request override, so the
        // wrapper cannot switch it off — but it can detect that the response came from a
        // location no check approved, and refuse rather than enforce a body it never
        // authorized the fetch of.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        using var following = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true })
        {
            BaseAddress = _api.BaseAddress,
            Timeout = TimeSpan.FromSeconds(10)
        };
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), following);

        var act = () => wrapper.RequestAsync(
            SignedContext(RedirectAndAdminPolicy()), new HttpRequestArgs("GET", "/redirect/302"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*transport followed a redirect that was not re-validated*");

        // The handler really does follow: used directly it lands on the audit log the
        // wrapper refused.
        var direct = await following.GetAsync("/redirect/302");
        direct.RequestMessage!.RequestUri!.AbsolutePath.Should().Be("/admin/audit");
    }

    // -- Object rules on the HTTP path (connector-spec.md section 6, last bullet) --

    // No resource name is derived from a path — the spec is explicit that an author "MUST
    // express API restrictions as endpointRules", and inferring a resource from a route is
    // unspecified guesswork. But an integrator who names the object gets the check, on every
    // method rather than only on a write.

    [Fact]
    public async Task HiddenObjectNamedByTheCaller_DeniesAGet()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: AllowAllGet(),
            HiddenObjects: new[] { "patients" }));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/patients", ObjectName: "patients"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*object is hidden*");
    }

    [Fact]
    public async Task ObjectOutsideTheAllowList_DeniesAGet()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: AllowAllGet(),
            AllowedObjects: new[] { "encounters" }));

        var act = () => Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/patients", ObjectName: "patients"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*object not in allowed set*");
    }

    [Fact]
    public async Task PermittedObjectName_StillReturnsAnEnforcedBody()
    {
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: AllowAllGet(),
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs(
                "GET", "/patients", CollectionPath: "results", ObjectName: "patients"));

        var records = body.GetProperty("results").EnumerateArray().ToList();
        records.Should().NotBeEmpty();
        foreach (var record in records)
        {
            record.TryGetProperty("ssn", out _).Should().BeFalse();
        }
    }

    [Fact]
    public async Task OmittingTheObjectName_SkipsTheCheckRatherThanGuessing()
    {
        // A wrapper that derived "patients" from /patients would deny this, which is exactly
        // the unspecified behaviour section 6 marks with a warning.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: AllowAllGet(),
            HiddenObjects: new[] { "patients" }));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/patients", CollectionPath: "results"));

        body.GetProperty("results").EnumerateArray().Should().NotBeEmpty();
    }

    [Fact]
    public async Task ARedirectHop_ReChecksTheNamedObject()
    {
        // The object check is part of a hop, so a redirect cannot shed it.
        if (!_api.Ready)
        {
            // Test API unavailable; mirror the Postgres/MySQL suites' skip behavior.
            return;
        }
        var policy = Policy(new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/redirect/*", "/patients" },
                AllowedMethods: new[] { "GET" }),
            HiddenObjects: new[] { "patients" }));

        var act = () => NonFollowingWrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("GET", "/redirect/302?to=%2Fpatients", ObjectName: "patients"));

        (await act.Should().ThrowAsync<UnauthorizedAccessException>())
            .WithMessage("*object is hidden*");
    }

    // -- Helpers --

    private SecureHttpToolWrapper Wrapper() =>
        new(new SecureHttpWrapperOptions(SigningKey), _api.CreateClient());

    /// <summary>
    /// A wrapper over a handler that does not follow redirects, which is what the wrapper's
    /// contract asks for: .NET fixes redirect behavior at handler construction, so the
    /// integrator supplies it rather than the wrapper overriding it per request.
    /// </summary>
    private SecureHttpToolWrapper NonFollowingWrapper()
    {
        var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
        {
            BaseAddress = _api.BaseAddress,
            Timeout = TimeSpan.FromSeconds(10)
        };
        return new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), client);
    }

    private static EndpointRules AllowAllGet() => new(
        AllowedEndpoints: new[] { "/*", "/**" }, AllowedMethods: new[] { "GET" });

    /// <summary>A chain of <paramref name="hops"/> redirects ending at /patients.</summary>
    private static string RedirectChain(int hops)
    {
        var target = "/patients";
        for (var i = 0; i < hops; i++)
        {
            target = $"/redirect/302?to={Uri.EscapeDataString(target)}";
        }
        return target;
    }

    private static EndpointRules AllowPatients() => new(
        AllowedEndpoints: new[] { "/patients", "/patients/*" },
        AllowedMethods: new[] { "GET" });

    private static EffectivePolicy EndpointPolicy() => Policy(new ObjectRules(
        EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/patients", "/patients/*", "/echo", "/drug/*" },
            HiddenEndpoints: new[] { "/admin/*" },
            AllowedMethods: new[] { "GET" })));

    private static EffectivePolicy Policy(
        ObjectRules? objectRules = null,
        PolicyLimits? limits = null,
        bool canQuery = true,
        bool readOnly = true,
        bool? canInsert = null) =>
        new(Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "live-api",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "live-api-test" },
            Permissions: new PolicyPermissions(
                CanQuery: canQuery, CanInsert: canInsert, ReadOnly: readOnly),
            ObjectRules: objectRules,
            Limits: limits);

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { policy }), SigningKey);

    // =======================================================================
    // The limit when the caller does not name the collection (spec §6)
    // =======================================================================

    /// <summary>
    /// <c>MaxResults</c> when the caller omits <c>CollectionPath</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These exist because a fail-open shipped in all three SDKs and the <c>api</c> suites did not
    /// catch it. Every existing <c>MaxResults</c> test passed <c>CollectionPath</c>, because that
    /// is what the implementation wanted -- so the branch taken when it is <i>omitted</i> was
    /// never executed, and <c>MaxResults: 1</c> against an enveloped body returned every record
    /// the upstream sent.
    /// </para>
    /// <para>
    /// <c>CollectionPath</c> is an optional record parameter. An integrator reading
    /// "post-response: the full pipeline over the body, walking nested structures" has no reason
    /// to pass it, gets no warning, and their limit silently does nothing. That usage is what
    /// these tests encode: the call an integrator makes, not the call the code prefers.
    /// </para>
    /// <para>
    /// What made the omission dangerous rather than merely surprising is that the three
    /// record-level controls disagreed on it: projection returned an empty object and the row
    /// filter dropped the body, both fail-closed. Only the limit failed open.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Regression_MaxResultsIsEnforcedOnAnEnvelopedBody()
    {
        if (!_api.Ready) return;
        var policy = Policy(
            new ObjectRules(EndpointRules: AllowAllGet()),
            new PolicyLimits(MaxResults: 1));

        // CollectionPath deliberately NOT passed -- this is the integrator's call.
        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients"));

        body.GetProperty("results").GetArrayLength().Should().Be(1,
            "an enveloped body must still respect maxResults when no CollectionPath is given");
    }

    [Fact]
    public async Task Control_TheUpstreamReallyReturnsMoreThanOneRecord()
    {
        if (!_api.Ready) return;
        // Without this the regression assertion could pass because the corpus shrank to one row.
        var raw = await Wrapper().RequestAsync(
            SignedContext(Policy(new ObjectRules(EndpointRules: AllowAllGet()))),
            new HttpRequestArgs("GET", "/patients"));

        raw.GetProperty("results").GetArrayLength().Should().BeGreaterThan(1);
    }

    [Fact]
    public async Task ADifferentlyNamedCollection_IsStillEnforced()
    {
        if (!_api.Ready) return;
        // The key is discovered, not assumed to be "results". openFDA uses `results`,
        // ClinicalTrials.gov uses `studies`, this endpoint uses `items` -- recognising only one
        // of them would be the same bug wearing a different hat.
        var policy = Policy(
            new ObjectRules(EndpointRules: AllowAllGet()),
            new PolicyLimits(MaxResults: 2));

        var body = await Wrapper().RequestAsync(
            SignedContext(policy), new HttpRequestArgs("GET", "/patients/envelope"));

        body.GetProperty("items").GetArrayLength().Should().Be(2);
        body.GetProperty("total").GetInt32().Should().Be(5,
            "a paging counter is not a record collection and must survive");
    }
}
