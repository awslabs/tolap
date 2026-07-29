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
        // Permitting a write takes BOTH AllowedMethods and ReadOnly: false. ReadOnly is a
        // permission-level ceiling over the method (spec section 9), so a policy still
        // declaring itself read-only cannot POST however its AllowedMethods reads.
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/echo" },
                AllowedMethods: new[] { "POST" })),
            readOnly: false);

        var body = await Wrapper().RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs("POST", "/echo", Body: new { full_name = "Mallory", count = 3 }));

        body.GetProperty("created").GetBoolean().Should().BeTrue();
        var received = body.GetProperty("received");
        received.GetProperty("full_name").GetString().Should().Be("Mallory");
        received.GetProperty("count").GetInt32().Should().Be(3);
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

        await act.Should().ThrowAsync<HttpRequestException>();
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

    // -- Helpers --

    private SecureHttpToolWrapper Wrapper() =>
        new(new SecureHttpWrapperOptions(SigningKey), _api.CreateClient());

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
        bool readOnly = true) =>
        new(Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "live-api",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "live-api-test" },
            Permissions: new PolicyPermissions(CanQuery: canQuery, ReadOnly: readOnly),
            ObjectRules: objectRules,
            Limits: limits);

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { policy }), SigningKey);
}
