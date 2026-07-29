using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Tolap.Core;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// The write entry points an integrator actually calls (connector-spec.md section 4).
/// </summary>
/// <remarks>
/// <para>
/// <c>Tolap.Core.Tests.WriteEnforcementTests</c> pins the decisions and
/// <c>Tolap.Core.Tests.WritePathParityTests</c> pins them against the other two SDKs. This
/// class covers what only exists at the wrapper level:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="SecureContextToolWrapper.PreWrite"/> and
///     <see cref="SecureContextToolWrapper.ExecuteWriteWithEnforcementAsync"/></description></item>
///   <item><description>the HTTP wrapper's write path, over an in-process
///     handler</description></item>
///   <item><description>section 4.5 post-write results: a write's response <i>is</i> a read
///     of the data it returns</description></item>
///   <item><description>that a denied write reaches neither the write delegate nor the
///     transport</description></item>
/// </list>
/// <para>The Python counterpart is <c>tests/test_write_enforcement.py</c>.</para>
/// </remarks>
public class WriteWrapperTests
{
    private const string SigningKey = "write-wrapper-key";

    // -- SecureContextToolWrapper.PreWrite --

    /// <summary>
    /// Insert and update granted, with a hidden field, a read-only field and a masked field
    /// so both the pre-write denials and the section 4.5 post-write pipeline are exercised
    /// against the same policy.
    /// </summary>
    private static EffectivePolicy WritePolicy() => Policy(
        new ObjectRules(
            AllowedObjects: new[] { "patients" },
            FieldRules: new FieldRules(
                HiddenFields: new[] { "patients.ssn" },
                ReadOnlyFields: new[] { "patients.created_at" },
                MaskedFields: new[]
                {
                    new MaskingRule(
                        "patients.email",
                        MaskType.Partial,
                        new MaskingParameters(ShowFirst: 1))
                })),
        canInsert: true,
        canUpdate: true);

    [Fact]
    public void PreWrite_ValidatesTheContextBeforeThePolicy()
    {
        // A forged context is a signature failure, not a policy decision: the context has to
        // be trustworthy before its policy means anything, and checking the policy first
        // would let an attacker's own policy answer the question.
        var forged = SignedContext(WritePolicy()) with
        {
            Integrity = new IntegrityBlock(
                SigningAlgorithm.HmacSha256, "not-the-real-signature")
        };

        var result = ContextWrapper().PreWrite(
            forged,
            WriteOperation.Insert,
            "patients",
            new Dictionary<string, object?> { ["full_name"] = "x" });

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("invalid signature");
    }

    [Fact]
    public void PreWrite_ContextWithNoPolicies_IsDenied()
    {
        // An empty policy array must deny rather than fall through to an unrestricted path;
        // a caller with no resolved policy has been granted nothing, and on the write path
        // "granted nothing" has to mean "writes nothing".
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>()), SigningKey);

        var result = ContextWrapper().PreWrite(context, WriteOperation.Insert, "patients");

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("no policy in context");
    }

    [Fact]
    public void PreWrite_PermitsAWritablePayload()
    {
        var result = ContextWrapper().PreWrite(
            SignedContext(WritePolicy()),
            WriteOperation.Insert,
            "patients",
            new Dictionary<string, object?> { ["full_name"] = "x" });

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreWrite_DeniesAReadOnlyField()
    {
        var result = ContextWrapper().PreWrite(
            SignedContext(WritePolicy()),
            WriteOperation.Insert,
            "patients",
            new Dictionary<string, object?> { ["created_at"] = "x" });

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is read-only: created_at");
    }

    [Fact]
    public void PreWrite_PassesFullReplaceThroughToTheWriteChecks()
    {
        // Same body, two verdicts, and the only difference is the replace semantics: the flag
        // has to survive the wrapper hop or the HTTP PUT rule has no teeth.
        var context = SignedContext(WritePolicy());
        var body = new Dictionary<string, object?> { ["full_name"] = "x" };

        var partial = ContextWrapper().PreWrite(context, WriteOperation.Update, "patients", body);
        var replace = ContextWrapper().PreWrite(
            context, WriteOperation.Update, "patients", body,
            new WriteValidationOptions(FullReplace: true));

        partial.Allowed.Should().BeTrue();
        replace.Allowed.Should().BeFalse();
        replace.Reason.Should().Be("field is hidden: patients.ssn");
    }

    [Fact]
    public void PreWrite_FullReplace_NamesAFieldThePayloadAlreadyCarriesOnlyOnce()
    {
        // The reason has to be the payload's own spelling (patients.ssn as written here
        // matches the rule exactly), not a second copy appended by the replace expansion --
        // otherwise a caller could see the same field reported twice, or reported under the
        // policy's spelling rather than their own.
        var result = ContextWrapper().PreWrite(
            SignedContext(WritePolicy()),
            WriteOperation.Update,
            "patients",
            new Dictionary<string, object?> { ["patients.ssn"] = "1", ["full_name"] = "x" },
            new WriteValidationOptions(FullReplace: true));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is hidden: patients.ssn");
    }

    // -- SecureContextToolWrapper.ExecuteWriteWithEnforcementAsync --

    [Fact]
    public async Task ExecuteWriteWithEnforcement_DeniedWrite_NeverInvokesTheDelegate()
    {
        // The whole point of pre-write validation: there is nothing to filter afterwards. If
        // the delegate ran and we then denied, the row would already be committed.
        var calls = 0;

        var exception = await Record.ExceptionAsync(() =>
            ContextWrapper().ExecuteWriteWithEnforcementAsync(
                SignedContext(WritePolicy()),
                WriteOperation.Insert,
                () =>
                {
                    calls++;
                    return Task.FromResult<object?>(new Dictionary<string, object?> { ["id"] = 1 });
                },
                "patients",
                new Dictionary<string, object?> { ["ssn"] = "1" }));

        exception.Should().BeOfType<UnauthorizedAccessException>();
        exception!.Message.Should().Be("Access denied: field is hidden: ssn");
        calls.Should().Be(0, "a refused write must never reach the source");
    }

    [Fact]
    public async Task ExecuteWriteWithEnforcement_RunsTheReadPipelineOverReturnedData()
    {
        // Section 4.5: a write's response IS a read of the data it returns. The caller wrote
        // `email` itself and gets it back masked, because what comes back is a read and every
        // read is masked. A hidden field it did not write does not appear at all -- an
        // INSERT ... RETURNING * would otherwise disclose it.
        var returned = await ContextWrapper().ExecuteWriteWithEnforcementAsync(
            SignedContext(WritePolicy()),
            WriteOperation.Insert,
            () => Task.FromResult<object?>(new Dictionary<string, object?>
            {
                ["id"] = 1,
                ["email"] = "alice@example.com",
                ["ssn"] = "111-22-3333"
            }),
            "patients",
            new Dictionary<string, object?> { ["email"] = "alice@example.com" });

        var record = returned.Should().BeAssignableTo<Dictionary<string, object?>>().Subject;
        record["email"].Should().Be("a****************");
        record.Should().NotContainKey("ssn");
        record["id"].Should().Be(1);
    }

    [Fact]
    public async Task ExecuteWriteWithEnforcement_RunsThePipelineOverEveryRecordOfAList()
    {
        // A multi-row INSERT ... RETURNING is a read of every row it returns, not just the
        // first.
        var returned = await ContextWrapper().ExecuteWriteWithEnforcementAsync(
            SignedContext(WritePolicy()),
            WriteOperation.Insert,
            () => Task.FromResult<object?>(new List<Dictionary<string, object?>>
            {
                new() { ["id"] = 1, ["ssn"] = "1", ["email"] = "a@b.c" },
                new() { ["id"] = 2, ["ssn"] = "2", ["email"] = "d@e.f" }
            }),
            "patients",
            new Dictionary<string, object?> { ["email"] = "a@b.c" });

        var records = returned.Should()
            .BeAssignableTo<IReadOnlyList<Dictionary<string, object?>>>().Subject;
        records.Should().OnlyContain(record => !record.ContainsKey("ssn"));
        records.Select(record => record["email"]).Should().Equal("a****", "d****");
    }

    [Fact]
    public async Task ExecuteWriteWithEnforcement_WriteReturningNull_IsPassedThroughNotDenied()
    {
        // There is no data to enforce a policy over, so null is not a violation. Denying here
        // would make every DELETE fail: a delete legitimately returns nothing, and the shape
        // rules exist to stop *data* escaping unenforced.
        var returned = await ContextWrapper().ExecuteWriteWithEnforcementAsync(
            SignedContext(WritePolicy()),
            WriteOperation.Insert,
            () => Task.FromResult<object?>(null),
            "patients",
            new Dictionary<string, object?> { ["full_name"] = "x" });

        returned.Should().BeNull();
    }

    [Fact]
    public async Task ExecuteWriteWithEnforcement_WriteReturningAScalar_IsStillDenied()
    {
        // A non-null unenforceable shape is denied exactly as on the read path. A row count
        // is fine to return, but the wrapper cannot tell a count from a leaked value, so
        // spec section 5 applies unchanged.
        var exception = await Record.ExceptionAsync(() =>
            ContextWrapper().ExecuteWriteWithEnforcementAsync(
                SignedContext(WritePolicy()),
                WriteOperation.Insert,
                () => Task.FromResult<object?>("1 row inserted"),
                "patients",
                new Dictionary<string, object?> { ["full_name"] = "x" }));

        exception.Should().BeOfType<UnenforceableResultException>();
        exception!.Message.Should().Contain("cannot be policy-enforced");
    }

    [Fact]
    public async Task ExecuteWriteWithEnforcement_UnverifiableTargetRow_IsRefusedBeforeTheDelegate()
    {
        // The refusal an integrator is most likely to meet in production: an UPDATE issued
        // under a row-scoped policy without having read the row. It must be refused, and
        // refused before the statement is issued, since an unqualified UPDATE would already
        // have modified rows outside the policy's scope.
        var calls = 0;
        var policy = Policy(
            new ObjectRules(RowFilters: new[]
            {
                new RowFilter("region", FilterOperator.Equals, Value: "us-east")
            }),
            canUpdate: true);

        var exception = await Record.ExceptionAsync(() =>
            ContextWrapper().ExecuteWriteWithEnforcementAsync(
                SignedContext(policy),
                WriteOperation.Update,
                () =>
                {
                    calls++;
                    return Task.FromResult<object?>(null);
                },
                "patients",
                new Dictionary<string, object?> { ["full_name"] = "x" }));

        exception!.Message.Should().Be("Access denied: write target unverifiable");
        calls.Should().Be(0);
    }

    // -- SecureHttpToolWrapper: the write path --

    private static EffectivePolicy HttpPolicy(
        bool canInsert = false,
        bool canUpdate = false,
        bool canDelete = false,
        bool readOnly = false,
        string[]? allowedMethods = null) => Policy(
        new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/patients*" },
                AllowedMethods: allowedMethods ?? new[] { "GET", "POST", "PUT", "PATCH", "DELETE" }),
            FieldRules: new FieldRules(
                HiddenFields: new[] { "ssn" },
                ReadOnlyFields: new[] { "created_at" },
                MaskedFields: new[]
                {
                    new MaskingRule("email", MaskType.Partial, new MaskingParameters(ShowFirst: 1))
                })),
        canInsert: canInsert,
        canUpdate: canUpdate,
        canDelete: canDelete,
        readOnly: readOnly);

    [Fact]
    public async Task Request_DeniedWrite_NeverPutsBytesOnTheTransport()
    {
        // The denial has to happen before the request leaves the process; a server-side
        // rejection would already have disclosed the payload.
        var handler = new RecordingHandler("""{"id": 7}""");
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var exception = await Record.ExceptionAsync(() => wrapper.RequestAsync(
            SignedContext(HttpPolicy(canInsert: true)),
            new HttpRequestArgs(
                "POST", "/patients",
                Body: new Dictionary<string, object?> { ["created_at"] = "x" })));

        exception.Should().BeOfType<UnauthorizedAccessException>();
        exception!.Message.Should().Be("Access denied: field is read-only: created_at");
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Request_CreatedBody_IsMaskedAndStrippedLikeAnyRead()
    {
        // Section 4.5 over HTTP: the created resource's body is a read of it.
        var handler = new RecordingHandler(
            """{"id": 7, "email": "alice@example.com", "ssn": "111"}""",
            HttpStatusCode.Created);
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var body = await wrapper.RequestAsync(
            SignedContext(HttpPolicy(canInsert: true)),
            new HttpRequestArgs(
                "POST", "/patients",
                Body: new Dictionary<string, object?> { ["email"] = "alice@example.com" }));

        body.GetProperty("email").GetString().Should().Be("a****************");
        body.TryGetProperty("ssn", out _).Should().BeFalse();
        body.GetProperty("id").GetInt32().Should().Be(7);
    }

    [Fact]
    public async Task Request_AnonymousTypeBody_IsValidatedRatherThanSilentlyPassing()
    {
        // The reason PayloadWriteFields walks POCOs by reflection: HttpRequestArgs.Body is
        // object?, and `new { ssn = "1" }` is the natural way to write a body here. Without
        // the walk the body would name no fields and this hidden-field rule would pass,
        // putting the SSN on the wire.
        var handler = new RecordingHandler("""{"id": 7}""", HttpStatusCode.Created);
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var exception = await Record.ExceptionAsync(() => wrapper.RequestAsync(
            SignedContext(HttpPolicy(canInsert: true)),
            new HttpRequestArgs("POST", "/patients", Body: new { ssn = "1" })));

        exception!.Message.Should().Be("Access denied: field is hidden: ssn");
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Request_Put_IsDeniedForAProtectedFieldTheBodyOmits()
    {
        // The full-replace rule reaches the HTTP wrapper. CanUpdate is granted here and PUT
        // is in AllowedMethods, so the only thing refusing this is the replace semantics
        // treating `ssn` as written.
        var handler = new RecordingHandler("""{"id": 7}""");
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var exception = await Record.ExceptionAsync(() => wrapper.RequestAsync(
            SignedContext(HttpPolicy(canUpdate: true)),
            new HttpRequestArgs(
                "PUT", "/patients/1",
                Body: new Dictionary<string, object?> { ["full_name"] = "x" })));

        exception!.Message.Should().Be("Access denied: field is hidden: ssn");
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Request_Patch_IsUnaffectedByTheReplaceRule()
    {
        // The counterpart to the PUT case above: the identical body through PATCH reaches
        // the transport, so the denial there is the method's semantics and not the policy
        // refusing every update.
        var handler = new RecordingHandler("""{"id": 7, "ssn": "111"}""");
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var body = await wrapper.RequestAsync(
            SignedContext(HttpPolicy(canUpdate: true)),
            new HttpRequestArgs(
                "PATCH", "/patients/1",
                Body: new Dictionary<string, object?> { ["full_name"] = "x" }));

        handler.Calls.Should().Be(1);
        // The response is still enforced: the hidden field the server volunteered is gone.
        body.TryGetProperty("ssn", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Request_PassesTheObjectNameToTheObjectRules()
    {
        var handler = new RecordingHandler("""{"id": 7}""");
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);
        var policy = Policy(
            new ObjectRules(
                HiddenObjects: new[] { "audit_log" },
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/patients*" },
                    AllowedMethods: new[] { "POST" })),
            canInsert: true);

        var exception = await Record.ExceptionAsync(() => wrapper.RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs(
                "POST", "/patients",
                Body: new Dictionary<string, object?> { ["a"] = 1 },
                ObjectName: "audit_log")));

        exception!.Message.Should().Be("Access denied: object is hidden");
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Request_PassesTheTargetRowToTheRowCheck()
    {
        // Without this hop a DELETE under a row-scoped policy would be refused as
        // unverifiable even when the integrator had read the row and could prove it
        // qualified.
        var policy = Policy(
            new ObjectRules(
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, Value: "us-east") },
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/patients*" },
                    AllowedMethods: new[] { "DELETE" })),
            canDelete: true);
        var context = SignedContext(policy);

        var permittedHandler = new RecordingHandler("""{"deleted": 1}""");
        using var permittedHttp = Client(permittedHandler);
        await new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), permittedHttp)
            .RequestAsync(context, new HttpRequestArgs(
                "DELETE", "/patients/1",
                WriteOptions: new WriteValidationOptions(
                    TargetRow: new Dictionary<string, object?> { ["region"] = "us-east" })));
        permittedHandler.Calls.Should().Be(1);

        var refusedHandler = new RecordingHandler("""{"deleted": 1}""");
        using var refusedHttp = Client(refusedHandler);
        var exception = await Record.ExceptionAsync(() =>
            new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), refusedHttp)
                .RequestAsync(context, new HttpRequestArgs(
                    "DELETE", "/patients/1",
                    WriteOptions: new WriteValidationOptions(
                        TargetRow: new Dictionary<string, object?> { ["region"] = "eu-west" }))));

        exception!.Message.Should().Be("Access denied: target row not permitted");
        refusedHandler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Request_ResourceFields_ExtendAPutToAnAllowList()
    {
        // The policy cannot know which resource fields its allow-list omits, so the
        // integrator supplies the shape; the argument has to reach ValidateHttpWrite for that
        // to mean anything.
        var handler = new RecordingHandler("""{"id": 7}""");
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);
        var policy = Policy(
            new ObjectRules(
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/patients*" },
                    AllowedMethods: new[] { "PUT" }),
                FieldRules: new FieldRules(AllowedFields: new[] { "full_name" })),
            canUpdate: true);

        var exception = await Record.ExceptionAsync(() => wrapper.RequestAsync(
            SignedContext(policy),
            new HttpRequestArgs(
                "PUT", "/patients/1",
                Body: new Dictionary<string, object?> { ["full_name"] = "x" },
                WriteOptions: new WriteValidationOptions(ResourceFields: new[] { "ssn" }))));

        exception!.Message.Should().Be("Access denied: field not in allowed set: ssn");
        handler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Request_Read_IsUnaffectedByTheWriteChecks()
    {
        // Regression guard: routing reads through the same entry point as writes must not
        // make CanQuery depend on CanInsert. A policy granting no write permission at all,
        // and declaring itself read-only, still reads.
        var handler = new RecordingHandler("""{"id": 1, "ssn": "111"}""");
        using var http = Client(handler);
        var wrapper = new SecureHttpToolWrapper(new SecureHttpWrapperOptions(SigningKey), http);

        var body = await wrapper.RequestAsync(
            SignedContext(HttpPolicy(readOnly: true)),
            new HttpRequestArgs("GET", "/patients"));

        handler.Calls.Should().Be(1);
        body.GetProperty("id").GetInt32().Should().Be(1);
        body.TryGetProperty("ssn", out _).Should().BeFalse();
    }

    // -- Fixtures --

    private static SecureContextToolWrapper ContextWrapper() =>
        new(new SecureContextWrapperOptions(SigningKey));

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { policy }), SigningKey);

    private static EffectivePolicy Policy(
        ObjectRules? objectRules,
        bool canInsert = false,
        bool canUpdate = false,
        bool canDelete = false,
        bool readOnly = false)
    {
        var now = DateTimeOffset.UtcNow;
        return new EffectivePolicy(
            Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "db:write-wrapper:patients",
            ResolvedAt: now,
            ExpiresAt: now.AddHours(1),
            SourceProfiles: new[] { "write-wrapper" },
            Permissions: new PolicyPermissions(
                CanQuery: true,
                CanInsert: canInsert ? true : null,
                CanUpdate: canUpdate ? true : null,
                CanDelete: canDelete ? true : null,
                CanExport: false,
                ReadOnly: readOnly),
            ObjectRules: objectRules);
    }

    private static HttpClient Client(HttpMessageHandler handler) =>
        new(handler) { BaseAddress = new Uri("https://api.example.test/") };

    /// <summary>
    /// An in-process transport that counts the requests it is asked to send, so a test can
    /// assert a denied write produced no call at all rather than merely that it threw.
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly string _body;
        private readonly HttpStatusCode _status;
        private int _calls;

        public RecordingHandler(string body, HttpStatusCode status = HttpStatusCode.OK)
        {
            _body = body;
            _status = status;
        }

        public int Calls => Volatile.Read(ref _calls);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(_status)
            {
                Content = new StringContent(_body, Encoding.UTF8, "application/json")
            });
        }
    }
}
