using FluentAssertions;
using Tolap.Core;
using Tolap.Store;
using Xunit;

namespace Tolap.Mcp.Tests;

/// <summary>
/// Exercises both outcomes of the wrapper conditionals the behavioural suites reach from
/// one side only, plus the identity-extractor and options surface.
/// </summary>
public class WrapperBranchCoverageTests
{
    private const string SigningKey = "wrapper-branch-key";

    // -- SecureContextToolWrapper: PreExecute gates --

    [Fact]
    public void PreExecute_AllowedToolsList_AdmitsListedAndRejectsUnlisted()
    {
        var wrapper = ContextWrapper(allowedTools: new[] { "query_patients" });
        var context = SignedContext(Policy());

        wrapper.PreExecute(context, new PreExecuteArgs("query_patients")).Allowed.Should().BeTrue();

        var denied = wrapper.PreExecute(context, new PreExecuteArgs("drop_table"));
        denied.Allowed.Should().BeFalse();
        denied.Reason.Should().Be("tool not in allowed list");
    }

    [Fact]
    public void PreExecute_EmptyAllowedToolsList_IsTreatedAsNoToolRestriction()
    {
        // An empty AllowedTools is the wrapper's "unconfigured" shape rather than a
        // deny-all: the check is guarded by Length > 0. Pinned so the behaviour is a
        // decision on record rather than an accident, since spec section 3's deny-all
        // reading of [] applies to *policy* allow-lists, not to this wrapper option.
        var wrapper = ContextWrapper(allowedTools: Array.Empty<string>());

        wrapper.PreExecute(SignedContext(Policy()), new PreExecuteArgs("anything"))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_NullAllowedToolsList_IsUnrestricted()
    {
        ContextWrapper().PreExecute(SignedContext(Policy()), new PreExecuteArgs("anything"))
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_ContextWithNoPolicies_IsDenied()
    {
        // An empty policy array must deny rather than fall through to an unrestricted
        // path; a caller with no resolved policy has been granted nothing.
        var wrapper = ContextWrapper();
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>()), SigningKey);

        var result = wrapper.PreExecute(context, new PreExecuteArgs("query"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("no policy in context");
    }

    [Fact]
    public void PreExecute_QueryPermissionDenied_IsDenied()
    {
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(canQuery: false));

        var result = wrapper.PreExecute(context, new PreExecuteArgs("query"));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("query not permitted");
    }

    [Fact]
    public void PreExecute_ObjectNameIsCheckedOnlyWhenSupplied()
    {
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(objectRules:
            new ObjectRules(AllowedObjects: new[] { "patients" })));

        wrapper.PreExecute(context, new PreExecuteArgs("t", ObjectName: "patients")).Allowed.Should().BeTrue();
        wrapper.PreExecute(context, new PreExecuteArgs("t", ObjectName: "invoices")).Allowed.Should().BeFalse();
        // Omitted entirely: the object check is skipped rather than defaulting to a deny.
        wrapper.PreExecute(context, new PreExecuteArgs("t", ObjectName: null)).Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_FieldsAreCheckedAndDeniedFieldsAreNamed()
    {
        // The denial must name the offending fields so an integrator can fix the query;
        // a bare "denied" is unactionable.
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(objectRules: new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" }))));

        var denied = wrapper.PreExecute(context, new PreExecuteArgs("t", Fields: new[] { "name", "ssn" }));
        denied.Allowed.Should().BeFalse();
        denied.Reason.Should().Contain("ssn");

        wrapper.PreExecute(context, new PreExecuteArgs("t", Fields: new[] { "name" })).Allowed.Should().BeTrue();
        // Null and empty field lists both skip the check.
        wrapper.PreExecute(context, new PreExecuteArgs("t", Fields: null)).Allowed.Should().BeTrue();
        wrapper.PreExecute(context, new PreExecuteArgs("t", Fields: Array.Empty<string>())).Allowed.Should().BeTrue();
    }

    [Fact]
    public void PreExecute_EndpointIsCheckedWithGetAsTheDefaultMethod()
    {
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(objectRules: new ObjectRules(
            EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/drug/*" },
                AllowedMethods: new[] { "GET" }))));

        // An omitted method defaults to GET rather than to "any method".
        wrapper.PreExecute(context, new PreExecuteArgs("t", EndpointPath: "/drug/event.json"))
            .Allowed.Should().BeTrue();
        wrapper.PreExecute(context, new PreExecuteArgs("t", EndpointPath: "/drug/event.json", EndpointMethod: "DELETE"))
            .Allowed.Should().BeFalse();
        wrapper.PreExecute(context, new PreExecuteArgs("t", EndpointPath: "/admin/audit"))
            .Allowed.Should().BeFalse();
        // Omitted entirely: skipped.
        wrapper.PreExecute(context, new PreExecuteArgs("t", EndpointPath: null)).Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateSecurityContext_SignatureAndExpiryChecksCanEachBeDisabled()
    {
        // The opt-outs exist for integrators terminating trust upstream. Both must be
        // honoured, and both must be *on* by default — a wrapper that silently skipped
        // signature verification would accept a forged context.
        var unsignedExpired = SecurityContextBuilder.Build(
            "u", "t", new[] { Policy() }, TimeSpan.FromHours(-1));

        ContextWrapper().ValidateSecurityContext(unsignedExpired)
            .Reason.Should().Be("invalid signature", "signature is checked first and enforced by default");

        ContextWrapper(enforceSignatures: false).ValidateSecurityContext(unsignedExpired)
            .Reason.Should().Be("security context has expired");

        ContextWrapper(enforceSignatures: false, enforceExpiry: false)
            .ValidateSecurityContext(unsignedExpired).Allowed.Should().BeTrue();
    }

    [Fact]
    public void PostExecute_ContextWithNoPolicies_Throws()
    {
        var wrapper = ContextWrapper();
        var context = SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", Array.Empty<EffectivePolicy>()), SigningKey);

        FluentActions.Invoking(() => wrapper.PostExecute(context, new List<Dictionary<string, object?>>()))
            .Should().Throw<InvalidOperationException>().WithMessage("*no policy in context*");

        FluentActions.Invoking(() => wrapper.PostExecuteResult(context, new Dictionary<string, object?>()))
            .Should().Throw<InvalidOperationException>().WithMessage("*no policy in context*");
    }

    [Fact]
    public async Task ExecuteWithEnforcementAsync_TypedOverload_DeniesBeforeInvokingTheTool()
    {
        // A denial must short-circuit: a tool that already ran has already touched the
        // data, so post-hoc filtering is not a substitute for not calling it.
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(canQuery: false));
        var invoked = false;

        var act = () => wrapper.ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("query"),
            () =>
            {
                invoked = true;
                return Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                    new List<Dictionary<string, object?>>());
            });

        (await act.Should().ThrowAsync<UnauthorizedAccessException>()).WithMessage("*query not permitted*");
        invoked.Should().BeFalse();
    }

    [Fact]
    public async Task ExecuteWithEnforcementAsync_UntypedOverload_DeniesBeforeInvokingTheTool()
    {
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(canQuery: false));
        var invoked = false;

        var act = () => wrapper.ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("query"),
            () => { invoked = true; return Task.FromResult<object?>(null); });

        await act.Should().ThrowAsync<UnauthorizedAccessException>();
        invoked.Should().BeFalse();
    }

    [Fact]
    public async Task ExecuteWithEnforcementAsync_TypedOverload_AppliesThePipelineOnSuccess()
    {
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(objectRules: new ObjectRules(
            FieldRules: new FieldRules(MaskedFields: new[] { new MaskingRule("ssn", MaskType.Redact) }))));

        var rows = await wrapper.ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("query"),
            () => Task.FromResult<IReadOnlyList<Dictionary<string, object?>>>(
                new List<Dictionary<string, object?>> { new() { ["ssn"] = "111-22-3333" } }));

        rows.Should().ContainSingle().Which["ssn"].Should().Be("[REDACTED]");
    }

    [Fact]
    public async Task ExecuteWithEnforcementAsync_UntypedOverload_AppliesThePipelineOnSuccess()
    {
        var wrapper = ContextWrapper();
        var context = SignedContext(Policy(objectRules: new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" }))));

        var result = await wrapper.ExecuteWithEnforcementAsync(
            context, new PreExecuteArgs("query"),
            () => Task.FromResult<object?>(new Dictionary<string, object?>
            {
                ["ssn"] = "111-22-3333",
                ["name"] = "Alice"
            }));

        result.Should().BeOfType<Dictionary<string, object?>>()
            .Which.Should().NotContainKey("ssn").And.ContainKey("name");
    }

    [Fact]
    public void SecureContextWrapperOptions_DefaultsEnforceEverything()
    {
        // The safe default is the whole point of the option set; a shipped default of
        // "off" would make enforcement opt-in.
        var options = new SecureContextWrapperOptions(SigningKey);

        options.EnforceSignatures.Should().BeTrue();
        options.EnforceExpiry.Should().BeTrue();
        options.AllowedTools.Should().BeNull();
        options.AllowUnenforceableShapes.Should().BeFalse();
        options.SigningKey.Should().Be(SigningKey);
    }

    [Fact]
    public void PreExecuteArgs_DefaultsToNoNarrowing()
    {
        var args = new PreExecuteArgs("query_patients");

        args.ToolName.Should().Be("query_patients");
        args.ObjectName.Should().BeNull();
        args.Fields.Should().BeNull();
        args.EndpointPath.Should().BeNull();
        args.EndpointMethod.Should().BeNull();
    }

    // -- SecureMcpToolWrapper --

    [Fact]
    public async Task McpWrapper_SourceMappingIsAppliedWhenPresentAndBypassedWhenAbsent()
    {
        // The mapping lets a logical tool name resolve to a physical connection id. A
        // miss must fall through to the supplied id rather than resolving to nothing,
        // which would silently deny-all.
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0", Name: "scoped",
            Permissions: new PolicyPermissions(CanQuery: true),
            SourcePatterns: new[] { "db:prod:patients" }));
        await store.AssignPolicyAsync(new PolicyAssignment(
            "1.0", "scoped", new Assignee(AssigneeType.User, "alice"),
            new AssignmentScope(), true, new AuditInfo("admin", DateTimeOffset.UtcNow, "t")));

        var wrapper = new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            SourceMapping: new Dictionary<string, string> { ["patients-tool"] = "db:prod:patients" }));

        // Mapped alias resolves to the scoped policy.
        (await Execute(wrapper, "patients-tool")).Allowed.Should().BeTrue();
        // An unmapped id is used verbatim, matches no source pattern, and is denied.
        (await Execute(wrapper, "db:dev:patients")).Allowed.Should().BeFalse();
    }

    [Fact]
    public async Task McpWrapper_ValidateEndpointAsync_ReturnsBothOutcomes()
    {
        var wrapper = await McpWrapper(new ObjectRules(EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/drug/*" },
            HiddenEndpoints: new[] { "/admin/*" },
            AllowedMethods: new[] { "GET" })));
        var headers = Headers();

        (await wrapper.ValidateEndpointAsync(headers, "s", "/drug/event.json", "GET"))
            .Allowed.Should().BeTrue();

        var hidden = await wrapper.ValidateEndpointAsync(headers, "s", "/admin/audit", "GET");
        hidden.Allowed.Should().BeFalse();
        hidden.Reason.Should().Be("endpoint is hidden");

        var badMethod = await wrapper.ValidateEndpointAsync(headers, "s", "/drug/event.json", "DELETE");
        badMethod.Allowed.Should().BeFalse();
        badMethod.Reason.Should().Be("method not allowed");
    }

    [Fact]
    public async Task McpWrapper_ValidateFieldsAsync_SplitsAllowedFromDenied()
    {
        var wrapper = await McpWrapper(new ObjectRules(
            FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })));

        var result = await wrapper.ValidateFieldsAsync(Headers(), "s", new[] { "name", "ssn" });

        result.Allowed.Should().BeEquivalentTo("name");
        result.Denied.Should().BeEquivalentTo("ssn");
    }

    [Fact]
    public async Task McpWrapper_PermissiveMode_TurnsAnObjectDenialIntoAnAllow()
    {
        // Permissive mode is the documented migration escape hatch (threat-model R-6).
        // The denial reason must still be reported so the bypass is visible in logs.
        var wrapper = await McpWrapper(
            new ObjectRules(AllowedObjects: new[] { "patients" }),
            mode: EnforcementMode.Permissive);

        var result = await Execute(wrapper, objectName: "audit_log");

        result.Allowed.Should().BeTrue();
        result.DenialReason.Should().StartWith("[permissive]").And.Contain("not in allowed set");
    }

    [Fact]
    public async Task McpWrapper_PermissiveMode_AlsoBypassesTheQueryPermissionDenial()
    {
        var wrapper = await McpWrapper(canQuery: false, mode: EnforcementMode.Permissive);

        var result = await Execute(wrapper);

        result.Allowed.Should().BeTrue();
        result.DenialReason.Should().Contain("[permissive]").And.Contain("query permission denied");
    }

    [Fact]
    public void EnforcementMode_HasNoAuditOnlyMemberThatCouldBeMistakenForOne()
    {
        // The TypeScript SDK's EnforcementMode has an `AuditOnly` member whose doc-comment
        // used to promise "log violations but allow access" while the code denied exactly
        // like Strict. This SDK has no audit-only mode at all, and that asymmetry is worth
        // pinning: someone porting a configuration between SDKs must not find a
        // similarly-named member here and assume matching semantics. Permissive is the only
        // non-strict mode, and unlike TypeScript's AuditOnly it genuinely grants access
        // (covered by the two tests above).
        Enum.GetNames<EnforcementMode>().Should().BeEquivalentTo("Strict", "Permissive");
    }

    [Fact]
    public async Task McpWrapper_StrictMode_DeniesWithoutThePermissivePrefix()
    {
        var wrapper = await McpWrapper(canQuery: false);

        var result = await Execute(wrapper);

        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Be("query permission denied");
        result.Result.Should().BeNull();
    }

    [Fact]
    public void SecureMcpServerOptions_DefaultsAreTheSafeOnes()
    {
        var options = new SecureMcpServerOptions(
            PolicyStore: new InMemoryPolicyStore(),
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey);

        options.EnforcementMode.Should().Be(EnforcementMode.Strict);
        options.AllowUnenforceableShapes.Should().BeFalse();
        options.ContextTtl.Should().BeNull();
        options.SourceMapping.Should().BeNull();
    }

    [Fact]
    public void SecureMcpServerOptions_ContextTtlRoundTrips()
    {
        // ContextTtl is part of the public option surface but is not consumed by any
        // wrapper code path today; asserting the round-trip records that it is a
        // carrier only, so a future reader does not assume it shortens a context's life.
        var options = new SecureMcpServerOptions(
            PolicyStore: new InMemoryPolicyStore(),
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            ContextTtl: TimeSpan.FromMinutes(15));

        options.ContextTtl.Should().Be(TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void ToolExecutionResult_ExposesItsMembers()
    {
        var result = new ToolExecutionResult(false, "denied", null);

        result.Allowed.Should().BeFalse();
        result.DenialReason.Should().Be("denied");
        result.Result.Should().BeNull();
    }

    // -- HeaderIdentityExtractor: the object-valued dictionary overload --

    [Fact]
    public void HeaderExtractor_ObjectValuedDictionary_ExtractsIdentity()
    {
        // Header collections commonly arrive as IDictionary<string, object>; this overload
        // was entirely unexercised.
        var extractor = new HeaderIdentityExtractor();
        IDictionary<string, object> headers = new Dictionary<string, object>
        {
            ["X-Tolap-User-Id"] = "alice",
            ["X-Tolap-Tenant-Id"] = "tenant-1"
        };

        extractor.ExtractIdentity(headers).Should().Be(("alice", "tenant-1"));
    }

    [Fact]
    public void HeaderExtractor_ObjectValuedDictionary_StringifiesNonStringValues()
    {
        var extractor = new HeaderIdentityExtractor();
        IDictionary<string, object> headers = new Dictionary<string, object>
        {
            ["X-Tolap-User-Id"] = 12345,
            ["X-Tolap-Tenant-Id"] = Guid.Empty
        };

        extractor.ExtractIdentity(headers).UserId.Should().Be("12345");
    }

    [Fact]
    public void HeaderExtractor_ObjectValuedDictionary_MissingHeaderThrows()
    {
        var extractor = new HeaderIdentityExtractor();

        FluentActions.Invoking(() => extractor.ExtractIdentity(
            new Dictionary<string, object> { ["X-Tolap-Tenant-Id"] = "t" }))
            .Should().Throw<InvalidOperationException>().WithMessage("*X-Tolap-User-Id*");

        FluentActions.Invoking(() => extractor.ExtractIdentity(
            new Dictionary<string, object> { ["X-Tolap-User-Id"] = "u" }))
            .Should().Throw<InvalidOperationException>().WithMessage("*X-Tolap-Tenant-Id*");
    }

    [Fact]
    public void HeaderExtractor_ObjectValuedDictionary_NullValueThrowsRatherThanYieldingEmptyIdentity()
    {
        // A null header must not resolve to an empty user id, which would resolve
        // whatever an empty-string assignment happens to grant.
        var extractor = new HeaderIdentityExtractor();

        FluentActions.Invoking(() => extractor.ExtractIdentity(
            new Dictionary<string, object?> { ["X-Tolap-User-Id"] = null, ["X-Tolap-Tenant-Id"] = "t" }!))
            .Should().Throw<InvalidOperationException>().WithMessage("*X-Tolap-User-Id*");

        FluentActions.Invoking(() => extractor.ExtractIdentity(
            new Dictionary<string, object?> { ["X-Tolap-User-Id"] = "u", ["X-Tolap-Tenant-Id"] = null }!))
            .Should().Throw<InvalidOperationException>().WithMessage("*X-Tolap-Tenant-Id*");
    }

    [Fact]
    public void HeaderExtractor_StringDictionary_MissingTenantHeaderThrows()
    {
        FluentActions.Invoking(() => new HeaderIdentityExtractor().ExtractIdentity(
            new Dictionary<string, string> { ["X-Tolap-User-Id"] = "alice" }))
            .Should().Throw<InvalidOperationException>().WithMessage("*X-Tolap-Tenant-Id*");
    }

    [Fact]
    public void HeaderExtractor_CustomHeaderNamesAreHonouredOnBothOverloads()
    {
        var extractor = new HeaderIdentityExtractor("uid", "tid");

        extractor.ExtractIdentity(new Dictionary<string, string> { ["uid"] = "a", ["tid"] = "t" })
            .Should().Be(("a", "t"));
        extractor.ExtractIdentity(new Dictionary<string, object> { ["uid"] = "a", ["tid"] = "t" })
            .Should().Be(("a", "t"));
    }

    // -- JwtIdentityExtractor: algorithm arms and error paths --

    [Theory]
    [InlineData("HS256")]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public void JwtExtractor_EachAllowedHmacAlgorithm_VerifiesAndExtracts(string algorithm)
    {
        // Each arm is a distinct HMAC implementation; only HS256 was exercised, so a
        // wrong-digest bug in HS384/HS512 would have shipped.
        var extractor = new JwtIdentityExtractor("secret", algorithms: new[] { algorithm });
        var token = JwtHelper.Signed("secret", algorithm,
            new Dictionary<string, object> { ["sub"] = "alice", ["tenant_id"] = "t" });

        extractor.ExtractIdentity(token).Should().Be(("alice", "t"));
    }

    [Theory]
    [InlineData("HS384")]
    [InlineData("HS512")]
    public void JwtExtractor_AlgorithmOutsideTheAllowList_IsRejected(string algorithm)
    {
        // A stronger algorithm is still a rejected one when the caller did not allow it:
        // the allow-list, not the token, decides. This is the alg-confusion defence.
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Signed("secret", algorithm,
            new Dictionary<string, object> { ["sub"] = "alice", ["tenant_id"] = "t" });

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<SecurityException>().WithMessage("*not allowed*");
    }

    [Fact]
    public void JwtExtractor_HeaderWithoutAnAlgClaim_IsRejected()
    {
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Compose(
            JwtHelper.Encode("""{"typ":"JWT"}"""),
            JwtHelper.Encode("""{"sub":"alice","tenant_id":"t"}"""),
            "AAAA");

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<SecurityException>().WithMessage("*not allowed*");
    }

    [Fact]
    public void JwtExtractor_SignatureThatIsNotBase64Url_IsRejected()
    {
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Compose(
            JwtHelper.Encode("""{"alg":"HS256"}"""),
            JwtHelper.Encode("""{"sub":"alice","tenant_id":"t"}"""),
            "!!!not-base64!!!");

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<SecurityException>();
    }

    [Fact]
    public void JwtExtractor_TruncatedSignature_IsRejectedOnLength()
    {
        // A length mismatch must be a rejection rather than an exception from the
        // constant-time comparison.
        var extractor = new JwtIdentityExtractor("secret");
        var valid = JwtHelper.Signed("secret", "HS256",
            new Dictionary<string, object> { ["sub"] = "alice", ["tenant_id"] = "t" });
        var parts = valid.Split('.');
        var truncated = JwtHelper.Compose(parts[0], parts[1], parts[2][..10]);

        FluentActions.Invoking(() => extractor.ExtractIdentity(truncated))
            .Should().Throw<SecurityException>().WithMessage("*signature*");
    }

    [Fact]
    public void JwtExtractor_AllowedAlgorithmWithNoConfiguredSecret_IsRejected()
    {
        // Reached by allow-listing an algorithm on an extractor built without a secret.
        // Must refuse rather than treating "cannot verify" as "verified".
        var extractor = new JwtIdentityExtractor("s", algorithms: new[] { "HS256", "RS256" });
        var token = JwtHelper.Compose(
            JwtHelper.Encode("""{"alg":"RS256"}"""),
            JwtHelper.Encode("""{"sub":"alice","tenant_id":"t"}"""),
            JwtHelper.Encode("sig"));

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<SecurityException>().WithMessage("*not supported*");
    }

    [Fact]
    public void JwtExtractor_NonNumericExpClaim_IsIgnoredRatherThanTreatedAsExpiry()
    {
        // A string exp is not a NumericDate. It is skipped, so the token stands or falls
        // on its signature and required claims; it must not be read as "expired long ago"
        // nor crash the extractor.
        var extractor = JwtIdentityExtractor.CreateUnverified();
        var token = JwtHelper.Compose(
            JwtHelper.Encode("""{"alg":"none"}"""),
            JwtHelper.Encode("""{"sub":"alice","tenant_id":"t","exp":"tomorrow"}"""),
            "");

        extractor.ExtractIdentity(token).Should().Be(("alice", "t"));
    }

    [Fact]
    public void JwtExtractor_ExpiryWithinLeeway_IsAccepted()
    {
        // The leeway applies to exp as well as nbf, for clock skew between issuer and
        // verifier.
        var extractor = new JwtIdentityExtractor("secret", leewaySeconds: 300);
        var token = JwtHelper.Signed("secret", "HS256", new Dictionary<string, object>
        {
            ["sub"] = "alice",
            ["tenant_id"] = "t",
            ["exp"] = DateTimeOffset.UtcNow.AddSeconds(-30).ToUnixTimeSeconds()
        });

        extractor.ExtractIdentity(token).Should().Be(("alice", "t"));
    }

    [Fact]
    public void JwtExtractor_ValidFutureExpiry_IsAccepted()
    {
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Signed("secret", "HS256", new Dictionary<string, object>
        {
            ["sub"] = "alice",
            ["tenant_id"] = "t",
            ["exp"] = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()
        });

        extractor.ExtractIdentity(token).Should().Be(("alice", "t"));
    }

    [Fact]
    public void JwtExtractor_CustomClaimNamesAreRequired()
    {
        var extractor = new JwtIdentityExtractor("secret", userIdClaim: "uid", tenantIdClaim: "org");
        var wrongClaims = JwtHelper.Signed("secret", "HS256",
            new Dictionary<string, object> { ["sub"] = "alice", ["tenant_id"] = "t" });

        FluentActions.Invoking(() => extractor.ExtractIdentity(wrongClaims))
            .Should().Throw<SecurityException>().WithMessage("*Missing claim: uid*");

        var rightClaims = JwtHelper.Signed("secret", "HS256",
            new Dictionary<string, object> { ["uid"] = "alice", ["org"] = "acme" });
        extractor.ExtractIdentity(rightClaims).Should().Be(("alice", "acme"));
    }

    [Fact]
    public void JwtExtractor_NonStringClaim_IsRejected()
    {
        // A numeric sub is not a usable principal identifier; accepting it would let the
        // policy engine key on a value the issuer did not mean as an identity string.
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Signed("secret", "HS256",
            new Dictionary<string, object> { ["sub"] = 12345, ["tenant_id"] = "t" });

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<SecurityException>().WithMessage("*Missing claim: sub*");
    }

    [Fact]
    public void JwtExtractor_MissingTenantClaim_IsRejected()
    {
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Signed("secret", "HS256",
            new Dictionary<string, object> { ["sub"] = "alice" });

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<SecurityException>().WithMessage("*Missing claim: tenant_id*");
    }

    [Fact]
    public void JwtExtractor_MalformedHeaderSegment_IsRejected()
    {
        var extractor = new JwtIdentityExtractor("secret");
        var token = JwtHelper.Compose("!!!", JwtHelper.Encode("""{"sub":"a"}"""), "AAAA");

        FluentActions.Invoking(() => extractor.ExtractIdentity(token))
            .Should().Throw<Exception>();
    }

    [Fact]
    public void JwtExtractor_UnverifiedExtractor_StillEnforcesTemporalClaimsAndRequiredClaims()
    {
        // "Trust the upstream signature" must not mean "trust everything": an expired or
        // claimless token is still an invalid credential (spec section 9).
        var extractor = JwtIdentityExtractor.CreateUnverified();

        var expired = JwtHelper.Compose(
            JwtHelper.Encode("""{"alg":"none"}"""),
            JwtHelper.Encode($$"""{"sub":"a","tenant_id":"t","exp":{{DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds()}}}"""),
            "");
        FluentActions.Invoking(() => extractor.ExtractIdentity(expired))
            .Should().Throw<SecurityException>().WithMessage("*expired*");

        var claimless = JwtHelper.Compose(
            JwtHelper.Encode("""{"alg":"none"}"""), JwtHelper.Encode("{}"), "");
        FluentActions.Invoking(() => extractor.ExtractIdentity(claimless))
            .Should().Throw<SecurityException>().WithMessage("*Missing claim*");
    }

    [Fact]
    public void JwtExtractor_UnverifiedWithCustomClaimsAndLeeway_IsHonoured()
    {
        var extractor = JwtIdentityExtractor.CreateUnverified("uid", "org", leewaySeconds: 600);
        var token = JwtHelper.Compose(
            JwtHelper.Encode("""{"alg":"none"}"""),
            JwtHelper.Encode($$"""{"uid":"a","org":"acme","nbf":{{DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()}}}"""),
            "");

        extractor.ExtractIdentity(token).Should().Be(("a", "acme"));
    }

    [Fact]
    public void JwtExtractor_Base64UrlPaddingVariants_AreAllDecoded()
    {
        // Base64url omits '=' padding, and the three residue cases take different
        // branches. A token whose segment length hits an unpadded case must still decode.
        foreach (var name in new[] { "a", "ab", "abc", "abcd", "abcde" })
        {
            var extractor = JwtIdentityExtractor.CreateUnverified();
            var token = JwtHelper.Compose(
                JwtHelper.Encode("""{"alg":"none"}"""),
                JwtHelper.Encode($$"""{"sub":"{{name}}","tenant_id":"t"}"""),
                "");

            extractor.ExtractIdentity(token).UserId.Should().Be(name);
        }
    }

    [Fact]
    public void JwtExtractor_NullSecret_ThrowsArgumentNull()
    {
        FluentActions.Invoking(() => new JwtIdentityExtractor(null!))
            .Should().Throw<ArgumentNullException>();
    }

    // -- Helpers --

    private static SecureContextToolWrapper ContextWrapper(
        bool enforceSignatures = true,
        bool enforceExpiry = true,
        string[]? allowedTools = null,
        bool allowUnenforceableShapes = false) =>
        new(new SecureContextWrapperOptions(
            SigningKey, enforceSignatures, enforceExpiry, allowedTools, allowUnenforceableShapes));

    private static EffectivePolicy Policy(bool canQuery = true, ObjectRules? objectRules = null) =>
        new(Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "s",
            ResolvedAt: DateTimeOffset.UtcNow,
            ExpiresAt: DateTimeOffset.UtcNow.AddHours(1),
            SourceProfiles: new[] { "branch-coverage" },
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            ObjectRules: objectRules);

    private static SecurityContext SignedContext(EffectivePolicy policy) =>
        SecurityContextSigner.Sign(
            SecurityContextBuilder.Build("u", "t", new[] { policy }), SigningKey);

    private static async Task<SecureMcpToolWrapper> McpWrapper(
        ObjectRules? objectRules = null,
        bool canQuery = true,
        EnforcementMode mode = EnforcementMode.Strict)
    {
        var store = new InMemoryPolicyStore();
        await store.CreatePolicyAsync(new PolicyDefinition(
            Version: "1.0",
            Name: "branch-policy",
            Permissions: new PolicyPermissions(CanQuery: canQuery),
            AppliesToAll: true,
            ObjectRules: objectRules ?? new ObjectRules(AllowedObjects: new[] { "patients" })));
        await store.AssignPolicyAsync(new PolicyAssignment(
            "1.0", "branch-policy", new Assignee(AssigneeType.User, "alice"),
            new AssignmentScope(), true, new AuditInfo("admin", DateTimeOffset.UtcNow, "test")));

        return new SecureMcpToolWrapper(new SecureMcpServerOptions(
            PolicyStore: store,
            IdentityResolver: new StaticIdentityResolver(),
            IdentityExtractor: new HeaderIdentityExtractor(),
            SigningKey: SigningKey,
            EnforcementMode: mode));
    }

    private static Dictionary<string, string> Headers() => new()
    {
        ["X-Tolap-User-Id"] = "alice",
        ["X-Tolap-Tenant-Id"] = "t"
    };

    private static Task<ToolExecutionResult> Execute(
        SecureMcpToolWrapper wrapper,
        string sourceConnectionId = "s",
        string objectName = "patients") =>
        wrapper.ExecuteWithEnforcementAsync(
            Headers(), "query", objectName, sourceConnectionId,
            () => Task.FromResult<object?>(new List<Dictionary<string, object?>>()));
}
