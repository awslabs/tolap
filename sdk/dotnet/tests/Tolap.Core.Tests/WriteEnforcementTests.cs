using System.Text.Json;
using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Write-path enforcement beyond the cross-SDK corpus (connector-spec.md section 4).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="WritePathParityTests"/> carries the decision table the three SDKs assert
/// identically. This class covers what is either .NET-specific or too shape-dependent to
/// express in a shared table:
/// </para>
/// <list type="bullet">
///   <item><description>the absent target row and the empty-row distinction</description></item>
///   <item><description><see cref="EnforcementEngine.PayloadWriteFields"/>'s tree walk,
///     including the reflection arm that no other SDK needs</description></item>
///   <item><description>the HTTP method-to-permission mapping and the <c>PUT</c>
///     full-replace rule</description></item>
///   <item><description>section 4.3: <c>readOnlyFields</c> is a write control and has no
///     effect on reads</description></item>
/// </list>
/// <para>
/// The Python counterpart is <c>tests/test_write_enforcement.py</c>; the wrapper-level cases
/// live in <c>tests/Tolap.Mcp.Tests/WriteWrapperTests.cs</c>.
/// </para>
/// </remarks>
public class WriteEnforcementTests
{
    // -- The absent target row (section 4.2) --
    //
    // An unverifiable target is a denial, never an allow.

    /// <summary>
    /// A row-scoped policy granting every write, so a denial below can only come from the
    /// target-row check and never from a missing permission.
    /// </summary>
    private static readonly EffectivePolicy Filtered = Policy(
        new ObjectRules(RowFilters: new[]
        {
            new RowFilter("region", FilterOperator.Equals, Value: "us-east")
        }),
        canInsert: true,
        canUpdate: true,
        canDelete: true);

    [Fact]
    public void ValidateWrite_OmittedOptions_TreatsTheTargetRowAsUnverifiable()
    {
        // The load-bearing default: an integrator who calls ValidateWrite without thinking
        // about the target row gets a denial, not a pass. Passing no options at all and
        // passing a default WriteValidationOptions must agree, or the convenience overload
        // would be more permissive than the explicit call.
        var payload = new Dictionary<string, object?> { ["a"] = 1 };

        var implicitOptions = EnforcementEngine.ValidateWrite(
            WriteOperation.Update, "patients", payload, Filtered);
        var explicitOptions = EnforcementEngine.ValidateWrite(
            WriteOperation.Update, "patients", payload, Filtered, new WriteValidationOptions());

        implicitOptions.Allowed.Should().BeFalse();
        implicitOptions.Reason.Should().Be("write target unverifiable");
        explicitOptions.Should().BeEquivalentTo(implicitOptions);
    }

    [Theory]
    [InlineData(WriteOperation.Update)]
    [InlineData(WriteOperation.Delete)]
    [InlineData(WriteOperation.Upsert)]
    public void ValidateWrite_NullTargetRow_IsUnverifiableForEveryTargetedOperation(
        WriteOperation operation)
    {
        // Insert is excluded deliberately -- it has no pre-existing target -- but every
        // operation that modifies an existing row must be refused when the filters cannot be
        // evaluated. An upsert reached through this path may overwrite, so it is targeted.
        var result = EnforcementEngine.ValidateWrite(
            operation,
            "patients",
            new Dictionary<string, object?> { ["a"] = 1 },
            Filtered,
            new WriteValidationOptions(TargetRow: null));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("write target unverifiable");
    }

    [Fact]
    public void ValidateWrite_EmptyTargetRow_IsEvaluatedAndFailsClosedOnTheFilters()
    {
        // An empty dictionary is a row, not an absent target, so the filters run and drop
        // it. The distinction matters: an empty row is missing the filtered field, which
        // spec section 7 drops -- so the reason is the row denial, not the unverifiable one.
        // An integrator seeing "target row not permitted" knows the row was checked;
        // "write target unverifiable" means it was not.
        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Update,
            "patients",
            new Dictionary<string, object?> { ["a"] = 1 },
            Filtered,
            new WriteValidationOptions(TargetRow: new Dictionary<string, object?>()));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("target row not permitted");
    }

    [Fact]
    public void ValidateWrite_AnyReadOnlyDictionaryImplementation_IsAcceptedAsARow()
    {
        // The parameter is IReadOnlyDictionary, not Dictionary, and the row check must not
        // quietly require the concrete type: a driver, an ORM projection, or a caller's own
        // case-insensitive map is still a row. A conversion that only handled Dictionary
        // would turn this permitted delete into "write target unverifiable".
        var row = new SortedDictionary<string, object?> { ["region"] = "us-east" };

        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Delete,
            "patients",
            null,
            Filtered,
            new WriteValidationOptions(TargetRow: row));

        result.Allowed.Should().BeTrue();
    }

    [Theory]
    [InlineData(WriteOperation.Update)]
    [InlineData(WriteOperation.Delete)]
    [InlineData(WriteOperation.Upsert)]
    public void ValidateWrite_NoObjectRules_HasNoFiltersToVerify(WriteOperation operation)
    {
        // No ObjectRules block at all means no row filters, so nothing is unverifiable. The
        // check is vacuous rather than fail-closed: a policy that never expressed a row
        // constraint cannot have one violated. Distinct from a filtered policy with no
        // target row, which denies.
        var unfiltered = Policy(
            objectRules: null, canInsert: true, canUpdate: true, canDelete: true);

        var result = EnforcementEngine.ValidateWrite(
            operation,
            "patients",
            new Dictionary<string, object?> { ["a"] = 1 },
            unfiltered);

        result.Allowed.Should().BeTrue();
        result.Reason.Should().BeNull();
    }

    // -- PayloadWriteFields: the tree walk that decides which fields a payload names --

    [Fact]
    public void PayloadWriteFields_CollectsKeysAtEveryDepth()
    {
        var fields = EnforcementEngine.PayloadWriteFields(new Dictionary<string, object?>
        {
            ["outer"] = new Dictionary<string, object?>
            {
                ["inner"] = new Dictionary<string, object?> { ["ssn"] = "1" }
            },
            ["sibling"] = 2
        });

        fields.Should().Equal("outer", "inner", "ssn", "sibling");
    }

    [Fact]
    public void PayloadWriteFields_CollectsTheKeysOfEveryRecordInASequence()
    {
        // A bulk insert names the fields of every record it carries.
        var fields = EnforcementEngine.PayloadWriteFields(new List<object?>
        {
            new Dictionary<string, object?> { ["a"] = 1 },
            new Dictionary<string, object?> { ["b"] = 2 }
        });

        fields.Should().Equal("a", "b");
    }

    [Fact]
    public void PayloadWriteFields_WalksASequenceNestedUnderAKey()
    {
        var fields = EnforcementEngine.PayloadWriteFields(new Dictionary<string, object?>
        {
            ["encounters"] = new List<object?>
            {
                new Dictionary<string, object?> { ["ssn"] = "1" }
            }
        });

        fields.Should().Equal("encounters", "ssn");
    }

    [Fact]
    public void PayloadWriteFields_ReportsADuplicateKeyOnce()
    {
        // Deduplicated so a denial names a field once, not per occurrence.
        var fields = EnforcementEngine.PayloadWriteFields(new List<object?>
        {
            new Dictionary<string, object?> { ["a"] = 1 },
            new Dictionary<string, object?> { ["a"] = 2 }
        });

        fields.Should().Equal("a");
    }

    [Fact]
    public void PayloadWriteFields_NullPayload_NamesNoFields()
    {
        // Not a fail-open: a null payload cannot carry a hidden field, and the permission,
        // object and row checks all still run.
        EnforcementEngine.PayloadWriteFields(null).Should().BeEmpty();
    }

    [Theory]
    [InlineData("a string")]
    [InlineData(42)]
    [InlineData(true)]
    [InlineData(1.5)]
    public void PayloadWriteFields_ScalarPayload_NamesNoFields(object payload)
    {
        // A string is IEnumerable and a boxed primitive has reflectable members, so without
        // the leaf guards a scalar body would be walked character by character or have
        // "Length"/"Chars" recorded as written fields -- a denial for a field the caller
        // never named.
        EnforcementEngine.PayloadWriteFields(payload).Should().BeEmpty();
    }

    [Fact]
    public void PayloadWriteFields_ExtendsTheSetWithResourceFieldsWithoutDuplicating()
    {
        var fields = EnforcementEngine.PayloadWriteFields(
            new Dictionary<string, object?> { ["a"] = 1 },
            new[] { "a", "b" });

        fields.Should().Equal("a", "b");
    }

    // -- PayloadWriteFields: the reflection arm, which has no Python or TypeScript
    //    counterpart --
    //
    // HttpRequestArgs.Body is object?, so an integrator naturally passes
    // `new { full_name = "..." }`. Without a reflection walk a POCO body would contribute
    // no field names at all and every field rule would silently pass -- a fail-open on the
    // write path, where there is nothing to filter afterwards.

    [Fact]
    public void PayloadWriteFields_AnonymousType_NamesItsProperties()
    {
        var fields = EnforcementEngine.PayloadWriteFields(new { full_name = "Alice", ssn = "1" });

        fields.Should().Equal("full_name", "ssn");
    }

    [Fact]
    public void ValidateWrite_AnonymousTypeBody_IsValidatedRatherThanSilentlyPassing()
    {
        // The fail-open this arm exists to prevent, asserted through the public decision
        // rather than through the field list: a POCO naming no fields would make every
        // field rule vacuous, so this insert would have been ALLOWED.
        var policy = Policy(
            new ObjectRules(FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })),
            canInsert: true);

        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Insert, "patients", new { ssn = "1" }, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is hidden: ssn");
    }

    [Fact]
    public void PayloadWriteFields_NestedPoco_IsWalked()
    {
        // A DTO carrying a nested DTO is the ordinary shape of a request body, and the field
        // matcher reaches a nested key from a bare rule (section 3.2), so the walk has to
        // descend rather than stopping at the outermost type.
        var fields = EnforcementEngine.PayloadWriteFields(
            new PatientDto("Alice", new DemographicsDto("1")));

        fields.Should().Contain("Demographics").And.Contain("Ssn");
    }

    [Fact]
    public void ValidateWrite_NestedPocoBody_DeniesAFieldBuriedInsideIt()
    {
        // The nested walk asserted through the decision: a rule of `ssn` must reach a field
        // one level down, or a hidden field could be smuggled past by wrapping it.
        var policy = Policy(
            new ObjectRules(FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })),
            canInsert: true);

        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Insert,
            "patients",
            new PatientDto("Alice", new DemographicsDto("1")),
            policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is hidden: Ssn");
    }

    [Fact]
    public void PayloadWriteFields_JsonElement_IsWalked()
    {
        // A body deserialized straight from a request arrives as a JsonElement, whose
        // properties are not reflectable members. Without its own arm it would fall through
        // to reflection and name JsonElement's own surface instead of the payload's fields.
        using var document = JsonDocument.Parse(
            """{"full_name": "Alice", "demographics": {"ssn": "1"}}""");

        var fields = EnforcementEngine.PayloadWriteFields(document.RootElement);

        fields.Should().Equal("full_name", "demographics", "ssn");
    }

    [Fact]
    public void ValidateWrite_JsonElementBody_DeniesAHiddenFieldInsideIt()
    {
        using var document = JsonDocument.Parse("""{"demographics": {"ssn": "1"}}""");
        var policy = Policy(
            new ObjectRules(FieldRules: new FieldRules(HiddenFields: new[] { "ssn" })),
            canInsert: true);

        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Insert, "patients", document.RootElement, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is hidden: ssn");
    }

    [Fact]
    public void PayloadWriteFields_CyclicObjectGraph_Terminates()
    {
        // Reflection can reach a cycle that JSON cannot express, and an unguarded walk would
        // recurse until the stack ran out -- turning a malformed DTO into a crash instead of
        // a policy decision.
        var node = new CyclicNode { Name = "root" };
        node.Self = node;

        var fields = EnforcementEngine.PayloadWriteFields(node);

        fields.Should().Contain("Name").And.Contain("Self");
    }

    [Fact]
    public void PayloadWriteFields_PropertyWhoseGetterThrows_StillNamesTheField()
    {
        // The name is what a rule matches on, so it is recorded before the value is read. A
        // write has to be denied or allowed on policy grounds, never crash on the shape of
        // the caller's DTO.
        var fields = EnforcementEngine.PayloadWriteFields(new ThrowingGetterDto());

        fields.Should().Contain("Ssn");
    }

    // -- HTTP method mapping (connector-spec.md section 6) --

    [Theory]
    [InlineData("POST", WriteOperation.Insert)]
    [InlineData("PUT", WriteOperation.Update)]
    [InlineData("PATCH", WriteOperation.Update)]
    [InlineData("DELETE", WriteOperation.Delete)]
    [InlineData("post", WriteOperation.Insert)]
    [InlineData("Delete", WriteOperation.Delete)]
    public void WriteOperationForMethod_MapsAWriteMethodToItsOperation(
        string method, WriteOperation expected)
    {
        EnforcementEngine.WriteOperationForMethod(method).Should().Be(expected);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    [InlineData("get")]
    public void WriteOperationForMethod_MapsAReadMethodToNoOperation(string method)
    {
        // A read is governed by canQuery, which ValidateEndpoint already gates.
        EnforcementEngine.WriteOperationForMethod(method).Should().BeNull();
    }

    [Fact]
    public void WriteOperationForMethod_UnknownMethod_MapsToNoOperationWithoutAdmittingTheVerb()
    {
        // Returning null here does not let TRACE through -- ValidateEndpoint refuses it
        // because an omitted AllowedMethods defaults to GET/HEAD/OPTIONS and an explicit
        // list would have to name TRACE for it to pass.
        EnforcementEngine.WriteOperationForMethod("TRACE").Should().BeNull();

        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(AllowedEndpoints: new[] { "/*" })),
            canInsert: true, canUpdate: true, canDelete: true);

        var result = EnforcementEngine.ValidateHttpWrite("TRACE", "/patients", null, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("method not allowed");
    }

    // -- ValidateHttpWrite: endpoint rules and the write checks both run, and neither
    //    substitutes for the other --

    private static ObjectRules AllowWriteMethods() => new(
        EndpointRules: new EndpointRules(
            AllowedEndpoints: new[] { "/patients*" },
            AllowedMethods: new[] { "GET", "POST", "PUT", "PATCH", "DELETE" }),
        FieldRules: new FieldRules(ReadOnlyFields: new[] { "patients.created_at" }));

    [Fact]
    public void ValidateHttpWrite_ReadMethod_ReturnsTheEndpointDecisionUnchanged()
    {
        // A GET is not a write, so no write permission is invented for it -- and a
        // read-only policy still reads.
        var policy = Policy(AllowWriteMethods(), readOnly: true);

        EnforcementEngine.ValidateHttpWrite("GET", "/patients", null, policy)
            .Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateHttpWrite_AnAllowedMethodIsNotAWriteGrant()
    {
        // POST in AllowedMethods says nothing about CanInsert. The two controls are
        // independent by design (connector-spec.md section 6): one says which verbs reach
        // which paths, the other says which operations the principal may perform.
        var policy = Policy(AllowWriteMethods());

        var result = EnforcementEngine.ValidateHttpWrite(
            "POST", "/patients", new Dictionary<string, object?> { ["a"] = 1 }, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("insert not permitted");
    }

    [Fact]
    public void ValidateHttpWrite_AWritePermissionDoesNotMakeAPathReachable()
    {
        // The converse: CanInsert says nothing about which endpoints exist.
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/patients*" },
                AllowedMethods: new[] { "POST" })),
            canInsert: true);

        var result = EnforcementEngine.ValidateHttpWrite(
            "POST", "/admin/audit", new Dictionary<string, object?> { ["a"] = 1 }, policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("endpoint not in allowed set");
    }

    [Fact]
    public void ValidateHttpWrite_TheEndpointCheckPrecedesTheWriteChecks()
    {
        // Both would deny; the endpoint reason wins because it runs first, so an integrator
        // is told the path is unreachable rather than sent to edit ReadOnlyFields for a call
        // that would fail anyway.
        var policy = Policy(AllowWriteMethods());

        var result = EnforcementEngine.ValidateHttpWrite(
            "POST",
            "/admin/audit",
            new Dictionary<string, object?> { ["created_at"] = "x" },
            policy);

        result.Reason.Should().Be("endpoint not in allowed set");
    }

    [Fact]
    public void ValidateHttpWrite_Patch_ValidatesOnlyTheKeysPresent()
    {
        // A PATCH is a partial update, so an unmentioned field is not written.
        var policy = Policy(AllowWriteMethods(), canUpdate: true);

        var result = EnforcementEngine.ValidateHttpWrite(
            "PATCH",
            "/patients/1",
            new Dictionary<string, object?> { ["full_name"] = "x" },
            policy);

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateHttpWrite_Put_TreatsAnOmittedProtectedFieldAsWritten()
    {
        // The full-replace rule (connector-spec.md section 6). A PUT replaces the whole
        // resource, so omitting created_at is not "leaving it alone" -- it is an attempt to
        // overwrite it with absent. The identical body through PATCH is permitted (above);
        // the only difference is the method's replace semantics.
        var policy = Policy(AllowWriteMethods(), canUpdate: true);

        var result = EnforcementEngine.ValidateHttpWrite(
            "PUT",
            "/patients/1",
            new Dictionary<string, object?> { ["full_name"] = "x" },
            policy);

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is read-only: patients.created_at");
    }

    [Fact]
    public void ValidateHttpWrite_Put_IsPermittedWhenThePolicyProtectsNoFields()
    {
        // A replace adds nothing when there is nothing to protect.
        var policy = Policy(
            new ObjectRules(EndpointRules: new EndpointRules(
                AllowedEndpoints: new[] { "/patients*" },
                AllowedMethods: new[] { "PUT" })),
            canUpdate: true);

        var result = EnforcementEngine.ValidateHttpWrite(
            "PUT",
            "/patients/1",
            new Dictionary<string, object?> { ["full_name"] = "x" },
            policy);

        result.Allowed.Should().BeTrue();
    }

    [Fact]
    public void ValidateHttpWrite_ResourceFields_ExtendAPutToAnAllowList()
    {
        // AllowedFields needs the resource's field list to be checked on a replace: the
        // policy alone cannot say which resource fields an allow-list omits -- that is
        // knowable only from the resource's shape -- so an integrator combining
        // AllowedFields with full-resource replaces supplies it.
        var policy = Policy(
            new ObjectRules(
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/patients*" },
                    AllowedMethods: new[] { "PUT" }),
                FieldRules: new FieldRules(AllowedFields: new[] { "full_name" })),
            canUpdate: true);
        var body = new Dictionary<string, object?> { ["full_name"] = "x" };

        var without = EnforcementEngine.ValidateHttpWrite("PUT", "/patients/1", body, policy);
        var withResource = EnforcementEngine.ValidateHttpWrite(
            "PUT", "/patients/1", body, policy, null,
            new WriteValidationOptions(ResourceFields: new[] { "ssn" }));

        without.Allowed.Should().BeTrue();
        withResource.Allowed.Should().BeFalse();
        withResource.Reason.Should().Be("field not in allowed set: ssn");
    }

    [Fact]
    public void ValidateHttpWrite_ChecksTheObjectNameWhenSupplied()
    {
        var policy = Policy(
            new ObjectRules(
                HiddenObjects: new[] { "audit_log" },
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/*" },
                    AllowedMethods: new[] { "POST" })),
            canInsert: true);

        var result = EnforcementEngine.ValidateHttpWrite(
            "POST",
            "/anything",
            new Dictionary<string, object?> { ["a"] = 1 },
            policy,
            objectName: "audit_log");

        result.Reason.Should().Be("object is hidden");
    }

    [Fact]
    public void ValidateHttpWrite_PassesTheTargetRowToTheRowCheck()
    {
        var policy = Policy(
            new ObjectRules(
                RowFilters: new[] { new RowFilter("region", FilterOperator.Equals, Value: "us-east") },
                EndpointRules: new EndpointRules(
                    AllowedEndpoints: new[] { "/*" },
                    AllowedMethods: new[] { "DELETE" })),
            canDelete: true);

        var permitted = EnforcementEngine.ValidateHttpWrite(
            "DELETE", "/patients/1", null, policy, null,
            new WriteValidationOptions(
                TargetRow: new Dictionary<string, object?> { ["region"] = "us-east" }));
        var refused = EnforcementEngine.ValidateHttpWrite(
            "DELETE", "/patients/1", null, policy, null,
            new WriteValidationOptions(
                TargetRow: new Dictionary<string, object?> { ["region"] = "eu-west" }));

        permitted.Allowed.Should().BeTrue();
        refused.Reason.Should().Be("target row not permitted");
    }

    [Fact]
    public void ValidateHttpWrite_PutFullReplace_IsNotDefeatedByCallerSuppliedOptions()
    {
        // The replace flag is imposed by the method, not taken from the caller: an
        // integrator who passes WriteValidationOptions with FullReplace left at its default
        // must not thereby downgrade a PUT to a partial update. Otherwise supplying a target
        // row -- the safe, encouraged thing to do -- would silently relax the field checks.
        var policy = Policy(AllowWriteMethods(), canUpdate: true);

        var result = EnforcementEngine.ValidateHttpWrite(
            "PUT",
            "/patients/1",
            new Dictionary<string, object?> { ["full_name"] = "x" },
            policy,
            null,
            new WriteValidationOptions(FullReplace: false));

        result.Allowed.Should().BeFalse();
        result.Reason.Should().Be("field is read-only: patients.created_at");
    }

    // -- Section 4.3: readOnlyFields is a write control only --
    //
    // A field listed there is returned normally, subject to hidden/allowed/masking rules
    // like any other. Two doc comments in a prior implementation contradicted each other on
    // this point, so it is pinned here from both sides.

    private static readonly EffectivePolicy ReadOnlyFieldsPolicy = Policy(
        new ObjectRules(FieldRules: new FieldRules(
            ReadOnlyFields: new[] { "created_at", "id" })),
        canUpdate: true);

    [Fact]
    public void ApplyResultPipeline_ReturnsAReadOnlyField()
    {
        var rows = new List<Dictionary<string, object?>>
        {
            new() { ["id"] = 1, ["created_at"] = "2026-01-01", ["full_name"] = "Alice" }
        };

        var result = EnforcementEngine.ApplyResultPipeline(rows, ReadOnlyFieldsPolicy);

        result.Should().BeEquivalentTo(rows);
    }

    [Fact]
    public void ValidateFieldAccess_DoesNotDenyAReadOnlyField()
    {
        var result = EnforcementEngine.ValidateFieldAccess(
            new[] { "id", "created_at" }, ReadOnlyFieldsPolicy);

        result.Denied.Should().BeEmpty();
        result.Allowed.Should().BeEquivalentTo("id", "created_at");
    }

    [Fact]
    public void ValidateWrite_DeniesTheSameFieldOnTheWritePath()
    {
        // The asymmetry is the whole feature: readable, not writable.
        var result = EnforcementEngine.ValidateWrite(
            WriteOperation.Update,
            null,
            new Dictionary<string, object?> { ["created_at"] = "x" },
            ReadOnlyFieldsPolicy);

        result.Reason.Should().Be("field is read-only: created_at");
    }

    // -- Fixtures --

    private static EffectivePolicy Policy(
        ObjectRules? objectRules,
        bool canInsert = false,
        bool canUpdate = false,
        bool canDelete = false,
        bool readOnly = false) =>
        new(Version: "1.0",
            UserId: "u",
            TenantId: "t",
            SourceConnectionId: "db:write-enforcement:patients",
            ResolvedAt: null,
            ExpiresAt: null,
            SourceProfiles: new[] { "write-enforcement" },
            Permissions: new PolicyPermissions(
                CanQuery: true,
                CanInsert: canInsert ? true : null,
                CanUpdate: canUpdate ? true : null,
                CanDelete: canDelete ? true : null,
                CanExport: false,
                ReadOnly: readOnly),
            ObjectRules: objectRules);

    private sealed record DemographicsDto(string Ssn);

    private sealed record PatientDto(string FullName, DemographicsDto Demographics);

    private sealed class CyclicNode
    {
        public string Name { get; set; } = "";
        public CyclicNode? Self { get; set; }
    }

    private sealed class ThrowingGetterDto
    {
        public string Ssn => throw new InvalidOperationException("not readable");
    }
}
