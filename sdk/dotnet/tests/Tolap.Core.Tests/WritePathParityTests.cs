using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Cross-SDK parity for the write path (connector-spec.md section 4).
/// </summary>
/// <remarks>
/// <para>
/// One case corpus — operation x policy x payload x target row -&gt; allowed + reason —
/// asserted with byte-identical expected outcomes in all three SDKs. The counterparts are:
/// </para>
/// <list type="bullet">
///   <item><description>Python: <c>tests/test_write_path_parity.py</c> (the reference
///     ordering)</description></item>
///   <item><description>TypeScript:
///     <c>packages/core/tests/write-path-parity.test.ts</c></description></item>
/// </list>
/// <para>
/// The three tables must stay identical case-for-case, and this file follows the Python
/// ordering row for row so a diff of the three is readable.
/// </para>
/// <para>
/// <b>The reason strings are asserted, not just the boolean.</b> They are the contract
/// integrators log and branch on, and each one names a different policy edit that would
/// unblock the caller: <c>insert not permitted</c> is fixed by granting <c>canInsert</c>,
/// <c>read-only policy</c> by clearing <c>readOnly</c>, <c>field is read-only: x</c> by
/// removing <c>x</c> from <c>readOnlyFields</c>, and <c>write target unverifiable</c> by
/// reading the target row first. An integrator who cannot tell them apart cannot tell which
/// edit to make.
/// </para>
/// <para>
/// A corpus of this shape is what catches divergence: a prior cross-SDK table exposed a real
/// fail-open that no single-SDK test had found, because every SDK's own suite asserted the
/// behaviour that SDK happened to implement.
/// </para>
/// </remarks>
public class WritePathParityTests
{
    private static EffectivePolicy Policy(
        PolicyPermissions permissions,
        ObjectRules? objectRules = null) =>
        new(Version: "1.0",
            UserId: "parity-user",
            TenantId: "parity-tenant",
            SourceConnectionId: "db:parity:patients",
            ResolvedAt: DateTimeOffset.Parse(
                "2026-01-15T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
            ExpiresAt: DateTimeOffset.Parse(
                "2026-01-15T11:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
            SourceProfiles: new[] { "write-path-parity" },
            Permissions: permissions,
            ObjectRules: objectRules);

    // -- The shared parity policies. Identical field-for-field in all three SDKs. --

    /// <summary>Every write granted, with object rules, field rules and a row filter.</summary>
    private static readonly EffectivePolicy FullWrite = Policy(
        new PolicyPermissions(
            CanQuery: true, CanInsert: true, CanUpdate: true, CanDelete: true,
            ReadOnly: false),
        new ObjectRules(
            AllowedObjects: new[] { "patients", "encounters" },
            HiddenObjects: new[] { "audit_log" },
            FieldRules: new FieldRules(
                HiddenFields: new[] { "patients.ssn" },
                ReadOnlyFields: new[] { "patients.created_at" },
                MaskedFields: new[] { new MaskingRule("patients.email", MaskType.Hash) }),
            RowFilters: new[]
            {
                new RowFilter("region", FilterOperator.In, Values: new object[] { "us-east" })
            }));

    /// <summary>
    /// A policy authored before writes existed: it grants reads and says nothing about writes.
    /// Every write must be denied, which is the whole point of the false default.
    /// </summary>
    private static readonly EffectivePolicy Silent =
        Policy(new PolicyPermissions(CanQuery: true));

    /// <summary>
    /// Contradictory on purpose: all three write permissions granted <i>and</i> readOnly set.
    /// The ceiling has to win (connector-spec.md section 4.1).
    /// </summary>
    private static readonly EffectivePolicy ReadOnlyCeiling = Policy(
        new PolicyPermissions(
            CanQuery: true, CanInsert: true, CanUpdate: true, CanDelete: true,
            ReadOnly: true));

    /// <summary>
    /// Insert and update granted, delete omitted; an allowedFields allow-list and no row
    /// filters, so the row check has nothing to verify and must not deny.
    /// </summary>
    private static readonly EffectivePolicy AllowList = Policy(
        new PolicyPermissions(
            CanQuery: true, CanInsert: true, CanUpdate: true, ReadOnly: false),
        new ObjectRules(FieldRules: new FieldRules(
            AllowedFields: new[] { "full_name", "status" })));

    /// <summary>
    /// An EMPTY allowedFields, which denies every field (canonical spec section 3) rather than
    /// lifting the restriction. The most restrictive possible field rule.
    /// </summary>
    private static readonly EffectivePolicy EmptyAllowList = Policy(
        new PolicyPermissions(
            CanQuery: true, CanInsert: true, ReadOnly: false),
        new ObjectRules(FieldRules: new FieldRules(AllowedFields: Array.Empty<string>())));

    /// <summary>
    /// canInsert without canUpdate, so an upsert — which needs both — is denied on the half it
    /// lacks (connector-spec.md section 8's safe intersection).
    /// </summary>
    private static readonly EffectivePolicy InsertOnly = Policy(
        new PolicyPermissions(
            CanQuery: true, CanInsert: true, ReadOnly: false));

    private static readonly Dictionary<string, EffectivePolicy> Policies = new()
    {
        ["full-write"] = FullWrite,
        ["silent"] = Silent,
        ["read-only-ceiling"] = ReadOnlyCeiling,
        ["allow-list"] = AllowList,
        ["empty-allow-list"] = EmptyAllowList,
        ["insert-only"] = InsertOnly
    };

    private static Dictionary<string, object?> Payload(params (string Key, object? Value)[] pairs)
    {
        var record = new Dictionary<string, object?>();
        foreach (var (key, value) in pairs) record[key] = value;
        return record;
    }

    /// <summary>
    /// One corpus row. <c>TargetRow</c> null means the caller supplied none.
    /// </summary>
    public sealed record ParityCase(
        string Id,
        string Policy,
        WriteOperation Operation,
        string? ObjectName,
        Dictionary<string, object?>? Payload,
        Dictionary<string, object?>? TargetRow,
        bool FullReplace,
        bool Allowed,
        string? Reason);

    /// <summary>The corpus, in the same order as the Python and TypeScript tables.</summary>
    public static readonly ParityCase[] Corpus =
    {
        // -- Check 1: operation permission, then the readOnly ceiling --
        new("silent-insert", "silent", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, false, "insert not permitted"),
        new("silent-update", "silent", WriteOperation.Update, "patients", Payload(("full_name", "x")), null, false, false, "update not permitted"),
        new("silent-delete", "silent", WriteOperation.Delete, "patients", null, null, false, false, "delete not permitted"),
        // An upsert reports the first permission it lacks, so the reason names insert.
        new("silent-upsert", "silent", WriteOperation.Upsert, "patients", Payload(("full_name", "x")), null, false, false, "insert not permitted"),
        // The ceiling overrides all three grants, and reports itself rather than a permission
        // -- clearing readOnly is the edit that unblocks the caller.
        new("ceiling-insert", "read-only-ceiling", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, false, "read-only policy"),
        new("ceiling-update", "read-only-ceiling", WriteOperation.Update, "patients", Payload(("full_name", "x")), null, false, false, "read-only policy"),
        new("ceiling-delete", "read-only-ceiling", WriteOperation.Delete, "patients", null, null, false, false, "read-only policy"),
        new("ceiling-upsert", "read-only-ceiling", WriteOperation.Upsert, "patients", Payload(("full_name", "x")), null, false, false, "read-only policy"),
        // The safe intersection: insert alone is not enough for an upsert.
        new("insert-only-upsert", "insert-only", WriteOperation.Upsert, "patients", Payload(("full_name", "x")), null, false, false, "update not permitted"),
        new("insert-only-insert", "insert-only", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, true, null),
        new("allow-list-delete", "allow-list", WriteOperation.Delete, "patients", null, null, false, false, "delete not permitted"),

        // -- Check 2: the target object --
        new("hidden-object", "full-write", WriteOperation.Insert, "audit_log", Payload(("full_name", "x")), null, false, false, "object is hidden"),
        new("object-not-allowed", "full-write", WriteOperation.Insert, "billing_internal", Payload(("full_name", "x")), null, false, false, "object not in allowed set"),
        // A hidden object is not writable even for a delete whose target row would pass.
        new("hidden-object-delete", "full-write", WriteOperation.Delete, "audit_log", null, Payload(("region", "us-east")), false, false, "object is hidden"),
        new("allowed-object", "full-write", WriteOperation.Insert, "encounters", Payload(("full_name", "x")), null, false, true, null),
        // No object supplied skips the check rather than denying: an integrator who cannot
        // name the object still gets the other three checks.
        new("no-object-name", "full-write", WriteOperation.Insert, null, Payload(("full_name", "x")), null, false, true, null),

        // -- Check 3: every field in the payload --
        new("insert-plain-field", "full-write", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, true, null),
        // A field the caller cannot read, it cannot write. The reason names the payload key as
        // the caller spelled it -- safe, since the caller supplied it.
        new("hidden-field-bare", "full-write", WriteOperation.Insert, "patients", Payload(("ssn", "1")), null, false, false, "field is hidden: ssn"),
        // Bidirectional, case-insensitive matching: a rule of patients.ssn blocks a key of
        // PATIENTS.SSN and of ssn alike (connector-spec.md section 3.2).
        new("hidden-field-qualified-upper", "full-write", WriteOperation.Insert, "patients", Payload(("PATIENTS.SSN", "1")), null, false, false, "field is hidden: PATIENTS.SSN"),
        // The readOnlyFields rule is written qualified; the payload key is bare.
        new("read-only-field", "full-write", WriteOperation.Insert, "patients", Payload(("created_at", "2026-01-01")), null, false, false, "field is read-only: created_at"),
        // Nested keys are reached at every depth, and the walk records the container key first
        // -- so the reported field is the offending leaf, not its parent.
        new("nested-hidden-field", "full-write", WriteOperation.Insert, "patients", Payload(("demographics", Payload(("ssn", "1")))), null, false, false, "field is hidden: ssn"),
        // Fail closed on the WHOLE write: a payload mixing a writable and an unwritable field
        // is rejected outright, never stripped down to the writable part.
        new("mixed-payload-rejected-whole", "full-write", WriteOperation.Update, "patients", Payload(("status", "active"), ("ssn", "1")), Payload(("region", "us-east")), false, false, "field is hidden: ssn"),
        // readOnlyFields has NO effect on reads: a masked field is still writable here, and
        // this row exists to pin that maskedFields is not a write restriction.
        new("masked-field-is-writable", "full-write", WriteOperation.Insert, "patients", Payload(("email", "a@b.c")), null, false, true, null),
        new("allow-list-permits-listed", "allow-list", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, true, null),
        new("allow-list-denies-unlisted", "allow-list", WriteOperation.Insert, "patients", Payload(("full_name", "x"), ("region", "us-east")), null, false, false, "field not in allowed set: region"),
        // [] denies every field rather than lifting the restriction.
        new("empty-allow-list-denies", "empty-allow-list", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, false, "field not in allowed set: full_name"),
        // An empty payload names no fields, so the field check has nothing to reject. The
        // permission and object checks still ran and passed.
        new("empty-payload-under-empty-allow-list", "empty-allow-list", WriteOperation.Insert, "patients", Payload(), null, false, true, null),

        // -- Check 4: row filters against the update/delete target --
        new("update-matching-row", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), Payload(("region", "us-east")), false, true, null),
        // A caller must not modify a row it could not have selected. The reason names no value
        // -- section 4.4 permits naming a payload field, never a row value.
        new("update-non-matching-row", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), Payload(("region", "eu-west")), false, false, "target row not permitted"),
        // A row missing the filtered field fails closed, exactly as it would on a read.
        new("update-row-missing-field", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), Payload(("id", 1)), false, false, "target row not permitted"),
        // No target row and filters present is UNVERIFIABLE, not an allow. This is the
        // fail-open a naive implementation reaches by treating "nothing to check" as pass.
        new("update-no-target-row", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), null, false, false, "write target unverifiable"),
        new("delete-no-target-row", "full-write", WriteOperation.Delete, "patients", null, null, false, false, "write target unverifiable"),
        // The Python and TypeScript corpora distinguish an OMITTED target row from an
        // EXPLICIT null one, because those SDKs reach two different branches (a sentinel
        // and a not-a-record guard) and a corpus spelling it only one way left the other
        // unexercised -- deleting the sentinel branch, a textbook "no target row means
        // nothing to check" fail-open, kept their tables green. .NET has no sentinel:
        // WriteValidationOptions.TargetRow is a nullable reference and null is the single
        // spelling of "the caller supplied none", so these two rows are the same code path
        // as the two above. They are carried anyway to keep the three tables aligned
        // case-for-case, which is what makes a diff of them readable.
        new("update-explicit-null-target", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), null, false, false, "write target unverifiable"),
        new("delete-explicit-null-target", "full-write", WriteOperation.Delete, "patients", null, null, false, false, "write target unverifiable"),
        new("delete-matching-row", "full-write", WriteOperation.Delete, "patients", null, Payload(("region", "us-east")), false, true, null),
        new("delete-non-matching-row", "full-write", WriteOperation.Delete, "patients", null, Payload(("region", "eu-west")), false, false, "target row not permitted"),
        new("upsert-matching-row", "full-write", WriteOperation.Upsert, "patients", Payload(("full_name", "x")), Payload(("region", "us-east")), false, true, null),
        new("upsert-no-target-row", "full-write", WriteOperation.Upsert, "patients", Payload(("full_name", "x")), null, false, false, "write target unverifiable"),
        // An insert has no pre-existing target, so the row check does not apply to it -- this
        // is why insert-plain-field above passes with no target row.
        new("insert-ignores-target-row", "full-write", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, false, true, null),
        // A policy with no row filters has nothing to verify, so an absent target row is not
        // unverifiable -- the check is vacuous rather than fail-closed.
        new("no-filters-no-target-row", "allow-list", WriteOperation.Update, "patients", Payload(("status", "active")), null, false, true, null),

        // -- Ordering: the field check precedes the row check --
        // Both would deny; the field reason wins because check 3 runs before check 4.
        new("field-denial-precedes-row-denial", "full-write", WriteOperation.Update, "patients", Payload(("created_at", "x")), Payload(("region", "eu-west")), false, false, "field is read-only: created_at"),
        // And the permission check precedes everything: this payload and object would both
        // deny under full-write, but under `silent` the permission reason is reported.
        new("permission-denial-precedes-all", "silent", WriteOperation.Insert, "audit_log", Payload(("ssn", "1")), null, false, false, "insert not permitted"),

        // -- The full-resource-replace rule (connector-spec.md section 6) --
        // Identical payload, identical policy, identical target row: the ONLY difference is
        // that a replace overwrites every field of the resource, so omitting a protected field
        // is still an attempt to overwrite it with absent.
        new("partial-update-omitting-protected-field", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), Payload(("region", "us-east")), false, true, null),
        new("full-replace-omitting-protected-field", "full-write", WriteOperation.Update, "patients", Payload(("full_name", "x")), Payload(("region", "us-east")), true, false, "field is hidden: patients.ssn"),
        // A replace under a policy with no protected fields adds nothing, so it behaves exactly
        // like a partial update.
        new("full-replace-with-no-protected-fields", "insert-only", WriteOperation.Insert, "patients", Payload(("full_name", "x")), null, true, true, null)
    };

    public static IEnumerable<object[]> CorpusCases()
        => Corpus.Select(c => new object[] { c });

    [Theory]
    [MemberData(nameof(CorpusCases))]
    public void WritePath_MatchesCrossSdkCorpus(ParityCase testCase)
    {
        var result = EnforcementEngine.ValidateWrite(
            testCase.Operation,
            testCase.ObjectName,
            testCase.Payload,
            Policies[testCase.Policy],
            // A null TargetRow is the corpus's spelling of "the caller supplied none", which
            // must be unverifiable rather than an allow.
            new WriteValidationOptions(
                TargetRow: testCase.TargetRow,
                FullReplace: testCase.FullReplace));

        result.Allowed.Should().Be(testCase.Allowed, $"{testCase.Id}: {result.Reason}");
        result.Reason.Should().Be(testCase.Reason, testCase.Id);
    }

    [Fact]
    public void Corpus_CoversEveryDocumentedWriteDenialReason()
    {
        // Without this, a reason could be dropped from the implementation *and* from the table
        // together and the parity suite would keep passing -- the corpus would agree with
        // itself across three SDKs while none of them enforced the rule.
        var documented = new[]
        {
            "insert not permitted",
            "update not permitted",
            "delete not permitted",
            "read-only policy",
            "field is hidden",
            "field is read-only",
            "field not in allowed set",
            "target row not permitted",
            "write target unverifiable",
            // Not from section 4.4 but part of the same contract: the object rules' reasons
            // (section 3.3) are reachable on the write path too.
            "object is hidden",
            "object not in allowed set"
        };
        // A parameterized reason is compared on its prefix; the field name after the colon is
        // the caller's own payload key.
        var seen = Corpus
            .Where(c => c.Reason is not null)
            .Select(c => c.Reason!.Split(':')[0])
            .ToHashSet(StringComparer.Ordinal);

        seen.Should().Contain(documented);
    }

    [Fact]
    public void Corpus_CaseIdsAreUnique()
    {
        // Duplicate ids would make a cross-SDK diff of the three tables unreadable.
        Corpus.Select(c => c.Id).Should().OnlyHaveUniqueItems();
    }
}
