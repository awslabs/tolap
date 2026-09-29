using Tolap.Core;
using FluentAssertions;
using Xunit;

namespace Tolap.Examples;

[Collection(ConsoleCapture.Name)]
public class PolicyTourExampleTests
{
    /// <summary>
    /// Every line of the tour that carries a result, in order. The Python and TypeScript suites
    /// assert this same list, so the three languages are held to one output.
    /// </summary>
    private static readonly string[] ExpectedLines =
    [
        "--- Masks: one rule per mask type ------------------------------------",
        "  id         no rule                 7                       7",
        "  name       partial showFirst 1     Alice Nguyen            A***********",
        "  phone      partial showLast 4 '#'  555-867-5309            ########5309",
        "  card       partial first 4 last 4  4111111111111111        4111********1111",
        "  address    full                    12 Elm Street           *************",
        "  email      hash sha256             alice@example.com       ff8d9819fc0e12bf",
        "  mrn        hash sha512             MRN-00417               972f27e06cb47c3e",
        "  member_id  hash blake2b            M-99812                 eeeb704b805ffb7c",
        "  notes      null                    allergic to penicillin  null",
        "  dob        redact                  1979-04-12              [REDACTED]",
        "  ssn        hiddenFields            111-22-3333             (dropped)",
        "--- Fields: allowedFields next to hiddenFields -----------------------",
        "  the source returns    id, name, region, dob, notes, ssn",
        "  allowedFields [id, name, region]",
        "    returns             id, name, region",
        "      asks for [id, ssn]            DENY    denied fields: ssn",
        "  hiddenFields [ssn, notes]",
        "    returns             id, name, region, dob",
        "      asks for [id, ssn]            DENY    denied fields: ssn",
        "--- Objects: allowedObjects [patients, encounters, billing_*] --------",
        "                       hiddenObjects [billing_internal]",
        "  patients                          ALLOW",
        "  encounters                        ALLOW",
        "  billing_invoices                  ALLOW",
        "  billing_internal                  DENY    object is hidden",
        "  audit_log                         DENY    object not in allowed set",
        "--- Row filters: one operator at a time over rows 1-6 ----------------",
        "  region equals us-east             ids 1, 4, 6",
        "  region notEquals us-east          ids 2, 3, 5",
        "  region in [us-east, us-west]      ids 1, 2, 4, 6",
        "  region notIn [us-east, us-west]   ids 3, 5",
        "  age greaterThan 40                ids 3, 4, 5",
        "  age lessThanOrEqual 29            ids 2, 6",
        "  age between [30, 52]              ids 1, 3, 5",
        "  email contains @clinic.           ids 1, 2, 4, 6",
        "  ward startsWith cardio            ids 1, 3, 6",
        "  email like %@partner.net          ids 3, 5",
        "  code matches PT-[0-9]{3}          ids 1, 2, 5",
        "  discharged_at isNull              ids 1, 3, 5",
        "  discharged_at isNotNull           ids 2, 4",
        "--- Permissions ------------------------------------------------------",
        "  canQuery false",
        "      query patients                DENY    query not permitted",
        "  canInsert true, readOnly true",
        "      insert                        DENY    read-only policy",
        "  canInsert, canUpdate, readOnly false; mrn read-only; region us-east",
        "      insert                        ALLOW",
        "      insert setting mrn            DENY    field is read-only: mrn",
        "      update a us-east row          ALLOW",
        "      update an eu-west row         DENY    target row not permitted",
        "      delete                        DENY    delete not permitted",
        "--- Limits over seven search hits ------------------------------------",
        "  scores  d1 0.92  d2 0.75  d3 0.60  d4 0.88  d5 0.81  d6 none  d7 0.99",
        "  sizes   d1 1200  d2 4096  d3 800   d4 2048  d5 none  d6 500   d7 100",
        "  minSimilarityScore 0.75           d1, d2, d4, d5, d7",
        "  maxObjectSizeBytes 2048           d1, d3, d4, d6, d7",
        "  maxResults 2                      d1, d2",
        "  all three                         d1, d4",
        "--- Merging: a user policy and a group policy ------------------------",
        "  resolved from    analyst-direct, clinicians-group",
        "  allowedObjects   intersected",
        "    analyst-direct     encounters, labs, patients",
        "    clinicians-group   billing, encounters, patients",
        "    merged             encounters, patients",
        "  hiddenFields     unioned",
        "    analyst-direct     ssn",
        "    clinicians-group   notes",
        "    merged             notes, ssn",
        "  phone mask       the most restrictive",
        "    analyst-direct     partial",
        "    clinicians-group   redact",
        "    merged             redact",
        "  rowFilters       all of them apply",
        "    analyst-direct     region in",
        "    clinicians-group   age greaterThanOrEqual",
        "    merged             region in, age greaterThanOrEqual",
        "  maxResults       the lowest",
        "    analyst-direct     100",
        "    clinicians-group   25",
        "    merged             25",
        "  canInsert        only if every policy grants it",
        "    analyst-direct     no",
        "    clinicians-group   yes",
        "    merged             no",
        "  readOnly         if any policy sets it",
        "    analyst-direct     yes",
        "    clinicians-group   no",
        "    merged             yes",
        "    id=1  region=us-east  age=34  phone=[REDACTED]",
        "    id=4  region=us-east  age=65  phone=[REDACTED]",
        "  labs                              DENY    object not in allowed set",
        "  billing                           DENY    object not in allowed set",
        "  insert                            DENY    insert not permitted",
    ];

    private static List<Dictionary<string, object?>> IdsOnly(params int[] ids) =>
        ids.Select(id => new Dictionary<string, object?> { ["id"] = id }).ToList();

    [Fact]
    public void EveryMaskType_ChangesTheValue_AndAHiddenFieldIsDropped()
    {
        var masked = PolicyTourExample.Enforce(PolicyTourExample.MaskPolicy(), [PolicyTourExample.Patient()])[0];

        masked["id"].Should().Be(7);
        masked["name"].Should().Be("A***********");
        masked["phone"].Should().Be("########5309");
        masked["card"].Should().Be("4111********1111");
        masked["address"].Should().Be("*************");
        masked["email"].Should().Be("ff8d9819fc0e12bf");
        masked["mrn"].Should().Be("972f27e06cb47c3e");
        masked["member_id"].Should().Be("eeeb704b805ffb7c");
        masked.Should().ContainKey("notes");
        masked["notes"].Should().BeNull();
        masked["dob"].Should().Be("[REDACTED]");
        masked.Should().NotContainKey("ssn");
    }

    [Fact]
    public void AllowedFields_KeepOnlyTheNamed_AndHiddenFields_DropOnlyTheNamed()
    {
        var source = new Dictionary<string, object?>
        {
            ["id"] = 1, ["name"] = "n", ["region"] = "r", ["dob"] = "d", ["notes"] = "x", ["ssn"] = "s",
        };

        PolicyTourExample.Enforce(PolicyTourExample.AllowedFieldsPolicy(), [source])[0].Keys
            .Should().BeEquivalentTo(["id", "name", "region"]);
        PolicyTourExample.Enforce(PolicyTourExample.HiddenFieldsPolicy(), [source])[0].Keys
            .Should().BeEquivalentTo(["id", "name", "region", "dob"]);
    }

    [Theory]
    [InlineData("patients", true, null)]
    [InlineData("billing_invoices", true, null)]
    [InlineData("billing_internal", false, "object is hidden")]
    [InlineData("audit_log", false, "object not in allowed set")]
    public void HiddenObjects_WinOverAllowedObjects(string name, bool allowed, string? reason)
    {
        var result = PolicyTourExample.Check(PolicyTourExample.ObjectPolicy(), objectName: name);

        result.Allowed.Should().Be(allowed);
        if (reason is not null)
            result.Reason.Should().Be(reason);
    }

    [Theory]
    [InlineData("region equals us-east", new[] { 1, 4, 6 })]
    [InlineData("region notEquals us-east", new[] { 2, 3, 5 })]
    [InlineData("region in [us-east, us-west]", new[] { 1, 2, 4, 6 })]
    [InlineData("region notIn [us-east, us-west]", new[] { 3, 5 })]
    [InlineData("age greaterThan 40", new[] { 3, 4, 5 })]
    [InlineData("age lessThanOrEqual 29", new[] { 2, 6 })]
    [InlineData("age between [30, 52]", new[] { 1, 3, 5 })]
    [InlineData("email contains @clinic.", new[] { 1, 2, 4, 6 })]
    [InlineData("ward startsWith cardio", new[] { 1, 3, 6 })]
    [InlineData("email like %@partner.net", new[] { 3, 5 })]
    [InlineData("code matches PT-[0-9]{3}", new[] { 1, 2, 5 })]
    [InlineData("discharged_at isNull", new[] { 1, 3, 5 })]
    [InlineData("discharged_at isNotNull", new[] { 2, 4 })]
    public void EachRowFilter_KeepsTheExpectedRows(string label, int[] ids)
    {
        var rule = PolicyTourExample.Filters.Single(f => f.Label == label).Rule;

        PolicyTourExample.Enforce(PolicyTourExample.FilterPolicy(rule), PolicyTourExample.Rows())
            .Select(r => r["id"]).Should().Equal(ids.Cast<object>());
    }

    [Fact]
    public void CanQueryFalse_AndReadOnly_Refuse()
    {
        var query = PolicyTourExample.Check(PolicyTourExample.QueryDeniedPolicy(), objectName: "patients");
        query.Allowed.Should().BeFalse();
        query.Reason.Should().Be("query not permitted");

        var insert = PolicyTourExample.CheckWrite(
            PolicyTourExample.ReadOnlyPolicy(), WriteOperation.Insert, new() { ["name"] = "Bo" });
        insert.Allowed.Should().BeFalse();
        insert.Reason.Should().Be("read-only policy");
    }

    [Fact]
    public void GrantedWrites_StillMeetTheFieldAndRowRules()
    {
        var writer = PolicyTourExample.WriterPolicy();
        var east = new Dictionary<string, object?> { ["id"] = 1, ["region"] = "us-east" };
        var west = new Dictionary<string, object?> { ["id"] = 3, ["region"] = "eu-west" };

        PolicyTourExample.CheckWrite(writer, WriteOperation.Insert, new() { ["name"] = "Bo", ["region"] = "us-east" })
            .Allowed.Should().BeTrue();
        PolicyTourExample.CheckWrite(writer, WriteOperation.Insert, new() { ["mrn"] = "MRN-1" })
            .Reason.Should().Be("field is read-only: mrn");
        PolicyTourExample.CheckWrite(writer, WriteOperation.Update, new() { ["name"] = "Bo" }, east)
            .Allowed.Should().BeTrue();
        PolicyTourExample.CheckWrite(writer, WriteOperation.Update, new() { ["name"] = "Bo" }, west)
            .Reason.Should().Be("target row not permitted");
        PolicyTourExample.CheckWrite(writer, WriteOperation.Delete, new(), east)
            .Reason.Should().Be("delete not permitted");
    }

    [Theory]
    [InlineData("minSimilarityScore 0.75", new[] { "d1", "d2", "d4", "d5", "d7" })]
    [InlineData("maxObjectSizeBytes 2048", new[] { "d1", "d3", "d4", "d6", "d7" })]
    [InlineData("maxResults 2", new[] { "d1", "d2" })]
    [InlineData("all three", new[] { "d1", "d4" })]
    public void Limits_KeepTheExpectedHits(string label, string[] ids)
    {
        var limits = PolicyTourExample.Limits.Single(l => l.Label == label).Limits;

        PolicyTourExample.Enforce(PolicyTourExample.Policy(limits: limits), PolicyTourExample.Documents())
            .Select(r => r["id"]).Should().Equal(ids);
    }

    [Fact]
    public void Merging_TheMostRestrictiveRuleWins()
    {
        var merged = PolicyTourExample.MergedPolicy();
        var rules = merged.ObjectRules!;

        merged.SourceProfiles.Should().Equal("analyst-direct", "clinicians-group");
        rules.AllowedObjects.Should().BeEquivalentTo(["patients", "encounters"]);
        rules.FieldRules!.HiddenFields.Should().BeEquivalentTo(["ssn", "notes"]);
        rules.FieldRules.MaskedFields!.Single(m => m.Field == "phone").MaskType.Should().Be(MaskType.Redact);
        rules.RowFilters.Should().HaveCount(2);
        merged.Limits!.MaxResults.Should().Be(25);
        merged.Permissions.CanInsert.Should().NotBe(true);
        merged.Permissions.ReadOnly.Should().BeTrue();

        var rows = PolicyTourExample.Enforce(merged, PolicyTourExample.MergeRows());
        rows.Select(r => r["id"]).Should().Equal(1, 4);
        rows.Should().OnlyContain(r => !r.ContainsKey("ssn") && !r.ContainsKey("notes"));
        rows.Should().OnlyContain(r => Equals(r["phone"], "[REDACTED]"));
    }

    [Fact]
    public async Task TheExampleRunsClean_AndPrintsTheLinesTheOtherTwoLanguagesPrint()
    {
        // RunExampleAsync throws if a mask or the merge lets a hidden field through, so this
        // covers those paths too.
        var original = Console.Out;
        var captured = new StringWriter();
        try
        {
            Console.SetOut(captured);
            await PolicyTourExample.RunExampleAsync();
        }
        finally
        {
            Console.SetOut(original);
        }

        var results = captured.ToString().Split(Environment.NewLine)
            .Where(l => l.StartsWith("  ", StringComparison.Ordinal) || l.StartsWith("---", StringComparison.Ordinal));

        results.Should().Equal(ExpectedLines);
    }
}
