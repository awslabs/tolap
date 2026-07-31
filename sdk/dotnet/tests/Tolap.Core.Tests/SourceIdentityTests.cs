using FluentAssertions;
using Xunit;

namespace Tolap.Core.Tests;

/// <summary>
/// Source identity parsing (connector-spec.md section 1).
/// </summary>
/// <remarks>
/// <para>
/// <c>category:namespace:name</c>, where the category is one of a fixed set of four. The
/// parser exists because the category decides which wrapper enforces a source, and that
/// decision must be driven by the <i>signed</i> identifier rather than by unsigned
/// configuration — a category that could be flipped from <c>db</c> to <c>api</c> would select
/// the wrapper that enforces the other category's rules, and <c>endpointRules</c> do not
/// constrain a SQL query.
/// </para>
/// <para>
/// So the rejection cases below matter as much as the accepting ones: every one of them
/// returns null, and every caller in this SDK treats null as a refusal to produce a tool. A
/// parser that guessed would guess a wrapper.
/// </para>
/// <para>
/// The Python and TypeScript suites cover the same corpus (<c>test_source_identity.py</c>,
/// <c>source-identity.test.ts</c>).
/// </para>
/// </remarks>
public class SourceIdentityTests
{
    [Theory]
    [InlineData("db", SourceCategory.Db)]
    [InlineData("api", SourceCategory.Api)]
    [InlineData("kb", SourceCategory.Kb)]
    [InlineData("storage", SourceCategory.Storage)]
    public void AcceptsEachCategory(string segment, SourceCategory expected)
    {
        SourceIdentityParser.Parse($"{segment}:production:patients")
            .Should().Be(new SourceIdentity(expected, "production", "patients"));
    }

    [Theory]
    [InlineData("graph:production:people")]
    [InlineData("DATABASE:production:patients")]
    public void RejectsACategoryOutsideTheFixedSet(string identifier)
    {
        // Section 1 calls the set fixed and section 10 makes adding one a breaking change, so
        // an unknown category is not a forward-compatible extension point — it is a source no
        // wrapper knows how to enforce.
        SourceIdentityParser.Parse(identifier).Should().BeNull();
    }

    [Theory]
    [InlineData("DB:production:patients", SourceCategory.Db)]
    [InlineData("Api:internal:orders", SourceCategory.Api)]
    public void MatchesTheCategoryCaseInsensitively(string identifier, SourceCategory expected)
    {
        // Consistent with the case-insensitive sourcePatterns matching of the canonical spec
        // section 10: the same identifier must resolve to the same category regardless of how
        // it was cased upstream.
        SourceIdentityParser.Parse(identifier)!.Category.Should().Be(expected);
    }

    [Fact]
    public void LeavesNamespaceAndNameVerbatim()
    {
        // Both are opaque to TOLAP (section 1). Folding their case here would make the parser
        // claim the identifier says something it does not.
        var parsed = SourceIdentityParser.Parse("db:Production:Patient_Records")!;

        parsed.Namespace.Should().Be("Production");
        parsed.Name.Should().Be("Patient_Records");
    }

    [Theory]
    // Two segments is the documented authoring mistake in reverse.
    [InlineData("db:production")]
    [InlineData("db")]
    // Not silently truncated to the first three: a fourth segment means something the spec
    // does not define, and treating it as a three-segment source would enforce a policy the
    // author did not write.
    [InlineData("db:production:patients:extra")]
    public void RejectsAnythingOtherThanThreeSegments(string identifier)
    {
        SourceIdentityParser.Parse(identifier).Should().BeNull();
    }

    [Theory]
    [InlineData("db::")]
    [InlineData("db::patients")]
    [InlineData("db:production:")]
    [InlineData(":production:patients")]
    public void RejectsAnEmptySegment(string identifier)
    {
        // `db::` has three segments but names no source, and it would match a `db:*:*`
        // pattern — so a policy scoped to that pattern would appear to govern it.
        SourceIdentityParser.Parse(identifier).Should().BeNull();
    }

    [Fact]
    public void RejectsEmptyAndNull()
    {
        SourceIdentityParser.Parse("").Should().BeNull();
        SourceIdentityParser.Parse(null).Should().BeNull();
    }

    [Fact]
    public void CategoryOf_ReturnsJustTheCategory()
    {
        SourceIdentityParser.CategoryOf("kb:research:trials").Should().Be(SourceCategory.Kb);
    }

    [Theory]
    [InlineData("db:production")]
    [InlineData("nope:a:b")]
    [InlineData(null)]
    public void CategoryOf_ReturnsNullForAnythingTheParserRejects(string? identifier)
    {
        SourceIdentityParser.CategoryOf(identifier).Should().BeNull();
    }
}
