namespace Tolap.Core;

/// <summary>
/// How a rule is combined into the provider filter.
/// </summary>
public enum KbFilterOp
{
    /// <summary>Metadata value equals one of the listed values.</summary>
    In,

    /// <summary>Metadata value equals none of the listed values.</summary>
    NotIn
}

/// <summary>
/// One clause of a provider-neutral filter: a metadata key tested against tag values.
/// </summary>
/// <remarks>
/// Values are lower-cased, matching the case-insensitive comparison
/// <see cref="EnforcementEngine.FilterByTags"/> performs. Note the limitation this implies: a
/// provider whose own matching is case-<i>sensitive</i> will fail to exclude a chunk tagged
/// <c>Secret</c> when the clause says <c>secret</c>. That is a pushdown miss, caught by the
/// post pass — and it is why <see cref="KbFilterResult.CaseSensitivityCaveat"/> says so out
/// loud rather than leaving an integrator to assume the provider did the whole job.
/// </remarks>
public sealed record KbFilterClause(string Key, KbFilterOp Op, string[] Values);

/// <summary>
/// A rule that could not be expressed as a provider filter, and why.
/// </summary>
public sealed record UnpushedRule(string Rule, string Reason);

/// <summary>
/// A provider-neutral filter plus an honest account of its limits.
/// </summary>
/// <param name="Clauses">
/// Clauses to combine with AND. Empty means nothing could be pushed — retrieve unfiltered and
/// let the post pass do the work.
/// </param>
/// <param name="DeniesEverything">
/// True when the policy denies every chunk (an empty <c>allowedTags</c>). No filter can
/// express this portably, so the caller MUST skip retrieval rather than treat an empty
/// <paramref name="Clauses"/> as "no restriction".
/// </param>
/// <param name="UnpushedRules">
/// Rules not represented in <paramref name="Clauses"/>. Non-empty means the provider will
/// return chunks the post pass still has to discard. Never let a non-empty list be read as
/// "filtered at the source".
/// </param>
/// <param name="CaseSensitivityCaveat">
/// True whenever clauses were emitted, as a standing reminder that tag comparison is
/// case-insensitive in TOLAP but may not be in the provider, and that the provider sees only
/// the configured keys at the depth it indexes them. The post pass remains normative.
/// </param>
public sealed record KbFilterResult(
    KbFilterClause[] Clauses,
    bool DeniesEverything,
    UnpushedRule[] UnpushedRules,
    bool CaseSensitivityCaveat);

/// <summary>
/// Provider-side metadata filters for <c>kb</c> sources (connector-spec.md section 7).
/// </summary>
/// <remarks>
/// <para>
/// <b>What this is for.</b> <c>tagRules</c> is the whole knowledge-base confidentiality
/// control — a classification level <i>is</i> a tag (section 7). Post-retrieval,
/// <see cref="EnforcementEngine.FilterByTags"/> enforces it on returned chunks. This class
/// additionally emits a <b>provider-native filter</b> so denied chunks are never retrieved in
/// the first place, which section 7 puts "on the same footing as SQL rewriting, never a
/// replacement for the post pass".
/// </para>
/// <para>
/// That framing is the entire safety argument, so it is worth being explicit about why the
/// pushdown is <i>structurally</i> weaker than the post pass rather than merely redundant:
/// post-retrieval extraction reads tags from <c>tags</c>, <c>Tags</c>, <c>labels</c>,
/// <c>classification</c> and <c>metadata.tags</c> — <b>at any depth</b>, matched with the same
/// bidirectional case-insensitive glob matcher masking uses. A provider filter cannot express
/// that; it filters one concrete indexed metadata field. A chunk tagged <c>secret</c> under a
/// key the provider does not index, or nested where it cannot reach, is invisible to the
/// filter and caught only by the post pass.
/// </para>
/// <para>
/// So a filter that matches nothing is <b>useless, not unsafe</b> — the post pass still runs
/// and still drops the chunk. The failure to avoid is the opposite one: emitting a filter that
/// causes the provider to return <i>more</i> than it should while something downstream
/// mistakenly treats the pushdown as sufficient. Two rules follow: never emit a filter broader
/// than the rule it came from (an inexact rule is reported unpushed rather than approximated),
/// and always report what was not pushed.
/// </para>
/// <para>
/// An empty <c>allowedTags</c> is the case that most invites a mistake. It means deny-all, and
/// no metadata predicate meaning "match no document" is portable across the six supported
/// providers — an empty <c>in</c> list is variously an error, a no-op, or a match-nothing.
/// Rendering it as a no-op would be a fail-open, so it is refused: the result carries
/// <see cref="KbFilterResult.DeniesEverything"/> and no filter, and the caller should skip
/// retrieval altogether.
/// </para>
/// <para>Mirrors <c>kb-filter.ts</c> and <c>kb_filter.py</c>.</para>
/// </remarks>
public static class KbFilter
{
    /// <summary>
    /// The metadata keys a provider filter may be built against.
    /// </summary>
    /// <remarks>
    /// Deliberately <b>not</b> the same list as post-retrieval extraction's, and deliberately
    /// caller-overridable. Extraction's key set is fixed and unconfigurable because it decides
    /// what counts as security metadata, and an unsigned knob must not influence a
    /// confidentiality decision. This one is different in kind: it names which field the
    /// <i>provider</i> happens to index, which is deployment knowledge the SDK cannot infer,
    /// and getting it wrong makes the filter match nothing — costing efficiency, never access.
    /// </remarks>
    public static readonly string[] DefaultMetadataKeys = { "tags", "labels", "classification" };

    /// <summary>
    /// Build a provider-neutral metadata filter from a policy's <c>tagRules</c> (section 7).
    /// </summary>
    /// <remarks>
    /// Returns clauses to AND together, plus what could not be pushed. A caller that ignores
    /// <see cref="KbFilterResult.UnpushedRules"/> still gets correct enforcement — the post
    /// pass is unconditional — but loses the ability to tell whether the provider did any of
    /// the work.
    /// </remarks>
    public static KbFilterResult Build(EffectivePolicy policy, string[]? metadataKeys = null)
    {
        var empty = new KbFilterResult(
            Array.Empty<KbFilterClause>(), false, Array.Empty<UnpushedRule>(), false);

        var tagRules = policy.ObjectRules?.TagRules;
        if (tagRules is null)
            return empty;

        var keys = metadataKeys ?? DefaultMetadataKeys;
        if (keys.Length == 0)
        {
            // No key to filter on. Reported rather than silently returning "no restriction".
            return empty with
            {
                UnpushedRules = UnpushedFor(
                    tagRules, "no metadata keys were supplied to filter on")
            };
        }

        var clauses = new List<KbFilterClause>();
        var unpushed = new List<UnpushedRule>();

        // Denied first, mirroring FilterByTags' precedence. A denylist is the well-behaved
        // case: "value not in [...]" excludes exactly the denied tags and leaves an untagged
        // chunk alone, which is what the post pass does.
        if (tagRules.DeniedTags is { Length: > 0 })
        {
            var denied = Normalize(tagRules.DeniedTags);
            foreach (var key in keys)
                clauses.Add(new KbFilterClause(key, KbFilterOp.NotIn, denied));
        }
        // An empty DeniedTags denies nothing: nothing to push, nothing unpushed.

        if (tagRules.AllowedTags is not null)
        {
            if (tagRules.AllowedTags.Length == 0)
            {
                // Deny-all. Not expressible portably (see the type remarks), and rendering it
                // as a no-op would be a fail-open, so it is refused loudly instead.
                return new KbFilterResult(
                    Array.Empty<KbFilterClause>(),
                    DeniesEverything: true,
                    UnpushedRules: new[]
                    {
                        new UnpushedRule(
                            "allowedTags",
                            "an empty allowedTags denies every chunk; no portable metadata " +
                            "filter expresses match-nothing, so skip retrieval entirely")
                    },
                    CaseSensitivityCaveat: false);
            }

            // A positive match on ONE key only. This is the constraint that makes multi-key
            // allow-lists unpushable: the post pass admits a chunk tagged `public` under
            // EITHER `tags` OR `classification`, which is a disjunction across keys. ANDing a
            // positive clause per key would instead demand the tag be present under *every*
            // key and drop chunks the policy allows — narrower than the policy, which is a
            // correctness bug even though it errs "safe". Emitting a single-key clause is
            // exact when there is one key; with several, the rule is reported unpushed rather
            // than approximated in either direction.
            if (keys.Length == 1)
            {
                clauses.Add(new KbFilterClause(
                    keys[0], KbFilterOp.In, Normalize(tagRules.AllowedTags)));
            }
            else
            {
                unpushed.Add(new UnpushedRule(
                    "allowedTags",
                    "an allow-list spans multiple metadata keys as a disjunction; ANDing per " +
                    "key would drop permitted chunks, so it is left to the post pass"));
            }
        }

        return new KbFilterResult(
            clauses.ToArray(),
            DeniesEverything: false,
            UnpushedRules: unpushed.ToArray(),
            CaseSensitivityCaveat: clauses.Count > 0);
    }

    /// <summary>
    /// Lower-cased, de-duplicated and sorted, matching <c>FilterByTags</c>' comparison.
    /// </summary>
    /// <remarks>
    /// Sorted with <see cref="StringComparer.Ordinal"/> so the same policy renders
    /// byte-identically in all three SDKs — the shared fixture compares rendered output, and
    /// an unstable or culture-dependent order would make it fail for the wrong reason.
    /// </remarks>
    private static string[] Normalize(string[] values)
        => values
            .Select(v => v.ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(v => v, StringComparer.Ordinal)
            .ToArray();

    private static UnpushedRule[] UnpushedFor(TagRules tagRules, string reason)
    {
        var out_ = new List<UnpushedRule>();
        if (tagRules.DeniedTags is { Length: > 0 })
            out_.Add(new UnpushedRule("deniedTags", reason));
        if (tagRules.AllowedTags is not null)
            out_.Add(new UnpushedRule("allowedTags", reason));
        return out_.ToArray();
    }
}
