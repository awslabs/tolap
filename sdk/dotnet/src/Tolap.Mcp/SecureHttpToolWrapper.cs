using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tolap.Core;

namespace Tolap.Mcp;

public sealed record SecureHttpWrapperOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true);

public sealed record HttpRequestArgs(
    string Method,
    string Path,
    string? CollectionPath = null,
    object? Body = null);

/// <summary>
/// TOLAP enforcement around an HttpClient.
///
/// Counterpart to Python tolap_mcp.http_wrapper.SecureHttpToolWrapper and
/// TypeScript SecureHttpToolWrapper:
///   - Pre-call: validateEndpoint + signature/expiry on the SecurityContext.
///   - Post-call: dotted-path masking, hidden-field stripping, and
///     CollectionPath-aware result-limit truncation of the JSON body.
/// </summary>
public sealed class SecureHttpToolWrapper
{
    private readonly SecureHttpWrapperOptions _options;
    private readonly HttpClient _client;

    public SecureHttpToolWrapper(SecureHttpWrapperOptions options, HttpClient client)
    {
        _options = options;
        _client = client;
    }

    public async Task<JsonElement> RequestAsync(SecurityContext context, HttpRequestArgs args)
    {
        var ctxResult = ValidateSecurityContext(context);
        if (!ctxResult.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {ctxResult.Reason}");
        }

        var policy = context.Policies.FirstOrDefault()
                     ?? throw new InvalidOperationException("no policy in context");

        if (!policy.Permissions.CanQuery)
        {
            throw new UnauthorizedAccessException("Access denied: query not permitted");
        }

        // Strip any query string before policy evaluation; policy patterns are
        // written against paths, not URLs.
        var queryIndex = args.Path.IndexOf('?');
        var policyPath = queryIndex >= 0 ? args.Path[..queryIndex] : args.Path;

        var ep = EnforcementEngine.ValidateEndpoint(policyPath, args.Method, policy);
        if (!ep.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {ep.Reason}");
        }

        using var request = new HttpRequestMessage(new HttpMethod(args.Method), args.Path);
        if (args.Body is not null)
        {
            request.Content = new StringContent(
                JsonSerializer.Serialize(args.Body),
                Encoding.UTF8,
                "application/json");
        }

        using var response = await _client.SendAsync(request).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        // Parse → mutate → reserialize → reparse so we hand back an immutable JsonElement.
        // The full canonical order per canonical-enforcement-spec.md section 4:
        // row filters -> tag filters -> hidden fields -> allowed fields -> masking ->
        // result limit.
        using var doc = JsonDocument.Parse(raw);
        var node = JsonNodeFromElement(doc.RootElement);
        node = FilterRecords(node, args.CollectionPath, policy);
        node = StripHiddenFields(node, policy);
        node = ProjectAllowedFields(node, args.CollectionPath, policy);
        node = ApplyMaskingToBody(node, policy);
        node = LimitCollection(node, args.CollectionPath, policy);

        var json = JsonSerializer.Serialize(node);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    /// <summary>
    /// Validates signature then expiry; a missing expiry is a denial, never a skipped check.
    /// </summary>
    private AccessResult ValidateSecurityContext(SecurityContext context)
    {
        if (_options.EnforceSignatures
            && !SecurityContextSigner.Validate(context, _options.SigningKey))
        {
            return new AccessResult(false, "invalid signature");
        }
        if (_options.EnforceExpiry)
        {
            var expiryReason = SecurityContextSigner.ValidateExpiry(context);
            if (expiryReason is not null)
            {
                return new AccessResult(false, expiryReason);
            }
        }
        return new AccessResult(true);
    }

    // ----- JSON tree manipulation (object/array node tree) -----

    // We use an internal mutable tree built from object?/Dictionary/List
    // because System.Text.Json elements are immutable.

    private static object? JsonNodeFromElement(JsonElement el)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                var dict = new Dictionary<string, object?>();
                foreach (var p in el.EnumerateObject())
                {
                    dict[p.Name] = JsonNodeFromElement(p.Value);
                }
                return dict;
            case JsonValueKind.Array:
                var list = new List<object?>();
                foreach (var item in el.EnumerateArray())
                {
                    list.Add(JsonNodeFromElement(item));
                }
                return list;
            case JsonValueKind.String:
                return el.GetString();
            case JsonValueKind.Number:
                if (el.TryGetInt64(out var lng)) return lng;
                return el.GetDouble();
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
            default:
                return null;
        }
    }

    /// <summary>
    /// Applies row filters and tag filters to the records in a response body.
    /// </summary>
    /// <remarks>
    /// Steps 1 and 2 of the post-execution pipeline (canonical-enforcement-spec.md
    /// section 4). These were previously absent from the HTTP path entirely, so
    /// <c>rowFilters</c>, <c>deniedTags</c> and <c>allowedTags</c> were a silent no-op
    /// over HTTP while the identical policy filtered correctly through the MCP and
    /// database wrappers — and an empty <c>allowedTags</c>, which denies everything under
    /// spec section 3, returned every record.
    ///
    /// <para>
    /// Filtering targets the record collection — the array at
    /// <paramref name="collectionPath"/>, or the body when the body <i>is</i> the
    /// collection — rather than the transport envelope, matching how the allowed-field
    /// projection and the result limit already locate records. Both steps delegate to
    /// <see cref="EnforcementEngine"/> so the HTTP path cannot drift from the SQL path:
    /// the fail-closed treatment of a missing field, the type-mismatch guards and the
    /// bounded regex all come from the shared implementation.
    /// </para>
    /// </remarks>
    private static object? FilterRecords(object? body, string? collectionPath, EffectivePolicy policy)
    {
        var hasRowFilters = policy.ObjectRules?.RowFilters is { Length: > 0 };
        // Tested for null, not for emptiness: an empty allow-list denies every record
        // (spec section 3), so a truthiness check here would discard the most restrictive
        // possible rule.
        var hasTagRules = policy.ObjectRules?.TagRules is not null;
        if (!hasRowFilters && !hasTagRules)
            return body;

        if (collectionPath is null)
            return FilterNode(body, policy);

        var parts = collectionPath.Split('.');
        object? cursor = body;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (cursor is not Dictionary<string, object?> d || !d.ContainsKey(parts[i]))
                return body;
            cursor = d[parts[i]];
        }

        var leaf = parts[^1];
        if (cursor is Dictionary<string, object?> leafDict
            && leafDict.TryGetValue(leaf, out var listObj)
            && listObj is List<object?>)
        {
            leafDict[leaf] = FilterNode(listObj, policy);
        }
        return body;
    }

    /// <summary>
    /// Runs the row and tag filters over a node that is expected to be a record array.
    /// </summary>
    /// <remarks>
    /// A node that is not a list of records is returned untouched: a scalar or a single
    /// object carries no collection to filter, and the pre-execution checks plus the
    /// remaining pipeline steps still apply to it. Non-record entries inside a list are
    /// preserved in place rather than dropped, so a heterogeneous array is not silently
    /// truncated by a rule that cannot address it.
    /// </remarks>
    private static object? FilterNode(object? node, EffectivePolicy policy)
    {
        if (node is not List<object?> list)
            return node;

        var records = new List<Dictionary<string, object?>>(list.Count);
        var nonRecords = new List<object?>();
        foreach (var item in list)
        {
            if (item is Dictionary<string, object?> record)
                records.Add(record);
            else
                nonRecords.Add(item);
        }

        if (records.Count == 0)
            return node;

        var kept = EnforcementEngine.ApplyRowFilters(records, policy);
        kept = EnforcementEngine.FilterByTags(kept, policy);

        var filtered = new List<object?>(kept.Count + nonRecords.Count);
        filtered.AddRange(kept);
        filtered.AddRange(nonRecords);
        return filtered;
    }

    /// <summary>
    /// Removes hidden fields from a JSON response tree.
    /// </summary>
    /// <remarks>
    /// Mirrors the SQL-side promise: a hidden field never reaches the agent. Delegates to
    /// the shared core implementation so the HTTP and MCP paths cannot drift; the core
    /// walks nested objects and arrays and matches a rule's bare and dotted forms against
    /// a key's bare and dotted forms, so "results.patient.ssn" still reaches a nested
    /// <c>ssn</c> key.
    /// </remarks>
    private static object? StripHiddenFields(object? node, EffectivePolicy policy)
        => EnforcementEngine.StripHiddenFieldsFromTree(node, policy);

    /// <summary>
    /// Applies every maskedFields rule to a (potentially nested) JSON body.
    /// </summary>
    /// <remarks>
    /// Matching goes through <see cref="EnforcementEngine.FieldNameMatches"/>, the same
    /// matcher hidden-field removal already used here via the shared core walker. That
    /// accepts a rule's bare, table-qualified and dotted forms against a key's bare and
    /// dotted forms, case-insensitively (spec section 4), so
    /// <c>results.demographics.ssn</c>, <c>patients.ssn</c>, <c>SSN</c> and <c>ssn</c> all
    /// reach an <c>ssn</c> key at any depth.
    ///
    /// <para>
    /// Masking previously walked a literal dotted path from the body root instead, so a
    /// bare rule matched a top-level key only and matching was case-sensitive: the
    /// identical policy that masked an SSN through the MCP wrapper returned it in
    /// cleartext over HTTP. A single matcher-driven pass replaces that walk — running both
    /// would apply a rule twice to the same key, and a second <c>hash</c> pass would
    /// digest the digest.
    /// </para>
    /// </remarks>
    private static object? ApplyMaskingToBody(object? node, EffectivePolicy policy)
    {
        var rules = policy.ObjectRules?.FieldRules?.MaskedFields;
        if (rules is null || rules.Length == 0) return node;

        MaskByFieldName(node, rules);
        return node;
    }

    /// <summary>
    /// Masks every key matching a rule under <see cref="EnforcementEngine"/>'s field-name
    /// matcher, recursing into nested objects and arrays.
    /// </summary>
    /// <remarks>
    /// A matched key is masked and <b>not</b> recursed into: the rule addressed that node,
    /// so its subtree is replaced rather than walked. Recursion continues only through
    /// unmatched keys.
    /// </remarks>
    private static void MaskByFieldName(object? node, MaskingRule[] rules)
    {
        if (node is List<object?> list)
        {
            foreach (var item in list) MaskByFieldName(item, rules);
            return;
        }

        if (node is not Dictionary<string, object?> dict)
            return;

        foreach (var key in dict.Keys.ToList())
        {
            // Most restrictive matching rule wins, ranked by disclosure, with an unknown
            // mask type ranking above every known one (spec section 6).
            MaskingRule? best = null;
            foreach (var rule in rules)
            {
                if (!EnforcementEngine.FieldNameMatches(rule.Field, key)) continue;
                if (best is null || rule.MaskType.Restrictiveness() > best.MaskType.Restrictiveness())
                    best = rule;
            }

            if (best is not null)
            {
                dict[key] = ApplyMask(dict[key], best);
            }
            else
            {
                MaskByFieldName(dict[key], rules);
            }
        }
    }

    /// <summary>
    /// Applies a masking rule to a JSON leaf value.
    /// </summary>
    /// <remarks>
    /// Delegates to <see cref="EnforcementEngine"/> so the HTTP path cannot drift from
    /// the database/MCP path: an unknown mask type redacts rather than returning the raw
    /// value, and a partial mask that would reveal the whole value degrades to a full
    /// mask (canonical-enforcement-spec.md section 6).
    /// </remarks>
    private static object? ApplyMask(object? value, MaskingRule rule)
        => EnforcementEngine.ApplyMask(value, rule);

    /// <summary>
    /// Projects the response's records down to allowedFields.
    /// </summary>
    /// <remarks>
    /// Step 4 of the pipeline. Projection targets the records themselves — the array at
    /// <paramref name="collectionPath"/>, or the body when the body <i>is</i> the
    /// collection — rather than the transport envelope, so an API's <c>meta</c>/paging
    /// block survives while a record returning columns the policy never listed is
    /// trimmed. A null allow-list is unrestricted; an empty allow-list denies every field.
    /// </remarks>
    private static object? ProjectAllowedFields(
        object? body,
        string? collectionPath,
        EffectivePolicy policy)
    {
        var allowed = policy.ObjectRules?.FieldRules?.AllowedFields;
        if (allowed is null) return body;

        if (collectionPath is null)
        {
            return ProjectNode(body, allowed);
        }

        var parts = collectionPath.Split('.');
        object? cursor = body;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (cursor is not Dictionary<string, object?> d || !d.ContainsKey(parts[i]))
                return body;
            cursor = d[parts[i]];
        }
        var leaf = parts[^1];
        if (cursor is Dictionary<string, object?> leafDict
            && leafDict.TryGetValue(leaf, out var listObj)
            && listObj is List<object?>)
        {
            leafDict[leaf] = ProjectNode(listObj, allowed);
        }
        return body;
    }

    private static object? ProjectNode(object? node, string[] allowed)
    {
        if (node is List<object?> list)
        {
            return list.Select(item => ProjectNode(item, allowed)).ToList();
        }

        if (node is Dictionary<string, object?> dict)
        {
            var projected = new Dictionary<string, object?>();
            foreach (var (key, value) in dict)
            {
                if (allowed.Any(a => EnforcementEngine.FieldNameMatches(a, key)))
                    projected[key] = value;
            }
            return projected;
        }

        return node;
    }

    private static object? LimitCollection(object? body, string? collectionPath, EffectivePolicy policy)
    {
        var max = policy.Limits?.MaxResults;
        if (max is null) return body;

        if (collectionPath is null)
        {
            if (body is List<object?> list && list.Count > max.Value)
            {
                return list.Take(max.Value).ToList();
            }
            return body;
        }

        var parts = collectionPath.Split('.');
        object? cursor = body;
        for (var i = 0; i < parts.Length - 1; i++)
        {
            if (cursor is not Dictionary<string, object?> d || !d.ContainsKey(parts[i]))
                return body;
            cursor = d[parts[i]];
        }
        var leaf = parts[^1];
        if (cursor is Dictionary<string, object?> leafDict
            && leafDict.TryGetValue(leaf, out var listObj)
            && listObj is List<object?> items
            && items.Count > max.Value)
        {
            leafDict[leaf] = items.Take(max.Value).ToList();
        }
        return body;
    }
}
