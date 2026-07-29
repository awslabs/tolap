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
        // Pipeline order per canonical-enforcement-spec.md section 4: hidden fields ->
        // allowed fields -> masking -> result limit.
        using var doc = JsonDocument.Parse(raw);
        var node = JsonNodeFromElement(doc.RootElement);
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

    private static object? ApplyMaskingToBody(object? node, EffectivePolicy policy)
    {
        var rules = policy.ObjectRules?.FieldRules?.MaskedFields;
        if (rules is null || rules.Length == 0) return node;
        foreach (var rule in rules)
        {
            WalkAndMask(node, rule.Field.Split('.'), rule);
        }
        return node;
    }

    private static void WalkAndMask(object? node, string[] parts, MaskingRule rule)
    {
        if (parts.Length == 0) return;
        if (node is List<object?> list)
        {
            foreach (var item in list) WalkAndMask(item, parts, rule);
            return;
        }
        if (node is Dictionary<string, object?> dict)
        {
            var head = parts[0];
            if (!dict.ContainsKey(head)) return;
            if (parts.Length == 1)
            {
                dict[head] = ApplyMask(dict[head], rule);
            }
            else
            {
                WalkAndMask(dict[head], parts[1..], rule);
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
