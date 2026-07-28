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
        using var doc = JsonDocument.Parse(raw);
        var node = JsonNodeFromElement(doc.RootElement);
        node = StripHiddenFields(node, policy);
        node = ApplyMaskingToBody(node, policy);
        node = LimitCollection(node, args.CollectionPath, policy);

        var json = JsonSerializer.Serialize(node);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private AccessResult ValidateSecurityContext(SecurityContext context)
    {
        if (_options.EnforceSignatures
            && !SecurityContextSigner.Validate(context, _options.SigningKey))
        {
            return new AccessResult(false, "invalid signature");
        }
        if (_options.EnforceExpiry && context.ExpiresAt < DateTimeOffset.UtcNow)
        {
            return new AccessResult(false, "security context expired");
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

    private static object? StripHiddenFields(object? node, EffectivePolicy policy)
    {
        var hidden = policy.ObjectRules?.FieldRules?.HiddenFields;
        if (hidden is null || hidden.Length == 0) return node;
        foreach (var pattern in hidden)
        {
            WalkAndDrop(node, pattern.Split('.'));
        }
        return node;
    }

    private static void WalkAndDrop(object? node, string[] parts)
    {
        if (parts.Length == 0) return;
        if (node is List<object?> list)
        {
            foreach (var item in list) WalkAndDrop(item, parts);
            return;
        }
        if (node is Dictionary<string, object?> dict)
        {
            var head = parts[0];
            if (!dict.ContainsKey(head)) return;
            if (parts.Length == 1)
            {
                dict.Remove(head);
            }
            else
            {
                WalkAndDrop(dict[head], parts[1..]);
            }
        }
    }

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

    private static object? ApplyMask(object? value, MaskingRule rule)
    {
        switch (rule.MaskType)
        {
            case MaskType.Null:
                return null;
            case MaskType.Redact:
                return "[REDACTED]";
            case MaskType.Full:
            {
                var s = value?.ToString() ?? "";
                var mc = rule.Parameters?.MaskChar ?? '*';
                return new string(mc, s.Length);
            }
            case MaskType.Partial:
            {
                var s = value?.ToString() ?? "";
                var sf = rule.Parameters?.ShowFirst ?? 0;
                var sl = rule.Parameters?.ShowLast ?? 0;
                var mc = rule.Parameters?.MaskChar ?? '*';
                if (sf + sl >= s.Length) return s;
                var sb = new StringBuilder(s.Length);
                if (sf > 0) sb.Append(s[..sf]);
                sb.Append(new string(mc, s.Length - sf - sl));
                if (sl > 0) sb.Append(s[^sl..]);
                return sb.ToString();
            }
            case MaskType.Hash:
            {
                var s = value?.ToString() ?? "";
                using var sha = SHA256.Create();
                var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(s));
                return Convert.ToHexString(hash).ToLowerInvariant()[..16];
            }
            default:
                return value;
        }
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
