using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tolap.Core;

namespace Tolap.Mcp;

public sealed record SecureHttpWrapperOptions(
    string SigningKey,
    bool EnforceSignatures = true,
    bool EnforceExpiry = true);

/// <param name="ObjectName">
/// The object behind this route, checked against <c>allowedObjects</c>/<c>hiddenObjects</c>.
/// <para>
/// Honoured on <b>every</b> method when supplied, not only on a write, and re-checked on every
/// redirect hop. Null skips the check rather than guessing: no wrapper derives a resource name
/// from a path, and connector-spec.md section 6 is explicit that an author "MUST express API
/// restrictions as <c>endpointRules</c>". Supplying it is what makes the control usable over
/// HTTP without inventing inference.
/// </para>
/// </param>
/// <param name="WriteOptions">
/// The target row and full-replace inputs for a write method's section 4 validation. Null
/// means no target row was supplied, which denies an update or delete under a policy carrying
/// row filters with <c>write target unverifiable</c>.
/// </param>
public sealed record HttpRequestArgs(
    string Method,
    string Path,
    string? CollectionPath = null,
    object? Body = null,
    string? ObjectName = null,
    WriteValidationOptions? WriteOptions = null);

/// <summary>
/// A non-2xx response, carrying the policy-enforced body.
/// </summary>
/// <remarks>
/// <para>
/// Thrown instead of letting <c>EnsureSuccessStatusCode</c> raise, because connector-spec.md
/// section 6 requires a 4xx/5xx payload to carry the same enforcement as a success payload — a
/// validation error echoing a rejected value is the common leak. <see cref="Body"/> is the
/// error payload after the full pipeline (canonical-enforcement-spec.md section 4) has run over
/// it, or null when the payload was not JSON and therefore could not be enforced at all: a body
/// policy cannot be applied to is withheld rather than passed through (section 5).
/// </para>
/// <para>
/// Deliberately carries no handle on the <see cref="HttpResponseMessage"/>. The whole point of
/// enforcing an error body is defeated if the exception also ships the raw one.
/// </para>
/// </remarks>
public sealed class UpstreamHttpException : Exception
{
    public UpstreamHttpException(int status, JsonElement? body, string url)
        : base($"HTTP {status} from {url}")
    {
        Status = status;
        Body = body;
        Url = url;
    }

    /// <summary>The response status code.</summary>
    public int Status { get; }

    /// <summary>The error body after the full enforcement pipeline, or null if not JSON.</summary>
    public JsonElement? Body { get; }

    /// <summary>The URL the failing response came from.</summary>
    public string Url { get; }
}

/// <summary>
/// TOLAP enforcement around an HttpClient.
///
/// Counterpart to Python tolap_mcp.http_wrapper.SecureHttpToolWrapper and
/// TypeScript SecureHttpToolWrapper:
///   - Pre-call: validateEndpoint + signature/expiry on the SecurityContext.
///   - Post-call: dotted-path masking, hidden-field stripping, and
///     CollectionPath-aware result-limit truncation of the JSON body.
/// </summary>
/// <remarks>
/// <para>
/// Two connector-spec.md section 6 requirements shape the request loop rather than the body
/// pipeline:
/// </para>
/// <para>
/// <b>Error bodies are enforced.</b> A 4xx/5xx payload carries the same fields as a success
/// payload, so it runs the identical pipeline and surfaces as
/// <see cref="UpstreamHttpException"/> carrying the <i>enforced</i> body.
/// <c>EnsureSuccessStatusCode</c> is deliberately not called: it raises before enforcement, so
/// the response never reached the pipeline.
/// </para>
/// <para>
/// <b>Redirects are re-validated.</b> Each hop's target is re-checked against the endpoint
/// rules before it is requested, because a permitted endpoint that 302s to a denied one
/// otherwise bypasses the check. This requires the <see cref="HttpClient"/> to be built with a
/// handler that does <b>not</b> follow redirects:
/// <c>new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })</c>. Unlike httpx and
/// <c>fetch</c>, .NET fixes redirect behavior on the handler at construction and exposes no way
/// to override it per request or to read it back, so the wrapper cannot switch it off itself.
/// What it can do — and does — is <i>detect</i> a handler that followed a redirect and refuse
/// the response, because that body came from a location no check approved. The default
/// <c>HttpClient</c> follows redirects, which is exactly why this fails closed and loudly
/// rather than trusting it.
/// </para>
/// </remarks>
public sealed class SecureHttpToolWrapper
{
    /// <summary>
    /// How many redirect hops a single request may take before it is denied.
    /// </summary>
    /// <remarks>
    /// Explicit, and identical in all three SDKs, precisely because every client's own default
    /// differs — <c>HttpClientHandler.MaxAutomaticRedirections</c> defaults to 50, httpx allows
    /// 20, <c>fetch</c> 20. Inheriting whichever number the transport happened to pick is how
    /// the redirect gap arose in the first place. Five is the historical HTTP recommendation and
    /// far more than any legitimate API needs; a longer chain is a loop or a misconfiguration,
    /// and either way the caller learns rather than hangs.
    /// </remarks>
    public const int MaxRedirects = 5;

    /// <summary>
    /// The 3xx codes that carry the original method and body to the new location.
    /// </summary>
    /// <remarks>
    /// 301/302/303 downgrade to <c>GET</c> and drop the body, as every browser and HTTP client
    /// does; the downgraded request is itself re-validated, so the downgrade cannot smuggle a
    /// request past the method rules either.
    /// </remarks>
    private static readonly int[] MethodPreservingRedirects = { 307, 308 };

    /// <summary>The 3xx statuses treated as a redirect needing re-validation.</summary>
    private static readonly int[] RedirectStatuses = { 301, 302, 303, 307, 308 };

    /// <summary>
    /// A base for a wrapper whose <see cref="HttpClient"/> carries no BaseAddress.
    /// </summary>
    /// <remarks>
    /// <see cref="Uri"/> arithmetic needs an absolute base. A reserved-TLD sentinel keeps the
    /// arithmetic honest without pretending to name a real host: every relative path then
    /// shares one origin, so a relative <c>Location</c> resolves, and a <c>Location</c> naming
    /// any real host reads as cross-origin and is refused — the conservative answer when the
    /// wrapper does not know what origin it is talking to.
    /// </remarks>
    private static readonly Uri RelativeOrigin = new("http://relative.invalid");

    private readonly SecureHttpWrapperOptions _options;
    private readonly HttpClient _client;

    public SecureHttpToolWrapper(SecureHttpWrapperOptions options, HttpClient client)
    {
        _options = options;
        _client = client;
    }

    /// <summary>
    /// Issues an HTTP request with full pre/post enforcement.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A write method is additionally validated per connector-spec.md section 4 before the
    /// request leaves the process: the operation's permission
    /// (<c>POST</c>-&gt;<c>canInsert</c>, <c>PUT</c>/<c>PATCH</c>-&gt;<c>canUpdate</c>,
    /// <c>DELETE</c>-&gt;<c>canDelete</c>), the <c>readOnly</c> ceiling,
    /// <see cref="HttpRequestArgs.ObjectName"/> against the object rules, every field in the
    /// body against <c>hiddenFields</c>/<c>readOnlyFields</c>/<c>allowedFields</c>, and the
    /// policy's row filters against the target row. Method and permission must both agree:
    /// <c>allowedMethods: ["POST"]</c> says nothing about <c>canInsert</c>.
    /// </para>
    /// <para>
    /// A <c>PUT</c> is treated as replacing the whole resource, so every field the policy
    /// protects is checked as though the body had named it — omitting a <c>readOnlyFields</c>
    /// field from a replace is still an attempt to overwrite it. Supply
    /// <see cref="WriteValidationOptions.ResourceFields"/> when the policy also sets
    /// <c>allowedFields</c>.
    /// </para>
    /// <para>
    /// The response body runs the same post-execution pipeline as a read, because a write's
    /// response <i>is</i> a read of the data it returns (section 4.5). That includes a
    /// <b>4xx/5xx</b> body: an error payload carries the same fields as a success payload, so it
    /// is enforced and then thrown as <see cref="UpstreamHttpException"/> with the enforced body
    /// attached (section 6).
    /// </para>
    /// <para>
    /// A <b>redirect is never followed blind</b> (section 6). Each hop's target is re-validated
    /// against the endpoint rules before it is requested, a cross-origin redirect is refused
    /// outright, and the chain is bounded by <see cref="MaxRedirects"/>. Build the
    /// <see cref="HttpClient"/> with <c>AllowAutoRedirect = false</c>; a handler that follows
    /// anyway is detected and its response refused, since that body came from a location no
    /// check approved.
    /// </para>
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">The policy denied the call.</exception>
    /// <exception cref="UpstreamHttpException">
    /// The upstream returned a non-2xx status. Carries the enforced error body.
    /// </exception>
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

        var first = ValidateHop(args.Method, args.Path, args.Body, policy, args);
        if (!first.Allowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {first.Reason}");
        }

        // The redirect chain. Each hop is re-validated before it is requested, because a
        // permitted endpoint that 302s to a denied one otherwise bypasses the endpoint check
        // entirely — and HttpClient follows redirects by default, so this SDK was exposed.
        var hopMethod = args.Method;
        var hopBody = args.Body;
        var target = args.Path;
        for (var hop = 0; ; hop++)
        {
            using var request = new HttpRequestMessage(new HttpMethod(hopMethod), target);
            if (hopBody is not null)
            {
                request.Content = new StringContent(
                    JsonSerializer.Serialize(hopBody),
                    Encoding.UTF8,
                    "application/json");
            }

            var requested = ResolveAgainstBase(target);
            using var response = await _client.SendAsync(request).ConfigureAwait(false);

            // A handler built with AllowAutoRedirect = true has already fetched a location no
            // check approved: the final RequestMessage.RequestUri is the *last* hop, not the
            // one we asked for. Refused rather than enforced — the body in hand came from an
            // unvalidated hop, and .NET offers no per-request way to switch following off.
            var landed = response.RequestMessage?.RequestUri;
            if (landed is not null && !UriEquals(landed, requested))
            {
                throw new UnauthorizedAccessException(
                    "Access denied: transport followed a redirect that was not re-validated; "
                    + "construct the HttpClient with AllowAutoRedirect = false");
            }

            var location = RedirectStatuses.Contains((int)response.StatusCode)
                ? response.Headers.Location
                : null;
            if (location is null)
            {
                return await EnforceResponseAsync(response, requested, args, policy)
                    .ConfigureAwait(false);
            }

            // Resolves a relative Location ("/admin/audit", "../v2/x") against the URL actually
            // requested, and leaves an absolute one alone.
            var next = new Uri(requested, location);
            if (!SameOrigin(requested, next))
            {
                // A cross-origin redirect is refused rather than re-globbed. An absolute URL to
                // another host is outside the policy's frame of reference entirely:
                // allowedEndpoints: ["/*"] describes paths on the source this policy was
                // resolved for, and matching that glob against a path on another host would
                // "permit" an origin the author never considered.
                throw new UnauthorizedAccessException(
                    $"Access denied: redirect crosses origin to {next.GetLeftPart(UriPartial.Authority)}");
            }

            // 301/302/303 downgrade to GET and drop the body; 307/308 preserve both. The
            // downgraded method is re-validated too, so the downgrade cannot smuggle a request
            // past the method rules in either direction.
            if (!MethodPreservingRedirects.Contains((int)response.StatusCode))
            {
                hopMethod = "GET";
                hopBody = null;
            }

            var hopResult = ValidateHop(hopMethod, next.PathAndQuery, hopBody, policy, args);
            if (!hopResult.Allowed)
            {
                throw new UnauthorizedAccessException(
                    $"Access denied: redirect target rejected: {hopResult.Reason}");
            }

            if (hop == MaxRedirects)
            {
                // The budget is exhausted and a redirect is still pending. Denied rather than
                // followed: /redirect-loop points at itself, and a wrapper that trusts the
                // transport's own limit spins for as many hops as that client allows.
                throw new UnauthorizedAccessException(
                    $"Access denied: too many redirects (limit {MaxRedirects})");
            }

            target = next.ToString();
        }
    }

    /// <summary>
    /// Runs every pre-request check for one request, initial hop or redirect.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Factored out of <see cref="RequestAsync"/> so a redirect hop cannot be validated more
    /// weakly than the request that produced it: the identical method decides both.
    /// connector-spec.md section 6 requires a redirect to be "re-validated against the endpoint
    /// rules before being followed", and a 307/308 preserves the method and body, so the write
    /// checks are re-run too rather than just the path.
    /// </para>
    /// <para>
    /// The query string is cut before evaluation because policy patterns are written against
    /// paths, not URLs, so <c>?</c> parameters cannot smuggle a path past a glob.
    /// </para>
    /// </remarks>
    private static AccessResult ValidateHop(
        string method,
        string path,
        object? body,
        EffectivePolicy policy,
        HttpRequestArgs args)
    {
        var queryIndex = path.IndexOf('?');
        var policyPath = queryIndex >= 0 ? path[..queryIndex] : path;

        // Endpoint rules and, for a write method, the section 4 write checks. Both halves run:
        // an endpoint allow-list is not a write grant, and a write permission does not make a
        // path reachable.
        var decision = EnforcementEngine.ValidateHttpWrite(
            method, policyPath, body, policy, args.ObjectName, args.WriteOptions);
        if (!decision.Allowed)
            return decision;

        // allowedObjects/hiddenObjects are honoured only when the integrator names the object
        // (connector-spec.md section 6, last bullet). No resource name is *derived* from the
        // path — that would be unspecified inference, and the spec requires API restrictions to
        // be expressed as endpointRules. But a caller who does know the resource behind a route
        // should not have the control silently ignored, which is what happened before:
        // ObjectName was forwarded to the write checks and therefore consulted on a POST, while
        // a GET to the same route skipped it entirely.
        //
        // Runs after the endpoint decision so a hidden endpoint keeps reporting itself as such,
        // and re-checks the write path's object rules with the identical outcome rather than
        // branching on the method.
        if (args.ObjectName is not null)
            return EnforcementEngine.ValidateAccess(args.ObjectName, policy);

        return decision;
    }

    /// <summary>
    /// Runs the full enforcement pipeline over a final response, success or error.
    /// </summary>
    /// <remarks>
    /// A 4xx/5xx body is enforced first and thrown second.
    /// <c>EnsureSuccessStatusCode</c> is deliberately not used: it raises before the pipeline
    /// runs, so the error payload was never enforced (connector-spec.md section 6, "error bodies
    /// are enforced").
    /// </remarks>
    private static async Task<JsonElement> EnforceResponseAsync(
        HttpResponseMessage response,
        Uri url,
        HttpRequestArgs args,
        EffectivePolicy policy)
    {
        var raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
            return RunPipeline(raw, args.CollectionPath, policy);

        JsonElement? errorBody;
        try
        {
            errorBody = RunPipeline(raw, args.CollectionPath, policy);
        }
        catch (JsonException)
        {
            // Not JSON, so the pipeline cannot walk it and no field rule applies. Withheld
            // rather than passed through (canonical-enforcement-spec.md section 5) — the status
            // still tells the caller what happened.
            errorBody = null;
        }

        throw new UpstreamHttpException((int)response.StatusCode, errorBody, url.ToString());
    }

    /// <summary>
    /// Runs the canonical pipeline over a raw JSON body and returns an immutable element.
    /// </summary>
    /// <remarks>
    /// Parse → mutate → reserialize → reparse so we hand back an immutable JsonElement. The full
    /// canonical order per canonical-enforcement-spec.md section 4: row filters, tag filters,
    /// hidden fields, allowed fields, masking, result limit. Shared by the success and the
    /// 4xx/5xx paths, because an error payload is not a different kind of data.
    /// </remarks>
    private static JsonElement RunPipeline(string raw, string? collectionPath, EffectivePolicy policy)
    {
        using var doc = JsonDocument.Parse(raw);
        var node = JsonNodeFromElement(doc.RootElement);
        node = FilterRecords(node, collectionPath, policy);
        node = StripHiddenFields(node, policy);
        node = ProjectAllowedFields(node, collectionPath, policy);
        node = ApplyMaskingToBody(node, policy);
        node = LimitCollection(node, collectionPath, policy);

        var json = JsonSerializer.Serialize(node);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    /// <summary>
    /// Resolves a request target against the client's BaseAddress, or against a sentinel origin
    /// when there is none.
    /// </summary>
    private Uri ResolveAgainstBase(string target)
        => new(_client.BaseAddress ?? RelativeOrigin, target);

    /// <summary>
    /// Whether two URLs address the same resource, ignoring only what HTTP itself ignores.
    /// </summary>
    /// <remarks>
    /// Used to detect a handler that followed a redirect: the response's final RequestUri is
    /// compared against the URL the wrapper asked for. <see cref="Uri.Equals(object?)"/> already
    /// normalizes a default port and is case-insensitive on scheme and host while remaining
    /// case-sensitive on the path, which is the correct comparison for a path.
    /// </remarks>
    private static bool UriEquals(Uri left, Uri right) => left.Equals(right);

    /// <summary>
    /// Whether a redirect target stays on the origin that issued the redirect.
    /// </summary>
    /// <remarks>
    /// Scheme, host and port must all match; <see cref="UriPartial.Authority"/> normalizes a
    /// default port away, so <c>http://a.test:80</c> and <c>http://a.test</c> are one origin. An
    /// http-&gt;https upgrade <i>is</i> a different origin and is refused: the policy was
    /// resolved for one source, and silently moving to another scheme is a decision for the
    /// integrator, not for this wrapper.
    /// </remarks>
    private static bool SameOrigin(Uri current, Uri target)
        => string.Equals(
            current.GetLeftPart(UriPartial.Authority),
            target.GetLeftPart(UriPartial.Authority),
            StringComparison.OrdinalIgnoreCase);

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
        {
            // A single-record body is one record, not an envelope, so it runs the identical
            // pipeline (canonical-enforcement-spec.md section 4, "Single records"). This
            // branch previously fell through to FilterNode, which returns any non-list node
            // untouched — so a body that WAS the record was handed back unfiltered, and a
            // policy with `status != deleted` disclosed {"id": 1, "status": "deleted"} from a
            // get-by-id route. Python already dropped it to None here; a dropped record
            // becomes null rather than an empty object, because an empty object would imply
            // the row existed but had no visible fields, which is a different statement from
            // "this row is not available to you".
            if (body is Dictionary<string, object?> singleRecord)
            {
                var keptOne = EnforcementEngine.FilterByTags(
                    EnforcementEngine.ApplyRowFilters(
                        new List<Dictionary<string, object?>> { singleRecord }, policy),
                    policy);
                return keptOne.Count > 0 ? keptOne[0] : null;
            }
            return FilterNode(body, policy);
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
