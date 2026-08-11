using System.Globalization;
using System.Text.RegularExpressions;
using ProcessShield.Core;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// Postman-style {{variable}} substitution.
//
// Why a hand-rolled resolver instead of a template engine: the only syntax we
// need is a double-brace placeholder, and an imported collection is untrusted
// input. A general template engine would give a malicious collection a scripting
// surface inside the analyst's own process. This resolver can only ever copy
// text out of a dictionary the operator supplied, and it terminates on cycles.
//
// Limitations worth stating plainly:
//  * There is no expression syntax ({{a || b}}, {{#each}}, function calls).
//    Anything other than a bare variable name is treated as an unknown name and
//    left alone.
//  * Resolution is textual. A value containing a quote or a brace is inserted
//    verbatim, so a variable can change the shape of a JSON body. That matches
//    Postman, and it is why Resolve is never applied to anything the operator
//    did not author.
// ---------------------------------------------------------------------------

/// <summary>
/// Resolves <c>{{name}}</c> placeholders against a variable dictionary, the way
/// Postman does: an unknown name is left in the text rather than blanked, so a
/// half-configured environment produces a visibly wrong URL instead of a subtly
/// wrong one.
/// </summary>
public static class Templating
{
    /// <summary>Built-in variable names, using the literal dollar prefix Postman uses.</summary>
    public const string VarGuid = "$guid";

    /// <summary>Seconds since the Unix epoch, taken from the injected clock.</summary>
    public const string VarTimestamp = "$timestamp";

    /// <summary>ISO-8601 UTC instant, taken from the injected clock.</summary>
    public const string VarIsoTimestamp = "$isoTimestamp";

    /// <summary>Integer in 0..1000, derived from the clock so runs are reproducible.</summary>
    public const string VarRandomInt = "$randomInt";

    /// <summary>
    /// Upper bound on <c>maxDepth</c>. Nested resolution recurses, so an unbounded
    /// depth from a config file would be a stack-overflow primitive.
    /// </summary>
    public const int MaxSupportedDepth = 64;

    /// <summary>
    /// Matches one placeholder. The inner class excludes braces, so nothing nested
    /// is matched in a single pass — nesting is handled by re-resolving the value,
    /// which is what gives us a depth bound and cycle detection.
    /// </summary>
    private static readonly Regex PlaceholderPattern =
        new(@"\{\{([^{}]*)\}\}", RegexOptions.CultureInvariant);

    /// <summary>
    /// Substitutes every known placeholder in <paramref name="input"/>, re-resolving
    /// values that themselves contain placeholders up to <paramref name="maxDepth"/>
    /// levels. Unknown names, cyclic names and names past the depth bound are left
    /// in the text literally.
    /// </summary>
    /// <param name="maxDepth">
    /// Number of substitution levels. 0 disables substitution entirely; values above
    /// <see cref="MaxSupportedDepth"/> are clamped.
    /// </param>
    public static string Resolve(string input, IReadOnlyDictionary<string, string> vars, int maxDepth = 8)
    {
        if (string.IsNullOrEmpty(input)) return input ?? "";
        if (vars is null || vars.Count == 0) return input;

        int depthLimit = Math.Clamp(maxDepth, 0, MaxSupportedDepth);
        if (depthLimit == 0) return input;

        // Ordinal here, not the dictionary's comparer: this set only guards against
        // re-entering the *same* placeholder we are already expanding.
        var active = new HashSet<string>(StringComparer.Ordinal);
        return ResolveCore(input, vars, 0, depthLimit, active);
    }

    /// <summary>
    /// Applies <see cref="Resolve(string, IReadOnlyDictionary{string, string}, int)"/>
    /// to exactly the fields that carry operator-authored text bound for the wire:
    /// the URL, header names and values, query names and values, the body text,
    /// form-field names and values, and every auth field.
    /// </summary>
    /// <remarks>
    /// Deliberately left untouched: <see cref="ApiRequest.Id"/>,
    /// <see cref="ApiRequest.Name"/>, <see cref="ApiRequest.Description"/>,
    /// <see cref="ApiRequest.Method"/>, assertions, captures, and
    /// <see cref="ApiBody.FilePath"/> / <see cref="ApiBody.ContentType"/>.
    /// Assertions and captures are checks *about* a response, so templating them
    /// would let an environment quietly weaken a test; the file path is left alone
    /// so an environment variable cannot redirect an upload to an arbitrary file.
    /// </remarks>
    public static ApiRequest Resolve(ApiRequest request, IReadOnlyDictionary<string, string> vars)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (vars is null || vars.Count == 0) return request;

        return request with
        {
            Url = Resolve(request.Url, vars),
            Headers = ResolvePairs(request.Headers, vars),
            Query = ResolvePairs(request.Query, vars),
            Body = ResolveBody(request.Body, vars),
            Auth = ResolveAuth(request.Auth, vars)
        };
    }

    /// <summary>
    /// Every distinct placeholder name appearing in <paramref name="input"/>, in order
    /// of first appearance. Dedupe is ordinal so that <c>{{Token}}</c> and
    /// <c>{{token}}</c> are both reported — they are genuinely different text, and a
    /// caller using a case-sensitive dictionary will only resolve one of them.
    /// </summary>
    public static IReadOnlyList<string> Placeholders(string input)
    {
        if (string.IsNullOrEmpty(input)) return Array.Empty<string>();

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var found = new List<string>();
        foreach (Match m in PlaceholderPattern.Matches(input))
        {
            var name = m.Groups[1].Value.Trim();
            if (name.Length == 0) continue;      // "{{}}" is text, not a variable
            if (seen.Add(name)) found.Add(name);
        }
        return found;
    }

    /// <summary>
    /// Placeholders still present after a full resolve — i.e. names that are unknown,
    /// cyclic, or beyond the depth bound. This is the list to show an operator before
    /// a run: every entry is a request that will go out with a literal <c>{{...}}</c>
    /// in it.
    /// </summary>
    public static IReadOnlyList<string> UnresolvedPlaceholders(
        string input, IReadOnlyDictionary<string, string> vars)
        => Placeholders(Resolve(input, vars));

    /// <summary>
    /// Layers variable dictionaries left to right, later layers winning, skipping
    /// nulls. The result compares names case-insensitively, which is the comparer the
    /// rest of API Studio assumes; pass the result to <c>Resolve</c> to get that
    /// behaviour rather than relying on whatever comparer an imported dictionary had.
    /// </summary>
    public static IReadOnlyDictionary<string, string> Merge(
        params IReadOnlyDictionary<string, string>?[] layers)
    {
        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (layers is null) return merged;

        foreach (var layer in layers)
        {
            if (layer is null) continue;
            foreach (var kv in layer)
            {
                if (string.IsNullOrEmpty(kv.Key)) continue;
                merged[kv.Key] = kv.Value ?? "";
            }
        }
        return merged;
    }

    /// <summary>
    /// The dynamic variables, computed from <paramref name="clock"/> so a replayed or
    /// unit-tested run produces byte-identical requests.
    /// </summary>
    /// <remarks>
    /// One deliberate exception: <see cref="VarGuid"/> is a fresh
    /// <see cref="Guid.NewGuid"/> on every call and is therefore NOT deterministic.
    /// Deriving it from the clock would make two requests in the same run share an
    /// idempotency key or correlation id, which is exactly the bug the variable
    /// exists to avoid. Tests that need a fixed guid should supply their own value
    /// for <c>$guid</c> in a later <see cref="Merge"/> layer, which overrides this one.
    /// <see cref="VarRandomInt"/> is clock-derived, so it is reproducible and is not
    /// suitable for anything security-relevant such as a nonce.
    /// </remarks>
    public static IReadOnlyDictionary<string, string> BuiltIns(IClock clock)
    {
        ArgumentNullException.ThrowIfNull(clock);

        // A third-party IClock may hand back DateTimeKind.Unspecified; force Utc so
        // the epoch conversion below cannot silently shift by the local offset.
        var now = DateTime.SpecifyKind(clock.UtcNow, DateTimeKind.Utc);
        long unix = new DateTimeOffset(now).ToUnixTimeSeconds();

        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [VarGuid] = Guid.NewGuid().ToString("d"),
            [VarTimestamp] = unix.ToString(CultureInfo.InvariantCulture),
            [VarIsoTimestamp] = now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture),
            [VarRandomInt] = (now.Ticks % 1001).ToString(CultureInfo.InvariantCulture)
        };
    }

    // ------------------------------------------------------------------ internals

    private static string ResolveCore(
        string input,
        IReadOnlyDictionary<string, string> vars,
        int depth,
        int depthLimit,
        HashSet<string> active)
    {
        if (depth >= depthLimit || input.Length == 0) return input;
        if (input.IndexOf("{{", StringComparison.Ordinal) < 0) return input;

        return PlaceholderPattern.Replace(input, m =>
        {
            var name = m.Groups[1].Value.Trim();
            if (name.Length == 0) return m.Value;
            if (!vars.TryGetValue(name, out var value)) return m.Value;   // unknown: leave literal
            value ??= "";

            // Cycle guard. Without it "a = {{a}}" or "a = {{b}}, b = {{a}}" would
            // recurse until the stack died; the placeholder is left literal instead
            // so the operator can see which variable is self-referential.
            if (!active.Add(name)) return m.Value;
            try
            {
                return ResolveCore(value, vars, depth + 1, depthLimit, active);
            }
            finally
            {
                active.Remove(name);
            }
        });
    }

    private static IReadOnlyList<ApiKeyValue> ResolvePairs(
        IReadOnlyList<ApiKeyValue> pairs, IReadOnlyDictionary<string, string> vars)
    {
        if (pairs is null || pairs.Count == 0) return Array.Empty<ApiKeyValue>();

        var result = new ApiKeyValue[pairs.Count];
        for (int i = 0; i < pairs.Count; i++)
        {
            var p = pairs[i];
            result[i] = p with { Name = Resolve(p.Name, vars), Value = Resolve(p.Value, vars) };
        }
        return result;
    }

    private static ApiBody ResolveBody(ApiBody body, IReadOnlyDictionary<string, string> vars)
    {
        if (body is null) return ApiBody.None;
        if (body.Text.Length == 0 && body.Form.Count == 0) return body;

        return body with
        {
            Text = Resolve(body.Text, vars),
            Form = ResolvePairs(body.Form, vars)
        };
    }

    private static ApiAuth ResolveAuth(ApiAuth auth, IReadOnlyDictionary<string, string> vars)
    {
        if (auth is null) return ApiAuth.None;

        // Skip the allocation when there is nothing to substitute. ApiAuth.None is a
        // shared instance and callers compare it by value, so leaving it untouched
        // also keeps reference identity for the common case.
        if (auth.Username.Length == 0 && auth.Password.Length == 0 && auth.Token.Length == 0 &&
            auth.KeyName.Length == 0 && auth.KeyValue.Length == 0 && auth.RawValue.Length == 0)
            return auth;

        return auth with
        {
            Username = Resolve(auth.Username, vars),
            Password = Resolve(auth.Password, vars),
            Token = Resolve(auth.Token, vars),
            KeyName = Resolve(auth.KeyName, vars),
            KeyValue = Resolve(auth.KeyValue, vars),
            RawValue = Resolve(auth.RawValue, vars)
        };
    }
}
