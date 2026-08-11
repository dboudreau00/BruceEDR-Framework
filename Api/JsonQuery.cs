using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// A deliberately small JSONPath subset over System.Text.Json.
//
// Why a subset rather than a JSONPath library: API Studio must not take a new
// dependency, and full JSONPath includes filter expressions and script
// evaluation. Response bodies are attacker-controlled in the threat model this
// tool is used in, so a query language with an evaluator is a liability. What is
// supported is what collection authors actually write:
//
//   $.data.items[0].id      dotted properties, array index, optional $ root
//   items[-1]               negative index, counted from the end
//   items[*].id             wildcard over an array
//   headers.*               wildcard over object values
//   meta['content.type']    bracket-quoted key, for names containing a dot
//
// NOT supported, on purpose: recursive descent (..), filters (?()), slices
// (a[1:3]), unions (a[0,1]), and functions. Any of those parse as a malformed
// path and yield "no match" rather than a partial, misleading result.
// ---------------------------------------------------------------------------

/// <summary>
/// Read-only queries over a JSON document. Every entry point is total: malformed
/// JSON and malformed paths return false or an empty result instead of throwing,
/// because these run against live response bodies inside an assertion loop where
/// an exception would abort a whole collection run.
/// </summary>
public static class JsonQuery
{
    /// <summary>
    /// Nesting limit for both the parser and the path. Bounded so a deeply nested
    /// hostile body cannot exhaust the stack inside System.Text.Json.
    /// </summary>
    public const int MaxDepth = 64;

    /// <summary>Cap on matches a wildcard path may produce, to bound memory on a huge array.</summary>
    public const int MaxMatches = 10_000;

    private static readonly JsonDocumentOptions ParseOptions = new()
    {
        MaxDepth = MaxDepth,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow
    };

    // Relaxed escaping keeps the operator's own characters (<, >, &, non-ASCII)
    // readable in the report instead of turning them into <. This output is
    // diagnostic text: any caller placing it in HTML must encode it there.
    private static readonly JsonSerializerOptions CompactOptions = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private static readonly JsonSerializerOptions PrettyOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>True when the text parses as a single complete JSON value.</summary>
    /// <remarks>
    /// Trailing content, comments and trailing commas all count as invalid: this
    /// backs the <c>BodyIsValidJson</c> assertion, and being lenient there would let
    /// a broken API pass a contract test.
    /// </remarks>
    public static bool IsValidJson(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return false;
        try
        {
            using var _ = JsonDocument.Parse(json, ParseOptions);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>
    /// First value matching <paramref name="path"/>, rendered as text: strings come
    /// back unquoted, numbers as their original JSON text, and objects/arrays as
    /// compact JSON. Returns false (with an empty value) for malformed JSON, a
    /// malformed path, or no match.
    /// </summary>
    public static bool TrySelect(string json, string path, out string value)
    {
        value = "";
        if (!TryEvaluate(json, path, out var doc, out var matches)) return false;
        using (doc)
        {
            if (matches.Count == 0) return false;
            value = Render(matches[0]);
            return true;
        }
    }

    /// <summary>
    /// Every value matching <paramref name="path"/>, rendered the same way as
    /// <see cref="TrySelect"/>, in document order. Empty on any failure.
    /// </summary>
    public static IReadOnlyList<string> SelectAll(string json, string path)
    {
        if (!TryEvaluate(json, path, out var doc, out var matches)) return Array.Empty<string>();
        using (doc)
        {
            if (matches.Count == 0) return Array.Empty<string>();
            var rendered = new string[matches.Count];
            for (int i = 0; i < matches.Count; i++) rendered[i] = Render(matches[i]);
            return rendered;
        }
    }

    /// <summary>
    /// How many things the path names. A wildcard path counts its matches; any other
    /// path that lands on exactly one array or object counts that container's
    /// children instead, so <c>data.items</c> and <c>data.items[*]</c> agree.
    /// Anything else is the number of matches (0 or 1 for a scalar).
    /// </summary>
    /// <remarks>
    /// The wildcard carve-out matters: without it <c>items[*]</c> over a
    /// single-element array of objects would report that object's field count rather
    /// than 1.
    /// </remarks>
    public static int Count(string json, string path)
    {
        if (!TryEvaluate(json, path, out var doc, out var matches)) return 0;
        using (doc)
        {
            if (matches.Count != 1 || EndsWithWildcard(path)) return matches.Count;

            var only = matches[0];
            return only.ValueKind switch
            {
                JsonValueKind.Array => only.GetArrayLength(),
                JsonValueKind.Object => CountProperties(only),
                _ => 1
            };
        }
    }

    /// <summary>
    /// First matching element, cloned. The clone is essential: the
    /// <see cref="JsonDocument"/> that owns the parsed buffer is disposed before this
    /// returns, and an un-cloned <see cref="JsonElement"/> would then point at pooled
    /// memory that has been handed back and may already have been overwritten.
    /// </summary>
    public static bool TryGetElement(string json, string path, out JsonElement element)
    {
        element = default;
        if (!TryEvaluate(json, path, out var doc, out var matches)) return false;
        using (doc)
        {
            if (matches.Count == 0) return false;
            element = matches[0].Clone();
            return true;
        }
    }

    /// <summary>
    /// Re-serialises with indentation. Malformed JSON is returned unchanged rather
    /// than swallowed, so an operator pressing "format" on a broken body still sees
    /// the broken body.
    /// </summary>
    public static string Pretty(string json) => Reformat(json, PrettyOptions);

    /// <summary>Re-serialises with all insignificant whitespace removed. Malformed JSON is returned unchanged.</summary>
    public static string Compact(string json) => Reformat(json, CompactOptions);

    // ------------------------------------------------------------------ internals

    private enum StepKind { Property, Index, Wildcard }

    private readonly record struct Step(StepKind Kind, string Name, int Index)
    {
        public static Step Property(string name) => new(StepKind.Property, name, 0);
        public static Step At(int index) => new(StepKind.Index, "", index);
        public static readonly Step Any = new(StepKind.Wildcard, "", 0);
    }

    /// <summary>
    /// Parses and evaluates in one go. On success the caller owns
    /// <paramref name="doc"/> and must dispose it; the returned elements are only
    /// valid until it is disposed.
    /// </summary>
    private static bool TryEvaluate(
        string json, string path, out JsonDocument doc, out List<JsonElement> matches)
    {
        doc = null!;
        matches = new List<JsonElement>(0);

        if (string.IsNullOrWhiteSpace(json)) return false;
        if (!TryParsePath(path, out var steps)) return false;

        JsonDocument parsed;
        try
        {
            parsed = JsonDocument.Parse(json, ParseOptions);
        }
        catch (JsonException)
        {
            return false;
        }

        doc = parsed;
        matches = Walk(parsed.RootElement, steps);
        return true;
    }

    private static bool TryParsePath(string path, out List<Step> steps)
    {
        steps = new List<Step>();
        if (path is null) return false;

        var s = path.Trim();
        if (s.Length == 0) return true;                 // empty path selects the root

        int i = 0;
        if (s[0] == '$') i = 1;

        while (i < s.Length)
        {
            if (steps.Count >= MaxDepth) return false;  // absurdly long path: refuse

            char c = s[i];

            if (c == '.')
            {
                i++;
                if (i >= s.Length) return false;        // trailing dot
                if (s[i] == '.') return false;          // recursive descent unsupported
                continue;
            }

            if (c == '[')
            {
                int open = i + 1;
                while (open < s.Length && char.IsWhiteSpace(s[open])) open++;

                // A quoted key is scanned to its closing quote before the closing
                // bracket is looked for, so a key such as ['c[d]'] survives. There is
                // no escape syntax inside the quotes, so a key containing the same
                // quote character it is wrapped in cannot be addressed; use the other
                // quote character, or accept that such a key is out of reach.
                if (open < s.Length && (s[open] == '\'' || s[open] == '"'))
                {
                    char quote = s[open];
                    int endQuote = s.IndexOf(quote, open + 1);
                    if (endQuote < 0) return false;

                    var quoted = s.Substring(open + 1, endQuote - open - 1);
                    if (quoted.Length == 0) return false;

                    int after = endQuote + 1;
                    while (after < s.Length && char.IsWhiteSpace(s[after])) after++;
                    if (after >= s.Length || s[after] != ']') return false;

                    steps.Add(Step.Property(quoted));
                    i = after + 1;
                    continue;
                }

                int close = s.IndexOf(']', i + 1);
                if (close < 0) return false;            // unbalanced bracket

                var inner = s.Substring(i + 1, close - i - 1).Trim();
                i = close + 1;

                if (inner.Length == 0) return false;

                if (inner == "*")
                {
                    steps.Add(Step.Any);
                    continue;
                }

                if (int.TryParse(inner, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int idx))
                {
                    steps.Add(Step.At(idx));
                    continue;
                }

                return false;                            // slices, unions, filters
            }

            int start = i;
            while (i < s.Length && s[i] != '.' && s[i] != '[') i++;
            var segment = s.Substring(start, i - start).Trim();
            if (segment.Length == 0) return false;

            steps.Add(segment == "*" ? Step.Any : Step.Property(segment));
        }

        return true;
    }

    private static List<JsonElement> Walk(JsonElement root, List<Step> steps)
    {
        var current = new List<JsonElement>(1) { root };

        foreach (var step in steps)
        {
            if (current.Count == 0) break;

            var next = new List<JsonElement>();
            foreach (var element in current)
            {
                if (next.Count >= MaxMatches) break;

                switch (step.Kind)
                {
                    case StepKind.Property:
                        // Ordinal, case-sensitive: JSON member names are case-sensitive,
                        // and matching loosely would let "Token" silently satisfy a path
                        // written for "token".
                        if (element.ValueKind == JsonValueKind.Object &&
                            element.TryGetProperty(step.Name, out var property))
                            next.Add(property);
                        break;

                    case StepKind.Index:
                        if (element.ValueKind == JsonValueKind.Array)
                        {
                            int length = element.GetArrayLength();
                            int index = step.Index < 0 ? length + step.Index : step.Index;
                            if (index >= 0 && index < length) next.Add(element[index]);
                        }
                        break;

                    case StepKind.Wildcard:
                        if (element.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var item in element.EnumerateArray())
                            {
                                if (next.Count >= MaxMatches) break;
                                next.Add(item);
                            }
                        }
                        else if (element.ValueKind == JsonValueKind.Object)
                        {
                            foreach (var member in element.EnumerateObject())
                            {
                                if (next.Count >= MaxMatches) break;
                                next.Add(member.Value);
                            }
                        }
                        break;
                }
            }

            current = next;
        }

        return current;
    }

    /// <summary>
    /// True when the last path step is a wildcard. Cheap textual check rather than a
    /// re-parse; both spellings a wildcard can take end the path the same way.
    /// </summary>
    private static bool EndsWithWildcard(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;
        var s = path.TrimEnd();
        return s.EndsWith("[*]", StringComparison.Ordinal) ||
               s.EndsWith(".*", StringComparison.Ordinal) ||
               s == "*";
    }

    private static int CountProperties(JsonElement obj)
    {
        int n = 0;
        foreach (var _ in obj.EnumerateObject()) n++;
        return n;
    }

    private static string Render(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString() ?? "",
        JsonValueKind.Null => "null",
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        // Raw text, not a round-trip through double: it preserves "1.0", "1e3" and
        // integers wider than long exactly as the server sent them, which is what an
        // equality assertion should be comparing against.
        JsonValueKind.Number => element.GetRawText(),
        _ => JsonSerializer.Serialize(element, CompactOptions)
    };

    private static string Reformat(string json, JsonSerializerOptions options)
    {
        if (string.IsNullOrWhiteSpace(json)) return json ?? "";
        try
        {
            using var doc = JsonDocument.Parse(json, ParseOptions);
            return JsonSerializer.Serialize(doc.RootElement, options);
        }
        catch (JsonException)
        {
            return json;
        }
    }
}
