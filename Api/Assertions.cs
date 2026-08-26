using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace BruceEDR.Api;

// ---------------------------------------------------------------------------
// Assertion evaluation and response captures.
//
// Two properties drive every decision in this file:
//
//  1. Nothing here may throw. Assertions run inside a collection loop; an
//     exception raised by a hostile response body would abort the whole run and
//     lose the results already gathered. Every failure mode - malformed expected
//     value, invalid regex, catastrophic backtracking, unparseable JSON - is
//     reported as a FAILED assertion with an explanatory Detail.
//
//  2. The Detail must be enough to diagnose a failure from the report alone,
//     with no re-run. So it always states expected and actual, and it is clipped
//     rather than omitted when the values are large.
//
// Regex handling deserves a note. Patterns come from a collection file and the
// subject comes from the network, so both sides of the match are untrusted. Every
// match runs with a 250 ms timeout; a timeout is a failed assertion, never an
// exception. That bounds a ReDoS attempt to a quarter second per assertion - it
// does not make the pattern safe, it just makes it survivable.
// ---------------------------------------------------------------------------

/// <summary>
/// Applies <see cref="ApiAssertion"/> checks to an <see cref="ApiResponse"/>.
/// Pure and side-effect free: no I/O, no clock, no shared mutable state, so the
/// same response and assertion always produce the same outcome.
/// </summary>
public static class AssertionEvaluator
{
    /// <summary>
    /// Ceiling on regex match time. Long enough for any legitimate pattern over a
    /// response body, short enough that a pathological pattern costs a quarter
    /// second rather than the rest of the run.
    /// </summary>
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    /// <summary>Maximum length of <see cref="AssertionOutcome.Detail"/>.</summary>
    public const int MaxDetailLength = 300;

    /// <summary>Per-component clip applied before the whole Detail is clipped.</summary>
    private const int ComponentClip = 120;

    /// <summary>
    /// Compiled patterns, keyed by pattern text. Bounded because the keys come from
    /// imported collections; past the cap we simply stop caching rather than let an
    /// import grow the dictionary without limit.
    /// </summary>
    private static readonly ConcurrentDictionary<string, Regex> RegexCache = new(StringComparer.Ordinal);

    private const int MaxCachedPatterns = 128;

    /// <summary>Evaluates every assertion in order. A null or empty list yields no outcomes.</summary>
    public static IReadOnlyList<AssertionOutcome> Evaluate(
        IReadOnlyList<ApiAssertion> assertions, ApiResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (assertions is null || assertions.Count == 0) return Array.Empty<AssertionOutcome>();

        var outcomes = new AssertionOutcome[assertions.Count];
        for (int i = 0; i < assertions.Count; i++) outcomes[i] = EvaluateOne(assertions[i], response);
        return outcomes;
    }

    /// <summary>
    /// Evaluates one assertion. Never throws for bad data in either the assertion or
    /// the response.
    /// </summary>
    public static AssertionOutcome EvaluateOne(ApiAssertion assertion, ApiResponse response)
    {
        ArgumentNullException.ThrowIfNull(assertion);
        ArgumentNullException.ThrowIfNull(response);

        // A transport failure means there is no status, no header and no body to
        // check. Reporting "status != 200" there would send an operator hunting for
        // a server bug when the real problem was DNS or TLS, so every assertion fails
        // naming the transport error instead.
        if (!response.Completed)
            return Fail(assertion, $"transport error: {response.Error}");

        return assertion.Kind switch
        {
            AssertionKind.StatusEquals => StatusEquals(assertion, response),
            AssertionKind.StatusIsSuccess => Check(assertion,
                response.StatusCode >= 200 && response.StatusCode < 300,
                response.StatusCode.ToString(CultureInfo.InvariantCulture)),
            AssertionKind.StatusIn => StatusIn(assertion, response),
            AssertionKind.HeaderExists => HeaderExists(assertion, response),
            AssertionKind.HeaderEquals => HeaderEquals(assertion, response),
            AssertionKind.HeaderContains => HeaderContains(assertion, response),
            AssertionKind.BodyContains => BodyContains(assertion, response, wanted: true),
            AssertionKind.BodyNotContains => BodyContains(assertion, response, wanted: false),
            AssertionKind.BodyMatchesRegex => BodyMatchesRegex(assertion, response),
            AssertionKind.BodyIsValidJson => BodyIsValidJson(assertion, response),
            AssertionKind.JsonPathExists => JsonPathExists(assertion, response),
            AssertionKind.JsonPathEquals => JsonPathEquals(assertion, response),
            AssertionKind.JsonPathMatches => JsonPathMatches(assertion, response),
            AssertionKind.JsonPathCountEquals => JsonPathCountEquals(assertion, response),
            AssertionKind.ResponseTimeUnderMs => ResponseTimeUnder(assertion, response),
            AssertionKind.BodySizeUnderBytes => BodySizeUnder(assertion, response),
            AssertionKind.ContentTypeContains => Check(assertion,
                assertion.Expected.Length > 0 &&
                response.ContentType.Contains(assertion.Expected, StringComparison.OrdinalIgnoreCase),
                response.ContentType.Length == 0 ? "(no Content-Type header)" : response.ContentType),
            _ => Fail(assertion, $"unsupported assertion kind {(int)assertion.Kind}")
        };
    }

    // -------------------------------------------------------------------- kinds

    private static AssertionOutcome StatusEquals(ApiAssertion a, ApiResponse r)
    {
        if (!TryParseInt(a.Expected, out int expected))
            return Fail(a, $"expected value '{Clip(a.Expected, ComponentClip)}' is not an integer");
        return Check(a, r.StatusCode == expected, r.StatusCode.ToString(CultureInfo.InvariantCulture));
    }

    private static AssertionOutcome StatusIn(ApiAssertion a, ApiResponse r)
    {
        if (!TryParseStatusSet(a.Expected, out var ranges, out string problem))
            return Fail(a, $"status list '{Clip(a.Expected, ComponentClip)}' is malformed: {problem}");

        bool hit = ranges.Any(range => r.StatusCode >= range.Low && r.StatusCode <= range.High);
        return Check(a, hit, r.StatusCode.ToString(CultureInfo.InvariantCulture));
    }

    private static AssertionOutcome HeaderExists(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no header name given");
        bool present = r.Header(a.Target) is not null;
        return Check(a, present, present ? "present" : "absent; headers: " + HeaderNames(r));
    }

    private static AssertionOutcome HeaderEquals(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no header name given");

        var values = r.HeaderValues(a.Target).ToArray();
        if (values.Length == 0)
            return Check(a, false, "header absent; headers: " + HeaderNames(r));

        // Name matched case-insensitively by ApiResponse.HeaderValues (HTTP field
        // names are case-insensitive); the value is compared ordinally because header
        // values such as an ETag or a bearer token are not.
        bool hit = values.Any(v => string.Equals(v, a.Expected, StringComparison.Ordinal));
        return Check(a, hit, string.Join(" | ", values));
    }

    private static AssertionOutcome HeaderContains(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no header name given");

        var values = r.HeaderValues(a.Target).ToArray();
        if (values.Length == 0)
            return Check(a, false, "header absent; headers: " + HeaderNames(r));

        // Contains is the one comparison that ignores case on the value: it exists to
        // spot a token inside a structured header (charset in a content type, a
        // directive in Cache-Control) where casing is not meaningful.
        bool hit = a.Expected.Length > 0 &&
                   values.Any(v => v.Contains(a.Expected, StringComparison.OrdinalIgnoreCase));
        return Check(a, hit, string.Join(" | ", values));
    }

    /// <summary>
    /// Substring check over the body, ordinal and case-sensitive (a body is data, not
    /// a header field). An empty <c>Expected</c> fails the positive form instead of
    /// passing vacuously, because "contains nothing" is always a configuration
    /// mistake and a silent pass would hide it.
    /// </summary>
    private static AssertionOutcome BodyContains(ApiAssertion a, ApiResponse r, bool wanted)
    {
        if (a.Expected.Length == 0)
            return wanted
                ? Fail(a, "no expected substring given")
                : Check(a, true, BodySummary(r));

        bool present = r.BodyText.Contains(a.Expected, StringComparison.Ordinal);
        return Check(a, present == wanted, BodySummary(r));
    }

    private static AssertionOutcome BodyIsValidJson(ApiAssertion a, ApiResponse r)
    {
        bool valid = JsonQuery.IsValidJson(r.BodyText);
        return Check(a, valid, valid ? "valid JSON" : "not valid JSON: " + BodySummary(r));
    }

    private static AssertionOutcome BodyMatchesRegex(ApiAssertion a, ApiResponse r)
    {
        string pattern = PatternOf(a);
        if (pattern.Length == 0) return Fail(a, "no regular expression given");

        var (matched, error) = TryMatch(pattern, r.BodyText);
        if (error is not null) return Fail(a, error);
        return Check(a, matched, matched ? "matched" : "no match in " + BodySummary(r));
    }

    private static AssertionOutcome JsonPathExists(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no json path given");
        bool found = JsonQuery.TrySelect(r.BodyText, a.Target, out string value);
        return Check(a, found, found ? Clip(value, ComponentClip) : "no match" + JsonHint(r));
    }

    private static AssertionOutcome JsonPathEquals(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no json path given");
        if (!JsonQuery.TrySelect(r.BodyText, a.Target, out string value))
            return Check(a, false, "no match" + JsonHint(r));

        // Ordinal comparison of the rendered value. Numbers compare by their JSON
        // text, so "1.0" does not equal "1" - that is intentional, an API changing
        // 1 to 1.0 is a contract change worth failing on.
        return Check(a, string.Equals(value, a.Expected, StringComparison.Ordinal), Clip(value, ComponentClip));
    }

    private static AssertionOutcome JsonPathMatches(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no json path given");
        if (a.Expected.Length == 0) return Fail(a, "no regular expression given");
        if (!JsonQuery.TrySelect(r.BodyText, a.Target, out string value))
            return Check(a, false, "no match" + JsonHint(r));

        var (matched, error) = TryMatch(a.Expected, value);
        if (error is not null) return Fail(a, error);
        return Check(a, matched, Clip(value, ComponentClip));
    }

    private static AssertionOutcome JsonPathCountEquals(ApiAssertion a, ApiResponse r)
    {
        if (a.Target.Length == 0) return Fail(a, "no json path given");
        if (!TryParseInt(a.Expected, out int expected))
            return Fail(a, $"expected value '{Clip(a.Expected, ComponentClip)}' is not an integer");

        int actual = JsonQuery.Count(r.BodyText, a.Target);
        return Check(a, actual == expected, actual.ToString(CultureInfo.InvariantCulture));
    }

    private static AssertionOutcome ResponseTimeUnder(ApiAssertion a, ApiResponse r)
    {
        if (!TryParseDouble(a.Expected, out double limit))
            return Fail(a, $"expected value '{Clip(a.Expected, ComponentClip)}' is not a number");

        double actual = r.Elapsed.TotalMilliseconds;
        // Strictly less than: "under 100 ms" should not be satisfied by exactly 100.
        return Check(a, actual < limit, actual.ToString("F1", CultureInfo.InvariantCulture) + " ms");
    }

    private static AssertionOutcome BodySizeUnder(ApiAssertion a, ApiResponse r)
    {
        if (!TryParseLong(a.Expected, out long limit))
            return Fail(a, $"expected value '{Clip(a.Expected, ComponentClip)}' is not an integer");

        // BodyBytes is what the client actually read off the wire and is authoritative.
        // Fall back to the UTF-8 length of the text for responses assembled by an
        // importer or a test, which set BodyText but leave BodyBytes at zero.
        long actual = r.BodyBytes > 0 ? r.BodyBytes : Encoding.UTF8.GetByteCount(r.BodyText);

        string note = r.BodyTruncated ? " (body was truncated by the read cap)" : "";
        return Check(a, actual < limit, actual.ToString(CultureInfo.InvariantCulture) + " bytes" + note);
    }

    // ---------------------------------------------------------------- rendering

    private static AssertionOutcome Check(ApiAssertion a, bool passed, string actual) => new()
    {
        Name = a.DisplayName,
        Kind = a.Kind,
        Passed = passed,
        Detail = Clip($"expected {ExpectedDescription(a)}; actual {Clip(actual, ComponentClip)}", MaxDetailLength)
    };

    private static AssertionOutcome Fail(ApiAssertion a, string actual) => new()
    {
        Name = a.DisplayName,
        Kind = a.Kind,
        Passed = false,
        Detail = Clip($"expected {ExpectedDescription(a)}; actual {Clip(actual, ComponentClip)}", MaxDetailLength)
    };

    /// <summary>
    /// Human phrasing of what the assertion demanded. Computed from the assertion
    /// alone so a transport failure can still report the expectation.
    /// </summary>
    private static string ExpectedDescription(ApiAssertion a) => a.Kind switch
    {
        AssertionKind.StatusEquals => $"status == {Clip(a.Expected, 40)}",
        AssertionKind.StatusIsSuccess => "status in 200-299",
        AssertionKind.StatusIn => $"status in [{Clip(a.Expected, 60)}]",
        AssertionKind.HeaderExists => $"header '{Clip(a.Target, 60)}' present",
        AssertionKind.HeaderEquals => $"header '{Clip(a.Target, 40)}' == '{Clip(a.Expected, 60)}'",
        AssertionKind.HeaderContains => $"header '{Clip(a.Target, 40)}' contains '{Clip(a.Expected, 60)}'",
        AssertionKind.BodyContains => $"body contains '{Clip(a.Expected, 60)}'",
        AssertionKind.BodyNotContains => $"body does not contain '{Clip(a.Expected, 60)}'",
        AssertionKind.BodyMatchesRegex => $"body matches /{Clip(PatternOf(a), 60)}/",
        AssertionKind.BodyIsValidJson => "body is valid JSON",
        AssertionKind.JsonPathExists => $"json path '{Clip(a.Target, 60)}' exists",
        AssertionKind.JsonPathEquals => $"json path '{Clip(a.Target, 40)}' == '{Clip(a.Expected, 60)}'",
        AssertionKind.JsonPathMatches => $"json path '{Clip(a.Target, 40)}' matches /{Clip(a.Expected, 60)}/",
        AssertionKind.JsonPathCountEquals => $"json path '{Clip(a.Target, 40)}' count == {Clip(a.Expected, 20)}",
        AssertionKind.ResponseTimeUnderMs => $"elapsed < {Clip(a.Expected, 20)} ms",
        AssertionKind.BodySizeUnderBytes => $"body size < {Clip(a.Expected, 20)} bytes",
        AssertionKind.ContentTypeContains => $"content-type contains '{Clip(a.Expected, 60)}'",
        _ => $"unsupported assertion kind {(int)a.Kind}"
    };

    private static string BodySummary(ApiResponse r) =>
        r.BodyText.Length == 0 ? "(empty body)" : Clip(Collapse(r.BodyText), ComponentClip);

    private static string HeaderNames(ApiResponse r) =>
        r.Headers.Count == 0 ? "(none)" : string.Join(", ", r.Headers.Select(h => h.Name));

    /// <summary>
    /// Explains a JSON-path miss: a body that is not JSON at all is by far the most
    /// common cause, and saying so saves the operator a round trip.
    /// </summary>
    private static string JsonHint(ApiResponse r) =>
        JsonQuery.IsValidJson(r.BodyText) ? " (path not present)" : " (body is not valid JSON)";

    /// <summary>Newlines and runs of whitespace collapse to single spaces so Detail stays one line.</summary>
    private static string Collapse(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, ComponentClip + 8));
        bool lastWasSpace = false;
        foreach (char c in text)
        {
            if (sb.Length > ComponentClip) break;
            bool space = char.IsWhiteSpace(c);
            if (space)
            {
                if (!lastWasSpace) sb.Append(' ');
            }
            else
            {
                sb.Append(c);
            }
            lastWasSpace = space;
        }
        return sb.ToString();
    }

    internal static string Clip(string value, int max)
    {
        if (string.IsNullOrEmpty(value)) return value ?? "";
        if (value.Length <= max) return value;
        return max <= 3 ? value[..max] : value[..(max - 3)] + "...";
    }

    // ------------------------------------------------------------------- parsing

    private readonly record struct StatusRange(int Low, int High);

    /// <summary>
    /// Parses a status list such as <c>200, 201 204</c> or <c>200-204,301</c>.
    /// Commas, semicolons and whitespace all separate; a reversed range is normalised
    /// rather than rejected. Any unparseable token fails the whole list, because
    /// silently ignoring one would widen or narrow the check without telling anyone.
    /// </summary>
    private static bool TryParseStatusSet(string spec, out List<StatusRange> ranges, out string problem)
    {
        ranges = new List<StatusRange>();
        problem = "";

        if (string.IsNullOrWhiteSpace(spec))
        {
            problem = "list is empty";
            return false;
        }

        var tokens = spec.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var raw in tokens)
        {
            var token = raw.Trim();
            if (token.Length == 0) continue;

            int dash = token.IndexOf('-', 1);       // start at 1: a leading '-' is a bad status, not a range
            if (dash > 0)
            {
                var lowText = token[..dash];
                var highText = token[(dash + 1)..];
                if (!TryParseInt(lowText, out int low) || !TryParseInt(highText, out int high))
                {
                    problem = $"'{Clip(token, 40)}' is not a range";
                    return false;
                }
                if (low > high) (low, high) = (high, low);
                ranges.Add(new StatusRange(low, high));
                continue;
            }

            if (!TryParseInt(token, out int single))
            {
                problem = $"'{Clip(token, 40)}' is not a status code";
                return false;
            }
            ranges.Add(new StatusRange(single, single));
        }

        if (ranges.Count == 0)
        {
            problem = "list is empty";
            return false;
        }
        return true;
    }

    private static bool TryParseInt(string text, out int value) =>
        int.TryParse((text ?? "").Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static bool TryParseLong(string text, out long value) =>
        long.TryParse((text ?? "").Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out value);

    private static bool TryParseDouble(string text, out double value) =>
        double.TryParse((text ?? "").Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out value);

    /// <summary>
    /// The regex for a body-match assertion. Target is the documented home for it,
    /// but importers that map a foreign format sometimes land the pattern in
    /// Expected, so fall back rather than silently checking nothing.
    /// </summary>
    private static string PatternOf(ApiAssertion a) =>
        a.Target.Length > 0 ? a.Target : a.Expected;

    /// <summary>
    /// Runs a timeout-bounded match. Returns the match result and a null error, or
    /// an error string describing an invalid pattern or a timeout.
    /// </summary>
    internal static (bool Matched, string? Error) TryMatch(string pattern, string subject)
    {
        Regex regex;
        try
        {
            regex = GetRegex(pattern);
        }
        catch (ArgumentException ex)
        {
            return (false, "invalid regular expression: " + ex.Message);
        }

        try
        {
            return (regex.IsMatch(subject ?? ""), null);
        }
        catch (RegexMatchTimeoutException)
        {
            return (false, $"regular expression timed out after {RegexTimeout.TotalMilliseconds:F0} ms " +
                           "(pattern backtracks catastrophically against this body)");
        }
    }

    private static Regex GetRegex(string pattern)
    {
        if (RegexCache.TryGetValue(pattern, out var cached)) return cached;

        // Not RegexOptions.Compiled: patterns arrive from imported files, and JIT-ing
        // each one would let a large collection burn memory that is never reclaimed.
        var regex = new Regex(pattern, RegexOptions.CultureInvariant, RegexTimeout);
        if (RegexCache.Count < MaxCachedPatterns) RegexCache.TryAdd(pattern, regex);
        return regex;
    }
}

/// <summary>
/// Extracts values from a response into runtime variables, so request N+1 can use
/// what request N returned (log in, capture the token, call the protected route).
/// </summary>
public static class CaptureEngine
{
    /// <summary>
    /// Runs every capture against the response. Sources are tried in a fixed
    /// precedence - JSON path, then header, then body regex - so a capture that
    /// specifies more than one has predictable behaviour rather than depending on
    /// field order in the file.
    /// </summary>
    /// <remarks>
    /// A capture that finds nothing is absent from the result rather than mapped to
    /// an empty string. That distinction matters: an empty string would resolve
    /// <c>{{token}}</c> to nothing and send an <c>Authorization: Bearer</c> header
    /// with no token, which usually produces a confusing 400 instead of an obvious
    /// unresolved-variable warning.
    /// </remarks>
    public static IReadOnlyDictionary<string, string> Apply(
        IReadOnlyList<ApiCapture> captures, ApiResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (captures is null || captures.Count == 0) return result;

        // Nothing arrived, so there is nothing to capture. Continuing would read the
        // empty placeholder fields of a failed exchange and record blanks.
        if (!response.Completed) return result;

        foreach (var capture in captures)
        {
            if (capture is null || string.IsNullOrWhiteSpace(capture.Variable)) continue;

            if (TryCapture(capture, response, out string value))
                result[capture.Variable.Trim()] = value;   // a later capture of the same name wins
        }
        return result;
    }

    private static bool TryCapture(ApiCapture capture, ApiResponse response, out string value)
    {
        value = "";

        if (capture.JsonPath.Length > 0 &&
            JsonQuery.TrySelect(response.BodyText, capture.JsonPath, out string fromJson))
        {
            value = fromJson;
            return true;
        }

        if (capture.HeaderName.Length > 0)
        {
            var header = response.Header(capture.HeaderName);
            if (header is not null)
            {
                value = header;
                return true;
            }
        }

        if (capture.BodyRegex.Length > 0)
            return TryCaptureRegex(capture.BodyRegex, response.BodyText, out value);

        return false;
    }

    /// <summary>
    /// Group 1 when the pattern has a capturing group that participated, otherwise the
    /// whole match. An invalid pattern or a timeout yields no capture rather than an
    /// exception, for the same reason assertions never throw.
    /// </summary>
    private static bool TryCaptureRegex(string pattern, string body, out string value)
    {
        value = "";
        try
        {
            var regex = new Regex(pattern, RegexOptions.CultureInvariant, AssertionEvaluator.RegexTimeout);
            var match = regex.Match(body ?? "");
            if (!match.Success) return false;

            value = match.Groups.Count > 1 && match.Groups[1].Success
                ? match.Groups[1].Value
                : match.Value;
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }
}
