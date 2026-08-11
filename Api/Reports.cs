using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Xml.Linq;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// Renders an ApiRunResult as JSON, JUnit XML, Markdown, HTML or console text.
//
// Design notes:
//  * Every format is rendered from ONE intermediate projection (RunReport).
//    Redaction therefore happens exactly once, in one place. Five independent
//    renderers reading ApiRunResult directly is five chances to leak a bearer
//    token into a CI artifact, and the fifth one always gets forgotten.
//  * Request and response BODIES are never included in any report. Bodies
//    routinely carry tokens, session identifiers and personal data, and there is
//    no dependable way to redact an arbitrary body. Size, content type and the
//    assertion outcomes are reported instead. This is a real loss of debugging
//    detail and it is the deliberate trade.
//  * Reports are pure functions of the result. Nothing reads the wall clock, so
//    rendering the same result twice produces byte-identical output.
// ---------------------------------------------------------------------------

/// <summary>
/// Report renderers for a collection run. All output is self-contained text; nothing
/// here writes files, so the caller decides where a report lands.
/// </summary>
public static class ApiReports
{
    /// <summary>What a redacted value is replaced with. Constant so tests and greps can find it.</summary>
    public const string RedactionPlaceholder = "[redacted]";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    // Query parameter names that carry credentials but do not contain "key"/"token"/"secret".
    private static readonly string[] SecretQueryNames =
    {
        "sig", "signature", "password", "passwd", "pwd", "credential", "auth", "code", "state", "session"
    };

    // ------------------------------------------------------------------- JSON

    /// <summary>
    /// Machine-readable report. Stable, camelCase, secrets redacted, no bodies.
    /// Intended for a CI artifact or for diffing two runs.
    /// </summary>
    public static string ToJson(ApiRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return JsonSerializer.Serialize(Project(result), JsonOptions);
    }

    // ------------------------------------------------------------------ JUnit

    /// <summary>
    /// JUnit XML for a CI test reporter. Built with <see cref="XDocument"/> rather than
    /// string concatenation so escaping is the serializer's problem, and every value is
    /// first stripped of characters XML 1.0 cannot represent at all (a NUL in a response
    /// header would otherwise make the document unwritable).
    /// </summary>
    public static string ToJUnitXml(ApiRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        RunReport report = Project(result);

        int errors = report.Executions.Count(e => !string.IsNullOrEmpty(e.Error));
        int failures = report.Executions.Count(e => string.IsNullOrEmpty(e.Error) && !e.Passed);
        double totalSeconds = report.DurationMs / 1000.0;

        var suite = new XElement("testsuite",
            new XAttribute("name", XmlSafe(report.Collection)),
            new XAttribute("tests", report.Summary.Total),
            new XAttribute("failures", failures),
            new XAttribute("errors", errors),
            new XAttribute("skipped", 0),
            new XAttribute("time", Seconds(totalSeconds)),
            new XAttribute("timestamp", XmlSafe(report.StartedUtc)),
            new XElement("properties",
                new XElement("property",
                    new XAttribute("name", "environment"),
                    new XAttribute("value", XmlSafe(report.Environment)))));

        foreach (var e in report.Executions)
        {
            var testcase = new XElement("testcase",
                new XAttribute("name", XmlSafe(e.Name)),
                new XAttribute("classname", XmlSafe(string.IsNullOrEmpty(report.Collection) ? "api" : report.Collection)),
                new XAttribute("time", Seconds(e.ElapsedMs / 1000.0)));

            if (!string.IsNullOrEmpty(e.Error))
            {
                testcase.Add(new XElement("error",
                    new XAttribute("type", "transport"),
                    new XAttribute("message", XmlSafe(e.Error)),
                    new XText(XmlSafe($"{e.Method} {e.Url}\n{e.Error}"))));
            }
            else if (!e.Passed)
            {
                var detail = new StringBuilder();
                foreach (var a in e.Assertions.Where(a => !a.Passed))
                    detail.Append(a.Name).Append(" -- ").Append(a.Detail).Append('\n');

                testcase.Add(new XElement("failure",
                    new XAttribute("type", "assertion"),
                    new XAttribute("message", XmlSafe($"{e.Assertions.Count(a => !a.Passed)} assertion(s) failed")),
                    new XText(XmlSafe(detail.ToString()))));
            }

            var systemOut = new StringBuilder();
            systemOut.Append(e.Method).Append(' ').Append(e.Url).Append('\n');
            systemOut.Append("status ").Append(e.StatusCode.ToString(CultureInfo.InvariantCulture));
            if (!string.IsNullOrEmpty(e.ReasonPhrase)) systemOut.Append(' ').Append(e.ReasonPhrase);
            systemOut.Append('\n');
            foreach (var f in e.Findings)
                systemOut.Append("finding ").Append(f.Severity).Append(": ").Append(f.Title).Append('\n');
            testcase.Add(new XElement("system-out", new XText(XmlSafe(systemOut.ToString()))));

            suite.Add(testcase);
        }

        var root = new XElement("testsuites",
            new XAttribute("name", XmlSafe(report.Collection)),
            new XAttribute("tests", report.Summary.Total),
            new XAttribute("failures", failures),
            new XAttribute("errors", errors),
            new XAttribute("time", Seconds(totalSeconds)),
            suite);

        // XElement.ToString() omits the declaration, and some CI reporters insist on one.
        var declaration = new XDeclaration("1.0", "utf-8", null);
        return declaration.ToString() + "\n" + root.ToString();
    }

    // --------------------------------------------------------------- Markdown

    /// <summary>Markdown summary for a pull-request comment or a wiki page.</summary>
    public static string ToMarkdown(ApiRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        RunReport report = Project(result);
        var sb = new StringBuilder();

        sb.Append("# API run: ").Append(Md(report.Collection)).Append('\n').Append('\n');
        sb.Append("- Environment: `").Append(Md(report.Environment)).Append("`\n");
        sb.Append("- Started: `").Append(Md(report.StartedUtc)).Append("`\n");
        sb.Append("- Duration: ").Append(Ms(report.DurationMs)).Append('\n');
        sb.Append("- Result: **").Append(report.Summary.Success ? "PASS" : "FAIL").Append("** - ")
          .Append(report.Summary.Passed).Append('/').Append(report.Summary.Total).Append(" requests, ")
          .Append(report.Summary.AssertionsRun - report.Summary.AssertionsFailed).Append('/')
          .Append(report.Summary.AssertionsRun).Append(" assertions\n\n");

        sb.Append("| # | Result | Request | Method | Status | Time |\n");
        sb.Append("|---:|:---|:---|:---|---:|---:|\n");
        foreach (var e in report.Executions)
        {
            sb.Append("| ").Append(e.Index)
              .Append(" | ").Append(e.Passed ? "PASS" : "FAIL")
              .Append(" | ").Append(Md(e.Name))
              .Append(" | ").Append(Md(e.Method))
              .Append(" | ").Append(string.IsNullOrEmpty(e.Error) ? e.StatusCode.ToString(CultureInfo.InvariantCulture) : "-")
              .Append(" | ").Append(Ms(e.ElapsedMs))
              .Append(" |\n");
        }

        var problems = report.Executions.Where(e => !e.Passed).ToList();
        if (problems.Count > 0)
        {
            sb.Append("\n## Failures\n\n");
            foreach (var e in problems)
            {
                sb.Append("### ").Append(Md(e.Name)).Append('\n');
                sb.Append('`').Append(Md(e.Method)).Append(' ').Append(Md(e.Url)).Append("`\n\n");
                if (!string.IsNullOrEmpty(e.Error))
                    sb.Append("- transport error: ").Append(Md(e.Error)).Append('\n');
                foreach (var a in e.Assertions.Where(a => !a.Passed))
                    sb.Append("- failed `").Append(Md(a.Kind)).Append("`: ").Append(Md(a.Detail)).Append('\n');
                sb.Append('\n');
            }
        }

        var findings = report.Executions.SelectMany(e => e.Findings).ToList();
        if (findings.Count > 0)
        {
            sb.Append("\n## Security findings\n\n");
            sb.Append("| Severity | Id | Title | Endpoint | OWASP |\n");
            sb.Append("|:---|:---|:---|:---|:---|\n");
            foreach (var f in findings.OrderByDescending(SeverityRank))
            {
                sb.Append("| ").Append(Md(f.Severity))
                  .Append(" | ").Append(Md(f.Id))
                  .Append(" | ").Append(Md(f.Title))
                  .Append(" | ").Append(Md(f.Endpoint))
                  .Append(" | ").Append(Md(f.Owasp))
                  .Append(" |\n");
            }
        }

        sb.Append("\n_Secrets in headers and URLs are redacted; request and response bodies are not included._\n");
        return sb.ToString();
    }

    // ------------------------------------------------------------------- HTML

    /// <summary>
    /// A single self-contained HTML file: inline CSS, no scripts, no external assets, so
    /// it can be opened from an air-gapped analyst workstation or attached to a ticket.
    /// Every interpolated value goes through <see cref="WebUtility.HtmlEncode"/>.
    /// </summary>
    public static string ToHtml(ApiRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        RunReport report = Project(result);
        var sb = new StringBuilder();

        sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.Append("<title>API run: ").Append(H(report.Collection)).Append("</title>\n");
        sb.Append("<style>\n").Append(Css).Append("</style>\n</head>\n<body>\n");

        sb.Append("<h1>API run: ").Append(H(report.Collection)).Append("</h1>\n");
        sb.Append("<p class=\"meta\">environment <code>").Append(H(report.Environment)).Append("</code>")
          .Append(" &middot; started <code>").Append(H(report.StartedUtc)).Append("</code>")
          .Append(" &middot; ").Append(H(Ms(report.DurationMs))).Append("</p>\n");

        sb.Append("<div class=\"cards\">");
        sb.Append(Card("result", report.Summary.Success ? "PASS" : "FAIL", report.Summary.Success ? "ok" : "bad"));
        sb.Append(Card("requests", $"{report.Summary.Passed}/{report.Summary.Total}", "neutral"));
        sb.Append(Card("assertions",
            $"{report.Summary.AssertionsRun - report.Summary.AssertionsFailed}/{report.Summary.AssertionsRun}", "neutral"));
        sb.Append(Card("findings", report.Executions.Sum(e => e.Findings.Count).ToString(CultureInfo.InvariantCulture), "neutral"));
        sb.Append("</div>\n");

        sb.Append("<table>\n<thead><tr><th>#</th><th>Result</th><th>Request</th><th>Method</th>")
          .Append("<th>URL</th><th>Status</th><th>Time</th></tr></thead>\n<tbody>\n");
        foreach (var e in report.Executions)
        {
            sb.Append("<tr>");
            sb.Append("<td>").Append(e.Index).Append("</td>");
            sb.Append("<td class=\"").Append(e.Passed ? "ok" : "bad").Append("\">").Append(e.Passed ? "PASS" : "FAIL").Append("</td>");
            sb.Append("<td>").Append(H(e.Name)).Append("</td>");
            sb.Append("<td>").Append(H(e.Method)).Append("</td>");
            sb.Append("<td class=\"url\">").Append(H(e.Url)).Append("</td>");
            sb.Append("<td>").Append(string.IsNullOrEmpty(e.Error) ? e.StatusCode.ToString(CultureInfo.InvariantCulture) : "&mdash;").Append("</td>");
            sb.Append("<td>").Append(H(Ms(e.ElapsedMs))).Append("</td>");
            sb.Append("</tr>\n");
        }
        sb.Append("</tbody>\n</table>\n");

        foreach (var e in report.Executions)
        {
            sb.Append("<section>\n<h2>").Append(e.Index).Append(". ").Append(H(e.Name)).Append("</h2>\n");
            sb.Append("<p class=\"meta\"><code>").Append(H(e.Method)).Append(' ').Append(H(e.Url)).Append("</code></p>\n");

            if (!string.IsNullOrEmpty(e.Error))
                sb.Append("<p class=\"bad\">transport error: ").Append(H(e.Error)).Append("</p>\n");

            if (e.Assertions.Count > 0)
            {
                sb.Append("<table class=\"inner\"><thead><tr><th>Assertion</th><th>Result</th><th>Detail</th></tr></thead><tbody>\n");
                foreach (var a in e.Assertions)
                {
                    sb.Append("<tr><td>").Append(H(a.Name)).Append("</td>")
                      .Append("<td class=\"").Append(a.Passed ? "ok" : "bad").Append("\">")
                      .Append(a.Passed ? "pass" : "fail").Append("</td>")
                      .Append("<td>").Append(H(a.Detail)).Append("</td></tr>\n");
                }
                sb.Append("</tbody></table>\n");
            }

            if (e.ResponseHeaders.Count > 0)
            {
                sb.Append("<details><summary>response headers</summary><table class=\"inner\"><tbody>\n");
                foreach (var h in e.ResponseHeaders)
                    sb.Append("<tr><td>").Append(H(h.Name)).Append("</td><td>").Append(H(h.Value)).Append("</td></tr>\n");
                sb.Append("</tbody></table></details>\n");
            }

            if (e.Findings.Count > 0)
            {
                sb.Append("<table class=\"inner\"><thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>OWASP</th></tr></thead><tbody>\n");
                foreach (var f in e.Findings.OrderByDescending(SeverityRank))
                {
                    sb.Append("<tr><td>").Append(H(f.Severity)).Append("</td>")
                      .Append("<td>").Append(H(f.Title)).Append("</td>")
                      .Append("<td>").Append(H(f.Detail)).Append("</td>")
                      .Append("<td>").Append(H(f.Owasp)).Append("</td></tr>\n");
                }
                sb.Append("</tbody></table>\n");
            }

            sb.Append("</section>\n");
        }

        sb.Append("<p class=\"foot\">Secrets in headers and URLs are redacted. ")
          .Append("Request and response bodies are deliberately omitted from this report.</p>\n");
        sb.Append("</body>\n</html>\n");
        return sb.ToString();
    }

    // ---------------------------------------------------------------- console

    /// <summary>Plain text for a terminal or a log file. No ANSI colour, so it stays readable when redirected.</summary>
    public static string ToConsoleText(ApiRunResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        RunReport report = Project(result);
        var sb = new StringBuilder();

        sb.Append("API run: ").Append(report.Collection)
          .Append("  [env ").Append(report.Environment).Append("]\n");
        sb.Append("started ").Append(report.StartedUtc)
          .Append("  duration ").Append(Ms(report.DurationMs)).Append("\n\n");

        foreach (var e in report.Executions)
        {
            sb.Append(e.Passed ? "PASS  " : "FAIL  ");
            sb.Append(e.Index.ToString(CultureInfo.InvariantCulture).PadLeft(3)).Append("  ");
            sb.Append(Fit(e.Method, 6)).Append(' ');
            sb.Append(Fit(e.Name, 40)).Append("  ");
            sb.Append((string.IsNullOrEmpty(e.Error) ? e.StatusCode.ToString(CultureInfo.InvariantCulture) : "---").PadLeft(4));
            sb.Append("  ").Append(Ms(e.ElapsedMs).PadLeft(10)).Append('\n');

            if (!string.IsNullOrEmpty(e.Error))
                sb.Append("        error: ").Append(e.Error).Append('\n');
            foreach (var a in e.Assertions.Where(a => !a.Passed))
                sb.Append("        assertion failed: ").Append(a.Name)
                  .Append(string.IsNullOrEmpty(a.Detail) ? "" : " -- " + a.Detail).Append('\n');
            foreach (var f in e.Findings.OrderByDescending(SeverityRank))
                sb.Append("        finding [").Append(f.Severity).Append("] ").Append(f.Title).Append('\n');
        }

        sb.Append('\n');
        sb.Append(report.Summary.Total).Append(" requests, ")
          .Append(report.Summary.Passed).Append(" passed, ")
          .Append(report.Summary.Failed).Append(" failed; ")
          .Append(report.Summary.AssertionsRun).Append(" assertions, ")
          .Append(report.Summary.AssertionsFailed).Append(" failed\n");
        sb.Append(report.Summary.Success ? "RESULT: PASS\n" : "RESULT: FAIL\n");
        return sb.ToString();
    }

    // ------------------------------------------------------------ projection

    /// <summary>
    /// The single redaction point. Everything a report can show is produced here.
    /// </summary>
    internal static RunReport Project(ApiRunResult result)
    {
        var executions = new List<ExecutionReport>(result.Executions.Count);
        int index = 0;

        foreach (var e in result.Executions)
        {
            index++;
            executions.Add(new ExecutionReport
            {
                Index = index,
                Name = e.Request.DisplayName,
                Method = string.IsNullOrWhiteSpace(e.Request.Method) ? "GET" : e.Request.Method,
                Url = RedactUrl(string.IsNullOrEmpty(e.ResolvedUrl) ? e.Request.Url : e.ResolvedUrl),
                StatusCode = e.Response.StatusCode,
                ReasonPhrase = e.Response.ReasonPhrase,
                ElapsedMs = Math.Round(e.Response.Elapsed.TotalMilliseconds, 3),
                BodyBytes = e.Response.BodyBytes,
                BodyTruncated = e.Response.BodyTruncated,
                ContentType = e.Response.ContentType,
                Error = e.Response.Error,
                Passed = e.Passed,
                RequestHeaders = RedactHeaders(e.Request.Headers.Where(h => h.Enabled)),
                ResponseHeaders = RedactHeaders(e.Response.Headers),
                RedirectChain = e.Response.RedirectChain.Select(RedactUrl).ToArray(),
                Assertions = e.Assertions.Select(a => new AssertionReport
                {
                    Name = a.Name,
                    Kind = a.Kind.ToString(),
                    Passed = a.Passed,
                    Detail = a.Detail
                }).ToArray(),
                Captured = e.Captured.ToDictionary(
                    kv => kv.Key,
                    kv => IsSecretName(kv.Key) ? RedactionPlaceholder : kv.Value,
                    StringComparer.OrdinalIgnoreCase),
                Findings = e.Findings.Select(f => new FindingReport
                {
                    Id = f.Id,
                    Title = f.Title,
                    Severity = f.Severity.ToString(),
                    Owasp = f.Owasp,
                    Detail = f.Detail,
                    Recommendation = f.Recommendation,
                    // Evidence is documented as already redacted by the analyzer; it is not
                    // re-processed here because we cannot tell a snippet from a secret.
                    Evidence = f.Evidence,
                    Endpoint = RedactUrl(f.Endpoint)
                }).ToArray(),
                Tls = e.Response.Tls is null ? null : new TlsReport
                {
                    Protocol = e.Response.Tls.Protocol,
                    CipherAlgorithm = e.Response.Tls.CipherAlgorithm,
                    Subject = e.Response.Tls.Subject,
                    Issuer = e.Response.Tls.Issuer,
                    NotBeforeUtc = Iso(e.Response.Tls.NotBeforeUtc),
                    NotAfterUtc = Iso(e.Response.Tls.NotAfterUtc),
                    Thumbprint = e.Response.Tls.Thumbprint,
                    SignatureAlgorithm = e.Response.Tls.SignatureAlgorithm,
                    KeySizeBits = e.Response.Tls.KeySizeBits,
                    ChainValid = e.Response.Tls.ChainValid,
                    ChainErrors = e.Response.Tls.ChainErrors,
                    SubjectAltNames = e.Response.Tls.SubjectAltNames
                }
            });
        }

        return new RunReport
        {
            Collection = result.CollectionName,
            Environment = result.EnvironmentName,
            StartedUtc = Iso(result.StartedUtc),
            DurationMs = Math.Round(result.Duration.TotalMilliseconds, 3),
            Summary = new SummaryReport
            {
                Total = result.Total,
                Passed = result.Passed,
                Failed = result.Failed,
                AssertionsRun = result.AssertionsRun,
                AssertionsFailed = result.AssertionsFailed,
                Success = result.Success
            },
            Executions = executions
        };
    }

    private static IReadOnlyList<HeaderReport> RedactHeaders(IEnumerable<ApiKeyValue> headers) =>
        headers.Select(h => new HeaderReport { Name = h.Name, Value = RedactHeaderValue(h.Name, h.Value) }).ToArray();

    // ------------------------------------------------------------- redaction

    /// <summary>
    /// True for header or variable names that plausibly carry a credential. The
    /// substring test over-matches on purpose (a header called <c>X-Monkey-Id</c>
    /// contains "key" and will be redacted): a redacted diagnostic is an annoyance,
    /// a leaked token in a CI artifact is an incident.
    /// </summary>
    internal static bool IsSecretName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        string n = name.ToLowerInvariant();
        return n is "authorization" or "proxy-authorization"
            || n.Contains("key", StringComparison.Ordinal)
            || n.Contains("token", StringComparison.Ordinal)
            || n.Contains("secret", StringComparison.Ordinal)
            || n.Contains("password", StringComparison.Ordinal)
            || n.Contains("credential", StringComparison.Ordinal);
    }

    internal static bool IsCookieHeader(string? name) =>
        string.Equals(name, "Cookie", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "Set-Cookie", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Redacts a header value while keeping the parts that carry no secret but do carry
    /// security meaning: the auth scheme, and the cookie attributes (HttpOnly, Secure,
    /// SameSite) that the endpoint analyzer and a human reviewer both need to see.
    /// </summary>
    internal static string RedactHeaderValue(string? name, string? value)
    {
        string v = value ?? "";
        if (v.Length == 0) return v;

        if (IsCookieHeader(name)) return RedactCookie(v);
        if (!IsSecretName(name)) return v;

        int space = v.IndexOf(' ');
        if (space > 0 && space <= 12 && IsSchemeToken(v.AsSpan(0, space)))
            return v[..space] + " " + RedactionPlaceholder;

        return RedactionPlaceholder;
    }

    private static bool IsSchemeToken(ReadOnlySpan<char> s)
    {
        foreach (char c in s)
            if (!char.IsAsciiLetter(c)) return false;
        return s.Length > 0;
    }

    // Cookie:      a=1; b=2          -> a=[redacted]; b=[redacted]
    // Set-Cookie:  a=1; Path=/; Secure -> a=[redacted]; Path=/; Secure
    private static string RedactCookie(string value)
    {
        string[] parts = value.Split(';');
        var sb = new StringBuilder();
        for (int i = 0; i < parts.Length; i++)
        {
            string part = parts[i];
            string trimmed = part.Trim();
            if (i > 0) sb.Append("; ");

            int eq = trimmed.IndexOf('=');
            bool isAttribute = i > 0 && IsCookieAttribute(eq >= 0 ? trimmed[..eq] : trimmed);
            if (eq > 0 && !isAttribute) sb.Append(trimmed[..eq]).Append('=').Append(RedactionPlaceholder);
            else sb.Append(trimmed);
        }
        return sb.ToString();
    }

    private static bool IsCookieAttribute(string name) => name.Trim().ToLowerInvariant() switch
    {
        "path" or "domain" or "expires" or "max-age" or "samesite" or "secure" or "httponly" or "priority" or "partitioned" => true,
        _ => false
    };

    /// <summary>
    /// Redacts credentials carried in a URL: the userinfo component and any query
    /// parameter whose name looks like a credential. An api-key-in-query auth kind puts
    /// a live key straight into <see cref="ApiExecution.ResolvedUrl"/>, so this is not a
    /// theoretical concern. Works on the raw string so a URL too broken to parse is
    /// still redacted rather than skipped.
    /// </summary>
    internal static string RedactUrl(string? url)
    {
        if (string.IsNullOrEmpty(url)) return "";
        string s = url;

        int schemeEnd = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd >= 0)
        {
            int authorityStart = schemeEnd + 3;
            int authorityEnd = s.IndexOfAny(new[] { '/', '?', '#' }, authorityStart);
            if (authorityEnd < 0) authorityEnd = s.Length;
            string authority = s[authorityStart..authorityEnd];
            int at = authority.LastIndexOf('@');
            if (at > 0)
            {
                string userinfo = authority[..at];
                int colon = userinfo.IndexOf(':');
                string masked = colon >= 0 ? userinfo[..colon] + ":" + RedactionPlaceholder : userinfo;
                s = s[..authorityStart] + masked + authority[at..] + s[authorityEnd..];
            }
        }

        int q = s.IndexOf('?');
        if (q < 0) return s;

        int fragment = s.IndexOf('#', q);
        string query = fragment >= 0 ? s[(q + 1)..fragment] : s[(q + 1)..];
        string tail = fragment >= 0 ? s[fragment..] : "";
        if (query.Length == 0) return s;

        string[] pairs = query.Split('&');
        for (int i = 0; i < pairs.Length; i++)
        {
            int eq = pairs[i].IndexOf('=');
            if (eq <= 0) continue;
            string name = Uri.UnescapeDataString(pairs[i][..eq]);
            if (IsSecretName(name) || SecretQueryNames.Contains(name.ToLowerInvariant()))
                pairs[i] = pairs[i][..eq] + "=" + RedactionPlaceholder;
        }

        return s[..(q + 1)] + string.Join("&", pairs) + tail;
    }

    // -------------------------------------------------------------- escaping

    /// <summary>
    /// Drops characters XML 1.0 cannot encode at all (control characters other than
    /// tab/CR/LF, and unpaired surrogates). <see cref="XElement"/> would throw when
    /// serializing them, which would turn a hostile response header into a crashed
    /// report generator. Valid surrogate pairs are preserved.
    /// </summary>
    internal static string XmlSafe(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(value.Length);
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                {
                    sb.Append(c).Append(value[i + 1]);
                    i++;
                }
                continue;   // lone high surrogate: not representable
            }
            if (char.IsLowSurrogate(c)) continue;
            bool ok = c is '\t' or '\n' or '\r' || (c >= 0x20 && c <= 0xD7FF) || (c >= 0xE000 && c <= 0xFFFD);
            if (ok) sb.Append(c);
        }
        return sb.ToString();
    }

    private static string H(string? value) => WebUtility.HtmlEncode(value ?? "");

    // Markdown cells break on a raw pipe or newline; backslash-escaping the pipe keeps
    // the table intact without mangling the text.
    private static string Md(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value.Replace("\\", "\\\\", StringComparison.Ordinal)
                    .Replace("|", "\\|", StringComparison.Ordinal)
                    .Replace("\r", " ", StringComparison.Ordinal)
                    .Replace("\n", " ", StringComparison.Ordinal);
    }

    private static string Card(string label, string value, string tone) =>
        $"<div class=\"card {H(tone)}\"><div class=\"card-value\">{H(value)}</div><div class=\"card-label\">{H(label)}</div></div>";

    private static string Fit(string? value, int width)
    {
        string s = value ?? "";
        if (s.Length > width) return s[..Math.Max(0, width - 3)] + "...";
        return s.PadRight(width);
    }

    private static string Ms(double milliseconds) =>
        milliseconds >= 1000
            ? (milliseconds / 1000.0).ToString("F2", CultureInfo.InvariantCulture) + " s"
            : milliseconds.ToString("F0", CultureInfo.InvariantCulture) + " ms";

    private static string Seconds(double seconds) => seconds.ToString("F3", CultureInfo.InvariantCulture);

    private static string Iso(DateTime value) =>
        value == default ? "" : value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    private static int SeverityRank(FindingReport f) => f.Severity switch
    {
        nameof(FindingSeverity.Critical) => 4,
        nameof(FindingSeverity.High) => 3,
        nameof(FindingSeverity.Medium) => 2,
        nameof(FindingSeverity.Low) => 1,
        _ => 0
    };

    private const string Css = """
        :root { color-scheme: light dark; }
        body { font-family: Segoe UI, system-ui, sans-serif; margin: 2rem; line-height: 1.45; }
        h1 { font-size: 1.5rem; margin-bottom: .25rem; }
        h2 { font-size: 1.05rem; margin: 1.5rem 0 .25rem; }
        .meta { color: #666; font-size: .85rem; margin-top: 0; }
        .cards { display: flex; gap: .75rem; flex-wrap: wrap; margin: 1rem 0 1.5rem; }
        .card { border: 1px solid #bbb; border-radius: 6px; padding: .6rem 1rem; min-width: 6rem; }
        .card-value { font-size: 1.3rem; font-weight: 600; }
        .card-label { font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #666; }
        table { border-collapse: collapse; width: 100%; font-size: .88rem; }
        th, td { border-bottom: 1px solid #ccc; padding: .35rem .5rem; text-align: left; vertical-align: top; }
        th { font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .03em; }
        table.inner { margin: .5rem 0 1rem; font-size: .82rem; }
        td.url { word-break: break-all; max-width: 32rem; }
        .ok { color: #14702f; font-weight: 600; }
        .bad { color: #a11; font-weight: 600; }
        code { font-family: Consolas, monospace; font-size: .85em; }
        section { border-top: 1px solid #ddd; padding-top: .25rem; }
        .foot { margin-top: 2rem; font-size: .78rem; color: #666; }
        @media (prefers-color-scheme: dark) {
          .meta, .card-label, .foot { color: #9aa; }
          .card { border-color: #445; }
          th, td { border-color: #334; }
          section { border-color: #334; }
          .ok { color: #4ec97a; }
          .bad { color: #ff7a7a; }
        }
        """;

    // ------------------------------------------------------------ report model

    /// <summary>Redacted, body-free projection of a run. The only thing the renderers see.</summary>
    internal sealed record RunReport
    {
        public string Collection { get; init; } = "";
        public string Environment { get; init; } = "";
        public string StartedUtc { get; init; } = "";
        public double DurationMs { get; init; }
        public SummaryReport Summary { get; init; } = new();
        public IReadOnlyList<ExecutionReport> Executions { get; init; } = Array.Empty<ExecutionReport>();
    }

    internal sealed record SummaryReport
    {
        public int Total { get; init; }
        public int Passed { get; init; }
        public int Failed { get; init; }
        public int AssertionsRun { get; init; }
        public int AssertionsFailed { get; init; }
        public bool Success { get; init; }
    }

    internal sealed record ExecutionReport
    {
        public int Index { get; init; }
        public string Name { get; init; } = "";
        public string Method { get; init; } = "";
        public string Url { get; init; } = "";
        public int StatusCode { get; init; }
        public string ReasonPhrase { get; init; } = "";
        public double ElapsedMs { get; init; }
        public long BodyBytes { get; init; }
        public bool BodyTruncated { get; init; }
        public string ContentType { get; init; } = "";
        public string Error { get; init; } = "";
        public bool Passed { get; init; }
        public IReadOnlyList<HeaderReport> RequestHeaders { get; init; } = Array.Empty<HeaderReport>();
        public IReadOnlyList<HeaderReport> ResponseHeaders { get; init; } = Array.Empty<HeaderReport>();
        public IReadOnlyList<string> RedirectChain { get; init; } = Array.Empty<string>();
        public IReadOnlyList<AssertionReport> Assertions { get; init; } = Array.Empty<AssertionReport>();
        public IReadOnlyDictionary<string, string> Captured { get; init; } = new Dictionary<string, string>();
        public IReadOnlyList<FindingReport> Findings { get; init; } = Array.Empty<FindingReport>();
        public TlsReport? Tls { get; init; }
    }

    internal sealed record HeaderReport
    {
        public string Name { get; init; } = "";
        public string Value { get; init; } = "";
    }

    internal sealed record AssertionReport
    {
        public string Name { get; init; } = "";
        public string Kind { get; init; } = "";
        public bool Passed { get; init; }
        public string Detail { get; init; } = "";
    }

    internal sealed record FindingReport
    {
        public string Id { get; init; } = "";
        public string Title { get; init; } = "";
        public string Severity { get; init; } = "";
        public string Owasp { get; init; } = "";
        public string Detail { get; init; } = "";
        public string Recommendation { get; init; } = "";
        public string Evidence { get; init; } = "";
        public string Endpoint { get; init; } = "";
    }

    internal sealed record TlsReport
    {
        public string Protocol { get; init; } = "";
        public string CipherAlgorithm { get; init; } = "";
        public string Subject { get; init; } = "";
        public string Issuer { get; init; } = "";
        public string NotBeforeUtc { get; init; } = "";
        public string NotAfterUtc { get; init; } = "";
        public string Thumbprint { get; init; } = "";
        public string SignatureAlgorithm { get; init; } = "";
        public int KeySizeBits { get; init; }
        public bool ChainValid { get; init; }
        public IReadOnlyList<string> ChainErrors { get; init; } = Array.Empty<string>();
        public IReadOnlyList<string> SubjectAltNames { get; init; } = Array.Empty<string>();
    }
}
