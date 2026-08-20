using System.Net;
using System.Text;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// Shared data contract for API Studio: the request/collection model, the
// response record, assertions, findings and the safety policy. Everything else
// in ProcessShield.Api (importers, exporters, the client, the runner, the
// security analyzer, the surface inventory and the control server) is written
// against these types.
//
// Design notes:
//  * All models are immutable records with defaulted members so a partially
//    populated import still round-trips.
//  * Nothing here performs I/O. That keeps the whole model layer trivially
//    unit-testable with no network and no disk.
// ---------------------------------------------------------------------------

public enum ApiAuthKind
{
    None,
    /// <summary>HTTP Basic: base64(user:pass) in an Authorization header.</summary>
    Basic,
    /// <summary>Authorization: Bearer &lt;token&gt;.</summary>
    Bearer,
    /// <summary>A named header carrying an API key.</summary>
    ApiKeyHeader,
    /// <summary>A named query-string parameter carrying an API key.</summary>
    ApiKeyQuery,
    /// <summary>Send a pre-built Authorization header verbatim.</summary>
    RawHeader
}

/// <summary>
/// Authentication material for a request. Secret fields are never written to
/// exported collections — see <see cref="Redacted"/>.
/// </summary>
public sealed record ApiAuth
{
    public static readonly ApiAuth None = new();

    public ApiAuthKind Kind { get; init; } = ApiAuthKind.None;
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public string Token { get; init; } = "";
    /// <summary>Header or query-parameter name for the API-key kinds.</summary>
    public string KeyName { get; init; } = "";
    public string KeyValue { get; init; } = "";
    /// <summary>Verbatim Authorization value for <see cref="ApiAuthKind.RawHeader"/>.</summary>
    public string RawValue { get; init; } = "";

    /// <summary>A copy with every secret replaced by a placeholder, for export and logs.</summary>
    public ApiAuth Redacted() => Kind == ApiAuthKind.None
        ? this
        : this with
        {
            Password = string.IsNullOrEmpty(Password) ? "" : "{{password}}",
            Token = string.IsNullOrEmpty(Token) ? "" : "{{token}}",
            KeyValue = string.IsNullOrEmpty(KeyValue) ? "" : "{{apiKey}}",
            RawValue = string.IsNullOrEmpty(RawValue) ? "" : "{{authorization}}"
        };

    /// <summary>
    /// The Authorization header value this auth produces, or null when the auth
    /// travels somewhere other than the Authorization header.
    /// </summary>
    public string? AuthorizationHeader() => Kind switch
    {
        ApiAuthKind.Basic => "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(Username + ":" + Password)),
        ApiAuthKind.Bearer => "Bearer " + Token,
        ApiAuthKind.RawHeader => string.IsNullOrEmpty(RawValue) ? null : RawValue,
        _ => null
    };
}

/// <summary>A header or query parameter. Disabled entries are kept so the UI can toggle them.</summary>
public sealed record ApiKeyValue
{
    public required string Name { get; init; }
    public string Value { get; init; } = "";
    public bool Enabled { get; init; } = true;
    public string Description { get; init; } = "";

    public static ApiKeyValue Of(string name, string value) => new() { Name = name, Value = value };
}

public enum ApiBodyKind
{
    None,
    /// <summary>Raw text sent as-is with an explicit content type.</summary>
    Raw,
    /// <summary>Raw text sent as application/json.</summary>
    Json,
    /// <summary>application/x-www-form-urlencoded from <see cref="ApiBody.Form"/>.</summary>
    UrlEncoded,
    /// <summary>multipart/form-data from <see cref="ApiBody.Form"/>.</summary>
    Multipart,
    /// <summary>The contents of a file on disk.</summary>
    File
}

public sealed record ApiBody
{
    public static readonly ApiBody None = new();

    public ApiBodyKind Kind { get; init; } = ApiBodyKind.None;
    public string Text { get; init; } = "";
    public IReadOnlyList<ApiKeyValue> Form { get; init; } = Array.Empty<ApiKeyValue>();
    /// <summary>Absolute path for <see cref="ApiBodyKind.File"/>.</summary>
    public string FilePath { get; init; } = "";
    /// <summary>Explicit content type. Empty means "derive from Kind".</summary>
    public string ContentType { get; init; } = "";

    public string EffectiveContentType() => !string.IsNullOrWhiteSpace(ContentType) ? ContentType : Kind switch
    {
        ApiBodyKind.Json => "application/json",
        ApiBodyKind.UrlEncoded => "application/x-www-form-urlencoded",
        ApiBodyKind.Multipart => "multipart/form-data",
        ApiBodyKind.Raw => "text/plain",
        ApiBodyKind.File => "application/octet-stream",
        _ => ""
    };

    public static ApiBody Json(string json) => new() { Kind = ApiBodyKind.Json, Text = json };
}

// ---------------------------------------------------------------- assertions

public enum AssertionKind
{
    StatusEquals,
    StatusIsSuccess,
    StatusIn,
    HeaderExists,
    HeaderEquals,
    HeaderContains,
    BodyContains,
    BodyNotContains,
    BodyMatchesRegex,
    BodyIsValidJson,
    JsonPathExists,
    JsonPathEquals,
    JsonPathMatches,
    JsonPathCountEquals,
    ResponseTimeUnderMs,
    BodySizeUnderBytes,
    ContentTypeContains
}

/// <summary>One check applied to a response. Purely declarative so it serialises.</summary>
public sealed record ApiAssertion
{
    public required AssertionKind Kind { get; init; }
    /// <summary>Header name, JSON path, or regex — depends on <see cref="Kind"/>.</summary>
    public string Target { get; init; } = "";
    /// <summary>Expected value; for StatusIn a comma-separated list.</summary>
    public string Expected { get; init; } = "";
    /// <summary>Human label. Auto-generated when empty.</summary>
    public string Name { get; init; } = "";

    public string DisplayName => string.IsNullOrWhiteSpace(Name)
        ? $"{Kind}{(string.IsNullOrEmpty(Target) ? "" : " " + Target)}{(string.IsNullOrEmpty(Expected) ? "" : " == " + Expected)}"
        : Name;

    public static ApiAssertion Status(int code) =>
        new() { Kind = AssertionKind.StatusEquals, Expected = code.ToString() };
}

public sealed record AssertionOutcome
{
    public required string Name { get; init; }
    public required bool Passed { get; init; }
    public string Detail { get; init; } = "";
    public AssertionKind Kind { get; init; }
}

/// <summary>
/// Pulls a value out of a response into a runtime variable, so request N+1 can use
/// what request N returned (login → token → authenticated call).
/// </summary>
public sealed record ApiCapture
{
    public required string Variable { get; init; }
    /// <summary>Dotted/bracketed JSON path, e.g. <c>data.items[0].id</c>.</summary>
    public string JsonPath { get; init; } = "";
    public string HeaderName { get; init; } = "";
    /// <summary>Regex over the body; group 1 (or group 0) is captured.</summary>
    public string BodyRegex { get; init; } = "";
}

// ------------------------------------------------------------------ requests

public sealed record ApiRequest
{
    public string Id { get; init; } = Guid.NewGuid().ToString("n");
    public string Name { get; init; } = "";
    public string Method { get; init; } = "GET";
    public string Url { get; init; } = "";
    public string Description { get; init; } = "";

    public IReadOnlyList<ApiKeyValue> Headers { get; init; } = Array.Empty<ApiKeyValue>();
    public IReadOnlyList<ApiKeyValue> Query { get; init; } = Array.Empty<ApiKeyValue>();
    public ApiBody Body { get; init; } = ApiBody.None;
    public ApiAuth Auth { get; init; } = ApiAuth.None;

    public IReadOnlyList<ApiAssertion> Assertions { get; init; } = Array.Empty<ApiAssertion>();
    public IReadOnlyList<ApiCapture> Captures { get; init; } = Array.Empty<ApiCapture>();

    public int TimeoutSeconds { get; init; } = 30;
    public bool FollowRedirects { get; init; } = true;
    /// <summary>Skip this request in a collection run without deleting it.</summary>
    public bool Disabled { get; init; }

    public string DisplayName => string.IsNullOrWhiteSpace(Name) ? $"{Method} {Url}" : Name;
}

/// <summary>A folder of requests. Folders nest; the collection owns a root folder.</summary>
public sealed record ApiFolder
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public IReadOnlyList<ApiRequest> Requests { get; init; } = Array.Empty<ApiRequest>();
    public IReadOnlyList<ApiFolder> Folders { get; init; } = Array.Empty<ApiFolder>();

    /// <summary>Depth-first flatten, parents before children, preserving order.</summary>
    public IEnumerable<ApiRequest> Flatten()
    {
        foreach (var r in Requests) yield return r;
        foreach (var f in Folders)
            foreach (var r in f.Flatten())
                yield return r;
    }

    public int Count() => Requests.Count + Folders.Sum(f => f.Count());
}

public sealed record ApiCollection
{
    public string Name { get; init; } = "Untitled collection";
    public string Description { get; init; } = "";
    public ApiFolder Root { get; init; } = new();
    /// <summary>Collection-level auth, inherited by requests whose own auth is None.</summary>
    public ApiAuth Auth { get; init; } = ApiAuth.None;
    /// <summary>Headers merged into every request unless the request overrides the name.</summary>
    public IReadOnlyList<ApiKeyValue> DefaultHeaders { get; init; } = Array.Empty<ApiKeyValue>();
    /// <summary>Collection variables; an environment of the same name wins.</summary>
    public IReadOnlyDictionary<string, string> Variables { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<ApiRequest> Requests() => Root.Flatten();
    public int RequestCount => Root.Count();
}

/// <summary>
/// A named set of variables (dev / staging / prod). Names listed in
/// <see cref="Secrets"/> are masked by <see cref="ApiReports"/> -- but only when the
/// environment is passed to the renderer, because an <see cref="ApiRunResult"/> does not
/// carry the environment it was produced with. A report rendered without it falls back
/// to the name-shaped heuristic and cannot know about an oddly named secret.
/// </summary>
public sealed record ApiEnvironment
{
    public string Name { get; init; } = "default";
    public IReadOnlyDictionary<string, string> Variables { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// Variable names whose values are credentials. When the environment reaches a
    /// report, both the named variable and any literal occurrence of its value are
    /// replaced by the redaction placeholder. Values shorter than a few characters are
    /// left alone: substituting them everywhere would corrupt unrelated text.
    /// </summary>
    public IReadOnlyCollection<string> Secrets { get; init; } = Array.Empty<string>();

    public bool IsSecret(string name) =>
        Secrets.Any(s => string.Equals(s, name, StringComparison.OrdinalIgnoreCase));
}

// ----------------------------------------------------------------- responses

/// <summary>TLS facts captured during the handshake, for the security analyzer.</summary>
public sealed record TlsInfo
{
    public string Protocol { get; init; } = "";          // e.g. "Tls13"
    public string CipherAlgorithm { get; init; } = "";
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public DateTime NotBeforeUtc { get; init; }
    public DateTime NotAfterUtc { get; init; }
    public string Thumbprint { get; init; } = "";
    public string SignatureAlgorithm { get; init; } = "";
    public int KeySizeBits { get; init; }
    public bool ChainValid { get; init; }
    public IReadOnlyList<string> ChainErrors { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> SubjectAltNames { get; init; } = Array.Empty<string>();

    public int DaysUntilExpiry(DateTime nowUtc) => (int)Math.Floor((NotAfterUtc - nowUtc).TotalDays);
}

/// <summary>
/// Everything observed about one HTTP exchange. <see cref="Error"/> is non-empty
/// when the request never completed; the rest of the record is then unset.
/// </summary>
public sealed record ApiResponse
{
    public int StatusCode { get; init; }
    public string ReasonPhrase { get; init; } = "";
    public IReadOnlyList<ApiKeyValue> Headers { get; init; } = Array.Empty<ApiKeyValue>();
    public string BodyText { get; init; } = "";
    public long BodyBytes { get; init; }
    public bool BodyTruncated { get; init; }
    public TimeSpan Elapsed { get; init; }
    public string FinalUrl { get; init; } = "";
    public IReadOnlyList<string> RedirectChain { get; init; } = Array.Empty<string>();
    public TlsInfo? Tls { get; init; }
    public string Error { get; init; } = "";
    /// <summary>
    /// Non-fatal facts about how the exchange was really performed: headers the HTTP
    /// stack refused to put on the wire, credentials dropped on a cross-origin redirect.
    /// Empty on a clean exchange. This exists so a report cannot claim a header was sent
    /// when it never was.
    /// </summary>
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public DateTime StartedUtc { get; init; }

    public bool Completed => string.IsNullOrEmpty(Error);
    public bool IsSuccess => Completed && StatusCode >= 200 && StatusCode < 300;

    /// <summary>First value of a header, case-insensitively. Null when absent.</summary>
    public string? Header(string name)
    {
        foreach (var h in Headers)
            if (string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase))
                return h.Value;
        return null;
    }

    public IEnumerable<string> HeaderValues(string name) =>
        Headers.Where(h => string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);

    public string ContentType => Header("Content-Type") ?? "";
}

/// <summary>The full record of running one request: what was sent, what came back, what was checked.</summary>
public sealed record ApiExecution
{
    public required ApiRequest Request { get; init; }
    /// <summary>The URL after variable substitution and query merging.</summary>
    public string ResolvedUrl { get; init; } = "";
    public required ApiResponse Response { get; init; }
    public IReadOnlyList<AssertionOutcome> Assertions { get; init; } = Array.Empty<AssertionOutcome>();
    public IReadOnlyDictionary<string, string> Captured { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    public IReadOnlyList<ApiFinding> Findings { get; init; } = Array.Empty<ApiFinding>();

    public bool Passed => Response.Completed && Assertions.All(a => a.Passed);
    public int FailedAssertions => Assertions.Count(a => !a.Passed);
}

/// <summary>Aggregate result of a collection run.</summary>
public sealed record ApiRunResult
{
    public string CollectionName { get; init; } = "";
    public string EnvironmentName { get; init; } = "";
    public DateTime StartedUtc { get; init; }
    public TimeSpan Duration { get; init; }
    public IReadOnlyList<ApiExecution> Executions { get; init; } = Array.Empty<ApiExecution>();

    public int Total => Executions.Count;
    public int Passed => Executions.Count(e => e.Passed);
    public int Failed => Total - Passed;
    public int AssertionsRun => Executions.Sum(e => e.Assertions.Count);
    public int AssertionsFailed => Executions.Sum(e => e.FailedAssertions);
    public bool Success => Failed == 0;
}

// ------------------------------------------------------------------ findings

public enum FindingSeverity { Info, Low, Medium, High, Critical }

/// <summary>
/// A security or hygiene observation about an endpoint. Findings are descriptive:
/// the analyzer reports what a normal response already revealed, it never probes
/// for exploitable behaviour.
/// </summary>
public sealed record ApiFinding
{
    public required string Id { get; init; }             // stable slug, e.g. "missing-hsts"
    public required string Title { get; init; }
    public required FindingSeverity Severity { get; init; }
    public string Detail { get; init; } = "";
    public string Recommendation { get; init; } = "";
    /// <summary>OWASP API Security Top 10 (2023) reference, e.g. "API8:2023".</summary>
    public string Owasp { get; init; } = "";
    /// <summary>The header/snippet that triggered it, already redacted.</summary>
    public string Evidence { get; init; } = "";
    public string Endpoint { get; init; } = "";
}

/// <summary>OWASP API Security Top 10 (2023) reference strings used by findings.</summary>
public static class OwaspApi
{
    public const string BrokenObjectLevelAuth = "API1:2023 Broken Object Level Authorization";
    public const string BrokenAuthentication = "API2:2023 Broken Authentication";
    public const string BrokenObjectPropertyAuth = "API3:2023 Broken Object Property Level Authorization";
    public const string UnrestrictedResourceConsumption = "API4:2023 Unrestricted Resource Consumption";
    public const string BrokenFunctionLevelAuth = "API5:2023 Broken Function Level Authorization";
    public const string SensitiveBusinessFlows = "API6:2023 Unrestricted Access to Sensitive Business Flows";
    public const string Ssrf = "API7:2023 Server Side Request Forgery";
    public const string SecurityMisconfiguration = "API8:2023 Security Misconfiguration";
    public const string ImproperInventory = "API9:2023 Improper Inventory Management";
    public const string UnsafeApiConsumption = "API10:2023 Unsafe Consumption of APIs";
}

// -------------------------------------------------------------------- safety

/// <summary>
/// Guard rails for outbound requests. API Studio is a diagnostic tool for APIs the
/// operator owns, so by default it will not send anything until a host is
/// explicitly allowed, and it refuses state-changing verbs unless asked.
/// </summary>
public sealed record ApiSafetyPolicy
{
    /// <summary>Permissive policy for tests and loopback work.</summary>
    public static readonly ApiSafetyPolicy Loopback = new()
    {
        AllowedHosts = new[] { "localhost", "127.0.0.1", "::1" },
        AllowMutatingMethods = true
    };

    /// <summary>Host names (or <c>*</c>) this policy permits. Empty means nothing is allowed.</summary>
    public IReadOnlyCollection<string> AllowedHosts { get; init; } = Array.Empty<string>();
    /// <summary>Allow POST/PUT/PATCH/DELETE. Off by default: read-only probing is the safe default.</summary>
    public bool AllowMutatingMethods { get; init; }
    /// <summary>Allow plain http:// targets. Off by default outside loopback.</summary>
    public bool AllowInsecureHttp { get; init; }
    /// <summary>Maximum requests per second across a run, to avoid hammering an endpoint.</summary>
    public double MaxRequestsPerSecond { get; init; } = 5.0;
    /// <summary>Hard cap on response bytes read into memory.</summary>
    public long MaxResponseBytes { get; init; } = 8L * 1024 * 1024;

    private static readonly HashSet<string> Mutating =
        new(StringComparer.OrdinalIgnoreCase) { "POST", "PUT", "PATCH", "DELETE" };

    /// <summary>Returns null when the request is permitted, or the refusal reason.</summary>
    public string? Refuse(string method, Uri uri)
    {
        if (Mutating.Contains(method) && !AllowMutatingMethods)
            return $"{method} is blocked: enable allowMutatingMethods to send state-changing requests";

        bool loopback = uri.IsLoopback;
        if (!AllowInsecureHttp && !loopback &&
            !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            return "plain http is blocked: enable allowInsecureHttp or use https";

        if (AllowedHosts.Contains("*")) return null;

        string host = NormalizeHost(uri.Host);
        bool hostOk = AllowedHosts.Any(h => HostMatches(h, host));

        return hostOk ? null : $"host '{uri.Host}' is not in the API allowlist";
    }

    /// <summary>
    /// Matches one allowlist entry against an already-normalised host. Both sides are
    /// normalised because <see cref="Uri.Host"/> keeps the brackets around an IPv6
    /// literal ("[::1]") while a human writes the entry without them, and without this
    /// the shipped "::1" entry could never match. Addresses are compared as parsed
    /// <see cref="IPAddress"/> values so "::1" and "0:0:0:0:0:0:0:1" are one host.
    /// Wildcards stay textual: a suffix match is meaningless for an address literal.
    /// </summary>
    private static bool HostMatches(string? entry, string host)
    {
        string e = NormalizeHost(entry ?? "");
        if (e.Length == 0) return false;

        if (e.StartsWith("*.", StringComparison.Ordinal))
            return host.EndsWith(e[1..], StringComparison.OrdinalIgnoreCase);

        if (string.Equals(e, host, StringComparison.OrdinalIgnoreCase)) return true;

        return IPAddress.TryParse(e, out IPAddress? left) &&
               IPAddress.TryParse(host, out IPAddress? right) &&
               left.Equals(right);
    }

    /// <summary>
    /// Strips what a host string carries but a comparison must ignore: the brackets
    /// around an IPv6 literal, an IPv6 zone index, and the root's trailing dot.
    /// </summary>
    private static string NormalizeHost(string? host)
    {
        string h = (host ?? "").Trim();
        if (h.Length >= 2 && h[0] == '[' && h[^1] == ']') h = h[1..^1];
        int zone = h.IndexOf('%');
        if (zone > 0) h = h[..zone];
        if (h.Length > 1 && h[^1] == '.') h = h[..^1];
        return h;
    }
}
