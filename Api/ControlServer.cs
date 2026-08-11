using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ProcessShield.Core;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// A loopback-only REST control plane, built on System.Net.HttpListener so it adds
// no dependency and no web framework. It exists so ProcessShield can be driven by
// scripts, by a dashboard, and by API Studio itself -- pointing the tool at its
// own agent is the shortest possible end-to-end test of both halves.
//
// The routing table is a PURE STATIC FUNCTION (Route). Nothing in it binds a
// socket, reads a header collection or touches the listener, so the entire
// contract -- status codes, error bodies, the actions gate -- is unit-tested
// without any privilege and without opening a port. Handle adds the bearer-token
// check in front of it and is equally pure.
// ---------------------------------------------------------------------------

/// <summary>
/// Control-plane configuration. Every default is the safe one: off, loopback,
/// read-only.
/// </summary>
public sealed record ControlServerOptions
{
    /// <summary>HttpListener prefix. Must be loopback and must end with a slash.</summary>
    public string Prefix { get; init; } = "http://127.0.0.1:8787/";

    /// <summary>
    /// Bearer token required on every route except <c>/health</c>. Empty means
    /// "generate a random one at start and log it once".
    /// </summary>
    public string Token { get; init; } = "";

    /// <summary>Off by default: an EDR should not open a port because someone forgot to say no.</summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Gate for state-changing routes (suspend, terminate, release...). Separate from
    /// <see cref="Enabled"/> so read-only monitoring can be exposed to a dashboard
    /// without also handing it the ability to kill processes.
    /// </summary>
    public bool AllowActions { get; init; }
}

/// <summary>
/// Everything the control plane needs from the agent, expressed as pre-rendered JSON
/// strings. Keeping serialisation on the agent side means the server owns transport
/// and authorisation only, and the whole routing table can be tested against a fake.
/// </summary>
public interface IControlBackend
{
    string AgentVersion { get; }

    /// <summary>Agent health, uptime, monitor states.</summary>
    string Status();

    /// <summary>All process profiles, or only contained ones.</summary>
    string Profiles(bool onlyContained);

    /// <summary>One profile by pid. Should render a JSON error object, not throw, when absent.</summary>
    string Profile(int pid);

    /// <summary>The discovered network/API surface.</summary>
    string Surface();

    /// <summary>Counters: signals ingested, detections, actions taken, queue depths.</summary>
    string Metrics();

    /// <summary>The most recent <paramref name="limit"/> events, newest first.</summary>
    string Events(int limit);

    /// <summary>Loaded detection rules.</summary>
    string Rules();

    /// <summary>ATT&amp;CK coverage derived from the loaded rules.</summary>
    string AttackCoverage();

    /// <summary>Perform a response action. Returning <c>false</c> is a refusal, not a crash.</summary>
    (bool ok, string message) Action(string verb, int pid);

    /// <summary>Re-verify the tamper-evident audit chain.</summary>
    (bool ok, string message) VerifyAudit();
}

/// <summary>
/// The localhost REST control plane. Start is a no-op unless explicitly enabled and
/// pointed at a loopback prefix; see <see cref="Start"/> for the refusal rules.
/// </summary>
public sealed class ControlServer : IDisposable
{
    internal const string JsonContentType = "application/json; charset=utf-8";

    /// <summary>Default page size for <c>/events</c> when the caller does not ask.</summary>
    internal const int DefaultEventLimit = 100;

    /// <summary>
    /// Hard ceiling for <c>/events</c>. An unbounded limit lets one loopback caller ask
    /// the agent to render its entire ring buffer repeatedly, which is a cheap local DoS.
    /// </summary>
    internal const int MaxEventLimit = 1000;

    private const string ApiPrefix = "/api/v1/";
    private const string BearerScheme = "Bearer ";

    /// <summary>
    /// Response headers stamped on every reply. A tool that grades other people's
    /// headers has no business failing its own checks, and nosniff plus no-store are
    /// genuinely correct here: the bodies are JSON containing process state that must
    /// never be cached by an intermediary or sniffed into an executable content type.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, string> SecurityHeaders =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["X-Content-Type-Options"] = "nosniff",
            ["Cache-Control"] = "no-store",
            ["Pragma"] = "no-cache",
            ["X-Frame-Options"] = "DENY",
            ["Referrer-Policy"] = "no-referrer",
            ["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        };

    private readonly object _gate = new();
    private readonly ControlServerOptions _options;
    private readonly IControlBackend _backend;
    private readonly Logger _log;

    private HttpListener? _listener;
    private Thread? _worker;
    private string _token = "";

    public ControlServer(ControlServerOptions options, IControlBackend backend, Logger log)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _backend = backend ?? throw new ArgumentNullException(nameof(backend));
        _log = log ?? throw new ArgumentNullException(nameof(log));
    }

    /// <summary>True once the listener is bound and accepting.</summary>
    public bool Running => _listener?.IsListening == true;

    /// <summary>
    /// The token clients must present. Empty until <see cref="Start"/> succeeds. In
    /// process only — it is logged once at start so the operator can copy it, and is
    /// never included in any HTTP response.
    /// </summary>
    public string Token => _token;

    /// <summary>
    /// Bind and start serving. Returns false, loudly but without throwing, when:
    /// the control plane is disabled (the default), the prefix is not loopback, or the
    /// bind fails. Callers treat a false as "the agent runs fine, just without a
    /// control plane" — losing remote control must never take the EDR down.
    /// </summary>
    public bool Start()
    {
        lock (_gate)
        {
            if (_listener is not null) return _listener.IsListening;

            if (!_options.Enabled)
            {
                _log.Info("control server disabled; not listening");
                return false;
            }

            if (!IsLoopbackPrefix(_options.Prefix, out string reason))
            {
                _log.Info(
                    $"control server refused to start on '{_options.Prefix}': {reason}. " +
                    "This endpoint exposes process state and, when actions are enabled, the ability to " +
                    "suspend and terminate processes, so it is loopback-only by design. Reach it remotely " +
                    "through an SSH tunnel or a reverse proxy that you authenticate yourself.");
                return false;
            }

            _token = string.IsNullOrEmpty(_options.Token) ? NewToken() : _options.Token;
            if (string.IsNullOrEmpty(_options.Token))
                _log.Info("control server generated a bearer token (shown once): " + _token);

            try
            {
                var listener = new HttpListener();
                listener.Prefixes.Add(_options.Prefix);
                listener.Start();
                _listener = listener;
            }
            catch (Exception ex)
            {
                _log.Error("control server could not bind " + _options.Prefix, ex);
                _listener = null;
                return false;
            }

            _worker = new Thread(AcceptLoop) { IsBackground = true, Name = "ControlServer" };
            _worker.Start();
            _log.Info("control server listening on " + _options.Prefix +
                      (_options.AllowActions ? " (actions ENABLED)" : " (read-only)"));
            return true;
        }
    }

    /// <summary>Stop accepting and release the port. Safe to call when never started.</summary>
    public void Stop()
    {
        Thread? worker;
        lock (_gate)
        {
            var listener = _listener;
            _listener = null;
            worker = _worker;
            _worker = null;
            if (listener is not null)
            {
                try { listener.Stop(); } catch { }
                try { listener.Close(); } catch { }
            }
        }

        // Joined outside the lock: the accept thread can be mid-request and a request
        // handler must never need a lock the stopper is holding.
        if (worker is not null)
        {
            try { worker.Join(TimeSpan.FromSeconds(2)); } catch { }
        }
    }

    public void Dispose() => Stop();

    // ------------------------------------------------------------------- pipeline

    /// <summary>
    /// Full request pipeline: authorise, then route. Split from <see cref="Route"/> so
    /// the token check lives in exactly one place that both the listener and the tests
    /// call, and so the routing table itself never has to know what an HTTP header is.
    /// <c>/health</c> is the only route reachable without a token.
    /// </summary>
    internal static (int status, string contentType, string body) Handle(
        string method, string path, string? query, string? authorizationHeader,
        string expectedToken, IControlBackend backend, bool allowActions)
    {
        if (IsHealthPath(NormalizePath(path)))
            return Route(method, path, query, backend, allowActions);

        if (!IsAuthorized(expectedToken, authorizationHeader))
            return (401, JsonContentType, JsonError("unauthorized"));

        return Route(method, path, query, backend, allowActions);
    }

    /// <summary>
    /// Constant-time bearer-token check. Fails closed on an empty expected token, so a
    /// misconfigured or not-yet-started server can never be authenticated against with
    /// an empty credential. <c>CryptographicOperations.FixedTimeEquals</c> still leaks
    /// the token LENGTH through its early return; that is acceptable for a fixed-length
    /// random token, and is why the generated token is a fixed 64 hex characters.
    /// </summary>
    internal static bool IsAuthorized(string expectedToken, string? authorizationHeader)
    {
        if (string.IsNullOrEmpty(expectedToken)) return false;
        if (string.IsNullOrWhiteSpace(authorizationHeader)) return false;

        string header = authorizationHeader.Trim();
        if (header.Length <= BearerScheme.Length) return false;
        if (!header.StartsWith(BearerScheme, StringComparison.OrdinalIgnoreCase)) return false;

        string presented = header[BearerScheme.Length..].Trim();
        if (presented.Length == 0) return false;

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presented),
            Encoding.UTF8.GetBytes(expectedToken));
    }

    /// <summary>
    /// The complete routing table as a pure function. The caller is responsible for
    /// having authorised the request already (see <see cref="Handle"/>); Route only
    /// enforces the <paramref name="allowActions"/> gate, which is a configuration
    /// decision rather than an identity one.
    ///
    /// Paths are matched case-insensitively after trailing slashes are trimmed, and are
    /// matched exactly — there is no filesystem behind any route, so an odd or
    /// percent-encoded path simply falls through to 404 rather than needing traversal
    /// defences.
    /// </summary>
    internal static (int status, string contentType, string body) Route(
        string method, string path, string? query, IControlBackend backend, bool allowActions)
    {
        if (backend is null) return (500, JsonContentType, JsonError("internal error"));

        string p = NormalizePath(path);
        bool isGet = string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase);
        bool isPost = string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase);

        if (IsHealthPath(p))
            return isGet ? Health(backend) : MethodNotAllowed();

        if (!p.StartsWith(ApiPrefix, StringComparison.Ordinal))
            return NotFound();

        string rest = p[ApiPrefix.Length..];

        switch (rest)
        {
            case "status": return isGet ? Guarded(backend.Status) : MethodNotAllowed();
            case "surface": return isGet ? Guarded(backend.Surface) : MethodNotAllowed();
            case "metrics": return isGet ? Guarded(backend.Metrics) : MethodNotAllowed();
            case "rules": return isGet ? Guarded(backend.Rules) : MethodNotAllowed();
            case "attack": return isGet ? Guarded(backend.AttackCoverage) : MethodNotAllowed();
            case "audit/verify": return isGet ? AuditVerify(backend) : MethodNotAllowed();

            case "profiles":
            {
                if (!isGet) return MethodNotAllowed();
                string? raw = QueryValue(query, "contained");
                bool contained = raw is not null &&
                                 (raw.Equals("true", StringComparison.OrdinalIgnoreCase) || raw == "1");
                return Guarded(() => backend.Profiles(contained));
            }

            case "events":
            {
                if (!isGet) return MethodNotAllowed();
                string? raw = QueryValue(query, "limit");
                int limit = DefaultEventLimit;
                if (raw is not null)
                {
                    if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit <= 0)
                        return BadRequest("limit must be a positive integer");
                    if (limit > MaxEventLimit) limit = MaxEventLimit;
                }
                int effective = limit;
                return Guarded(() => backend.Events(effective));
            }
        }

        if (rest.StartsWith("profiles/", StringComparison.Ordinal))
        {
            if (!isGet) return MethodNotAllowed();
            string[] segments = rest["profiles/".Length..].Split('/');
            // An extra segment is a different (non-existent) route, not a bad pid.
            if (segments.Length != 1) return NotFound();
            if (!TryPid(segments[0], out int pid)) return BadRequest("pid must be a positive integer");
            return Guarded(() => backend.Profile(pid));
        }

        if (rest.StartsWith("actions/", StringComparison.Ordinal))
        {
            if (!isPost) return MethodNotAllowed();

            if (!allowActions)
                return (403, JsonContentType, JsonError(
                    "state-changing actions are disabled; set the control server's allowActions option to true to enable them"));

            string[] parts = rest["actions/".Length..].Split('/');
            if (parts.Length != 2) return NotFound();
            if (!IsValidVerb(parts[0])) return BadRequest("action verb must be 1-32 characters of a-z, 0-9, '-' or '_'");
            if (!TryPid(parts[1], out int pid)) return BadRequest("pid must be a positive integer");

            return Act(backend, parts[0], pid);
        }

        return NotFound();
    }

    /// <summary>
    /// Copy the security headers onto a response through a setter callback, so the same
    /// code path is exercised by the listener and by a test that owns no socket.
    /// </summary>
    internal static void ApplySecurityHeaders(Action<string, string> set)
    {
        if (set is null) return;
        foreach (var kv in SecurityHeaders)
        {
            // A header a particular stack considers restricted must not abort the reply.
            try { set(kv.Key, kv.Value); } catch { }
        }
    }

    /// <summary>
    /// Validate an HttpListener prefix as loopback. Deliberately hand-parsed rather than
    /// handed to <see cref="Uri"/>: the wildcard prefixes HttpListener accepts
    /// (<c>http://+:8787/</c>, <c>http://*:8787/</c>) are not valid URIs, and those are
    /// exactly the ones that must be rejected.
    /// </summary>
    internal static bool IsLoopbackPrefix(string? prefix, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(prefix)) { reason = "prefix is empty"; return false; }

        string s = prefix.Trim();
        int schemeEnd = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0) { reason = "prefix must start with http:// or https://"; return false; }

        string scheme = s[..schemeEnd].ToLowerInvariant();
        if (scheme is not ("http" or "https")) { reason = "only http and https prefixes are supported"; return false; }
        if (!s.EndsWith("/", StringComparison.Ordinal)) { reason = "HttpListener prefixes must end with '/'"; return false; }

        string afterScheme = s[(schemeEnd + 3)..];
        int slash = afterScheme.IndexOf('/');
        if (slash < 0) { reason = "prefix must end with '/'"; return false; }

        string authority = afterScheme[..slash];
        if (authority.Length == 0) { reason = "prefix has no host"; return false; }
        if (authority.Contains('+') || authority.Contains('*'))
        {
            reason = "wildcard prefixes bind every interface, which would expose the control plane off-box";
            return false;
        }
        if (authority.Contains('@')) { reason = "userinfo is not allowed in a listener prefix"; return false; }

        string host;
        string portPart = "";
        if (authority[0] == '[')
        {
            int close = authority.IndexOf(']');
            if (close < 0) { reason = "malformed IPv6 literal in prefix"; return false; }
            host = authority[1..close];
            string tail = authority[(close + 1)..];
            if (tail.Length > 0)
            {
                if (tail[0] != ':') { reason = "malformed port in prefix"; return false; }
                portPart = tail[1..];
            }
        }
        else
        {
            int colon = authority.LastIndexOf(':');
            if (colon >= 0 && authority.IndexOf(':') == colon)
            {
                host = authority[..colon];
                portPart = authority[(colon + 1)..];
            }
            else if (colon >= 0)
            {
                reason = "an IPv6 host must be written in square brackets";
                return false;
            }
            else
            {
                host = authority;
            }
        }

        if (portPart.Length > 0)
        {
            if (!int.TryParse(portPart, NumberStyles.None, CultureInfo.InvariantCulture, out int port) ||
                port is < 1 or > 65535)
            {
                reason = "port must be an integer between 1 and 65535";
                return false;
            }
        }

        if (host.Length == 0) { reason = "prefix has no host"; return false; }

        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip)) return true;

        reason = $"'{host}' is not a loopback address";
        return false;
    }

    /// <summary>
    /// First value of a query parameter, or null when absent. First occurrence wins, so
    /// a duplicated parameter appended by something in the middle cannot override the
    /// one the caller actually wrote.
    /// </summary>
    internal static string? QueryValue(string? query, string name)
    {
        if (string.IsNullOrEmpty(query)) return null;

        string q = query[0] == '?' ? query[1..] : query;
        foreach (string pair in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string key = eq < 0 ? pair : pair[..eq];
            if (!string.Equals(Unescape(key), name, StringComparison.OrdinalIgnoreCase)) continue;
            return eq < 0 ? "" : Unescape(pair[(eq + 1)..]);
        }
        return null;
    }

    // ------------------------------------------------------------------ internals

    private void AcceptLoop()
    {
        while (true)
        {
            var listener = _listener;
            if (listener is null || !listener.IsListening) return;

            HttpListenerContext ctx;
            try
            {
                ctx = listener.GetContext();
            }
            catch (HttpListenerException) { return; }      // listener stopped
            catch (ObjectDisposedException) { return; }
            catch (InvalidOperationException) { return; }

            try { Serve(ctx); }
            catch (Exception ex) { _log.Error("control server request", ex); }
        }
    }

    private void Serve(HttpListenerContext ctx)
    {
        var request = ctx.Request;
        var response = ctx.Response;

        string path = request.Url?.AbsolutePath ?? "/";
        string? query = request.Url?.Query;
        string? auth = request.Headers["Authorization"];

        var (status, contentType, body) =
            Handle(request.HttpMethod ?? "GET", path, query, auth, _token, _backend, _options.AllowActions);

        // No route consumes a request body; drain it so the connection can be reused
        // and a caller cannot hold the accept loop open by dribbling bytes.
        try { request.InputStream.Dispose(); } catch { }

        try
        {
            response.StatusCode = status;
            response.ContentType = contentType;
            ApplySecurityHeaders((k, v) => response.Headers[k] = v);
            if (status == 401)
            {
                try { response.Headers["WWW-Authenticate"] = "Bearer"; } catch { }
            }

            byte[] bytes = Encoding.UTF8.GetBytes(body);
            response.ContentLength64 = bytes.Length;
            response.OutputStream.Write(bytes, 0, bytes.Length);
            response.OutputStream.Flush();
        }
        finally
        {
            try { response.Close(); } catch { }
        }
    }

    private static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

    private static bool IsHealthPath(string normalizedPath) =>
        normalizedPath == "/health" || normalizedPath == "/api/v1/health";

    private static (int, string, string) Health(IControlBackend backend)
    {
        // Unauthenticated on purpose: a liveness probe that needs a secret is not a
        // liveness probe. The version is disclosed here because the endpoint is bound to
        // loopback, and any caller that can reach it can already read the binary on disk,
        // so withholding it would buy nothing.
        string version;
        try { version = backend.AgentVersion ?? ""; }
        catch (Exception) { version = ""; }

        return (200, JsonContentType,
            "{\"status\":\"ok\",\"version\":" + JsonSerializer.Serialize(version) + "}");
    }

    private static (int, string, string) AuditVerify(IControlBackend backend)
    {
        try
        {
            var (ok, message) = backend.VerifyAudit();
            // A failed verification is a successful QUERY with a negative answer, so it
            // is 200. Returning 5xx here would make a tampered log look like an outage
            // to a monitoring system, which is precisely backwards.
            return (200, JsonContentType,
                "{\"ok\":" + (ok ? "true" : "false") +
                ",\"message\":" + JsonSerializer.Serialize(message ?? "") + "}");
        }
        catch (Exception)
        {
            return (500, JsonContentType, JsonError("internal error"));
        }
    }

    private static (int, string, string) Act(IControlBackend backend, string verb, int pid)
    {
        try
        {
            var (ok, message) = backend.Action(verb, pid);
            // Well-formed and authorised but not carried out (unknown pid, already gone,
            // refused by policy) is 409, distinguishing it from a 400 the caller can fix.
            return (ok ? 200 : 409, JsonContentType,
                "{\"ok\":" + (ok ? "true" : "false") +
                ",\"verb\":" + JsonSerializer.Serialize(verb) +
                ",\"pid\":" + pid.ToString(CultureInfo.InvariantCulture) +
                ",\"message\":" + JsonSerializer.Serialize(message ?? "") + "}");
        }
        catch (Exception)
        {
            return (500, JsonContentType, JsonError("internal error"));
        }
    }

    /// <summary>
    /// Run a backend accessor and turn any failure into a generic 500. Exception text
    /// can carry file paths, rule internals and stack frames; none of that goes over
    /// HTTP, even on loopback.
    /// </summary>
    private static (int, string, string) Guarded(Func<string> produce)
    {
        try
        {
            string body = produce();
            // Never emit a zero-length body under a JSON content type: a client that
            // parses on faith should get a valid document.
            return (200, JsonContentType, string.IsNullOrWhiteSpace(body) ? "{}" : body);
        }
        catch (Exception)
        {
            return (500, JsonContentType, JsonError("internal error"));
        }
    }

    private static (int, string, string) NotFound() => (404, JsonContentType, JsonError("no such route"));

    private static (int, string, string) MethodNotAllowed() =>
        (405, JsonContentType, JsonError("method not allowed"));

    private static (int, string, string) BadRequest(string message) =>
        (400, JsonContentType, JsonError(message));

    private static string JsonError(string message) =>
        "{\"error\":" + JsonSerializer.Serialize(message) + "}";

    private static bool TryPid(string text, out int pid)
    {
        // NumberStyles.None rejects signs, whitespace and thousands separators, so
        // "-1", " 1" and "+1" are refused rather than silently coerced.
        pid = 0;
        return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out pid) && pid > 0;
    }

    private static bool IsValidVerb(string verb)
    {
        if (verb.Length is 0 or > 32) return false;
        foreach (char c in verb)
        {
            bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "/";

        string p = path.Trim();
        int q = p.IndexOf('?');
        if (q >= 0) p = p[..q];
        if (p.Length == 0 || p[0] != '/') p = "/" + p;
        while (p.Length > 1 && p[^1] == '/') p = p[..^1];
        return p.ToLowerInvariant();
    }

    private static string Unescape(string value)
    {
        try { return Uri.UnescapeDataString(value); }
        catch (UriFormatException) { return value; }   // malformed %-escape: match literally
    }
}
