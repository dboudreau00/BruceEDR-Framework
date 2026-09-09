using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using BruceEDR.Core;

namespace BruceEDR.Api;

// ---------------------------------------------------------------------------
// The outbound half of API Studio: turn an ApiRequest plus a variable bag into
// an ApiResponse, without ever throwing at the caller and without ever sending
// something the safety policy forbids.
//
// Design notes:
//  * SendAsync is total. Every failure -- bad URL, refused by policy, DNS
//    failure, TLS failure, timeout -- comes back as an ApiResponse with Error
//    set. A runner iterating 200 requests must not be derailed by an exception
//    from request 3, and a UI must not need a try/catch around every send.
//  * The safety policy is consulted before a socket is opened, and again for
//    every redirect hop, because a redirect is an attacker-controlled way to
//    move the request to a host the operator never allowed.
//  * Credentials do not cross an origin boundary. When a redirect moves the
//    request to a different scheme/host/port, the Authorization,
//    Proxy-Authorization, Cookie and api-key headers are left behind and the drop
//    is reported in ApiResponse.Warnings. Replaying them is how a hostile endpoint
//    turns a 302 into a token harvest; curl --location behaves the same way.
//  * Headers the HTTP stack refuses to send are recorded in the same Warnings
//    list rather than vanishing, so a report cannot claim a header was on the wire
//    when it was not.
//  * ApiSafetyPolicy.MaxRequestsPerSecond is enforced here as well as in
//    CollectionRunner, so a direct SendAsync is paced instead of being unlimited.
//    Two limiters in series simply take the slower of the two. The honest limit of
//    this one: the budget is per ApiClient instance and nothing here is static, so a
//    caller that constructs a fresh client per send (ApiStudioConsole.Send does) gets
//    no pacing between those sends. It bounds a burst from one client, not the
//    process. A policy with MaxRequestsPerSecond <= 0 turns it off entirely.
//  * Nothing here mutates global state (no cookie container, no shared handler
//    configuration), so two concurrent sends cannot contaminate each other.
// ---------------------------------------------------------------------------

/// <summary>
/// Sends one API request. Abstracted so collection runs, the security analyzer
/// and every test can be driven from canned responses with no network at all.
/// </summary>
public interface IApiClient : IDisposable
{
    /// <summary>
    /// Sends <paramref name="request"/> after substituting <paramref name="variables"/>.
    /// Implementations must not throw for transport, policy or parsing failures;
    /// those are reported through <see cref="ApiResponse.Error"/>.
    /// </summary>
    Task<ApiResponse> SendAsync(ApiRequest request, IReadOnlyDictionary<string, string> variables,
                                CancellationToken ct = default);
}

/// <summary>
/// The real HTTP client. Enforces <see cref="ApiSafetyPolicy"/>, follows redirects
/// manually so the hop chain is observable, caps the response body, paces its own sends
/// to <see cref="ApiSafetyPolicy.MaxRequestsPerSecond"/>, and records what it can see of
/// the TLS handshake for the security analyzer.
/// <para>
/// An instance is safe to share between concurrent callers, and sharing one is what makes
/// the rate limit useful: the budget lives on the instance, so a caller that builds a new
/// client for every request is not paced between them.
/// </para>
/// </summary>
public sealed class ApiClient : IApiClient
{
    /// <summary>Hard ceiling on manual redirect hops; a redirect loop must terminate.</summary>
    internal const int MaxRedirects = 10;

    /// <summary>
    /// Ceiling on a file-backed request body. Reading an arbitrary path fully into
    /// memory is a self-inflicted denial of service otherwise.
    /// </summary>
    internal const long MaxRequestFileBytes = 32L * 1024 * 1024;

    private static readonly IReadOnlyDictionary<string, string> NoVariables =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    // Headers that HttpClient models on the content rather than the request. Adding
    // them to HttpRequestMessage.Headers silently fails, so they are routed here.
    private static readonly HashSet<string> ContentHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Allow", "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Length",
        "Content-Location", "Content-MD5", "Content-Range", "Content-Type", "Expires", "Last-Modified"
    };

    private readonly ApiSafetyPolicy _policy;
    private readonly IClock _clock;
    private volatile bool _disposed;

    private readonly object _rateGate = new();

    /// <summary>
    /// Monotonic <see cref="Stopwatch"/> timestamp at which the next send may start.
    /// Zero until the first send, which is therefore never delayed. This deliberately
    /// does not use <see cref="IClock"/>: a rate limit must not be steered by a wall
    /// clock that can jump, which also means it cannot be virtualised by a test clock.
    /// </summary>
    private long _nextSendTicks;

    public ApiClient(ApiSafetyPolicy policy, IClock? clock = null)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _clock = clock ?? SystemClock.Instance;
    }

    /// <inheritdoc />
    public async Task<ApiResponse> SendAsync(ApiRequest request, IReadOnlyDictionary<string, string> variables,
                                             CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        DateTime started = _clock.UtcNow;
        var sw = Stopwatch.StartNew();

        if (_disposed)
            return Fail(started, sw, "client has been disposed");

        ApiRequest resolved;
        try
        {
            resolved = Templating.Resolve(request, variables ?? NoVariables);
        }
        catch (Exception ex)
        {
            // A malformed template ({{unclosed, or a cycle the resolver rejects) is a
            // request-authoring bug, not a transport failure -- but it still must not
            // escape as an exception.
            return Fail(started, sw, "variable substitution failed: " + ex.Message);
        }

        if (!TryNormalizeMethod(resolved.Method, out string method, out string methodError))
            return Fail(started, sw, methodError);

        if (!ValidateHeaders(resolved.Headers, out string headerError))
            return Fail(started, sw, headerError);

        if (!TryBuildRequestUri(resolved, out Uri? uri, out string urlError) || uri is null)
            return Fail(started, sw, urlError);

        // Policy first, socket second. Refuse() is the whole point of the safety model,
        // so it runs before anything that could touch the network -- including DNS.
        string? refusal = _policy.Refuse(method, uri);
        if (refusal is not null)
            return Fail(started, sw, "blocked by API safety policy: " + refusal, uri.AbsoluteUri);

        string boundary = "----BruceEDRBoundary" + Guid.NewGuid().ToString("n");
        if (!TryBuildBody(resolved, boundary, _policy, out byte[]? payload, out string bodyContentType, out string bodyError))
            return Fail(started, sw, bodyError, uri.AbsoluteUri);

        // Pace the send. Everything above this line can fail without a packet leaving the
        // machine, so a refused, malformed or unbuildable request neither waits nor burns a
        // slot -- there is nothing to pace. Only the caller's token cancels the wait; the
        // per-request timeout is started afterwards so queueing does not eat into it.
        TimeSpan queued;
        try
        {
            queued = await ThrottleAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Fail(started, sw, "canceled", uri.AbsoluteUri);
        }

        if (queued > TimeSpan.Zero)
        {
            // Waiting for our own rate limit is queueing, not endpoint latency. Folding it
            // into Elapsed would fail a ResponseTimeUnderMs assertion against a server that
            // answered instantly, so the reported clocks start when the wait ends.
            started = _clock.UtcNow;
            sw.Restart();
        }

        int timeoutSeconds = EffectiveTimeoutSeconds(resolved.TimeoutSeconds);
        long maxBytes = _policy.MaxResponseBytes > 0 ? _policy.MaxResponseBytes : 8L * 1024 * 1024;

        var tls = new TlsCapture();
        var chain = new List<string>();

        // Warnings describe the gap between what was configured and what was sent.
        var warnings = new List<string>();
        var droppedHeaders = new List<string>();
        IReadOnlyList<string> credentialHeaders = CrossOriginCredentialHeaders(resolved);
        bool credentialsDropped = false;

        IReadOnlyList<string> CollectWarnings()
        {
            if (droppedHeaders.Count == 0) return warnings.ToArray();
            var all = new List<string>(warnings)
            {
                // "on at least one hop", not "never": a content header attaches to hop 1 but
                // has nothing to attach to after a 303 drops the body, and claiming it never
                // travelled would be the same kind of lie this list exists to prevent.
                "header(s) the HTTP stack refused on at least one hop and did not send: " +
                string.Join(", ", droppedHeaders)
            };
            return all.ToArray();
        }

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);

        // One handler per request. That costs a fresh connection pool (and therefore a
        // fresh TCP+TLS handshake) every time, and a burst of requests can leave sockets
        // in TIME_WAIT -- the classic socket-exhaustion trap. It is the right trade here
        // anyway: the SslOptions callback has to close over per-request state to record
        // the certificate, API Studio is an interactive diagnostic tool sending tens of
        // requests, and the throttle above bounds how fast this client opens fresh
        // connections whenever the policy sets a rate (<= 0 removes that bound).
        // A shared handler would need an AsyncLocal to route certificates back to the
        // right request, and would also share connections (and therefore TLS sessions)
        // across targets, which is exactly what we are trying to observe.
        using var handler = CreateHandler(tls, _policy);
        using var http = new HttpClient(handler, disposeHandler: false)
        {
            // Timing is owned by the linked CTS above so a timeout is reported as a
            // timeout rather than as an indistinguishable TaskCanceledException.
            Timeout = Timeout.InfiniteTimeSpan
        };

        Uri current = uri;
        bool sendBody = true;
        HttpResponseMessage? response = null;

        try
        {
            for (int hop = 0; ; hop++)
            {
                // Credentials are scoped to the origin the operator typed. Replaying them to
                // wherever a Location header points hands the bearer token to whoever controls
                // the endpoint, so they are dropped once the request leaves that origin -- and
                // stay dropped, because the comparison is always against the original URI.
                bool crossOrigin = !SameOrigin(uri, current);
                if (crossOrigin && !credentialsDropped && credentialHeaders.Count > 0)
                {
                    credentialsDropped = true;
                    warnings.Add($"credentials were not replayed across the redirect to " +
                                 $"{current.GetLeftPart(UriPartial.Authority)}: " +
                                 string.Join(", ", credentialHeaders) + " dropped");
                }

                using var message = BuildMessage(method, current, resolved, payload, bodyContentType, boundary,
                                                 sendBody, crossOrigin ? credentialHeaders : null, droppedHeaders);

                response?.Dispose();
                response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, linked.Token)
                                     .ConfigureAwait(false);
                chain.Add(current.AbsoluteUri);

                if (!resolved.FollowRedirects) break;

                int status = (int)response.StatusCode;
                if (!IsRedirect(status)) break;

                Uri? location = response.Headers.Location;
                if (location is null) break;

                Uri next;
                try { next = location.IsAbsoluteUri ? location : new Uri(current, location); }
                catch (UriFormatException) { break; }   // unusable Location: report the 3xx as-is

                if (!IsSupportedScheme(next.Scheme)) break;
                if (hop + 1 >= MaxRedirects) break;     // stop following; the last 3xx is the answer

                (method, sendBody) = RedirectMethod(method, status, sendBody);

                // Re-check every hop. Following a redirect blindly is how a diagnostic
                // client gets turned into an SSRF pivot onto an internal host.
                string? hopRefusal = _policy.Refuse(method, next);
                if (hopRefusal is not null)
                {
                    chain.Add(next.AbsoluteUri);
                    return Fail(started, sw,
                        $"blocked by API safety policy: redirect to '{next}' refused ({hopRefusal})",
                        current.AbsoluteUri, tls.Build(), chain, CollectWarnings());
                }

                current = next;
            }

            var (text, bytes, truncated) = await ReadBodyAsync(response!, maxBytes, linked.Token).ConfigureAwait(false);
            sw.Stop();

            string finalUrl = response!.RequestMessage?.RequestUri?.AbsoluteUri ?? current.AbsoluteUri;
            return new ApiResponse
            {
                StatusCode = (int)response.StatusCode,
                ReasonPhrase = response.ReasonPhrase ?? "",
                Headers = FlattenHeaders(response),
                BodyText = text,
                BodyBytes = bytes,
                BodyTruncated = truncated,
                Elapsed = sw.Elapsed,
                FinalUrl = finalUrl,
                RedirectChain = chain.Count > 1 ? chain.ToArray() : Array.Empty<string>(),
                Tls = tls.Build(),
                Warnings = CollectWarnings(),
                StartedUtc = started
            };
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return Fail(started, sw, $"timed out after {timeoutSeconds}s", current.AbsoluteUri, tls.Build(), chain,
                        CollectWarnings());
        }
        catch (OperationCanceledException)
        {
            // Caller-initiated cancellation. Reported, not thrown, so a partial collection
            // run still has a complete record of what happened to this request.
            return Fail(started, sw, "canceled", current.AbsoluteUri, tls.Build(), chain, CollectWarnings());
        }
        catch (HttpRequestException ex)
        {
            return Fail(started, sw, "request failed: " + Flatten(ex), current.AbsoluteUri, tls.Build(), chain,
                        CollectWarnings());
        }
        catch (Exception ex)
        {
            return Fail(started, sw, "request failed: " + Flatten(ex), current.AbsoluteUri, tls.Build(), chain,
                        CollectWarnings());
        }
        finally
        {
            response?.Dispose();
        }
    }

    public void Dispose() => _disposed = true;

    // -------------------------------------------------------------- throttle

    /// <summary>
    /// Waits for this client's rate-limit slot and returns how long that actually took,
    /// so the caller can keep its own queueing out of the reported exchange timings.
    /// Cancellation surfaces as <see cref="OperationCanceledException"/>; the single
    /// caller converts it into an error response, because SendAsync never throws.
    /// </summary>
    private async Task<TimeSpan> ThrottleAsync(CancellationToken ct)
    {
        TimeSpan wait = ReserveSendSlot();
        if (wait <= TimeSpan.Zero) return TimeSpan.Zero;
        await Task.Delay(wait, ct).ConfigureAwait(false);
        return wait;
    }

    /// <summary>
    /// Claims the next slot allowed by <see cref="ApiSafetyPolicy.MaxRequestsPerSecond"/>
    /// and returns how long the caller must wait for it. The marker is advanced under a
    /// lock as the slot is handed out, so concurrent callers on one client queue behind
    /// each other rather than all observing the same "last send" and leaving together.
    /// <para>
    /// Limitations, stated plainly: the budget is per <see cref="ApiClient"/> instance, so
    /// two clients (or a second process) do not share it; a slot claimed by a caller that
    /// is then cancelled is simply left unused; and the pacing is a minimum gap between
    /// starts, not a sliding window, so it does not smooth a burst that was already in
    /// flight. A non-positive or NaN rate disables the limit entirely.
    /// </para>
    /// </summary>
    private TimeSpan ReserveSendSlot()
    {
        double perSecond = _policy.MaxRequestsPerSecond;
        if (double.IsNaN(perSecond) || perSecond <= 0) return TimeSpan.Zero;

        long interval = (long)(Stopwatch.Frequency / perSecond);
        if (interval <= 0) return TimeSpan.Zero;   // finer than the timer can resolve

        long now = Stopwatch.GetTimestamp();
        long slot;
        lock (_rateGate)
        {
            slot = _nextSendTicks > now ? _nextSendTicks : now;
            _nextSendTicks = slot + interval;
        }

        return slot <= now
            ? TimeSpan.Zero
            : TimeSpan.FromSeconds((double)(slot - now) / Stopwatch.Frequency);
    }

    // ------------------------------------------------------------------ URL

    /// <summary>
    /// Builds the absolute URI: request URL, plus enabled query entries, plus the
    /// api-key query parameter when that auth kind is in use. Query already present
    /// in the URL is preserved verbatim -- re-encoding it would corrupt a URL the
    /// operator deliberately hand-encoded.
    /// </summary>
    internal static bool TryBuildRequestUri(ApiRequest request, out Uri? uri, out string error)
    {
        uri = null;
        error = "";

        string raw = (request.Url ?? "").Trim();
        if (raw.Length == 0) { error = "invalid URL: the request has no URL"; return false; }
        if (HasControlChars(raw)) { error = "invalid URL: control characters are not allowed"; return false; }

        // The fragment is not sent to the server, but appended query has to land in
        // front of it or it becomes part of the fragment instead.
        int hash = raw.IndexOf('#');
        string basePart = hash >= 0 ? raw[..hash] : raw;
        string fragment = hash >= 0 ? raw[hash..] : "";

        var extra = new StringBuilder();
        foreach (var q in request.Query)
        {
            if (!q.Enabled || string.IsNullOrEmpty(q.Name)) continue;
            if (extra.Length > 0) extra.Append('&');
            extra.Append(Uri.EscapeDataString(q.Name)).Append('=').Append(Uri.EscapeDataString(q.Value ?? ""));
        }

        if (request.Auth.Kind == ApiAuthKind.ApiKeyQuery && !string.IsNullOrWhiteSpace(request.Auth.KeyName))
        {
            if (extra.Length > 0) extra.Append('&');
            extra.Append(Uri.EscapeDataString(request.Auth.KeyName)).Append('=')
                 .Append(Uri.EscapeDataString(request.Auth.KeyValue ?? ""));
        }

        if (extra.Length > 0)
        {
            char last = basePart.Length > 0 ? basePart[^1] : '\0';
            string separator = basePart.Contains('?')
                ? (last is '?' or '&' ? "" : "&")
                : "?";
            basePart = basePart + separator + extra;
        }

        string full = basePart + fragment;
        if (!Uri.TryCreate(full, UriKind.Absolute, out Uri? parsed))
        {
            error = $"invalid URL: '{raw}' is not an absolute URI";
            return false;
        }

        if (!IsSupportedScheme(parsed.Scheme))
        {
            error = $"invalid URL: scheme '{parsed.Scheme}' is not supported (only http and https)";
            return false;
        }

        uri = parsed;
        return true;
    }

    internal static bool IsSupportedScheme(string scheme) =>
        string.Equals(scheme, "http", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(scheme, "https", StringComparison.OrdinalIgnoreCase);

    /// <summary>Status codes that carry a Location we are willing to follow.</summary>
    internal static bool IsRedirect(int status) => status is 301 or 302 or 303 or 307 or 308;

    /// <summary>
    /// Same scheme, host and port. Uri.Host renders an IPv6 literal identically on both
    /// sides, so an ordinal comparison is enough here; no normalisation is needed.
    /// </summary>
    internal static bool SameOrigin(Uri a, Uri b) =>
        string.Equals(a.Scheme, b.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase) &&
        a.Port == b.Port;

    /// <summary>
    /// The credential-bearing headers this request would actually put on the wire. Only
    /// these are withheld on a cross-origin redirect, and only these are named in the
    /// warning, so a report never claims a header was dropped that was never there.
    /// An api key carried in the query string is not covered: it lives in the URL the
    /// operator wrote, and a redirect target supplies its own URL.
    /// </summary>
    internal static IReadOnlyList<string> CrossOriginCredentialHeaders(ApiRequest request)
    {
        var names = new List<string>();

        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            string n = name.Trim();
            foreach (string existing in names)
                if (string.Equals(existing, n, StringComparison.OrdinalIgnoreCase)) return;
            names.Add(n);
        }

        foreach (var h in request.Headers)
        {
            if (!h.Enabled || string.IsNullOrWhiteSpace(h.Name)) continue;
            if (IsCredentialHeaderName(h.Name)) Add(h.Name);
        }

        if (request.Auth.AuthorizationHeader() is not null) Add("Authorization");
        if (request.Auth.Kind == ApiAuthKind.ApiKeyHeader) Add(request.Auth.KeyName);

        return names;
    }

    private static bool IsCredentialHeaderName(string name) =>
        string.Equals(name, "Authorization", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(name, "Cookie", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Method and body for the next hop. 303 always downgrades to GET; 301/302 downgrade
    /// a non-idempotent method to GET because that is what every browser and every server
    /// expects in practice, whatever RFC 9110 says. 307/308 preserve both.
    /// </summary>
    internal static (string Method, bool SendBody) RedirectMethod(string method, int status, bool sendBody)
    {
        bool safe = method is "GET" or "HEAD";
        if (status == 303 || ((status is 301 or 302) && !safe))
            return ("GET", false);
        return (method, sendBody);
    }

    /// <summary>Uppercases and validates the verb; an HTTP method is a bare token.</summary>
    internal static bool TryNormalizeMethod(string? method, out string normalized, out string error)
    {
        normalized = string.IsNullOrWhiteSpace(method) ? "GET" : method.Trim().ToUpperInvariant();
        error = "";
        if (normalized.Length is 0 or > 32)
        {
            error = "invalid HTTP method: empty or absurdly long";
            return false;
        }
        foreach (char c in normalized)
        {
            if (c is < 'A' or > 'Z')
            {
                error = $"invalid HTTP method '{normalized}': only letters are accepted";
                return false;
            }
        }
        return true;
    }

    // -------------------------------------------------------------- headers

    /// <summary>
    /// Rejects header names/values that could split the request. TryAddWithoutValidation
    /// is used later (to allow the unusual headers an operator may legitimately need), so
    /// CR/LF has to be caught here or a template could inject a whole second request.
    /// Disabled entries are not validated because they are never sent.
    /// </summary>
    internal static bool ValidateHeaders(IReadOnlyList<ApiKeyValue> headers, out string error)
    {
        error = "";
        foreach (var h in headers)
        {
            if (!h.Enabled) continue;
            string name = h.Name ?? "";
            if (string.IsNullOrWhiteSpace(name))
            {
                error = "invalid header: an enabled header has no name";
                return false;
            }
            foreach (char c in name)
            {
                if (c <= ' ' || c == ':' || c == 127)
                {
                    error = $"invalid header name '{Printable(name)}': separators and control characters are not allowed";
                    return false;
                }
            }
            if (HasControlChars(h.Value ?? ""))
            {
                error = $"invalid header value for '{name}': control characters are not allowed";
                return false;
            }
        }
        return true;
    }

    private static bool HasControlChars(string s)
    {
        foreach (char c in s)
            if (c < 0x20 || c == 0x7F) return true;
        return false;
    }

    private static string Printable(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s) sb.Append(c < 0x20 || c == 0x7F ? '?' : c);
        return sb.ToString();
    }

    private static string? FindHeader(IReadOnlyList<ApiKeyValue> headers, string name)
    {
        foreach (var h in headers)
            if (h.Enabled && string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase))
                return h.Value;
        return null;
    }

    // ----------------------------------------------------------------- body

    /// <summary>
    /// Renders the request body once, up front, as bytes plus a content type. Rendering
    /// once (rather than per hop) keeps a redirect from re-reading a file that changed
    /// underneath us, and gives multipart a stable boundary.
    /// </summary>
    /// <summary>
    /// Resolves a host and keeps only the addresses the policy allows connecting to. A
    /// literal address skips DNS. Never throws: a resolution failure is an empty result,
    /// which the caller reports as a policy refusal.
    /// </summary>
    internal static async Task<IPAddress[]> ResolvePermittedAsync(string host, ApiSafetyPolicy policy, CancellationToken ct)
    {
        IPAddress[] resolved;
        try
        {
            string bare = host.Trim();
            if (bare.Length >= 2 && bare[0] == '[' && bare[^1] == ']') bare = bare[1..^1];
            resolved = IPAddress.TryParse(bare, out var literal)
                ? new[] { literal }
                : await Dns.GetHostAddressesAsync(bare, ct).ConfigureAwait(false);
        }
        catch { return Array.Empty<IPAddress>(); }

        return policy.FilterResolved(resolved, ApiSafetyPolicy.IsLoopbackHostName(host));
    }

    /// <summary>
    /// Confines a file-body path to the policy's root. Returns null when the path is
    /// acceptable, otherwise the reason. Rejects UNC and device paths outright (an
    /// elevated process opening \\host\share authenticates to it as SYSTEM), requires the
    /// resolved path to sit under the root, and refuses any reparse point on the way --
    /// a junction under the root is how the root gets escaped.
    /// </summary>
    internal static string? ValidateBodyFilePath(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            return "file bodies are disabled: set api.studio.fileBodyRoot to the directory request files may be read from";

        string p = path.Trim();
        if (p.StartsWith(@"\\", StringComparison.Ordinal) || p.StartsWith("//", StringComparison.Ordinal))
            return "UNC and device paths are not allowed as request bodies";

        string fullRoot, full;
        try
        {
            fullRoot = Path.GetFullPath(root).TrimEnd('\\', '/') + Path.DirectorySeparatorChar;
            full = Path.GetFullPath(Path.IsPathRooted(p) ? p : Path.Combine(fullRoot, p));
        }
        catch (Exception ex) { return "path could not be resolved: " + ex.Message; }

        if (full.StartsWith(@"\\", StringComparison.Ordinal)) return "UNC and device paths are not allowed as request bodies";
        if (!full.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
            return $"request body file must be under '{fullRoot}'";

        // Walk every component under the root; any reparse point (junction, symlink,
        // mount point) can redirect out of the root after the textual check passed.
        string cursor = fullRoot.TrimEnd(Path.DirectorySeparatorChar);
        string rel = full[fullRoot.Length..];
        foreach (var part in rel.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries))
        {
            cursor = Path.Combine(cursor, part);
            try
            {
                if (!File.Exists(cursor) && !Directory.Exists(cursor)) break;
                if ((File.GetAttributes(cursor) & FileAttributes.ReparsePoint) != 0)
                    return $"'{cursor}' is a reparse point; request body files must be regular files under the root";
            }
            catch (Exception ex) { return "path could not be inspected: " + ex.Message; }
        }
        return null;
    }

    internal static bool TryBuildBody(ApiRequest request, string boundary,
                                      out byte[]? payload, out string contentType, out string error)
        => TryBuildBody(request, boundary, null, out payload, out contentType, out error);

    internal static bool TryBuildBody(ApiRequest request, string boundary, ApiSafetyPolicy? policy,
                                      out byte[]? payload, out string contentType, out string error)
    {
        payload = null;
        contentType = "";
        error = "";

        ApiBody body = request.Body;
        switch (body.Kind)
        {
            case ApiBodyKind.None:
                return true;

            case ApiBodyKind.Raw:
            case ApiBodyKind.Json:
                payload = Encoding.UTF8.GetBytes(body.Text ?? "");
                contentType = body.EffectiveContentType();
                return true;

            case ApiBodyKind.UrlEncoded:
            {
                var sb = new StringBuilder();
                foreach (var f in body.Form)
                {
                    if (!f.Enabled || string.IsNullOrEmpty(f.Name)) continue;
                    if (sb.Length > 0) sb.Append('&');
                    sb.Append(Uri.EscapeDataString(f.Name)).Append('=').Append(Uri.EscapeDataString(f.Value ?? ""));
                }
                payload = Encoding.UTF8.GetBytes(sb.ToString());
                contentType = body.EffectiveContentType();
                return true;
            }

            case ApiBodyKind.Multipart:
            {
                var sb = new StringBuilder();
                foreach (var f in body.Form)
                {
                    if (!f.Enabled || string.IsNullOrEmpty(f.Name)) continue;
                    sb.Append("--").Append(boundary).Append("\r\n");
                    sb.Append("Content-Disposition: form-data; name=\"")
                      .Append(SanitizeMultipartName(f.Name)).Append("\"\r\n\r\n");
                    sb.Append(f.Value ?? "").Append("\r\n");
                }
                sb.Append("--").Append(boundary).Append("--\r\n");
                payload = Encoding.UTF8.GetBytes(sb.ToString());
                contentType = MultipartContentType(body, boundary);
                return true;
            }

            case ApiBodyKind.File:
            {
                string path = body.FilePath ?? "";
                if (string.IsNullOrWhiteSpace(path))
                {
                    error = "request body is a file but no path was given";
                    return false;
                }
                // Policy BEFORE FileInfo: touching a UNC path with Exists() is already a
                // network round-trip carrying this process's credentials.
                string? refusal = ValidateBodyFilePath(path, policy?.FileBodyRoot ?? "");
                if (refusal is not null)
                {
                    error = refusal;
                    return false;
                }
                try
                {
                    var info = new FileInfo(path);
                    if (!info.Exists)
                    {
                        error = $"request body file not found: {path}";
                        return false;
                    }
                    if (info.Length > MaxRequestFileBytes)
                    {
                        error = $"request body file is too large ({info.Length} bytes, limit {MaxRequestFileBytes})";
                        return false;
                    }
                    payload = File.ReadAllBytes(path);
                    contentType = body.EffectiveContentType();
                    return true;
                }
                catch (Exception ex)
                {
                    error = $"cannot read request body file '{path}': {ex.Message}";
                    return false;
                }
            }

            default:
                error = $"unsupported body kind '{body.Kind}'";
                return false;
        }
    }

    /// <summary>
    /// A multipart content type is only valid with its boundary, so an explicit
    /// Content-Type that omits one gets ours appended rather than being sent broken.
    /// </summary>
    internal static string MultipartContentType(ApiBody body, string boundary)
    {
        string declared = body.EffectiveContentType();
        if (declared.Contains("boundary=", StringComparison.OrdinalIgnoreCase)) return declared;
        return declared + "; boundary=" + boundary;
    }

    // A field name is placed inside a quoted string in a header. Quotes, backslashes and
    // control characters would either break the header or splice a new one in.
    private static string SanitizeMultipartName(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            if (c < 0x20 || c == 0x7F) continue;
            if (c is '"' or '\\') { sb.Append('_'); continue; }
            sb.Append(c);
        }
        return sb.ToString();
    }

    // -------------------------------------------------------------- message

    /// <summary>
    /// Builds one hop's message. <paramref name="suppressed"/> names headers that must not
    /// be sent to this destination (cross-origin credentials); <paramref name="dropped"/>
    /// collects the names the HTTP stack itself refused, which would otherwise disappear
    /// without trace and leave a report describing a header that never travelled.
    /// </summary>
    private static HttpRequestMessage BuildMessage(string method, Uri uri, ApiRequest request,
                                                   byte[]? payload, string bodyContentType,
                                                   string boundary, bool sendBody,
                                                   IReadOnlyList<string>? suppressed = null,
                                                   ICollection<string>? dropped = null)
    {
        var message = new HttpRequestMessage(new HttpMethod(method), uri);

        bool IsSuppressed(string? name)
        {
            if (suppressed is null || string.IsNullOrEmpty(name)) return false;
            foreach (string s in suppressed)
                if (string.Equals(s, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        void Drop(string name)
        {
            if (dropped is null) return;
            foreach (string d in dropped)
                if (string.Equals(d, name, StringComparison.OrdinalIgnoreCase)) return;
            dropped.Add(name);
        }

        HttpContent? content = null;
        if (sendBody && payload is not null)
        {
            content = new ByteArrayContent(payload);

            string? explicitType = FindHeader(request.Headers, "Content-Type");
            string effective = !string.IsNullOrWhiteSpace(explicitType) ? explicitType! : bodyContentType;

            if (request.Body.Kind == ApiBodyKind.Multipart &&
                !effective.Contains("boundary=", StringComparison.OrdinalIgnoreCase))
            {
                effective = effective.TrimEnd(';', ' ') + "; boundary=" + boundary;
            }

            if (!string.IsNullOrWhiteSpace(effective))
            {
                if (MediaTypeHeaderValue.TryParse(effective, out var parsed)) content.Headers.ContentType = parsed;
                else content.Headers.TryAddWithoutValidation("Content-Type", effective);
            }
        }

        foreach (var h in request.Headers)
        {
            if (!h.Enabled || string.IsNullOrWhiteSpace(h.Name)) continue;
            if (string.Equals(h.Name, "Content-Type", StringComparison.OrdinalIgnoreCase)) continue; // set above
            if (IsSuppressed(h.Name)) continue;
            if (ContentHeaders.Contains(h.Name))
            {
                // A content header with no body has nothing to attach to, and TryAdd on a
                // null content is a silent no-op unless it is recorded here.
                if (content is null) { Drop(h.Name); continue; }
                if (!content.Headers.TryAddWithoutValidation(h.Name, h.Value)) Drop(h.Name);
                continue;
            }
            if (!message.Headers.TryAddWithoutValidation(h.Name, h.Value)) Drop(h.Name);
        }

        // An explicit Authorization header the operator typed wins over the auth block:
        // the header is the more specific statement of intent.
        string? authorization = request.Auth.AuthorizationHeader();
        if (authorization is not null && FindHeader(request.Headers, "Authorization") is null && !IsSuppressed("Authorization"))
        {
            if (!message.Headers.TryAddWithoutValidation("Authorization", authorization)) Drop("Authorization");
        }

        if (request.Auth.Kind == ApiAuthKind.ApiKeyHeader && !string.IsNullOrWhiteSpace(request.Auth.KeyName) &&
            FindHeader(request.Headers, request.Auth.KeyName) is null && !IsSuppressed(request.Auth.KeyName))
        {
            if (!message.Headers.TryAddWithoutValidation(request.Auth.KeyName, request.Auth.KeyValue))
                Drop(request.Auth.KeyName);
        }

        message.Content = content;
        return message;
    }

    private static SocketsHttpHandler CreateHandler(TlsCapture capture, ApiSafetyPolicy policy)
    {
        var handler = new SocketsHttpHandler
        {
            // DNS pinning. The allowlist is checked by NAME before any socket opens; this
            // callback re-checks the ADDRESSES that name resolves to and connects only to
            // one the policy permits, so a rebinding name cannot route the request into
            // internal space. Resolving and connecting in the same callback is what
            // removes the check-then-connect race.
            ConnectCallback = async (context, ct) =>
            {
                var ep = context.DnsEndPoint;
                IPAddress[] permitted = await ResolvePermittedAsync(ep.Host, policy, ct).ConfigureAwait(false);
                if (permitted.Length == 0)
                    throw new HttpRequestException(
                        $"host '{ep.Host}' resolved only to addresses the API policy refuses " +
                        "(internal, link-local, loopback or metadata space)");

                Exception? last = null;
                foreach (var addr in permitted)
                {
                    var socket = new Socket(addr.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        await socket.ConnectAsync(new IPEndPoint(addr, ep.Port), ct).ConfigureAwait(false);
                        return new NetworkStream(socket, ownsSocket: true);
                    }
                    catch (Exception ex) { last = ex; socket.Dispose(); }
                }
                throw new HttpRequestException($"could not connect to '{ep.Host}'", last);
            },
            // Manual redirects: the automatic ones are invisible, and the whole point of
            // RedirectChain is to show the operator where a request actually went.
            AllowAutoRedirect = false,
            // No cookie jar. A diagnostic client that silently carries state between
            // requests produces results the operator cannot reproduce by hand.
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15)
        };

        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
        {
            // OBSERVATIONAL ONLY. Installing a callback replaces the built-in validation,
            // so this returns exactly what the built-in policy would have: the platform has
            // already run the default chain build and reduced the result to `errors`.
            // Returning `errors == SslPolicyErrors.None` reproduces that verdict bit for
            // bit -- validation is recorded here, never relaxed. Do not "improve" this into
            // anything that returns true on a non-empty error set.
            capture.Record(certificate, chain, errors);
            return errors == SslPolicyErrors.None;
        };

        return handler;
    }

    // ------------------------------------------------------------- response

    private static IReadOnlyList<ApiKeyValue> FlattenHeaders(HttpResponseMessage response)
    {
        var list = new List<ApiKeyValue>();
        foreach (var h in response.Headers)
            foreach (var v in h.Value)
                list.Add(ApiKeyValue.Of(h.Key, v));
        foreach (var h in response.Content.Headers)
            foreach (var v in h.Value)
                list.Add(ApiKeyValue.Of(h.Key, v));
        return list;
    }

    private static async Task<(string Text, long Bytes, bool Truncated)> ReadBodyAsync(
        HttpResponseMessage response, long max, CancellationToken ct)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[64 * 1024];
        bool truncated = false;
        long kept = 0;

        while (true)
        {
            int n = await stream.ReadAsync(chunk.AsMemory(), ct).ConfigureAwait(false);
            if (n <= 0) break;

            long room = max - kept;
            if (room <= 0) { truncated = true; break; }

            int take = (int)Math.Min(n, room);
            buffer.Write(chunk, 0, take);
            kept += take;
            if (take < n) { truncated = true; break; }
        }

        // Byte counts are of the DECODED body: AutomaticDecompression has already run, so
        // this is not the number of bytes that crossed the wire.
        return (PickEncoding(response.Content.Headers.ContentType?.CharSet).GetString(buffer.ToArray()), kept, truncated);
    }

    // InvariantGlobalization is on for this assembly, so only the encodings baked into
    // the runtime resolve. Anything else falls back to UTF-8 rather than failing the read.
    private static Encoding PickEncoding(string? charSet)
    {
        if (string.IsNullOrWhiteSpace(charSet)) return Encoding.UTF8;
        try { return Encoding.GetEncoding(charSet.Trim().Trim('"')); }
        catch { return Encoding.UTF8; }
    }

    private static int EffectiveTimeoutSeconds(int requested)
    {
        if (requested <= 0) return 30;                 // "unset" must not mean "wait forever"
        return Math.Min(requested, 3600);
    }

    private static string Flatten(Exception ex)
    {
        var sb = new StringBuilder(ex.Message);
        var inner = ex.InnerException;
        int depth = 0;
        while (inner is not null && depth++ < 4)
        {
            sb.Append(" -> ").Append(inner.Message);
            inner = inner.InnerException;
        }
        return sb.ToString();
    }

    private static ApiResponse Fail(DateTime started, Stopwatch sw, string error, string url = "",
                                    TlsInfo? tls = null, IReadOnlyList<string>? chain = null,
                                    IReadOnlyList<string>? warnings = null)
    {
        sw.Stop();
        return new ApiResponse
        {
            StatusCode = 0,
            Error = error,
            Elapsed = sw.Elapsed,
            StartedUtc = started,
            FinalUrl = url,
            Tls = tls,
            RedirectChain = chain is { Count: > 1 } ? chain.ToArray() : Array.Empty<string>(),
            Warnings = warnings ?? Array.Empty<string>()
        };
    }

    /// <summary>
    /// Collects what the validation callback can see. Nothing here is authoritative about
    /// the negotiated connection -- see <see cref="Build"/>.
    /// </summary>
    private sealed class TlsCapture
    {
        private readonly object _gate = new();
        private TlsInfo? _info;

        public void Record(X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
        {
            TlsInfo info;
            try
            {
                var errorList = new List<string>();
                if (chain is not null)
                    foreach (var status in chain.ChainStatus)
                        if (status.Status != X509ChainStatusFlags.NoError)
                            errorList.Add($"{status.Status}: {status.StatusInformation.Trim()}");
                if (errors != SslPolicyErrors.None && errorList.Count == 0)
                    errorList.Add(errors.ToString());

                // The callback nearly always hands us an X509Certificate2 already; the
                // re-wrap is only a fallback for a platform that passes the base type.
                var cert = certificate as X509Certificate2 ??
                           (certificate is not null ? new X509Certificate2(certificate.GetRawCertData()) : null);

                info = new TlsInfo
                {
                    // Protocol and CipherAlgorithm are deliberately empty. HttpClient does not
                    // surface the negotiated SslStream to this callback and there is no supported
                    // way to read them from a SocketsHttpHandler exchange, so reporting anything
                    // here would be an invention. An empty string means "not observed", not "none".
                    Protocol = "",
                    CipherAlgorithm = "",
                    Subject = cert?.Subject ?? "",
                    Issuer = cert?.Issuer ?? "",
                    NotBeforeUtc = cert is not null ? cert.NotBefore.ToUniversalTime() : default,
                    NotAfterUtc = cert is not null ? cert.NotAfter.ToUniversalTime() : default,
                    Thumbprint = cert?.Thumbprint ?? "",
                    SignatureAlgorithm = cert?.SignatureAlgorithm?.FriendlyName ?? cert?.SignatureAlgorithm?.Value ?? "",
                    KeySizeBits = KeySize(cert),
                    ChainValid = errors == SslPolicyErrors.None,
                    ChainErrors = errorList,
                    SubjectAltNames = SubjectAltNames(cert)
                };
            }
            catch (Exception ex)
            {
                // Certificate parsing must never break the handshake; record the failure instead.
                info = new TlsInfo { ChainValid = false, ChainErrors = new[] { "certificate inspection failed: " + ex.Message } };
            }

            lock (_gate) _info = info;
        }

        /// <summary>The captured facts, or null when the exchange never reached a handshake (plain http, DNS failure).</summary>
        public TlsInfo? Build()
        {
            lock (_gate) return _info;
        }

        private static int KeySize(X509Certificate2? cert)
        {
            if (cert is null) return 0;
            try
            {
                using var rsa = cert.GetRSAPublicKey();
                if (rsa is not null) return rsa.KeySize;
                using var ecdsa = cert.GetECDsaPublicKey();
                if (ecdsa is not null) return ecdsa.KeySize;
            }
            catch { /* unusable key material: report 0 rather than guessing */ }
            return 0;
        }

        private static IReadOnlyList<string> SubjectAltNames(X509Certificate2? cert)
        {
            if (cert is null) return Array.Empty<string>();
            var names = new List<string>();
            try
            {
                foreach (var extension in cert.Extensions)
                {
                    if (extension.Oid?.Value != "2.5.29.17") continue;
                    var san = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
                    names.AddRange(san.EnumerateDnsNames());
                    foreach (var ip in san.EnumerateIPAddresses()) names.Add(ip.ToString());
                }
            }
            catch
            {
                // A malformed SAN extension is itself interesting, but it is not worth
                // failing the request over; an empty list is honest about what we read.
            }
            return names;
        }
    }
}

/// <summary>
/// An <see cref="IApiClient"/> that never touches a socket: it hands back queued or
/// computed responses and keeps every request it was given. This is what makes the
/// collection runner, the reports and the security analyzer testable offline, and it
/// also lets the UI replay a saved run.
/// </summary>
public sealed class RecordingApiClient : IApiClient
{
    private readonly object _gate = new();
    private readonly Queue<ApiResponse> _queued;
    private readonly Func<ApiRequest, ApiResponse>? _responder;
    private readonly List<RecordedCall> _calls = new();

    /// <summary>Serves <paramref name="responses"/> in order; further sends report an error.</summary>
    public RecordingApiClient(IEnumerable<ApiResponse> responses)
    {
        ArgumentNullException.ThrowIfNull(responses);
        _queued = new Queue<ApiResponse>(responses);
    }

    /// <summary>Computes a response per request. The delegate may throw, which is how a transport fault is simulated.</summary>
    public RecordingApiClient(Func<ApiRequest, ApiResponse> responder)
    {
        _responder = responder ?? throw new ArgumentNullException(nameof(responder));
        _queued = new Queue<ApiResponse>();
    }

    /// <summary>Every send, in order, with the variable bag as it stood at that moment.</summary>
    public IReadOnlyList<RecordedCall> Calls
    {
        get { lock (_gate) return _calls.ToArray(); }
    }

    /// <summary>Convenience view over <see cref="Calls"/>.</summary>
    public IReadOnlyList<ApiRequest> Requests
    {
        get { lock (_gate) return _calls.Select(c => c.Request).ToArray(); }
    }

    public Task<ApiResponse> SendAsync(ApiRequest request, IReadOnlyDictionary<string, string> variables,
                                       CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Snapshot the variables: the runner mutates its own dictionary as captures land,
        // and a recorded call that changes after the fact is useless as evidence.
        var snapshot = new Dictionary<string, string>(
            variables ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);

        lock (_gate) _calls.Add(new RecordedCall { Request = request, Variables = snapshot });

        if (_responder is not null)
            return Task.FromResult(_responder(request));

        lock (_gate)
        {
            if (_queued.Count > 0) return Task.FromResult(_queued.Dequeue());
        }

        return Task.FromResult(new ApiResponse
        {
            Error = "no canned response queued for " + request.DisplayName
        });
    }

    public void Dispose() { }

    /// <summary>One recorded send.</summary>
    public sealed record RecordedCall
    {
        public required ApiRequest Request { get; init; }
        public required IReadOnlyDictionary<string, string> Variables { get; init; }
    }
}
