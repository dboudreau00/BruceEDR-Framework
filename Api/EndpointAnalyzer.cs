using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BruceEDR.Intel;

namespace BruceEDR.Api;

// ---------------------------------------------------------------------------
// Passive security review of one HTTP exchange.
//
// Everything in this file is a pure function of (request, response, now). There
// is no I/O, no clock read and no second request, which is what makes the whole
// analyzer unit-testable without a network and keeps it honest: it can only
// report what the operator's own endpoint already said.
// ---------------------------------------------------------------------------

/// <summary>
/// Reviews a single HTTP response for security misconfiguration and information
/// disclosure.
///
/// This analyzer is PASSIVE. It draws conclusions only from a response the operator
/// already requested against their own endpoint. It must not craft attack payloads,
/// must not brute force, must not enumerate objects, and must not attempt to bypass
/// anything. Every finding is "here is what your own response revealed"; that is what
/// makes it a defensible tool to ship.
///
/// Two consequences of that design are worth stating plainly, because they bound how
/// much a report is worth:
/// <list type="bullet">
/// <item><description>One exchange is one sample. The analyzer can say "this response
/// echoed this origin"; it cannot say "this server reflects any origin". Wording of
/// every inferred finding is deliberately hedged and asks the operator to verify.</description></item>
/// <item><description>Absence of findings is not evidence of security. Authorization
/// logic, business-flow abuse, injection and rate limiting are all invisible to a
/// passive read of one response, and none of them are covered here.</description></item>
/// </list>
/// </summary>
public static class EndpointAnalyzer
{
    // --- thresholds, named so the reasoning is visible at the call site --------

    /// <summary>180 days, the floor most HSTS preload guidance settles on.</summary>
    private const long WeakHstsMaxAgeSeconds = 15_552_000;

    /// <summary>Renewal windows are typically 30 days; inside that, expiry is operationally urgent.</summary>
    private const int CertExpiryWarningDays = 30;

    /// <summary>Below this an RSA key is considered weak. Only applied to RSA — see the check.</summary>
    private const int MinRsaKeyBits = 2048;

    /// <summary>A cookie living longer than 30 days is a long-lived credential, not a session.</summary>
    private const long LongLivedCookieSeconds = 30L * 24 * 60 * 60;

    private const long LargeResponseBytes = 1L << 20;   // 1 MiB
    private const int LargeListElements = 500;

    /// <summary>Bodies above this are not JSON-parsed or secret-scanned; the cost is unbounded otherwise.</summary>
    private const int MaxStructuredScanChars = 4_000_000;

    /// <summary>Evidence is always snipped to this so a report never becomes a second copy of the body.</summary>
    private const int MaxEvidenceChars = 160;

    /// <summary>
    /// Every regex here runs against attacker-influenced text (a response body from a
    /// host the operator may not fully control), so each one carries a match timeout and
    /// each use goes through <see cref="SafeMatch"/>. A pathological body must degrade the
    /// report, never hang or crash the run.
    /// </summary>
    private static readonly TimeSpan RegexBudget = TimeSpan.FromMilliseconds(250);

    private static Regex Rx(string pattern, RegexOptions extra = RegexOptions.None) =>
        new(pattern, extra | RegexOptions.CultureInvariant, RegexBudget);

    // Octet fragment reused by the private-address patterns. The lookarounds (rather
    // than \b) stop "10.0.19041.1" — a Windows build number — from reading as an IP.
    private const string Octet = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";

    private static readonly Regex PrivateAddress = Rx(
        "(?<![0-9.])(?:" +
        "10\\." + Octet + "\\." + Octet + "\\." + Octet + "|" +
        "192\\.168\\." + Octet + "\\." + Octet + "|" +
        "172\\.(?:1[6-9]|2[0-9]|3[01])\\." + Octet + "\\." + Octet + "|" +
        "127\\.0\\.0\\.1|169\\.254\\.169\\.254" +
        ")(?![0-9.])");

    private static readonly Regex InternalHostname = Rx(
        "(?:\\\\\\\\[A-Za-z0-9._-]{2,}\\\\|\\b[A-Za-z0-9][A-Za-z0-9-]{0,62}\\.(?:local|internal|corp|lan|intranet)\\b)",
        RegexOptions.IgnoreCase);

    private static readonly Regex EmailAddress = Rx(
        "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+");

    // Deliberately excludes the ranges the SSA never issues (000/666/9xx area, 00 group,
    // 0000 serial) so that ordinary "123-45-6789"-shaped ids fail more often than they fire.
    private static readonly Regex UsSsn = Rx(
        "(?<![0-9-])(?!000|666|9[0-9][0-9])[0-9]{3}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}(?![0-9-])");

    // Candidate card numbers only; every hit is then Luhn-checked and IIN-checked.
    private static readonly Regex CardCandidate = Rx("(?<![0-9-])[0-9](?:[ -]?[0-9]){12,18}(?![0-9-])");

    private static readonly Regex PhpOnLine = Rx("\\bon line [0-9]+\\b", RegexOptions.IgnoreCase);

    private static readonly Regex Sha1Signature = Rx("sha-?1(?![0-9])", RegexOptions.IgnoreCase);
    private static readonly Regex Md5Signature = Rx("md-?5(?![0-9])", RegexOptions.IgnoreCase);

    // A "Server: nginx" tells an attacker little; "Server: nginx/1.18.0" tells them
    // which CVEs to read. Only the versioned form is reported as a disclosure.
    private static readonly Regex VersionInHeader = Rx("[0-9]+\\.[0-9]+");

    // ------------------------------------------------------------------ entry point

    /// <summary>
    /// Runs every passive check over one exchange and returns the findings in a stable
    /// order (severity descending, then id ascending) so two runs over the same data
    /// produce byte-identical reports.
    /// </summary>
    /// <param name="request">The request as the operator configured it. Used only to know
    /// what authentication was sent and what Origin was offered — never replayed.</param>
    /// <param name="response">The observed response. A response with
    /// <see cref="ApiResponse.Error"/> set yields no findings: nothing was observed.</param>
    /// <param name="nowUtc">Injected time, so certificate-expiry findings are deterministic.</param>
    public static IReadOnlyList<ApiFinding> Analyze(ApiRequest request, ApiResponse response, DateTime nowUtc)
    {
        if (response is null || !response.Completed) return Array.Empty<ApiFinding>();
        request ??= new ApiRequest();

        var findings = new List<ApiFinding>();
        findings.AddRange(AnalyzeHeaders(response));
        findings.AddRange(AnalyzeCors(response, RequestOrigin(request)));
        findings.AddRange(AnalyzeCookies(response));
        findings.AddRange(AnalyzeBody(response));

        var uri = EndpointUri(response, request);
        if (uri is not null) findings.AddRange(AnalyzeTls(response.Tls, uri, nowUtc));

        var unauthenticated = UnauthenticatedDataExposure(request, response);
        if (unauthenticated is not null) findings.Add(unauthenticated);

        string endpoint = DescribeEndpoint(request, response, uri);
        for (int i = 0; i < findings.Count; i++)
            findings[i] = findings[i] with { Endpoint = endpoint };

        return Order(findings);
    }

    // --------------------------------------------------------------------- headers

    /// <summary>
    /// Checks the response headers that a browser (or an intermediary cache) acts on.
    /// Header checks are the least ambiguous part of the review: the header is either
    /// present and well-formed or it is not, so these findings carry no inference.
    /// </summary>
    public static IReadOnlyList<ApiFinding> AnalyzeHeaders(ApiResponse response)
    {
        if (response is null || !response.Completed) return Array.Empty<ApiFinding>();

        var f = new List<ApiFinding>();
        var origin = OriginOf(response);
        string contentType = response.ContentType;
        bool html = IsHtml(contentType);
        string body = response.BodyText ?? "";

        // --- HSTS. Only meaningful over https: a browser ignores the header on a plain
        //     http response, and setting it for localhost would poison every other
        //     service a developer runs there, so neither case is reported.
        if (origin.HstsApplies)
        {
            string? hsts = response.Header("Strict-Transport-Security");
            if (string.IsNullOrWhiteSpace(hsts))
            {
                f.Add(New("missing-hsts", "Strict-Transport-Security is not set", FindingSeverity.Medium,
                    "The response was served over https but carries no HSTS header, so a client that first reaches the host over http can still be downgraded before it ever sees a secure response.",
                    "Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every https response. Add preload only once you are certain every subdomain is https-only.",
                    OwaspApi.SecurityMisconfiguration));
            }
            else
            {
                long? maxAge = HstsMaxAge(hsts);
                if (maxAge is null)
                    f.Add(New("weak-hsts", "Strict-Transport-Security has no usable max-age", FindingSeverity.Low,
                        "The HSTS header is present but no max-age directive could be parsed from it, which means clients will ignore it entirely.",
                        "Emit an explicit max-age in seconds, for example max-age=31536000.",
                        OwaspApi.SecurityMisconfiguration, Snip(hsts)));
                else if (maxAge.Value < WeakHstsMaxAgeSeconds)
                    f.Add(New("weak-hsts", "Strict-Transport-Security max-age is short", FindingSeverity.Low,
                        $"max-age is {maxAge.Value} seconds; below {WeakHstsMaxAgeSeconds} (180 days) the pin lapses often enough that a client returning after a gap is unprotected. A value of 0 actively clears an existing pin.",
                        "Raise max-age to at least 15552000, and to 31536000 if you intend to preload.",
                        OwaspApi.SecurityMisconfiguration, Snip(hsts)));
            }
        }

        // --- MIME sniffing. Cheap, universally applicable, no downside.
        string? nosniff = response.Header("X-Content-Type-Options");
        if (!string.Equals(nosniff?.Trim(), "nosniff", StringComparison.OrdinalIgnoreCase))
            f.Add(New("missing-nosniff", "X-Content-Type-Options: nosniff is not set", FindingSeverity.Low,
                nosniff is null
                    ? "The header is absent, so a browser may content-sniff the body and treat it as a type you did not declare."
                    : $"The header is present but its value is '{Snip(nosniff)}'; only the exact token 'nosniff' has any effect.",
                "Send X-Content-Type-Options: nosniff on every response, including API responses.",
                OwaspApi.SecurityMisconfiguration, nosniff is null ? "" : Snip(nosniff)));

        // --- CSP and framing. Both are document-level controls enforced by a rendering
        //     engine. A pure JSON response is never rendered, so firing them there would
        //     be pure noise; they are checked only when the response is HTML.
        if (html)
        {
            string? csp = response.Header("Content-Security-Policy");
            if (string.IsNullOrWhiteSpace(csp))
                f.Add(New("missing-csp", "Content-Security-Policy is not set on an HTML response", FindingSeverity.Medium,
                    "This response is HTML and will be rendered, but ships no CSP, so any injected markup executes with the page's full privileges. (CSP is not checked for JSON responses: a body that is never rendered gains nothing from it.)",
                    "Add a Content-Security-Policy with an explicit default-src and no unsafe-inline. Start in report-only mode if you need to measure breakage first.",
                    OwaspApi.SecurityMisconfiguration));

            bool frameAncestors = csp is not null &&
                                  csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase);
            string? xfo = response.Header("X-Frame-Options");
            if (!frameAncestors && string.IsNullOrWhiteSpace(xfo))
                f.Add(New("missing-frame-protection", "HTML response can be framed by any site", FindingSeverity.Medium,
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive is present, so a third-party page can embed this document and overlay it (clickjacking).",
                    "Send Content-Security-Policy: frame-ancestors 'none' (or an explicit allowlist), and X-Frame-Options: DENY for older clients.",
                    OwaspApi.SecurityMisconfiguration));
        }

        // --- Referrer-Policy. Reported for any response, but the detail says plainly that
        //     it is a document control; on a pure JSON endpoint this is defence in depth.
        if (string.IsNullOrWhiteSpace(response.Header("Referrer-Policy")))
            f.Add(New("missing-referrer-policy", "Referrer-Policy is not set", FindingSeverity.Low,
                "Without an explicit policy the client falls back to its default, which for many clients still leaks the full URL — including path segments that identify objects — to third-party hosts. This matters most for HTML; for a pure JSON API it is defence in depth.",
                "Send Referrer-Policy: no-referrer (or strict-origin-when-cross-origin if you need referrers for analytics).",
                OwaspApi.SecurityMisconfiguration));

        // --- Product/version disclosure.
        var disclosures = new List<string>();
        foreach (string name in new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime" })
        {
            foreach (string value in response.HeaderValues(name))
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                // X-Powered-By and the X-AspNet* pair exist only to advertise a stack, so
                // their presence is the disclosure. Server is reported only when versioned:
                // "Server: cloudflare" tells an attacker nothing actionable.
                bool alwaysDiscloses = !name.Equals("Server", StringComparison.OrdinalIgnoreCase);
                if (alwaysDiscloses || SafeIsMatch(VersionInHeader, value))
                    disclosures.Add($"{name}: {value.Trim()}");
            }
        }
        if (disclosures.Count > 0)
            f.Add(New("server-version-disclosure", "Response advertises server product and version", FindingSeverity.Low,
                "These headers name the software and, in most cases, its exact version. That does not create a vulnerability on its own, but it turns 'find a bug in this host' into 'look up known bugs for this build'.",
                "Suppress or blank these headers at the edge. On IIS/ASP.NET remove X-Powered-By and X-AspNet-Version; on nginx set server_tokens off; behind a proxy, strip them there.",
                OwaspApi.SecurityMisconfiguration, Snip(string.Join("; ", disclosures))));

        // --- X-XSS-Protection. The filter is gone from modern browsers, and in the ones
        //     that had it the blocking mode was itself exploitable, so any non-zero value
        //     is a defect rather than a hardening measure.
        string? xxp = response.Header("X-XSS-Protection");
        if (!string.IsNullOrWhiteSpace(xxp) && !xxp.TrimStart().StartsWith("0", StringComparison.Ordinal))
            f.Add(New("xss-protection-enabled", "X-XSS-Protection is enabled", FindingSeverity.Low,
                "The legacy XSS auditor is deprecated and removed from current browsers. In the browsers that implemented it, '1; mode=block' introduced its own information-disclosure and false-positive-blocking behaviour, so enabling it is a net negative.",
                "Send X-XSS-Protection: 0 and rely on Content-Security-Policy and output encoding instead.",
                OwaspApi.SecurityMisconfiguration, Snip(xxp)));

        // --- Caching of sensitive responses.
        if (LooksSensitive(response, body))
        {
            string cacheControl = response.Header("Cache-Control") ?? "";
            if (!cacheControl.Contains("no-store", StringComparison.OrdinalIgnoreCase))
                f.Add(New("missing-cache-control-sensitive", "Sensitive-looking response is not marked no-store", FindingSeverity.Medium,
                    "This response sets a cookie or carries credential/PII-shaped content, but its Cache-Control does not include no-store, so a shared proxy or the browser disk cache may retain it. Note that no-cache is not sufficient: it permits storage and only forces revalidation.",
                    "Send Cache-Control: no-store on any response carrying credentials or personal data.",
                    OwaspApi.SecurityMisconfiguration,
                    cacheControl.Length == 0 ? "Cache-Control absent" : Snip("Cache-Control: " + cacheControl)));
        }

        // --- Content-Type hygiene. 204/304 legitimately carry no body and no type.
        bool bodyless = response.StatusCode is 204 or 304 || (body.Length == 0 && response.BodyBytes == 0);
        if (!bodyless && string.IsNullOrWhiteSpace(contentType))
            f.Add(New("missing-content-type", "Response body has no Content-Type", FindingSeverity.Medium,
                "A body was returned with no declared type, which forces every client to guess. Sniffing is exactly the ambiguity that turns an uploaded file or an echoed parameter into script execution.",
                "Always declare an explicit Content-Type with a charset, for example application/json; charset=utf-8.",
                OwaspApi.SecurityMisconfiguration));

        if (html && IsJsonBody(body))
            f.Add(New("json-served-as-html", "JSON body is served as text/html", FindingSeverity.Medium,
                "The body parses as JSON but is labelled text/html, so a browser will render it. Any attacker-controlled string inside that JSON becomes markup in the victim's origin.",
                "Serve JSON as application/json. If a browser must be able to open the URL directly, still keep the JSON type and add X-Content-Type-Options: nosniff.",
                OwaspApi.SecurityMisconfiguration, Snip("Content-Type: " + contentType)));

        return Order(f);
    }

    // ------------------------------------------------------------------------- TLS

    /// <summary>
    /// Reviews the certificate and handshake facts captured during the request. Only what
    /// <see cref="TlsInfo"/> recorded is available — this never opens a second connection
    /// and never tests cipher or protocol negotiation, so a clean result here says nothing
    /// about whether the server would also accept TLS 1.0.
    /// </summary>
    /// <param name="tls">Handshake facts, or null for a plaintext exchange or one where
    /// the client did not capture them. Null yields no findings.</param>
    /// <param name="uri">The endpoint URI, used for hostname coverage and to recognise
    /// loopback, where a self-signed development certificate is expected.</param>
    /// <param name="nowUtc">Injected time, so expiry findings do not depend on the wall clock.</param>
    public static IReadOnlyList<ApiFinding> AnalyzeTls(TlsInfo? tls, Uri uri, DateTime nowUtc)
    {
        if (tls is null) return Array.Empty<ApiFinding>();

        var f = new List<ApiFinding>();
        bool loopback = uri is not null && uri.IsLoopback;
        string host = uri is null ? "" : uri.Host.Trim('[', ']');

        // --- Validity window. Expiry is the one finding that is purely arithmetic.
        if (tls.NotAfterUtc != default && tls.NotAfterUtc <= nowUtc)
        {
            f.Add(New("tls-cert-expired", "Certificate has expired", FindingSeverity.Critical,
                $"The certificate expired on {Iso(tls.NotAfterUtc)}, {Math.Abs(tls.DaysUntilExpiry(nowUtc))} day(s) ago. Conforming clients refuse the connection outright, so this is an availability outage as much as a security one.",
                "Renew and deploy the certificate now, then add expiry monitoring that alerts well before the renewal window closes.",
                OwaspApi.SecurityMisconfiguration, Snip(tls.Subject)));
        }
        else if (tls.NotAfterUtc != default && tls.DaysUntilExpiry(nowUtc) <= CertExpiryWarningDays)
        {
            f.Add(New("tls-cert-expiring", "Certificate expires soon", FindingSeverity.Medium,
                $"The certificate expires on {Iso(tls.NotAfterUtc)}, in {tls.DaysUntilExpiry(nowUtc)} day(s).",
                "Confirm automated renewal is working for this host, or renew manually before the date above.",
                OwaspApi.SecurityMisconfiguration, Snip(tls.Subject)));
        }

        if (tls.NotBeforeUtc != default && tls.NotBeforeUtc > nowUtc)
            f.Add(New("tls-cert-not-yet-valid", "Certificate is not valid yet", FindingSeverity.High,
                $"The certificate's notBefore is {Iso(tls.NotBeforeUtc)}, which is in the future. This is usually a clock skew problem on the server or a certificate deployed ahead of its issue date; either way strict clients reject it.",
                "Check the server clock and the issuance date of the deployed certificate.",
                OwaspApi.SecurityMisconfiguration, Snip(tls.Subject)));

        // --- Chain. Reported as observed, including on loopback, because "the chain did
        //     not validate" is a fact rather than an inference. The self-signed finding
        //     below is the usual explanation and is deliberately scored lower so a single
        //     self-signed certificate is not penalised twice at full weight.
        if (!tls.ChainValid || tls.ChainErrors.Count > 0)
            f.Add(New("tls-chain-invalid", "Certificate chain did not validate", FindingSeverity.High,
                "The client could not build a trusted chain to a root it accepts. A client that continues anyway has no assurance about who it is talking to, which removes the protection TLS was there to provide.",
                "Install the full intermediate chain, and make sure the issuing root is one your clients trust. If the errors are trust-store gaps on this machine, fix the client rather than disabling validation.",
                OwaspApi.SecurityMisconfiguration,
                Snip(tls.ChainErrors.Count > 0 ? string.Join("; ", tls.ChainErrors) : "ChainValid = false")));

        bool selfSigned = !string.IsNullOrWhiteSpace(tls.Subject) &&
                          string.Equals(tls.Subject.Trim(), tls.Issuer?.Trim(), StringComparison.OrdinalIgnoreCase);
        if (selfSigned && !loopback)
            f.Add(New("tls-self-signed", "Certificate is self-signed", FindingSeverity.Medium,
                "Subject and issuer are identical, so no certificate authority vouches for this host. Clients can only accept it by pinning it or by disabling verification, and the latter is how downgrade-to-no-verification habits start. (Self-signed certificates on loopback are normal for development and are not reported.)",
                "Issue a certificate from a CA your clients already trust, or distribute your internal root to those clients and keep verification on.",
                OwaspApi.SecurityMisconfiguration, Snip(tls.Subject)));

        // --- Hostname coverage. Skipped entirely when neither SAN nor CN was captured:
        //     with no names to compare against, claiming a mismatch would be a fabrication.
        if (host.Length > 0)
        {
            var names = new List<string>(tls.SubjectAltNames);
            string? cn = CommonName(tls.Subject);
            if (cn is not null) names.Add(cn);
            names.RemoveAll(string.IsNullOrWhiteSpace);

            if (names.Count > 0 && !names.Any(n => HostMatches(host, n)))
                f.Add(New("tls-hostname-mismatch", "Host is not covered by the certificate", FindingSeverity.High,
                    $"'{host}' matches none of the names on this certificate. Note that a wildcard covers exactly one label, so *.example.com does not cover a.b.example.com.",
                    "Reissue the certificate with the served hostname in a subjectAltName entry. CN-only certificates are ignored by modern clients.",
                    OwaspApi.SecurityMisconfiguration,
                    Snip("names: " + string.Join(", ", names.Take(8)))));
        }

        // --- Key strength. Applied only when the algorithm looks like RSA: a 256-bit
        //     ECDSA key is strong, and a naive "KeySizeBits < 2048" test would slander it.
        bool rsa = (tls.SignatureAlgorithm ?? "").Contains("rsa", StringComparison.OrdinalIgnoreCase);
        if (rsa && tls.KeySizeBits > 0 && tls.KeySizeBits < MinRsaKeyBits)
            f.Add(New("tls-weak-key", "RSA key is smaller than 2048 bits", FindingSeverity.High,
                $"The certificate carries a {tls.KeySizeBits}-bit RSA key. Anything under 2048 bits is below every current baseline and is refused outright by several client stacks.",
                "Reissue with at least a 2048-bit RSA key, or move to ECDSA P-256.",
                OwaspApi.SecurityMisconfiguration, Snip(tls.SignatureAlgorithm)));

        string sigAlg = tls.SignatureAlgorithm ?? "";
        if (SafeIsMatch(Sha1Signature, sigAlg) || SafeIsMatch(Md5Signature, sigAlg))
            f.Add(New("tls-sha1-signature", "Certificate uses a broken signature hash", FindingSeverity.High,
                $"The signature algorithm is '{Snip(sigAlg)}'. Practical collisions exist for both SHA-1 and MD5, so the signature no longer binds the certificate to its contents in a way you can rely on.",
                "Reissue the certificate with a SHA-256 or stronger signature.",
                OwaspApi.SecurityMisconfiguration, Snip(sigAlg)));

        return Order(f);
    }

    // ------------------------------------------------------------------------ CORS

    /// <summary>
    /// Reviews the CORS response headers. CORS is enforced by browsers only: none of these
    /// findings restrict a non-browser client, which can read the endpoint regardless. What
    /// they describe is which other web origins the server has invited to read authenticated
    /// responses on a user's behalf.
    /// </summary>
    public static IReadOnlyList<ApiFinding> AnalyzeCors(ApiResponse response) => AnalyzeCors(response, null);

    /// <param name="requestOrigin">The Origin header the operator's request actually sent,
    /// when known. Supplying it upgrades the reflection check from an inference to an
    /// observation; it is still a single sample and the wording says so.</param>
    internal static IReadOnlyList<ApiFinding> AnalyzeCors(ApiResponse response, string? requestOrigin)
    {
        if (response is null || !response.Completed) return Array.Empty<ApiFinding>();

        string? acao = response.Header("Access-Control-Allow-Origin")?.Trim();
        if (string.IsNullOrEmpty(acao) &&
            string.IsNullOrEmpty(response.Header("Access-Control-Allow-Headers")) &&
            string.IsNullOrEmpty(response.Header("Access-Control-Allow-Methods")))
            return Array.Empty<ApiFinding>();

        var f = new List<ApiFinding>();
        bool credentials = string.Equals(
            response.Header("Access-Control-Allow-Credentials")?.Trim(), "true", StringComparison.OrdinalIgnoreCase);

        if (acao == "*" && credentials)
            f.Add(New("cors-wildcard-with-credentials", "CORS allows any origin together with credentials", FindingSeverity.High,
                "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is 'true'. Browsers reject this exact pair, so in practice the credentialed cross-origin read fails closed rather than succeeding — but the pair only appears when the CORS layer is hand-rolled and does not understand the model, and a small change (echoing the origin instead of '*') turns it into a working cross-origin read of authenticated data.",
                "Decide which it is. For a public, unauthenticated resource keep '*' and drop Allow-Credentials. For a credentialed API, drop the wildcard and validate the Origin against an explicit allowlist.",
                OwaspApi.SecurityMisconfiguration, Snip($"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true")));

        if (string.Equals(acao, "null", StringComparison.OrdinalIgnoreCase))
            f.Add(New("cors-null-origin-allowed", "CORS allows the literal null origin", FindingSeverity.Medium,
                "'null' is the origin a sandboxed iframe, a redirected request and a local file all present. It is not a private value: an attacker can arrange to send it, so allowing it is close to allowing any origin.",
                "Never allowlist 'null'. Name the origins you actually serve.",
                OwaspApi.SecurityMisconfiguration, Snip("Access-Control-Allow-Origin: null")));

        bool concreteOrigin = acao is not null && acao != "*" &&
                              (acao.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                               acao.StartsWith("https://", StringComparison.OrdinalIgnoreCase));

        if (concreteOrigin && !string.IsNullOrWhiteSpace(requestOrigin) &&
            string.Equals(acao, requestOrigin.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            // Observed, not proven: one echo is consistent with reflection and equally
            // consistent with this origin being on a correct allowlist. The recommendation
            // asks the operator to check rather than asserting a vulnerability.
            f.Add(New("cors-reflected-origin", "Response echoed the request's Origin",
                credentials ? FindingSeverity.High : FindingSeverity.Medium,
                credentials
                    ? "Access-Control-Allow-Origin came back exactly equal to the Origin that was sent, and credentials are allowed. If the value is copied from the request rather than matched against an allowlist, any site a victim visits can read this endpoint's authenticated responses. One exchange cannot distinguish reflection from a correct allowlist that happens to contain this origin."
                    : "Access-Control-Allow-Origin came back exactly equal to the Origin that was sent. One exchange cannot distinguish reflection from an allowlist that contains this origin; without Allow-Credentials the impact is limited to what an unauthenticated client could already read.",
                "Verify the server matches Origin against a fixed allowlist and returns nothing when it does not match. A prefix or substring test (endsWith(\"example.com\")) is not an allowlist.",
                OwaspApi.SecurityMisconfiguration, Snip($"Origin: {requestOrigin.Trim()} -> Access-Control-Allow-Origin: {acao}")));
        }
        else if (concreteOrigin && credentials &&
                 !(response.Header("Vary") ?? "").Contains("Origin", StringComparison.OrdinalIgnoreCase))
        {
            f.Add(New("cors-missing-vary-origin", "Per-origin CORS response does not send Vary: Origin", FindingSeverity.Low,
                "The response names one concrete origin and allows credentials, but does not vary by Origin. Either the value is computed per request — in which case a shared cache can hand one origin's Allow-Origin header to another — or it is static, in which case Vary is still the correct signal to caches.",
                "Add Vary: Origin whenever Access-Control-Allow-Origin is computed from the request.",
                OwaspApi.SecurityMisconfiguration, Snip($"Access-Control-Allow-Origin: {acao}")));
        }

        string? acah = response.Header("Access-Control-Allow-Headers");
        if (acah is not null)
        {
            var headers = SplitList(acah);
            if (headers.Contains("*") || headers.Count >= 15)
                f.Add(New("cors-broad-allow-headers", "CORS allows an unusually broad set of request headers", FindingSeverity.Low,
                    headers.Contains("*")
                        ? "Access-Control-Allow-Headers is '*', which waives the preflight's job of constraining what a cross-origin caller may set. Note '*' does not cover Authorization, which must still be named explicitly."
                        : $"Access-Control-Allow-Headers lists {headers.Count} headers. A list that long usually means it was copied rather than derived from what the API reads.",
                    "List only the headers the endpoint actually reads.",
                    OwaspApi.SecurityMisconfiguration, Snip(acah)));
        }

        string? acam = response.Header("Access-Control-Allow-Methods");
        if (acam is not null)
        {
            var methods = SplitList(acam);
            if (methods.Contains("*") || methods.Count >= 6 ||
                methods.Any(m => m.Equals("TRACE", StringComparison.OrdinalIgnoreCase)))
                f.Add(New("cors-broad-allow-methods", "CORS allows an unusually broad set of methods", FindingSeverity.Low,
                    $"Access-Control-Allow-Methods is '{Snip(acam)}'. Advertising verbs the endpoint does not implement widens the cross-origin surface for no benefit, and TRACE in particular should never be reachable.",
                    "Advertise only the methods this endpoint implements.",
                    OwaspApi.SecurityMisconfiguration, Snip(acam)));
        }

        return Order(f);
    }

    // --------------------------------------------------------------------- cookies

    /// <summary>
    /// Reviews every Set-Cookie header. Cookie <em>values</em> are never placed in a
    /// finding: the value of a session cookie is the credential itself, and a report is a
    /// file that gets emailed around. Evidence carries the cookie name and attributes only.
    /// </summary>
    public static IReadOnlyList<ApiFinding> AnalyzeCookies(ApiResponse response)
    {
        if (response is null || !response.Completed) return Array.Empty<ApiFinding>();

        var f = new List<ApiFinding>();
        var origin = OriginOf(response);

        foreach (string raw in response.HeaderValues("Set-Cookie"))
        {
            var cookie = ParseCookie(raw);
            if (cookie is null) continue;

            string evidence = Snip(cookie.Describe());
            bool session = LooksLikeSessionCookie(cookie.Name);
            bool secure = cookie.HasFlag("Secure");

            // Over plain http a cookie cannot be protected at all, so on a loopback dev
            // endpoint the missing Secure flag is expected and is not reported. When the
            // scheme is unknown the finding is still raised: a cookie without Secure is a
            // defect anywhere it is deployed over https, which is everywhere real.
            if (!secure && origin.SecureCookiesExpected)
                f.Add(New("cookie-missing-secure", $"Cookie '{cookie.Name}' is set without Secure", FindingSeverity.Medium,
                    "Without the Secure attribute the browser will also send this cookie over plain http, so a single downgraded or mixed-content request leaks it to anyone on the path.",
                    "Add the Secure attribute to every cookie set over https.",
                    OwaspApi.SecurityMisconfiguration, evidence));

            // Severity turns on the name: a script-readable session cookie is a direct path
            // from any XSS to account takeover, whereas a script-readable UI preference is
            // often deliberate. The name is a guess, so the non-session wording says so.
            if (!cookie.HasFlag("HttpOnly"))
                f.Add(New("cookie-missing-httponly", $"Cookie '{cookie.Name}' is readable by script",
                    session ? FindingSeverity.Medium : FindingSeverity.Low,
                    session
                        ? "This cookie's name suggests it carries a session or token, and it lacks HttpOnly, so any script injected into the origin can read it directly and exfiltrate the session."
                        : "The cookie lacks HttpOnly and is therefore readable by page script. Some cookies are deliberately script-readable (a CSRF token the page must echo, a UI preference), so this is only a defect if this one is not.",
                    "Set HttpOnly on every cookie that page script does not have to read.",
                    OwaspApi.SecurityMisconfiguration, evidence));

            string? sameSite = cookie.Attribute("SameSite");
            if (string.IsNullOrWhiteSpace(sameSite))
                f.Add(New("cookie-missing-samesite", $"Cookie '{cookie.Name}' has no SameSite attribute", FindingSeverity.Low,
                    "No SameSite was declared, so behaviour depends on the client's default. Current browsers default to Lax, but older ones default to None, and relying on a default that changed once is not a control.",
                    "Declare SameSite explicitly: Lax for ordinary session cookies, Strict where no cross-site entry point is needed, None (with Secure) only for genuine cross-site use.",
                    OwaspApi.SecurityMisconfiguration, evidence));
            else if (sameSite.Trim().Equals("None", StringComparison.OrdinalIgnoreCase) && !secure)
                f.Add(New("cookie-samesite-none-insecure", $"Cookie '{cookie.Name}' is SameSite=None without Secure", FindingSeverity.Medium,
                    "SameSite=None requires Secure. Browsers reject the whole cookie in this state, so besides the exposure this is very likely a functional bug you have not noticed yet.",
                    "Add Secure alongside SameSite=None, or drop to SameSite=Lax if the cookie is not needed cross-site.",
                    OwaspApi.SecurityMisconfiguration, evidence));

            string? maxAge = cookie.Attribute("Max-Age");
            if (session && maxAge is not null &&
                long.TryParse(maxAge.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long seconds) &&
                seconds > LongLivedCookieSeconds)
                f.Add(New("cookie-long-lived-session", $"Session-looking cookie '{cookie.Name}' lives for {seconds / 86400} days", FindingSeverity.Low,
                    "A session credential with a multi-month lifetime cannot be revoked by waiting, and a copy stolen once stays useful for as long as the server keeps honouring it.",
                    "Keep session cookies short-lived and refresh them; if you need long-lived sign-in, use a separate rotating refresh token that the server can revoke.",
                    OwaspApi.BrokenAuthentication, evidence));

            string? domain = cookie.Attribute("Domain")?.Trim().TrimStart('.');
            if (!string.IsNullOrEmpty(domain) && origin.Known && origin.Host.Length > 0 &&
                !domain.Equals(origin.Host, StringComparison.OrdinalIgnoreCase) &&
                origin.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
                f.Add(New("cookie-parent-domain-scope", $"Cookie '{cookie.Name}' is scoped to a parent domain", FindingSeverity.Low,
                    $"The cookie is issued by '{origin.Host}' but scoped to '{domain}', so every sibling host under that domain receives it. One compromised or less-trusted subdomain is then enough to collect it. This check has no public-suffix list, so treat it as advisory.",
                    "Drop the Domain attribute so the cookie is host-only, unless sharing it across subdomains is a deliberate requirement.",
                    OwaspApi.SecurityMisconfiguration, evidence));
        }

        return Order(f);
    }

    // ------------------------------------------------------------------------ body

    /// <summary>
    /// Reviews the response body for disclosure. Every check here reports what the body
    /// contained; none of them assert that the disclosure is exploitable, and the PII
    /// checks in particular are about exposure surface rather than about a defect.
    /// </summary>
    public static IReadOnlyList<ApiFinding> AnalyzeBody(ApiResponse response)
    {
        if (response is null || !response.Completed) return Array.Empty<ApiFinding>();
        string body = response.BodyText ?? "";

        var f = new List<ApiFinding>();
        if (body.Length > 0) f.AddRange(ScanSecrets(body));

        // --- Framework error output. One finding per response: the first marker is enough
        //     evidence, and listing every frame would just copy the trace into the report.
        //     These markers are specific enough to be worth the occasional false positive on
        //     a page that legitimately discusses errors.
        bool tracedFound = false;
        foreach (var (marker, label) in StackTraceMarkers)
        {
            int at = body.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (at < 0) continue;
            f.Add(New("body-stack-trace", "Response body contains a stack trace or framework error page", FindingSeverity.Medium,
                $"The body carries {label} output. Traces leak source paths, package versions, SQL fragments and internal class names, which is the map an attacker would otherwise have to guess at.",
                "Return a generic error body with a correlation id and log the detail server-side. Ensure the production configuration disables developer exception pages.",
                OwaspApi.SecurityMisconfiguration, Snip(Window(body, at))));
            tracedFound = true;
            break;
        }
        if (!tracedFound && SafeMatch(PhpOnLine, body) is { Success: true } onLine)
            f.Add(New("body-stack-trace", "Response body contains a stack trace or framework error page", FindingSeverity.Medium,
                "The body contains an 'on line N' fragment, the shape of an interpreted-language warning or fatal error. Those messages normally carry the absolute source path alongside them.",
                "Disable display_errors (or the equivalent) in production and return a generic error body.",
                OwaspApi.SecurityMisconfiguration, Snip(Window(body, onLine.Index))));

        // --- Internal topology. Low severity: it narrows an attacker's search, it does
        //     not by itself grant anything, and documentation legitimately contains RFC1918
        //     examples.
        var ip = SafeMatch(PrivateAddress, body);
        var hostMatch = SafeMatch(InternalHostname, body);
        if (ip is { Success: true } || hostMatch is { Success: true })
        {
            string sample = ip is { Success: true } ? ip.Value : hostMatch!.Value;
            bool metadata = sample == "169.254.169.254";
            f.Add(New("body-internal-address", "Response discloses an internal address or hostname", FindingSeverity.Low,
                metadata
                    ? "The body references 169.254.169.254, the cloud instance metadata address. Seeing it in a response usually means a server-side fetch is being described or echoed, which is worth tracing for SSRF exposure."
                    : $"The body references '{Snip(sample)}', an address or name that only resolves inside your network. That maps internal topology for anyone who reads the response.",
                "Strip internal hosts and addresses from anything a client can see, including error text and debug fields.",
                metadata ? OwaspApi.Ssrf : OwaspApi.SecurityMisconfiguration,
                Snip(sample)));
        }

        // --- PII. A legitimate API returns emails, card numbers and national ids by
        //     design; this finding is informational about EXPOSURE, not a vulnerability.
        //     It exists so the operator can ask "should this caller see this?", which is a
        //     question only they can answer.
        var pii = FindPii(body);
        if (pii.Count > 0)
            f.Add(New("body-pii-exposed", "Response body contains personal data", FindingSeverity.Medium,
                $"Detected {string.Join(", ", pii.Select(p => $"{p.Count} {p.Label}"))}. Returning personal data is not a vulnerability — for many endpoints it is the entire point. This finding is about exposure: confirm that this caller, at this authorization level, is meant to receive these fields, and that the response is not cached or logged in transit.",
                "Return only the fields the caller needs, mask what they do not, and make sure this response is marked no-store and excluded from access logs that capture bodies.",
                OwaspApi.BrokenObjectPropertyAuth,
                Snip(string.Join("; ", pii.SelectMany(p => p.Samples).Take(3)))));

        // --- Volume. Size alone is weak evidence, so a list shape is required unless the
        //     client already had to truncate.
        long bytes = response.BodyBytes > 0 ? response.BodyBytes : body.Length;
        int arrayLength = TopLevelArrayLength(body);
        bool listShaped = arrayLength >= 0 || LooksLikeEmbeddedList(body);
        if (response.BodyTruncated || (bytes >= LargeResponseBytes && listShaped) || arrayLength >= LargeListElements)
            f.Add(New("body-large-response", "List response is unusually large", FindingSeverity.Low,
                $"The response is {bytes} byte(s){(arrayLength >= 0 ? $" and contains {arrayLength} top-level elements" : "")}{(response.BodyTruncated ? ", and the client had to truncate it" : "")}. An unbounded list endpoint is both a denial-of-service lever and a bulk-extraction lever: one request that returns everything is the cheapest way to take everything.",
                "Enforce a server-side maximum page size that the client cannot raise, and return a cursor rather than the full set.",
                OwaspApi.UnrestrictedResourceConsumption));

        // --- Non-JSON 5xx. The interesting part is not the status, it is that the error
        //     path leaves the API's own contract and hands back whatever the stack produced.
        if (response.StatusCode >= 500 && body.Trim().Length > 0 && !IsJsonContentType(response.ContentType) && !IsJsonBody(body))
            f.Add(New("error-page-not-json", "Server error returned a non-JSON body", FindingSeverity.Low,
                $"Status {response.StatusCode} came back as '{Snip(response.ContentType)}' rather than JSON. If this endpoint is a JSON API, its error path is falling through to a default handler, and default handlers are the ones that print diagnostics.",
                "Handle 5xx inside the API's own error contract so failures return the same JSON shape as everything else.",
                OwaspApi.SecurityMisconfiguration, Snip(body.Trim())));

        return Order(f);
    }

    // ------------------------------------------------------------- grading + report

    /// <summary>
    /// Reduces a finding list to a single score. The weights are a blunt instrument: they
    /// encode "one Critical outweighs any number of Lows" and nothing more subtle than
    /// that. A grade is useful for tracking one endpoint over time; comparing grades
    /// between different endpoints mostly compares how much of each response was visible.
    /// </summary>
    public static (char Grade, int Score) Grade(IReadOnlyList<ApiFinding> findings)
    {
        int score = 100;
        if (findings is not null)
            foreach (var finding in findings)
                score -= Penalty(finding.Severity);

        if (score < 0) score = 0;
        char grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
        return (grade, score);
    }

    private static int Penalty(FindingSeverity severity) => severity switch
    {
        FindingSeverity.Critical => 40,
        FindingSeverity.High => 20,
        FindingSeverity.Medium => 8,
        FindingSeverity.Low => 3,
        _ => 0
    };

    /// <summary>
    /// Renders a plain-text report. Line endings are hard-coded to "\n" and the findings
    /// are re-sorted here rather than trusted, so the same input always produces the same
    /// bytes — that is what lets a report be diffed between runs or committed to a repo.
    /// </summary>
    public static string Explain(IReadOnlyList<ApiFinding> findings)
    {
        var ordered = Order(findings is null ? new List<ApiFinding>() : findings.ToList());
        var (grade, score) = Grade(ordered);

        var sb = new StringBuilder();
        sb.Append("API security review: grade ").Append(grade)
          .Append(" (").Append(score.ToString(CultureInfo.InvariantCulture)).Append("/100)\n");

        if (ordered.Count == 0)
        {
            sb.Append("No findings. Note that a passive review of one response cannot see authorization logic,\n")
              .Append("injection, rate limiting or business-flow abuse, so this is not a clean bill of health.\n");
            return sb.ToString();
        }

        sb.Append(ordered.Count.ToString(CultureInfo.InvariantCulture)).Append(" finding(s): ");
        sb.Append(string.Join(", ", new[]
        {
            FindingSeverity.Critical, FindingSeverity.High, FindingSeverity.Medium,
            FindingSeverity.Low, FindingSeverity.Info
        }.Select(s => $"{ordered.Count(x => x.Severity == s)} {s.ToString().ToLowerInvariant()}")));
        sb.Append('\n');

        foreach (var finding in ordered)
        {
            sb.Append('\n').Append('[').Append(finding.Severity.ToString()).Append("] ")
              .Append(finding.Id).Append(" - ").Append(finding.Title).Append('\n');
            if (finding.Endpoint.Length > 0) sb.Append("  endpoint: ").Append(finding.Endpoint).Append('\n');
            if (finding.Owasp.Length > 0) sb.Append("  owasp:    ").Append(finding.Owasp).Append('\n');
            if (finding.Detail.Length > 0) sb.Append("  detail:   ").Append(finding.Detail).Append('\n');
            if (finding.Evidence.Length > 0) sb.Append("  evidence: ").Append(finding.Evidence).Append('\n');
            if (finding.Recommendation.Length > 0) sb.Append("  fix:      ").Append(finding.Recommendation).Append('\n');
        }

        return sb.ToString();
    }

    // ---------------------------------------------------------------- auth exposure

    /// <summary>
    /// Flags a 200 that carried no authentication and came back looking like user data.
    /// This is deliberately Low and deliberately worded as a question: plenty of endpoints
    /// are public on purpose, and the analyzer has no way to know this one is not.
    /// </summary>
    private static ApiFinding? UnauthenticatedDataExposure(ApiRequest request, ApiResponse response)
    {
        if (response.StatusCode != 200) return null;
        if (CarriesAuthentication(request)) return null;

        string body = response.BodyText ?? "";
        if (body.Trim().Length == 0) return null;

        int hits = UserDataKeys.Count(k => body.Contains(k, StringComparison.OrdinalIgnoreCase));
        bool pii = SafeMatch(EmailAddress, body) is { Success: true } || SafeMatch(UsSsn, body) is { Success: true };
        if (hits < 2 && !pii) return null;

        return New("unauthenticated-user-data", "Unauthenticated request returned user-shaped data", FindingSeverity.Low,
            "The request carried no Authorization header, cookie, API key or configured auth, and the endpoint answered 200 with a body containing user-shaped fields. Verify this endpoint is intended to be public. This is not an assertion that authorization is broken: many endpoints return exactly this and are meant to.",
            "If the data is not meant to be public, require authentication and re-check that the object being returned belongs to the caller. If it is meant to be public, record that decision so the next review does not re-raise it.",
            OwaspApi.BrokenFunctionLevelAuth);
    }

    private static readonly string[] UserDataKeys =
    {
        "\"email\"", "\"username\"", "\"user_id\"", "\"userId\"", "\"first_name\"", "\"firstName\"",
        "\"last_name\"", "\"lastName\"", "\"phone\"", "\"ssn\"", "\"address\"", "\"role\"",
        "\"password\"", "\"is_admin\"", "\"isAdmin\"", "\"date_of_birth\"", "\"dob\""
    };

    /// <summary>
    /// True when the request carried anything that could be an authenticator. The test is
    /// deliberately generous: over-detecting auth suppresses the "unauthenticated" finding,
    /// which is the safe direction to be wrong in — a missed finding beats accusing an
    /// operator of exposing an endpoint that was in fact authenticated.
    /// </summary>
    private static bool CarriesAuthentication(ApiRequest request)
    {
        bool material = request.Auth.Kind switch
        {
            ApiAuthKind.Basic => !string.IsNullOrEmpty(request.Auth.Username) || !string.IsNullOrEmpty(request.Auth.Password),
            ApiAuthKind.Bearer => !string.IsNullOrWhiteSpace(request.Auth.Token),
            ApiAuthKind.ApiKeyHeader or ApiAuthKind.ApiKeyQuery => !string.IsNullOrWhiteSpace(request.Auth.KeyValue),
            ApiAuthKind.RawHeader => !string.IsNullOrWhiteSpace(request.Auth.RawValue),
            _ => false
        };
        if (material) return true;

        foreach (var h in request.Headers)
        {
            if (!h.Enabled || string.IsNullOrWhiteSpace(h.Value)) continue;
            if (LooksLikeAuthName(h.Name) || h.Name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)) return true;
        }

        foreach (var q in request.Query)
            if (q.Enabled && !string.IsNullOrWhiteSpace(q.Value) && LooksLikeAuthName(q.Name)) return true;

        // Query parameters may also be baked into the URL text rather than the Query list.
        int mark = request.Url.IndexOf('?');
        if (mark >= 0)
            foreach (string pair in request.Url[(mark + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=');
                if (eq <= 0 || eq == pair.Length - 1) continue;
                if (LooksLikeAuthName(Uri.UnescapeDataString(pair[..eq]))) return true;
            }

        return false;
    }

    private static bool LooksLikeAuthName(string name) =>
        name.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("token", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("api-key", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("apikey", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("api_key", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("access-key", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("session", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("sig", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("signature", StringComparison.OrdinalIgnoreCase);

    private static string? RequestOrigin(ApiRequest request)
    {
        foreach (var h in request.Headers)
            if (h.Enabled && h.Name.Equals("Origin", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(h.Value))
                return h.Value;
        return null;
    }

    // --------------------------------------------------------------- secret scanning

    /// <summary>
    /// Delegates to the shared secret scanner and converts each distinct rule hit into one
    /// finding. Only the scanner's redacted rendering is ever copied into evidence: a
    /// report that quoted the live key would be a second copy of the leak.
    /// </summary>
    private static IReadOnlyList<ApiFinding> ScanSecrets(string body)
    {
        if (body.Length > MaxStructuredScanChars) return Array.Empty<ApiFinding>();

        IReadOnlyList<SecretMatch> matches;
        try
        {
            matches = SecretScanner.Scan(body);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // The scanner is a separate subsystem carrying operator-editable rules. A faulty
            // rule must not take down the whole report, but it must not fail silently either,
            // so the failure is surfaced as a finding. Only the exception type is reported:
            // an exception message could quote the body it choked on.
            return new[]
            {
                New("body-secret-scan-error", "Secret scan did not complete", FindingSeverity.Info,
                    $"The secret scanner threw {ex.GetType().Name} while reading this body, so the body was not checked for credentials. The rest of the review is unaffected.",
                    "Re-run with the failing rule disabled to identify it, then fix or remove that rule.")
            };
        }

        var findings = new List<ApiFinding>();
        foreach (var group in matches.GroupBy(m => m.RuleId, StringComparer.OrdinalIgnoreCase)
                                     .OrderBy(g => g.Key, StringComparer.Ordinal))
        {
            var first = group.First();
            findings.Add(New(
                "body-secret-" + Slug(group.Key),
                $"Response body exposes a credential ({first.Description})",
                FindingSeverity.High,
                $"The scanner matched rule '{group.Key}' {group.Count()} time(s) in the response body (scanner confidence: {first.Confidence}). A credential returned to a client should be assumed compromised from the moment it was served, because every proxy, cache and log between here and the caller has now seen it.",
                "Rotate the credential first, then remove it from the response. Serving a secret to a client is not fixed by removing it later.",
                OwaspApi.SecurityMisconfiguration,
                Snip(first.Redacted)));
        }
        return findings;
    }

    // -------------------------------------------------------------------------- PII

    private readonly record struct PiiHit(string Label, int Count, IReadOnlyList<string> Samples);

    private static List<PiiHit> FindPii(string body)
    {
        var hits = new List<PiiHit>();
        if (body.Length == 0) return hits;

        var emails = SafeMatches(EmailAddress, body, 50);
        if (emails.Count > 0)
            hits.Add(new PiiHit("email address(es)", emails.Count,
                emails.Take(3).Select(m => MaskEmail(m.Value)).ToList()));

        var ssns = SafeMatches(UsSsn, body, 50);
        if (ssns.Count > 0)
            hits.Add(new PiiHit("US SSN-shaped value(s)", ssns.Count,
                ssns.Take(3).Select(m => "***-**-" + m.Value[^4..]).ToList()));

        var cards = new List<string>();
        foreach (var m in SafeMatches(CardCandidate, body, 100))
        {
            string digits = new(m.Value.Where(char.IsAsciiDigit).ToArray());
            if (!IsPlausibleCard(digits)) continue;
            cards.Add(new string('*', Math.Max(0, digits.Length - 4)) + digits[^4..]);
        }
        if (cards.Count > 0) hits.Add(new PiiHit("payment-card-shaped value(s)", cards.Count, cards.Take(3).ToList()));

        return hits;
    }

    /// <summary>
    /// Luhn plus an issuer-prefix and length sanity check. Luhn alone passes roughly one in
    /// ten random digit runs, which would make every long numeric id look like a card, so
    /// the prefix test is what keeps this usable.
    /// </summary>
    private static bool IsPlausibleCard(string digits)
    {
        if (digits.Length is < 13 or > 19) return false;
        if (!PassesLuhn(digits)) return false;

        if (digits[0] == '4') return digits.Length is 13 or 16 or 19;                       // Visa
        int two = int.Parse(digits[..2], CultureInfo.InvariantCulture);
        if (two is >= 51 and <= 55) return digits.Length == 16;                              // MasterCard
        if (two is 34 or 37) return digits.Length == 15;                                     // Amex
        if (two is 30 or 36 or 38) return digits.Length is 14 or 16;                         // Diners
        if (two == 35) return digits.Length == 16;                                           // JCB
        if (two == 65 || digits.StartsWith("6011", StringComparison.Ordinal)) return digits.Length == 16; // Discover
        int four = int.Parse(digits[..4], CultureInfo.InvariantCulture);
        if (four is >= 2221 and <= 2720) return digits.Length == 16;                         // MasterCard 2-series
        return false;
    }

    private static bool PassesLuhn(string digits)
    {
        int sum = 0;
        bool doubling = false;
        for (int i = digits.Length - 1; i >= 0; i--)
        {
            int d = digits[i] - '0';
            if (doubling)
            {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubling = !doubling;
        }
        return sum % 10 == 0;
    }

    private static string MaskEmail(string email)
    {
        int at = email.IndexOf('@');
        if (at <= 0) return "***";
        return email[0] + "***" + email[at..];
    }

    // ---------------------------------------------------------------- body shape

    private static readonly (string Marker, string Label)[] StackTraceMarkers =
    {
        ("at System.", ".NET stack trace"),
        ("at java.", "Java stack trace"),
        ("java.lang.", "Java exception"),
        ("Traceback (most recent call last)", "Python traceback"),
        ("ORA-0", "Oracle database error"),
        ("SQLSTATE", "SQL error"),
        ("Server Error in '", "ASP.NET error page"),
        ("Microsoft.AspNetCore.Diagnostics", "ASP.NET Core developer exception page")
    };

    private static bool LooksLikeEmbeddedList(string body)
    {
        foreach (string key in new[] { "\"items\":", "\"data\":", "\"results\":", "\"records\":", "\"rows\":" })
        {
            int at = body.IndexOf(key, StringComparison.OrdinalIgnoreCase);
            if (at < 0) continue;
            for (int i = at + key.Length; i < body.Length && i < at + key.Length + 8; i++)
            {
                if (char.IsWhiteSpace(body[i])) continue;
                if (body[i] == '[') return true;
                break;
            }
        }
        return false;
    }

    /// <summary>Element count of a top-level JSON array, or -1 when the body is not one.</summary>
    private static int TopLevelArrayLength(string body)
    {
        if (body.Length == 0 || body.Length > MaxStructuredScanChars) return -1;
        var trimmed = body.AsSpan().TrimStart();
        if (trimmed.Length == 0 || trimmed[0] != '[') return -1;
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.GetArrayLength() : -1;
        }
        catch (JsonException) { return -1; }
    }

    private static bool IsJsonBody(string body)
    {
        if (body.Length == 0 || body.Length > MaxStructuredScanChars) return false;
        var trimmed = body.AsSpan().Trim();
        if (trimmed.Length == 0 || (trimmed[0] != '{' && trimmed[0] != '[')) return false;
        try
        {
            using var _ = JsonDocument.Parse(body);
            return true;
        }
        catch (JsonException) { return false; }
    }

    private static bool IsJsonContentType(string contentType) =>
        contentType.Contains("json", StringComparison.OrdinalIgnoreCase);

    private static bool IsHtml(string contentType) =>
        contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("application/xhtml", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when the response looks like it carries credentials or personal data, used only
    /// to decide whether the missing-no-store finding applies. Erring towards "sensitive"
    /// costs one Low-value finding; erring the other way silently drops a real one.
    /// </summary>
    private static bool LooksSensitive(ApiResponse response, string body)
    {
        if (response.HeaderValues("Set-Cookie").Any(v => !string.IsNullOrWhiteSpace(v))) return true;
        if (body.Length == 0) return false;

        foreach (string key in SensitiveBodyKeys)
            if (body.Contains(key, StringComparison.OrdinalIgnoreCase)) return true;

        return SafeMatch(EmailAddress, body) is { Success: true };
    }

    private static readonly string[] SensitiveBodyKeys =
    {
        "\"password\"", "\"token\"", "access_token", "refresh_token", "id_token",
        "\"secret\"", "\"ssn\"", "api_key", "apiKey", "\"authorization\"",
        "credit_card", "card_number", "\"private_key\""
    };

    // ------------------------------------------------------------------- cookie model

    private sealed record ParsedCookie(string Name, IReadOnlyList<KeyValuePair<string, string>> Attributes)
    {
        public bool HasFlag(string name) =>
            Attributes.Any(a => a.Key.Equals(name, StringComparison.OrdinalIgnoreCase));

        public string? Attribute(string name)
        {
            foreach (var a in Attributes)
                if (a.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return a.Value;
            return null;
        }

        /// <summary>Name and attributes only. The cookie value is deliberately never rendered.</summary>
        public string Describe()
        {
            var sb = new StringBuilder(Name).Append("=<redacted>");
            foreach (var a in Attributes)
                sb.Append("; ").Append(a.Key).Append(a.Value.Length > 0 ? "=" + a.Value : "");
            return sb.ToString();
        }
    }

    private static ParsedCookie? ParseCookie(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var parts = raw.Split(';');
        string first = parts[0].Trim();
        if (first.Length == 0) return null;

        int eq = first.IndexOf('=');
        string name = eq >= 0 ? first[..eq].Trim() : first;
        if (name.Length == 0) return null;

        var attributes = new List<KeyValuePair<string, string>>();
        for (int i = 1; i < parts.Length; i++)
        {
            string part = parts[i].Trim();
            if (part.Length == 0) continue;
            int at = part.IndexOf('=');
            attributes.Add(at >= 0
                ? new KeyValuePair<string, string>(part[..at].Trim(), part[(at + 1)..].Trim())
                : new KeyValuePair<string, string>(part, ""));
        }
        return new ParsedCookie(name, attributes);
    }

    private static readonly string[] SessionCookieMarkers =
    {
        "sess", "sid", "auth", "token", "jwt", "login", "remember", "identity"
    };

    private static bool LooksLikeSessionCookie(string name) =>
        SessionCookieMarkers.Any(m => name.Contains(m, StringComparison.OrdinalIgnoreCase));

    // ------------------------------------------------------------------ origin model

    /// <summary>
    /// What the analyzer knows about where the response came from. <c>Known</c> is false when
    /// no absolute final URL was recorded, and the scheme-dependent checks then fall back to
    /// the conservative assumption that this will be deployed over https.
    /// </summary>
    private readonly record struct ResponseOrigin(string Scheme, string Host, bool Loopback, bool Known)
    {
        public bool Https => Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

        /// <summary>HSTS is ignored over http and would be harmful on loopback.</summary>
        public bool HstsApplies => !Loopback && (Https || !Known);

        /// <summary>A cookie can only be protected by Secure where https is in play.</summary>
        public bool SecureCookiesExpected => !Loopback && (Https || !Known);
    }

    private static ResponseOrigin OriginOf(ApiResponse response)
    {
        var uri = TryUri(response.FinalUrl);
        return uri is null
            ? new ResponseOrigin("", "", false, false)
            : new ResponseOrigin(uri.Scheme.ToLowerInvariant(), uri.Host.Trim('[', ']'), uri.IsLoopback, true);
    }

    private static Uri? TryUri(string? value) =>
        !string.IsNullOrWhiteSpace(value) && Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null;

    private static Uri? EndpointUri(ApiResponse response, ApiRequest request) =>
        TryUri(response.FinalUrl) ?? TryUri(request.Url);

    private static string DescribeEndpoint(ApiRequest request, ApiResponse response, Uri? uri)
    {
        string url = uri?.ToString() ?? (response.FinalUrl.Length > 0 ? response.FinalUrl : request.Url);
        string method = string.IsNullOrWhiteSpace(request.Method) ? "" : request.Method.Trim().ToUpperInvariant();
        if (url.Length == 0) return method;
        return method.Length == 0 ? url : method + " " + url;
    }

    // ----------------------------------------------------------------- TLS helpers

    /// <summary>
    /// Pulls CN out of a distinguished name. This is a comma split, not an RFC 4514 parser:
    /// a CN containing an escaped comma parses wrong. That only matters when SANs are absent,
    /// which for any certificate issued this decade they are not.
    /// </summary>
    private static string? CommonName(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject)) return null;
        foreach (string part in subject.Split(','))
        {
            string p = part.Trim();
            if (p.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                string value = p[3..].Trim().Trim('"');
                return value.Length == 0 ? null : value;
            }
        }
        return null;
    }

    private static bool HostMatches(string host, string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(host)) return false;

        // SAN entries are sometimes captured with the X.509 type prefix still attached
        // ("DNS Name=example.com" from Windows, "DNS:example.com" from OpenSSL).
        int eq = pattern.IndexOf('=');
        if (eq >= 0 && eq + 1 < pattern.Length) pattern = pattern[(eq + 1)..];
        else if (pattern.StartsWith("DNS:", StringComparison.OrdinalIgnoreCase)) pattern = pattern[4..];
        else if (pattern.StartsWith("IP:", StringComparison.OrdinalIgnoreCase)) pattern = pattern[3..];

        pattern = pattern.Trim().TrimEnd('.');
        host = host.Trim().TrimEnd('.');

        if (pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            // A wildcard covers exactly one label: *.example.com does not cover a.b.example.com.
            string suffix = pattern[1..];
            int dot = host.IndexOf('.');
            return dot > 0 && string.Equals(host[dot..], suffix, StringComparison.OrdinalIgnoreCase);
        }
        return string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static long? HstsMaxAge(string header)
    {
        foreach (string part in header.Split(';'))
        {
            string p = part.Trim();
            if (!p.StartsWith("max-age", StringComparison.OrdinalIgnoreCase)) continue;
            int eq = p.IndexOf('=');
            if (eq < 0) continue;
            string number = p[(eq + 1)..].Trim().Trim('"');
            if (long.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out long value)) return value;
        }
        return null;
    }

    // --------------------------------------------------------------------- plumbing

    private static ApiFinding New(
        string id, string title, FindingSeverity severity, string detail,
        string recommendation, string owasp = "", string evidence = "") => new()
        {
            Id = id,
            Title = title,
            Severity = severity,
            Detail = detail,
            Recommendation = recommendation,
            Owasp = owasp,
            Evidence = evidence
        };

    /// <summary>
    /// Severity descending, then id ascending. LINQ ordering is stable, so findings that tie
    /// on both keys keep the order the checks produced them in — the report is byte-identical
    /// across runs, which is the whole point of ordering it here rather than at the caller.
    /// </summary>
    private static IReadOnlyList<ApiFinding> Order(List<ApiFinding> findings) =>
        findings
            .OrderByDescending(f => (int)f.Severity)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();

    private static List<string> SplitList(string value) =>
        value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static string Slug(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
            sb.Append(char.IsAsciiLetterOrDigit(c) ? char.ToLowerInvariant(c) : '-');
        string s = sb.ToString().Trim('-');
        while (s.Contains("--", StringComparison.Ordinal)) s = s.Replace("--", "-", StringComparison.Ordinal);
        return s.Length == 0 ? "unknown" : s;
    }

    /// <summary>Collapses whitespace and truncates, so evidence never becomes a second copy of the body.</summary>
    private static string Snip(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(Math.Min(value.Length, MaxEvidenceChars + 3));
        bool space = false;
        foreach (char c in value)
        {
            if (char.IsWhiteSpace(c) || char.IsControl(c))
            {
                if (!space && sb.Length > 0) { sb.Append(' '); space = true; }
                continue;
            }
            sb.Append(c);
            space = false;
            if (sb.Length >= MaxEvidenceChars) { sb.Append("..."); break; }
        }
        return sb.ToString().Trim();
    }

    private static string Window(string body, int index)
    {
        int start = Math.Max(0, index - 20);
        int length = Math.Min(body.Length - start, MaxEvidenceChars + 20);
        return body.Substring(start, length);
    }

    private static string Iso(DateTime utc) =>
        utc.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    // A regex timeout must degrade this analyzer to "found nothing here", never abort a run.
    private static bool SafeIsMatch(Regex regex, string input)
    {
        try { return regex.IsMatch(input); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static Match? SafeMatch(Regex regex, string input)
    {
        try { return regex.Match(input); }
        catch (RegexMatchTimeoutException) { return null; }
    }

    private static List<Match> SafeMatches(Regex regex, string input, int cap)
    {
        var result = new List<Match>();
        try
        {
            for (var m = regex.Match(input); m.Success && result.Count < cap; m = m.NextMatch())
                result.Add(m);
        }
        catch (RegexMatchTimeoutException) { /* partial results are still useful */ }
        return result;
    }
}
