using BruceEDR.Api;
using Xunit;
using static BruceEDR.Tests.ApiSecurityFixture;

namespace BruceEDR.Tests;

// ---------------------------------------------------------------------------
// Tests for BruceEDR.Api.EndpointAnalyzer.
//
// The analyzer is a pure function of (request, response, now), so every case here
// is a literal: no network, no disk, no wall clock, no admin rights, no temporary
// files. Where a check is a heuristic there is a paired negative test pinning the
// false positive it must not produce. Those pairs are the point of this file: a
// security tool that cries wolf gets switched off, and then it protects nothing.
// ---------------------------------------------------------------------------

/// <summary>
/// Literal builders shared by the ApiSecurity* fixtures. Header collections are plain
/// arrays rather than <c>params</c> because a named argument cannot use params expansion.
/// </summary>
internal static class ApiSecurityFixture
{
    /// <summary>Fixed "now". Nothing in these tests reads the real clock.</summary>
    public static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);

    /// <summary>Terse header-array literal, so a one-header case does not need array syntax.</summary>
    public static (string Name, string Value)[] H(params (string Name, string Value)[] headers) => headers;

    public static ApiResponse Resp(
        int status = 200,
        string url = "https://api.example.com/v1/users",
        string? contentType = "application/json",
        string body = "{}",
        (string Name, string Value)[]? headers = null)
    {
        var list = new List<ApiKeyValue>();
        if (contentType is not null) list.Add(ApiKeyValue.Of("Content-Type", contentType));
        foreach (var (name, value) in headers ?? Array.Empty<(string, string)>())
            list.Add(ApiKeyValue.Of(name, value));

        return new ApiResponse
        {
            StatusCode = status,
            FinalUrl = url,
            Headers = list,
            BodyText = body,
            BodyBytes = body.Length,
            StartedUtc = Now
        };
    }

    /// <summary>A response carrying every header the analyzer asks for, so a test can isolate one omission.</summary>
    public static ApiResponse Hardened(string body = "{}", (string Name, string Value)[]? extra = null)
    {
        var headers = new List<(string Name, string Value)>
        {
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store")
        };
        if (extra is not null) headers.AddRange(extra);
        return Resp(body: body, headers: headers.ToArray());
    }

    public static ApiRequest Req(
        string url = "https://api.example.com/v1/users",
        string method = "GET",
        ApiAuth? auth = null,
        (string Name, string Value)[]? headers = null) => new()
        {
            Url = url,
            Method = method,
            Auth = auth ?? ApiAuth.None,
            Headers = (headers ?? Array.Empty<(string, string)>())
                .Select(h => ApiKeyValue.Of(h.Name, h.Value)).ToList()
        };

    public static TlsInfo Cert(
        DateTime? notAfter = null,
        DateTime? notBefore = null,
        string subject = "CN=api.example.com, O=Example",
        string issuer = "CN=Example Issuing CA, O=Example",
        string signature = "sha256RSA",
        int keyBits = 2048,
        bool chainValid = true,
        string[]? sans = null,
        string[]? chainErrors = null) => new()
        {
            NotBeforeUtc = notBefore ?? Now.AddDays(-90),
            NotAfterUtc = notAfter ?? Now.AddDays(200),
            Subject = subject,
            Issuer = issuer,
            SignatureAlgorithm = signature,
            KeySizeBits = keyBits,
            ChainValid = chainValid,
            SubjectAltNames = sans ?? new[] { "api.example.com" },
            ChainErrors = chainErrors ?? Array.Empty<string>()
        };

    public static HashSet<string> IdsOf(IReadOnlyList<ApiFinding> findings) =>
        findings.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);

    public static ApiFinding Only(IReadOnlyList<ApiFinding> findings, string id) =>
        Assert.Single(findings, f => f.Id == id);

    public static ApiFinding Fake(string id, FindingSeverity severity) =>
        new() { Id = id, Title = id, Severity = severity };

    /// <summary>Every public entry point promises severity-descending, then id-ascending.</summary>
    public static void Ordered(IReadOnlyList<ApiFinding> findings)
    {
        for (int i = 1; i < findings.Count; i++)
        {
            var previous = findings[i - 1];
            var current = findings[i];
            Assert.True((int)previous.Severity >= (int)current.Severity,
                $"severity out of order at {i}: {previous.Id} then {current.Id}");
            if (previous.Severity == current.Severity)
                Assert.True(string.CompareOrdinal(previous.Id, current.Id) <= 0,
                    $"id out of order at {i}: {previous.Id} then {current.Id}");
        }
    }
}

public class ApiSecurityHeaderTests
{
    private static HashSet<string> Ids(ApiResponse response) =>
        IdsOf(EndpointAnalyzer.AnalyzeHeaders(response));

    [Fact]
    public void Https_Without_Hsts_Fires()
    {
        Assert.Contains("missing-hsts", Ids(Resp()));
    }

    [Fact]
    public void Strong_Hsts_Produces_No_Hsts_Findings()
    {
        var ids = Ids(Hardened());
        Assert.DoesNotContain("missing-hsts", ids);
        Assert.DoesNotContain("weak-hsts", ids);
    }

    [Theory]
    [InlineData("max-age=100")]
    [InlineData("max-age=0")]
    [InlineData("max-age=15551999")]                    // one second under the 180-day floor
    [InlineData("max-age=\"600\"; includeSubDomains")]
    public void Short_Hsts_MaxAge_Fires_Weak(string value)
    {
        var ids = Ids(Resp(headers: H(("Strict-Transport-Security", value))));
        Assert.Contains("weak-hsts", ids);
        Assert.DoesNotContain("missing-hsts", ids);
    }

    [Fact]
    public void Hsts_Exactly_At_Threshold_Is_Accepted()
    {
        Assert.DoesNotContain("weak-hsts",
            Ids(Resp(headers: H(("Strict-Transport-Security", "max-age=15552000")))));
    }

    [Fact]
    public void Hsts_Without_Parseable_MaxAge_Fires_Weak()
    {
        // The header exists but no client will honour it, which is worse than absent
        // because it looks like the control is in place.
        Assert.Contains("weak-hsts",
            Ids(Resp(headers: H(("Strict-Transport-Security", "includeSubDomains; preload")))));
    }

    [Fact]
    public void Hsts_Is_Not_Reported_On_Plain_Http()
    {
        Assert.DoesNotContain("missing-hsts", Ids(Resp(url: "http://api.example.com/v1")));
    }

    [Theory]
    [InlineData("https://localhost:5001/v1")]
    [InlineData("https://127.0.0.1:5001/v1")]
    public void Hsts_Is_Not_Reported_On_Loopback(string url)
    {
        // Pinning HSTS for localhost would affect every other service a developer runs there.
        Assert.DoesNotContain("missing-hsts", Ids(Resp(url: url)));
    }

    [Fact]
    public void Hsts_Is_Reported_When_The_Final_Url_Is_Unknown()
    {
        // No URL was recorded, so the analyzer assumes the conservative case.
        Assert.Contains("missing-hsts", Ids(new ApiResponse { StatusCode = 200, BodyText = "{}" }));
    }

    [Fact]
    public void Missing_Nosniff_Fires()
    {
        Assert.Contains("missing-nosniff", Ids(Resp()));
    }

    [Theory]
    [InlineData("nosniff", false)]
    [InlineData("NOSNIFF", false)]
    [InlineData(" nosniff ", false)]
    [InlineData("no-sniff", true)]
    [InlineData("", true)]
    public void Nosniff_Value_Must_Be_The_Exact_Token(string value, bool expectFinding)
    {
        Assert.Equal(expectFinding, Ids(Resp(headers: H(("X-Content-Type-Options", value)))).Contains("missing-nosniff"));
    }

    [Fact]
    public void Csp_Is_Required_On_Html()
    {
        Assert.Contains("missing-csp", Ids(Resp(contentType: "text/html; charset=utf-8", body: "<html></html>")));
    }

    [Fact]
    public void Csp_Is_Not_Required_On_Json()
    {
        // A body that is never rendered gains nothing from CSP; firing here would be noise.
        Assert.DoesNotContain("missing-csp", Ids(Resp(body: "{\"a\":1}")));
    }

    [Fact]
    public void Framing_Protection_Is_Required_On_Html()
    {
        Assert.Contains("missing-frame-protection", Ids(Resp(contentType: "text/html", body: "<html></html>")));
    }

    [Theory]
    [InlineData("X-Frame-Options", "DENY")]
    [InlineData("X-Frame-Options", "SAMEORIGIN")]
    [InlineData("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")]
    public void Either_Framing_Control_Suppresses_The_Finding(string name, string value)
    {
        Assert.DoesNotContain("missing-frame-protection",
            Ids(Resp(contentType: "text/html", body: "<html></html>", headers: H((name, value)))));
    }

    [Fact]
    public void Framing_Protection_Is_Not_Reported_On_Json()
    {
        Assert.DoesNotContain("missing-frame-protection", Ids(Resp()));
    }

    [Fact]
    public void Missing_Referrer_Policy_Fires_And_Present_Does_Not()
    {
        Assert.Contains("missing-referrer-policy", Ids(Resp()));
        Assert.DoesNotContain("missing-referrer-policy", Ids(Resp(headers: H(("Referrer-Policy", "no-referrer")))));
    }

    [Theory]
    [InlineData("Server", "nginx/1.18.0", true)]
    [InlineData("Server", "Apache/2.4.41 (Ubuntu)", true)]
    [InlineData("Server", "cloudflare", false)]        // no version: nothing actionable disclosed
    [InlineData("Server", "nginx", false)]
    [InlineData("X-Powered-By", "PHP/8.1.2", true)]
    [InlineData("X-Powered-By", "ASP.NET", true)]      // the header exists only to advertise a stack
    [InlineData("X-AspNet-Version", "4.0.30319", true)]
    [InlineData("X-Runtime", "0.123456", true)]
    public void Version_Disclosure_Requires_An_Actionable_Value(string name, string value, bool expected)
    {
        Assert.Equal(expected, Ids(Resp(headers: H((name, value)))).Contains("server-version-disclosure"));
    }

    [Fact]
    public void Version_Disclosure_Evidence_Names_The_Header()
    {
        var finding = Only(EndpointAnalyzer.AnalyzeHeaders(Resp(headers: H(("Server", "nginx/1.18.0")))),
            "server-version-disclosure");
        Assert.Contains("nginx/1.18.0", finding.Evidence, StringComparison.Ordinal);
        Assert.Equal(FindingSeverity.Low, finding.Severity);
    }

    [Theory]
    [InlineData("1; mode=block", true)]
    [InlineData("1", true)]
    [InlineData("0", false)]
    [InlineData("0; mode=block", false)]
    public void Legacy_Xss_Filter_Is_Reported_Only_When_Enabled(string value, bool expected)
    {
        Assert.Equal(expected, Ids(Resp(headers: H(("X-XSS-Protection", value)))).Contains("xss-protection-enabled"));
    }

    [Fact]
    public void Absent_Xss_Protection_Is_Not_A_Finding()
    {
        Assert.DoesNotContain("xss-protection-enabled", Ids(Resp()));
    }

    [Fact]
    public void Cookie_Bearing_Response_Must_Be_No_Store()
    {
        Assert.Contains("missing-cache-control-sensitive", Ids(Resp(headers: H(("Set-Cookie", "sid=abc; Path=/")))));
    }

    [Fact]
    public void No_Store_Suppresses_The_Cache_Finding()
    {
        Assert.DoesNotContain("missing-cache-control-sensitive",
            Ids(Resp(headers: H(("Set-Cookie", "sid=abc"), ("Cache-Control", "no-store, private")))));
    }

    [Fact]
    public void No_Cache_Alone_Is_Not_Enough()
    {
        // no-cache permits storage and only forces revalidation, so it does not clear this.
        Assert.Contains("missing-cache-control-sensitive",
            Ids(Resp(headers: H(("Set-Cookie", "sid=abc"), ("Cache-Control", "no-cache")))));
    }

    [Fact]
    public void Ordinary_Response_Does_Not_Demand_No_Store()
    {
        Assert.DoesNotContain("missing-cache-control-sensitive", Ids(Resp(body: "{\"count\":3}")));
    }

    [Fact]
    public void Body_Without_Content_Type_Fires()
    {
        Assert.Contains("missing-content-type", Ids(Resp(contentType: null, body: "{\"a\":1}")));
    }

    [Theory]
    [InlineData(204)]
    [InlineData(304)]
    public void Bodyless_Statuses_Do_Not_Need_A_Content_Type(int status)
    {
        Assert.DoesNotContain("missing-content-type", Ids(Resp(status: status, contentType: null, body: "")));
    }

    [Fact]
    public void Json_Served_As_Html_Fires()
    {
        Assert.Contains("json-served-as-html", Ids(Resp(contentType: "text/html", body: "{\"name\":\"<script>\"}")));
    }

    [Fact]
    public void Real_Html_Is_Not_Reported_As_Mislabelled_Json()
    {
        Assert.DoesNotContain("json-served-as-html",
            Ids(Resp(contentType: "text/html", body: "<html><body>hi</body></html>")));
    }

    [Fact]
    public void Failed_Request_Yields_Nothing_Anywhere()
    {
        var failed = new ApiResponse { Error = "Name or service not known", FinalUrl = "https://api.example.com/v1" };
        Assert.Empty(EndpointAnalyzer.AnalyzeHeaders(failed));
        Assert.Empty(EndpointAnalyzer.AnalyzeCors(failed));
        Assert.Empty(EndpointAnalyzer.AnalyzeCookies(failed));
        Assert.Empty(EndpointAnalyzer.AnalyzeBody(failed));
        Assert.Empty(EndpointAnalyzer.Analyze(Req(), failed, Now));
    }

    [Fact]
    public void Completely_Empty_Response_Does_Not_Throw()
    {
        var bare = new ApiResponse();
        var findings = EndpointAnalyzer.AnalyzeHeaders(bare);
        Assert.NotNull(findings);
        Ordered(findings);
        Assert.Empty(EndpointAnalyzer.AnalyzeCookies(bare));
        Assert.Empty(EndpointAnalyzer.AnalyzeCors(bare));
        Assert.Empty(EndpointAnalyzer.AnalyzeBody(bare));
    }

    [Fact]
    public void Header_Findings_Are_Ordered()
    {
        Ordered(EndpointAnalyzer.AnalyzeHeaders(Resp(
            contentType: "text/html",
            body: "{\"password\":\"x\"}",
            headers: H(("Server", "nginx/1.18.0"), ("X-XSS-Protection", "1; mode=block")))));
    }
}

public class ApiSecurityTlsTests
{
    private static readonly Uri Endpoint = new("https://api.example.com/v1/users");
    private static readonly Uri Loopback = new("https://localhost:5001/v1/users");

    private static HashSet<string> Ids(TlsInfo? tls, Uri? uri = null) =>
        IdsOf(EndpointAnalyzer.AnalyzeTls(tls, uri ?? Endpoint, Now));

    [Fact]
    public void Null_Tls_Yields_Nothing()
    {
        Assert.Empty(EndpointAnalyzer.AnalyzeTls(null, Endpoint, Now));
    }

    [Fact]
    public void Healthy_Certificate_Yields_Nothing()
    {
        Assert.Empty(EndpointAnalyzer.AnalyzeTls(Cert(), Endpoint, Now));
    }

    [Fact]
    public void Expired_Certificate_Is_Critical()
    {
        var findings = EndpointAnalyzer.AnalyzeTls(Cert(notAfter: Now.AddDays(-1)), Endpoint, Now);
        Assert.Equal(FindingSeverity.Critical, Only(findings, "tls-cert-expired").Severity);
        // Expired and expiring are mutually exclusive: reporting both would double-count.
        Assert.DoesNotContain("tls-cert-expiring", IdsOf(findings));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(29)]
    [InlineData(30)]
    public void Certificate_Inside_The_Renewal_Window_Is_Reported(int days)
    {
        Assert.Contains("tls-cert-expiring", Ids(Cert(notAfter: Now.AddDays(days))));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(200)]
    public void Certificate_Beyond_The_Window_Is_Not_Reported(int days)
    {
        Assert.DoesNotContain("tls-cert-expiring", Ids(Cert(notAfter: Now.AddDays(days))));
    }

    [Fact]
    public void Certificate_Dated_In_The_Future_Is_Reported()
    {
        Assert.Contains("tls-cert-not-yet-valid", Ids(Cert(notBefore: Now.AddDays(2))));
    }

    [Fact]
    public void Default_Dates_Do_Not_Fabricate_Expiry_Findings()
    {
        // A TlsInfo whose dates were never captured must not read as "expired in year 1".
        var ids = Ids(new TlsInfo
        {
            ChainValid = true,
            Subject = "CN=api.example.com",
            Issuer = "CN=Example CA",
            SubjectAltNames = new[] { "api.example.com" }
        });
        Assert.DoesNotContain("tls-cert-expired", ids);
        Assert.DoesNotContain("tls-cert-expiring", ids);
        Assert.DoesNotContain("tls-cert-not-yet-valid", ids);
    }

    [Fact]
    public void Chain_Errors_Are_High_And_Are_Quoted()
    {
        var findings = EndpointAnalyzer.AnalyzeTls(
            Cert(chainValid: false, chainErrors: new[] { "PartialChain", "UntrustedRoot" }), Endpoint, Now);
        var finding = Only(findings, "tls-chain-invalid");
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Contains("UntrustedRoot", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Chain_Valid_False_Alone_Is_Enough()
    {
        Assert.Contains("tls-chain-invalid", Ids(Cert(chainValid: false)));
    }

    [Fact]
    public void Host_Not_On_The_Certificate_Is_Reported()
    {
        Assert.Contains("tls-hostname-mismatch",
            Ids(Cert(subject: "CN=other.example.net", sans: new[] { "other.example.net" })));
    }

    [Theory]
    [InlineData("api.example.com")]
    [InlineData("*.example.com")]
    [InlineData("API.EXAMPLE.COM")]
    [InlineData("api.example.com.")]              // trailing root dot
    [InlineData("DNS:api.example.com")]
    [InlineData("DNS Name=api.example.com")]
    public void Covered_Hosts_Are_Not_Reported(string san)
    {
        Assert.DoesNotContain("tls-hostname-mismatch", Ids(Cert(subject: "CN=unrelated", sans: new[] { san })));
    }

    [Fact]
    public void Wildcard_Covers_Exactly_One_Label()
    {
        // *.example.com must not be accepted for deep.api.example.com.
        Assert.Contains("tls-hostname-mismatch", IdsOf(EndpointAnalyzer.AnalyzeTls(
            Cert(subject: "CN=*.example.com", sans: new[] { "*.example.com" }),
            new Uri("https://deep.api.example.com/v1"), Now)));
    }

    [Fact]
    public void Common_Name_Is_Used_When_There_Are_No_Sans()
    {
        Assert.DoesNotContain("tls-hostname-mismatch",
            Ids(Cert(subject: "CN=api.example.com, O=Example", sans: Array.Empty<string>())));
    }

    [Fact]
    public void No_Captured_Names_Means_No_Mismatch_Claim()
    {
        // With nothing to compare against, asserting a mismatch would be a fabrication.
        Assert.DoesNotContain("tls-hostname-mismatch",
            Ids(Cert(subject: "O=Example", issuer: "O=Example CA", sans: Array.Empty<string>())));
    }

    [Theory]
    [InlineData(1024, "sha256RSA", true)]
    [InlineData(2047, "sha256RSA", true)]
    [InlineData(2048, "sha256RSA", false)]
    [InlineData(4096, "sha256RSA", false)]
    [InlineData(256, "sha256ECDSA", false)]   // a 256-bit ECDSA key is strong, not weak
    [InlineData(384, "sha384ECDSA", false)]
    [InlineData(0, "sha256RSA", false)]       // unknown size: say nothing
    public void Weak_Key_Check_Only_Applies_To_Rsa(int bits, string signature, bool expected)
    {
        Assert.Equal(expected, Ids(Cert(keyBits: bits, signature: signature)).Contains("tls-weak-key"));
    }

    [Theory]
    [InlineData("sha1RSA", true)]
    [InlineData("sha1WithRSAEncryption", true)]
    [InlineData("SHA-1", true)]
    [InlineData("md5RSA", true)]
    [InlineData("sha256RSA", false)]
    [InlineData("sha512RSA", false)]
    [InlineData("sha384ECDSA", false)]
    [InlineData("", false)]
    public void Broken_Signature_Hashes_Are_Reported(string signature, bool expected)
    {
        Assert.Equal(expected, Ids(Cert(signature: signature)).Contains("tls-sha1-signature"));
    }

    [Fact]
    public void Self_Signed_Certificate_Is_Reported_Off_Loopback()
    {
        Assert.Contains("tls-self-signed", Ids(Cert(subject: "CN=api.example.com", issuer: "CN=api.example.com")));
    }

    [Fact]
    public void Self_Signed_Certificate_Is_Expected_On_Loopback()
    {
        var tls = Cert(subject: "CN=localhost", issuer: "CN=localhost", sans: new[] { "localhost" });
        Assert.DoesNotContain("tls-self-signed", Ids(tls, Loopback));
    }

    [Fact]
    public void A_Broken_Certificate_Produces_An_Ordered_Report()
    {
        var findings = EndpointAnalyzer.AnalyzeTls(
            Cert(notAfter: Now.AddDays(-5), chainValid: false, signature: "sha1RSA", keyBits: 1024,
                 subject: "CN=nope.example.org", sans: new[] { "nope.example.org" }),
            Endpoint, Now);

        Assert.True(findings.Count >= 5, $"expected at least 5 findings, got {findings.Count}");
        Ordered(findings);
        Assert.Equal(FindingSeverity.Critical, findings[0].Severity);
    }
}

public class ApiSecurityCorsTests
{
    private static HashSet<string> Ids(params (string Name, string Value)[] headers) =>
        IdsOf(EndpointAnalyzer.AnalyzeCors(Resp(headers: headers)));

    [Fact]
    public void No_Cors_Headers_Yields_Nothing()
    {
        Assert.Empty(EndpointAnalyzer.AnalyzeCors(Resp()));
    }

    [Fact]
    public void Wildcard_With_Credentials_Is_High()
    {
        var findings = EndpointAnalyzer.AnalyzeCors(Resp(headers: H(
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"))));
        var finding = Only(findings, "cors-wildcard-with-credentials");
        Assert.Equal(FindingSeverity.High, finding.Severity);
        Assert.Equal(OwaspApi.SecurityMisconfiguration, finding.Owasp);
        // The detail must admit that browsers reject this pair rather than overclaim.
        Assert.Contains("reject", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Wildcard_Without_Credentials_Is_Not_The_Dangerous_Pair()
    {
        Assert.DoesNotContain("cors-wildcard-with-credentials", Ids(("Access-Control-Allow-Origin", "*")));
    }

    [Fact]
    public void Credentials_Value_Must_Be_True()
    {
        Assert.DoesNotContain("cors-wildcard-with-credentials",
            Ids(("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "false")));
    }

    [Fact]
    public void Literal_Null_Origin_Is_Reported()
    {
        var finding = Only(
            EndpointAnalyzer.AnalyzeCors(Resp(headers: H(("Access-Control-Allow-Origin", "null")))),
            "cors-null-origin-allowed");
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
    }

    [Fact]
    public void Echoed_Origin_With_Credentials_Is_High()
    {
        var response = Resp(headers: H(
            ("Access-Control-Allow-Origin", "https://evil.test"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin")));

        var finding = Only(EndpointAnalyzer.AnalyzeCors(response, "https://evil.test"), "cors-reflected-origin");
        Assert.Equal(FindingSeverity.High, finding.Severity);
        // One sample cannot prove reflection, and the wording must say so.
        Assert.Contains("cannot distinguish", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Echoed_Origin_Without_Credentials_Is_Medium()
    {
        var response = Resp(headers: H(("Access-Control-Allow-Origin", "https://app.example.com")));
        Assert.Equal(FindingSeverity.Medium,
            Only(EndpointAnalyzer.AnalyzeCors(response, "https://app.example.com"), "cors-reflected-origin").Severity);
    }

    [Fact]
    public void Origin_That_Was_Not_Echoed_Is_Not_Reflection()
    {
        var response = Resp(headers: H(("Access-Control-Allow-Origin", "https://app.example.com")));
        Assert.DoesNotContain("cors-reflected-origin",
            IdsOf(EndpointAnalyzer.AnalyzeCors(response, "https://evil.test")));
    }

    [Fact]
    public void Credentialed_Per_Origin_Response_Should_Vary_On_Origin()
    {
        Assert.Contains("cors-missing-vary-origin", Ids(
            ("Access-Control-Allow-Origin", "https://app.example.com"),
            ("Access-Control-Allow-Credentials", "true")));
    }

    [Fact]
    public void Vary_Origin_Suppresses_The_Cache_Finding()
    {
        Assert.DoesNotContain("cors-missing-vary-origin", Ids(
            ("Access-Control-Allow-Origin", "https://app.example.com"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Accept-Encoding, Origin")));
    }

    [Theory]
    [InlineData("*", true)]
    [InlineData("Content-Type, Authorization", false)]
    [InlineData("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o", true)]   // 15 entries: copied, not derived
    public void Broad_Allow_Headers_Is_Reported(string value, bool expected)
    {
        Assert.Equal(expected, Ids(("Access-Control-Allow-Headers", value)).Contains("cors-broad-allow-headers"));
    }

    [Theory]
    [InlineData("*", true)]
    [InlineData("GET, POST", false)]
    [InlineData("GET, HEAD, POST, PUT, PATCH, DELETE", true)]
    [InlineData("GET, TRACE", true)]
    public void Broad_Allow_Methods_Is_Reported(string value, bool expected)
    {
        Assert.Equal(expected, Ids(("Access-Control-Allow-Methods", value)).Contains("cors-broad-allow-methods"));
    }

    [Fact]
    public void Cors_Findings_Are_Ordered()
    {
        Ordered(EndpointAnalyzer.AnalyzeCors(Resp(headers: H(
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Access-Control-Allow-Headers", "*"),
            ("Access-Control-Allow-Methods", "*")))));
    }
}

public class ApiSecurityCookieTests
{
    private static HashSet<string> Ids(string setCookie, string url = "https://api.example.com/v1/users") =>
        IdsOf(EndpointAnalyzer.AnalyzeCookies(Resp(url: url, headers: H(("Set-Cookie", setCookie)))));

    [Fact]
    public void No_Cookies_Yields_Nothing()
    {
        Assert.Empty(EndpointAnalyzer.AnalyzeCookies(Resp()));
    }

    [Fact]
    public void Cookie_Without_Secure_On_Https_Fires()
    {
        Assert.Contains("cookie-missing-secure", Ids("sid=abc123; Path=/; HttpOnly; SameSite=Lax"));
    }

    [Fact]
    public void Cookie_With_Secure_Does_Not_Fire()
    {
        Assert.DoesNotContain("cookie-missing-secure", Ids("sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"));
    }

    [Fact]
    public void Loopback_Development_Cookie_Is_Not_Penalised_For_Secure()
    {
        Assert.DoesNotContain("cookie-missing-secure",
            Ids("sid=abc123; Path=/; HttpOnly; SameSite=Lax", "http://localhost:5001/v1"));
    }

    [Fact]
    public void Session_Cookie_Readable_By_Script_Is_Medium()
    {
        var findings = EndpointAnalyzer.AnalyzeCookies(
            Resp(headers: H(("Set-Cookie", "session_token=abc; Secure; SameSite=Lax"))));
        Assert.Equal(FindingSeverity.Medium, Only(findings, "cookie-missing-httponly").Severity);
    }

    [Fact]
    public void Non_Session_Cookie_Readable_By_Script_Is_Low()
    {
        var findings = EndpointAnalyzer.AnalyzeCookies(
            Resp(headers: H(("Set-Cookie", "theme=dark; Secure; SameSite=Lax"))));
        Assert.Equal(FindingSeverity.Low, Only(findings, "cookie-missing-httponly").Severity);
    }

    [Fact]
    public void Missing_SameSite_Fires()
    {
        Assert.Contains("cookie-missing-samesite", Ids("sid=abc; Secure; HttpOnly"));
    }

    [Theory]
    [InlineData("Strict")]
    [InlineData("Lax")]
    public void Declared_SameSite_Does_Not_Fire(string value)
    {
        Assert.DoesNotContain("cookie-missing-samesite", Ids($"sid=abc; Secure; HttpOnly; SameSite={value}"));
    }

    [Fact]
    public void SameSite_None_Without_Secure_Fires()
    {
        var ids = Ids("sid=abc; HttpOnly; SameSite=None");
        Assert.Contains("cookie-samesite-none-insecure", ids);
        Assert.DoesNotContain("cookie-missing-samesite", ids);
    }

    [Fact]
    public void SameSite_None_With_Secure_Is_Fine()
    {
        Assert.DoesNotContain("cookie-samesite-none-insecure", Ids("sid=abc; Secure; HttpOnly; SameSite=None"));
    }

    [Fact]
    public void Long_Lived_Session_Cookie_Fires()
    {
        Assert.Contains("cookie-long-lived-session", Ids("sid=abc; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000"));
    }

    [Theory]
    [InlineData("2592000")]      // exactly 30 days: at the boundary, not over it
    [InlineData("3600")]
    [InlineData("not-a-number")]
    [InlineData("-1")]
    [InlineData("")]
    public void Reasonable_Or_Malformed_MaxAge_Does_Not_Fire(string maxAge)
    {
        Assert.DoesNotContain("cookie-long-lived-session",
            Ids($"sid=abc; Secure; HttpOnly; SameSite=Lax; Max-Age={maxAge}"));
    }

    [Fact]
    public void Long_Lived_Non_Session_Cookie_Is_Not_Reported()
    {
        // A year-long locale preference is not a credential.
        Assert.DoesNotContain("cookie-long-lived-session",
            Ids("locale=en-GB; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000"));
    }

    [Fact]
    public void Parent_Domain_Scope_Fires()
    {
        Assert.Contains("cookie-parent-domain-scope", Ids("sid=abc; Secure; HttpOnly; SameSite=Lax; Domain=.example.com"));
    }

    [Fact]
    public void Host_Only_Cookie_Does_Not_Fire()
    {
        Assert.DoesNotContain("cookie-parent-domain-scope",
            Ids("sid=abc; Secure; HttpOnly; SameSite=Lax; Domain=api.example.com"));
    }

    [Fact]
    public void Unrelated_Domain_Is_Not_Reported_As_Parent_Scope()
    {
        // A browser simply rejects this cookie; it is not a parent-scope exposure.
        Assert.DoesNotContain("cookie-parent-domain-scope",
            Ids("sid=abc; Secure; HttpOnly; SameSite=Lax; Domain=elsewhere.test"));
    }

    [Fact]
    public void Cookie_Value_Is_Never_Copied_Into_A_Finding()
    {
        // The value of a session cookie is the credential, and a report gets emailed around.
        const string secret = "eyJhbGciOiJIUzI1NiJ9.SUPERSECRETSESSIONVALUE.sig";
        var findings = EndpointAnalyzer.AnalyzeCookies(Resp(headers: H(
            ("Set-Cookie", $"session={secret}; Path=/; Domain=.example.com; Max-Age=99999999"))));

        Assert.NotEmpty(findings);
        foreach (var finding in findings)
        {
            Assert.DoesNotContain("SUPERSECRETSESSIONVALUE", finding.Evidence, StringComparison.Ordinal);
            Assert.DoesNotContain("SUPERSECRETSESSIONVALUE", finding.Detail, StringComparison.Ordinal);
            Assert.DoesNotContain("SUPERSECRETSESSIONVALUE", finding.Title, StringComparison.Ordinal);
        }
        Assert.Contains(findings, f => f.Evidence.Contains("<redacted>", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(";;;")]
    [InlineData("=value")]
    [InlineData("=")]
    [InlineData("name")]
    [InlineData("a=b; ; ; Secure; ; HttpOnly; SameSite=")]
    [InlineData("name=value; Max-Age=99999999999999999999")]
    [InlineData("name=value; Domain=")]
    public void Malformed_Set_Cookie_Never_Throws(string raw)
    {
        var findings = EndpointAnalyzer.AnalyzeCookies(Resp(headers: H(("Set-Cookie", raw))));
        Assert.NotNull(findings);
        Ordered(findings);
    }

    [Fact]
    public void Multiple_Set_Cookie_Headers_Are_All_Reviewed()
    {
        var findings = EndpointAnalyzer.AnalyzeCookies(Resp(headers: H(
            ("Set-Cookie", "sid=a; HttpOnly"),
            ("Set-Cookie", "csrf=b; Secure"))));

        Assert.Contains(findings, f => f.Title.Contains("'sid'", StringComparison.Ordinal));
        Assert.Contains(findings, f => f.Title.Contains("'csrf'", StringComparison.Ordinal));
        Ordered(findings);
    }
}

public class ApiSecurityBodyTests
{
    private static HashSet<string> Ids(string body, int status = 200, string contentType = "application/json") =>
        IdsOf(EndpointAnalyzer.AnalyzeBody(Resp(status: status, contentType: contentType, body: body)));

    [Fact]
    public void Empty_Body_Yields_Nothing()
    {
        Assert.Empty(EndpointAnalyzer.AnalyzeBody(Resp(body: "")));
    }

    [Theory]
    [InlineData("System.NullReferenceException: Object reference not set\n   at System.Web.Handler.Process()")]
    [InlineData("Traceback (most recent call last):\n  File \"/srv/app/views.py\", line 42")]
    [InlineData("java.lang.IllegalStateException: broken")]
    [InlineData("Exception in thread main\n\tat java.base/java.util.List.get(List.java:1)")]
    [InlineData("ORA-01722: invalid number")]
    [InlineData("SQLSTATE[42S02]: Base table or view not found")]
    [InlineData("Server Error in '/' Application. Runtime Error")]
    [InlineData("Warning: include(): failed to open stream in /var/www/index.php on line 27")]
    public void Framework_Error_Output_Is_Reported(string body)
    {
        Assert.Contains("body-stack-trace", Ids(body, contentType: "text/plain"));
    }

    [Fact]
    public void Only_One_Stack_Trace_Finding_Per_Response()
    {
        // Listing every frame would just copy the trace into the report.
        var findings = EndpointAnalyzer.AnalyzeBody(Resp(contentType: "text/plain",
            body: "java.lang.RuntimeException\n\tat java.base/x.y(z.java:9)\nCaused by: ORA-01722 on line 3"));
        Assert.Single(findings, f => f.Id == "body-stack-trace");
    }

    [Theory]
    [InlineData("{\"note\":\"see the manual on line spacing\"}")]
    [InlineData("{\"status\":\"ok\"}")]
    [InlineData("{\"title\":\"Errors and how to read them\"}")]
    public void Ordinary_Prose_Is_Not_A_Stack_Trace(string body)
    {
        Assert.DoesNotContain("body-stack-trace", Ids(body));
    }

    [Theory]
    [InlineData("{\"host\":\"10.1.2.3\"}")]
    [InlineData("{\"host\":\"192.168.0.17\"}")]
    [InlineData("{\"host\":\"172.16.5.5\"}")]
    [InlineData("{\"host\":\"172.31.255.254\"}")]
    [InlineData("{\"host\":\"127.0.0.1\"}")]
    [InlineData("{\"host\":\"169.254.169.254\"}")]
    [InlineData("{\"db\":\"sql01.internal\"}")]
    [InlineData("{\"db\":\"dc1.corp\"}")]
    public void Internal_Topology_Is_Reported(string body)
    {
        Assert.Contains("body-internal-address", Ids(body));
    }

    [Fact]
    public void Unc_Paths_Are_Reported()
    {
        // Two literal backslashes, a host, then a share separator.
        string body = "{\"share\":\"" + new string('\\', 2) + "FILESRV01" + new string('\\', 1) + "logs\"}";
        Assert.Contains("body-internal-address",
            IdsOf(EndpointAnalyzer.AnalyzeBody(Resp(contentType: "text/plain", body: body))));
    }

    [Theory]
    [InlineData("{\"host\":\"8.8.8.8\"}")]                 // public resolver, not internal
    [InlineData("{\"build\":\"10.0.19041.1\"}")]           // Windows build number, not an IP
    [InlineData("{\"host\":\"172.15.0.1\"}")]              // just outside the private range
    [InlineData("{\"host\":\"172.32.0.1\"}")]              // just outside the private range
    [InlineData("{\"version\":\"192.168\"}")]              // incomplete, not an address
    [InlineData("{\"ip\":\"192.168.1.256\"}")]             // 256 is not a valid octet
    public void Public_Or_Version_Shaped_Values_Are_Not_Internal_Addresses(string body)
    {
        Assert.DoesNotContain("body-internal-address", Ids(body));
    }

    [Fact]
    public void Metadata_Address_Is_Tied_To_Ssrf()
    {
        var finding = Only(EndpointAnalyzer.AnalyzeBody(Resp(body: "{\"url\":\"http://169.254.169.254/latest\"}")),
            "body-internal-address");
        Assert.Equal(OwaspApi.Ssrf, finding.Owasp);
    }

    [Fact]
    public void Email_Addresses_Are_Reported_As_Exposure_Not_Vulnerability()
    {
        var finding = Only(EndpointAnalyzer.AnalyzeBody(Resp(body: "{\"email\":\"alice@example.com\"}")),
            "body-pii-exposed");
        Assert.Equal(FindingSeverity.Medium, finding.Severity);
        Assert.Contains("not a vulnerability", finding.Detail, StringComparison.OrdinalIgnoreCase);
        // The sample must be masked, never the live address.
        Assert.DoesNotContain("alice@example.com", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("@example.com", finding.Evidence, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"ssn\":\"123-45-6789\"}", true)]
    [InlineData("{\"ssn\":\"000-12-3456\"}", false)]   // never-issued area number
    [InlineData("{\"ssn\":\"666-12-3456\"}", false)]
    [InlineData("{\"ssn\":\"900-12-3456\"}", false)]
    [InlineData("{\"ssn\":\"123-00-6789\"}", false)]   // never-issued group
    [InlineData("{\"ssn\":\"123-45-0000\"}", false)]   // never-issued serial
    [InlineData("{\"code\":\"1234-56-7890\"}", false)] // wrong shape
    public void Ssn_Pattern_Excludes_Never_Issued_Ranges(string body, bool expected)
    {
        Assert.Equal(expected, Ids(body).Contains("body-pii-exposed"));
    }

    [Theory]
    [InlineData("4111111111111111", true)]     // Visa test number, passes Luhn
    [InlineData("4111 1111 1111 1111", true)]  // spaced form
    [InlineData("5555555555554444", true)]     // MasterCard test number
    [InlineData("378282246310005", true)]      // Amex test number
    [InlineData("4111111111111112", false)]    // fails Luhn
    [InlineData("1712345678901", false)]       // millisecond timestamp: no issuer prefix
    [InlineData("9999999999999999", false)]    // no issuer prefix
    [InlineData("41111111111", false)]         // too short to be a card
    public void Card_Detection_Requires_Luhn_And_An_Issuer_Prefix(string number, bool expected)
    {
        Assert.Equal(expected, Ids("{\"value\":\"" + number + "\"}").Contains("body-pii-exposed"));
    }

    [Fact]
    public void Card_Sample_Shows_Only_The_Last_Four_Digits()
    {
        var finding = Only(EndpointAnalyzer.AnalyzeBody(Resp(body: "{\"pan\":\"4111111111111111\"}")),
            "body-pii-exposed");
        Assert.DoesNotContain("4111111111111111", finding.Evidence, StringComparison.Ordinal);
        Assert.Contains("1111", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Large_Json_List_Is_Reported()
    {
        Assert.Contains("body-large-response", Ids("[" + string.Join(",", Enumerable.Range(0, 600)) + "]"));
    }

    [Fact]
    public void Small_List_Is_Not_Reported()
    {
        Assert.DoesNotContain("body-large-response", Ids("[1,2,3]"));
    }

    [Fact]
    public void Large_Embedded_List_Is_Reported_By_Byte_Count()
    {
        var response = Resp(body: "{\"items\":[1,2,3]}") with { BodyBytes = 4L * 1024 * 1024 };
        Assert.Contains("body-large-response", IdsOf(EndpointAnalyzer.AnalyzeBody(response)));
    }

    [Fact]
    public void Large_Non_List_Response_Is_Not_Reported()
    {
        // Size alone is weak evidence: a big document is not a bulk-extraction lever.
        var response = Resp(contentType: "text/plain", body: "prose") with { BodyBytes = 4L * 1024 * 1024 };
        Assert.DoesNotContain("body-large-response", IdsOf(EndpointAnalyzer.AnalyzeBody(response)));
    }

    [Fact]
    public void Truncated_Response_Is_Always_Reported()
    {
        var response = Resp(body: "{\"a\":1}") with { BodyTruncated = true };
        Assert.Contains("body-large-response", IdsOf(EndpointAnalyzer.AnalyzeBody(response)));
    }

    [Fact]
    public void Non_Json_Server_Error_Is_Reported()
    {
        Assert.Contains("error-page-not-json",
            Ids("<html><body>Something went wrong</body></html>", status: 500, contentType: "text/html"));
    }

    [Fact]
    public void Json_Server_Error_Is_Not_Reported()
    {
        Assert.DoesNotContain("error-page-not-json",
            Ids("{\"error\":\"internal\"}", status: 500, contentType: "application/problem+json"));
    }

    [Fact]
    public void Json_Body_With_A_Wrong_Content_Type_Still_Counts_As_Json()
    {
        Assert.DoesNotContain("error-page-not-json",
            Ids("{\"error\":\"internal\"}", status: 503, contentType: "text/plain"));
    }

    [Fact]
    public void Empty_Server_Error_Body_Is_Not_Reported()
    {
        Assert.DoesNotContain("error-page-not-json", Ids("   ", status: 500, contentType: "text/html"));
    }

    [Fact]
    public void Client_Errors_Are_Not_Error_Page_Findings()
    {
        Assert.DoesNotContain("error-page-not-json", Ids("<html>Not Found</html>", status: 404, contentType: "text/html"));
    }

    [Fact]
    public void Any_Secret_Finding_Carries_Only_The_Redacted_Form()
    {
        // Contract with BruceEDR.Intel.SecretScanner: whatever its rules match, the
        // analyzer must promote it to High and must never copy the live value into the
        // report. Written so it holds whether or not the scanner's rules match this body.
        const string secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
        var findings = EndpointAnalyzer.AnalyzeBody(Resp(
            body: "{\"aws_access_key_id\":\"AKIA" + "IOSFODNN7EXAMPLE\",\"aws_secret_access_key\":\"" + secret + "\"}"));

        foreach (var finding in findings.Where(f => f.Id.StartsWith("body-secret-", StringComparison.Ordinal)))
        {
            Assert.Equal(FindingSeverity.High, finding.Severity);
            Assert.DoesNotContain(secret, finding.Evidence, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, finding.Detail, StringComparison.Ordinal);
            Assert.NotEmpty(finding.Recommendation);
        }
        Ordered(findings);
    }

    [Fact]
    public void Adversarial_Body_Does_Not_Throw_Or_Hang()
    {
        // Nesting past the JSON reader's depth limit, a long digit run that the card
        // pattern must chew through, and a long letter run, all at once. The analyzer
        // must degrade to "found nothing here" rather than abort the run.
        string body = new string('{', 5000) + new string('9', 20000) + new string('a', 50000);
        var findings = EndpointAnalyzer.AnalyzeBody(Resp(contentType: "text/plain", body: body));
        Assert.NotNull(findings);
        Ordered(findings);
    }

    [Fact]
    public void Evidence_Is_Always_Bounded()
    {
        string body = "java.lang.Error: " + new string('x', 10000);
        foreach (var finding in EndpointAnalyzer.AnalyzeBody(Resp(contentType: "text/plain", body: body)))
            Assert.True(finding.Evidence.Length <= 256, $"{finding.Id} evidence was {finding.Evidence.Length} chars");
    }
}

public class ApiSecurityGradeTests
{
    [Fact]
    public void No_Findings_Scores_A_Hundred()
    {
        var (grade, score) = EndpointAnalyzer.Grade(Array.Empty<ApiFinding>());
        Assert.Equal('A', grade);
        Assert.Equal(100, score);
    }

    [Fact]
    public void Info_Findings_Cost_Nothing()
    {
        var (grade, score) = EndpointAnalyzer.Grade(new[]
        {
            Fake("a", FindingSeverity.Info),
            Fake("b", FindingSeverity.Info)
        });
        Assert.Equal('A', grade);
        Assert.Equal(100, score);
    }

    [Theory]
    // critical, high, medium, low -> expected score, expected grade
    [InlineData(0, 0, 0, 1, 97, 'A')]
    [InlineData(0, 0, 1, 0, 92, 'A')]
    [InlineData(0, 0, 1, 1, 89, 'B')]
    [InlineData(0, 1, 0, 0, 80, 'B')]
    [InlineData(0, 0, 2, 3, 75, 'C')]
    [InlineData(0, 0, 3, 2, 70, 'C')]
    [InlineData(0, 0, 3, 3, 67, 'D')]
    [InlineData(1, 0, 0, 0, 60, 'D')]
    [InlineData(1, 0, 0, 1, 57, 'F')]
    [InlineData(0, 2, 1, 0, 52, 'F')]
    public void Score_And_Grade_Follow_The_Published_Weights(
        int critical, int high, int medium, int low, int expectedScore, char expectedGrade)
    {
        var findings = new List<ApiFinding>();
        for (int i = 0; i < critical; i++) findings.Add(Fake("c" + i, FindingSeverity.Critical));
        for (int i = 0; i < high; i++) findings.Add(Fake("h" + i, FindingSeverity.High));
        for (int i = 0; i < medium; i++) findings.Add(Fake("m" + i, FindingSeverity.Medium));
        for (int i = 0; i < low; i++) findings.Add(Fake("l" + i, FindingSeverity.Low));

        var (grade, score) = EndpointAnalyzer.Grade(findings);
        Assert.Equal(expectedScore, score);
        Assert.Equal(expectedGrade, grade);
    }

    [Fact]
    public void Score_Floors_At_Zero()
    {
        var findings = Enumerable.Range(0, 10).Select(i => Fake("c" + i, FindingSeverity.Critical)).ToList();
        var (grade, score) = EndpointAnalyzer.Grade(findings);
        Assert.Equal(0, score);
        Assert.Equal('F', grade);
    }

    [Fact]
    public void Explain_Reports_The_Grade_And_Every_Finding()
    {
        var findings = new[]
        {
            Fake("zeta-low", FindingSeverity.Low),
            Fake("alpha-high", FindingSeverity.High) with
            {
                Detail = "d", Recommendation = "r", Owasp = OwaspApi.SecurityMisconfiguration, Endpoint = "GET /x"
            }
        };

        string text = EndpointAnalyzer.Explain(findings);
        Assert.Contains("grade C (77/100)", text, StringComparison.Ordinal);
        Assert.Contains("alpha-high", text, StringComparison.Ordinal);
        Assert.Contains("zeta-low", text, StringComparison.Ordinal);
        Assert.Contains("GET /x", text, StringComparison.Ordinal);
        Assert.True(text.IndexOf("alpha-high", StringComparison.Ordinal) <
                    text.IndexOf("zeta-low", StringComparison.Ordinal));
    }

    [Fact]
    public void Explain_Sorts_Input_It_Was_Given_Out_Of_Order()
    {
        var unordered = new[]
        {
            Fake("m-second", FindingSeverity.Medium),
            Fake("m-first", FindingSeverity.Medium),
            Fake("crit", FindingSeverity.Critical)
        };
        string text = EndpointAnalyzer.Explain(unordered);
        int crit = text.IndexOf("crit", StringComparison.Ordinal);
        int first = text.IndexOf("m-first", StringComparison.Ordinal);
        int second = text.IndexOf("m-second", StringComparison.Ordinal);
        Assert.True(crit < first && first < second, "Explain must sort by severity then id");
    }

    [Fact]
    public void Explain_Is_Byte_Stable_Across_Calls()
    {
        var findings = new[] { Fake("b", FindingSeverity.Medium), Fake("a", FindingSeverity.Medium) };
        Assert.Equal(EndpointAnalyzer.Explain(findings), EndpointAnalyzer.Explain(findings));
    }

    [Fact]
    public void Explain_With_No_Findings_Does_Not_Claim_The_Endpoint_Is_Secure()
    {
        string text = EndpointAnalyzer.Explain(Array.Empty<ApiFinding>());
        Assert.Contains("grade A (100/100)", text, StringComparison.Ordinal);
        Assert.Contains("not a clean bill of health", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Explain_Uses_Newline_Only_Line_Endings()
    {
        string text = EndpointAnalyzer.Explain(new[] { Fake("x", FindingSeverity.Low) });
        Assert.DoesNotContain("\r", text, StringComparison.Ordinal);
    }
}

public class ApiSecurityAnalyzeTests
{
    private const string UserBody =
        "{\"user_id\":7,\"email\":\"alice@example.com\",\"first_name\":\"Alice\",\"role\":\"admin\"}";

    private static IReadOnlyList<ApiFinding> Run(ApiRequest request, ApiResponse? response = null) =>
        EndpointAnalyzer.Analyze(request, response ?? Hardened(UserBody), Now);

    [Fact]
    public void Unauthenticated_Two_Hundred_With_User_Data_Is_Flagged_As_A_Question()
    {
        var finding = Only(Run(Req()), "unauthenticated-user-data");
        Assert.Equal(FindingSeverity.Low, finding.Severity);
        Assert.Equal(OwaspApi.BrokenFunctionLevelAuth, finding.Owasp);
        Assert.Contains("Verify this endpoint is intended to be public", finding.Detail, StringComparison.Ordinal);
        // It must never assert a vulnerability.
        Assert.Contains("not an assertion", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(ApiAuthKind.Bearer)]
    [InlineData(ApiAuthKind.Basic)]
    [InlineData(ApiAuthKind.ApiKeyHeader)]
    [InlineData(ApiAuthKind.ApiKeyQuery)]
    [InlineData(ApiAuthKind.RawHeader)]
    public void Configured_Auth_Suppresses_The_Finding(ApiAuthKind kind)
    {
        var auth = new ApiAuth
        {
            Kind = kind,
            Token = "t", Username = "u", Password = "p",
            KeyName = "X-Key", KeyValue = "k", RawValue = "Bearer t"
        };
        Assert.DoesNotContain("unauthenticated-user-data", IdsOf(Run(Req(auth: auth))));
    }

    [Fact]
    public void Empty_Auth_Material_Does_Not_Count_As_Authentication()
    {
        var auth = new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "" };
        Assert.Contains("unauthenticated-user-data", IdsOf(Run(Req(auth: auth))));
    }

    [Theory]
    [InlineData("Authorization", "Bearer abc")]
    [InlineData("Cookie", "sid=abc")]
    [InlineData("X-API-Key", "abc")]
    [InlineData("x-auth-token", "abc")]
    [InlineData("X-Session-Id", "abc")]
    public void Auth_Bearing_Headers_Suppress_The_Finding(string name, string value)
    {
        Assert.DoesNotContain("unauthenticated-user-data", IdsOf(Run(Req(headers: H((name, value))))));
    }

    [Fact]
    public void An_Empty_Auth_Header_Value_Does_Not_Count()
    {
        Assert.Contains("unauthenticated-user-data", IdsOf(Run(Req(headers: H(("Authorization", ""))))));
    }

    [Fact]
    public void Disabled_Auth_Header_Is_Not_Counted()
    {
        var request = new ApiRequest
        {
            Url = "https://api.example.com/v1/users",
            Headers = new[] { new ApiKeyValue { Name = "Authorization", Value = "Bearer abc", Enabled = false } }
        };
        Assert.Contains("unauthenticated-user-data", IdsOf(Run(request)));
    }

    [Theory]
    [InlineData("https://api.example.com/v1/users?api_key=abc")]
    [InlineData("https://api.example.com/v1/users?page=1&access_token=abc")]
    [InlineData("https://api.example.com/v1/users?signature=deadbeef")]
    public void Auth_In_The_Url_Query_Suppresses_The_Finding(string url)
    {
        Assert.DoesNotContain("unauthenticated-user-data", IdsOf(Run(Req(url: url))));
    }

    [Fact]
    public void Ordinary_Query_Parameters_Do_Not_Look_Like_Auth()
    {
        Assert.Contains("unauthenticated-user-data",
            IdsOf(Run(Req(url: "https://api.example.com/v1/users?page=2&sort=name"))));
    }

    [Theory]
    [InlineData(201)]
    [InlineData(204)]
    [InlineData(302)]
    [InlineData(401)]
    public void Only_A_Two_Hundred_Triggers_The_Auth_Question(int status)
    {
        Assert.DoesNotContain("unauthenticated-user-data",
            IdsOf(Run(Req(), Hardened(UserBody) with { StatusCode = status })));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"count\":42}")]
    [InlineData("[1,2,3]")]
    [InlineData("   ")]
    public void Non_User_Shaped_Bodies_Do_Not_Trigger_The_Auth_Question(string body)
    {
        Assert.DoesNotContain("unauthenticated-user-data", IdsOf(Run(Req(), Hardened(body))));
    }

    [Fact]
    public void One_Weak_Signal_Is_Not_Enough()
    {
        // A single "role" key is not user data; the check needs corroboration.
        Assert.DoesNotContain("unauthenticated-user-data", IdsOf(Run(Req(), Hardened("{\"role\":\"reader\"}"))));
    }

    [Fact]
    public void Every_Finding_Carries_The_Endpoint()
    {
        var findings = Run(Req(method: "get"));
        Assert.NotEmpty(findings);
        foreach (var finding in findings)
        {
            Assert.StartsWith("GET ", finding.Endpoint, StringComparison.Ordinal);
            Assert.Contains("api.example.com", finding.Endpoint, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Analyze_Merges_Every_Category_And_Stays_Ordered()
    {
        var response = Resp(
            contentType: "text/html",
            body: "{\"email\":\"alice@example.com\",\"user_id\":1}",
            headers: H(
                ("Server", "nginx/1.18.0"),
                ("Set-Cookie", "session=abc; Path=/"),
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"))) with
        {
            Tls = Cert(notAfter: Now.AddDays(-1))
        };

        var findings = EndpointAnalyzer.Analyze(Req(), response, Now);
        var ids = IdsOf(findings);

        Assert.Contains("missing-hsts", ids);                      // headers
        Assert.Contains("cors-wildcard-with-credentials", ids);    // cors
        Assert.Contains("cookie-missing-secure", ids);             // cookies
        Assert.Contains("body-pii-exposed", ids);                  // body
        Assert.Contains("tls-cert-expired", ids);                  // tls
        Assert.Contains("unauthenticated-user-data", ids);         // the auth question

        Ordered(findings);
        Assert.Equal(FindingSeverity.Critical, findings[0].Severity);
        Assert.Equal('F', EndpointAnalyzer.Grade(findings).Grade);
    }

    [Fact]
    public void Analyze_Is_Deterministic()
    {
        var request = Req();
        var response = Resp(body: UserBody, headers: H(("Set-Cookie", "sid=a")));

        Assert.Equal(
            EndpointAnalyzer.Explain(EndpointAnalyzer.Analyze(request, response, Now)),
            EndpointAnalyzer.Explain(EndpointAnalyzer.Analyze(request, response, Now)));
    }

    [Fact]
    public void Analyze_Uses_The_Injected_Time_Not_The_Wall_Clock()
    {
        var response = Hardened() with { Tls = Cert(notAfter: Now.AddDays(10)) };
        var request = Req();

        Assert.Contains("tls-cert-expiring", IdsOf(EndpointAnalyzer.Analyze(request, response, Now)));
        Assert.Contains("tls-cert-expired", IdsOf(EndpointAnalyzer.Analyze(request, response, Now.AddDays(20))));
        Assert.DoesNotContain("tls-cert-expiring", IdsOf(EndpointAnalyzer.Analyze(request, response, Now.AddDays(-60))));
    }

    [Fact]
    public void Tls_Is_Skipped_When_No_Url_Can_Be_Resolved()
    {
        var response = new ApiResponse { StatusCode = 200, BodyText = "{}", Tls = Cert(notAfter: Now.AddDays(-1)) };
        var findings = EndpointAnalyzer.Analyze(new ApiRequest { Url = "" }, response, Now);
        Assert.DoesNotContain("tls-cert-expired", IdsOf(findings));
        Ordered(findings);
    }

    [Fact]
    public void Request_Origin_Is_Passed_Through_To_The_Cors_Check()
    {
        var response = Hardened(extra: H(
            ("Access-Control-Allow-Origin", "https://evil.test"),
            ("Access-Control-Allow-Credentials", "true"),
            ("Vary", "Origin")));

        Assert.Contains("cors-reflected-origin",
            IdsOf(EndpointAnalyzer.Analyze(Req(headers: H(("Origin", "https://evil.test"))), response, Now)));
    }

    [Fact]
    public void A_Well_Configured_Json_Endpoint_Grades_Well()
    {
        // The hardening the analyzer asks for must actually be reachable, or the tool is
        // just a machine for producing an F. Secret-scanner findings are excluded here so
        // this case stays decoupled from that subsystem's rule set.
        var response = Resp(body: "{\"count\":3}", headers: H(
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Cache-Control", "no-store"))) with
        {
            Tls = Cert()
        };

        var findings = EndpointAnalyzer
            .Analyze(Req(headers: H(("Authorization", "Bearer abc"))), response, Now)
            .Where(f => !f.Id.StartsWith("body-secret", StringComparison.Ordinal))
            .ToList();

        Assert.Empty(findings);
        Assert.Equal('A', EndpointAnalyzer.Grade(findings).Grade);
    }
}
