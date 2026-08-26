using System.Net;
using System.Net.Sockets;
using System.Text;
using BruceEDR.Api;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// End-to-end proof that API Studio works over a real socket, not just against canned
/// responses. Every other API test injects a fake client; these drive
/// <see cref="ApiClient"/> itself through a loopback server.
///
/// The server is a raw <see cref="TcpListener"/> speaking minimal HTTP/1.1 rather than
/// <c>HttpListener</c>, because HttpListener needs a URL ACL reservation (an elevated
/// <c>netsh http add urlacl</c>) for any prefix a normal user has not been granted. A
/// socket on an ephemeral loopback port always works, which keeps these tests runnable
/// in CI and on a developer machine with no setup at all.
/// </summary>
public sealed class ApiEndToEndTests
{
    // ------------------------------------------------------------- test server

    /// <summary>One canned reply, returned for every request the server receives.</summary>
    private sealed record Reply(int Status, string ReasonPhrase, string Body, params string[] Headers);

    private sealed class LoopbackServer : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;
        private readonly Func<string, Reply> _responder;
        private readonly List<string> _requests = new();
        private readonly object _gate = new();

        public LoopbackServer(Func<string, Reply> responder)
        {
            _responder = responder;
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _loop = Task.Run(AcceptLoop);
        }

        public int Port { get; }
        public string Origin => "http://127.0.0.1:" + Port;

        /// <summary>Raw request text of everything the server received, in arrival order.</summary>
        public IReadOnlyList<string> Requests { get { lock (_gate) return _requests.ToArray(); } }

        private async Task AcceptLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_cts.Token); }
                catch { return; }

                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try { await ServeAsync(client); } catch { /* a torn-down client is not a test failure */ }
                    }
                });
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using var stream = client.GetStream();
            string request = await ReadRequestAsync(stream);
            lock (_gate) _requests.Add(request);

            var reply = _responder(request);
            var body = Encoding.UTF8.GetBytes(reply.Body);

            var sb = new StringBuilder();
            sb.Append("HTTP/1.1 ").Append(reply.Status).Append(' ').Append(reply.ReasonPhrase).Append("\r\n");
            foreach (var h in reply.Headers) sb.Append(h).Append("\r\n");
            sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
            sb.Append("Connection: close\r\n\r\n");

            var head = Encoding.ASCII.GetBytes(sb.ToString());
            await stream.WriteAsync(head);
            await stream.WriteAsync(body);
            await stream.FlushAsync();
        }

        /// <summary>
        /// Reads headers, then exactly Content-Length bytes of body. Enough HTTP to be a
        /// faithful peer for the client under test; deliberately not a general server.
        /// </summary>
        private static async Task<string> ReadRequestAsync(NetworkStream stream)
        {
            var buffer = new byte[16384];
            int total = 0, headerEnd = -1;

            while (total < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total));
                if (read == 0) break;
                total += read;
                headerEnd = IndexOfDoubleCrlf(buffer, total);
                if (headerEnd >= 0) break;
            }
            if (headerEnd < 0) return Encoding.UTF8.GetString(buffer, 0, total);

            string headers = Encoding.UTF8.GetString(buffer, 0, headerEnd);
            int contentLength = ContentLength(headers);
            int bodyStart = headerEnd + 4;
            while (total - bodyStart < contentLength && total < buffer.Length)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total));
                if (read == 0) break;
                total += read;
            }
            return Encoding.UTF8.GetString(buffer, 0, total);
        }

        private static int IndexOfDoubleCrlf(byte[] b, int length)
        {
            for (int i = 0; i + 3 < length; i++)
                if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i;
            return -1;
        }

        private static int ContentLength(string headers)
        {
            foreach (var line in headers.Split("\r\n"))
            {
                if (!line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase)) continue;
                if (int.TryParse(line[15..].Trim(), out int n)) return n;
            }
            return 0;
        }

        public void Dispose()
        {
            try { _cts.Cancel(); } catch { }
            try { _listener.Stop(); } catch { }
            try { _loop.Wait(TimeSpan.FromSeconds(2)); } catch { }
            _cts.Dispose();
        }
    }

    private static ApiSafetyPolicy PolicyFor(LoopbackServer server, bool mutating = false) => new()
    {
        AllowedHosts = new[] { "127.0.0.1" },
        AllowInsecureHttp = true,
        AllowMutatingMethods = mutating,
        MaxRequestsPerSecond = 1000,
        MaxResponseBytes = 1024 * 1024
    };

    private static readonly Dictionary<string, string> NoVars = new(StringComparer.OrdinalIgnoreCase);

    private static Reply Json(string body, params string[] extraHeaders)
        => new(200, "OK", body, extraHeaders.Append("Content-Type: application/json").ToArray());

    // ------------------------------------------------------------------- tests

    [Fact]
    public async Task Get_Over_A_Real_Socket_Returns_Status_Headers_And_Body()
    {
        using var server = new LoopbackServer(_ => Json("{\"ok\":true,\"id\":42}", "X-Trace: abc123"));
        using var client = new ApiClient(PolicyFor(server));

        var response = await client.SendAsync(
            new ApiRequest { Method = "GET", Url = server.Origin + "/v1/health" }, NoVars);

        Assert.True(response.Completed, response.Error);
        Assert.Equal(200, response.StatusCode);
        Assert.True(response.IsSuccess);
        Assert.Contains("\"id\":42", response.BodyText);
        Assert.Equal("abc123", response.Header("X-Trace"));
        Assert.Contains("application/json", response.ContentType);
        Assert.True(response.Elapsed > TimeSpan.Zero);

        Assert.Contains("GET /v1/health HTTP/1.1", server.Requests[0]);
    }

    [Fact]
    public async Task Query_Parameters_And_Template_Variables_Reach_The_Wire()
    {
        using var server = new LoopbackServer(_ => Json("{}"));
        using var client = new ApiClient(PolicyFor(server));

        var request = new ApiRequest
        {
            Method = "GET",
            Url = server.Origin + "/search?existing=keep",
            Query = new[]
            {
                ApiKeyValue.Of("q", "a b&c"),
                ApiKeyValue.Of("tenant", "{{tenant}}"),
                new ApiKeyValue { Name = "off", Value = "no", Enabled = false }
            }
        };
        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["tenant"] = "acme" };

        var response = await client.SendAsync(request, vars);
        Assert.True(response.Completed, response.Error);

        string raw = server.Requests[0];
        Assert.Contains("existing=keep", raw);          // pre-existing query survives
        Assert.Contains("tenant=acme", raw);            // template variable substituted
        Assert.Contains("q=a%20b%26c", raw);            // reserved characters encoded
        Assert.DoesNotContain("off=no", raw);           // disabled parameter omitted
    }

    [Fact]
    public async Task Bearer_Auth_And_Json_Body_Are_Sent_On_A_Post()
    {
        using var server = new LoopbackServer(_ => new Reply(201, "Created", "{\"created\":true}",
            "Content-Type: application/json"));
        using var client = new ApiClient(PolicyFor(server, mutating: true));

        var response = await client.SendAsync(new ApiRequest
        {
            Method = "POST",
            Url = server.Origin + "/v1/items",
            Auth = new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "tok-{{suffix}}" },
            Body = ApiBody.Json("{\"name\":\"{{name}}\"}")
        }, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["suffix"] = "xyz",
            ["name"] = "widget"
        });

        Assert.True(response.Completed, response.Error);
        Assert.Equal(201, response.StatusCode);

        string raw = server.Requests[0];
        Assert.Contains("POST /v1/items HTTP/1.1", raw);
        Assert.Contains("Authorization: Bearer tok-xyz", raw);
        Assert.Contains("application/json", raw);
        Assert.Contains("{\"name\":\"widget\"}", raw);
    }

    [Fact]
    public async Task A_Mutating_Method_Is_Refused_Before_Any_Socket_Is_Opened()
    {
        using var server = new LoopbackServer(_ => Json("{}"));
        using var client = new ApiClient(PolicyFor(server, mutating: false));

        var response = await client.SendAsync(
            new ApiRequest { Method = "DELETE", Url = server.Origin + "/v1/items/1" }, NoVars);

        Assert.False(response.Completed);
        Assert.Contains("safety policy", response.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, response.StatusCode);
        Assert.Empty(server.Requests);      // the refusal must happen before we connect
    }

    [Fact]
    public async Task A_Host_Outside_The_Allowlist_Is_Refused()
    {
        using var server = new LoopbackServer(_ => Json("{}"));
        var policy = PolicyFor(server) with { AllowedHosts = new[] { "example.test" } };
        using var client = new ApiClient(policy);

        var response = await client.SendAsync(
            new ApiRequest { Method = "GET", Url = server.Origin + "/" }, NoVars);

        Assert.False(response.Completed);
        Assert.Contains("allowlist", response.Error, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(server.Requests);
    }

    [Fact]
    public async Task A_Body_Beyond_The_Cap_Is_Truncated_Not_Buffered_Whole()
    {
        string big = new('x', 200_000);
        using var server = new LoopbackServer(_ => Json("\"" + big + "\""));
        var policy = PolicyFor(server) with { MaxResponseBytes = 4096 };
        using var client = new ApiClient(policy);

        var response = await client.SendAsync(
            new ApiRequest { Method = "GET", Url = server.Origin + "/big" }, NoVars);

        Assert.True(response.Completed, response.Error);
        Assert.True(response.BodyTruncated);
        Assert.True(response.BodyText.Length <= 4096,
            $"expected the body to stop at the cap, got {response.BodyText.Length} chars");
    }

    [Fact]
    public async Task A_Redirect_Chain_Is_Recorded_When_Following_Is_Enabled()
    {
        LoopbackServer? server = null;
        server = new LoopbackServer(request =>
            request.Contains("GET /start ", StringComparison.Ordinal)
                ? new Reply(302, "Found", "", "Location: " + server!.Origin + "/final")
                : Json("{\"final\":true}"));

        using (server)
        using (var client = new ApiClient(PolicyFor(server)))
        {
            var response = await client.SendAsync(
                new ApiRequest { Method = "GET", Url = server.Origin + "/start", FollowRedirects = true }, NoVars);

            Assert.True(response.Completed, response.Error);
            Assert.Equal(200, response.StatusCode);
            Assert.Contains("\"final\":true", response.BodyText);
            Assert.NotEmpty(response.RedirectChain);
            Assert.Contains(response.RedirectChain, u => u.Contains("/start", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task Redirects_Are_Not_Followed_When_Disabled()
    {
        using var server = new LoopbackServer(_ =>
            new Reply(302, "Found", "", "Location: /somewhere-else"));
        using var client = new ApiClient(PolicyFor(server));

        var response = await client.SendAsync(
            new ApiRequest { Method = "GET", Url = server.Origin + "/start", FollowRedirects = false }, NoVars);

        Assert.True(response.Completed, response.Error);
        Assert.Equal(302, response.StatusCode);
    }

    [Fact]
    public async Task A_Full_Collection_Run_Asserts_Captures_And_Chains_Requests()
    {
        // Request 1 logs in and returns a token; request 2 must send that token back.
        using var server = new LoopbackServer(request =>
            request.Contains("POST /login ", StringComparison.Ordinal)
                ? Json("{\"data\":{\"token\":\"s3cr3t-token\"}}")
                : Json("{\"me\":\"analyst\"}"));

        var policy = PolicyFor(server, mutating: true);
        using var client = new ApiClient(policy);

        var collection = new ApiCollection
        {
            Name = "chained",
            Variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["base"] = server.Origin
            },
            Root = new ApiFolder
            {
                Requests = new[]
                {
                    new ApiRequest
                    {
                        Name = "login",
                        Method = "POST",
                        Url = "{{base}}/login",
                        Body = ApiBody.Json("{\"user\":\"a\"}"),
                        Assertions = new[] { ApiAssertion.Status(200) },
                        Captures = new[] { new ApiCapture { Variable = "token", JsonPath = "data.token" } }
                    },
                    new ApiRequest
                    {
                        Name = "whoami",
                        Method = "GET",
                        Url = "{{base}}/me",
                        Auth = new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "{{token}}" },
                        Assertions = new[]
                        {
                            ApiAssertion.Status(200),
                            new ApiAssertion { Kind = AssertionKind.JsonPathEquals, Target = "me", Expected = "analyst" }
                        }
                    }
                }
            }
        };

        var result = await new CollectionRunner(client).RunAsync(
            collection, new ApiEnvironment { Name = "test" }, policy);

        Assert.Equal(2, result.Total);
        Assert.True(result.Success,
            "failures: " + string.Join("; ", result.Executions
                .SelectMany(e => e.Assertions.Where(a => !a.Passed).Select(a => a.Name + ": " + a.Detail))));
        Assert.Equal(0, result.AssertionsFailed);

        // The capture from request 1 must have travelled to request 2's Authorization header.
        Assert.Equal("s3cr3t-token", result.Executions[0].Captured["token"]);
        Assert.Contains(server.Requests, r => r.Contains("Authorization: Bearer s3cr3t-token", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_Failing_Assertion_Is_Reported_Without_Aborting_The_Run()
    {
        using var server = new LoopbackServer(_ => new Reply(500, "Internal Server Error",
            "boom", "Content-Type: text/plain"));
        var policy = PolicyFor(server);
        using var client = new ApiClient(policy);

        var collection = new ApiCollection
        {
            Name = "failing",
            Root = new ApiFolder
            {
                Requests = new[]
                {
                    new ApiRequest
                    {
                        Name = "expects 200",
                        Url = server.Origin + "/a",
                        Assertions = new[] { ApiAssertion.Status(200) }
                    },
                    new ApiRequest
                    {
                        Name = "expects 500",
                        Url = server.Origin + "/b",
                        Assertions = new[] { ApiAssertion.Status(500) }
                    }
                }
            }
        };

        var result = await new CollectionRunner(client).RunAsync(
            collection, new ApiEnvironment { Name = "test" }, policy);

        Assert.Equal(2, result.Total);
        Assert.Equal(1, result.Failed);
        Assert.False(result.Executions[0].Passed);
        Assert.True(result.Executions[1].Passed);      // the run continued past the failure
    }

    [Fact]
    public async Task The_Security_Analyzer_Grades_A_Real_Response()
    {
        // A response that is missing every hardening header and leaks a server banner.
        using var server = new LoopbackServer(_ => Json("{\"users\":[]}", "Server: TestServer/9.9.9"));
        var policy = PolicyFor(server);
        using var client = new ApiClient(policy);

        var request = new ApiRequest { Method = "GET", Url = server.Origin + "/v1/users" };
        var response = await client.SendAsync(request, NoVars);
        Assert.True(response.Completed, response.Error);

        var findings = EndpointAnalyzer.Analyze(request, response, DateTime.UtcNow);
        Assert.NotEmpty(findings);
        Assert.Contains(findings, f => f.Id.Contains("nosniff", StringComparison.OrdinalIgnoreCase)
                                    || f.Id.Contains("content-type-options", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(findings, f => f.Title.Contains("Server", StringComparison.OrdinalIgnoreCase)
                                    || f.Evidence.Contains("TestServer", StringComparison.OrdinalIgnoreCase));

        var (grade, score) = EndpointAnalyzer.Grade(findings);
        Assert.InRange(score, 0, 100);
        Assert.Contains(grade, new[] { 'A', 'B', 'C', 'D', 'F' });

        // Findings must be ordered most-severe first so a report is stable and scannable.
        for (int i = 1; i < findings.Count; i++)
            Assert.True(findings[i - 1].Severity >= findings[i].Severity,
                "findings are not sorted by descending severity");
    }

    [Fact]
    public async Task A_Leaked_Credential_In_A_Response_Body_Is_Reported_Redacted()
    {
        const string leaked = "AKIA" + "IOSFODNN7EXAMPLE";
        using var server = new LoopbackServer(_ => Json("{\"awsKey\":\"" + leaked + "\"}"));
        var policy = PolicyFor(server);
        using var client = new ApiClient(policy);

        var request = new ApiRequest { Method = "GET", Url = server.Origin + "/v1/config" };
        var response = await client.SendAsync(request, NoVars);

        var findings = EndpointAnalyzer.Analyze(request, response, DateTime.UtcNow);
        var secret = findings.FirstOrDefault(f => f.Severity >= FindingSeverity.High &&
            (f.Id.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
             f.Title.Contains("credential", StringComparison.OrdinalIgnoreCase)));

        Assert.NotNull(secret);
        // The whole point of redaction: the finding must never carry the live credential.
        Assert.DoesNotContain(leaked, secret!.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain(leaked, secret.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_Render_From_A_Real_Run_And_Never_Leak_The_Authorization_Header()
    {
        using var server = new LoopbackServer(_ => Json("{\"ok\":true}"));
        var policy = PolicyFor(server);
        using var client = new ApiClient(policy);

        var collection = new ApiCollection
        {
            Name = "report source",
            Root = new ApiFolder
            {
                Requests = new[]
                {
                    new ApiRequest
                    {
                        Name = "<script>alert(1)</script>",     // must not break the HTML report
                        Url = server.Origin + "/x",
                        Headers = new[] { ApiKeyValue.Of("Authorization", "Bearer super-secret-value") },
                        Assertions = new[] { ApiAssertion.Status(200) }
                    }
                }
            }
        };

        var result = await new CollectionRunner(client).RunAsync(
            collection, new ApiEnvironment { Name = "test" }, policy);
        Assert.True(result.Success);

        string json = ApiReports.ToJson(result);
        string junit = ApiReports.ToJUnitXml(result);
        string html = ApiReports.ToHtml(result);
        string md = ApiReports.ToMarkdown(result);
        string text = ApiReports.ToConsoleText(result);

        foreach (var report in new[] { json, junit, html, md, text })
            Assert.DoesNotContain("super-secret-value", report, StringComparison.Ordinal);

        // JUnit must be parseable, and the HTML must not contain a live script element.
        System.Xml.Linq.XDocument.Parse(junit);
        Assert.DoesNotContain("<script>alert(1)</script>", html, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_Request_To_A_Dead_Port_Fails_As_An_Error_Not_An_Exception()
    {
        // Bind then immediately release a port so it is almost certainly closed.
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int deadPort = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        var policy = new ApiSafetyPolicy
        {
            AllowedHosts = new[] { "127.0.0.1" },
            AllowInsecureHttp = true,
            MaxResponseBytes = 65536
        };
        using var client = new ApiClient(policy);

        var response = await client.SendAsync(
            new ApiRequest { Method = "GET", Url = $"http://127.0.0.1:{deadPort}/", TimeoutSeconds = 5 }, NoVars);

        Assert.False(response.Completed);
        Assert.False(string.IsNullOrWhiteSpace(response.Error));
    }

    [Fact]
    public async Task A_Malformed_Url_Fails_Cleanly()
    {
        using var client = new ApiClient(ApiSafetyPolicy.Loopback);
        var response = await client.SendAsync(
            new ApiRequest { Method = "GET", Url = "not a url at all" }, NoVars);

        Assert.False(response.Completed);
        Assert.False(string.IsNullOrWhiteSpace(response.Error));
    }
}
