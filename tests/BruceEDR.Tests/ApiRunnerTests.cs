using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using BruceEDR.Api;
using BruceEDR.Core;
using Xunit;

namespace BruceEDR.Tests;

// ---------------------------------------------------------------------------
// Tests for the API Studio execution half: the HTTP client's pre-flight logic,
// the collection runner, and the report renderers.
//
// Nothing here opens a socket. Every ApiClient case is one the client answers
// before a connection is attempted (policy refusal, bad URL, bad header, bad
// body), and every runner case is driven by RecordingApiClient. File IO goes to
// a unique directory under the temp path and is deleted in Dispose.
// ---------------------------------------------------------------------------

/// <summary>Unique scratch directory for the handful of file-backed body cases.</summary>
internal sealed class ApiRunnerTempDir : IDisposable
{
    public string Root { get; }

    public ApiRunnerTempDir()
    {
        Root = Path.Combine(Path.GetTempPath(), "psapi-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(Root);
    }

    public string Write(string name, byte[] bytes)
    {
        string path = Path.Combine(Root, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public void Dispose()
    {
        try { Directory.Delete(Root, recursive: true); } catch { /* best effort */ }
    }
}

internal static class ApiRunnerFixtures
{
    public static readonly IReadOnlyDictionary<string, string> NoVars =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>Refuses everything: the safe backstop for client tests, so a bug cannot reach the network.</summary>
    public static ApiSafetyPolicy DenyAll => new() { AllowedHosts = Array.Empty<string>() };

    /// <summary>Permits everything and disables throttling; used for runner tests with a canned client.</summary>
    public static ApiSafetyPolicy Open => new()
    {
        AllowedHosts = new[] { "*" },
        AllowMutatingMethods = true,
        AllowInsecureHttp = true,
        MaxRequestsPerSecond = 0
    };

    public static ApiCollection Collection(params ApiRequest[] requests) =>
        new() { Name = "demo", Root = new ApiFolder { Requests = requests } };

    public static ApiEnvironment Env(params (string Name, string Value)[] variables)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (n, v) in variables) dict[n] = v;
        return new ApiEnvironment { Name = "dev", Variables = dict };
    }

    public static ApiResponse Ok(int status = 200, params ApiKeyValue[] headers) => new()
    {
        StatusCode = status,
        ReasonPhrase = "OK",
        Headers = headers,
        BodyText = "{}",
        BodyBytes = 2,
        Elapsed = TimeSpan.FromMilliseconds(12),
        FinalUrl = "https://api.example.com/",
        StartedUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
    };
}

/// <summary>Collects progress synchronously; <see cref="Progress{T}"/> marshals through the thread pool and would race.</summary>
internal sealed class ApiRunnerProgressSpy : IProgress<ApiExecution>
{
    private readonly List<ApiExecution> _items = new();
    private readonly bool _throw;

    public ApiRunnerProgressSpy(bool throwOnReport = false) => _throw = throwOnReport;

    public IReadOnlyList<ApiExecution> Items => _items;

    public void Report(ApiExecution value)
    {
        _items.Add(value);
        if (_throw) throw new InvalidOperationException("progress handler blew up");
    }
}

// ============================================================== URL building

public class ApiRunnerUriTests
{
    private static ApiRequest Req(string url, params ApiKeyValue[] query) =>
        new() { Url = url, Query = query };

    [Fact]
    public void Appends_Query_Parameters_When_Url_Has_None()
    {
        Assert.True(ApiClient.TryBuildRequestUri(Req("https://h.example/p", ApiKeyValue.Of("a", "1")), out var uri, out _));
        Assert.Equal("https://h.example/p?a=1", uri!.AbsoluteUri);
    }

    [Fact]
    public void Preserves_Existing_Query_And_Joins_With_Ampersand()
    {
        Assert.True(ApiClient.TryBuildRequestUri(Req("https://h.example/p?x=9", ApiKeyValue.Of("a", "1")), out var uri, out _));
        Assert.Equal("https://h.example/p?x=9&a=1", uri!.AbsoluteUri);
    }

    [Fact]
    public void Does_Not_Emit_Empty_Pair_When_Url_Ends_With_Question_Mark()
    {
        Assert.True(ApiClient.TryBuildRequestUri(Req("https://h.example/p?", ApiKeyValue.Of("a", "1")), out var uri, out _));
        Assert.DoesNotContain("?&", uri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.Contains("a=1", uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void Url_Encodes_Parameter_Names_And_Values()
    {
        Assert.True(ApiClient.TryBuildRequestUri(
            Req("https://h.example/p", ApiKeyValue.Of("a b", "c&d=e")), out var uri, out _));
        Assert.Contains("a%20b=c%26d%3De", uri!.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void Skips_Disabled_Query_Entries()
    {
        var request = Req("https://h.example/p",
            new ApiKeyValue { Name = "keep", Value = "1" },
            new ApiKeyValue { Name = "drop", Value = "2", Enabled = false });
        Assert.True(ApiClient.TryBuildRequestUri(request, out var uri, out _));
        Assert.Contains("keep=1", uri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.DoesNotContain("drop", uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void ApiKeyQuery_Auth_Becomes_A_Query_Parameter()
    {
        var request = new ApiRequest
        {
            Url = "https://h.example/p",
            Auth = new ApiAuth { Kind = ApiAuthKind.ApiKeyQuery, KeyName = "api_key", KeyValue = "s3cr3t" }
        };
        Assert.True(ApiClient.TryBuildRequestUri(request, out var uri, out _));
        Assert.Contains("api_key=s3cr3t", uri!.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void ApiKeyQuery_With_Empty_Name_Adds_Nothing()
    {
        var request = new ApiRequest
        {
            Url = "https://h.example/p",
            Auth = new ApiAuth { Kind = ApiAuthKind.ApiKeyQuery, KeyName = "", KeyValue = "s3cr3t" }
        };
        Assert.True(ApiClient.TryBuildRequestUri(request, out var uri, out _));
        Assert.Equal("https://h.example/p", uri!.AbsoluteUri);
        Assert.DoesNotContain("s3cr3t", uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void Query_Is_Inserted_Before_The_Fragment()
    {
        Assert.True(ApiClient.TryBuildRequestUri(Req("https://h.example/p#frag", ApiKeyValue.Of("a", "1")), out var uri, out _));
        Assert.Equal("https://h.example/p?a=1#frag", uri!.AbsoluteUri);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_Url_Is_Rejected(string url)
    {
        Assert.False(ApiClient.TryBuildRequestUri(Req(url), out _, out string error));
        Assert.Contains("no URL", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/relative/path")]
    [InlineData("not a url at all")]
    public void Non_Absolute_Url_Is_Rejected(string url)
    {
        Assert.False(ApiClient.TryBuildRequestUri(Req(url), out _, out string error));
        Assert.Contains("invalid URL", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("file:///C:/windows/win.ini")]
    [InlineData("ftp://h.example/x")]
    public void Non_Http_Schemes_Are_Rejected(string url)
    {
        Assert.False(ApiClient.TryBuildRequestUri(Req(url), out _, out string error));
        Assert.Contains("scheme", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Control_Characters_In_Url_Are_Rejected()
    {
        Assert.False(ApiClient.TryBuildRequestUri(Req("https://h.example/p\r\nX-Evil: 1"), out _, out string error));
        Assert.Contains("control characters", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(301, true)]
    [InlineData(302, true)]
    [InlineData(303, true)]
    [InlineData(307, true)]
    [InlineData(308, true)]
    [InlineData(200, false)]
    [InlineData(304, false)]
    [InlineData(404, false)]
    public void IsRedirect_Matches_Only_Followable_Codes(int status, bool expected)
        => Assert.Equal(expected, ApiClient.IsRedirect(status));

    [Fact]
    public void Redirect_303_Downgrades_To_Get_And_Drops_Body()
    {
        var (method, sendBody) = ApiClient.RedirectMethod("POST", 303, true);
        Assert.Equal("GET", method);
        Assert.False(sendBody);
    }

    [Fact]
    public void Redirect_302_Downgrades_Post_But_Keeps_Get()
    {
        Assert.Equal("GET", ApiClient.RedirectMethod("POST", 302, true).Method);
        Assert.Equal("GET", ApiClient.RedirectMethod("GET", 302, false).Method);
    }

    [Fact]
    public void Redirect_307_Preserves_Method_And_Body()
    {
        var (method, sendBody) = ApiClient.RedirectMethod("POST", 307, true);
        Assert.Equal("POST", method);
        Assert.True(sendBody);
    }

    [Theory]
    [InlineData("get", "GET")]
    [InlineData(" PosT ", "POST")]
    [InlineData("", "GET")]
    public void Method_Is_Normalized(string input, string expected)
    {
        Assert.True(ApiClient.TryNormalizeMethod(input, out string normalized, out _));
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("GE T")]
    [InlineData("GET\r\nHost: evil")]
    [InlineData("P0ST")]
    public void Malformed_Methods_Are_Rejected(string input)
        => Assert.False(ApiClient.TryNormalizeMethod(input, out _, out _));
}

// ============================================================ header hygiene

public class ApiRunnerHeaderValidationTests
{
    [Fact]
    public void Normal_Headers_Pass()
    {
        var headers = new[] { ApiKeyValue.Of("Accept", "application/json"), ApiKeyValue.Of("X-Trace", "abc-123") };
        Assert.True(ApiClient.ValidateHeaders(headers, out _));
    }

    [Fact]
    public void Crlf_In_Value_Is_Rejected_So_A_Template_Cannot_Split_The_Request()
    {
        var headers = new[] { ApiKeyValue.Of("X-Thing", "ok\r\nX-Injected: yes") };
        Assert.False(ApiClient.ValidateHeaders(headers, out string error));
        Assert.Contains("control characters", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("X-Bad\r\nEvil")]
    [InlineData("X Bad")]
    [InlineData("X-Bad:")]
    public void Malformed_Header_Names_Are_Rejected(string name)
    {
        Assert.False(ApiClient.ValidateHeaders(new[] { ApiKeyValue.Of(name, "v") }, out _));
    }

    [Fact]
    public void Empty_Header_Name_Is_Rejected()
    {
        Assert.False(ApiClient.ValidateHeaders(new[] { ApiKeyValue.Of("", "v") }, out _));
    }

    [Fact]
    public void Disabled_Headers_Are_Not_Validated_Because_They_Are_Never_Sent()
    {
        var headers = new[] { new ApiKeyValue { Name = "X-Bad", Value = "a\r\nb", Enabled = false } };
        Assert.True(ApiClient.ValidateHeaders(headers, out _));
    }
}

// ================================================================ body build

public class ApiRunnerBodyTests
{
    [Fact]
    public void None_Produces_No_Payload()
    {
        Assert.True(ApiClient.TryBuildBody(new ApiRequest(), "b", out var payload, out string contentType, out _));
        Assert.Null(payload);
        Assert.Equal("", contentType);
    }

    [Fact]
    public void Json_Body_Uses_Application_Json()
    {
        var request = new ApiRequest { Body = ApiBody.Json("{\"a\":1}") };
        Assert.True(ApiClient.TryBuildBody(request, "b", out var payload, out string contentType, out _));
        Assert.Equal("application/json", contentType);
        Assert.Equal("{\"a\":1}", Encoding.UTF8.GetString(payload!));
    }

    [Fact]
    public void Raw_Body_Honours_An_Explicit_Content_Type()
    {
        var request = new ApiRequest
        {
            Body = new ApiBody { Kind = ApiBodyKind.Raw, Text = "<x/>", ContentType = "application/xml" }
        };
        Assert.True(ApiClient.TryBuildBody(request, "b", out _, out string contentType, out _));
        Assert.Equal("application/xml", contentType);
    }

    [Fact]
    public void UrlEncoded_Escapes_And_Skips_Disabled_Fields()
    {
        var request = new ApiRequest
        {
            Body = new ApiBody
            {
                Kind = ApiBodyKind.UrlEncoded,
                Form = new[]
                {
                    ApiKeyValue.Of("q", "a b&c"),
                    new ApiKeyValue { Name = "skip", Value = "1", Enabled = false }
                }
            }
        };
        Assert.True(ApiClient.TryBuildBody(request, "b", out var payload, out string contentType, out _));
        string text = Encoding.UTF8.GetString(payload!);
        Assert.Equal("application/x-www-form-urlencoded", contentType);
        Assert.Equal("q=a%20b%26c", text);
        Assert.DoesNotContain("skip", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Multipart_Uses_The_Supplied_Boundary_In_Body_And_Content_Type()
    {
        var request = new ApiRequest
        {
            Body = new ApiBody { Kind = ApiBodyKind.Multipart, Form = new[] { ApiKeyValue.Of("field", "value") } }
        };
        Assert.True(ApiClient.TryBuildBody(request, "BOUND", out var payload, out string contentType, out _));
        string text = Encoding.UTF8.GetString(payload!);
        Assert.Contains("boundary=BOUND", contentType, StringComparison.Ordinal);
        Assert.Contains("--BOUND\r\n", text, StringComparison.Ordinal);
        Assert.Contains("name=\"field\"", text, StringComparison.Ordinal);
        Assert.EndsWith("--BOUND--\r\n", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Multipart_Field_Name_Cannot_Inject_A_Header()
    {
        var request = new ApiRequest
        {
            Body = new ApiBody
            {
                Kind = ApiBodyKind.Multipart,
                Form = new[] { ApiKeyValue.Of("a\r\nX-Injected: 1", "v") }
            }
        };
        Assert.True(ApiClient.TryBuildBody(request, "BOUND", out var payload, out _, out _));
        string text = Encoding.UTF8.GetString(payload!);
        Assert.DoesNotContain("\r\nX-Injected", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Multipart_Field_Name_Quotes_Are_Neutralised()
    {
        var request = new ApiRequest
        {
            Body = new ApiBody { Kind = ApiBodyKind.Multipart, Form = new[] { ApiKeyValue.Of("a\"b\\c", "v") } }
        };
        Assert.True(ApiClient.TryBuildBody(request, "BOUND", out var payload, out _, out _));
        Assert.Contains("name=\"a_b_c\"", Encoding.UTF8.GetString(payload!), StringComparison.Ordinal);
    }

    [Fact]
    public void Multipart_Content_Type_Keeps_An_Explicit_Boundary()
    {
        var body = new ApiBody { Kind = ApiBodyKind.Multipart, ContentType = "multipart/form-data; boundary=XYZ" };
        Assert.Equal("multipart/form-data; boundary=XYZ", ApiClient.MultipartContentType(body, "BOUND"));
    }

    [Fact]
    public void File_Body_Reads_The_File()
    {
        using var temp = new ApiRunnerTempDir();
        string path = temp.Write("payload.bin", new byte[] { 1, 2, 3, 4 });

        var request = new ApiRequest { Body = new ApiBody { Kind = ApiBodyKind.File, FilePath = path } };
        Assert.True(ApiClient.TryBuildBody(request, "b", out var payload, out string contentType, out _));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, payload);
        Assert.Equal("application/octet-stream", contentType);
    }

    [Fact]
    public void Missing_File_Body_Is_An_Error_Not_An_Exception()
    {
        using var temp = new ApiRunnerTempDir();
        string path = Path.Combine(temp.Root, "does-not-exist.bin");

        var request = new ApiRequest { Body = new ApiBody { Kind = ApiBodyKind.File, FilePath = path } };
        Assert.False(ApiClient.TryBuildBody(request, "b", out _, out _, out string error));
        Assert.Contains("not found", error, StringComparison.Ordinal);
    }

    [Fact]
    public void File_Body_Without_A_Path_Is_An_Error()
    {
        var request = new ApiRequest { Body = new ApiBody { Kind = ApiBodyKind.File } };
        Assert.False(ApiClient.TryBuildBody(request, "b", out _, out _, out string error));
        Assert.Contains("no path", error, StringComparison.Ordinal);
    }
}

// ======================================================== client pre-flight

public class ApiRunnerClientPolicyTests
{
    private static readonly ManualClock Clock = new(new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc));

    [Fact]
    public async Task Host_Not_In_Allowlist_Is_Refused_Before_Any_Socket()
    {
        using var client = new ApiClient(new ApiSafetyPolicy { AllowedHosts = new[] { "good.example" } }, Clock);
        var response = await client.SendAsync(new ApiRequest { Url = "https://evil.example/x" }, ApiRunnerFixtures.NoVars);

        Assert.Equal(0, response.StatusCode);
        Assert.StartsWith("blocked by API safety policy: ", response.Error, StringComparison.Ordinal);
        Assert.Contains("allowlist", response.Error, StringComparison.Ordinal);
        Assert.False(response.Completed);
    }

    [Fact]
    public async Task Mutating_Method_Is_Refused_When_The_Policy_Says_So()
    {
        var policy = new ApiSafetyPolicy { AllowedHosts = new[] { "*" }, AllowMutatingMethods = false };
        using var client = new ApiClient(policy, Clock);
        var response = await client.SendAsync(
            new ApiRequest { Url = "https://good.example/x", Method = "DELETE" }, ApiRunnerFixtures.NoVars);

        Assert.StartsWith("blocked by API safety policy: ", response.Error, StringComparison.Ordinal);
        Assert.Contains("DELETE", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Plain_Http_Is_Refused_By_Default()
    {
        var policy = new ApiSafetyPolicy { AllowedHosts = new[] { "*" } };
        using var client = new ApiClient(policy, Clock);
        var response = await client.SendAsync(new ApiRequest { Url = "http://good.example/x" }, ApiRunnerFixtures.NoVars);

        Assert.Contains("plain http", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Malformed_Url_Returns_An_Error_Response_Not_An_Exception()
    {
        using var client = new ApiClient(ApiRunnerFixtures.DenyAll, Clock);
        var response = await client.SendAsync(new ApiRequest { Url = "::::" }, ApiRunnerFixtures.NoVars);

        Assert.Equal(0, response.StatusCode);
        Assert.Contains("invalid URL", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_Header_Is_Rejected_Before_The_Policy_Check()
    {
        using var client = new ApiClient(ApiRunnerFixtures.DenyAll, Clock);
        var response = await client.SendAsync(new ApiRequest
        {
            Url = "https://good.example/x",
            Headers = new[] { ApiKeyValue.Of("X-Thing", "a\r\nX-Injected: 1") }
        }, ApiRunnerFixtures.NoVars);

        Assert.Contains("control characters", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_Method_Is_Reported()
    {
        using var client = new ApiClient(ApiRunnerFixtures.DenyAll, Clock);
        var response = await client.SendAsync(
            new ApiRequest { Url = "https://good.example/x", Method = "GE T" }, ApiRunnerFixtures.NoVars);

        Assert.Contains("invalid HTTP method", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Disposed_Client_Reports_Instead_Of_Throwing()
    {
        var client = new ApiClient(ApiRunnerFixtures.DenyAll, Clock);
        client.Dispose();
        var response = await client.SendAsync(new ApiRequest { Url = "https://good.example/x" }, ApiRunnerFixtures.NoVars);

        Assert.Contains("disposed", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StartedUtc_Comes_From_The_Injected_Clock()
    {
        var clock = new ManualClock(new DateTime(2030, 12, 25, 1, 2, 3, DateTimeKind.Utc));
        using var client = new ApiClient(ApiRunnerFixtures.DenyAll, clock);
        var response = await client.SendAsync(new ApiRequest { Url = "https://good.example/x" }, ApiRunnerFixtures.NoVars);

        Assert.Equal(clock.UtcNow, response.StartedUtc);
    }

    [Fact]
    public async Task Null_Variables_Are_Tolerated()
    {
        using var client = new ApiClient(ApiRunnerFixtures.DenyAll, Clock);
        var response = await client.SendAsync(new ApiRequest { Url = "https://good.example/x" }, null!);

        Assert.False(response.Completed);   // refused by policy, but no NullReferenceException
    }
}

// ========================================================= recording client

public class ApiRunnerRecordingClientTests
{
    [Fact]
    public async Task Queued_Responses_Are_Served_In_Order()
    {
        using var client = new RecordingApiClient(new[] { ApiRunnerFixtures.Ok(201), ApiRunnerFixtures.Ok(202) });

        Assert.Equal(201, (await client.SendAsync(new ApiRequest(), ApiRunnerFixtures.NoVars)).StatusCode);
        Assert.Equal(202, (await client.SendAsync(new ApiRequest(), ApiRunnerFixtures.NoVars)).StatusCode);
    }

    [Fact]
    public async Task Exhausted_Queue_Reports_An_Error_Rather_Than_A_Fake_Success()
    {
        using var client = new RecordingApiClient(Array.Empty<ApiResponse>());
        var response = await client.SendAsync(new ApiRequest { Name = "probe" }, ApiRunnerFixtures.NoVars);

        Assert.False(response.Completed);
        Assert.Contains("no canned response", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Requests_And_Variables_Are_Recorded()
    {
        using var client = new RecordingApiClient(new[] { ApiRunnerFixtures.Ok() });
        var vars = new Dictionary<string, string> { ["host"] = "h.example" };
        await client.SendAsync(new ApiRequest { Name = "one" }, vars);

        Assert.Single(client.Calls);
        Assert.Equal("one", client.Requests[0].Name);
        Assert.Equal("h.example", client.Calls[0].Variables["host"]);
    }

    [Fact]
    public async Task Recorded_Variables_Are_A_Snapshot_Not_A_Live_View()
    {
        using var client = new RecordingApiClient(new[] { ApiRunnerFixtures.Ok() });
        var vars = new Dictionary<string, string> { ["a"] = "1" };
        await client.SendAsync(new ApiRequest(), vars);
        vars["a"] = "2";

        Assert.Equal("1", client.Calls[0].Variables["a"]);
    }

    [Fact]
    public async Task Responder_Delegate_Sees_The_Request()
    {
        using var client = new RecordingApiClient(r => ApiRunnerFixtures.Ok(r.Method == "POST" ? 201 : 200));

        Assert.Equal(201, (await client.SendAsync(new ApiRequest { Method = "POST" }, ApiRunnerFixtures.NoVars)).StatusCode);
        Assert.Equal(200, (await client.SendAsync(new ApiRequest { Method = "GET" }, ApiRunnerFixtures.NoVars)).StatusCode);
    }

    [Fact]
    public async Task Responder_Exceptions_Propagate_So_The_Runner_Can_Be_Tested()
    {
        using var client = new RecordingApiClient(_ => throw new InvalidOperationException("boom"));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.SendAsync(new ApiRequest(), ApiRunnerFixtures.NoVars));
    }
}

// ========================================================= collection runner

public class ApiRunnerCollectionTests
{
    private static CollectionRunner Runner(IApiClient client, IClock clock, List<TimeSpan>? delays = null)
    {
        var runner = new CollectionRunner(client, clock);
        if (delays is not null)
        {
            runner.Sleep = (delay, _) =>
            {
                delays.Add(delay);
                return Task.CompletedTask;
            };
        }
        return runner;
    }

    private static ApiRequest Get(string name, string url = "https://api.example.com/x") =>
        new() { Name = name, Url = url };

    [Fact]
    public async Task Runs_Every_Enabled_Request_In_Order()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(Get("first"), Get("second"), Get("third"));

        var result = await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal(3, result.Total);
        Assert.Equal(new[] { "first", "second", "third" }, result.Executions.Select(e => e.Request.Name));
    }

    [Fact]
    public async Task Disabled_Requests_Are_Skipped_Entirely()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(
            Get("on"),
            new ApiRequest { Name = "off", Url = "https://api.example.com/y", Disabled = true });

        var result = await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Single(result.Executions);
        Assert.Single(client.Calls);
        Assert.Equal("on", result.Executions[0].Request.Name);
    }

    [Fact]
    public async Task Nested_Folders_Are_Flattened_Parents_First()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = new ApiCollection
        {
            Name = "nested",
            Root = new ApiFolder
            {
                Requests = new[] { Get("root") },
                Folders = new[] { new ApiFolder { Name = "sub", Requests = new[] { Get("child") } } }
            }
        };

        var result = await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal(new[] { "root", "child" }, result.Executions.Select(e => e.Request.Name));
    }

    [Fact]
    public async Task Default_Headers_Are_Added_Only_When_Absent()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(new ApiRequest
        {
            Name = "r",
            Url = "https://api.example.com/x",
            Headers = new[] { ApiKeyValue.Of("Accept", "text/plain") }
        }) with
        {
            DefaultHeaders = new[] { ApiKeyValue.Of("Accept", "application/json"), ApiKeyValue.Of("X-Tenant", "acme") }
        };

        await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        var headers = client.Requests[0].Headers;
        Assert.Equal("text/plain", headers.Single(h => h.Name == "Accept").Value);
        Assert.Equal("acme", headers.Single(h => h.Name == "X-Tenant").Value);
    }

    [Fact]
    public async Task Disabled_Default_Headers_Are_Not_Inherited()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(Get("r")) with
        {
            DefaultHeaders = new[] { new ApiKeyValue { Name = "X-Off", Value = "1", Enabled = false } }
        };

        await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.DoesNotContain(client.Requests[0].Headers, h => h.Name == "X-Off");
    }

    [Fact]
    public async Task Collection_Auth_Applies_Only_When_The_Request_Has_None()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(
            Get("inherits"),
            new ApiRequest
            {
                Name = "overrides",
                Url = "https://api.example.com/y",
                Auth = new ApiAuth { Kind = ApiAuthKind.ApiKeyHeader, KeyName = "X-Key", KeyValue = "k" }
            }) with
        {
            Auth = new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "collection-token" }
        };

        await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal(ApiAuthKind.Bearer, client.Requests[0].Auth.Kind);
        Assert.Equal(ApiAuthKind.ApiKeyHeader, client.Requests[1].Auth.Kind);
    }

    [Fact]
    public async Task Environment_Variables_Outrank_Collection_Variables()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(Get("r")) with
        {
            Variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["host"] = "collection.example",
                ["only"] = "from-collection"
            }
        };
        var environment = ApiRunnerFixtures.Env(("host", "env.example"));

        await runner.RunAsync(collection, environment, ApiRunnerFixtures.Open);

        var vars = client.Calls[0].Variables;
        Assert.Equal("env.example", vars["host"]);
        Assert.Equal("from-collection", vars["only"]);
    }

    [Fact]
    public async Task Captures_Feed_The_Next_Request_Not_The_Current_One()
    {
        var responses = new[]
        {
            ApiRunnerFixtures.Ok(200, ApiKeyValue.Of("X-Session", "abc123")),
            ApiRunnerFixtures.Ok()
        };
        using var client = new RecordingApiClient(responses);
        var runner = Runner(client, new ManualClock());

        var login = new ApiRequest
        {
            Name = "login",
            Url = "https://api.example.com/login",
            Captures = new[] { new ApiCapture { Variable = "sid", HeaderName = "X-Session" } }
        };
        var collection = ApiRunnerFixtures.Collection(login, Get("use"));

        var result = await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.False(client.Calls[0].Variables.ContainsKey("sid"));
        Assert.Equal("abc123", client.Calls[1].Variables["sid"]);
        Assert.Equal("abc123", result.Executions[0].Captured["sid"]);
    }

    [Fact]
    public async Task Failing_Assertion_Fails_The_Execution_And_The_Run()
    {
        using var client = new RecordingApiClient(new[] { ApiRunnerFixtures.Ok(404) });
        var runner = Runner(client, new ManualClock());
        var request = new ApiRequest
        {
            Name = "expect-200",
            Url = "https://api.example.com/x",
            Assertions = new[] { ApiAssertion.Status(200) }
        };

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(request), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.False(result.Success);
        Assert.Equal(1, result.Failed);
        Assert.Equal(1, result.AssertionsRun);
        Assert.Equal(1, result.AssertionsFailed);
    }

    [Fact]
    public async Task Passing_Assertion_Passes_The_Run()
    {
        using var client = new RecordingApiClient(new[] { ApiRunnerFixtures.Ok(200) });
        var runner = Runner(client, new ManualClock());
        var request = new ApiRequest
        {
            Name = "expect-200",
            Url = "https://api.example.com/x",
            Assertions = new[] { ApiAssertion.Status(200) }
        };

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(request), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.True(result.Success);
        Assert.Equal(0, result.AssertionsFailed);
    }

    [Fact]
    public async Task Assertions_Still_Run_When_The_Transport_Failed()
    {
        using var client = new RecordingApiClient(Array.Empty<ApiResponse>());   // exhausted: every send errors
        var runner = Runner(client, new ManualClock());
        var request = new ApiRequest
        {
            Name = "unreachable",
            Url = "https://api.example.com/x",
            Assertions = new[] { ApiAssertion.Status(200) }
        };

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(request), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.False(result.Success);
        Assert.NotEmpty(result.Executions[0].Assertions);
        Assert.False(result.Executions[0].Passed);
    }

    [Fact]
    public async Task A_Client_That_Throws_Does_Not_Abort_The_Run()
    {
        int calls = 0;
        using var client = new RecordingApiClient(_ =>
        {
            calls++;
            if (calls == 1) throw new InvalidOperationException("socket exploded");
            return ApiRunnerFixtures.Ok();
        });
        var runner = Runner(client, new ManualClock());

        var result = await runner.RunAsync(
            ApiRunnerFixtures.Collection(Get("bad"), Get("good")), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal(2, result.Total);
        Assert.Contains("socket exploded", result.Executions[0].Response.Error, StringComparison.Ordinal);
        Assert.True(result.Executions[1].Response.Completed);
    }

    [Fact]
    public async Task Cancellation_Returns_The_Partial_Result()
    {
        using var cts = new CancellationTokenSource();
        int calls = 0;
        using var client = new RecordingApiClient(_ =>
        {
            calls++;
            if (calls == 1) cts.Cancel();
            return ApiRunnerFixtures.Ok();
        });
        var runner = Runner(client, new ManualClock());
        var collection = ApiRunnerFixtures.Collection(Get("a"), Get("b"), Get("c"));

        var result = await runner.RunAsync(collection, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open,
                                           progress: null, analyzeSecurity: false, ct: cts.Token);

        Assert.Single(result.Executions);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Progress_Is_Reported_For_Every_Execution()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var spy = new ApiRunnerProgressSpy();

        await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a"), Get("b")),
                              ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open, spy);

        Assert.Equal(2, spy.Items.Count);
    }

    [Fact]
    public async Task A_Throwing_Progress_Handler_Cannot_Abort_The_Run()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var spy = new ApiRunnerProgressSpy(throwOnReport: true);

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a"), Get("b")),
                                           ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open, spy);

        Assert.Equal(2, result.Total);
        Assert.Equal(2, spy.Items.Count);
    }

    [Fact]
    public async Task Security_Analysis_Can_Be_Switched_Off()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a")), ApiRunnerFixtures.Env(),
                                           ApiRunnerFixtures.Open, progress: null, analyzeSecurity: false);

        Assert.Empty(result.Executions[0].Findings);
    }

    [Fact]
    public async Task Security_Analysis_On_Does_Not_Throw()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a")), ApiRunnerFixtures.Env(),
                                           ApiRunnerFixtures.Open, progress: null, analyzeSecurity: true);

        Assert.NotNull(result.Executions[0].Findings);   // content is the analyzer's business, not ours
    }

    [Fact]
    public async Task The_Runner_Refuses_A_Blocked_Host_Without_Calling_The_Client()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var policy = new ApiSafetyPolicy { AllowedHosts = new[] { "allowed.example" }, MaxRequestsPerSecond = 0 };

        var result = await runner.RunAsync(
            ApiRunnerFixtures.Collection(Get("blocked", "https://forbidden.example/x")),
            ApiRunnerFixtures.Env(), policy);

        Assert.Empty(client.Calls);
        Assert.Contains("blocked by API safety policy", result.Executions[0].Response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task A_Bad_Url_Is_Recorded_Without_Calling_The_Client()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());

        var result = await runner.RunAsync(
            ApiRunnerFixtures.Collection(Get("bad", "totally not a url")),
            ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Empty(client.Calls);
        Assert.Contains("invalid URL", result.Executions[0].Response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ResolvedUrl_Includes_Merged_Query_Parameters()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());
        var request = new ApiRequest
        {
            Name = "q",
            Url = "https://api.example.com/search",
            Query = new[] { ApiKeyValue.Of("term", "shield") }
        };

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(request), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal("https://api.example.com/search?term=shield", result.Executions[0].ResolvedUrl);
    }

    [Fact]
    public async Task Throttle_Waits_Between_Requests()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var delays = new List<TimeSpan>();
        var runner = Runner(client, new ManualClock(), delays);
        var policy = ApiRunnerFixtures.Open with { MaxRequestsPerSecond = 4 };

        await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a"), Get("b"), Get("c")),
                              ApiRunnerFixtures.Env(), policy);

        // Two gaps for three requests; the clock never advances, so each gap is the full interval.
        Assert.Equal(2, delays.Count);
        Assert.All(delays, d => Assert.Equal(TimeSpan.FromMilliseconds(250), d));
    }

    [Fact]
    public async Task No_Throttle_When_The_Rate_Limit_Is_Disabled()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var delays = new List<TimeSpan>();
        var runner = Runner(client, new ManualClock(), delays);

        await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a"), Get("b")),
                              ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Empty(delays);
    }

    [Fact]
    public async Task No_Throttle_When_Enough_Time_Already_Passed()
    {
        var clock = new ManualClock();
        using var client = new RecordingApiClient(_ =>
        {
            clock.Advance(TimeSpan.FromSeconds(5));   // the request itself outlasted the interval
            return ApiRunnerFixtures.Ok();
        });
        var delays = new List<TimeSpan>();
        var runner = Runner(client, clock, delays);
        var policy = ApiRunnerFixtures.Open with { MaxRequestsPerSecond = 4 };

        await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a"), Get("b")), ApiRunnerFixtures.Env(), policy);

        Assert.Empty(delays);
    }

    [Fact]
    public async Task Run_Metadata_Comes_From_The_Injected_Clock()
    {
        var clock = new ManualClock(new DateTime(2027, 6, 1, 12, 0, 0, DateTimeKind.Utc));
        DateTime start = clock.UtcNow;
        using var client = new RecordingApiClient(_ =>
        {
            clock.Advance(TimeSpan.FromSeconds(2));
            return ApiRunnerFixtures.Ok();
        });
        var runner = Runner(client, clock);

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(Get("a")), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal(start, result.StartedUtc);
        Assert.Equal(TimeSpan.FromSeconds(2), result.Duration);
        Assert.Equal("demo", result.CollectionName);
        Assert.Equal("dev", result.EnvironmentName);
    }

    [Fact]
    public async Task An_Empty_Collection_Succeeds_With_No_Executions()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());

        var result = await runner.RunAsync(ApiRunnerFixtures.Collection(), ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open);

        Assert.Equal(0, result.Total);
        Assert.True(result.Success);
        Assert.Empty(client.Calls);
    }

    [Fact]
    public void ApplyCollectionDefaults_Does_Not_Mutate_The_Original_Request()
    {
        var request = new ApiRequest { Name = "r", Url = "https://h/x" };
        var collection = ApiRunnerFixtures.Collection(request) with
        {
            DefaultHeaders = new[] { ApiKeyValue.Of("X-Tenant", "acme") },
            Auth = new ApiAuth { Kind = ApiAuthKind.Bearer, Token = "t" }
        };

        var effective = CollectionRunner.ApplyCollectionDefaults(request, collection);

        Assert.Empty(request.Headers);
        Assert.Equal(ApiAuthKind.None, request.Auth.Kind);
        Assert.Single(effective.Headers);
        Assert.Equal(ApiAuthKind.Bearer, effective.Auth.Kind);
    }

    [Fact]
    public async Task Null_Arguments_Are_Rejected_Loudly()
    {
        using var client = new RecordingApiClient(_ => ApiRunnerFixtures.Ok());
        var runner = Runner(client, new ManualClock());

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => runner.RunAsync(null!, ApiRunnerFixtures.Env(), ApiRunnerFixtures.Open));
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => runner.RunAsync(ApiRunnerFixtures.Collection(), null!, ApiRunnerFixtures.Open));
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => runner.RunAsync(ApiRunnerFixtures.Collection(), ApiRunnerFixtures.Env(), null!));
    }
}

// ================================================================= redaction

public class ApiRunnerRedactionTests
{
    [Theory]
    [InlineData("Authorization", true)]
    [InlineData("authorization", true)]
    [InlineData("X-Api-Key", true)]
    [InlineData("x-refresh-token", true)]
    [InlineData("Client-Secret", true)]
    [InlineData("X-Password", true)]
    [InlineData("Accept", false)]
    [InlineData("Content-Type", false)]
    [InlineData("", false)]
    public void Secret_Name_Detection(string name, bool expected)
        => Assert.Equal(expected, ApiReports.IsSecretName(name));

    [Fact]
    public void Authorization_Keeps_Its_Scheme_But_Loses_The_Credential()
    {
        Assert.Equal("Bearer " + ApiReports.RedactionPlaceholder,
            ApiReports.RedactHeaderValue("Authorization", "Bearer eyJhbGciOiJub25lIn0.payload.sig"));
    }

    [Fact]
    public void Schemeless_Secret_Header_Is_Fully_Redacted()
    {
        Assert.Equal(ApiReports.RedactionPlaceholder, ApiReports.RedactHeaderValue("X-Api-Key", "abc123"));
    }

    [Fact]
    public void Ordinary_Headers_Are_Left_Alone()
    {
        Assert.Equal("application/json", ApiReports.RedactHeaderValue("Accept", "application/json"));
    }

    [Fact]
    public void Set_Cookie_Keeps_The_Security_Attributes()
    {
        string redacted = ApiReports.RedactHeaderValue("Set-Cookie", "sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax");

        Assert.DoesNotContain("abc123", redacted, StringComparison.Ordinal);
        Assert.Contains("sid=" + ApiReports.RedactionPlaceholder, redacted, StringComparison.Ordinal);
        Assert.Contains("HttpOnly", redacted, StringComparison.Ordinal);
        Assert.Contains("Secure", redacted, StringComparison.Ordinal);
        Assert.Contains("SameSite=Lax", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Cookie_Header_Redacts_Every_Pair()
    {
        string redacted = ApiReports.RedactHeaderValue("Cookie", "a=1; b=2");

        Assert.DoesNotContain("=1", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("=2", redacted, StringComparison.Ordinal);
        Assert.Contains("a=" + ApiReports.RedactionPlaceholder, redacted, StringComparison.Ordinal);
        Assert.Contains("b=" + ApiReports.RedactionPlaceholder, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_Header_Value_Survives()
    {
        Assert.Equal("", ApiReports.RedactHeaderValue("Authorization", ""));
    }

    [Fact]
    public void Url_Query_Secrets_Are_Redacted_And_Ordinary_Parameters_Kept()
    {
        string redacted = ApiReports.RedactUrl("https://h.example/p?api_key=SUPERSECRET&page=2");

        Assert.DoesNotContain("SUPERSECRET", redacted, StringComparison.Ordinal);
        Assert.Contains("api_key=" + ApiReports.RedactionPlaceholder, redacted, StringComparison.Ordinal);
        Assert.Contains("page=2", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Url_Userinfo_Password_Is_Redacted()
    {
        string redacted = ApiReports.RedactUrl("https://alice:hunter2@h.example/p");

        Assert.DoesNotContain("hunter2", redacted, StringComparison.Ordinal);
        Assert.Contains("alice:" + ApiReports.RedactionPlaceholder + "@h.example", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Url_Without_Query_Is_Unchanged()
    {
        Assert.Equal("https://h.example/p", ApiReports.RedactUrl("https://h.example/p"));
    }

    [Fact]
    public void Url_Fragment_Survives_Query_Redaction()
    {
        string redacted = ApiReports.RedactUrl("https://h.example/p?token=abc#anchor");

        Assert.EndsWith("#anchor", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("abc", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Unparseable_Url_Is_Still_Redacted()
    {
        string redacted = ApiReports.RedactUrl("{{base}}/p?access_token=LEAK");
        Assert.DoesNotContain("LEAK", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void XmlSafe_Drops_Characters_Xml_Cannot_Encode()
    {
        string cleaned = ApiReports.XmlSafe("a\u0000b\u0008c");
        Assert.Equal("abc", cleaned);
    }

    [Fact]
    public void XmlSafe_Keeps_Tabs_Newlines_And_Surrogate_Pairs()
    {
        string input = "a\tb\nc\U0001F600";
        Assert.Equal(input, ApiReports.XmlSafe(input));
    }

    [Fact]
    public void XmlSafe_Drops_A_Lone_Surrogate()
    {
        Assert.Equal("ab", ApiReports.XmlSafe("a\uD800b"));
    }
}

// =================================================================== reports

public class ApiRunnerReportTests
{
    private const string SecretBody = "SUPER_SECRET_RESPONSE_BODY";

    private static ApiExecution Execution(
        string name = "get widget",
        int status = 200,
        string error = "",
        bool assertionPasses = true,
        params ApiKeyValue[] responseHeaders)
    {
        var request = new ApiRequest
        {
            Name = name,
            Method = "GET",
            Url = "https://api.example.com/widget?api_key=LEAKED&page=1",
            Headers = new[]
            {
                ApiKeyValue.Of("Authorization", "Bearer topsecrettoken"),
                ApiKeyValue.Of("Accept", "application/json")
            }
        };

        var response = new ApiResponse
        {
            StatusCode = status,
            ReasonPhrase = status == 200 ? "OK" : "Not Found",
            Headers = responseHeaders,
            BodyText = SecretBody,
            BodyBytes = SecretBody.Length,
            Elapsed = TimeSpan.FromMilliseconds(37),
            FinalUrl = "https://api.example.com/widget",
            Error = error,
            StartedUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
        };

        return new ApiExecution
        {
            Request = request,
            ResolvedUrl = request.Url,
            Response = response,
            Assertions = new[]
            {
                new AssertionOutcome
                {
                    Name = "status is 200",
                    Kind = AssertionKind.StatusEquals,
                    Passed = assertionPasses,
                    Detail = assertionPasses ? "200" : "expected 200, got " + status
                }
            }
        };
    }

    private static ApiRunResult Result(params ApiExecution[] executions) => new()
    {
        CollectionName = "Widget API",
        EnvironmentName = "staging",
        StartedUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        Duration = TimeSpan.FromMilliseconds(1500),
        Executions = executions
    };

    [Fact]
    public void Json_Is_Well_Formed_And_Carries_The_Summary()
    {
        string json = ApiReports.ToJson(Result(Execution(), Execution("second", 404, assertionPasses: false)));
        using var document = JsonDocument.Parse(json);

        var summary = document.RootElement.GetProperty("summary");
        Assert.Equal(2, summary.GetProperty("total").GetInt32());
        Assert.Equal(1, summary.GetProperty("passed").GetInt32());
        Assert.Equal(1, summary.GetProperty("failed").GetInt32());
        Assert.False(summary.GetProperty("success").GetBoolean());
        Assert.Equal("Widget API", document.RootElement.GetProperty("collection").GetString());
    }

    [Fact]
    public void Json_Redacts_The_Authorization_Header()
    {
        string json = ApiReports.ToJson(Result(Execution()));

        Assert.DoesNotContain("topsecrettoken", json, StringComparison.Ordinal);
        Assert.Contains(ApiReports.RedactionPlaceholder, json, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_Redacts_A_Key_In_The_Resolved_Url()
    {
        string json = ApiReports.ToJson(Result(Execution()));
        Assert.DoesNotContain("LEAKED", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Json_Redacts_Set_Cookie_From_The_Response()
    {
        var execution = Execution("cookies", 200, "", true, ApiKeyValue.Of("Set-Cookie", "sid=deadbeef; HttpOnly"));
        string json = ApiReports.ToJson(Result(execution));

        Assert.DoesNotContain("deadbeef", json, StringComparison.Ordinal);
        Assert.Contains("HttpOnly", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Reports_Never_Contain_The_Response_Body()
    {
        var result = Result(Execution());

        Assert.DoesNotContain(SecretBody, ApiReports.ToJson(result), StringComparison.Ordinal);
        Assert.DoesNotContain(SecretBody, ApiReports.ToJUnitXml(result), StringComparison.Ordinal);
        Assert.DoesNotContain(SecretBody, ApiReports.ToMarkdown(result), StringComparison.Ordinal);
        Assert.DoesNotContain(SecretBody, ApiReports.ToHtml(result), StringComparison.Ordinal);
        Assert.DoesNotContain(SecretBody, ApiReports.ToConsoleText(result), StringComparison.Ordinal);
    }

    [Fact]
    public void Reports_Are_Deterministic()
    {
        var result = Result(Execution());

        Assert.Equal(ApiReports.ToJson(result), ApiReports.ToJson(result));
        Assert.Equal(ApiReports.ToHtml(result), ApiReports.ToHtml(result));
        Assert.Equal(ApiReports.ToJUnitXml(result), ApiReports.ToJUnitXml(result));
    }

    [Fact]
    public void JUnit_Xml_Parses_And_Counts_Correctly()
    {
        var result = Result(
            Execution(),
            Execution("failing", 404, assertionPasses: false),
            Execution("broken", 0, error: "timed out after 30s"));

        var document = XDocument.Parse(ApiReports.ToJUnitXml(result));

        Assert.Equal("testsuites", document.Root!.Name.LocalName);
        Assert.Equal("3", document.Root.Attribute("tests")!.Value);
        Assert.Equal("1", document.Root.Attribute("failures")!.Value);
        Assert.Equal("1", document.Root.Attribute("errors")!.Value);
        Assert.Equal(3, document.Descendants("testcase").Count());
        Assert.Single(document.Descendants("failure"));
        Assert.Single(document.Descendants("error"));
    }

    [Fact]
    public void JUnit_Xml_Escapes_Hostile_Request_Names()
    {
        string hostile = "</testcase><injected/>&\"'<script>";
        var document = XDocument.Parse(ApiReports.ToJUnitXml(Result(Execution(hostile))));

        Assert.Empty(document.Descendants("injected"));
        Assert.Equal(hostile, document.Descendants("testcase").Single().Attribute("name")!.Value);
    }

    [Fact]
    public void JUnit_Xml_Survives_Control_Characters_In_A_Name()
    {
        var document = XDocument.Parse(ApiReports.ToJUnitXml(Result(Execution("na\u0000me\u0007"))));
        Assert.Equal("name", document.Descendants("testcase").Single().Attribute("name")!.Value);
    }

    [Fact]
    public void JUnit_Xml_Includes_The_Xml_Declaration()
    {
        Assert.StartsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>", ApiReports.ToJUnitXml(Result(Execution())),
            StringComparison.Ordinal);
    }

    [Fact]
    public void JUnit_Time_Is_Invariant_Formatted_Seconds()
    {
        var document = XDocument.Parse(ApiReports.ToJUnitXml(Result(Execution())));
        Assert.Equal("1.500", document.Root!.Attribute("time")!.Value);
        Assert.Equal("0.037", document.Descendants("testcase").Single().Attribute("time")!.Value);
    }

    [Fact]
    public void Html_Escapes_A_Script_Tag_In_A_Request_Name()
    {
        string html = ApiReports.ToHtml(Result(Execution("<script>alert(1)</script>")));

        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_Escapes_Attribute_Breaking_Quotes()
    {
        string html = ApiReports.ToHtml(Result(Execution("\" onmouseover=\"alert(1)")));

        Assert.DoesNotContain("onmouseover=\"alert", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_Is_Self_Contained()
    {
        string html = ApiReports.ToHtml(Result(Execution()));

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<style>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Html_Redacts_Secrets()
    {
        var execution = Execution("secrets", 200, "", true, ApiKeyValue.Of("X-Api-Token", "hunter2"));
        string html = ApiReports.ToHtml(Result(execution));

        Assert.DoesNotContain("hunter2", html, StringComparison.Ordinal);
        Assert.DoesNotContain("LEAKED", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_Escapes_Pipes_So_The_Table_Survives()
    {
        string markdown = ApiReports.ToMarkdown(Result(Execution("a|b")));

        Assert.Contains("a\\|b", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_Flattens_Newlines_In_A_Cell()
    {
        string markdown = ApiReports.ToMarkdown(Result(Execution("line1\nline2")));

        Assert.Contains("line1 line2", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_Lists_Failures()
    {
        string markdown = ApiReports.ToMarkdown(Result(Execution("failing", 404, assertionPasses: false)));

        Assert.Contains("## Failures", markdown, StringComparison.Ordinal);
        Assert.Contains("expected 200, got 404", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Markdown_Redacts_Secrets()
    {
        string markdown = ApiReports.ToMarkdown(Result(Execution()));
        Assert.DoesNotContain("LEAKED", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Console_Text_Shows_Pass_Fail_And_A_Summary()
    {
        string text = ApiReports.ToConsoleText(Result(Execution(), Execution("failing", 404, assertionPasses: false)));

        Assert.Contains("PASS", text, StringComparison.Ordinal);
        Assert.Contains("FAIL", text, StringComparison.Ordinal);
        Assert.Contains("2 requests, 1 passed, 1 failed", text, StringComparison.Ordinal);
        Assert.Contains("RESULT: FAIL", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Console_Text_Reports_A_Transport_Error()
    {
        string text = ApiReports.ToConsoleText(Result(Execution("broken", 0, error: "timed out after 30s")));

        Assert.Contains("error: timed out after 30s", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Console_Text_Says_Pass_When_Everything_Passed()
    {
        Assert.Contains("RESULT: PASS", ApiReports.ToConsoleText(Result(Execution())), StringComparison.Ordinal);
    }

    [Fact]
    public void An_Empty_Run_Renders_In_Every_Format()
    {
        var result = Result();

        Assert.NotEmpty(ApiReports.ToJson(result));
        Assert.NotEmpty(ApiReports.ToMarkdown(result));
        Assert.NotEmpty(ApiReports.ToHtml(result));
        Assert.NotEmpty(ApiReports.ToConsoleText(result));

        var document = XDocument.Parse(ApiReports.ToJUnitXml(result));
        Assert.Equal("0", document.Root!.Attribute("tests")!.Value);
    }

    [Fact]
    public void Tls_Facts_Reach_The_Json_Report()
    {
        var execution = Execution() with
        {
            Response = Execution().Response with
            {
                Tls = new TlsInfo
                {
                    Subject = "CN=api.example.com",
                    Issuer = "CN=Test CA",
                    Thumbprint = "AABBCC",
                    KeySizeBits = 2048,
                    ChainValid = true,
                    SubjectAltNames = new[] { "api.example.com" },
                    NotAfterUtc = new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                }
            }
        };

        using var document = JsonDocument.Parse(ApiReports.ToJson(Result(execution)));
        var tls = document.RootElement.GetProperty("executions")[0].GetProperty("tls");

        Assert.Equal("CN=api.example.com", tls.GetProperty("subject").GetString());
        Assert.Equal(2048, tls.GetProperty("keySizeBits").GetInt32());
        Assert.True(tls.GetProperty("chainValid").GetBoolean());
    }

    [Fact]
    public void Captured_Variables_With_Secret_Names_Are_Redacted()
    {
        var execution = Execution() with
        {
            Captured = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["auth_token"] = "abc123",
                ["orderId"] = "42"
            }
        };

        string json = ApiReports.ToJson(Result(execution));

        Assert.DoesNotContain("abc123", json, StringComparison.Ordinal);
        Assert.Contains("\"42\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Findings_Reach_The_Markdown_And_Html_Reports()
    {
        var execution = Execution() with
        {
            Findings = new[]
            {
                new ApiFinding
                {
                    Id = "missing-hsts",
                    Title = "Strict-Transport-Security is absent",
                    Severity = FindingSeverity.Medium,
                    Owasp = OwaspApi.SecurityMisconfiguration,
                    Endpoint = "https://api.example.com/widget"
                }
            }
        };

        Assert.Contains("missing-hsts", ApiReports.ToMarkdown(Result(execution)), StringComparison.Ordinal);
        Assert.Contains("Strict-Transport-Security is absent", ApiReports.ToHtml(Result(execution)), StringComparison.Ordinal);
        Assert.Contains("finding [Medium]", ApiReports.ToConsoleText(Result(execution)), StringComparison.Ordinal);
    }

    [Fact]
    public void Null_Result_Is_Rejected_By_Every_Renderer()
    {
        Assert.Throws<ArgumentNullException>(() => ApiReports.ToJson(null!));
        Assert.Throws<ArgumentNullException>(() => ApiReports.ToJUnitXml(null!));
        Assert.Throws<ArgumentNullException>(() => ApiReports.ToMarkdown(null!));
        Assert.Throws<ArgumentNullException>(() => ApiReports.ToHtml(null!));
        Assert.Throws<ArgumentNullException>(() => ApiReports.ToConsoleText(null!));
    }
}
