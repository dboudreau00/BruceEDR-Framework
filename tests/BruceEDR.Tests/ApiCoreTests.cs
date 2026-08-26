using System.Diagnostics;
using System.Text.Json;
using BruceEDR.Api;
using BruceEDR.Core;
using Xunit;

namespace BruceEDR.Tests;

// ---------------------------------------------------------------------------
// Tests for the three pure pieces of API Studio: variable templating, the
// JSONPath subset, and assertion/capture evaluation.
//
// Everything in here is offline and admin-free by construction: the code under
// test performs no I/O at all, so the tests need no temp files, no sockets and
// no elevation. Time-dependent behaviour is driven through ManualClock.
// ---------------------------------------------------------------------------

public class ApiTemplatingTests
{
    private static IReadOnlyDictionary<string, string> Vars(params (string Key, string Value)[] pairs)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in pairs) d[k] = v;
        return d;
    }

    [Fact]
    public void Resolve_Substitutes_Known_Variable()
    {
        var vars = Vars(("host", "api.example.test"));
        Assert.Equal("https://api.example.test/v1", Templating.Resolve("https://{{host}}/v1", vars));
    }

    [Fact]
    public void Resolve_Substitutes_Every_Occurrence()
    {
        var vars = Vars(("x", "1"));
        Assert.Equal("1-1-1", Templating.Resolve("{{x}}-{{x}}-{{x}}", vars));
    }

    [Fact]
    public void Resolve_Trims_Whitespace_Inside_Braces()
    {
        var vars = Vars(("name", "nova"));
        Assert.Equal("nova", Templating.Resolve("{{  name  }}", vars));
    }

    [Fact]
    public void Resolve_Unknown_Placeholder_Is_Left_Literal()
    {
        // Postman's behaviour, and the safer one: a blank would produce a URL that
        // looks plausible, a literal {{...}} is obviously wrong.
        Assert.Equal("https://{{host}}/v1", Templating.Resolve("https://{{host}}/v1", Vars(("other", "x"))));
    }

    [Fact]
    public void Resolve_Empty_Placeholder_Is_Not_A_Variable()
    {
        Assert.Equal("a{{}}b", Templating.Resolve("a{{}}b", Vars(("", "zzz"))));
    }

    [Fact]
    public void Resolve_Nested_Value_Resolves_Transitively()
    {
        var vars = Vars(("base", "https://{{host}}"), ("host", "example.test"));
        Assert.Equal("https://example.test/users", Templating.Resolve("{{base}}/users", vars));
    }

    [Theory]
    [InlineData(0, "{{a}}")]
    [InlineData(1, "{{b}}")]
    [InlineData(2, "{{c}}")]
    [InlineData(3, "end")]
    [InlineData(8, "end")]
    public void Resolve_Honours_MaxDepth(int maxDepth, string expected)
    {
        var vars = Vars(("a", "{{b}}"), ("b", "{{c}}"), ("c", "end"));
        Assert.Equal(expected, Templating.Resolve("{{a}}", vars, maxDepth));
    }

    [Fact]
    public void Resolve_Self_Reference_Terminates_And_Leaves_Literal()
    {
        var vars = Vars(("loop", "{{loop}}"));
        Assert.Equal("{{loop}}", Templating.Resolve("{{loop}}", vars));
    }

    [Fact]
    public void Resolve_Two_Variable_Cycle_Terminates()
    {
        var vars = Vars(("a", "{{b}}"), ("b", "{{a}}"));
        Assert.Equal("{{a}}", Templating.Resolve("{{a}}", vars));
    }

    [Fact]
    public void Resolve_Cycle_Embedded_In_Text_Still_Resolves_The_Rest()
    {
        // The cycle stops at the re-entered name and leaves that one placeholder
        // literal; everything around it still resolves.
        var vars = Vars(("a", "x{{b}}y"), ("b", "{{a}}"), ("ok", "fine"));
        var result = Templating.Resolve("{{ok}} {{a}}", vars);
        Assert.Equal("fine x{{a}}y", result);
        Assert.Equal(new[] { "a" }, Templating.UnresolvedPlaceholders("{{ok}} {{a}}", vars));
    }

    [Fact]
    public void Resolve_Empty_Or_Variable_Free_Input_Is_Unchanged()
    {
        Assert.Equal("", Templating.Resolve("", Vars(("a", "b"))));
        Assert.Equal("plain text", Templating.Resolve("plain text", Vars(("a", "b"))));
    }

    [Fact]
    public void Resolve_With_No_Variables_Is_Identity()
    {
        var empty = new Dictionary<string, string>();
        Assert.Equal("{{a}}", Templating.Resolve("{{a}}", empty));
    }

    [Fact]
    public void Placeholders_Are_Distinct_And_In_First_Appearance_Order()
    {
        var found = Templating.Placeholders("{{b}}/{{a}}/{{b}}/{{c}}");
        Assert.Equal(new[] { "b", "a", "c" }, found);
    }

    [Fact]
    public void Placeholders_Reports_Both_Case_Spellings()
    {
        // They are different text and a case-sensitive environment resolves only one,
        // so collapsing them would hide a real misconfiguration.
        var found = Templating.Placeholders("{{Token}} {{token}}");
        Assert.Equal(new[] { "Token", "token" }, found);
    }

    [Fact]
    public void UnresolvedPlaceholders_Lists_Unknown_And_Cyclic_Names()
    {
        var vars = Vars(("known", "yes"), ("loop", "{{loop}}"));
        var unresolved = Templating.UnresolvedPlaceholders("{{known}} {{missing}} {{loop}}", vars);
        Assert.Equal(2, unresolved.Count);
        Assert.Contains("missing", unresolved);
        Assert.Contains("loop", unresolved);
    }

    [Fact]
    public void UnresolvedPlaceholders_Is_Empty_When_Everything_Resolves()
    {
        var vars = Vars(("a", "{{b}}"), ("b", "done"));
        Assert.Empty(Templating.UnresolvedPlaceholders("{{a}}", vars));
    }

    [Fact]
    public void Merge_Later_Layers_Win()
    {
        var merged = Templating.Merge(
            Vars(("k", "first"), ("only1", "a")),
            Vars(("k", "second")),
            Vars(("k", "third"), ("only3", "c")));

        Assert.Equal("third", merged["k"]);
        Assert.Equal("a", merged["only1"]);
        Assert.Equal("c", merged["only3"]);
    }

    [Fact]
    public void Merge_Skips_Null_Layers()
    {
        var merged = Templating.Merge(null, Vars(("k", "v")), null);
        Assert.Single(merged);
        Assert.Equal("v", merged["k"]);
    }

    [Fact]
    public void Merge_Result_Is_Case_Insensitive()
    {
        var merged = Templating.Merge(Vars(("Token", "abc")));
        Assert.True(merged.ContainsKey("token"));
        Assert.True(merged.ContainsKey("TOKEN"));
    }

    [Fact]
    public void Merge_With_No_Layers_Is_Empty()
    {
        Assert.Empty(Templating.Merge());
    }

    [Fact]
    public void Merge_Ignores_Empty_Names()
    {
        var source = new Dictionary<string, string> { [""] = "ignored", ["good"] = "kept" };
        var merged = Templating.Merge(source);
        Assert.Single(merged);
        Assert.Equal("kept", merged["good"]);
    }

    [Fact]
    public void BuiltIns_Timestamp_And_Iso_Come_From_The_Clock()
    {
        var clock = new ManualClock(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var builtIns = Templating.BuiltIns(clock);

        Assert.Equal("1767225600", builtIns["$timestamp"]);
        Assert.Equal("2026-01-01T00:00:00.000Z", builtIns["$isoTimestamp"]);
    }

    [Fact]
    public void BuiltIns_Follow_The_Clock_When_It_Advances()
    {
        var clock = new ManualClock(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        string before = Templating.BuiltIns(clock)["$timestamp"];
        clock.Advance(TimeSpan.FromSeconds(90));
        string after = Templating.BuiltIns(clock)["$timestamp"];

        Assert.Equal("1767225690", after);
        Assert.NotEqual(before, after);
    }

    [Fact]
    public void BuiltIns_RandomInt_Is_Deterministic_And_Bounded()
    {
        var clock = new ManualClock(new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc));
        string first = Templating.BuiltIns(clock)["$randomInt"];
        string second = Templating.BuiltIns(clock)["$randomInt"];

        Assert.Equal(first, second);
        int value = int.Parse(first);
        Assert.InRange(value, 0, 1000);

        clock.Advance(TimeSpan.FromTicks(1));
        Assert.NotEqual(first, Templating.BuiltIns(clock)["$randomInt"]);
    }

    [Fact]
    public void BuiltIns_Guid_Is_The_Documented_Non_Deterministic_Exception()
    {
        var clock = new ManualClock();
        Assert.NotEqual(Templating.BuiltIns(clock)["$guid"], Templating.BuiltIns(clock)["$guid"]);
        Assert.True(Guid.TryParse(Templating.BuiltIns(clock)["$guid"], out _));
    }

    [Fact]
    public void BuiltIn_Guid_Can_Be_Pinned_By_A_Later_Merge_Layer()
    {
        var vars = Templating.Merge(
            Templating.BuiltIns(new ManualClock()),
            Vars(("$guid", "00000000-0000-0000-0000-000000000001")));

        Assert.Equal("00000000-0000-0000-0000-000000000001",
            Templating.Resolve("{{$guid}}", vars));
    }

    [Fact]
    public void BuiltIns_Resolve_Inside_A_Template()
    {
        var clock = new ManualClock(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var vars = Templating.BuiltIns(clock);
        Assert.Equal("t=1767225600", Templating.Resolve("t={{$timestamp}}", vars));
    }

    // ------------------------------------------------------------- ApiRequest

    private static ApiRequest SampleRequest() => new()
    {
        Name = "{{name}} request",
        Description = "{{name}} description",
        Method = "POST",
        Url = "https://{{host}}/{{path}}",
        Headers = new[] { ApiKeyValue.Of("X-{{hdr}}", "v-{{hdr}}") },
        Query = new[] { ApiKeyValue.Of("q-{{qn}}", "{{qv}}") },
        Body = new ApiBody
        {
            Kind = ApiBodyKind.Json,
            Text = """{"id":"{{id}}"}""",
            Form = new[] { ApiKeyValue.Of("f-{{fn}}", "{{fv}}") },
            FilePath = @"C:\payloads\{{id}}.bin",
            ContentType = "application/{{ct}}"
        },
        Auth = new ApiAuth
        {
            Kind = ApiAuthKind.Basic,
            Username = "{{user}}",
            Password = "{{pass}}",
            Token = "{{tok}}",
            KeyName = "{{kn}}",
            KeyValue = "{{kv}}",
            RawValue = "{{raw}}"
        },
        Assertions = new[] { new ApiAssertion { Kind = AssertionKind.BodyContains, Expected = "{{id}}" } },
        Captures = new[] { new ApiCapture { Variable = "next", JsonPath = "{{id}}" } }
    };

    private static IReadOnlyDictionary<string, string> RequestVars() => Vars(
        ("name", "N"), ("host", "h.test"), ("path", "p"), ("hdr", "H"),
        ("qn", "QN"), ("qv", "QV"), ("id", "ID"), ("fn", "FN"), ("fv", "FV"),
        ("ct", "json"), ("user", "U"), ("pass", "P"), ("tok", "T"),
        ("kn", "KN"), ("kv", "KV"), ("raw", "R"));

    [Fact]
    public void ResolveRequest_Substitutes_Url_Headers_Query_Body_Form_And_Auth()
    {
        var resolved = Templating.Resolve(SampleRequest(), RequestVars());

        Assert.Equal("https://h.test/p", resolved.Url);
        Assert.Equal("X-H", resolved.Headers[0].Name);
        Assert.Equal("v-H", resolved.Headers[0].Value);
        Assert.Equal("q-QN", resolved.Query[0].Name);
        Assert.Equal("QV", resolved.Query[0].Value);
        Assert.Equal("""{"id":"ID"}""", resolved.Body.Text);
        Assert.Equal("f-FN", resolved.Body.Form[0].Name);
        Assert.Equal("FV", resolved.Body.Form[0].Value);

        Assert.Equal("U", resolved.Auth.Username);
        Assert.Equal("P", resolved.Auth.Password);
        Assert.Equal("T", resolved.Auth.Token);
        Assert.Equal("KN", resolved.Auth.KeyName);
        Assert.Equal("KV", resolved.Auth.KeyValue);
        Assert.Equal("R", resolved.Auth.RawValue);
    }

    [Fact]
    public void ResolveRequest_Leaves_Metadata_FilePath_ContentType_Assertions_And_Captures_Alone()
    {
        var original = SampleRequest();
        var resolved = Templating.Resolve(original, RequestVars());

        Assert.Equal("{{name}} request", resolved.Name);
        Assert.Equal("{{name}} description", resolved.Description);
        Assert.Equal(@"C:\payloads\{{id}}.bin", resolved.Body.FilePath);
        Assert.Equal("application/{{ct}}", resolved.Body.ContentType);
        Assert.Equal("{{id}}", resolved.Assertions[0].Expected);
        Assert.Equal("{{id}}", resolved.Captures[0].JsonPath);
        Assert.Equal(original.Id, resolved.Id);
        Assert.Equal("POST", resolved.Method);
    }

    [Fact]
    public void ResolveRequest_Preserves_Enabled_Flags_And_Other_Settings()
    {
        var request = new ApiRequest
        {
            Url = "https://{{host}}/x",
            Headers = new[] { new ApiKeyValue { Name = "A", Value = "{{v}}", Enabled = false, Description = "{{d}}" } },
            TimeoutSeconds = 7,
            FollowRedirects = false,
            Disabled = true
        };

        var resolved = Templating.Resolve(request, Vars(("host", "h"), ("v", "V"), ("d", "D")));

        Assert.False(resolved.Headers[0].Enabled);
        Assert.Equal("V", resolved.Headers[0].Value);
        Assert.Equal("{{d}}", resolved.Headers[0].Description);
        Assert.Equal(7, resolved.TimeoutSeconds);
        Assert.False(resolved.FollowRedirects);
        Assert.True(resolved.Disabled);
    }

    [Fact]
    public void ResolveRequest_With_No_Variables_Returns_The_Same_Instance()
    {
        var request = SampleRequest();
        Assert.Same(request, Templating.Resolve(request, new Dictionary<string, string>()));
    }

    [Fact]
    public void ResolveRequest_Leaves_Empty_Auth_Untouched()
    {
        var request = new ApiRequest { Url = "https://{{host}}/x" };
        var resolved = Templating.Resolve(request, Vars(("host", "h")));
        Assert.Equal(ApiAuthKind.None, resolved.Auth.Kind);
        Assert.Equal("", resolved.Auth.Token);
    }
}

public class ApiJsonQueryTests
{
    private const string Sample = """
    {
      "data": {
        "items": [
          { "id": 1, "name": "alpha" },
          { "id": 2, "name": "beta" }
        ],
        "total": 2
      },
      "meta": { "content.type": "application/json", "flags": { "a": true, "b": false } },
      "token": "abc",
      "nothing": null,
      "ratio": 1.50,
      "Token": "upper"
    }
    """;

    [Theory]
    [InlineData("{}")]
    [InlineData("[]")]
    [InlineData("123")]
    [InlineData("\"text\"")]
    [InlineData("null")]
    [InlineData("{\"a\":1}")]
    public void IsValidJson_Accepts_Complete_Values(string json) => Assert.True(JsonQuery.IsValidJson(json));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("{\"a\":}")]
    [InlineData("{\"a\":1,}")]         // trailing comma is rejected on purpose
    [InlineData("{} {}")]              // trailing content
    [InlineData("{\"a\":1} // note")]  // comments are rejected on purpose
    [InlineData("<html>nope</html>")]
    public void IsValidJson_Rejects_Malformed_Or_Extra_Content(string json) =>
        Assert.False(JsonQuery.IsValidJson(json));

    [Fact]
    public void IsValidJson_Rejects_Excessive_Nesting()
    {
        // A body nested past the parser depth limit must be reported as invalid,
        // not crash the assertion loop.
        string deep = new string('[', 200) + new string(']', 200);
        Assert.False(JsonQuery.IsValidJson(deep));
    }

    [Theory]
    [InlineData("token", "abc")]
    [InlineData("$.token", "abc")]
    [InlineData("$token", "abc")]
    [InlineData("data.total", "2")]
    [InlineData("data.items[0].id", "1")]
    [InlineData("data.items[1].name", "beta")]
    [InlineData("$.data.items[-1].id", "2")]
    [InlineData("data.items[-2].id", "1")]
    [InlineData("meta['content.type']", "application/json")]
    [InlineData("meta[\"content.type\"]", "application/json")]
    [InlineData("nothing", "null")]
    [InlineData("meta.flags.a", "true")]
    [InlineData("meta.flags.b", "false")]
    public void TrySelect_Reads_Scalars(string path, string expected)
    {
        Assert.True(JsonQuery.TrySelect(Sample, path, out string value));
        Assert.Equal(expected, value);
    }

    [Fact]
    public void TrySelect_Preserves_Number_Text_Exactly()
    {
        // 1.50 must not become 1.5: an equality assertion is about the contract the
        // server published, not about the numeric value.
        Assert.True(JsonQuery.TrySelect(Sample, "ratio", out string value));
        Assert.Equal("1.50", value);
    }

    [Fact]
    public void TrySelect_Property_Lookup_Is_Case_Sensitive()
    {
        Assert.True(JsonQuery.TrySelect(Sample, "token", out string lower));
        Assert.True(JsonQuery.TrySelect(Sample, "Token", out string upper));
        Assert.Equal("abc", lower);
        Assert.Equal("upper", upper);
    }

    [Fact]
    public void TrySelect_Renders_Objects_And_Arrays_As_Compact_Json()
    {
        Assert.True(JsonQuery.TrySelect(Sample, "data.items[0]", out string value));
        Assert.Equal("""{"id":1,"name":"alpha"}""", value);
    }

    [Fact]
    public void TrySelect_Empty_Path_Selects_The_Root()
    {
        Assert.True(JsonQuery.TrySelect("""{"a":1}""", "", out string value));
        Assert.Equal("""{"a":1}""", value);
        Assert.True(JsonQuery.TrySelect("""{"a":1}""", "$", out string rooted));
        Assert.Equal("""{"a":1}""", rooted);
    }

    [Theory]
    [InlineData("data.items[9].id")]
    [InlineData("data.items[-9].id")]
    [InlineData("data.missing")]
    [InlineData("token.nested")]        // property step into a scalar
    [InlineData("data.items.id")]       // property step into an array
    [InlineData("token[0]")]            // index step into a scalar
    [InlineData("token.*")]             // wildcard over a scalar
    public void TrySelect_Returns_False_For_Paths_That_Match_Nothing(string path)
    {
        Assert.False(JsonQuery.TrySelect(Sample, path, out string value));
        Assert.Equal("", value);
    }

    [Theory]
    [InlineData("a[")]
    [InlineData("a[0")]
    [InlineData("a.")]
    [InlineData("a..b")]
    [InlineData("..a")]
    [InlineData("a[]")]
    [InlineData("a['']")]
    [InlineData("a[1:2]")]              // slices are unsupported, not silently ignored
    [InlineData("a[0,1]")]              // unions likewise
    [InlineData("a[?(@.x)]")]           // filter expressions are refused outright
    [InlineData("a[abc]")]
    public void Malformed_Paths_Yield_Nothing_And_Never_Throw(string path)
    {
        Assert.False(JsonQuery.TrySelect(Sample, path, out _));
        Assert.Empty(JsonQuery.SelectAll(Sample, path));
        Assert.Equal(0, JsonQuery.Count(Sample, path));
        Assert.False(JsonQuery.TryGetElement(Sample, path, out _));
    }

    [Theory]
    [InlineData("{ not json")]
    [InlineData("")]
    [InlineData("   ")]
    public void Malformed_Json_Yields_Nothing_And_Never_Throws(string json)
    {
        Assert.False(JsonQuery.TrySelect(json, "a.b", out _));
        Assert.Empty(JsonQuery.SelectAll(json, "a.b"));
        Assert.Equal(0, JsonQuery.Count(json, "a.b"));
        Assert.False(JsonQuery.TryGetElement(json, "a.b", out _));
    }

    [Fact]
    public void SelectAll_Wildcard_Over_An_Array()
    {
        Assert.Equal(new[] { "1", "2" }, JsonQuery.SelectAll(Sample, "data.items[*].id"));
        Assert.Equal(new[] { "alpha", "beta" }, JsonQuery.SelectAll(Sample, "$.data.items[*].name"));
    }

    [Fact]
    public void SelectAll_Wildcard_Over_Object_Values()
    {
        Assert.Equal(new[] { "true", "false" }, JsonQuery.SelectAll(Sample, "meta.flags.*"));
    }

    [Fact]
    public void SelectAll_Returns_Matches_In_Document_Order()
    {
        const string json = """{"a":[{"v":"first"},{"v":"second"},{"v":"third"}]}""";
        Assert.Equal(new[] { "first", "second", "third" }, JsonQuery.SelectAll(json, "a[*].v"));
    }

    [Fact]
    public void TrySelect_Takes_The_First_Wildcard_Match()
    {
        Assert.True(JsonQuery.TrySelect(Sample, "data.items[*].id", out string value));
        Assert.Equal("1", value);
    }

    [Theory]
    [InlineData("data.items", 2)]
    [InlineData("data.items[*]", 2)]
    [InlineData("data.items[*].id", 2)]
    [InlineData("meta.flags", 2)]
    [InlineData("meta.flags.*", 2)]
    [InlineData("token", 1)]
    [InlineData("missing", 0)]
    [InlineData("data.items[0]", 2)]     // one object: counts its members
    public void Count_Reports_Container_Size_Or_Match_Count(string path, int expected) =>
        Assert.Equal(expected, JsonQuery.Count(Sample, path));

    [Fact]
    public void Count_Wildcard_Over_A_Single_Element_Array_Is_One()
    {
        // Without the wildcard carve-out this would report the element's field count.
        const string json = """{"items":[{"a":1,"b":2}]}""";
        Assert.Equal(1, JsonQuery.Count(json, "items[*]"));
        Assert.Equal(1, JsonQuery.Count(json, "items"));
    }

    [Fact]
    public void Count_Of_An_Empty_Array_Is_Zero()
    {
        Assert.Equal(0, JsonQuery.Count("""{"items":[]}""", "items"));
    }

    [Fact]
    public void TryGetElement_Returns_A_Clone_That_Outlives_The_Document()
    {
        Assert.True(JsonQuery.TryGetElement(Sample, "data.items[0]", out JsonElement element));

        // The JsonDocument that owned the parse buffer has already been disposed and
        // its pooled memory returned. Churn the pool so an un-cloned element would be
        // reading a buffer that has since been reused, then read the clone.
        for (int i = 0; i < 200; i++)
        {
            using var scratch = JsonDocument.Parse(Sample);
            _ = scratch.RootElement.GetRawText();
        }
        GC.Collect();

        Assert.Equal(JsonValueKind.Object, element.ValueKind);
        Assert.Equal("alpha", element.GetProperty("name").GetString());
        Assert.Equal(1, element.GetProperty("id").GetInt32());
    }

    [Fact]
    public void TryGetElement_Reports_Failure_Without_Setting_An_Element()
    {
        Assert.False(JsonQuery.TryGetElement(Sample, "nope.nope", out JsonElement element));
        Assert.Equal(JsonValueKind.Undefined, element.ValueKind);
    }

    [Fact]
    public void Pretty_Indents_And_Compact_Strips()
    {
        const string json = """{"a":1,"b":[1,2]}""";
        string pretty = JsonQuery.Pretty(json);
        Assert.Contains("\n", pretty);
        Assert.Equal(json, JsonQuery.Compact(pretty));
    }

    [Fact]
    public void Pretty_And_Compact_Return_Malformed_Input_Unchanged()
    {
        const string broken = "{ this is not json";
        Assert.Equal(broken, JsonQuery.Pretty(broken));
        Assert.Equal(broken, JsonQuery.Compact(broken));
    }

    [Fact]
    public void Compact_Does_Not_Escape_Ordinary_Punctuation()
    {
        // Escaping < and & here would make every rendered value differ from what the
        // server sent and break string equality assertions.
        const string json = """{"html":"<b>a & b</b>"}""";
        Assert.Equal(json, JsonQuery.Compact(json));
    }

    [Fact]
    public void Root_Level_Array_Indexing_Works()
    {
        const string json = """["a","b","c"]""";
        Assert.True(JsonQuery.TrySelect(json, "[1]", out string second));
        Assert.Equal("b", second);
        Assert.True(JsonQuery.TrySelect(json, "$[-1]", out string last));
        Assert.Equal("c", last);
        Assert.Equal(3, JsonQuery.Count(json, "$"));
    }

    [Fact]
    public void Bracket_Quoted_Key_Handles_Names_With_Brackets_And_Dots()
    {
        const string json = """{"a.b":{"c[d]":"v"}}""";
        Assert.True(JsonQuery.TrySelect(json, "['a.b']['c[d]']", out string value));
        Assert.Equal("v", value);
    }
}

public class ApiAssertionTests
{
    private static ApiResponse Response(
        int status = 200,
        string body = "",
        (string Name, string Value)[]? headers = null,
        TimeSpan elapsed = default,
        long bodyBytes = 0,
        bool truncated = false,
        string error = "") => new()
        {
            StatusCode = status,
            BodyText = body,
            BodyBytes = bodyBytes,
            BodyTruncated = truncated,
            Elapsed = elapsed,
            Error = error,
            Headers = (headers ?? Array.Empty<(string Name, string Value)>())
                .Select(h => ApiKeyValue.Of(h.Name, h.Value)).ToArray()
        };

    private static AssertionOutcome Run(AssertionKind kind, ApiResponse response, string target = "", string expected = "")
        => AssertionEvaluator.EvaluateOne(
            new ApiAssertion { Kind = kind, Target = target, Expected = expected }, response);

    [Fact]
    public void StatusEquals_Passes_And_Fails()
    {
        Assert.True(Run(AssertionKind.StatusEquals, Response(200), expected: "200").Passed);
        Assert.False(Run(AssertionKind.StatusEquals, Response(404), expected: "200").Passed);
    }

    [Fact]
    public void StatusEquals_With_Non_Numeric_Expected_Fails_Instead_Of_Throwing()
    {
        var outcome = Run(AssertionKind.StatusEquals, Response(200), expected: "two hundred");
        Assert.False(outcome.Passed);
        Assert.Contains("not an integer", outcome.Detail);
    }

    [Theory]
    [InlineData(200, true)]
    [InlineData(204, true)]
    [InlineData(299, true)]
    [InlineData(199, false)]
    [InlineData(300, false)]
    [InlineData(500, false)]
    public void StatusIsSuccess_Covers_The_2xx_Boundaries(int status, bool expected) =>
        Assert.Equal(expected, Run(AssertionKind.StatusIsSuccess, Response(status)).Passed);

    [Theory]
    [InlineData("200,201,204", 201, true)]
    [InlineData("200 201 204", 204, true)]
    [InlineData("200, 201 204", 203, false)]
    [InlineData("200-204", 202, true)]
    [InlineData("200-204", 205, false)]
    [InlineData("204-200", 202, true)]           // reversed range is normalised
    [InlineData("200-204,301;404", 404, true)]
    [InlineData("  200 ,  ", 200, true)]         // stray separators are tolerated
    public void StatusIn_Parses_Lists_And_Ranges(string spec, int status, bool expected) =>
        Assert.Equal(expected, Run(AssertionKind.StatusIn, Response(status), expected: spec).Passed);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("ok")]
    [InlineData("200-")]
    [InlineData("200-abc")]
    public void StatusIn_Rejects_A_Malformed_List_Rather_Than_Guessing(string spec)
    {
        var outcome = Run(AssertionKind.StatusIn, Response(200), expected: spec);
        Assert.False(outcome.Passed);
        Assert.Contains("malformed", outcome.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HeaderExists_Matches_The_Name_Case_Insensitively()
    {
        var response = Response(headers: new[] { ("Content-Type", "application/json") });
        Assert.True(Run(AssertionKind.HeaderExists, response, target: "content-TYPE").Passed);
    }

    [Fact]
    public void HeaderExists_Failure_Lists_The_Headers_That_Were_Present()
    {
        var response = Response(headers: new[] { ("Server", "nginx"), ("Date", "now") });
        var outcome = Run(AssertionKind.HeaderExists, response, target: "X-Frame-Options");
        Assert.False(outcome.Passed);
        Assert.Contains("Server", outcome.Detail);
        Assert.Contains("Date", outcome.Detail);
    }

    [Fact]
    public void HeaderExists_Without_A_Target_Fails_Explicitly()
    {
        var outcome = Run(AssertionKind.HeaderExists, Response());
        Assert.False(outcome.Passed);
        Assert.Contains("no header name", outcome.Detail);
    }

    [Fact]
    public void HeaderEquals_Is_Case_Sensitive_On_The_Value()
    {
        var response = Response(headers: new[] { ("X-Token", "AbC") });
        Assert.True(Run(AssertionKind.HeaderEquals, response, "x-token", "AbC").Passed);
        Assert.False(Run(AssertionKind.HeaderEquals, response, "x-token", "abc").Passed);
    }

    [Fact]
    public void HeaderEquals_Matches_Any_Of_Several_Values_For_The_Same_Name()
    {
        var response = Response(headers: new[] { ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2") });
        Assert.True(Run(AssertionKind.HeaderEquals, response, "Set-Cookie", "b=2").Passed);
        Assert.False(Run(AssertionKind.HeaderEquals, response, "Set-Cookie", "c=3").Passed);
    }

    [Fact]
    public void HeaderContains_Ignores_Case_On_The_Value()
    {
        var response = Response(headers: new[] { ("Cache-Control", "No-Store, max-age=0") });
        Assert.True(Run(AssertionKind.HeaderContains, response, "cache-control", "no-store").Passed);
        Assert.False(Run(AssertionKind.HeaderContains, response, "cache-control", "private").Passed);
    }

    [Fact]
    public void Header_Assertions_On_A_Missing_Header_Fail_Cleanly()
    {
        var response = Response();
        Assert.False(Run(AssertionKind.HeaderEquals, response, "X-Missing", "v").Passed);
        Assert.False(Run(AssertionKind.HeaderContains, response, "X-Missing", "v").Passed);
        Assert.Contains("absent", Run(AssertionKind.HeaderEquals, response, "X-Missing", "v").Detail);
    }

    [Fact]
    public void BodyContains_Is_Case_Sensitive()
    {
        var response = Response(body: "Hello World");
        Assert.True(Run(AssertionKind.BodyContains, response, expected: "Hello").Passed);
        Assert.False(Run(AssertionKind.BodyContains, response, expected: "hello").Passed);
    }

    [Fact]
    public void BodyNotContains_Inverts_The_Check()
    {
        var response = Response(body: "Hello World");
        Assert.True(Run(AssertionKind.BodyNotContains, response, expected: "error").Passed);
        Assert.False(Run(AssertionKind.BodyNotContains, response, expected: "World").Passed);
    }

    [Fact]
    public void BodyContains_With_An_Empty_Expected_Fails_Rather_Than_Passing_Vacuously()
    {
        var outcome = Run(AssertionKind.BodyContains, Response(body: "anything"));
        Assert.False(outcome.Passed);
        Assert.Contains("no expected substring", outcome.Detail);
    }

    [Fact]
    public void BodyMatchesRegex_Reads_The_Pattern_From_Target()
    {
        var response = Response(body: "order-4821 accepted");
        Assert.True(Run(AssertionKind.BodyMatchesRegex, response, target: @"order-\d+").Passed);
        Assert.False(Run(AssertionKind.BodyMatchesRegex, response, target: @"order-[a-z]+\b").Passed);
    }

    [Fact]
    public void BodyMatchesRegex_Falls_Back_To_Expected_When_Target_Is_Empty()
    {
        var response = Response(body: "order-4821 accepted");
        Assert.True(Run(AssertionKind.BodyMatchesRegex, response, expected: @"order-\d+").Passed);
    }

    [Fact]
    public void BodyMatchesRegex_Without_A_Pattern_Fails_Explicitly()
    {
        var outcome = Run(AssertionKind.BodyMatchesRegex, Response(body: "x"));
        Assert.False(outcome.Passed);
        Assert.Contains("no regular expression", outcome.Detail);
    }

    [Fact]
    public void BodyMatchesRegex_With_An_Invalid_Pattern_Fails_Instead_Of_Throwing()
    {
        var outcome = Run(AssertionKind.BodyMatchesRegex, Response(body: "x"), target: "([unclosed");
        Assert.False(outcome.Passed);
        Assert.Contains("invalid regular expression", outcome.Detail);
    }

    [Fact]
    public void Catastrophic_Regex_Is_Bounded_And_Never_Escapes_As_An_Exception()
    {
        // A collection file is untrusted input. Without the match timeout this pattern
        // backtracks exponentially and would hang the run; the assertion must simply
        // come back failed, quickly. The bound here is generous so the test is not
        // timing-flaky, while still being thousands of times shorter than the
        // unguarded runtime.
        var response = Response(body: new string('a', 44) + "!");
        var stopwatch = Stopwatch.StartNew();
        var outcome = Run(AssertionKind.BodyMatchesRegex, response, target: "^(a+)+$");
        stopwatch.Stop();

        Assert.False(outcome.Passed);
        Assert.NotEqual("", outcome.Detail);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"regex evaluation was not bounded: took {stopwatch.Elapsed}");
    }

    [Fact]
    public void BodyIsValidJson_Distinguishes_Json_From_An_Error_Page()
    {
        Assert.True(Run(AssertionKind.BodyIsValidJson, Response(body: """{"ok":true}""")).Passed);
        var outcome = Run(AssertionKind.BodyIsValidJson, Response(body: "<html>502</html>"));
        Assert.False(outcome.Passed);
        Assert.Contains("not valid JSON", outcome.Detail);
    }

    [Fact]
    public void JsonPathExists_Passes_On_A_Present_Path()
    {
        var response = Response(body: """{"data":{"id":"x"}}""");
        Assert.True(Run(AssertionKind.JsonPathExists, response, target: "data.id").Passed);
    }

    [Fact]
    public void JsonPathExists_Explains_Whether_The_Body_Was_Even_Json()
    {
        var notJson = Run(AssertionKind.JsonPathExists, Response(body: "<html>"), target: "data.id");
        Assert.False(notJson.Passed);
        Assert.Contains("not valid JSON", notJson.Detail);

        var missing = Run(AssertionKind.JsonPathExists, Response(body: "{}"), target: "data.id");
        Assert.False(missing.Passed);
        Assert.Contains("path not present", missing.Detail);
    }

    [Fact]
    public void JsonPathExists_Without_A_Path_Fails_Explicitly()
    {
        var outcome = Run(AssertionKind.JsonPathExists, Response(body: "{}"));
        Assert.False(outcome.Passed);
        Assert.Contains("no json path", outcome.Detail);
    }

    [Fact]
    public void JsonPathEquals_Compares_The_Rendered_Value_Ordinally()
    {
        var response = Response(body: """{"status":"OK","n":1.0}""");
        Assert.True(Run(AssertionKind.JsonPathEquals, response, "status", "OK").Passed);
        Assert.False(Run(AssertionKind.JsonPathEquals, response, "status", "ok").Passed);
        Assert.True(Run(AssertionKind.JsonPathEquals, response, "n", "1.0").Passed);
        Assert.False(Run(AssertionKind.JsonPathEquals, response, "n", "1").Passed);
    }

    [Fact]
    public void JsonPathMatches_Applies_Expected_As_A_Regex_To_The_Selected_Value()
    {
        var response = Response(body: """{"id":"user-00193"}""");
        Assert.True(Run(AssertionKind.JsonPathMatches, response, "id", @"^user-\d{5}$").Passed);
        Assert.False(Run(AssertionKind.JsonPathMatches, response, "id", @"^admin-").Passed);
    }

    [Fact]
    public void JsonPathMatches_With_An_Invalid_Pattern_Fails_Instead_Of_Throwing()
    {
        var response = Response(body: """{"id":"x"}""");
        var outcome = Run(AssertionKind.JsonPathMatches, response, "id", "(");
        Assert.False(outcome.Passed);
        Assert.Contains("invalid regular expression", outcome.Detail);
    }

    [Fact]
    public void JsonPathCountEquals_Counts_Array_Members()
    {
        var response = Response(body: """{"items":[1,2,3]}""");
        Assert.True(Run(AssertionKind.JsonPathCountEquals, response, "items", "3").Passed);
        Assert.False(Run(AssertionKind.JsonPathCountEquals, response, "items", "2").Passed);
        Assert.False(Run(AssertionKind.JsonPathCountEquals, response, "items", "many").Passed);
    }

    [Theory]
    [InlineData(50, "100", true)]
    [InlineData(100, "100", false)]     // "under 100" is strict
    [InlineData(150, "100", false)]
    public void ResponseTimeUnderMs_Is_A_Strict_Bound(int elapsedMs, string limit, bool expected)
    {
        var response = Response(elapsed: TimeSpan.FromMilliseconds(elapsedMs));
        Assert.Equal(expected, Run(AssertionKind.ResponseTimeUnderMs, response, expected: limit).Passed);
    }

    [Fact]
    public void ResponseTimeUnderMs_With_A_Non_Numeric_Limit_Fails()
    {
        var outcome = Run(AssertionKind.ResponseTimeUnderMs, Response(), expected: "fast");
        Assert.False(outcome.Passed);
        Assert.Contains("not a number", outcome.Detail);
    }

    [Fact]
    public void BodySizeUnderBytes_Prefers_The_Measured_Byte_Count()
    {
        var measured = Response(body: "abcd", bodyBytes: 4096);
        Assert.False(Run(AssertionKind.BodySizeUnderBytes, measured, expected: "10").Passed);
        Assert.True(Run(AssertionKind.BodySizeUnderBytes, measured, expected: "5000").Passed);
    }

    [Fact]
    public void BodySizeUnderBytes_Falls_Back_To_Utf8_Length_When_Bytes_Were_Not_Recorded()
    {
        // "e-acute" is two UTF-8 bytes, so a char-count fallback would be wrong.
        var response = Response(body: "\u00e9");
        Assert.False(Run(AssertionKind.BodySizeUnderBytes, response, expected: "2").Passed);
        Assert.True(Run(AssertionKind.BodySizeUnderBytes, response, expected: "3").Passed);
    }

    [Fact]
    public void BodySizeUnderBytes_Flags_A_Truncated_Body_In_The_Detail()
    {
        var response = Response(body: "abc", bodyBytes: 10, truncated: true);
        Assert.Contains("truncated", Run(AssertionKind.BodySizeUnderBytes, response, expected: "100").Detail);
    }

    [Fact]
    public void ContentTypeContains_Ignores_Case()
    {
        var response = Response(headers: new[] { ("Content-Type", "Application/JSON; charset=utf-8") });
        Assert.True(Run(AssertionKind.ContentTypeContains, response, expected: "application/json").Passed);
        Assert.False(Run(AssertionKind.ContentTypeContains, response, expected: "text/html").Passed);
    }

    [Fact]
    public void ContentTypeContains_Says_So_When_There_Is_No_Content_Type()
    {
        var outcome = Run(AssertionKind.ContentTypeContains, Response(), expected: "application/json");
        Assert.False(outcome.Passed);
        Assert.Contains("no Content-Type", outcome.Detail);
    }

    [Fact]
    public void Every_Assertion_Kind_Fails_And_Names_The_Transport_Error()
    {
        const string error = "No such host is known (api.example.test:443)";
        var response = Response(error: error);

        foreach (AssertionKind kind in Enum.GetValues<AssertionKind>())
        {
            var outcome = AssertionEvaluator.EvaluateOne(
                new ApiAssertion { Kind = kind, Target = "x", Expected = "200" }, response);

            Assert.False(outcome.Passed);
            Assert.Contains("transport error", outcome.Detail);
            Assert.Contains("No such host", outcome.Detail);
        }
    }

    [Fact]
    public void Every_Assertion_Kind_Produces_A_Detail_With_Expected_And_Actual()
    {
        var response = Response(200, """{"a":[1]}""",
            new[] { ("Content-Type", "application/json") }, TimeSpan.FromMilliseconds(12), 9);

        foreach (AssertionKind kind in Enum.GetValues<AssertionKind>())
        {
            var outcome = AssertionEvaluator.EvaluateOne(
                new ApiAssertion { Kind = kind, Target = "a", Expected = "1" }, response);

            Assert.Contains("expected ", outcome.Detail);
            Assert.Contains("actual ", outcome.Detail);
            Assert.True(outcome.Detail.Length <= AssertionEvaluator.MaxDetailLength);
            Assert.Equal(kind, outcome.Kind);
        }
    }

    [Fact]
    public void Detail_Is_Clipped_Even_When_Both_Sides_Are_Enormous()
    {
        var response = Response(body: new string('x', 50_000));
        var assertion = new ApiAssertion
        {
            Kind = AssertionKind.BodyContains,
            Expected = new string('y', 50_000)
        };

        var outcome = AssertionEvaluator.EvaluateOne(assertion, response);
        Assert.False(outcome.Passed);
        Assert.True(outcome.Detail.Length <= AssertionEvaluator.MaxDetailLength,
            $"detail was {outcome.Detail.Length} chars");
    }

    [Fact]
    public void Detail_Collapses_Newlines_So_A_Report_Line_Stays_One_Line()
    {
        var response = Response(body: "line one\r\n\r\nline two");
        var outcome = Run(AssertionKind.BodyContains, response, expected: "absent");
        Assert.DoesNotContain("\n", outcome.Detail);
    }

    [Fact]
    public void An_Unsupported_Kind_Fails_Rather_Than_Throwing()
    {
        var outcome = AssertionEvaluator.EvaluateOne(
            new ApiAssertion { Kind = (AssertionKind)999 }, Response());
        Assert.False(outcome.Passed);
        Assert.Contains("unsupported assertion kind", outcome.Detail);
    }

    [Fact]
    public void Outcome_Name_Uses_The_Assertion_DisplayName()
    {
        var named = AssertionEvaluator.EvaluateOne(
            new ApiAssertion { Kind = AssertionKind.StatusEquals, Expected = "200", Name = "should be OK" },
            Response(200));
        Assert.Equal("should be OK", named.Name);

        var unnamed = AssertionEvaluator.EvaluateOne(ApiAssertion.Status(200), Response(200));
        Assert.Contains("StatusEquals", unnamed.Name);
    }

    [Fact]
    public void Evaluate_Returns_One_Outcome_Per_Assertion_In_Order()
    {
        var assertions = new[]
        {
            new ApiAssertion { Kind = AssertionKind.StatusEquals, Expected = "200", Name = "first" },
            new ApiAssertion { Kind = AssertionKind.BodyContains, Expected = "nope", Name = "second" },
            new ApiAssertion { Kind = AssertionKind.StatusIsSuccess, Name = "third" }
        };

        var outcomes = AssertionEvaluator.Evaluate(assertions, Response(200, "body"));

        Assert.Equal(3, outcomes.Count);
        Assert.Equal(new[] { "first", "second", "third" }, outcomes.Select(o => o.Name));
        Assert.Equal(new[] { true, false, true }, outcomes.Select(o => o.Passed));
    }

    [Fact]
    public void Evaluate_With_No_Assertions_Returns_An_Empty_List()
    {
        Assert.Empty(AssertionEvaluator.Evaluate(Array.Empty<ApiAssertion>(), Response()));
        Assert.Empty(AssertionEvaluator.Evaluate(null!, Response()));
    }

    [Fact]
    public void Evaluation_Is_Deterministic_For_The_Same_Inputs()
    {
        var assertion = new ApiAssertion { Kind = AssertionKind.JsonPathEquals, Target = "a.b", Expected = "1" };
        var response = Response(body: """{"a":{"b":1}}""");

        var first = AssertionEvaluator.EvaluateOne(assertion, response);
        var second = AssertionEvaluator.EvaluateOne(assertion, response);

        Assert.Equal(first, second);
    }
}

public class ApiCaptureTests
{
    private static ApiResponse Response(string body = "", (string Name, string Value)[]? headers = null, string error = "") => new()
    {
        StatusCode = 200,
        BodyText = body,
        Error = error,
        Headers = (headers ?? Array.Empty<(string Name, string Value)>())
            .Select(h => ApiKeyValue.Of(h.Name, h.Value)).ToArray()
    };

    [Fact]
    public void Captures_A_Json_Path()
    {
        var captures = new[] { new ApiCapture { Variable = "token", JsonPath = "data.access_token" } };
        var result = CaptureEngine.Apply(captures, Response("""{"data":{"access_token":"t-123"}}"""));

        Assert.Equal("t-123", result["token"]);
    }

    [Fact]
    public void Captures_A_Header()
    {
        var captures = new[] { new ApiCapture { Variable = "loc", HeaderName = "location" } };
        var result = CaptureEngine.Apply(captures, Response(headers: new[] { ("Location", "/v1/orders/9") }));

        Assert.Equal("/v1/orders/9", result["loc"]);
    }

    [Fact]
    public void Captures_Group_One_Of_A_Body_Regex()
    {
        var captures = new[] { new ApiCapture { Variable = "csrf", BodyRegex = @"name=""csrf""\s+value=""([^""]+)""" } };
        var result = CaptureEngine.Apply(captures, Response("""<input name="csrf" value="abc123">"""));

        Assert.Equal("abc123", result["csrf"]);
    }

    [Fact]
    public void Captures_The_Whole_Match_When_The_Regex_Has_No_Group()
    {
        var captures = new[] { new ApiCapture { Variable = "id", BodyRegex = @"\d{4}" } };
        var result = CaptureEngine.Apply(captures, Response("order 8123 created"));

        Assert.Equal("8123", result["id"]);
    }

    [Fact]
    public void JsonPath_Takes_Precedence_Over_Header_And_Regex()
    {
        var captures = new[]
        {
            new ApiCapture
            {
                Variable = "v",
                JsonPath = "value",
                HeaderName = "X-Value",
                BodyRegex = "from-regex"
            }
        };

        // All three sources can supply a value here; the JSON path must win.
        var result = CaptureEngine.Apply(captures,
            Response("""{"value":"from-json","note":"from-regex"}""", new[] { ("X-Value", "from-header") }));

        Assert.Equal("from-json", result["v"]);
    }

    [Fact]
    public void Header_Takes_Precedence_Over_Regex_When_The_Json_Path_Misses()
    {
        var captures = new[]
        {
            new ApiCapture { Variable = "v", JsonPath = "absent", HeaderName = "X-Value", BodyRegex = "regexvalue" }
        };

        var result = CaptureEngine.Apply(captures,
            Response("body containing regexvalue", new[] { ("X-Value", "header-wins") }));

        Assert.Equal("header-wins", result["v"]);
    }

    [Fact]
    public void Regex_Is_Used_When_There_Is_No_Json_Path_Or_Header_Match()
    {
        var captures = new[]
        {
            new ApiCapture { Variable = "v", JsonPath = "absent", HeaderName = "X-Missing", BodyRegex = "regexvalue" }
        };

        var result = CaptureEngine.Apply(captures, Response("body with regexvalue inside"));
        Assert.Equal("regexvalue", result["v"]);
    }

    [Fact]
    public void A_Capture_That_Finds_Nothing_Is_Absent_Not_Empty()
    {
        // An empty string would resolve {{token}} to nothing and send a header with no
        // token, which looks like a server bug instead of a missing capture.
        var captures = new[] { new ApiCapture { Variable = "token", JsonPath = "data.token" } };
        var result = CaptureEngine.Apply(captures, Response("""{"data":{}}"""));

        Assert.False(result.ContainsKey("token"));
        Assert.Empty(result);
    }

    [Fact]
    public void A_Capture_With_No_Source_Is_Skipped()
    {
        var result = CaptureEngine.Apply(new[] { new ApiCapture { Variable = "v" } }, Response("""{"v":1}"""));
        Assert.Empty(result);
    }

    [Fact]
    public void A_Capture_With_A_Blank_Variable_Name_Is_Skipped()
    {
        var captures = new[] { new ApiCapture { Variable = "   ", JsonPath = "a" } };
        Assert.Empty(CaptureEngine.Apply(captures, Response("""{"a":1}""")));
    }

    [Fact]
    public void An_Invalid_Capture_Regex_Yields_No_Capture_Rather_Than_An_Exception()
    {
        var captures = new[] { new ApiCapture { Variable = "v", BodyRegex = "([unclosed" } };
        Assert.Empty(CaptureEngine.Apply(captures, Response("anything")));
    }

    [Fact]
    public void A_Catastrophic_Capture_Regex_Is_Bounded()
    {
        var captures = new[] { new ApiCapture { Variable = "v", BodyRegex = "^(a+)+$" } };
        var stopwatch = Stopwatch.StartNew();
        var result = CaptureEngine.Apply(captures, Response(new string('a', 44) + "!"));
        stopwatch.Stop();

        Assert.Empty(result);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5),
            $"capture regex was not bounded: took {stopwatch.Elapsed}");
    }

    [Fact]
    public void Nothing_Is_Captured_From_A_Failed_Exchange()
    {
        var captures = new[] { new ApiCapture { Variable = "v", JsonPath = "a", HeaderName = "H", BodyRegex = ".*" } };
        Assert.Empty(CaptureEngine.Apply(captures, Response(error: "connection reset")));
    }

    [Fact]
    public void Captured_Variables_Are_Matched_Case_Insensitively()
    {
        var captures = new[] { new ApiCapture { Variable = "Token", JsonPath = "t" } };
        var result = CaptureEngine.Apply(captures, Response("""{"t":"v"}"""));

        Assert.True(result.ContainsKey("token"));
        Assert.True(result.ContainsKey("TOKEN"));
    }

    [Fact]
    public void A_Later_Capture_Of_The_Same_Variable_Wins()
    {
        var captures = new[]
        {
            new ApiCapture { Variable = "v", JsonPath = "first" },
            new ApiCapture { Variable = "V", JsonPath = "second" }
        };

        var result = CaptureEngine.Apply(captures, Response("""{"first":"1","second":"2"}"""));
        Assert.Single(result);
        Assert.Equal("2", result["v"]);
    }

    [Fact]
    public void Captures_Feed_Straight_Back_Into_Templating()
    {
        var captured = CaptureEngine.Apply(
            new[] { new ApiCapture { Variable = "token", JsonPath = "access_token" } },
            Response("""{"access_token":"bearer-value"}"""));

        var vars = Templating.Merge(captured);
        Assert.Equal("Bearer bearer-value", Templating.Resolve("Bearer {{token}}", vars));
    }

    [Fact]
    public void Apply_With_No_Captures_Returns_An_Empty_Dictionary()
    {
        Assert.Empty(CaptureEngine.Apply(Array.Empty<ApiCapture>(), Response("{}")));
        Assert.Empty(CaptureEngine.Apply(null!, Response("{}")));
    }
}
