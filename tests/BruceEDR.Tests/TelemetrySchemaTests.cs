using System.Globalization;
using System.Text;
using System.Text.Json;
using BruceEDR.Core;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>Shared fixtures and JSON helpers for the schema/metrics tests.</summary>
internal static class TelemetrySchemaFixtures
{
    internal const string Host = "TEST-HOST";

    /// <summary>A fully populated event, so a mapping omission shows up as a missing field.</summary>
    internal static BruceEvent Rich() => new()
    {
        Level = "QUARANTINE",
        Category = "detection",
        TimeUtc = new DateTime(2026, 3, 4, 5, 6, 7, 890, DateTimeKind.Utc),
        Pid = 4242,
        Process = "powershell.exe",
        Image = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        Score = 95,
        Trigger = "Credential store read then archived",
        Reasons = new[] { "[+35] read Login Data", "[+30] staged loot.zip" },
        StagedArchives = new[] { @"C:\Users\u\AppData\Local\Temp\loot.zip" },
        Message = "quarantined powershell.exe",
        IncidentId = "INC-0001",
        Techniques = new[] { "T1555.003", "T1560.001" },
        RuleIds = new[] { "browser-cred-read", "archive-staging" },
        ParentPid = 1234,
        CommandLine = "powershell.exe -nop -w hidden -enc SQBFAFgA",
        User = @"CONTOSO\alice",
        Ancestry = new[] { "winword.exe", "explorer.exe" },
        RemoteEndpoints = new[] { "203.0.113.10:443" },
        Domains = new[] { "cdn.example.test" },
        Sha256 = new string('a', 64)
    };

    /// <summary>Every field at its empty value, including a zeroed timestamp.</summary>
    internal static BruceEvent Empty() => new()
    {
        Level = "",
        Category = "",
        TimeUtc = default,
        Process = "",
        Image = "",
        Trigger = "",
        Reasons = Array.Empty<string>(),
        StagedArchives = Array.Empty<string>(),
        Message = ""
    };

    /// <summary>
    /// An event whose collection properties are null. This is not hypothetical: a
    /// <c>{"Reasons":null}</c> line replayed from the audit log or posted to the API
    /// deserializes to exactly this, and a formatter that trusts the record's declared
    /// non-nullability would take the sink pipeline down with it.
    /// </summary>
    internal static BruceEvent Nulls() => new()
    {
        Level = null!,
        Category = null!,
        Process = null!,
        Image = null!,
        Trigger = null!,
        Message = null!,
        IncidentId = null!,
        CommandLine = null!,
        User = null!,
        Sha256 = null!,
        Reasons = null!,
        StagedArchives = null!,
        Techniques = null!,
        RuleIds = null!,
        Ancestry = null!,
        RemoteEndpoints = null!,
        Domains = null!
    };

    /// <summary>An event whose lists contain null and blank entries.</summary>
    internal static BruceEvent DirtyLists() => new()
    {
        Level = "WARN",
        Category = "detection",
        Reasons = new[] { "ok", null!, "  ", "" },
        Techniques = new[] { "t1059.001", null!, "T1059.001", " T1055 " },
        RuleIds = new[] { null!, "rule-a" },
        Domains = new[] { "a.test", null! },
        RemoteEndpoints = new[] { null!, "1.2.3.4:80" },
        Ancestry = new[] { null!, "explorer.exe" },
        StagedArchives = new string[] { null! }
    };

    internal static IEventFormatter[] All() => new IEventFormatter[]
    {
        new NativeFormatter(), new EcsFormatter(Host), new OcsfFormatter(Host), new CefFormatter(Host)
    };

    internal static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement.Clone();

    /// <summary>Walks a nested path, failing the test with the path that was missing.</summary>
    internal static JsonElement At(JsonElement root, params string[] path)
    {
        JsonElement cur = root;
        foreach (var p in path)
        {
            Assert.True(cur.ValueKind == JsonValueKind.Object, "not an object before '" + p + "'");
            Assert.True(cur.TryGetProperty(p, out var next), "missing property '" + p + "'");
            cur = next;
        }
        return cur;
    }

    internal static bool Has(JsonElement root, params string[] path)
    {
        JsonElement cur = root;
        foreach (var p in path)
        {
            if (cur.ValueKind != JsonValueKind.Object || !cur.TryGetProperty(p, out var next)) return false;
            cur = next;
        }
        return true;
    }

    internal static string[] Strings(JsonElement array)
    {
        Assert.Equal(JsonValueKind.Array, array.ValueKind);
        var list = new List<string>();
        foreach (var v in array.EnumerateArray()) list.Add(v.GetString() ?? "");
        return list.ToArray();
    }

    /// <summary>
    /// Splits a CEF line into its 7 header fields plus the extension remainder,
    /// UN-escaping as it goes. Written independently of the production escaper so the
    /// tests verify the wire format, not the implementation's own idea of it.
    /// </summary>
    internal static string[] SplitCef(string line)
    {
        var fields = new List<string>();
        var cur = new StringBuilder();
        int i = 0;
        while (i < line.Length && fields.Count < 7)
        {
            char c = line[i];
            if (c == '\\' && i + 1 < line.Length) { cur.Append(line[i + 1]); i += 2; continue; }
            if (c == '|') { fields.Add(cur.ToString()); cur.Clear(); i++; continue; }
            cur.Append(c);
            i++;
        }
        fields.Add(line[i..]);
        return fields.ToArray();
    }
}

/// <summary>Registry behaviour: names, aliases and the deliberate fallback.</summary>
public class TelemetryFormatterRegistryTests
{
    [Fact]
    public void Names_Lists_Every_Schema()
    {
        Assert.Equal(new[] { "native", "ecs", "ocsf", "cef" }, EventFormatters.Names.ToArray());
    }

    [Theory]
    [InlineData("native", "native")]
    [InlineData("json", "native")]
    [InlineData("jsonl", "native")]
    [InlineData("", "native")]
    [InlineData("ecs", "ecs")]
    [InlineData("Elastic", "ecs")]
    [InlineData("  OCSF  ", "ocsf")]
    [InlineData("cef", "cef")]
    [InlineData("ArcSight", "cef")]
    public void Resolve_Maps_Names_And_Aliases(string input, string expected)
        => Assert.Equal(expected, EventFormatters.Resolve(input).Name);

    [Fact]
    public void Every_Canonical_Name_Round_Trips()
    {
        foreach (var name in EventFormatters.Names)
            Assert.Equal(name, EventFormatters.Resolve(name).Name);
    }

    [Fact]
    public void Unknown_Name_Falls_Back_To_Native_But_TryResolve_Reports_It()
    {
        // A config typo must not stop a security agent from logging, but the operator
        // still needs to find out, hence the two-method split.
        Assert.Equal("native", EventFormatters.Resolve("elastic-common-schemaa").Name);
        Assert.False(EventFormatters.TryResolve("elastic-common-schemaa", out var f));
        Assert.Equal("native", f.Name);
        Assert.True(EventFormatters.TryResolve("ecs", out var ecs));
        Assert.Equal("ecs", ecs.Name);
    }

    [Fact]
    public void TryResolve_Accepts_Null()
    {
        Assert.True(EventFormatters.TryResolve(null, out var f));
        Assert.Equal("native", f.Name);
    }

    [Fact]
    public void AgentVersion_Is_Populated()
        => Assert.False(string.IsNullOrWhiteSpace(EventFormatters.AgentVersion));
}

/// <summary>Properties every formatter must hold, whatever the event looks like.</summary>
public class TelemetryFormatterContractTests
{
    public static IEnumerable<object[]> Formatters()
    {
        foreach (var f in TelemetrySchemaFixtures.All()) yield return new object[] { f };
    }

    public static IEnumerable<object[]> JsonFormatters()
    {
        yield return new object[] { new NativeFormatter() };
        yield return new object[] { new EcsFormatter(TelemetrySchemaFixtures.Host) };
        yield return new object[] { new OcsfFormatter(TelemetrySchemaFixtures.Host) };
    }

    [Theory]
    [MemberData(nameof(Formatters))]
    public void Never_Throws_On_Default_Event(IEventFormatter f)
        => Assert.False(string.IsNullOrEmpty(f.Format(new BruceEvent())));

    [Theory]
    [MemberData(nameof(Formatters))]
    public void Never_Throws_On_All_Empty_Event(IEventFormatter f)
        => Assert.False(string.IsNullOrEmpty(f.Format(TelemetrySchemaFixtures.Empty())));

    [Theory]
    [MemberData(nameof(Formatters))]
    public void Never_Throws_On_Null_Fields(IEventFormatter f)
        => Assert.False(string.IsNullOrEmpty(f.Format(TelemetrySchemaFixtures.Nulls())));

    [Theory]
    [MemberData(nameof(Formatters))]
    public void Never_Throws_On_Dirty_Lists(IEventFormatter f)
        => Assert.False(string.IsNullOrEmpty(f.Format(TelemetrySchemaFixtures.DirtyLists())));

    [Theory]
    [MemberData(nameof(Formatters))]
    public void Output_Is_Exactly_One_Line(IEventFormatter f)
    {
        var e = TelemetrySchemaFixtures.Rich() with
        {
            Message = "line one\nline two\r\nline three",
            CommandLine = "cmd /c echo hi\r\n& whoami",
            Trigger = "multi\nline\ttrigger"
        };
        string s = f.Format(e);
        Assert.DoesNotContain('\n', s);
        Assert.DoesNotContain('\r', s);
    }

    [Theory]
    [MemberData(nameof(Formatters))]
    public void Is_Pure_Across_Repeated_Calls(IEventFormatter f)
    {
        var e = TelemetrySchemaFixtures.Rich();
        Assert.Equal(f.Format(e), f.Format(e));
    }

    [Theory]
    [MemberData(nameof(JsonFormatters))]
    public void Json_Round_Trips_For_Rich_Event(IEventFormatter f)
        => Assert.NotEqual(JsonValueKind.Undefined,
            TelemetrySchemaFixtures.Parse(f.Format(TelemetrySchemaFixtures.Rich())).ValueKind);

    [Theory]
    [MemberData(nameof(JsonFormatters))]
    public void Json_Round_Trips_For_Hostile_Strings(IEventFormatter f)
    {
        // Quotes, backslashes, a control character, a lone surrogate escape sequence in
        // text form, RTL marks and CJK all have to survive as valid JSON.
        var e = TelemetrySchemaFixtures.Rich() with
        {
            Message = "he said \"hi\" \\ \u0001 \u202E \uFFFD 漢字",
            CommandLine = @"C:\a\""b"" --x={""y"":1}",
            Process = "\t\u0000tab.exe"
        };
        var root = TelemetrySchemaFixtures.Parse(f.Format(e));
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
    }

    [Theory]
    [MemberData(nameof(JsonFormatters))]
    public void Json_Round_Trips_For_Very_Long_Values(IEventFormatter f)
    {
        var e = TelemetrySchemaFixtures.Rich() with { CommandLine = new string('x', 100_000) };
        var root = TelemetrySchemaFixtures.Parse(f.Format(e));
        Assert.Equal(JsonValueKind.Object, root.ValueKind);
    }

    [Fact]
    public void Native_Format_Matches_The_Historical_Jsonl_Shape()
    {
        // The audit chain hashes this exact rendering, so it must not drift.
        var e = TelemetrySchemaFixtures.Rich();
        var root = TelemetrySchemaFixtures.Parse(new NativeFormatter().Format(e));
        Assert.Equal("QUARANTINE", root.GetProperty("Level").GetString());
        Assert.Equal(4242, root.GetProperty("Pid").GetInt32());
    }
}

/// <summary>ECS field-name fidelity. Getting these wrong is the whole failure mode.</summary>
public class TelemetryEcsFormatterTests
{
    private static JsonElement Ecs(BruceEvent e)
        => TelemetrySchemaFixtures.Parse(new EcsFormatter(TelemetrySchemaFixtures.Host).Format(e));

    [Fact]
    public void Emits_Core_Envelope_Fields()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        Assert.Equal("2026-03-04T05:06:07.890Z", root.GetProperty("@timestamp").GetString());
        Assert.Equal("8.11.0", TelemetrySchemaFixtures.At(root, "ecs", "version").GetString());
        Assert.Equal("bruceedr.detection", TelemetrySchemaFixtures.At(root, "event", "dataset").GetString());
        Assert.Equal("bruceedr", TelemetrySchemaFixtures.At(root, "event", "module").GetString());
        Assert.Equal("BruceEDR", TelemetrySchemaFixtures.At(root, "event", "provider").GetString());
        Assert.Equal("windows", TelemetrySchemaFixtures.At(root, "host", "os", "type").GetString());
        Assert.Equal(TelemetrySchemaFixtures.Host, TelemetrySchemaFixtures.At(root, "host", "name").GetString());
    }

    [Theory]
    [InlineData("QUARANTINE", "alert")]
    [InlineData("WARN", "alert")]
    [InlineData("INFO", "event")]
    [InlineData("ACTION", "event")]
    [InlineData("", "event")]
    [InlineData("warn", "alert")]      // level normalisation
    public void Event_Kind_Is_Alert_Only_For_Warn_And_Quarantine(string level, string expected)
    {
        var root = Ecs(new BruceEvent { Level = level, TimeUtc = default });
        Assert.Equal(expected, TelemetrySchemaFixtures.At(root, "event", "kind").GetString());
    }

    [Theory]
    [InlineData("detection", "QUARANTINE", "intrusion_detection")]
    [InlineData("detection", "WARN", "intrusion_detection")]
    [InlineData("response", "ACTION", "process")]
    [InlineData("api", "INFO", "api")]
    [InlineData("system", "INFO", "host")]
    public void Event_Category_Uses_The_Ecs_Vocabulary(string category, string level, string expected)
    {
        var root = Ecs(new BruceEvent { Category = category, Level = level, TimeUtc = default });
        Assert.Contains(expected, TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "event", "category")));
    }

    [Fact]
    public void Quarantine_Detection_Also_Categorised_As_Malware()
    {
        var root = Ecs(new BruceEvent { Category = "detection", Level = "QUARANTINE", TimeUtc = default });
        Assert.Equal(new[] { "intrusion_detection", "malware" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "event", "category")));
    }

    [Fact]
    public void Response_Event_Type_Is_Change()
    {
        var root = Ecs(new BruceEvent { Category = "response", Level = "ACTION", TimeUtc = default });
        Assert.Equal(new[] { "change" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "event", "type")));
    }

    [Fact]
    public void Event_Action_Is_A_Slug_Of_The_Trigger()
    {
        var root = Ecs(new BruceEvent { Trigger = "Credential Store Read!", TimeUtc = default });
        Assert.Equal("credential-store-read",
            TelemetrySchemaFixtures.At(root, "event", "action").GetString());
    }

    [Fact]
    public void Event_Action_Falls_Back_When_Nothing_Is_Sluggable()
    {
        var root = Ecs(TelemetrySchemaFixtures.Empty());
        Assert.Equal("event", TelemetrySchemaFixtures.At(root, "event", "action").GetString());
    }

    [Fact]
    public void Risk_Score_And_Severity_Are_Numbers()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        Assert.Equal(95, TelemetrySchemaFixtures.At(root, "event", "risk_score").GetInt32());
        Assert.Equal(8, TelemetrySchemaFixtures.At(root, "event", "severity").GetInt32());
    }

    [Fact]
    public void Process_Fields_Use_The_Ecs_Names()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        var p = TelemetrySchemaFixtures.At(root, "process");
        Assert.Equal(4242, p.GetProperty("pid").GetInt32());
        Assert.Equal("powershell.exe", p.GetProperty("name").GetString());
        Assert.Contains("powershell.exe", p.GetProperty("executable").GetString());
        Assert.Contains("-enc", p.GetProperty("command_line").GetString());
        Assert.Equal(1234, TelemetrySchemaFixtures.At(p, "parent", "pid").GetInt32());
        Assert.Equal(new string('a', 64), TelemetrySchemaFixtures.At(p, "hash", "sha256").GetString());
        Assert.Equal(@"CONTOSO\alice", TelemetrySchemaFixtures.At(root, "user", "name").GetString());
    }

    [Fact]
    public void Process_Object_Is_Omitted_When_There_Is_No_Process()
        => Assert.False(TelemetrySchemaFixtures.Has(Ecs(TelemetrySchemaFixtures.Empty()), "process"));

    [Fact]
    public void Threat_Carries_Technique_Ids_Names_And_Tactics()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        Assert.Equal("MITRE ATT&CK", TelemetrySchemaFixtures.At(root, "threat", "framework").GetString());
        Assert.Equal(new[] { "T1555.003", "T1560.001" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "threat", "technique", "id")));
        var names = TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "threat", "technique", "name"));
        Assert.Contains(names, n => n.Contains("Web Browsers"));
        var tactics = TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "threat", "tactic", "name"));
        Assert.Contains("Credential Access", tactics);
        Assert.Contains("Collection", tactics);
    }

    [Fact]
    public void Unknown_Technique_Id_Still_Maps_Without_Throwing()
    {
        var root = Ecs(new BruceEvent { Techniques = new[] { "T9999.999" }, TimeUtc = default });
        Assert.Equal(new[] { "T9999.999" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "threat", "technique", "id")));
    }

    [Fact]
    public void Techniques_Are_Deduplicated_Uppercased_And_Sorted()
    {
        var root = Ecs(TelemetrySchemaFixtures.DirtyLists());
        Assert.Equal(new[] { "T1055", "T1059.001" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "threat", "technique", "id")));
    }

    [Fact]
    public void Rule_Id_And_Name_Both_Carry_The_Rule_Slugs()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        Assert.Equal(new[] { "browser-cred-read", "archive-staging" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "rule", "id")));
        Assert.Equal(new[] { "browser-cred-read", "archive-staging" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "rule", "name")));
    }

    [Fact]
    public void Single_Endpoint_Populates_Destination()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        Assert.Equal("203.0.113.10", TelemetrySchemaFixtures.At(root, "destination", "address").GetString());
        Assert.Equal("203.0.113.10", TelemetrySchemaFixtures.At(root, "destination", "ip").GetString());
        Assert.Equal(443, TelemetrySchemaFixtures.At(root, "destination", "port").GetInt32());
    }

    [Fact]
    public void Ipv6_Endpoint_Splits_On_The_Last_Colon()
    {
        var root = Ecs(new BruceEvent
        {
            RemoteEndpoints = new[] { "2606:4700:4700::1111:8443" },
            TimeUtc = default
        });
        Assert.Equal("2606:4700:4700::1111", TelemetrySchemaFixtures.At(root, "destination", "address").GetString());
        Assert.Equal(8443, TelemetrySchemaFixtures.At(root, "destination", "port").GetInt32());
    }

    [Fact]
    public void Bare_Ipv6_Without_Port_Is_Not_Mis_Split()
    {
        // "2606:4700::1111" would naively split into address "2606:4700:" + port 1111.
        var root = Ecs(new BruceEvent { RemoteEndpoints = new[] { "2606:4700::1111" }, TimeUtc = default });
        Assert.Equal("2606:4700::1111", TelemetrySchemaFixtures.At(root, "destination", "address").GetString());
        Assert.False(TelemetrySchemaFixtures.Has(root, "destination", "port"));
    }

    [Theory]
    [InlineData("1.2.3.4:0")]        // port 0 is not a real destination
    [InlineData("1.2.3.4:65536")]    // out of range
    [InlineData("1.2.3.4:")]         // trailing colon
    [InlineData("1.2.3.4:http")]     // service name, not a number
    public void Malformed_Port_Leaves_The_Endpoint_Opaque(string endpoint)
    {
        var root = Ecs(new BruceEvent { RemoteEndpoints = new[] { endpoint }, TimeUtc = default });
        Assert.False(TelemetrySchemaFixtures.Has(root, "destination", "port"));
        Assert.Equal(endpoint, TelemetrySchemaFixtures.At(root, "destination", "address").GetString());
    }

    [Fact]
    public void Multiple_Endpoints_Do_Not_Guess_A_Destination()
    {
        var root = Ecs(new BruceEvent
        {
            RemoteEndpoints = new[] { "1.2.3.4:80", "5.6.7.8:443" },
            TimeUtc = default
        });
        Assert.False(TelemetrySchemaFixtures.Has(root, "destination"));
        Assert.Equal(new[] { "1.2.3.4", "5.6.7.8" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "related", "ip")));
        Assert.Equal(new[] { "1.2.3.4:80", "5.6.7.8:443" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "bruceedr", "remote_endpoints")));
    }

    [Fact]
    public void Dns_Questions_Are_An_Array()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        Assert.Equal(new[] { "cdn.example.test" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "dns", "question", "name")));
    }

    [Fact]
    public void Incident_Id_Is_A_String_Label()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        var v = TelemetrySchemaFixtures.At(root, "labels", "incident_id");
        Assert.Equal(JsonValueKind.String, v.ValueKind);
        Assert.Equal("INC-0001", v.GetString());
    }

    [Fact]
    public void Custom_Fields_Are_Preserved_Under_The_Product_Namespace()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        var ps = TelemetrySchemaFixtures.At(root, "bruceedr");
        Assert.Equal("QUARANTINE", ps.GetProperty("level").GetString());
        Assert.Equal("detection", ps.GetProperty("category").GetString());
        Assert.Equal(2, TelemetrySchemaFixtures.Strings(ps.GetProperty("reasons")).Length);
        Assert.Single(TelemetrySchemaFixtures.Strings(ps.GetProperty("staged_archives")));
        Assert.Equal(new[] { "winword.exe", "explorer.exe" },
            TelemetrySchemaFixtures.Strings(ps.GetProperty("ancestry")));
    }

    [Fact]
    public void Event_Reason_Joins_The_Reason_Lines()
    {
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        string reason = TelemetrySchemaFixtures.At(root, "event", "reason").GetString() ?? "";
        Assert.Contains("read Login Data", reason);
        Assert.Contains("staged loot.zip", reason);
    }

    [Fact]
    public void Message_Falls_Back_To_A_Summary_Rather_Than_Being_Empty()
    {
        var root = Ecs(new BruceEvent
        {
            Level = "WARN", Process = "evil.exe", Pid = 7, Trigger = "beaconing", Message = "", TimeUtc = default
        });
        string msg = root.GetProperty("message").GetString() ?? "";
        Assert.Contains("WARN", msg);
        Assert.Contains("evil.exe", msg);
        Assert.Contains("7", msg);
    }

    [Fact]
    public void Uses_Nested_Objects_Not_Dotted_Keys()
    {
        // Dotted keys survive ingest but break runtime fields and copy_to in Elastic.
        var root = Ecs(TelemetrySchemaFixtures.Rich());
        AssertNoDots(root);

        static void AssertNoDots(JsonElement el)
        {
            switch (el.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var p in el.EnumerateObject())
                    {
                        Assert.DoesNotContain('.', p.Name);
                        AssertNoDots(p.Value);
                    }
                    break;
                case JsonValueKind.Array:
                    foreach (var v in el.EnumerateArray()) AssertNoDots(v);
                    break;
            }
        }
    }

    [Fact]
    public void Event_Id_Is_Stable_For_Identical_Events_And_Differs_Otherwise()
    {
        var a = TelemetrySchemaFixtures.Rich();
        var b = TelemetrySchemaFixtures.Rich();
        var c = a with { Score = 96 };
        string ida = TelemetrySchemaFixtures.At(Ecs(a), "event", "id").GetString()!;
        string idb = TelemetrySchemaFixtures.At(Ecs(b), "event", "id").GetString()!;
        string idc = TelemetrySchemaFixtures.At(Ecs(c), "event", "id").GetString()!;
        Assert.Equal(ida, idb);
        Assert.NotEqual(ida, idc);
        Assert.Equal(32, ida.Length);
    }

    [Fact]
    public void Unspecified_Kind_Timestamp_Is_Treated_As_Utc_Not_Shifted()
    {
        // Every producer in the codebase fills TimeUtc from a UTC clock; converting an
        // Unspecified kind would silently move the event by the local offset.
        var e = new BruceEvent { TimeUtc = new DateTime(2026, 3, 4, 5, 6, 7, 890, DateTimeKind.Unspecified) };
        Assert.Equal("2026-03-04T05:06:07.890Z", Ecs(e).GetProperty("@timestamp").GetString());
    }
}

/// <summary>OCSF 1.1 Detection Finding shape.</summary>
public class TelemetryOcsfFormatterTests
{
    private static JsonElement Ocsf(BruceEvent e)
        => TelemetrySchemaFixtures.Parse(new OcsfFormatter(TelemetrySchemaFixtures.Host).Format(e));

    [Fact]
    public void Emits_The_Detection_Finding_Class_Identifiers()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        Assert.Equal(2004, root.GetProperty("class_uid").GetInt32());
        Assert.Equal(2, root.GetProperty("category_uid").GetInt32());
        Assert.Equal(1, root.GetProperty("activity_id").GetInt32());
        Assert.Equal(200401, root.GetProperty("type_uid").GetInt32());
    }

    [Fact]
    public void Metadata_Names_The_Product_And_Schema_Version()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        Assert.Equal("1.1.0", TelemetrySchemaFixtures.At(root, "metadata", "version").GetString());
        Assert.Equal("BruceEDR", TelemetrySchemaFixtures.At(root, "metadata", "product", "name").GetString());
        Assert.Equal("BruceEDR", TelemetrySchemaFixtures.At(root, "metadata", "product", "vendor_name").GetString());
        Assert.Equal(EventFormatters.AgentVersion,
            TelemetrySchemaFixtures.At(root, "metadata", "product", "version").GetString());
    }

    [Theory]
    [InlineData("QUARANTINE", 5)]
    [InlineData("WARN", 3)]
    [InlineData("ACTION", 2)]
    [InlineData("INFO", 1)]
    [InlineData("weird", 0)]
    public void Severity_Id_Follows_The_Ocsf_Scale(string level, int expected)
        => Assert.Equal(expected, Ocsf(new BruceEvent { Level = level, TimeUtc = default })
            .GetProperty("severity_id").GetInt32());

    [Theory]
    [InlineData("detection", "QUARANTINE", 1)]   // New
    [InlineData("detection", "WARN", 1)]
    [InlineData("response", "ACTION", 4)]        // Resolved: the agent already acted
    [InlineData("system", "INFO", 99)]           // Other: not a finding at all
    public void Status_Id_Distinguishes_Findings_From_Chatter(string category, string level, int expected)
        => Assert.Equal(expected, Ocsf(new BruceEvent { Category = category, Level = level, TimeUtc = default })
            .GetProperty("status_id").GetInt32());

    [Fact]
    public void Time_Is_Unix_Milliseconds()
    {
        var e = TelemetrySchemaFixtures.Rich();
        long expected = (long)(e.TimeUtc - DateTime.UnixEpoch).TotalMilliseconds;
        Assert.Equal(expected, Ocsf(e).GetProperty("time").GetInt64());
    }

    [Fact]
    public void Unset_Time_Clamps_To_Zero_Instead_Of_Going_Negative()
    {
        // A negative epoch is rejected outright by several lakes, which would drop the
        // record rather than store an obviously wrong timestamp.
        Assert.Equal(0, Ocsf(TelemetrySchemaFixtures.Empty()).GetProperty("time").GetInt64());
    }

    [Fact]
    public void Finding_Info_Uses_The_Incident_Id_As_Uid()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        Assert.Equal("INC-0001", TelemetrySchemaFixtures.At(root, "finding_info", "uid").GetString());
        Assert.Equal("Credential store read then archived",
            TelemetrySchemaFixtures.At(root, "finding_info", "title").GetString());
        Assert.Equal(new[] { "browser-cred-read", "archive-staging" },
            TelemetrySchemaFixtures.Strings(TelemetrySchemaFixtures.At(root, "finding_info", "types")));
    }

    [Fact]
    public void Finding_Uid_Falls_Back_To_The_Content_Id()
    {
        var root = Ocsf(new BruceEvent { Level = "WARN", Pid = 3, TimeUtc = default });
        string uid = TelemetrySchemaFixtures.At(root, "finding_info", "uid").GetString() ?? "";
        Assert.Equal(32, uid.Length);
        Assert.Equal(uid, TelemetrySchemaFixtures.At(root, "metadata", "uid").GetString());
    }

    [Fact]
    public void Process_Object_Uses_Ocsf_Names()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        var p = TelemetrySchemaFixtures.At(root, "process");
        Assert.Equal(4242, p.GetProperty("pid").GetInt32());
        Assert.Equal("powershell.exe", p.GetProperty("name").GetString());
        Assert.Contains("-enc", p.GetProperty("cmd_line").GetString());
        Assert.Equal("powershell.exe", TelemetrySchemaFixtures.At(p, "file", "name").GetString());
        Assert.Contains(@"\System32\", TelemetrySchemaFixtures.At(p, "file", "path").GetString());
        Assert.Equal(1234, TelemetrySchemaFixtures.At(p, "parent_process", "pid").GetInt32());
        Assert.Equal(@"CONTOSO\alice", TelemetrySchemaFixtures.At(p, "user", "name").GetString());
    }

    [Fact]
    public void File_Hash_Uses_The_Sha256_Algorithm_Id()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        var hashes = TelemetrySchemaFixtures.At(root, "process", "file", "hashes");
        var first = hashes.EnumerateArray().First();
        Assert.Equal(3, first.GetProperty("algorithm_id").GetInt32());
        Assert.Equal(new string('a', 64), first.GetProperty("value").GetString());
    }

    [Fact]
    public void Attacks_Carry_Technique_And_Tactic()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        var attacks = root.GetProperty("attacks").EnumerateArray().ToArray();
        Assert.Equal(2, attacks.Length);
        Assert.Equal("T1555.003", TelemetrySchemaFixtures.At(attacks[0], "technique", "uid").GetString());
        Assert.Equal("Credential Access", TelemetrySchemaFixtures.At(attacks[0], "tactic", "name").GetString());
        Assert.False(string.IsNullOrWhiteSpace(attacks[0].GetProperty("version").GetString()));
    }

    [Fact]
    public void Attacks_Are_Omitted_When_No_Technique_Was_Cited()
        => Assert.False(TelemetrySchemaFixtures.Has(Ocsf(TelemetrySchemaFixtures.Empty()), "attacks"));

    [Fact]
    public void Observables_Cover_Endpoints_Domains_Hash_And_Process()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        var obs = root.GetProperty("observables").EnumerateArray()
            .Select(o => (o.GetProperty("name").GetString() ?? "",
                          o.GetProperty("type_id").GetInt32(),
                          o.GetProperty("value").GetString() ?? ""))
            .ToArray();
        Assert.Contains(("dst_endpoint.ip", 2, "203.0.113.10"), obs);
        Assert.Contains(("dns_query.hostname", 1, "cdn.example.test"), obs);
        Assert.Contains(("file.hashes", 8, new string('a', 64)), obs);
        Assert.Contains(("process.name", 9, "powershell.exe"), obs);
    }

    [Fact]
    public void Duplicate_Observables_Are_Collapsed()
    {
        var root = Ocsf(new BruceEvent
        {
            Domains = new[] { "a.test", "a.test", "A.TEST" },
            TimeUtc = default
        });
        Assert.Single(root.GetProperty("observables").EnumerateArray());
    }

    [Fact]
    public void Unmapped_Preserves_What_Ocsf_Has_No_Slot_For()
    {
        var root = Ocsf(TelemetrySchemaFixtures.Rich());
        var u = TelemetrySchemaFixtures.At(root, "unmapped");
        Assert.Equal("QUARANTINE", u.GetProperty("level").GetString());
        Assert.Equal("detection", u.GetProperty("category").GetString());
        Assert.Equal(TelemetrySchemaFixtures.Host, u.GetProperty("hostname").GetString());
        Assert.Equal(2, TelemetrySchemaFixtures.Strings(u.GetProperty("reasons")).Length);
        Assert.Equal(new[] { "winword.exe", "explorer.exe" },
            TelemetrySchemaFixtures.Strings(u.GetProperty("ancestry")));
    }

    [Fact]
    public void Risk_Score_Is_Carried_Through()
        => Assert.Equal(95, Ocsf(TelemetrySchemaFixtures.Rich()).GetProperty("risk_score").GetInt32());
}

/// <summary>CEF header/extension shape and, above all, the escaping rules.</summary>
public class TelemetryCefFormatterTests
{
    private static string Cef(BruceEvent e) => new CefFormatter(TelemetrySchemaFixtures.Host).Format(e);

    [Fact]
    public void Header_Has_Seven_Pipe_Delimited_Fields()
    {
        var f = TelemetrySchemaFixtures.SplitCef(Cef(TelemetrySchemaFixtures.Rich()));
        Assert.Equal(8, f.Length);   // 7 header fields + the extension remainder
        Assert.Equal("CEF:0", f[0]);
        Assert.Equal("BruceEDR", f[1]);
        Assert.Equal("BruceEDR", f[2]);
        Assert.Equal(EventFormatters.AgentVersion, f[3]);
        Assert.Equal("browser-cred-read", f[4]);
        Assert.Equal("Credential store read then archived", f[5]);
        Assert.Equal("9", f[6]);
    }

    [Theory]
    [InlineData("QUARANTINE", "9")]
    [InlineData("WARN", "6")]
    [InlineData("ACTION", "3")]
    [InlineData("INFO", "1")]
    [InlineData("", "0")]
    public void Severity_Maps_Into_The_Zero_To_Ten_Range(string level, string expected)
        => Assert.Equal(expected, TelemetrySchemaFixtures.SplitCef(
            Cef(new BruceEvent { Level = level, TimeUtc = default }))[6]);

    [Fact]
    public void Header_Escapes_Pipe_And_Backslash_And_Survives_A_Round_Trip()
    {
        var e = new BruceEvent
        {
            RuleIds = new[] { @"a|b\c" },
            Trigger = @"pipe | and \ backslash",
            TimeUtc = default
        };
        var f = TelemetrySchemaFixtures.SplitCef(Cef(e));
        Assert.Equal(@"a|b\c", f[4]);
        Assert.Equal(@"pipe | and \ backslash", f[5]);
    }

    [Fact]
    public void Header_Never_Contains_A_Line_Break()
    {
        // CEF headers may not span lines, so breaks are folded to spaces before escaping.
        var line = Cef(new BruceEvent { Trigger = "one\ntwo\r\nthree", TimeUtc = default });
        var f = TelemetrySchemaFixtures.SplitCef(line);
        Assert.DoesNotContain('\n', f[5]);
        Assert.DoesNotContain('\r', f[5]);
        Assert.Contains("one two", f[5]);
    }

    [Fact]
    public void Extension_Escapes_Equals_And_Backslash_But_Not_Pipe()
    {
        var e = new BruceEvent
        {
            Trigger = "t",
            Message = "a=b" + @"\c" + "|d\ne",
            TimeUtc = default
        };
        string line = Cef(e);
        // Expected on the wire: msg=a\=b\\c|d\ne
        Assert.Contains(@"msg=a\=b\\c|d\ne", line);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a=b", @"a\=b")]
    [InlineData(@"a\b", @"a\\b")]
    [InlineData("a|b", "a|b")]                 // pipe is only special in the header
    [InlineData("a\nb", @"a\nb")]
    [InlineData("a\r\nb", @"a\r\nb")]
    [InlineData(@"a\=b", @"a\\\=b")]           // pre-escaped input must be re-escaped
    public void Extension_Value_Escaping_Matrix(string raw, string expected)
    {
        // Routed through cs4 (IncidentId), which has no other transformation applied.
        string line = Cef(new BruceEvent { IncidentId = raw, TimeUtc = default });
        Assert.Contains("cs4=" + expected + " ", line + " ");
    }

    [Fact]
    public void Timestamp_Is_Unix_Milliseconds_In_Rt()
    {
        var e = TelemetrySchemaFixtures.Rich();
        long expected = (long)(e.TimeUtc - DateTime.UnixEpoch).TotalMilliseconds;
        Assert.Contains("rt=" + expected.ToString(CultureInfo.InvariantCulture), Cef(e));
    }

    [Fact]
    public void Single_Endpoint_Becomes_Dst_And_Dpt()
    {
        string line = Cef(TelemetrySchemaFixtures.Rich());
        Assert.Contains("dst=203.0.113.10", line);
        Assert.Contains("dpt=443", line);
    }

    [Fact]
    public void Multiple_Endpoints_Go_To_A_Labelled_Custom_Slot()
    {
        string line = Cef(new BruceEvent
        {
            RemoteEndpoints = new[] { "1.2.3.4:80", "5.6.7.8:443" },
            TimeUtc = default
        });
        Assert.DoesNotContain("dst=", line);
        Assert.Contains("flexString1=1.2.3.4:80,5.6.7.8:443", line);
        Assert.Contains("flexString1Label=RemoteEndpoints", line);
    }

    [Fact]
    public void Custom_Slots_Are_Labelled()
    {
        string line = Cef(TelemetrySchemaFixtures.Rich());
        Assert.Contains("cs1=T1555.003,T1560.001", line);
        Assert.Contains("cs1Label=MitreTechniques", line);
        Assert.Contains("cs2Label=RuleIds", line);
        Assert.Contains("cs3Label=Reasons", line);
        Assert.Contains("cs4=INC-0001", line);
        Assert.Contains("cn1=95", line);
        Assert.Contains("cn1Label=Score", line);
        Assert.Contains("cn2=1234", line);
    }

    [Fact]
    public void Empty_Event_Still_Produces_A_Valid_Header()
    {
        var f = TelemetrySchemaFixtures.SplitCef(Cef(TelemetrySchemaFixtures.Empty()));
        Assert.Equal(8, f.Length);
        Assert.Equal("CEF:0", f[0]);
        Assert.Equal("bruceedr", f[4]);   // signature id fallback
        Assert.False(string.IsNullOrWhiteSpace(f[5]));
    }
}

/// <summary>File sink behaviour: one record per line, failures counted not thrown.</summary>
public class TelemetryFormattingSinkTests : IDisposable
{
    private readonly string _dir = Path.Combine(
        Path.GetTempPath(), "bruce_fmt_" + Guid.NewGuid().ToString("N"));

    public TelemetryFormattingSinkTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private string PathFor(string name) => Path.Combine(_dir, name);

    [Fact]
    public void Writes_One_Parsable_Json_Line_Per_Event()
    {
        string path = PathFor("ecs.log");
        using var sink = new FormattingSink(path, new EcsFormatter(TelemetrySchemaFixtures.Host));
        sink.Emit(TelemetrySchemaFixtures.Rich());
        sink.Emit(TelemetrySchemaFixtures.Rich() with { Pid = 2 });
        sink.Emit(TelemetrySchemaFixtures.Empty());

        var lines = File.ReadAllLines(path);
        Assert.Equal(3, lines.Length);
        foreach (var l in lines)
            Assert.Equal(JsonValueKind.Object, JsonDocument.Parse(l).RootElement.ValueKind);
        Assert.Equal(0, sink.Errors);
    }

    [Fact]
    public void Resolves_The_Formatter_By_Name()
    {
        string path = PathFor("byname.log");
        using var sink = new FormattingSink(path, "cef");
        Assert.Equal("cef", sink.FormatName);
        Assert.Equal(path, sink.FilePath);
        sink.Emit(TelemetrySchemaFixtures.Rich());
        Assert.StartsWith("CEF:0|", File.ReadAllLines(path)[0]);
    }

    [Fact]
    public void Creates_The_Parent_Directory()
    {
        string path = Path.Combine(_dir, "nested", "deeper", "out.log");
        using var sink = new FormattingSink(path, new NativeFormatter());
        sink.Emit(new BruceEvent { Level = "INFO" });
        Assert.True(File.Exists(path));
    }

    [Fact]
    public void An_Unwritable_Path_Counts_An_Error_Instead_Of_Throwing()
    {
        // A full disk or a revoked ACL must never take detection down with it.
        string path = Path.Combine(_dir, "a-directory");
        Directory.CreateDirectory(path);
        using var sink = new FormattingSink(path, new NativeFormatter());
        sink.Emit(new BruceEvent { Level = "INFO" });
        Assert.Equal(1, sink.Errors);
    }

    [Fact]
    public void A_Throwing_Formatter_Is_Counted_Not_Propagated()
    {
        using var sink = new FormattingSink(PathFor("bad.log"), new ThrowingFormatter());
        sink.Emit(new BruceEvent());
        Assert.Equal(1, sink.Errors);
        Assert.False(File.Exists(PathFor("bad.log")));
    }

    [Fact]
    public void A_Multiline_Formatter_Cannot_Break_The_One_Record_Per_Line_Contract()
    {
        string path = PathFor("multiline.log");
        using (var sink = new FormattingSink(path, new MultilineFormatter()))
            sink.Emit(new BruceEvent());
        Assert.Single(File.ReadAllLines(path));
    }

    [Fact]
    public void Concurrent_Emits_Do_Not_Interleave()
    {
        string path = PathFor("concurrent.log");
        using (var sink = new FormattingSink(path, new EcsFormatter(TelemetrySchemaFixtures.Host)))
        {
            Parallel.For(0, 400, i => sink.Emit(TelemetrySchemaFixtures.Rich() with { Pid = i }));
        }

        var lines = File.ReadAllLines(path);
        Assert.Equal(400, lines.Length);
        foreach (var l in lines)
            Assert.Equal(JsonValueKind.Object, JsonDocument.Parse(l).RootElement.ValueKind);
    }

    [Fact]
    public void Null_Arguments_Are_Rejected_At_Construction()
    {
        Assert.Throws<ArgumentNullException>(() => new FormattingSink(null!, new NativeFormatter()));
        Assert.Throws<ArgumentNullException>(() => new FormattingSink(PathFor("x.log"), (IEventFormatter)null!));
    }

    private sealed class ThrowingFormatter : IEventFormatter
    {
        public string Name => "throwing";
        public string Format(BruceEvent e) => throw new InvalidOperationException("boom");
    }

    private sealed class MultilineFormatter : IEventFormatter
    {
        public string Name => "multiline";
        public string Format(BruceEvent e) => "a\nb\r\nc";
    }
}

/// <summary>Counters, reservoir percentiles and the Prometheus rendering.</summary>
public class TelemetryMetricsTests
{
    private static BruceMetrics New(out ManualClock clock)
    {
        clock = new ManualClock(new DateTime(2026, 5, 1, 12, 0, 0, DateTimeKind.Utc));
        return new BruceMetrics(clock);
    }

    [Fact]
    public void Counters_Start_At_Zero()
    {
        var s = New(out _).Snapshot();
        Assert.Equal(0, s.Signals);
        Assert.Equal(0, s.Dropped);
        Assert.Equal(0, s.Warns);
        Assert.Equal(0, s.Quarantines);
        Assert.Equal(0, s.ResponsesOk);
        Assert.Equal(0, s.ResponsesFailed);
        Assert.Equal(0, s.LatencyP50Ms);
        Assert.Equal(0, s.LatencySamples);
        Assert.Empty(s.Gauges);
    }

    [Fact]
    public void Counters_Accumulate()
    {
        var m = New(out _);
        m.IncSignals();
        m.IncSignals(9);
        m.IncDropped(3);
        m.IncResponses(true);
        m.IncResponses(true);
        m.IncResponses(false);
        var s = m.Snapshot();
        Assert.Equal(10, s.Signals);
        Assert.Equal(3, s.Dropped);
        Assert.Equal(2, s.ResponsesOk);
        Assert.Equal(1, s.ResponsesFailed);
    }

    [Theory]
    [InlineData("WARN", 1, 0)]
    [InlineData("warn", 1, 0)]
    [InlineData("  Quarantine  ", 0, 1)]
    [InlineData("INFO", 0, 0)]
    [InlineData("ACTION", 0, 0)]
    [InlineData("", 0, 0)]
    public void Detections_Are_Only_Counted_For_Real_Verdicts(string level, long warns, long quarantines)
    {
        var m = New(out _);
        m.IncDetections(level);
        var s = m.Snapshot();
        Assert.Equal(warns, s.Warns);
        Assert.Equal(quarantines, s.Quarantines);
    }

    [Fact]
    public void IncDetections_Tolerates_Null()
    {
        var m = New(out _);
        m.IncDetections(null!);
        Assert.Equal(0, m.Snapshot().Warns);
    }

    [Fact]
    public void Percentiles_Use_Nearest_Rank_Over_The_Observations()
    {
        var m = New(out _);
        for (int i = 1; i <= 100; i++) m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(i));
        var s = m.Snapshot();
        Assert.Equal(50, s.LatencyP50Ms);
        Assert.Equal(95, s.LatencyP95Ms);
        Assert.Equal(99, s.LatencyP99Ms);
        Assert.Equal(100, s.LatencySamples);
        Assert.Equal(5050, s.LatencySumMs, 3);
    }

    [Fact]
    public void A_Single_Observation_Is_Every_Percentile()
    {
        var m = New(out _);
        m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(7));
        var s = m.Snapshot();
        Assert.Equal(7, s.LatencyP50Ms);
        Assert.Equal(7, s.LatencyP99Ms);
    }

    [Fact]
    public void Reservoir_Slides_So_Percentiles_Reflect_Recent_Behaviour()
    {
        // The whole point of a bounded reservoir: an agent that was fast an hour ago and
        // is slow now must report slow.
        var m = New(out _);
        for (int i = 0; i < 4000; i++) m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(1));
        for (int i = 0; i < BruceMetrics.ReservoirSize; i++) m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(100));
        var s = m.Snapshot();
        Assert.Equal(100, s.LatencyP50Ms);
        Assert.Equal(4000 + BruceMetrics.ReservoirSize, s.LatencySamples);
    }

    [Fact]
    public void Negative_Latency_Is_Clamped_Rather_Than_Poisoning_The_Percentiles()
    {
        var m = New(out _);
        m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(-500));
        var s = m.Snapshot();
        Assert.Equal(0, s.LatencyP50Ms);
        Assert.Equal(1, s.LatencySamples);
        Assert.Equal(0, s.LatencySumMs);
    }

    [Fact]
    public void Sub_Millisecond_Latency_Is_Not_Rounded_Away()
    {
        var m = New(out _);
        m.ObserveDetectionLatency(TimeSpan.FromTicks(TimeSpan.TicksPerMillisecond / 4));
        Assert.Equal(0.25, m.Snapshot().LatencyP50Ms, 6);
    }

    [Fact]
    public void Gauges_Are_Set_And_Overwritten()
    {
        var m = New(out _);
        m.SetGauge("queue_depth", 5);
        m.SetGauge("queue_depth", 9);
        m.SetGauge("tracked_processes", 42);
        var g = m.Snapshot().Gauges;
        Assert.Equal(9, g["queue_depth"]);
        Assert.Equal(42, g["tracked_processes"]);
    }

    [Fact]
    public void Blank_Gauge_Names_Are_Ignored_Not_Thrown()
    {
        var m = New(out _);
        m.SetGauge("", 1);
        m.SetGauge("   ", 1);
        m.SetGauge(null!, 1);
        Assert.Empty(m.Snapshot().Gauges);
    }

    [Fact]
    public void Snapshot_Is_A_Frozen_Copy()
    {
        var m = New(out _);
        m.IncSignals();
        var first = m.Snapshot();
        m.IncSignals(100);
        m.SetGauge("later", 1);
        Assert.Equal(1, first.Signals);
        Assert.Empty(first.Gauges);
    }

    [Fact]
    public void Snapshot_Reads_The_Injected_Clock()
    {
        var m = New(out var clock);
        clock.Advance(TimeSpan.FromHours(3));
        Assert.Equal(new DateTime(2026, 5, 1, 15, 0, 0, DateTimeKind.Utc), m.Snapshot().CollectedUtc);
    }

    [Fact]
    public void All_Counters_Are_Thread_Safe()
    {
        var m = New(out _);
        Parallel.For(0, 2000, i =>
        {
            m.IncSignals();
            m.IncDetections(i % 2 == 0 ? "WARN" : "QUARANTINE");
            m.IncResponses(i % 3 != 0);
            m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(i % 50));
            m.SetGauge("g" + (i % 4), i);
        });

        var s = m.Snapshot();
        Assert.Equal(2000, s.Signals);
        Assert.Equal(1000, s.Warns);
        Assert.Equal(1000, s.Quarantines);
        Assert.Equal(2000, s.ResponsesOk + s.ResponsesFailed);
        Assert.Equal(2000, s.LatencySamples);
        Assert.Equal(4, s.Gauges.Count);
    }

    [Fact]
    public void Prometheus_Text_Declares_Help_And_Type_For_Every_Metric()
    {
        var m = New(out _);
        m.SetGauge("queue_depth", 3);
        string text = m.ToPrometheusText();

        foreach (var name in new[]
                 {
                     "bruceedr_signals_total", "bruceedr_signals_dropped_total",
                     "bruceedr_detections_total", "bruceedr_responses_total",
                     "bruceedr_detection_latency_ms", "bruceedr_queue_depth"
                 })
        {
            Assert.Contains("# HELP " + name + " ", text);
            Assert.Contains("# TYPE " + name + " ", text);
        }
    }

    [Fact]
    public void Prometheus_Uses_Bare_Line_Feeds()
    {
        // A scraper rejects CRLF, which is exactly what a Windows-default newline gives.
        Assert.DoesNotContain("\r", New(out _).ToPrometheusText());
    }

    [Fact]
    public void Prometheus_Blocks_Are_Sorted_By_Metric_Name()
    {
        var m = New(out _);
        m.SetGauge("zeta", 1);
        m.SetGauge("alpha", 2);
        var names = m.ToPrometheusText()
            .Split('\n')
            .Where(l => l.StartsWith("# TYPE ", StringComparison.Ordinal))
            .Select(l => l.Split(' ')[2])
            .ToArray();
        Assert.Equal(names.OrderBy(n => n, StringComparer.Ordinal).ToArray(), names);
    }

    [Fact]
    public void Prometheus_Output_Is_Byte_Stable_For_An_Unchanged_Snapshot()
    {
        var m = New(out _);
        m.IncSignals(5);
        m.SetGauge("b", 2);
        m.SetGauge("a", 1);
        m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(3));
        Assert.Equal(m.ToPrometheusText(), m.ToPrometheusText());
    }

    [Fact]
    public void Prometheus_Renders_The_Expected_Counter_Lines()
    {
        var m = New(out _);
        m.IncSignals(7);
        m.IncDropped(2);
        m.IncDetections("WARN");
        m.IncDetections("QUARANTINE");
        m.IncDetections("QUARANTINE");
        m.IncResponses(true);
        m.IncResponses(false);
        string text = m.ToPrometheusText();

        Assert.Contains("\nbruceedr_signals_total 7\n", "\n" + text);
        Assert.Contains("\nbruceedr_signals_dropped_total 2\n", "\n" + text);
        Assert.Contains("bruceedr_detections_total{level=\"warn\"} 1\n", text);
        Assert.Contains("bruceedr_detections_total{level=\"quarantine\"} 2\n", text);
        Assert.Contains("bruceedr_responses_total{result=\"ok\"} 1\n", text);
        Assert.Contains("bruceedr_responses_total{result=\"failed\"} 1\n", text);
    }

    [Fact]
    public void Prometheus_Summary_Has_Quantiles_Count_And_Sum()
    {
        var m = New(out _);
        for (int i = 1; i <= 10; i++) m.ObserveDetectionLatency(TimeSpan.FromMilliseconds(i));
        string text = m.ToPrometheusText();
        Assert.Contains("# TYPE bruceedr_detection_latency_ms summary\n", text);
        Assert.Contains("bruceedr_detection_latency_ms{quantile=\"0.5\"} 5\n", text);
        Assert.Contains("bruceedr_detection_latency_ms{quantile=\"0.95\"} 10\n", text);
        Assert.Contains("bruceedr_detection_latency_ms{quantile=\"0.99\"} 10\n", text);
        Assert.Contains("bruceedr_detection_latency_ms_count 10\n", text);
        Assert.Contains("bruceedr_detection_latency_ms_sum 55\n", text);
    }

    [Fact]
    public void Gauge_Names_Are_Mapped_Into_The_Prometheus_Grammar()
    {
        var m = New(out _);
        m.SetGauge("queue depth (pending)", 4);
        string text = m.ToPrometheusText();
        Assert.Contains("bruceedr_queue_depth_pending 4\n", text);
    }

    [Fact]
    public void Gauge_Name_Is_Not_Double_Prefixed()
    {
        var m = New(out _);
        m.SetGauge("bruceedr_custom", 1);
        Assert.Contains("\nbruceedr_custom 1\n", "\n" + m.ToPrometheusText());
        Assert.DoesNotContain("bruceedr_bruceedr_custom", m.ToPrometheusText());
    }

    [Fact]
    public void Colliding_Gauge_Names_Do_Not_Emit_Duplicate_Metric_Lines()
    {
        // "a b" and "a-b" both sanitise to a_b; duplicate lines break scrapers.
        var m = New(out _);
        m.SetGauge("a b", 1);
        m.SetGauge("a-b", 2);
        string text = m.ToPrometheusText();
        int typeLines = text.Split('\n').Count(l => l == "# TYPE bruceedr_a_b gauge");
        Assert.Equal(1, typeLines);
    }

    [Fact]
    public void A_Gauge_Cannot_Shadow_A_Built_In_Metric()
    {
        // Without this guard a gauge called "signals_total" would emit a second block
        // under the same name and the scrape would be rejected wholesale.
        var m = New(out _);
        m.IncSignals(7);
        m.SetGauge("signals total", 99);
        m.SetGauge("detection_latency_ms_count", 99);
        string text = m.ToPrometheusText();
        Assert.Equal(1, text.Split('\n').Count(l => l == "# TYPE bruceedr_signals_total counter"));
        Assert.Contains("bruceedr_signals_total 7\n", text);
        Assert.DoesNotContain("bruceedr_signals_total 99", text);
        Assert.DoesNotContain("bruceedr_detection_latency_ms_count 99", text);
    }

    [Fact]
    public void A_Gauge_Name_With_Nothing_Usable_Is_Dropped()
    {
        var m = New(out _);
        m.SetGauge("!!!", 1);
        Assert.DoesNotContain("gauge", m.ToPrometheusText());
    }

    [Fact]
    public void Help_Text_Escapes_The_Raw_Gauge_Name()
    {
        var m = New(out _);
        m.SetGauge(@"weird\name", 1);
        string text = m.ToPrometheusText();
        Assert.Contains(@"Gauge 'weird\\name' reported by BruceEDR.", text);
        Assert.Contains("bruceedr_weird_name 1\n", text);
    }

    [Theory]
    [InlineData(double.NaN, "NaN")]
    [InlineData(double.PositiveInfinity, "+Inf")]
    [InlineData(double.NegativeInfinity, "-Inf")]
    [InlineData(-0.0, "0")]
    [InlineData(1.5, "1.5")]
    [InlineData(-2.25, "-2.25")]
    public void Prometheus_Formats_Non_Finite_And_Fractional_Values(double value, string expected)
    {
        var m = New(out _);
        m.SetGauge("v", value);
        Assert.Contains("bruceedr_v " + expected + "\n", m.ToPrometheusText());
    }

    [Fact]
    public void Prometheus_Numbers_Are_Invariant_Not_Locale_Formatted()
    {
        // A comma decimal separator (de-DE, fr-FR) would silently corrupt every scrape.
        var previous = Thread.CurrentThread.CurrentCulture;
        try
        {
            Thread.CurrentThread.CurrentCulture = new CultureInfo("de-DE");
            var m = New(out _);
            m.SetGauge("fraction", 1.5);
            Assert.Contains("bruceedr_fraction 1.5\n", m.ToPrometheusText());
        }
        finally { Thread.CurrentThread.CurrentCulture = previous; }
    }
}
