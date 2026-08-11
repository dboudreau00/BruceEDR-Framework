using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Replay;
using Xunit;

namespace ProcessShield.Tests;

// ---------------------------------------------------------------------------
// Tests for the trace replay subsystem (Replay/TraceFormat.cs, Replay/TraceReplay.cs
// and the shipped scenarios).
//
// Nothing here touches the network, starts a process or needs administrator rights.
// File IO is confined to a unique directory under Path.GetTempPath() and removed in a
// finally block.
// ---------------------------------------------------------------------------

/// <summary>
/// Records everything it is fed and returns whatever a caller-supplied script decides.
/// Deliberately not a rule engine: these tests must fail when the harness is wrong, not
/// when a detection rule changes.
/// </summary>
internal sealed class ReplayScriptedEngine : IReplayEngine
{
    private readonly IClock _clock;
    private readonly Func<Signal, IClock, IReadOnlyList<ReplayVerdict>?>? _script;

    public readonly List<Signal> Fed = new();
    public readonly List<DateTime> ClockAtFeed = new();
    public readonly Dictionary<int, int> ScoreTable = new();

    public ReplayScriptedEngine(IClock clock, Func<Signal, IClock, IReadOnlyList<ReplayVerdict>?>? script = null)
    {
        _clock = clock;
        _script = script;
    }

    public IReadOnlyList<ReplayVerdict> Feed(Signal signal)
    {
        Fed.Add(signal);
        ClockAtFeed.Add(_clock.UtcNow);
        ScoreTable.TryAdd(signal.Pid, 0);
        // The bang is intentional: a badly written adapter CAN return null and the
        // harness has to survive it, so the tests need a way to produce that.
        return _script is null ? Array.Empty<ReplayVerdict>() : _script(signal, _clock)!;
    }

    public IReadOnlyDictionary<int, int> Scores() => ScoreTable;
}

/// <summary>
/// A deliberately small re-implementation of the shipped heuristics (unusual parent,
/// command-line IOCs, credential stores, archive staging, exfil window, RAT modules).
///
/// It exists so the scenario files can be checked for plausibility without wiring up
/// DetectionEngine, ShieldHost or the response pipeline. It is NOT a copy of the engine
/// and must never be treated as one: if it and DetectionEngine ever disagree, the engine
/// is right. Its only job is to answer "does this trace look like an attack, and does the
/// benign trace look benign?".
///
/// It reads time from the injected clock rather than from the signal, so a bug in
/// TraceReplay's clock advancement shows up here as a missed correlation window.
/// </summary>
internal sealed class ReplayMiniRuleEngine : IReplayEngine
{
    private const int WarnAt = 40;
    private const int QuarantineAt = 70;
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(30);

    private readonly IClock _clock;
    private readonly Dictionary<int, int> _scores = new();
    private readonly Dictionary<int, string> _names = new();
    private readonly Dictionary<int, DateTime> _credentialAccess = new();
    private readonly Dictionary<int, DateTime> _archiveStaged = new();
    private readonly HashSet<string> _stagedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<int> _warned = new();
    private readonly HashSet<int> _contained = new();

    public ReplayMiniRuleEngine(IClock clock) => _clock = clock;

    public IReadOnlyList<ReplayVerdict> Feed(Signal s)
    {
        if (s.Pid <= 0) return Array.Empty<ReplayVerdict>();

        if (s.Kind == SignalKind.ProcessStart)
        {
            // Mirrors the engine's PID-reuse handling: a second ProcessStart for a pid
            // means Windows recycled it, so the old state must not carry over.
            _scores.Remove(s.Pid);
            _credentialAccess.Remove(s.Pid);
            _archiveStaged.Remove(s.Pid);
            _warned.Remove(s.Pid);
            _contained.Remove(s.Pid);
        }

        _scores.TryAdd(s.Pid, 0);
        if (!string.IsNullOrEmpty(s.ProcessName)) _names[s.Pid] = s.ProcessName.ToLowerInvariant();

        int before = _scores[s.Pid];
        var now = _clock.UtcNow;

        switch (s.Kind)
        {
            case SignalKind.ProcessStart:
            {
                string name = s.ProcessName.ToLowerInvariant();
                string parent = _names.TryGetValue(s.ParentPid, out var pn) ? pn : "";
                if (IocDatabase.LolBins.Contains(name) && IocDatabase.UnusualParents.Contains(parent))
                    Add(s.Pid, 45);
                string cmd = s.CommandLine.ToLowerInvariant();
                foreach (var ioc in IocDatabase.CommandLineIocs)
                    if (cmd.Contains(ioc)) Add(s.Pid, 15);
                break;
            }
            case SignalKind.ImageLoad:
            {
                string file = (s.FilePath ?? "").ToLowerInvariant();
                foreach (var frag in IocDatabase.SuspiciousModuleFragments)
                    if (file.Contains(frag)) Add(s.Pid, 50);
                break;
            }
            case SignalKind.FileCreate:
            {
                string file = (s.FilePath ?? "").ToLowerInvariant();
                if (file.Length == 0) break;
                if (IocDatabase.SensitiveFileFragments.Any(file.Contains))
                {
                    _credentialAccess[s.Pid] = now;
                    Add(s.Pid, 35);
                }
                bool archive = IocDatabase.ArchiveExtensions.Contains(Path.GetExtension(file));
                bool staging = IocDatabase.StagingDirFragments.Any(file.Contains);
                if (archive && staging && _stagedPaths.Add(file))
                {
                    _archiveStaged[s.Pid] = now;
                    Add(s.Pid, 30);
                    if (_credentialAccess.TryGetValue(s.Pid, out var c) && now - c <= Window) Add(s.Pid, 25);
                }
                break;
            }
            case SignalKind.NetworkConnect:
            {
                if (!NetworkUtil.IsRoutableRemote(s.RemoteAddress)) break;
                if (_archiveStaged.TryGetValue(s.Pid, out var t) && now - t <= Window) Add(s.Pid, 45);
                else if (_scores[s.Pid] >= WarnAt) Add(s.Pid, 15);
                break;
            }
        }

        int after = _scores[s.Pid];
        if (after == before) return Array.Empty<ReplayVerdict>();

        if (after >= QuarantineAt && _contained.Add(s.Pid))
            return new[] { Make(s, "Quarantine", after) };
        if (after >= WarnAt && after < QuarantineAt && _warned.Add(s.Pid))
            return new[] { Make(s, "Warn", after) };
        return Array.Empty<ReplayVerdict>();
    }

    public IReadOnlyDictionary<int, int> Scores() => _scores;

    private void Add(int pid, int points) => _scores[pid] = _scores[pid] + points;

    private static ReplayVerdict Make(Signal s, string verdict, int score) => new()
    {
        Pid = s.Pid,
        Verdict = verdict,
        Trigger = s.Kind.ToString(),
        Score = score,
        Reasons = new[] { $"{s.Kind} on {s.ProcessName}" }
    };
}

public class ReplayTraceFormatTests
{
    private static TraceScenario Parse(string text, out IReadOnlyList<string> warnings, string name = "unit")
        => TraceFormat.Parse(text.Split('\n'), name, out warnings);

    // ------------------------------------------------------------- happy path

    [Fact]
    public void Parse_Empty_Input_Yields_Empty_Scenario_With_Default_Start()
    {
        var s = TraceFormat.Parse(Array.Empty<string>(), "empty", out var w);
        Assert.Empty(s.Events);
        Assert.Empty(w);
        Assert.Equal("empty", s.Name);
        Assert.Equal(TraceFormat.DefaultStartUtc, s.StartUtc);
        Assert.Equal(TimeSpan.Zero, s.Duration);
    }

    [Fact]
    public void Parse_Null_Enumerable_Is_Treated_As_Empty()
    {
        var s = TraceFormat.Parse(null!, "n", out var w);
        Assert.Empty(s.Events);
        Assert.Empty(w);
    }

    [Fact]
    public void Parse_Meta_Populates_Every_Field()
    {
        var s = Parse("""
            {"meta":{"name":"chain","description":"a narrative","start":"2026-03-04T14:02:11Z","expect":["quarantine:pid=1","verdicts<=3"]}}
            """, out var w);

        Assert.Empty(w);
        Assert.Equal("chain", s.Name);
        Assert.Equal("a narrative", s.Description);
        Assert.Equal(new DateTime(2026, 3, 4, 14, 2, 11, DateTimeKind.Utc), s.StartUtc);
        Assert.Equal(DateTimeKind.Utc, s.StartUtc.Kind);
        Assert.Equal(new[] { "quarantine:pid=1", "verdicts<=3" }, s.Expect);
    }

    [Fact]
    public void Parse_Meta_Name_Wins_Over_Fallback()
    {
        var s = Parse("""{"meta":{"name":"from-meta"}}""", out _, name: "from-file");
        Assert.Equal("from-meta", s.Name);
    }

    [Fact]
    public void Parse_Fallback_Name_Used_When_Meta_Name_Blank()
    {
        var s = Parse("""{"meta":{"name":"   ","description":"d"}}""", out _, name: "from-file");
        Assert.Equal("from-file", s.Name);
    }

    [Fact]
    public void Parse_Reads_Every_Signal_Field()
    {
        var s = Parse("""
            {"meta":{"start":"2026-01-02T03:04:05Z"}}
            {"at":250,"kind":"ProcessAccess","pid":10,"parentPid":4,"processName":"a.exe","imagePath":"C:\\a.exe","commandLine":"a.exe -x","filePath":"C:\\f.txt","remoteAddress":"203.0.113.9","remotePort":8443,"detail":"d","targetPid":77,"desiredAccess":5136,"registryKey":"HKCU\\K","registryValue":"V","domain":"c2.example","scriptText":"iex","pipeName":"pipe1","user":"CORP\\u"}
            """, out var w);

        Assert.Empty(w);
        var sig = Assert.Single(s.Events).Signal;
        Assert.Equal(SignalKind.ProcessAccess, sig.Kind);
        Assert.Equal(10, sig.Pid);
        Assert.Equal(4, sig.ParentPid);
        Assert.Equal("a.exe", sig.ProcessName);
        Assert.Equal(@"C:\a.exe", sig.ImagePath);
        Assert.Equal("a.exe -x", sig.CommandLine);
        Assert.Equal(@"C:\f.txt", sig.FilePath);
        Assert.Equal("203.0.113.9", sig.RemoteAddress);
        Assert.Equal(8443, sig.RemotePort);
        Assert.Equal("d", sig.Detail);
        Assert.Equal(77, sig.TargetPid);
        Assert.Equal(5136u, sig.DesiredAccess);
        Assert.Equal(@"HKCU\K", sig.RegistryKey);
        Assert.Equal("V", sig.RegistryValue);
        Assert.Equal("c2.example", sig.Domain);
        Assert.Equal("iex", sig.ScriptText);
        Assert.Equal("pipe1", sig.PipeName);
        Assert.Equal(@"CORP\u", sig.User);
        Assert.Equal(new DateTime(2026, 1, 2, 3, 4, 5, 250, DateTimeKind.Utc), sig.TimestampUtc);
    }

    [Fact]
    public void Parse_Field_Names_Are_Case_Insensitive()
    {
        var s = Parse("""{"AT":100,"Kind":"FileCreate","PID":7,"FilePath":"C:\\x.zip"}""", out var w);
        Assert.Empty(w);
        var e = Assert.Single(s.Events);
        Assert.Equal(TimeSpan.FromMilliseconds(100), e.At);
        Assert.Equal(7, e.Signal.Pid);
        Assert.Equal(@"C:\x.zip", e.Signal.FilePath);
    }

    [Theory]
    [InlineData("ProcessStart", SignalKind.ProcessStart)]
    [InlineData("processstop", SignalKind.ProcessStop)]
    [InlineData("REGISTRYWRITE", SignalKind.RegistryWrite)]
    [InlineData("  DnsQuery  ", SignalKind.DnsQuery)]
    [InlineData("NamedPipe", SignalKind.NamedPipe)]
    [InlineData("ScriptContent", SignalKind.ScriptContent)]
    [InlineData("MemoryMatch", SignalKind.MemoryMatch)]
    public void Parse_Kind_Is_Case_Insensitive_And_Trimmed(string text, SignalKind expected)
    {
        var s = Parse($$"""{"kind":"{{text}}","pid":1}""", out var w);
        Assert.Empty(w);
        Assert.Equal(expected, Assert.Single(s.Events).Signal.Kind);
    }

    [Fact]
    public void Parse_Comment_Record_Is_Ignored_Without_Warning()
    {
        var s = Parse("""
            {"#":"this line explains the trace"}
            {"kind":"ProcessStop","pid":3}
            """, out var w);
        Assert.Empty(w);
        Assert.Single(s.Events);
    }

    [Theory]
    [InlineData("# a bare comment")]
    [InlineData("// another convention")]
    [InlineData("   ")]
    [InlineData("")]
    public void Parse_Ignores_Blank_And_Prefixed_Comment_Lines(string line)
    {
        var s = Parse(line + "\n" + """{"kind":"ProcessStop","pid":3}""", out var w);
        Assert.Empty(w);
        Assert.Single(s.Events);
    }

    // ------------------------------------------------------------- offsets

    [Fact]
    public void Parse_First_Event_Without_At_Starts_At_Zero()
    {
        var s = Parse("""{"kind":"ProcessStop","pid":1}""", out var w);
        Assert.Empty(w);
        Assert.Equal(TimeSpan.Zero, Assert.Single(s.Events).At);
    }

    [Fact]
    public void Parse_Missing_At_Reuses_Previous_Offset()
    {
        var s = Parse("""
            {"at":5000,"kind":"ProcessStop","pid":1}
            {"kind":"ProcessStop","pid":2}
            """, out var w);
        Assert.Empty(w);
        Assert.Equal(2, s.Events.Count);
        Assert.Equal(s.Events[0].At, s.Events[1].At);
    }

    [Fact]
    public void Parse_Negative_At_Is_Clamped_With_A_Warning()
    {
        var s = Parse("""
            {"at":1000,"kind":"ProcessStop","pid":1}
            {"at":-9000,"kind":"ProcessStop","pid":2}
            """, out var w);
        Assert.Contains(w, x => x.Contains("negative") && x.Contains("line 2"));
        Assert.Equal(TimeSpan.FromSeconds(1), s.Events[1].At);
    }

    [Fact]
    public void Parse_Backwards_At_Is_Clamped_So_The_Clock_Never_Rewinds()
    {
        var s = Parse("""
            {"at":5000,"kind":"ProcessStop","pid":1}
            {"at":2000,"kind":"ProcessStop","pid":2}
            {"at":6000,"kind":"ProcessStop","pid":3}
            """, out var w);
        Assert.Contains(w, x => x.Contains("earlier than the previous step"));
        Assert.Equal(TimeSpan.FromSeconds(5), s.Events[1].At);
        Assert.Equal(TimeSpan.FromSeconds(6), s.Events[2].At);
        Assert.True(s.Events[0].At <= s.Events[1].At && s.Events[1].At <= s.Events[2].At);
    }

    [Fact]
    public void Parse_Absurd_At_Is_Clamped_To_The_Cap()
    {
        var s = Parse("""{"at":9007199254740991,"kind":"ProcessStop","pid":1}""", out var w);
        Assert.Contains(w, x => x.Contains("cap"));
        Assert.Equal(TraceFormat.MaxOffset, Assert.Single(s.Events).At);
    }

    [Fact]
    public void Parse_Fractional_At_Is_Rounded()
    {
        var s = Parse("""{"at":1500.6,"kind":"ProcessStop","pid":1}""", out var w);
        Assert.Empty(w);
        Assert.Equal(TimeSpan.FromMilliseconds(1501), Assert.Single(s.Events).At);
    }

    [Fact]
    public void Parse_NonNumeric_At_Warns_And_Reuses_Previous_Offset()
    {
        var s = Parse("""
            {"at":700,"kind":"ProcessStop","pid":1}
            {"at":"soon","kind":"ProcessStop","pid":2}
            """, out var w);
        Assert.Contains(w, x => x.Contains("'at' must be a number"));
        Assert.Equal(TimeSpan.FromMilliseconds(700), s.Events[1].At);
    }

    // ------------------------------------------------------------- timestamps

    [Fact]
    public void Parse_Implied_Timestamp_Is_Start_Plus_Offset()
    {
        var s = Parse("""
            {"meta":{"start":"2026-03-04T14:02:11Z"}}
            {"at":1490,"kind":"ProcessStart","pid":1}
            """, out _);
        Assert.Equal(new DateTime(2026, 3, 4, 14, 2, 12, 490, DateTimeKind.Utc),
                     Assert.Single(s.Events).Signal.TimestampUtc);
    }

    [Fact]
    public void Parse_Explicit_Timestamp_Overrides_The_Implied_One()
    {
        var s = Parse("""
            {"meta":{"start":"2026-03-04T14:02:11Z"}}
            {"at":1000,"kind":"ProcessStart","pid":1,"timestampUtc":"2026-03-04T15:00:00Z"}
            """, out var w);
        Assert.Empty(w);
        var e = Assert.Single(s.Events);
        Assert.Equal(TimeSpan.FromSeconds(1), e.At);
        Assert.Equal(new DateTime(2026, 3, 4, 15, 0, 0, DateTimeKind.Utc), e.Signal.TimestampUtc);
    }

    [Fact]
    public void Parse_Meta_Placed_After_The_Events_Still_Anchors_Them()
    {
        var s = Parse("""
            {"at":1000,"kind":"ProcessStart","pid":1}
            {"meta":{"start":"2030-06-01T00:00:00Z"}}
            """, out var w);
        Assert.Empty(w);
        Assert.Equal(new DateTime(2030, 6, 1, 0, 0, 1, DateTimeKind.Utc),
                     Assert.Single(s.Events).Signal.TimestampUtc);
    }

    [Fact]
    public void Parse_Start_With_Offset_Is_Converted_To_Utc()
    {
        var s = Parse("""{"meta":{"start":"2026-03-04T16:02:11+02:00"}}""", out var w);
        Assert.Empty(w);
        Assert.Equal(new DateTime(2026, 3, 4, 14, 2, 11, DateTimeKind.Utc), s.StartUtc);
    }

    [Fact]
    public void Parse_Unparsable_Start_Falls_Back_And_Warns()
    {
        var s = Parse("""{"meta":{"start":"the third of never"}}""", out var w);
        Assert.Contains(w, x => x.Contains("meta.start"));
        Assert.Equal(TraceFormat.DefaultStartUtc, s.StartUtc);
    }

    // ------------------------------------------------------------- malformed input

    [Fact]
    public void Parse_Malformed_Json_Is_Skipped_And_Recorded()
    {
        var s = Parse("""
            {"kind":"ProcessStop","pid":1}
            {"kind":"ProcessStop", pid oops
            {"kind":"ProcessStop","pid":2}
            """, out var w);
        Assert.Equal(2, s.Events.Count);
        Assert.Contains(w, x => x.StartsWith("line 2:") && x.Contains("not valid JSON"));
    }

    [Theory]
    [InlineData("[1,2,3]")]
    [InlineData("\"just a string\"")]
    [InlineData("42")]
    [InlineData("true")]
    [InlineData("null")]
    public void Parse_NonObject_Line_Is_Skipped(string line)
    {
        var s = Parse(line, out var w);
        Assert.Empty(s.Events);
        Assert.Contains(w, x => x.Contains("expected a JSON object"));
    }

    [Fact]
    public void Parse_Unknown_Kind_Skips_The_Line()
    {
        var s = Parse("""{"kind":"SomethingNew","pid":1}""", out var w);
        Assert.Empty(s.Events);
        Assert.Contains(w, x => x.Contains("line skipped"));
    }

    [Theory]
    [InlineData("\"5\"")]
    [InlineData("5")]
    public void Parse_Numeric_Kind_Is_Rejected(string kindJson)
    {
        // An ordinal would silently change meaning the next time SignalKind grows a member.
        var s = Parse($$"""{"kind":{{kindJson}},"pid":1}""", out var w);
        Assert.Empty(s.Events);
        Assert.Contains(w, x => x.Contains("'kind' must be one of"));
    }

    [Fact]
    public void Parse_Missing_Kind_Skips_The_Line()
    {
        var s = Parse("""{"pid":1,"filePath":"C:\\x"}""", out var w);
        Assert.Empty(s.Events);
        Assert.Contains(w, x => x.Contains("no 'kind' field"));
    }

    [Fact]
    public void Parse_Missing_Pid_Defaults_To_Zero_And_Warns()
    {
        var s = Parse("""{"kind":"FileCreate","filePath":"C:\\loot.zip"}""", out var w);
        Assert.Equal(0, Assert.Single(s.Events).Signal.Pid);
        Assert.Contains(w, x => x.Contains("unattributed"));
    }

    [Fact]
    public void Parse_Explicit_Zero_Pid_Does_Not_Warn()
    {
        var s = Parse("""{"kind":"FileCreate","pid":0,"filePath":"C:\\loot.zip"}""", out var w);
        Assert.Empty(w);
        Assert.Equal(0, Assert.Single(s.Events).Signal.Pid);
    }

    [Fact]
    public void Parse_Unknown_Field_Warns_But_Keeps_The_Event()
    {
        var s = Parse("""{"kind":"ProcessStop","pid":1,"sha256":"deadbeef","severity":9}""", out var w);
        Assert.Single(s.Events);
        Assert.Contains(w, x => x.Contains("unknown field 'sha256'"));
        Assert.Contains(w, x => x.Contains("unknown field 'severity'"));
    }

    [Fact]
    public void Parse_Unknown_Meta_Field_Warns()
    {
        var s = Parse("""{"meta":{"name":"x","author":"someone"}}""", out var w);
        Assert.Equal("x", s.Name);
        Assert.Contains(w, x => x.Contains("unknown meta field 'author'"));
    }

    [Theory]
    [InlineData("\"pid\":\"4242\"", "'pid' must be a 32-bit integer")]
    [InlineData("\"pid\":{\"a\":1}", "'pid' must be a 32-bit integer")]
    [InlineData("\"pid\":99999999999999", "'pid' must be a 32-bit integer")]
    [InlineData("\"processName\":123", "'processName' must be a string")]
    [InlineData("\"processName\":[\"a\"]", "'processName' must be a string")]
    [InlineData("\"remotePort\":\"443\"", "'remotePort' must be a 32-bit integer")]
    [InlineData("\"desiredAccess\":\"notahexnumber\"", "'desiredAccess' must be an access mask")]
    [InlineData("\"timestampUtc\":17", "'timestampUtc' must be an ISO-8601 timestamp")]
    public void Parse_Wrong_Typed_Field_Warns_And_Is_Ignored(string fieldJson, string expectedWarning)
    {
        var s = Parse($$"""{"kind":"ProcessStop",{{fieldJson}}}""", out var w);
        Assert.Single(s.Events);                       // the event survives
        Assert.Contains(w, x => x.Contains(expectedWarning));
    }

    [Fact]
    public void Parse_Explicit_Null_Field_Is_Treated_As_Absent_Without_A_Warning()
    {
        var s = Parse("""{"kind":"ProcessStop","pid":1,"filePath":null,"detail":null}""", out var w);
        Assert.Empty(w);
        var sig = Assert.Single(s.Events).Signal;
        Assert.Null(sig.FilePath);
        Assert.Null(sig.Detail);
    }

    [Theory]
    [InlineData("0x1410", 5136u)]
    [InlineData("0X1410", 5136u)]
    [InlineData("5136", 5136u)]
    public void Parse_DesiredAccess_Accepts_Hex_And_Decimal_Strings(string text, uint expected)
    {
        var s = Parse($$"""{"kind":"ProcessAccess","pid":1,"targetPid":2,"desiredAccess":"{{text}}"}""", out var w);
        Assert.Empty(w);
        Assert.Equal(expected, Assert.Single(s.Events).Signal.DesiredAccess);
    }

    [Fact]
    public void Parse_Duplicate_Meta_Keeps_The_First_And_Warns()
    {
        var s = Parse("""
            {"meta":{"name":"first","start":"2026-01-05T00:00:00Z"}}
            {"meta":{"name":"second","start":"2030-01-01T00:00:00Z"}}
            """, out var w);
        Assert.Equal("first", s.Name);
        Assert.Equal(new DateTime(2026, 1, 5, 0, 0, 0, DateTimeKind.Utc), s.StartUtc);
        Assert.Contains(w, x => x.Contains("duplicate meta"));
    }

    [Fact]
    public void Parse_Expect_Rejects_NonString_Entries_But_Keeps_The_Rest()
    {
        var s = Parse("""{"meta":{"expect":["quarantine:pid=1",7,"","warn:pid=2"]}}""", out var w);
        Assert.Equal(new[] { "quarantine:pid=1", "warn:pid=2" }, s.Expect);
        Assert.Contains(w, x => x.Contains("meta.expect[1]"));
        Assert.Contains(w, x => x.Contains("meta.expect[2]"));
    }

    [Fact]
    public void Parse_Expect_That_Is_Not_An_Array_Warns()
    {
        var s = Parse("""{"meta":{"expect":"quarantine:pid=1"}}""", out var w);
        Assert.Empty(s.Expect);
        Assert.Contains(w, x => x.Contains("'meta.expect' must be an array"));
    }

    [Fact]
    public void Parse_Meta_That_Is_Not_An_Object_Warns()
    {
        var s = Parse("""{"meta":"chain"}""", out var w);
        Assert.Contains(w, x => x.Contains("'meta' must be an object"));
        Assert.Empty(s.Events);
    }

    [Theory]
    [InlineData("{")]
    [InlineData("}")]
    [InlineData("{\"kind\":\"ProcessStart\",\"pid\":1,}")]
    [InlineData("{\"kind\":\"ProcessStart\",\"pid\":1e999}")]
    [InlineData("\u0000\u0001\u0002")]
    [InlineData("{\"kind\":\"ProcessStart\",\"pid\":1,\"commandLine\":\"\\uD800\"}")]
    [InlineData("{\"#\":null}")]
    [InlineData("{\"meta\":null}")]
    [InlineData("{\"at\":null,\"kind\":\"ProcessStop\",\"pid\":1}")]
    [InlineData("{\"kind\":null,\"pid\":1}")]
    public void Parse_Never_Throws_On_Adversarial_Lines(string line)
    {
        var ex = Record.Exception(() => TraceFormat.Parse(new[] { line }, "adversarial", out _));
        Assert.Null(ex);
    }

    [Fact]
    public void Parse_Deeply_Nested_Json_Is_Skipped_Not_Fatal()
    {
        // System.Text.Json caps nesting depth; the parser must degrade to a warning.
        string deep = new string('[', 200) + new string(']', 200);
        var s = TraceFormat.Parse(new[] { deep }, "deep", out var w);
        Assert.Empty(s.Events);
        Assert.NotEmpty(w);
    }

    [Fact]
    public void Parse_Warnings_Carry_The_Line_Number()
    {
        var s = Parse("""
            {"#":"comment"}

            {"kind":"Nope","pid":1}
            """, out var w);
        Assert.Empty(s.Events);
        Assert.Contains(w, x => x.StartsWith("line 3:"));
    }

    // ------------------------------------------------------------- writing

    [Fact]
    public void Write_Then_Parse_Round_Trips_Everything()
    {
        const string source = """
            {"meta":{"name":"rt","description":"round trip","start":"2026-07-08T09:10:11Z","expect":["quarantine:pid=9","technique:T1059.001"]}}
            {"at":0,"kind":"ProcessStart","pid":9,"parentPid":4,"processName":"p.exe","imagePath":"C:\\p.exe","commandLine":"p.exe -a \"b c\"","user":"CORP\\u"}
            {"at":1200,"kind":"FileCreate","pid":9,"filePath":"C:\\Users\\u\\AppData\\Local\\Temp\\x.zip","detail":"staged"}
            {"at":1800,"kind":"NetworkConnect","pid":9,"remoteAddress":"203.0.113.4","remotePort":443}
            {"at":2400,"kind":"ProcessAccess","pid":9,"targetPid":600,"desiredAccess":"0x1410"}
            {"at":3000,"kind":"RegistryWrite","pid":9,"registryKey":"HKCU\\Run","registryValue":"V"}
            {"at":3600,"kind":"DnsQuery","pid":9,"domain":"c2.example"}
            {"at":4200,"kind":"NamedPipe","pid":9,"pipeName":"pipe"}
            {"at":4800,"kind":"ScriptContent","pid":9,"scriptText":"Write-Host 'hi <b> & co'"}
            """;

        var first = Parse(source, out var w1);
        Assert.Empty(w1);

        var lines = TraceFormat.Write(first).ToList();
        var second = TraceFormat.Parse(lines, "ignored", out var w2);
        Assert.Empty(w2);

        Assert.Equal(first.Name, second.Name);
        Assert.Equal(first.Description, second.Description);
        Assert.Equal(first.StartUtc, second.StartUtc);
        Assert.Equal(first.Expect, second.Expect);
        Assert.Equal(first.Events.Count, second.Events.Count);
        for (int i = 0; i < first.Events.Count; i++)
        {
            Assert.Equal(first.Events[i].At, second.Events[i].At);
            Assert.Equal(first.Events[i].Signal, second.Events[i].Signal);
        }
    }

    [Fact]
    public void Write_Omits_Defaulted_Fields()
    {
        var scenario = new TraceScenario
        {
            Name = "n",
            StartUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            Events = new[]
            {
                new TraceStep(TimeSpan.Zero, new Signal
                {
                    Kind = SignalKind.ProcessStop, Pid = 5,
                    TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                })
            }
        };

        string eventLine = TraceFormat.Write(scenario).Skip(1).Single();
        Assert.Equal("""{"at":0,"kind":"ProcessStop","pid":5}""", eventLine);
    }

    [Fact]
    public void Write_Emits_TimestampUtc_Only_When_It_Disagrees_With_The_Offset()
    {
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var scenario = new TraceScenario
        {
            Name = "n",
            StartUtc = start,
            Events = new[]
            {
                new TraceStep(TimeSpan.FromSeconds(1),
                    new Signal { Kind = SignalKind.ProcessStop, Pid = 5, TimestampUtc = start.AddHours(9) })
            }
        };

        string eventLine = TraceFormat.Write(scenario).Skip(1).Single();
        Assert.Contains("timestampUtc", eventLine);

        var reparsed = TraceFormat.Parse(TraceFormat.Write(scenario), "n", out var w);
        Assert.Empty(w);
        Assert.Equal(start.AddHours(9), reparsed.Events[0].Signal.TimestampUtc);
    }

    [Fact]
    public void Write_Null_Scenario_Throws()
        => Assert.Throws<ArgumentNullException>(() => TraceFormat.Write(null!).ToList());

    // ------------------------------------------------------------- FromSignals

    [Fact]
    public void FromSignals_Anchors_At_The_First_Timestamp()
    {
        var t0 = new DateTime(2026, 9, 9, 12, 0, 0, DateTimeKind.Utc);
        var s = TraceFormat.FromSignals(new[]
        {
            new Signal { Kind = SignalKind.ProcessStart, Pid = 1, TimestampUtc = t0 },
            new Signal { Kind = SignalKind.FileCreate, Pid = 1, TimestampUtc = t0.AddMilliseconds(1500) },
            new Signal { Kind = SignalKind.NetworkConnect, Pid = 1, TimestampUtc = t0.AddSeconds(30) }
        }, "recorded");

        Assert.Equal(t0, s.StartUtc);
        Assert.Equal(new[] { TimeSpan.Zero, TimeSpan.FromMilliseconds(1500), TimeSpan.FromSeconds(30) },
                     s.Events.Select(e => e.At));
        Assert.Equal("recorded", s.Name);
    }

    [Fact]
    public void FromSignals_Clamps_Out_Of_Order_Timestamps_Without_Reordering()
    {
        var t0 = new DateTime(2026, 9, 9, 12, 0, 0, DateTimeKind.Utc);
        var s = TraceFormat.FromSignals(new[]
        {
            new Signal { Kind = SignalKind.ProcessStart, Pid = 1, TimestampUtc = t0 },
            new Signal { Kind = SignalKind.FileCreate, Pid = 2, TimestampUtc = t0.AddSeconds(5) },
            new Signal { Kind = SignalKind.ImageLoad, Pid = 3, TimestampUtc = t0.AddSeconds(2) }
        }, "skewed");

        Assert.Equal(new[] { 1, 2, 3 }, s.Events.Select(e => e.Signal.Pid));   // order preserved
        Assert.Equal(TimeSpan.FromSeconds(5), s.Events[2].At);                 // offset clamped
    }

    [Fact]
    public void FromSignals_Handles_An_Empty_Capture()
    {
        var s = TraceFormat.FromSignals(Array.Empty<Signal>(), "nothing");
        Assert.Empty(s.Events);
        Assert.Equal("nothing", s.Name);
        Assert.Equal(TraceFormat.DefaultStartUtc, s.StartUtc);
    }

    [Fact]
    public void FromSignals_Normalises_Unspecified_Kind_Timestamps()
    {
        var unspecified = new DateTime(2026, 9, 9, 12, 0, 0, DateTimeKind.Unspecified);
        var s = TraceFormat.FromSignals(new[]
        {
            new Signal { Kind = SignalKind.ProcessStart, Pid = 1, TimestampUtc = unspecified }
        }, "n");
        Assert.Equal(DateTimeKind.Utc, s.StartUtc.Kind);
        Assert.Equal(12, s.StartUtc.Hour);
    }

    [Fact]
    public void FromSignals_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => TraceFormat.FromSignals(null!, "x"));

    [Fact]
    public void Scenario_Normalises_A_NonUtc_Start()
    {
        var s = new TraceScenario { StartUtc = new DateTime(2026, 1, 1, 6, 0, 0, DateTimeKind.Unspecified) };
        Assert.Equal(DateTimeKind.Utc, s.StartUtc.Kind);
        Assert.Equal(6, s.StartUtc.Hour);
    }

    // ------------------------------------------------------------- disk IO

    [Fact]
    public void Save_Then_Load_Round_Trips_Through_A_File()
    {
        string dir = Path.Combine(Path.GetTempPath(), "psreplay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, "sample.jsonl");
            var scenario = TraceFormat.Parse(new[]
            {
                """{"meta":{"name":"sample","description":"d","start":"2026-02-02T02:02:02Z","expect":["verdicts<=1"]}}""",
                """{"at":10,"kind":"ProcessStart","pid":11,"processName":"p.exe"}"""
            }, "sample", out _);

            TraceFormat.Save(path, scenario);
            var loaded = TraceFormat.Load(path, out var w);

            Assert.Empty(w);
            Assert.Equal("sample", loaded.Name);
            Assert.Equal(scenario.StartUtc, loaded.StartUtc);
            Assert.Equal(new[] { "verdicts<=1" }, loaded.Expect);
            Assert.Equal(scenario.Events[0].Signal, loaded.Events[0].Signal);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void Load_Uses_The_File_Name_When_Meta_Has_None()
    {
        string dir = Path.Combine(Path.GetTempPath(), "psreplay-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, "named-by-file.jsonl");
            File.WriteAllLines(path, new[] { """{"kind":"ProcessStop","pid":1}""" });
            Assert.Equal("named-by-file", TraceFormat.Load(path).Name);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public void Load_Of_A_Missing_File_Throws_Rather_Than_Returning_Empty()
    {
        string path = Path.Combine(Path.GetTempPath(), "psreplay-" + Guid.NewGuid().ToString("N") + ".jsonl");
        Assert.ThrowsAny<IOException>(() => TraceFormat.Load(path));
    }

    [Fact]
    public void Load_Rejects_A_Blank_Path()
        => Assert.Throws<ArgumentException>(() => TraceFormat.Load("   "));
}

public class ReplayExpectationTests
{
    private static ReplayVerdict V(int pid, string verdict, int score = 0, params string[] techniques) => new()
    {
        AtUtc = new DateTime(2026, 1, 1, 0, 0, 5, DateTimeKind.Utc),
        Pid = pid,
        Verdict = verdict,
        Score = score,
        Trigger = "Test",
        Techniques = techniques
    };

    private static readonly IReadOnlyList<ReplayVerdict> Sample = new[]
    {
        V(100, "Warn", 45, "T1059.001"),
        V(100, "Quarantine", 95, "T1555.003", "T1041"),
        V(200, "Warn", 41)
    };

    private static readonly IReadOnlyDictionary<int, int> Scores =
        new Dictionary<int, int> { [100] = 95, [200] = 41, [300] = 0 };

    private static string? Check(string e) => Expectation.Check(e, Sample, Scores);

    [Theory]
    [InlineData("quarantine:pid=4242")]
    [InlineData("warn:pid=1")]
    [InlineData("no-quarantine:pid=0")]
    [InlineData("score>=70:pid=1")]
    [InlineData("score>70:pid=1")]
    [InlineData("score<=70:pid=1")]
    [InlineData("score<70:pid=1")]
    [InlineData("score==70:pid=1")]
    [InlineData("score=70:pid=1")]
    [InlineData("score>=-5:pid=1")]
    [InlineData("technique:T1059.001")]
    [InlineData("verdicts<=3")]
    [InlineData("verdicts==0")]
    [InlineData("  QUARANTINE : PID = 42  ")]
    public void WellFormed_Expectations_Parse(string e)
    {
        Assert.True(Expectation.IsWellFormed(e, out string err), err);
    }

    [Theory]
    [InlineData("")]
    [InlineData("    ")]
    [InlineData("quarantine")]
    [InlineData("quarantine:")]
    [InlineData("quarantine:4242")]
    [InlineData("quarantine:pid=")]
    [InlineData("quarantine:pid=abc")]
    [InlineData("quarantine:pid=-1")]
    [InlineData("quarantine:process=chrome.exe")]
    [InlineData("quarentine:pid=1")]
    [InlineData("kill:pid=1")]
    [InlineData("technique:")]
    [InlineData("technique:T1059.001 and T1055")]
    [InlineData("score:pid=1")]
    [InlineData("score>=:pid=1")]
    [InlineData("score>=abc:pid=1")]
    [InlineData("score>=70")]
    [InlineData("score!=70:pid=1")]
    [InlineData("verdicts")]
    [InlineData("verdicts<=")]
    [InlineData("verdicts<=3:pid=1")]
    [InlineData("no_quarantine:pid=1")]
    public void Malformed_Expectations_Are_Rejected_With_A_Reason(string e)
    {
        Assert.False(Expectation.IsWellFormed(e, out string err));
        Assert.False(string.IsNullOrWhiteSpace(err));
        // The critical property: a mistyped assertion must never silently pass.
        Assert.NotNull(Check(e));
    }

    [Fact]
    public void Null_Expectation_Is_Rejected()
        => Assert.False(Expectation.IsWellFormed(null!, out _));

    [Fact]
    public void Quarantine_Holds_When_A_Quarantine_Was_Raised()
        => Assert.Null(Check("quarantine:pid=100"));

    [Fact]
    public void Quarantine_Fails_When_Only_A_Warn_Was_Raised()
    {
        string? reason = Check("quarantine:pid=200");
        Assert.NotNull(reason);
        Assert.Contains("Warn", reason);
    }

    [Fact]
    public void Quarantine_Fails_For_A_Pid_With_No_Verdicts()
    {
        string? reason = Check("quarantine:pid=999");
        Assert.NotNull(reason);
        Assert.Contains("none", reason);
    }

    [Fact]
    public void Warn_Is_Satisfied_By_A_Quarantine()
    {
        var only = new[] { V(7, "Quarantine", 80) };
        Assert.Null(Expectation.Check("warn:pid=7", only, Scores));
    }

    [Fact]
    public void Warn_Is_Not_Satisfied_By_An_Allow()
    {
        var only = new[] { V(7, "Allow") };
        Assert.NotNull(Expectation.Check("warn:pid=7", only, Scores));
    }

    [Fact]
    public void Unrecognised_Verdict_Names_Satisfy_Nothing()
    {
        var odd = new[] { V(7, "Escalate") };
        Assert.NotNull(Expectation.Check("warn:pid=7", odd, Scores));
        Assert.NotNull(Expectation.Check("quarantine:pid=7", odd, Scores));
        Assert.Null(Expectation.Check("no-quarantine:pid=7", odd, Scores));
    }

    [Fact]
    public void Verdict_Names_Are_Case_Insensitive()
    {
        var lower = new[] { V(7, "quarantine", 80) };
        Assert.Null(Expectation.Check("quarantine:pid=7", lower, Scores));
    }

    [Fact]
    public void NoQuarantine_Holds_For_A_Warned_Pid()
        => Assert.Null(Check("no-quarantine:pid=200"));

    [Fact]
    public void NoQuarantine_Holds_For_A_Completely_Silent_Pid()
        => Assert.Null(Check("no-quarantine:pid=54321"));

    [Fact]
    public void NoQuarantine_Fails_And_Names_The_Moment()
    {
        string? reason = Check("no-quarantine:pid=100");
        Assert.NotNull(reason);
        Assert.Contains("WAS quarantined", reason);
        Assert.Contains("2026-01-01", reason);
    }

    [Theory]
    [InlineData("score>=95:pid=100", true)]
    [InlineData("score>=96:pid=100", false)]
    [InlineData("score>94:pid=100", true)]
    [InlineData("score>95:pid=100", false)]
    [InlineData("score<=95:pid=100", true)]
    [InlineData("score<95:pid=100", false)]
    [InlineData("score==95:pid=100", true)]
    [InlineData("score=95:pid=100", true)]
    [InlineData("score==94:pid=100", false)]
    [InlineData("score<40:pid=300", true)]
    [InlineData("score>=40:pid=200", true)]
    public void Score_Comparisons_Evaluate_Correctly(string e, bool expectedToHold)
        => Assert.Equal(expectedToHold, Check(e) is null);

    [Fact]
    public void Score_On_An_Unknown_Pid_Fails_Rather_Than_Assuming_Zero()
    {
        // The failure mode this defends against: score<40:pid=<typo> passing forever.
        string? reason = Check("score<40:pid=987654");
        Assert.NotNull(reason);
        Assert.Contains("never scored", reason);
    }

    [Fact]
    public void Technique_Matching_Is_Case_Insensitive()
    {
        Assert.Null(Check("technique:t1555.003"));
        Assert.Null(Check("technique:T1041"));
    }

    [Fact]
    public void Technique_Miss_Lists_What_Was_Cited()
    {
        string? reason = Check("technique:T1003.001");
        Assert.NotNull(reason);
        Assert.Contains("T1059.001", reason);
        Assert.Contains("T1555.003", reason);
    }

    [Fact]
    public void Technique_Miss_On_An_Engine_That_Cites_Nothing_Says_So()
    {
        var plain = new[] { V(1, "Warn", 50) };
        string? reason = Expectation.Check("technique:T1059.001", plain, Scores);
        Assert.NotNull(reason);
        Assert.Contains("none", reason);
    }

    [Theory]
    [InlineData("verdicts<=3", true)]
    [InlineData("verdicts<3", false)]
    [InlineData("verdicts==3", true)]
    [InlineData("verdicts>=3", true)]
    [InlineData("verdicts>3", false)]
    public void Verdict_Count_Bounds_Evaluate_Correctly(string e, bool expectedToHold)
        => Assert.Equal(expectedToHold, Check(e) is null);

    [Fact]
    public void Check_Tolerates_Null_Collections()
    {
        Assert.NotNull(Expectation.Check("quarantine:pid=1", null, null));
        Assert.Null(Expectation.Check("no-quarantine:pid=1", null, null));
        Assert.Null(Expectation.Check("verdicts==0", null, null));
    }
}

public class ReplayHarnessTests
{
    private static TraceScenario Scenario(params (int Ms, int Pid)[] steps) => new()
    {
        Name = "harness",
        StartUtc = new DateTime(2026, 5, 1, 10, 0, 0, DateTimeKind.Utc),
        Events = steps.Select(s => new TraceStep(
            TimeSpan.FromMilliseconds(s.Ms),
            new Signal { Kind = SignalKind.ProcessStart, Pid = s.Pid })).ToList()
    };

    [Fact]
    public void Null_Factory_Is_Rejected_At_Construction()
        => Assert.Throws<ArgumentNullException>(() => new TraceReplay(null!));

    [Fact]
    public void Null_Scenario_Is_Rejected()
        => Assert.Throws<ArgumentNullException>(() => new TraceReplay(c => new ReplayScriptedEngine(c)).Run(null!));

    [Fact]
    public void A_Factory_That_Returns_Null_Fails_Loudly()
        => Assert.Throws<InvalidOperationException>(() => new TraceReplay(_ => null!).Run(Scenario((0, 1))));

    [Fact]
    public void The_Engine_Receives_A_Clock_Already_Set_To_The_Scenario_Start()
    {
        DateTime seen = default;
        var replay = new TraceReplay(c => { seen = c.UtcNow; return new ReplayScriptedEngine(c); });
        var scenario = Scenario((0, 1));
        replay.Run(scenario);
        Assert.Equal(scenario.StartUtc, seen);
    }

    [Fact]
    public void The_Clock_Is_Advanced_To_Each_Step_Offset_Before_The_Feed()
    {
        ReplayScriptedEngine? engine = null;
        var scenario = Scenario((0, 1), (1500, 2), (32000, 3));
        new TraceReplay(c => engine = new ReplayScriptedEngine(c)).Run(scenario);

        Assert.NotNull(engine);
        Assert.Equal(new[]
        {
            scenario.StartUtc,
            scenario.StartUtc.AddMilliseconds(1500),
            scenario.StartUtc.AddMilliseconds(32000)
        }, engine!.ClockAtFeed);
    }

    [Fact]
    public void Steps_Sharing_An_Offset_Do_Not_Advance_The_Clock_Twice()
    {
        ReplayScriptedEngine? engine = null;
        var scenario = Scenario((500, 1), (500, 2), (500, 3));
        new TraceReplay(c => engine = new ReplayScriptedEngine(c)).Run(scenario);
        Assert.Single(engine!.ClockAtFeed.Distinct());
        Assert.Equal(scenario.StartUtc.AddMilliseconds(500), engine.ClockAtFeed[0]);
    }

    [Fact]
    public void A_Scenario_Built_With_Backwards_Offsets_Never_Rewinds_The_Clock()
    {
        // Parse enforces monotonic offsets, but a scenario built in code can violate it.
        ReplayScriptedEngine? engine = null;
        var scenario = Scenario((5000, 1), (1000, 2), (6000, 3));
        new TraceReplay(c => engine = new ReplayScriptedEngine(c)).Run(scenario);

        var seen = engine!.ClockAtFeed;
        Assert.Equal(seen.OrderBy(t => t).ToList(), seen);
        Assert.Equal(scenario.StartUtc.AddMilliseconds(5000), seen[1]);
    }

    [Fact]
    public void Every_Step_Is_Fed_And_Counted()
    {
        var scenario = Scenario((0, 1), (10, 2), (20, 3), (30, 4));
        var result = new TraceReplay(c => new ReplayScriptedEngine(c)).Run(scenario);
        Assert.Equal(4, result.SignalsFed);
        Assert.Equal(TimeSpan.FromMilliseconds(30), result.SimulatedDuration);
        Assert.Equal("harness", result.Scenario);
    }

    [Fact]
    public void An_Empty_Scenario_Runs_Cleanly()
    {
        var result = new TraceReplay(c => new ReplayScriptedEngine(c)).Run(new TraceScenario { Name = "nothing" });
        Assert.Equal(0, result.SignalsFed);
        Assert.Equal(TimeSpan.Zero, result.SimulatedDuration);
        Assert.True(result.Success);
        Assert.Contains("RESULT: PASS", result.Summary);
    }

    [Fact]
    public void Verdicts_Without_A_Timestamp_Are_Stamped_From_The_Replay_Clock()
    {
        var scenario = Scenario((0, 1), (7000, 2));
        var result = new TraceReplay(c => new ReplayScriptedEngine(c,
            (s, _) => s.Pid == 2 ? new[] { new ReplayVerdict { Pid = 2, Verdict = "Warn" } } : null)).Run(scenario);

        var v = Assert.Single(result.Verdicts);
        Assert.Equal(scenario.StartUtc.AddSeconds(7), v.AtUtc);
    }

    [Fact]
    public void Verdicts_That_Carry_Their_Own_Timestamp_Keep_It()
    {
        var stamped = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var result = new TraceReplay(c => new ReplayScriptedEngine(c,
            (_, _) => new[] { new ReplayVerdict { Pid = 1, Verdict = "Warn", AtUtc = stamped } })).Run(Scenario((0, 1)));

        Assert.Equal(stamped, Assert.Single(result.Verdicts).AtUtc);
    }

    [Fact]
    public void A_Feed_That_Returns_Null_Is_Tolerated()
    {
        var result = new TraceReplay(c => new ReplayScriptedEngine(c, (_, _) => null)).Run(Scenario((0, 1), (5, 2)));
        Assert.Equal(2, result.SignalsFed);
        Assert.Empty(result.Verdicts);
    }

    [Fact]
    public void A_Feed_That_Returns_A_Null_Entry_Is_Tolerated()
    {
        var result = new TraceReplay(c => new ReplayScriptedEngine(c,
            (_, _) => new ReplayVerdict?[] { null }!)).Run(Scenario((0, 1)));
        Assert.Empty(result.Verdicts);
    }

    [Fact]
    public void An_Exception_From_The_Engine_Is_Not_Swallowed()
    {
        var replay = new TraceReplay(c => new ReplayScriptedEngine(c,
            (_, _) => throw new InvalidTimeZoneException("engine bug")));
        Assert.Throws<InvalidTimeZoneException>(() => replay.Run(Scenario((0, 1))));
    }

    [Fact]
    public void Final_Scores_Are_Snapshotted_Away_From_The_Engine()
    {
        ReplayScriptedEngine? engine = null;
        var result = new TraceReplay(c => engine = new ReplayScriptedEngine(c)).Run(Scenario((0, 42)));

        Assert.Equal(0, result.FinalScores[42]);
        engine!.ScoreTable[42] = 999;
        engine.ScoreTable[7] = 1;
        Assert.Equal(0, result.FinalScores[42]);
        Assert.False(result.FinalScores.ContainsKey(7));
    }

    [Fact]
    public void Met_Expectations_Produce_Success()
    {
        var scenario = Scenario((0, 1)) with
        {
            Expect = new[] { "quarantine:pid=1", "verdicts==1", "no-quarantine:pid=2", "technique:T1059.001" }
        };
        var result = new TraceReplay(c => new ReplayScriptedEngine(c,
            (_, _) => new[]
            {
                new ReplayVerdict { Pid = 1, Verdict = "Quarantine", Score = 90, Techniques = new[] { "T1059.001" } }
            })).Run(scenario);

        Assert.True(result.Success, result.Summary);
        Assert.Empty(result.UnmetExpectations);
        Assert.Contains("RESULT: PASS", result.Summary);
    }

    [Fact]
    public void Unmet_Expectations_Are_Reported_With_The_Original_Text_And_A_Reason()
    {
        var scenario = Scenario((0, 1)) with { Expect = new[] { "quarantine:pid=1", "bogus:pid=1" } };
        var result = new TraceReplay(c => new ReplayScriptedEngine(c)).Run(scenario);

        Assert.False(result.Success);
        Assert.Equal(2, result.UnmetExpectations.Count);
        Assert.All(result.UnmetExpectations, u => Assert.Contains(" -- ", u));
        Assert.Contains(result.UnmetExpectations, u => u.StartsWith("quarantine:pid=1 -- "));
        Assert.Contains(result.UnmetExpectations, u => u.Contains("unrecognised expectation keyword"));
        Assert.Contains("RESULT: FAIL", result.Summary);
        Assert.Contains("2 expectations unmet", result.Summary);
    }

    [Fact]
    public void Summary_Is_A_Printable_Multiline_Report()
    {
        var scenario = Scenario((0, 1), (2500, 2)) with
        {
            Description = "a short narrative",
            Expect = new[] { "quarantine:pid=2" }
        };
        var result = new TraceReplay(c => new ReplayScriptedEngine(c,
            (s, _) => s.Pid == 2
                ? new[] { new ReplayVerdict { Pid = 2, Verdict = "Quarantine", Score = 90, Trigger = "ProcessStart" } }
                : null)).Run(scenario);

        var lines = result.Summary.Split('\n');
        Assert.True(lines.Length >= 6);
        Assert.Contains("Replay: harness", result.Summary);
        Assert.Contains("a short narrative", result.Summary);
        Assert.Contains("QUARANTINE", result.Summary);
        Assert.Contains("pid 2", result.Summary);
        Assert.Contains("00:00:02.500", result.Summary);
        Assert.Contains("2 fed over", result.Summary);
        Assert.Contains("RESULT: PASS", result.Summary);
        Assert.DoesNotContain("FAIL", result.Summary);
    }

    [Fact]
    public void Summary_Truncates_A_Flood_Of_Verdicts()
    {
        var scenario = new TraceScenario
        {
            Name = "flood",
            Events = Enumerable.Range(0, 60)
                .Select(i => new TraceStep(TimeSpan.FromSeconds(i),
                    new Signal { Kind = SignalKind.NetworkConnect, Pid = 1 })).ToList()
        };
        var result = new TraceReplay(c => new ReplayScriptedEngine(c,
            (_, _) => new[] { new ReplayVerdict { Pid = 1, Verdict = "Warn" } })).Run(scenario);

        Assert.Equal(60, result.Verdicts.Count);
        Assert.Contains("and 20 more", result.Summary);
    }

    [Fact]
    public void Each_Run_Gets_A_Fresh_Engine()
    {
        int built = 0;
        var replay = new TraceReplay(c => { built++; return new ReplayScriptedEngine(c); });
        replay.Run(Scenario((0, 1)));
        replay.Run(Scenario((0, 1)));
        Assert.Equal(2, built);
    }

    [Fact]
    public void Replaying_The_Same_Scenario_Twice_Gives_Identical_Results()
    {
        var scenario = Scenario((0, 1), (1000, 2), (60000, 3)) with { Expect = new[] { "verdicts==1" } };
        var replay = new TraceReplay(c => new ReplayScriptedEngine(c,
            (s, clock) => s.Pid == 3
                ? new[] { new ReplayVerdict { Pid = 3, Verdict = "Warn", AtUtc = clock.UtcNow, Score = 50 } }
                : null));

        var a = replay.Run(scenario);
        var b = replay.Run(scenario);

        Assert.Equal(a.Summary, b.Summary);
        Assert.Equal(a.Success, b.Success);
        Assert.Equal(a.Verdicts[0].AtUtc, b.Verdicts[0].AtUtc);
    }
}

public class ReplayScenarioFileTests
{
    /// <summary>
    /// Scenario files are source data, not build output, so they are located by walking up
    /// from the test binary. When they cannot be found (a packaged or partial checkout)
    /// the test returns rather than failing: a missing data directory is not a defect in
    /// the code under test.
    /// </summary>
    private static string? ScenarioDir()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 12 && dir is not null; i++, dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "Replay", "scenarios");
            if (Directory.Exists(candidate)) return candidate;
        }
        return null;
    }

    private static TraceScenario? Load(string file, out IReadOnlyList<string> warnings)
    {
        warnings = Array.Empty<string>();
        string? dir = ScenarioDir();
        if (dir is null) return null;
        string path = Path.Combine(dir, file);
        if (!File.Exists(path)) return null;
        return TraceFormat.Load(path, out warnings);
    }

    public static TheoryData<string> ShippedScenarios() => new()
    {
        "infostealer-chain.jsonl",
        "rat-beacon.jsonl",
        "benign-developer-day.jsonl"
    };

    [Theory]
    [MemberData(nameof(ShippedScenarios))]
    public void Shipped_Scenario_Parses_Without_A_Single_Warning(string file)
    {
        var s = Load(file, out var warnings);
        if (s is null) return;
        Assert.True(warnings.Count == 0, file + ": " + string.Join(" | ", warnings));
        Assert.NotEmpty(s.Events);
    }

    [Theory]
    [MemberData(nameof(ShippedScenarios))]
    public void Shipped_Scenario_Has_Usable_Metadata(string file)
    {
        var s = Load(file, out _);
        if (s is null) return;
        Assert.False(string.IsNullOrWhiteSpace(s.Name));
        Assert.False(string.IsNullOrWhiteSpace(s.Description));
        Assert.NotEmpty(s.Expect);
        Assert.NotEqual(TraceFormat.DefaultStartUtc, s.StartUtc);   // a real anchor, not the fallback
    }

    [Theory]
    [MemberData(nameof(ShippedScenarios))]
    public void Shipped_Scenario_Asserts_Only_Checkable_Expectations(string file)
    {
        var s = Load(file, out _);
        if (s is null) return;
        foreach (var e in s.Expect)
            Assert.True(Expectation.IsWellFormed(e, out string err), $"{file}: '{e}' -- {err}");
    }

    [Theory]
    [MemberData(nameof(ShippedScenarios))]
    public void Shipped_Scenario_Has_Monotonic_Offsets_And_Consistent_Timestamps(string file)
    {
        var s = Load(file, out _);
        if (s is null) return;
        for (int i = 1; i < s.Events.Count; i++)
            Assert.True(s.Events[i].At >= s.Events[i - 1].At, $"{file}: step {i} goes backwards");
        foreach (var e in s.Events)
            Assert.Equal(s.StartUtc + e.At, e.Signal.TimestampUtc);
    }

    [Theory]
    [MemberData(nameof(ShippedScenarios))]
    public void Shipped_Scenario_Survives_A_Write_Parse_Round_Trip(string file)
    {
        var s = Load(file, out _);
        if (s is null) return;
        var again = TraceFormat.Parse(TraceFormat.Write(s), s.Name, out var w);
        Assert.Empty(w);
        Assert.Equal(s.Events.Count, again.Events.Count);
        Assert.Equal(s.Expect, again.Expect);
        for (int i = 0; i < s.Events.Count; i++)
            Assert.Equal(s.Events[i].Signal, again.Events[i].Signal);
    }

    [Theory]
    [MemberData(nameof(ShippedScenarios))]
    public void Shipped_Scenario_Replays_Every_Step(string file)
    {
        var s = Load(file, out _);
        if (s is null) return;

        ReplayScriptedEngine? engine = null;
        var result = new TraceReplay(c => engine = new ReplayScriptedEngine(c)).Run(s);

        Assert.Equal(s.Events.Count, result.SignalsFed);
        Assert.Equal(s.Duration, result.SimulatedDuration);
        Assert.Equal(s.Events.Select(e => e.Signal).ToList(), engine!.Fed);
    }

    [Fact]
    public void Infostealer_Chain_Reaches_Quarantine_On_The_Stealer_Process()
    {
        var s = Load("infostealer-chain.jsonl", out _);
        if (s is null) return;

        var result = new TraceReplay(c => new ReplayMiniRuleEngine(c)).Run(s);

        Assert.Null(Expectation.Check("quarantine:pid=4816", result.Verdicts, result.FinalScores));
        Assert.Null(Expectation.Check("no-quarantine:pid=3120", result.Verdicts, result.FinalScores));
        Assert.Null(Expectation.Check("no-quarantine:pid=1044", result.Verdicts, result.FinalScores));
    }

    [Fact]
    public void Infostealer_Chain_Contains_The_Whole_Narrative()
    {
        var s = Load("infostealer-chain.jsonl", out _);
        if (s is null) return;
        var signals = s.Events.Select(e => e.Signal).ToList();

        Assert.Contains(signals, x => x.Kind == SignalKind.ProcessStart &&
                                      x.ProcessName.Equals("winword.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(signals, x => x.Kind == SignalKind.ProcessStart &&
                                      x.ProcessName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) &&
                                      x.CommandLine.Contains("-enc", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(signals, x => x.Kind == SignalKind.FileCreate &&
                                      (x.FilePath ?? "").Contains("Login Data", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(signals, x => x.Kind == SignalKind.FileCreate &&
                                      (x.FilePath ?? "").Contains("Local State", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(signals, x => x.Kind == SignalKind.DnsQuery && (x.Domain ?? "").EndsWith(".ddns.net"));

        var archive = Assert.Single(signals, x =>
            x.Kind == SignalKind.FileCreate &&
            IocDatabase.ArchiveExtensions.Contains(Path.GetExtension(x.FilePath ?? "").ToLowerInvariant()));
        var connect = Assert.Single(signals, x => x.Kind == SignalKind.NetworkConnect);

        // The staging -> exfil gap has to sit inside the default 30 s correlation window,
        // otherwise the scenario is not exercising the rule it claims to.
        var gap = connect.TimestampUtc - archive.TimestampUtc;
        Assert.InRange(gap, TimeSpan.Zero, TimeSpan.FromSeconds(30));
    }

    [Fact]
    public void Rat_Beacon_Warns_Or_Worse_On_The_Dropped_Executable()
    {
        var s = Load("rat-beacon.jsonl", out _);
        if (s is null) return;

        var result = new TraceReplay(c => new ReplayMiniRuleEngine(c)).Run(s);

        Assert.Null(Expectation.Check("warn:pid=6620", result.Verdicts, result.FinalScores));
        Assert.Null(Expectation.Check("no-quarantine:pid=2288", result.Verdicts, result.FinalScores));
    }

    [Fact]
    public void Rat_Beacon_Has_Twelve_Regular_Connections_To_One_Host()
    {
        var s = Load("rat-beacon.jsonl", out _);
        if (s is null) return;

        var beacons = s.Events
            .Where(e => e.Signal.Kind == SignalKind.NetworkConnect)
            .ToList();

        Assert.Equal(12, beacons.Count);
        Assert.Single(beacons.Select(b => $"{b.Signal.RemoteAddress}:{b.Signal.RemotePort}").Distinct());

        var gaps = beacons.Zip(beacons.Skip(1), (a, b) => (b.At - a.At).TotalSeconds).ToList();
        Assert.Equal(11, gaps.Count);
        Assert.All(gaps, g => Assert.InRange(g, 29.0, 31.0));
        // Jitter must actually be present: an exactly periodic trace would let a naive
        // "is the period constant" detector pass here and miss every real beacon.
        Assert.True(gaps.Distinct().Count() > 5, "the beacon cadence has no jitter");

        Assert.Contains(s.Events, e => e.Signal.Kind == SignalKind.NamedPipe);
        Assert.Contains(s.Events, e => e.Signal.Kind == SignalKind.ImageLoad &&
            IocDatabase.SuspiciousModuleFragments.Any((e.Signal.FilePath ?? "").ToLowerInvariant().Contains));
    }

    [Fact]
    public void Benign_Developer_Day_Quarantines_Nothing()
    {
        var s = Load("benign-developer-day.jsonl", out _);
        if (s is null) return;

        var result = new TraceReplay(c => new ReplayMiniRuleEngine(c)).Run(s);

        Assert.DoesNotContain(result.Verdicts,
            v => v.Verdict.Equals("Quarantine", StringComparison.OrdinalIgnoreCase));
        foreach (int pid in s.Events.Select(e => e.Signal.Pid).Distinct())
            Assert.Null(Expectation.Check($"no-quarantine:pid={pid}", result.Verdicts, result.FinalScores));
    }

    [Fact]
    public void Benign_Developer_Day_Scores_Nothing_At_All()
    {
        var s = Load("benign-developer-day.jsonl", out _);
        if (s is null) return;

        var result = new TraceReplay(c => new ReplayMiniRuleEngine(c)).Run(s);

        Assert.Empty(result.Verdicts);
        Assert.All(result.FinalScores, kv => Assert.Equal(0, kv.Value));
    }

    [Fact]
    public void Benign_Developer_Day_Avoids_Every_Credential_And_Staging_Indicator()
    {
        // Asserted directly against the IOC tables rather than through the engine, so this
        // still guards the file if the scoring weights are ever retuned.
        var s = Load("benign-developer-day.jsonl", out _);
        if (s is null) return;

        foreach (var e in s.Events)
        {
            string file = (e.Signal.FilePath ?? "").ToLowerInvariant();
            if (file.Length == 0) continue;

            Assert.DoesNotContain(IocDatabase.SensitiveFileFragments, file.Contains);

            bool archive = IocDatabase.ArchiveExtensions.Contains(Path.GetExtension(file));
            bool staging = IocDatabase.StagingDirFragments.Any(file.Contains);
            Assert.False(archive && staging, $"benign trace stages an archive: {file}");
        }
    }

    [Fact]
    public void Benign_Developer_Day_Still_Exercises_The_Near_Misses()
    {
        // If the benign trace stopped containing LolBins, archives and outbound traffic it
        // would stop being a false-positive guard and become a file that always passes.
        var s = Load("benign-developer-day.jsonl", out _);
        if (s is null) return;
        var signals = s.Events.Select(e => e.Signal).ToList();

        Assert.Contains(signals, x => x.Kind == SignalKind.ProcessStart &&
                                      IocDatabase.LolBins.Contains(x.ProcessName.ToLowerInvariant()));
        Assert.Contains(signals, x => x.Kind == SignalKind.FileCreate &&
                                      IocDatabase.ArchiveExtensions.Contains(
                                          Path.GetExtension((x.FilePath ?? "").ToLowerInvariant())));
        Assert.Contains(signals, x => x.Kind == SignalKind.NetworkConnect &&
                                      NetworkUtil.IsRoutableRemote(x.RemoteAddress));
        Assert.Contains(signals, x => x.Kind == SignalKind.RegistryWrite);
        Assert.Contains(signals, x => x.Kind == SignalKind.NamedPipe);
    }

    [Fact]
    public void Attack_Scenarios_Only_Reach_Documentation_Ip_Ranges()
    {
        // A shipped scenario must never double as a copy-pasteable list of live C2 hosts.
        foreach (string file in new[] { "infostealer-chain.jsonl", "rat-beacon.jsonl" })
        {
            var s = Load(file, out _);
            if (s is null) continue;

            foreach (var e in s.Events.Where(x => x.Signal.Kind == SignalKind.NetworkConnect))
            {
                string ip = e.Signal.RemoteAddress ?? "";
                Assert.True(
                    ip.StartsWith("192.0.2.") || ip.StartsWith("198.51.100.") || ip.StartsWith("203.0.113."),
                    $"{file}: {ip} is not an RFC 5737 documentation address");
                // …and still routable, or the scenario would not exercise the exfil rule.
                Assert.True(NetworkUtil.IsRoutableRemote(ip), $"{file}: {ip} is filtered as private");
            }
        }
    }
}
