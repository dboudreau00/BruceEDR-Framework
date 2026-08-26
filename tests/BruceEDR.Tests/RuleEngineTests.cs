using BruceEDR.Core;
using BruceEDR.Detection;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The rule engine is the project's extensibility surface: it runs JSON written by people
/// who are not us, on a hot path, against hostile input. So these tests care as much about
/// what it refuses and survives as about what it matches.
/// </summary>
public class RuleEngineTests
{
    // ----------------------------------------------------------------- helpers

    private static DetectionRule Rule(string id, params RuleCondition[] all) => new()
    {
        Id = id,
        Title = id,
        Score = 10,
        Detection = new[] { new RuleClause { All = all } }
    };

    private static RuleCondition Cond(string field, MatchOp op, string value) =>
        new() { Field = field, Op = op, Value = value };

    private static RuleCondition CondIn(string field, params string[] values) =>
        new() { Field = field, Op = MatchOp.In, Values = values };

    private static RuleEngine EngineOf(params DetectionRule[] rules) => new(RuleSet.Of(rules));

    private static Signal Start(string name, string commandLine = "", int pid = 100) => new()
    {
        Kind = SignalKind.ProcessStart,
        Pid = pid,
        ProcessName = name,
        ImagePath = @"C:\Windows\System32\" + name,
        CommandLine = commandLine
    };

    // --------------------------------------------------------------- matching

    [Fact]
    public void A_Simple_Equality_Rule_Fires()
    {
        var engine = EngineOf(Rule("r1", Cond("processName", MatchOp.Equals, "powershell.exe")));
        var matches = engine.Evaluate(Start("powershell.exe"), RuleContext.Empty);

        var m = Assert.Single(matches);
        Assert.Equal("r1", m.Rule.Id);
        Assert.False(string.IsNullOrWhiteSpace(m.Explanation));
    }

    [Fact]
    public void Matching_Is_Case_Insensitive_By_Default()
    {
        var engine = EngineOf(Rule("r1", Cond("processName", MatchOp.Equals, "PowerShell.EXE")));
        Assert.Single(engine.Evaluate(Start("powershell.exe"), RuleContext.Empty));
    }

    [Fact]
    public void CaseSensitive_Opt_In_Is_Honoured()
    {
        var rule = new DetectionRule
        {
            Id = "cs",
            Score = 5,
            Detection = new[]
            {
                new RuleClause
                {
                    All = new[]
                    {
                        new RuleCondition
                        {
                            Field = "processName", Op = MatchOp.Equals,
                            Value = "PowerShell.EXE", CaseSensitive = true
                        }
                    }
                }
            }
        };
        Assert.Empty(EngineOf(rule).Evaluate(Start("powershell.exe"), RuleContext.Empty));
        Assert.Single(EngineOf(rule).Evaluate(Start("PowerShell.EXE"), RuleContext.Empty));
    }

    [Fact]
    public void All_Conditions_Must_Match_Within_A_Clause()
    {
        var engine = EngineOf(Rule("r1",
            Cond("processName", MatchOp.Equals, "powershell.exe"),
            Cond("commandLine", MatchOp.Contains, "-enc")));

        Assert.Empty(engine.Evaluate(Start("powershell.exe", "-NoProfile"), RuleContext.Empty));
        Assert.Single(engine.Evaluate(Start("powershell.exe", "-enc ABC"), RuleContext.Empty));
    }

    [Fact]
    public void Clauses_Are_Ored_Together()
    {
        var rule = new DetectionRule
        {
            Id = "either",
            Score = 5,
            Detection = new[]
            {
                new RuleClause { All = new[] { Cond("processName", MatchOp.Equals, "mshta.exe") } },
                new RuleClause { All = new[] { Cond("processName", MatchOp.Equals, "regsvr32.exe") } }
            }
        };
        var engine = EngineOf(rule);
        Assert.Single(engine.Evaluate(Start("mshta.exe"), RuleContext.Empty));
        Assert.Single(engine.Evaluate(Start("regsvr32.exe"), RuleContext.Empty));
        Assert.Empty(engine.Evaluate(Start("notepad.exe"), RuleContext.Empty));
    }

    [Fact]
    public void A_None_Condition_Suppresses_An_Otherwise_Matching_Clause()
    {
        var rule = new DetectionRule
        {
            Id = "with-exception",
            Score = 5,
            Detection = new[]
            {
                new RuleClause
                {
                    All = new[] { Cond("processName", MatchOp.Equals, "curl.exe") },
                    None = new[] { Cond("commandLine", MatchOp.Contains, "--approved") }
                }
            }
        };
        var engine = EngineOf(rule);
        Assert.Single(engine.Evaluate(Start("curl.exe", "https://x/y"), RuleContext.Empty));
        Assert.Empty(engine.Evaluate(Start("curl.exe", "--approved https://x/y"), RuleContext.Empty));
    }

    [Theory]
    [InlineData(MatchOp.Contains, "power", true)]
    [InlineData(MatchOp.NotContains, "power", false)]
    [InlineData(MatchOp.StartsWith, "power", true)]
    [InlineData(MatchOp.StartsWith, "shell", false)]
    [InlineData(MatchOp.EndsWith, ".exe", true)]
    [InlineData(MatchOp.EndsWith, "power", false)]
    [InlineData(MatchOp.NotEquals, "notepad.exe", true)]
    [InlineData(MatchOp.Regex, "^power.*\\.exe$", true)]
    [InlineData(MatchOp.Regex, "^cmd", false)]
    public void String_Operators_Behave(MatchOp op, string value, bool shouldFire)
    {
        var engine = EngineOf(Rule("r", Cond("processName", op, value)));
        var matches = engine.Evaluate(Start("powershell.exe"), RuleContext.Empty);
        Assert.Equal(shouldFire, matches.Count == 1);
    }

    [Fact]
    public void In_And_NotIn_Use_The_Values_List()
    {
        var inRule = new DetectionRule
        {
            Id = "in", Score = 5,
            Detection = new[] { new RuleClause { All = new[] { CondIn("processName", "cmd.exe", "powershell.exe") } } }
        };
        Assert.Single(EngineOf(inRule).Evaluate(Start("powershell.exe"), RuleContext.Empty));
        Assert.Empty(EngineOf(inRule).Evaluate(Start("notepad.exe"), RuleContext.Empty));

        var notIn = new DetectionRule
        {
            Id = "notin", Score = 5,
            Detection = new[]
            {
                new RuleClause
                {
                    All = new[] { new RuleCondition { Field = "processName", Op = MatchOp.NotIn, Values = new[] { "cmd.exe" } } }
                }
            }
        };
        Assert.Single(EngineOf(notIn).Evaluate(Start("powershell.exe"), RuleContext.Empty));
        Assert.Empty(EngineOf(notIn).Evaluate(Start("cmd.exe"), RuleContext.Empty));
    }

    [Fact]
    public void Numeric_Operators_Work_On_Ports_And_Score()
    {
        var engine = EngineOf(Rule("high-port", Cond("remotePort", MatchOp.GreaterThan, "1024")));
        var high = new Signal { Kind = SignalKind.NetworkConnect, Pid = 5, RemoteAddress = "203.0.113.1", RemotePort = 8443 };
        var low = high with { RemotePort = 443 };

        Assert.Single(engine.Evaluate(high, RuleContext.Empty));
        Assert.Empty(engine.Evaluate(low, RuleContext.Empty));

        var scored = EngineOf(Rule("already-hot", Cond("score", MatchOp.GreaterThan, "39")));
        Assert.Single(scored.Evaluate(high, new RuleContext { Score = 40 }));
        Assert.Empty(scored.Evaluate(high, new RuleContext { Score = 39 }));
    }

    [Fact]
    public void CidrIn_Matches_IPv4_And_IPv6_Ranges()
    {
        var v4 = EngineOf(Rule("v4", Cond("remoteAddress", MatchOp.CidrIn, "203.0.113.0/24")));
        Assert.Single(v4.Evaluate(new Signal { Kind = SignalKind.NetworkConnect, Pid = 1, RemoteAddress = "203.0.113.55" }, RuleContext.Empty));
        Assert.Empty(v4.Evaluate(new Signal { Kind = SignalKind.NetworkConnect, Pid = 1, RemoteAddress = "203.0.114.55" }, RuleContext.Empty));

        var v6 = EngineOf(Rule("v6", Cond("remoteAddress", MatchOp.CidrIn, "2001:db8::/32")));
        Assert.Single(v6.Evaluate(new Signal { Kind = SignalKind.NetworkConnect, Pid = 1, RemoteAddress = "2001:db8:dead::1" }, RuleContext.Empty));
        Assert.Empty(v6.Evaluate(new Signal { Kind = SignalKind.NetworkConnect, Pid = 1, RemoteAddress = "2001:dbf:dead::1" }, RuleContext.Empty));
    }

    [Fact]
    public void Exists_And_NotExists_Test_Presence()
    {
        var exists = EngineOf(Rule("has-domain", Cond("domain", MatchOp.Exists, "")));
        var withDomain = new Signal { Kind = SignalKind.DnsQuery, Pid = 7, Domain = "evil.example" };
        var withoutDomain = new Signal { Kind = SignalKind.DnsQuery, Pid = 7 };

        Assert.Single(exists.Evaluate(withDomain, RuleContext.Empty));
        Assert.Empty(exists.Evaluate(withoutDomain, RuleContext.Empty));

        var missing = EngineOf(Rule("no-domain", Cond("domain", MatchOp.NotExists, "")));
        Assert.Empty(missing.Evaluate(withDomain, RuleContext.Empty));
        Assert.Single(missing.Evaluate(withoutDomain, RuleContext.Empty));
    }

    [Fact]
    public void Context_Fields_Resolve_From_The_Rule_Context()
    {
        var engine = EngineOf(Rule("office-parent", Cond("parentName", MatchOp.Equals, "winword.exe")));
        Assert.Single(engine.Evaluate(Start("powershell.exe"), new RuleContext { ParentName = "winword.exe" }));
        Assert.Empty(engine.Evaluate(Start("powershell.exe"), new RuleContext { ParentName = "explorer.exe" }));
    }

    [Fact]
    public void Ancestry_Matches_Any_Ancestor_Not_Just_The_Parent()
    {
        var engine = EngineOf(Rule("office-ancestor", Cond("ancestry", MatchOp.Contains, "winword.exe")));
        var ctx = new RuleContext { ParentName = "cmd.exe", Ancestry = new[] { "cmd.exe", "winword.exe", "explorer.exe" } };

        Assert.Single(engine.Evaluate(Start("powershell.exe"), ctx));
        Assert.Empty(engine.Evaluate(Start("powershell.exe"),
            new RuleContext { Ancestry = new[] { "cmd.exe", "explorer.exe" } }));
    }

    [Fact]
    public void PrimaryTarget_Lets_One_Rule_Cover_Several_Signal_Kinds()
    {
        var engine = EngineOf(Rule("wallet", Cond("primaryTarget", MatchOp.Contains, "wallet.dat")));

        Assert.Single(engine.Evaluate(
            new Signal { Kind = SignalKind.FileCreate, Pid = 1, FilePath = @"C:\u\wallet.dat" }, RuleContext.Empty));
        Assert.Single(engine.Evaluate(
            new Signal { Kind = SignalKind.RegistryWrite, Pid = 1, RegistryKey = @"HKCU\Software\wallet.dat" }, RuleContext.Empty));
    }

    [Fact]
    public void Kinds_Gate_Which_Signals_A_Rule_Sees()
    {
        var rule = new DetectionRule
        {
            Id = "only-dns",
            Score = 5,
            Kinds = new[] { "DnsQuery" },
            Detection = new[] { new RuleClause { All = new[] { Cond("pid", MatchOp.GreaterThan, "0") } } }
        };
        var engine = EngineOf(rule);

        Assert.Single(engine.Evaluate(new Signal { Kind = SignalKind.DnsQuery, Pid = 4, Domain = "x.example" }, RuleContext.Empty));
        Assert.Empty(engine.Evaluate(Start("notepad.exe"), RuleContext.Empty));
    }

    [Fact]
    public void A_Disabled_Rule_Never_Fires()
    {
        var rule = Rule("off", Cond("processName", MatchOp.Equals, "powershell.exe")) with { Enabled = false };
        Assert.Empty(EngineOf(rule).Evaluate(Start("powershell.exe"), RuleContext.Empty));
    }

    [Fact]
    public void The_Explanation_Names_The_Rule_And_Is_Bounded()
    {
        var engine = EngineOf(Rule("r", Cond("commandLine", MatchOp.Contains, "-enc")) with
        {
            Title = "Encoded PowerShell command"
        });

        var m = Assert.Single(engine.Evaluate(Start("powershell.exe", "-enc " + new string('A', 5000)), RuleContext.Empty));
        Assert.Contains("Encoded PowerShell command", m.Explanation, StringComparison.Ordinal);
        Assert.True(m.Explanation.Length < 400,
            $"the explanation must stay readable in an alert; got {m.Explanation.Length} chars");
    }

    // ------------------------------------------------------------- robustness

    [Fact]
    public void Evaluate_Never_Throws_For_A_Signal_With_Every_Optional_Field_Null()
    {
        var engine = EngineOf(
            Rule("a", Cond("filePath", MatchOp.Contains, "x")),
            Rule("b", Cond("domain", MatchOp.Regex, ".*")),
            Rule("c", Cond("registryKey", MatchOp.EndsWith, "Run")),
            Rule("d", Cond("scriptText", MatchOp.Contains, "iex")),
            Rule("e", Cond("remoteAddress", MatchOp.CidrIn, "10.0.0.0/8")),
            Rule("f", Cond("pipeName", MatchOp.StartsWith, "msagent")));

        foreach (SignalKind kind in Enum.GetValues<SignalKind>())
        {
            var bare = new Signal { Kind = kind, Pid = 1 };
            var ex = Record.Exception(() => engine.Evaluate(bare, RuleContext.Empty));
            Assert.True(ex is null, $"{kind} threw: {ex}");
        }
    }

    [Fact]
    public void A_Catastrophically_Backtracking_Regex_Does_Not_Hang_Evaluation()
    {
        // Classic exponential pattern. A rule author can write this by accident, and the
        // engine must degrade to "this rule did not match" rather than freezing the
        // detection thread for the whole endpoint.
        var engine = EngineOf(Rule("evil", Cond("commandLine", MatchOp.Regex, "^(a+)+$")));
        var signal = Start("x.exe", new string('a', 40) + "!");

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var ex = Record.Exception(() => engine.Evaluate(signal, RuleContext.Empty));
        sw.Stop();

        Assert.Null(ex);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5),
            $"regex evaluation must be bounded by the match timeout; took {sw.Elapsed}");
    }

    // ------------------------------------------------------------- validation

    [Fact]
    public void Validation_Rejects_A_Missing_Id()
    {
        var errors = RuleEngine.Validate(new DetectionRule { Id = "  ", Score = 1 });
        Assert.Contains(errors, e => e.IsBlocking);
    }

    [Fact]
    public void Validation_Rejects_An_Unknown_Field()
    {
        var errors = RuleEngine.Validate(Rule("bad", Cond("notAField", MatchOp.Equals, "x")));
        Assert.Contains(errors, e => e.IsBlocking && e.Message.Contains("notAField", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validation_Rejects_An_Uncompilable_Regex()
    {
        var errors = RuleEngine.Validate(Rule("bad", Cond("commandLine", MatchOp.Regex, "([unclosed")));
        Assert.Contains(errors, e => e.IsBlocking);
    }

    [Fact]
    public void Validation_Rejects_An_Empty_Values_List_For_In()
    {
        var rule = new DetectionRule
        {
            Id = "bad", Score = 1,
            Detection = new[]
            {
                new RuleClause { All = new[] { new RuleCondition { Field = "processName", Op = MatchOp.In } } }
            }
        };
        Assert.Contains(RuleEngine.Validate(rule), e => e.IsBlocking);
    }

    [Fact]
    public void Validation_Rejects_An_Unknown_Signal_Kind()
    {
        var rule = Rule("bad", Cond("pid", MatchOp.GreaterThan, "0")) with { Kinds = new[] { "NotAKind" } };
        Assert.Contains(RuleEngine.Validate(rule), e => e.IsBlocking);
    }

    [Fact]
    public void An_Unknown_Attack_Technique_Is_A_Note_Not_A_Blocking_Error()
    {
        // A rule citing a technique newer than the bundled catalogue must still load:
        // punishing a contributor for our stale lookup table would be backwards.
        var rule = Rule("future", Cond("processName", MatchOp.Equals, "x.exe")) with
        {
            Techniques = new[] { "T9999.001" }
        };
        var errors = RuleEngine.Validate(rule);

        Assert.Contains(errors, e => !e.IsBlocking);
        Assert.DoesNotContain(errors, e => e.IsBlocking);
        Assert.Single(EngineOf(rule).Evaluate(Start("x.exe"), RuleContext.Empty));
    }

    // ------------------------------------------------------------ json loading

    [Fact]
    public void ParseJson_Accepts_A_Wrapper_An_Array_And_A_Single_Rule()
    {
        const string body = """
            { "id": "one", "title": "One", "score": 10,
              "detection": [ { "all": [ { "field": "processName", "op": "equals", "value": "a.exe" } ] } ] }
            """;

        Assert.Single(RuleEngine.ParseJson($$"""{ "name": "p", "rules": [ {{body}} ] }""", "wrapper").Rules);
        Assert.Single(RuleEngine.ParseJson($"[ {body} ]", "array").Rules);
        Assert.Single(RuleEngine.ParseJson(body, "single").Rules);
    }

    [Fact]
    public void One_Bad_Rule_Does_Not_Cost_You_The_Good_Ones()
    {
        const string json = """
            { "rules": [
              { "id": "good", "title": "Good rule", "score": 10,
                "detection": [ { "all": [ { "field": "processName", "op": "equals", "value": "a.exe" } ] } ] },
              { "id": "bad", "title": "Bad rule", "score": 10,
                "detection": [ { "all": [ { "field": "nope", "op": "equals", "value": "a.exe" } ] } ] }
            ] }
            """;

        var set = RuleEngine.ParseJson(json, "mixed");
        Assert.Single(set.Rules);
        Assert.Equal("good", set.Rules[0].Id);
        Assert.Contains(set.BlockingErrors, e => e.RuleId == "bad");
    }

    [Fact]
    public void A_Duplicate_Id_Is_Rejected_Rather_Than_Silently_Shadowing()
    {
        const string json = """
            { "rules": [
              { "id": "dup", "title": "First", "score": 10, "detection": [ { "all": [ { "field": "pid", "op": "greaterThan", "value": "0" } ] } ] },
              { "id": "dup", "title": "Second", "score": 20, "detection": [ { "all": [ { "field": "pid", "op": "greaterThan", "value": "0" } ] } ] }
            ] }
            """;

        var set = RuleEngine.ParseJson(json, "dupes");
        Assert.Single(set.Rules);
        Assert.Contains(set.BlockingErrors, e => e.Message.Contains("duplicate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Malformed_Json_Produces_An_Error_Not_An_Exception()
    {
        foreach (var bad in new[] { "", "   ", "{", "not json", "[1,2,3]", "null" })
        {
            var ex = Record.Exception(() => RuleEngine.ParseJson(bad, "bad"));
            Assert.True(ex is null, $"ParseJson threw for {bad.Length} char input: {ex}");
        }
    }

    [Fact]
    public void Operator_Aliases_Parse()
    {
        const string json = """
            { "rules": [ { "id": "aliased", "title": "Aliased", "score": 5, "detection": [ { "all": [
                { "field": "processName", "op": "eq",  "value": "a.exe" },
                { "field": "commandLine", "op": "has", "value": "x" }
            ] } ] } ] }
            """;

        var set = RuleEngine.ParseJson(json, "aliases");
        Assert.Empty(set.BlockingErrors);
        Assert.Single(new RuleEngine(set).Evaluate(Start("a.exe", "-x"), RuleContext.Empty));
    }

    [Fact]
    public void TechniqueCoverage_Counts_Rules_Per_Technique()
    {
        var engine = EngineOf(
            Rule("a", Cond("pid", MatchOp.GreaterThan, "0")) with { Techniques = new[] { "T1059", "T1105" } },
            Rule("b", Cond("pid", MatchOp.GreaterThan, "0")) with { Techniques = new[] { "T1059" } });

        var coverage = engine.TechniqueCoverage();
        Assert.Equal(2, coverage["T1059"]);
        Assert.Equal(1, coverage["T1105"]);
    }

    [Fact]
    public void LoadDirectory_Is_Safe_On_A_Missing_Or_Empty_Directory()
    {
        Assert.Empty(RuleEngine.LoadDirectory(Path.Combine(Path.GetTempPath(), "no-such-dir-" + Guid.NewGuid().ToString("N"))).Rules);

        string dir = Path.Combine(Path.GetTempPath(), "ps-rules-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try { Assert.Empty(RuleEngine.LoadDirectory(dir).Rules); }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void LoadDirectory_Reads_Every_Pack_And_Skips_Unparsable_Files()
    {
        string dir = Path.Combine(Path.GetTempPath(), "ps-rules-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "10-a.json"), """
                { "rules": [ { "id": "a", "title": "A", "score": 5, "detection": [ { "all": [ { "field": "pid", "op": "greaterThan", "value": "0" } ] } ] } ] }
                """);
            File.WriteAllText(Path.Combine(dir, "20-b.json"), """
                { "rules": [ { "id": "b", "title": "B", "score": 5, "detection": [ { "all": [ { "field": "pid", "op": "greaterThan", "value": "0" } ] } ] } ] }
                """);
            File.WriteAllText(Path.Combine(dir, "30-broken.json"), "{ this is not json");

            var set = RuleEngine.LoadDirectory(dir);
            Assert.Equal(2, set.Rules.Count);
            Assert.NotEmpty(set.Errors);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ------------------------------------------------------- the shipped packs

    /// <summary>Walks up to the repo's rules directory; null when running outside a source tree.</summary>
    private static string? ShippedRulesDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "rules", "detection");
            if (Directory.Exists(probe) && Directory.GetFiles(probe, "*.json").Length > 0) return probe;
        }
        return null;
    }

    [Fact]
    public void The_Shipped_Rule_Packs_Load_With_No_Blocking_Errors()
    {
        var dir = ShippedRulesDirectory();
        if (dir is null) return;

        var set = RuleEngine.LoadDirectory(dir);
        Assert.Empty(set.BlockingErrors.Select(e => e.ToString()));
        Assert.True(set.Rules.Count >= 40, $"expected the shipped packs to carry real content, found {set.Rules.Count}");
    }

    [Fact]
    public void Every_Shipped_Rule_Is_Documented_Well_Enough_To_Action()
    {
        var dir = ShippedRulesDirectory();
        if (dir is null) return;

        var problems = new List<string>();
        foreach (var r in RuleEngine.LoadDirectory(dir).Rules)
        {
            if (string.IsNullOrWhiteSpace(r.Title)) problems.Add($"{r.Id}: no title");
            if (string.IsNullOrWhiteSpace(r.Description)) problems.Add($"{r.Id}: no description");
            if (r.Techniques.Count == 0) problems.Add($"{r.Id}: no ATT&CK techniques");
            if (r.FalsePositives.Count == 0) problems.Add($"{r.Id}: no documented false positives");
            if (r.Score == 0) problems.Add($"{r.Id}: scores zero, so it can never affect a verdict");
        }

        Assert.True(problems.Count == 0, "shipped rules must meet the contribution bar:\n  " + string.Join("\n  ", problems));
    }

    /// <summary>
    /// The only shipped rules allowed to cross the default quarantine threshold on their
    /// own. Both describe behaviour with essentially no benign explanation on a normal
    /// endpoint, and both document a narrow, scheduled false positive.
    ///
    /// Adding to this list must be a conscious decision, which is the point of pinning it
    /// in a test: at score 70 a single heuristic suspends a live process with no
    /// corroboration. <c>lsass-handle-with-vm-read</c> was deliberately moved below the
    /// line because its own falsePositives note lists Defender, Windows Error Reporting
    /// and Task Manager — shipping it at 70 would suspend the user's antivirus by default.
    /// </summary>
    private static readonly HashSet<string> MayQuarantineAlone = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass-handle-with-write-or-inject",
        "ntds-database-access"
    };

    [Fact]
    public void Only_Explicitly_Sanctioned_Rules_Can_Quarantine_On_Their_Own()
    {
        var dir = ShippedRulesDirectory();
        if (dir is null) return;

        var overreaching = RuleEngine.LoadDirectory(dir).Rules
            .Where(r => r.Score >= 70 && !MayQuarantineAlone.Contains(r.Id))
            .Select(r => $"{r.Id} scores {r.Score}")
            .ToArray();

        Assert.True(overreaching.Length == 0,
            "a rule at or above the default quarantine threshold suspends a process with no " +
            "corroborating signal. Either lower the score or add the id to MayQuarantineAlone " +
            "with a justification:\n  " + string.Join("\n  ", overreaching));
    }

    [Fact]
    public void No_Shipped_Rule_Scores_Absurdly_High()
    {
        var dir = ShippedRulesDirectory();
        if (dir is null) return;

        foreach (var r in RuleEngine.LoadDirectory(dir).Rules)
            Assert.True(r.Score <= 80, $"{r.Id} scores {r.Score}; nothing observable at this layer is that certain");
    }

    [Fact]
    public void The_Shipped_Packs_Do_Not_Fire_On_Obviously_Benign_Activity()
    {
        var dir = ShippedRulesDirectory();
        if (dir is null) return;
        var engine = new RuleEngine(RuleEngine.LoadDirectory(dir));

        // Ordinary developer-workstation signals. None of these should trip a detection on
        // their own; anything that does is a false positive shipped by default.
        var benign = new Signal[]
        {
            new() { Kind = SignalKind.ProcessStart, Pid = 10, ProcessName = "notepad.exe",
                    ImagePath = @"C:\Windows\System32\notepad.exe" },
            new() { Kind = SignalKind.ProcessStart, Pid = 11, ProcessName = "explorer.exe",
                    ImagePath = @"C:\Windows\explorer.exe" },
            new() { Kind = SignalKind.FileCreate, Pid = 12,
                    FilePath = @"C:\Users\dev\source\myproject\bin\Release\app.dll" },
            new() { Kind = SignalKind.DnsQuery, Pid = 13, Domain = "github.com" },
            new() { Kind = SignalKind.DnsQuery, Pid = 13, Domain = "registry.npmjs.org" },
            new() { Kind = SignalKind.NetworkConnect, Pid = 13, RemoteAddress = "140.82.121.4", RemotePort = 443 }
        };

        var fired = new List<string>();
        foreach (var s in benign)
            foreach (var m in engine.Evaluate(s, RuleContext.Empty))
                fired.Add($"{m.Rule.Id} fired on {s.Kind} {s.PrimaryTarget}");

        Assert.True(fired.Count == 0, "shipped rules fired on benign activity:\n  " + string.Join("\n  ", fired));
    }
}
