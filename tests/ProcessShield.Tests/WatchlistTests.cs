using ProcessShield.Configuration;
using ProcessShield.Core;
using ProcessShield.Detection;
using Xunit;

namespace ProcessShield.Tests;

/// <summary>
/// The operator watchlist is the custom-detection surface: "if you ever see this, act".
/// These tests pin the behaviour an operator is relying on when they add an entry --
/// especially that a Quarantine entry convicts a SIGNED binary (the whole point) and that
/// it can never be aimed at a core Windows process (the whole risk).
/// </summary>
public sealed class WatchlistTests
{
    private static WatchlistEntryConfig Entry(string value, string match = "name",
        string action = "quarantine", int score = 50, string note = "")
        => new() { Value = value, Match = match, Action = action, Score = score, Note = note };

    private static Watchlist Compile(params WatchlistEntryConfig[] entries)
        => Watchlist.Compile(entries);

    private static DetectionEngine Engine(Watchlist list, bool trusted = false,
        bool alertOnEveryHit = true, Func<string, string?>? hash = null)
        => new(new EngineOptions { AlertOnEveryWatchlistHit = alertOnEveryHit },
               _ => trusted,
               new EngineDependencies { Watchlist = list, ImageHash = hash });

    private static Signal Start(int pid, string name, string image = "", string cmd = "")
        => new()
        {
            Kind = SignalKind.ProcessStart,
            Pid = pid,
            ProcessName = name,
            ImagePath = image,
            CommandLine = cmd,
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        };

    // ---------------------------------------------------------------- compiling

    [Fact]
    public void Name_entry_gets_an_implicit_exe_suffix()
    {
        var list = Compile(Entry("mimikatz"));
        Assert.Equal("mimikatz.exe", list.Entries[0].Pattern);
    }

    [Fact]
    public void Name_entry_strips_a_path_the_operator_pasted()
    {
        var list = Compile(Entry(@"C:\tools\Mimikatz.exe"));
        Assert.Equal("mimikatz.exe", list.Entries[0].Pattern);
    }

    [Theory]
    [InlineData("*")]
    [InlineData("*.*")]
    [InlineData("*.exe")]
    [InlineData("**")]
    public void Patterns_that_match_everything_are_refused(string pattern)
    {
        var errors = new List<string>();
        var list = Watchlist.Compile(new[] { Entry(pattern) }, errors.Add);
        Assert.Equal(0, list.Count);
        Assert.Contains(errors, e => e.Contains("matches everything"));
    }

    [Fact]
    public void A_bad_entry_does_not_discard_the_good_ones()
    {
        var errors = new List<string>();
        var list = Watchlist.Compile(
            new[] { Entry("*"), Entry("mimikatz"), Entry("x", match: "nonsense") }, errors.Add);

        Assert.Equal(1, list.Count);
        Assert.Equal("mimikatz.exe", list.Entries[0].Pattern);
        Assert.Equal(2, errors.Count);
    }

    [Fact]
    public void Hash_entries_must_be_sha256()
    {
        var errors = new List<string>();
        var list = Watchlist.Compile(new[] { Entry("deadbeef", match: "hash") }, errors.Add);
        Assert.Equal(0, list.Count);
        Assert.Contains(errors, e => e.Contains("SHA-256"));
    }

    [Fact]
    public void Disabled_entries_are_not_compiled()
    {
        var list = Watchlist.Compile(new[] { new WatchlistEntryConfig { Value = "mimikatz", Enabled = false } });
        Assert.Equal(0, list.Count);
    }

    [Fact]
    public void Duplicate_entries_are_collapsed()
    {
        var list = Compile(Entry("mimikatz"), Entry("MIMIKATZ.EXE"));
        Assert.Equal(1, list.Count);
    }

    [Fact]
    public void Hash_matching_is_only_armed_when_a_hash_entry_exists()
    {
        Assert.False(Compile(Entry("mimikatz")).NeedsHash);
        Assert.True(Compile(Entry(new string('a', 64), match: "hash")).NeedsHash);
    }

    // ---------------------------------------------------------------- matching

    [Fact]
    public void Matches_by_name_case_insensitively()
    {
        var hit = Compile(Entry("mimikatz")).Match("MiMiKatz.exe", "", "", null);
        Assert.NotNull(hit);
        Assert.Equal(WatchAction.Quarantine, hit!.Action);
    }

    [Fact]
    public void Name_match_is_exact_not_substring()
    {
        // "notmimikatz.exe" must NOT trip an entry for "mimikatz" -- a substring match here
        // would let an attacker dodge the list by renaming, and would also over-match.
        Assert.Null(Compile(Entry("mimikatz")).Match("notmimikatz.exe", "", "", null));
    }

    [Fact]
    public void Glob_names_match()
    {
        var list = Compile(Entry("psexe*"));
        Assert.NotNull(list.Match("psexesvc.exe", "", "", null));
        Assert.Null(list.Match("explorer.exe", "", "", null));
    }

    [Fact]
    public void Path_entries_match_a_substring_of_the_image_path()
    {
        var hit = Compile(Entry(@"\temp\", match: "path")).Match("x.exe", @"C:\Users\a\Temp\x.exe", "", null);
        Assert.NotNull(hit);
    }

    [Fact]
    public void Command_line_entries_match_a_substring()
    {
        var hit = Compile(Entry("--rhost", match: "cmdline"))
            .Match("x.exe", "", "x.exe --rhost 10.0.0.1", null);
        Assert.NotNull(hit);
    }

    [Fact]
    public void Hash_entries_match_exactly()
    {
        string sha = new('a', 64);
        var list = Compile(Entry(sha.ToUpperInvariant(), match: "hash"));
        Assert.NotNull(list.Match("x.exe", "", "", sha));
        Assert.Null(list.Match("x.exe", "", "", new string('b', 64)));
    }

    [Fact]
    public void Entries_are_evaluated_in_order_so_a_specific_rule_can_win()
    {
        var list = Compile(
            Entry("tool.exe", action: "score", score: 10),
            Entry("tool*", action: "quarantine"));
        Assert.Equal(WatchAction.Score, list.Match("tool.exe", "", "", null)!.Action);
    }

    [Fact]
    public void Empty_watchlist_matches_nothing()
        => Assert.Null(Watchlist.Empty.Match("mimikatz.exe", "", "", null));

    [Theory]
    [InlineData("a*c", "abc", true)]
    [InlineData("a*c", "ac", true)]
    [InlineData("a?c", "abc", true)]
    [InlineData("a?c", "ac", false)]
    [InlineData("*.exe", "x.exe", true)]
    [InlineData("a*b*c", "azzbzzc", true)]
    [InlineData("a*b*c", "azzbzz", false)]
    public void Glob_semantics(string pattern, string subject, bool expected)
        => Assert.Equal(expected, Watchlist.Glob(pattern, subject));

    // ---------------------------------------------------------------- safety

    [Theory]
    [InlineData("lsass.exe")]
    [InlineData("csrss.exe")]
    [InlineData("services.exe")]
    [InlineData("wininit.exe")]
    [InlineData("smss.exe")]
    [InlineData("svchost.exe")]
    public void Containment_is_withheld_for_protected_windows_processes(string name)
    {
        var hit = Compile(Entry(name)).Match(name, "", "", null);

        Assert.NotNull(hit);
        Assert.True(hit!.Downgraded);
        Assert.Equal(WatchAction.Warn, hit.Action);          // reported, never contained
        Assert.Contains("containment withheld", hit.Reason);
    }

    [Fact]
    public void A_protected_process_still_produces_a_warn_not_silence()
    {
        var engine = Engine(Compile(Entry("lsass.exe")));
        var results = engine.Ingest(Start(700, "lsass.exe"));

        var r = Assert.Single(results);
        Assert.Equal(Verdict.Warn, r.Verdict);
    }

    [Fact]
    public void Protected_list_normalises_the_name_it_is_given()
    {
        Assert.True(Watchlist.IsProtected(@"C:\Windows\System32\LSASS.EXE"));
        Assert.False(Watchlist.IsProtected("mimikatz.exe"));
    }

    // ---------------------------------------------------------------- engine wiring

    [Fact]
    public void Quarantine_entry_contains_on_sight_with_no_other_evidence()
    {
        var engine = Engine(Compile(Entry("mimikatz")));

        var results = engine.Ingest(Start(1000, "mimikatz.exe"));

        var r = Assert.Single(results);
        Assert.Equal(Verdict.Quarantine, r.Verdict);
        // The trigger names the watchlist, not the signal that happened to arrive first,
        // so the alert says WHY this was contained.
        Assert.Equal("Watchlist", r.Trigger);
        // Containment here is policy, not accumulated evidence: the score stays at the
        // entry's own weight rather than being inflated to the quarantine threshold.
        Assert.Equal(50, r.Snapshot.Score);
    }

    [Fact]
    public void Quarantine_entry_beats_the_trusted_publisher_discount()
    {
        // The point of the feature: an operator naming a binary outranks its signature.
        // If the trust discount could veto this, watchlisting any signed tool (a legitimately
        // signed remote-access product, say) would silently do nothing.
        var engine = Engine(Compile(Entry("teamviewer")), trusted: true);

        var results = engine.Ingest(Start(1001, "teamviewer.exe"));

        var r = Assert.Single(results);
        Assert.Equal(Verdict.Quarantine, r.Verdict);
    }

    [Fact]
    public void Warn_entry_alerts_without_containing()
    {
        var engine = Engine(Compile(Entry("nmap", action: "warn")));

        var r = Assert.Single(engine.Ingest(Start(1002, "nmap.exe")));

        Assert.Equal(Verdict.Warn, r.Verdict);
        Assert.False(r.Snapshot.Contained);
    }

    [Fact]
    public void Score_entry_below_threshold_alerts_but_does_not_contain()
    {
        var engine = Engine(Compile(Entry("curl", action: "score", score: 10)));

        var r = Assert.Single(engine.Ingest(Start(1003, "curl.exe")));

        Assert.Equal(Verdict.Warn, r.Verdict);
        Assert.Equal(10, r.Snapshot.Score);
    }

    [Fact]
    public void Score_entry_is_silent_when_alerting_on_every_hit_is_off()
    {
        var engine = Engine(Compile(Entry("curl", action: "score", score: 10)), alertOnEveryHit: false);

        Assert.Empty(engine.Ingest(Start(1004, "curl.exe")));
    }

    [Fact]
    public void The_reason_carries_the_operator_note_into_the_alert()
    {
        var engine = Engine(Compile(Entry("mimikatz", note: "known red-team tool")));

        var r = Assert.Single(engine.Ingest(Start(1005, "mimikatz.exe")));

        Assert.Contains("known red-team tool", string.Join(" ", r.Snapshot.Reasons));
    }

    [Fact]
    public void A_hit_fires_once_not_on_every_subsequent_signal()
    {
        var engine = Engine(Compile(Entry("mimikatz")));
        engine.Ingest(Start(1006, "mimikatz.exe"));

        // Later signals for the same, already-contained process must not re-convict.
        var again = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate,
            Pid = 1006,
            ProcessName = "mimikatz.exe",
            FilePath = @"C:\x.txt",
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 5, DateTimeKind.Utc),
        });

        Assert.All(again, r => Assert.NotEqual(Verdict.Quarantine, r.Verdict));
    }

    [Fact]
    public void An_entry_matching_a_late_arriving_image_path_still_fires()
    {
        // ProcessStart under the WMI fallback often has no ImagePath; it arrives later.
        // The engine re-checks when the identity fingerprint changes, so the entry must
        // still fire rather than being missed because the first check saw only a name.
        var engine = Engine(Compile(Entry(@"\appdata\local\temp\", match: "path")));

        Assert.Empty(engine.Ingest(Start(1007, "x.exe")));

        var later = engine.Ingest(new Signal
        {
            Kind = SignalKind.ImageLoad,
            Pid = 1007,
            ProcessName = "x.exe",
            ImagePath = @"C:\Users\a\AppData\Local\Temp\x.exe",
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 2, DateTimeKind.Utc),
        });

        Assert.Contains(later, r => r.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void Hash_entries_are_matched_through_the_supplied_hasher()
    {
        string sha = new('c', 64);
        var engine = Engine(Compile(Entry(sha, match: "hash")), hash: _ => sha);

        var r = Assert.Single(engine.Ingest(Start(1008, "renamed.exe", @"C:\x\renamed.exe")));

        Assert.Equal(Verdict.Quarantine, r.Verdict);
    }

    [Fact]
    public void The_hasher_is_not_called_when_no_hash_entry_exists()
    {
        int calls = 0;
        var engine = Engine(Compile(Entry("mimikatz")), hash: _ => { calls++; return null; });

        engine.Ingest(Start(1009, "notmatching.exe", @"C:\x\notmatching.exe"));

        Assert.Equal(0, calls);
    }

    [Fact]
    public void A_recycled_pid_does_not_inherit_a_watchlist_conviction()
    {
        var engine = Engine(Compile(Entry("mimikatz")));
        engine.Ingest(Start(1010, "mimikatz.exe"));
        Assert.True(engine.SnapshotOne(1010)!.Contained);

        // Windows reuses the pid for something innocent. The fresh profile must not carry
        // the previous tenant's containment, or the new process starts life convicted.
        var reborn = engine.Ingest(Start(1010, "notepad.exe"));

        Assert.Empty(reborn);
        var snap = engine.SnapshotOne(1010)!;
        Assert.Equal("notepad.exe", snap.ProcessName);
        Assert.False(snap.Contained);
        Assert.Equal(0, snap.Score);
    }

    [Fact]
    public void Watchlist_is_read_late_so_a_reload_takes_effect()
    {
        // The engine must consult the CURRENT watchlist on every signal. Capturing the
        // list at construction would make editing it a silent no-op until restart.
        var live = Watchlist.Empty;
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { WatchlistProvider = () => live });

        Assert.Empty(engine.Ingest(Start(1011, "mimikatz.exe")));

        live = Compile(Entry("mimikatz"));

        var after = engine.Ingest(Start(1012, "mimikatz.exe"));
        Assert.Equal(Verdict.Quarantine, Assert.Single(after).Verdict);
    }

    [Fact]
    public void Techniques_from_an_entry_reach_the_snapshot()
    {
        var list = Watchlist.Compile(new[]
        {
            new WatchlistEntryConfig
            {
                Value = "mimikatz", Action = "quarantine",
                Techniques = new[] { "T1003.001" },
            }
        });
        var engine = Engine(list);

        var r = Assert.Single(engine.Ingest(Start(1013, "mimikatz.exe")));

        Assert.Contains("T1003.001", r.Snapshot.Techniques);
    }

    [Fact]
    public void Config_clamps_an_out_of_range_entry_score()
    {
        var cfg = new ShieldConfig();
        cfg.Watchlist.Entries = new[] { Entry("x", action: "score", score: 5000) };

        cfg.ClampAndValidate();

        Assert.Equal(100, cfg.Watchlist.Entries[0].Score);
    }
}
