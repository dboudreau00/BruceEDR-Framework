using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Response;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Firewall cleanup (BruceEDR.exe --cleanup, the MSI uninstaller, the GUI button), driven
/// through a fake rule store so no test changes the real firewall.
/// </summary>
public class FirewallCleanupTests
{
    /// <summary>Behaves like the worst plausible INetFwRules: Remove deletes one rule per call.</summary>
    private sealed class FakeStore : IFirewallRuleStore
    {
        public readonly List<string> Rules;
        public int RemoveCalls;
        public bool RemoveIsBroken;
        public FakeStore(params string[] rules) => Rules = rules.ToList();
        public IReadOnlyList<string> RuleNames() => Rules.ToArray();
        public void Remove(string name)
        {
            RemoveCalls++;
            if (RemoveIsBroken) return;
            int i = Rules.IndexOf(name);
            if (i >= 0) Rules.RemoveAt(i);
        }
    }

    private static bool NotApplied() => false;
    private static ActionResult NotCalled() => throw new Xunit.Sdk.XunitException("isolation release must not run");

    [Theory]
    [InlineData("BruceEDR Block evil.exe 4242", true)]
    [InlineData("BruceEDR Block", true)]                       // the sanitiser's fallback name
    [InlineData("ProcessShield Block evil.exe 7", true)]       // created before the rename
    [InlineData("ProcessShield Block", true)]
    [InlineData("BruceEDR Blocklist", false)]                  // someone else's rule
    [InlineData("BruceEDR Isolation Allow Out", false)]
    [InlineData("Block BruceEDR", false)]
    [InlineData("bruceedr block evil.exe 1", false)]           // ordinal: only our exact casing
    [InlineData("Core Networking - DNS (UDP-Out)", false)]
    [InlineData(null, false)]
    public void Only_BruceEDR_block_rules_are_matched(string? name, bool expected)
        => Assert.Equal(expected, FirewallCleanup.IsBlockRule(name));

    [Fact]
    public void Removes_every_block_rule_including_duplicates_and_leaves_other_rules_alone()
    {
        var store = new FakeStore(
            "BruceEDR Block a.exe 1", "BruceEDR Block a.exe 1", "BruceEDR Block b.exe 2",
            "ProcessShield Block c.exe 3", "Core Networking - DNS (UDP-Out)", "BruceEDR Blocklist");

        var r = FirewallCleanup.RemoveAll(store, NotApplied, NotCalled);

        Assert.True(r.Ok, r.Message);
        Assert.Contains("removed 4", r.Message);
        Assert.Equal(new[] { "Core Networking - DNS (UDP-Out)", "BruceEDR Blocklist" }, store.Rules);
    }

    [Fact]
    public void Nothing_to_do_is_a_success_and_isolation_is_not_touched()
    {
        var store = new FakeStore("Core Networking - DNS (UDP-Out)");
        var r = FirewallCleanup.RemoveAll(store, NotApplied, NotCalled);
        Assert.True(r.Ok);
        Assert.Contains("removed 0", r.Message);
        Assert.Equal(0, store.RemoveCalls);
    }

    [Fact]
    public void Isolation_BruceEDR_applied_is_released_before_the_blocks_are_removed()
    {
        var order = new List<string>();
        var store = new FakeStore("BruceEDR Isolation Allow Out", "BruceEDR Block a.exe 1");
        var r = FirewallCleanup.RemoveAll(store, () => true, () =>
        {
            order.Add("release");
            store.Rules.RemoveAll(FirewallCleanup.IsIsolationRule);
            return ActionResult.Success("host isolation released");
        });

        Assert.True(r.Ok, r.Message);
        Assert.Contains("host isolation lifted", r.Message);
        Assert.Equal("release", Assert.Single(order));
        Assert.Empty(store.Rules);
    }

    [Fact]
    public void Isolation_rules_without_proof_leave_the_policy_and_the_allow_rules_alone()
    {
        // The case that matters on a host whose baseline already blocks outbound: allow rules
        // from an aborted or older isolation are no proof BruceEDR changed the policy, so the
        // policy must not be "restored" to allow-outbound, and the allow rules stay (deleting
        // them could lock out a host that is in fact isolated).
        var store = new FakeStore("BruceEDR Isolation Allow Out", "BruceEDR Isolation Allow In", "BruceEDR Block a.exe 1");
        var r = FirewallCleanup.RemoveAll(store, NotApplied, NotCalled);

        Assert.True(r.Ok, r.Message);
        Assert.Contains("isolation allow rules left in place", r.Message);
        Assert.Equal(new[] { "BruceEDR Isolation Allow Out", "BruceEDR Isolation Allow In" }, store.Rules);
    }

    [Fact]
    public void A_failed_isolation_release_is_reported_not_hidden()
    {
        var store = new FakeStore("BruceEDR Isolation Allow In");
        var r = FirewallCleanup.RemoveAll(store, () => true, () => ActionResult.Fail("FAILED TO RESTORE the firewall policy"));
        Assert.False(r.Ok);
        Assert.Contains("FAILED TO RESTORE", r.Message);
    }

    [Fact]
    public void A_store_whose_remove_never_works_ends_with_a_failure_instead_of_spinning()
    {
        var store = new FakeStore("BruceEDR Block a.exe 1") { RemoveIsBroken = true };
        var r = FirewallCleanup.RemoveAll(store, NotApplied, NotCalled);
        Assert.False(r.Ok);
        Assert.Contains("1 block(s) could not be removed", r.Message);
        Assert.Equal(FirewallCleanup.MaxPasses, store.RemoveCalls);
    }

    [Fact]
    public void Access_denied_reads_as_needing_administrator()
    {
        var r = FirewallCleanup.RemoveAll(new ThrowingStore(), NotApplied, NotCalled);
        Assert.False(r.Ok);
        Assert.Contains("administrator", r.Message);
    }

    private sealed class ThrowingStore : IFirewallRuleStore
    {
        public IReadOnlyList<string> RuleNames() => new[] { "BruceEDR Block a.exe 1" };
        public void Remove(string name) => throw new UnauthorizedAccessException();
    }

    [Fact]
    public void The_real_firewall_api_can_be_enumerated_through_the_same_late_bound_calls()
    {
        // READ-ONLY: enumerates rule names, the late-bound COM path no fake can prove.
        // Remove is never called here.
        ComFirewallRuleStore store;
        try { store = new ComFirewallRuleStore(); }
        catch { return; }   // no Windows Firewall service on this machine

        var names = store.RuleNames();
        Assert.NotEmpty(names);                      // Windows always ships built-in rules
        Assert.All(names, n => Assert.False(string.IsNullOrEmpty(n)));
    }
}

/// <summary>
/// The console echo budget. Only the human-facing console is limited; the sink must still
/// receive every event, because that is the record an investigation relies on.
/// </summary>
public class LoggerConsoleThrottleTests
{
    private sealed class CountingSink : IEventSink
    {
        public int Count;
        public void Emit(BruceEvent e) => Interlocked.Increment(ref Count);
        public void Dispose() { }
    }

    private static string[] Lines(StringWriter w)
        => w.ToString().Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);

    [Fact]
    public void A_flood_is_capped_on_the_console_and_summarised_but_the_sink_gets_everything()
    {
        long now = 0;
        var console = new StringWriter();
        var sink = new CountingSink();
        var log = new Logger(sink, console, () => now);

        for (int i = 0; i < 100; i++) log.Info("event " + i);
        Assert.Equal(Logger.ConsoleLinesPerSecond, Lines(console).Length);

        now = 1000;                                   // next window
        log.Info("after the flood");

        var lines = Lines(console);
        Assert.Contains(lines, l => l.Contains("60 line(s) not shown") && l.Contains("every event still reached the log sinks"));
        Assert.Equal("[*] after the flood", lines[^1]);
        Assert.Equal(101, sink.Count);
    }

    [Fact]
    public void Quarantine_and_error_lines_are_never_suppressed_by_a_flood()
    {
        long now = 0;
        var console = new StringWriter();
        var log = new Logger(null, console, () => now);

        for (int i = 0; i < Logger.ConsoleLinesPerSecond + 50; i++) log.Info("noise " + i);
        log.Error("response worker", new InvalidOperationException("boom"));
        log.Quarantine(new DetectionResult
        {
            Verdict = Verdict.Quarantine,
            Trigger = "Watchlist",
            Snapshot = new ProfileSnapshot
            {
                Pid = 4242, ProcessName = "evil.exe", ImagePath = @"C:\t\evil.exe", Score = 90,
                Trusted = false, Contained = true, SuspendedByAnalyst = false, Terminated = false,
                Reasons = new[] { "[+90] watchlist" }, StagedArchives = Array.Empty<string>(),
                FirstSeenUtc = DateTime.UtcNow, LastUpdatedUtc = DateTime.UtcNow,
            },
        });

        var lines = Lines(console);
        Assert.Contains(lines, l => l.StartsWith("[ERR] response worker"));
        Assert.Contains(lines, l => l.StartsWith("[QUARANTINE] pid 4242 evil.exe"));
    }

    [Fact]
    public void Interactive_output_reports_what_was_held_back_and_is_never_suppressed()
    {
        long now = 0;
        var console = new StringWriter();
        var log = new Logger(null, console, () => now);

        for (int i = 0; i < Logger.ConsoleLinesPerSecond + 10; i++) log.Info("noise " + i);
        log.Raw("  pid 4242 evil.exe score 90");     // the answer to a command the analyst typed

        var lines = Lines(console);
        Assert.Equal("  pid 4242 evil.exe score 90", lines[^1]);
        Assert.Contains(lines, l => l.Contains("10 line(s) not shown"));   // flushed before the answer
    }

    [Fact]
    public void Quiet_output_is_untouched()
    {
        long now = 0;
        var console = new StringWriter();
        var log = new Logger(null, console, () => now);
        for (int i = 0; i < 5; i++) { log.Info("line " + i); now += 300; }
        var lines = Lines(console);
        Assert.Equal(5, lines.Length);
        Assert.DoesNotContain(lines, l => l.Contains("not shown"));
    }
}
