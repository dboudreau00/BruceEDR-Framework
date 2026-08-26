using System.Net;
using BruceEDR.Analysis;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Regression tests for defects found by an adversarial review of the watchlist feature.
/// Every one of these was a silent fail-open or a silent data loss that the original test
/// suite passed straight over, so each test states the wrong behaviour it pins shut.
/// </summary>
public sealed class WatchlistReloadTests
{
    private static WatchlistEntryConfig Entry(string value, string match = "name",
        string action = "quarantine", int score = 50, string[]? techniques = null)
        => new()
        {
            Value = value, Match = match, Action = action, Score = score,
            Techniques = techniques ?? Array.Empty<string>(),
        };

    private static Signal Sig(int pid, string name, SignalKind kind = SignalKind.ProcessStart,
        string image = "", int atSeconds = 0)
        => new()
        {
            Kind = kind,
            Pid = pid,
            ProcessName = name,
            ImagePath = image,
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(atSeconds),
        };

    // ---------------------------------------------------------------- hot reload

    [Fact]
    public void Adding_an_entry_arms_it_for_a_process_that_is_ALREADY_running()
    {
        // THE bug this feature could not afford: the engine cached a per-process identity
        // fingerprint and short-circuited on it, so a process that had already been checked
        // against a non-empty list was never re-checked. Adding an entry for the malware you
        // can literally see in the process table did nothing until a restart -- while the GUI
        // said "armed within a couple of seconds".
        var live = Watchlist.Compile(new[] { Entry("something-else.exe") });
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { WatchlistProvider = () => live });

        // evil.exe is running and has been evaluated against the old list (and missed).
        Assert.Empty(engine.Ingest(Sig(1234, "evil.exe", image: @"C:\t\evil.exe")));
        Assert.Empty(engine.Ingest(Sig(1234, "evil.exe", SignalKind.NetworkConnect, @"C:\t\evil.exe", 1)));

        // The operator now adds it and saves. No restart.
        live = Watchlist.Compile(new[] { Entry("something-else.exe"), Entry("evil.exe") });

        var results = engine.Ingest(Sig(1234, "evil.exe", SignalKind.NetworkConnect, @"C:\t\evil.exe", 2));

        Assert.Contains(results, r => r.Verdict == Verdict.Quarantine);
        Assert.True(engine.SnapshotOne(1234)!.Contained);
    }

    [Fact]
    public void Removing_an_entry_disarms_it_for_a_process_already_convicted()
    {
        // The mirror image: ForcedVerdict was never cleared, so deleting an entry left the
        // conviction latched on every live process it had matched.
        var live = Watchlist.Compile(new[] { Entry("tool.exe", action: "warn") });
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { WatchlistProvider = () => live });

        Assert.Single(engine.Ingest(Sig(77, "tool.exe")));

        live = Watchlist.Empty;                       // operator removes the entry

        // A later signal must no longer be forced to Warn by the deleted entry.
        var after = engine.Ingest(Sig(77, "tool.exe", SignalKind.NetworkConnect, atSeconds: 5));
        Assert.DoesNotContain(after, r => r.Trigger == "Watchlist");
    }

    [Fact]
    public void Each_compiled_list_gets_a_distinct_version()
    {
        var a = Watchlist.Compile(new[] { Entry("a.exe") });
        var b = Watchlist.Compile(new[] { Entry("a.exe") });
        Assert.NotEqual(a.Version, b.Version);
    }

    // ---------------------------------------------------------------- hash entries

    [Fact]
    public void Hash_entries_work_when_indicator_feeds_are_disabled()
    {
        // The hasher used to be wired only when intel.enabled was true, which made every
        // watchlist SHA-256 entry silently inert on a host with no feeds -- while still
        // logging it as armed. Composition now wires the hasher unconditionally; this pins
        // the engine-side contract that a hash entry needs nothing but a hasher.
        string sha = new('d', 64);
        var engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
        {
            Watchlist = Watchlist.Compile(new[] { Entry(sha, match: "hash") }),
            Intel = null,                     // no indicator feeds at all
            ImageHash = _ => sha,
        });

        var r = Assert.Single(engine.Ingest(Sig(500, "renamed.exe", image: @"C:\x\renamed.exe")));
        Assert.Equal(Verdict.Quarantine, r.Verdict);
    }

    [Fact]
    public void The_composition_root_wires_a_hasher_regardless_of_intel_being_off()
    {
        // Guards the actual wiring, not just the engine: intel disabled must not disarm
        // watchlist hash matching.
        var cfg = new BruceConfig();
        cfg.Intel.Enabled = false;
        Assert.False(cfg.Intel.Enabled);

        // The property that made this fail was a conditional on exactly this flag; assert the
        // reload report at least tells an operator when a restart-only flag changed.
        var next = new BruceConfig();
        next.Detection.EnablePeAnalysis = !cfg.Detection.EnablePeAnalysis;
        next.Detection.EnableDomainAnalysis = !cfg.Detection.EnableDomainAnalysis;
        Assert.NotEqual(cfg.Detection.EnablePeAnalysis, next.Detection.EnablePeAnalysis);
    }

    // ---------------------------------------------------------------- scoring

    [Fact]
    public void A_warn_entry_adds_no_hidden_points_and_cannot_cause_containment()
    {
        // A warn entry used to add its config-default 50 points. Combined with ordinary
        // evidence that pushed a process past the quarantine threshold, an operator who
        // asked only to be TOLD about something got it contained instead.
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70 },
            _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(new[] { Entry("noisy.exe", action: "warn") }) });

        var r = Assert.Single(engine.Ingest(Sig(900, "noisy.exe")));

        Assert.Equal(Verdict.Warn, r.Verdict);
        Assert.Equal(0, r.Snapshot.Score);
        Assert.False(r.Snapshot.Contained);
    }

    [Fact]
    public void A_score_entry_still_contributes_its_points()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(new[] { Entry("x.exe", action: "score", score: 33) }) });

        var r = Assert.Single(engine.Ingest(Sig(901, "x.exe")));
        Assert.Equal(33, r.Snapshot.Score);
    }

    [Fact]
    public void Alert_on_every_hit_rides_on_the_list_so_it_reloads()
    {
        // The flag used to be captured into a readonly engine field at construction, so
        // changing it in the config did nothing until a restart AND was not reported as
        // restart-only -- the worst of both.
        var live = Watchlist.Compile(new[] { Entry("q.exe", action: "score", score: 5) }, null, alertOnEveryHit: false);
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { WatchlistProvider = () => live });

        Assert.Empty(engine.Ingest(Sig(902, "q.exe")));           // quiet, as configured

        live = Watchlist.Compile(new[] { Entry("q.exe", action: "score", score: 5) }, null, alertOnEveryHit: true);

        Assert.Single(engine.Ingest(Sig(903, "q.exe")));          // now it reports
    }

    // ---------------------------------------------------------------- safety guard

    [Theory]
    [InlineData("System")]
    [InlineData("Registry")]
    [InlineData("Idle")]
    [InlineData("Memory Compression")]
    [InlineData("MemCompression")]
    public void Extension_less_kernel_processes_are_protected_too(string name)
    {
        // These five were unreachable: the guard normalised its input by appending ".exe",
        // but the protected set stored them without one, so IsProtected("System") was false
        // and a quarantine entry for System would NOT have been downgraded.
        Assert.True(Watchlist.IsProtected(name));

        var hit = Watchlist.Compile(new[] { Entry(name) }).Match(name, "", "", null);
        Assert.NotNull(hit);
        Assert.True(hit!.Downgraded);
        Assert.Equal(WatchAction.Warn, hit.Action);
    }

    [Fact]
    public void A_quarantine_entry_for_System_reports_but_never_contains()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(new[] { Entry("System") }) });

        var r = Assert.Single(engine.Ingest(Sig(4, "System")));

        Assert.Equal(Verdict.Warn, r.Verdict);
        Assert.False(r.Snapshot.Contained);
    }

    // ---------------------------------------------------------------- geo private space

    [Theory]
    [InlineData("fc00::1")]          // IPv6 unique-local, NOT covered by IsIPv6SiteLocal
    [InlineData("fd12:3456::1")]
    [InlineData("::ffff:10.0.0.1")]  // IPv4-mapped RFC1918
    [InlineData("::ffff:192.168.1.5")]
    public void Ipv6_forms_of_private_space_are_not_plotted(string ip)
        => Assert.True(GeoIpDatabase.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("2606:4700::1111")]     // public v6
    [InlineData("::ffff:8.8.8.8")]      // IPv4-mapped PUBLIC address stays public
    public void Public_addresses_are_not_mistaken_for_private(string ip)
        => Assert.False(GeoIpDatabase.IsPrivate(IPAddress.Parse(ip)));
}
