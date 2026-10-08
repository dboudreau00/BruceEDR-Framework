using System.Text.Json;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Hosting;
using BruceEDR.Memory;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// response.mode = monitor is the shipped default: a first run must detect and log, and
/// never suspend, firewall-block, quarantine or kill anything on its own. Every test that
/// matters here drives the real host, because containment is decided at the host seam,
/// not in the engine. The pids used do not exist, so an attempted suspend shows up as
/// "suspend failed" -- which is exactly the line monitor mode must never produce.
/// </summary>
public sealed class MonitorModeTests : IDisposable
{
    private readonly List<BruceHost> _hosts = new();
    private readonly List<string> _tempDirs = new();

    public void Dispose()
    {
        foreach (var h in _hosts) { try { h.Dispose(); } catch { } }
        foreach (var d in _tempDirs) { try { Directory.Delete(d, recursive: true); } catch { } }
    }

    private sealed class RecordingSink : IEventSink
    {
        private readonly List<BruceEvent> _events = new();
        public void Emit(BruceEvent e) { lock (_events) _events.Add(e); }
        public void Dispose() { }
        public bool Any(string level, string fragment)
        {
            lock (_events)
                return _events.Any(e => e.Level == level && e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        }
        public bool AnyMessage(string fragment)
        {
            lock (_events)
                return _events.Any(e => e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        }
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    private static Signal Sig(int pid, string name, SignalKind kind = SignalKind.ProcessStart, int atSeconds = 0)
        => new()
        {
            Kind = kind, Pid = pid, ProcessName = name, ImagePath = @"C:\t\" + name,
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(atSeconds),
        };

    private sealed class CountingSink : IEventSink
    {
        private readonly List<BruceEvent> _events = new();
        public void Emit(BruceEvent e) { lock (_events) _events.Add(e); }
        public void Dispose() { }
        public int Count(string fragment)
        {
            lock (_events) return _events.Count(e => e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        }
    }

    private BruceHost NewHost(RecordingSink sink, bool monitorOnly, bool autoKill = false, params string[] watchlisted)
    {
        var log = new Logger(sink);
        var verifier = new AuthenticodeVerifier(new AllowlistConfig());
        var response = new ResponseManager(log, verifier);
        var entries = watchlisted.Select(v => new WatchlistEntryConfig { Value = v, Match = "name", Action = "quarantine" });
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(entries), ResolveProcessName = null });
        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            StartMonitors = false,
            EnableExtendedMonitors = false,
            MonitorOnly = monitorOnly,
            AutoKill = autoKill,
        });
        _hosts.Add(host);
        host.Start();
        return host;
    }

    private static bool WaitFor(Func<bool> condition, int millis = 5000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < millis)
        {
            if (condition()) return true;
            Thread.Sleep(10);
        }
        return condition();
    }

    // ================================================================ the host seam

    [Fact]
    public void Monitor_mode_records_the_verdict_but_never_attempts_containment()
    {
        // A watchlist quarantine is the strongest automatic verdict there is: in enforce
        // mode it reaches Suspend + FirewallBlock unconditionally. In monitor mode it must
        // stop at a log line that names what enforce mode would have done.
        var sink = new RecordingSink();
        NewHost(sink, monitorOnly: true, autoKill: false, "evil.exe")
            .Submit(Sig(888_001, "evil.exe"));

        Assert.True(WaitFor(() => sink.Any("ACTION", "monitor mode, nothing done")), "monitor mode never reported the verdict");
        Assert.True(sink.Any("ACTION", "Suspend, FirewallBlock"), "the would-run list is missing the containment primitives");
        Assert.True(sink.Any("QUARANTINE", ""), "the verdict itself must still be recorded");

        Thread.Sleep(250);   // anything the host was going to attempt has been attempted by now
        Assert.False(sink.Any("ACTION", "suspend failed"), "monitor mode attempted a suspend");
        Assert.False(sink.Any("ACTION", "suspended"), "monitor mode suspended a process");
        // Contain() always ends in one of these lines; none may appear.
        Assert.False(sink.AnyMessage("skipped firewall block"), "monitor mode reached the firewall step");
        Assert.False(sink.AnyMessage("awaiting analyst"), "monitor mode ran Contain()");
    }

    [Fact]
    public void AutoKill_does_not_bypass_monitor_mode()
    {
        var sink = new RecordingSink();
        NewHost(sink, monitorOnly: true, autoKill: true, "evil.exe")
            .Submit(Sig(888_002, "evil.exe"));

        Assert.True(WaitFor(() => sink.Any("ACTION", "monitor mode, nothing done")));
        Assert.True(sink.Any("ACTION", "Kill"), "auto-kill should be named in what enforce mode would run");

        Thread.Sleep(250);
        Assert.False(sink.Any("ACTION", "suspend failed"));
        Assert.False(sink.AnyMessage("auto-kill"), "monitor mode reached the kill step");
        Assert.False(sink.AnyMessage("skipped firewall block"));
    }

    [Fact]
    public void Enforce_mode_still_reaches_the_containment_primitives()
    {
        // The other half of the contract: switching to enforce must not leave the host
        // stuck hands-off. Same verdict, and the suspend is attempted.
        var sink = new RecordingSink();
        NewHost(sink, monitorOnly: false, autoKill: false, "evil.exe")
            .Submit(Sig(888_003, "evil.exe"));

        Assert.True(WaitFor(() => sink.Any("ACTION", "suspend failed")), "enforce mode did not attempt containment");
        Assert.True(WaitFor(() => sink.AnyMessage("skipped firewall block")), "enforce mode did not reach Contain()");
        Assert.False(sink.Any("ACTION", "monitor mode"));
    }

    [Fact]
    public void Switching_modes_live_takes_effect_on_the_next_verdict()
    {
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true, autoKill: false, "first.exe", "second.exe");

        host.Submit(Sig(888_004, "first.exe"));
        Assert.True(WaitFor(() => sink.Any("ACTION", "pid 888004: monitor mode")));

        host.SetMonitorOnly(false);
        Assert.False(host.MonitorOnly);
        Assert.True(sink.Any("INFO", "response mode: ENFORCE"));

        host.Submit(Sig(888_005, "second.exe"));
        Assert.True(WaitFor(() => sink.Any("ACTION", "pid 888005 suspend failed")), "the live switch did not arm enforcement");

        host.SetMonitorOnly(true);
        Assert.True(host.MonitorOnly);
        Assert.True(sink.Any("INFO", "response mode: monitor"));
    }

    [Fact]
    public void Switching_to_enforce_rearms_a_process_monitor_mode_already_flagged()
    {
        // Both reviews found this: monitor mode leaves the profile marked Contained (the
        // one-shot gate), so after a switch to enforce every later verdict for that same
        // process was swallowed as an "incident update" and it could never be contained.
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true, autoKill: false, "evil.exe");

        host.Submit(Sig(888_010, "evil.exe"));
        Assert.True(WaitFor(() => sink.Any("ACTION", "pid 888010: monitor mode")));
        Assert.True(WaitFor(() => host.ListProfiles(onlyContained: false).Any(p => p.Pid == 888_010 && p.ContainmentSkipped)),
            "the snapshot does not say containment was skipped");

        host.SetMonitorOnly(false);
        Assert.True(WaitFor(() => sink.Any("INFO", "will be contained if they act again")), "nothing was re-armed");
        Assert.True(WaitFor(() => !host.ListProfiles(onlyContained: true).Any(p => p.Pid == 888_010)),
            "the re-armed process still reads as contained");

        host.Submit(Sig(888_010, "evil.exe", SignalKind.NetworkConnect, atSeconds: 5));   // same process acts again
        Assert.True(WaitFor(() => sink.Any("ACTION", "pid 888010 suspend failed")), "the re-armed process was not sent for containment");
    }

    [Fact]
    public void A_failed_suspend_is_not_retried_on_every_signal()
    {
        // The pid does not exist, so suspend always fails and the engine re-arms the process.
        // Before the pause, every following signal re-ran suspend + firewall and printed a
        // fresh QUARANTINE: the flood an operator saw. One attempt per incident per window.
        var sink = new CountingSink();
        var log = new Logger(sink);
        var verifier = new AuthenticodeVerifier(new AllowlistConfig());
        var engine = new DetectionEngine(new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70 }, _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(new[] { new WatchlistEntryConfig { Value = "evil.exe", Match = "name", Action = "quarantine" } }), ResolveProcessName = null });
        var host = new BruceHost(engine, new ResponseManager(log, verifier), new NullScanner(), log,
            new BruceHostOptions { StartMonitors = false, EnableExtendedMonitors = false, MonitorOnly = false });
        _hosts.Add(host);
        host.Start();

        host.Submit(Sig(888_020, "evil.exe"));
        Assert.True(WaitFor(() => sink.Count("pid 888020 suspend failed") == 1));
        for (int i = 1; i <= 5; i++) host.Submit(Sig(888_020, "evil.exe", SignalKind.NetworkConnect, atSeconds: i));

        Assert.True(WaitFor(() => host.VerdictsInBackoff >= 1), "no verdict reached the pause");
        Thread.Sleep(300);
        Assert.Equal(1, sink.Count("pid 888020 suspend failed"));
        Assert.Equal(1, sink.Count("next attempt for this incident in 60 s"));   // the operator is told when
    }

    [Fact]
    public void An_exited_process_monitor_mode_only_reported_is_pruned_but_real_containment_is_kept()
    {
        var clock = new ManualClock();
        var deps = new EngineDependencies
        {
            Clock = clock, ResolveProcessName = null,
            Watchlist = Watchlist.Compile(new[] { new WatchlistEntryConfig { Value = "evil.exe", Match = "name", Action = "quarantine" } }),
        };
        var engine = new DetectionEngine(new EngineOptions(), _ => false, deps);

        Assert.Contains(engine.Ingest(Sig(7, "evil.exe")), r => r.Verdict == Verdict.Quarantine);     // only reported
        Assert.True(engine.MarkContainmentSkipped(7));
        Assert.Contains(engine.Ingest(Sig(8, "evil.exe")), r => r.Verdict == Verdict.Quarantine);     // really contained

        engine.Ingest(Sig(7, "evil.exe", SignalKind.ProcessStop, atSeconds: 1));
        engine.Ingest(Sig(8, "evil.exe", SignalKind.ProcessStop, atSeconds: 1));
        clock.Advance(TimeSpan.FromMinutes(11));
        engine.Ingest(Sig(9, "calc.exe"));                                                               // triggers the prune

        Assert.Null(engine.SnapshotOne(7));
        Assert.NotNull(engine.SnapshotOne(8));
    }

    [Fact]
    public void Rearming_skips_processes_that_already_exited()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
        {
            ResolveProcessName = null,
            Watchlist = Watchlist.Compile(new[] { new WatchlistEntryConfig { Value = "evil.exe", Match = "name", Action = "quarantine" } }),
        });
        engine.Ingest(Sig(11, "evil.exe"));
        engine.Ingest(Sig(12, "evil.exe"));
        Assert.True(engine.MarkContainmentSkipped(11));
        Assert.True(engine.MarkContainmentSkipped(12));
        engine.Ingest(Sig(12, "evil.exe", SignalKind.ProcessStop, atSeconds: 1));

        Assert.Equal(1, engine.RearmSkippedContainment());
        Assert.False(engine.SnapshotOne(11)!.Contained);
        Assert.True(engine.SnapshotOne(12)!.ContainmentSkipped);    // left for the pruner
    }

    // ================================================================ configuration

    [Fact]
    public void The_default_mode_is_monitor()
    {
        var r = new ResponseConfig();
        Assert.Equal(ResponseModes.Monitor, r.Mode);
        Assert.False(r.IsEnforcing);
        Assert.False(new BruceConfig().Response.IsEnforcing);
    }

    [Theory]
    [InlineData("enforce", true)]
    [InlineData("ENFORCE", true)]
    [InlineData(" Enforce ", true)]
    [InlineData("monitor", false)]
    [InlineData("enforced", false)]
    [InlineData("on", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_an_explicit_enforce_arms_automatic_response(string? mode, bool enforcing)
    {
        var cfg = new BruceConfig();
        cfg.Response.Mode = mode!;
        Assert.Equal(enforcing, cfg.Response.IsEnforcing);

        cfg.ClampAndValidate();
        Assert.Equal(enforcing ? ResponseModes.Enforce : ResponseModes.Monitor, cfg.Response.Mode);
    }

    [Fact]
    public void Mode_round_trips_through_the_loader_without_writing_the_computed_flag()
    {
        string dir = Path.Combine(Path.GetTempPath(), "bruce-mode-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _tempDirs.Add(dir);
        string path = Path.Combine(dir, "bruce.config.json");

        File.WriteAllText(path, "{ \"response\": { \"mode\": \"enforce\" } }");
        Assert.True(ConfigLoader.Load(path).Response.IsEnforcing);

        var cfg = ConfigLoader.Load(path);
        cfg.Response.Mode = ResponseModes.Monitor;
        ConfigLoader.Save(cfg, path);
        string json = File.ReadAllText(path);
        Assert.DoesNotContain("IsEnforcing", json, StringComparison.OrdinalIgnoreCase);
        Assert.False(ConfigLoader.Load(path).Response.IsEnforcing);
    }

    [Fact]
    public void The_shipped_config_is_monitor_mode()
    {
        // The file that goes into the release zip and the installer. A first run on a
        // workstation must never be the one that starts freezing processes.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? shipped = null;
        for (int i = 0; i < 12 && dir is not null; i++, dir = dir.Parent)
        {
            string probe = Path.Combine(dir.FullName, "bruce.config.json");
            if (File.Exists(probe) && File.Exists(Path.Combine(dir.FullName, "BruceEDR.sln"))) { shipped = probe; break; }
        }
        Assert.True(shipped is not null, "bruce.config.json was not found next to BruceEDR.sln above " + AppContext.BaseDirectory);

        using var doc = JsonDocument.Parse(File.ReadAllText(shipped!),
            new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        Assert.Equal("monitor", doc.RootElement.GetProperty("response").GetProperty("mode").GetString());
        Assert.False(ConfigLoader.Load(shipped!).Response.IsEnforcing);
    }
}
