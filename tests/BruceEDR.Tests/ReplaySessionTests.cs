using BruceEDR.Api;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Hosting;
using BruceEDR.Replay;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The desktop app's replay drives a real host from a recorded trace. It must reach the same
/// detections a live agent would, compressed in time, and it must never act on a process.
/// </summary>
public sealed class ReplaySessionTests : IDisposable
{
    private readonly List<ReplaySession> _sessions = new();
    private readonly List<BruceHost> _hosts = new();

    public void Dispose()
    {
        foreach (var s in _sessions) { try { s.Dispose(); } catch { } }
        foreach (var h in _hosts) { try { h.Dispose(); } catch { } }
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    /// <summary>
    /// A host wired the way <see cref="ReplaySession"/> wires one (shipped rules, monitor mode,
    /// auto-kill off, no monitors, no scanner, names from the trace), left unstarted so a test
    /// can queue signals before the owner thread runs.
    /// </summary>
    private BruceHost ReplayStyleHost(TraceScenario scenario)
    {
        var cfg = new BruceConfig();
        var clock = new ManualClock(scenario.StartUtc);
        var log = new Logger(new RecordingSink());
        var rules = new RuleEngine(Composition.LoadRules(cfg.Detection, log));
        var intel = Composition.LoadIntel(cfg.Intel, log);
        var watchlist = Composition.LoadWatchlist(cfg.Watchlist, log);
        var names = new Dictionary<int, string>();
        foreach (var step in scenario.Events)
            if (step?.Signal is { Pid: > 0 } s && !string.IsNullOrEmpty(s.ProcessName))
                names[s.Pid] = s.ProcessName;

        var tree = new ProcessTree(clock);
        var surface = new ApiSurfaceInventory(clock);
        var engine = new DetectionEngine(Composition.BuildEngineOptions(cfg, autoKill: false), _ => false,
            new EngineDependencies
            {
                Clock = clock,
                Tree = tree,
                Beacons = new BeaconAnalyzer(clock, cfg.Detection.BeaconMinConnections),
                RulesProvider = () => rules,
                IntelProvider = () => intel,
                WatchlistProvider = () => watchlist,
                Surface = surface,
                ResolveProcessName = pid => names.TryGetValue(pid, out var n) ? n : null,
            });
        var host = new BruceHost(engine, new ResponseManager(log, new AuthenticodeVerifier(cfg.Allowlist)),
            new NullScanner(), log, new BruceHostOptions
            {
                AutoKill = false,
                MonitorOnly = true,
                StartMonitors = false,
                EnableExtendedMonitors = false,
                Tree = tree,
                Surface = surface,
                Playbook = Composition.LoadPlaybook(cfg.Response, log),
                Metrics = new BruceMetrics(clock),
            });
        _hosts.Add(host);
        return host;
    }

    private static string Profiles(BruceHost host)
        => string.Join("\n", host.ListProfiles(onlyContained: false).OrderBy(p => p.Pid)
            .Select(p => $"{p.Pid} {p.ProcessName} score={p.Score}: " + string.Join(" | ", p.Reasons)));

    private sealed class RecordingSink : IEventSink
    {
        public readonly List<BruceEvent> Events = new();
        public void Emit(BruceEvent e) { lock (Events) Events.Add(e); }
        public void Dispose() { }
        public List<BruceEvent> Snapshot() { lock (Events) return Events.ToList(); }
    }

    private static string ScenarioPath(string name)
        => Path.Combine(AppContext.BaseDirectory, "Replay", "scenarios", name + ".jsonl");

    private ReplaySession Play(string scenario, RecordingSink sink)
    {
        var clock = new ManualClock(DateTime.UtcNow);
        var session = ReplaySession.Start(new BruceConfig(), TraceFormat.Load(ScenarioPath(scenario)), sink,
            clock, (gap, _) => { clock.Advance(gap); return Task.CompletedTask; });
        _sessions.Add(session);
        Assert.True(session.Completion.Wait(TimeSpan.FromSeconds(10)), "playback did not finish");
        Assert.True(WaitFor(() => session.Host.StatsSnapshot().SignalsProcessed >= session.Total),
            "the host did not process every replayed signal");
        return session;
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

    [Fact]
    public void Infostealer_replay_reaches_the_scenario_verdicts_and_touches_nothing()
    {
        var sink = new RecordingSink();
        var session = Play("infostealer-chain", sink);

        var profiles = session.Host.ListProfiles(onlyContained: false);
        var stealer = Assert.Single(profiles, p => p.Pid == 4816);
        Assert.True(stealer.Contained);
        Assert.True(stealer.ContainmentSkipped, "a replayed verdict was treated as a real containment");
        Assert.DoesNotContain(profiles, p => (p.Pid == 3120 || p.Pid == 1044) && p.Contained);

        var actions = sink.Snapshot().Where(e => e.Level == "ACTION").ToList();
        Assert.NotEmpty(actions);
        Assert.All(actions, a => Assert.Contains("monitor mode", a.Message));
    }

    [Fact]
    public void A_burst_keeps_telemetry_queued_behind_a_stop_on_the_process_that_produced_it()
    {
        var scenario = TraceFormat.Load(ScenarioPath("infostealer-chain"));
        var signals = scenario.Events.Where(e => e?.Signal is not null).Select(e => e.Signal!).ToList();

        var inOrder = ReplayStyleHost(scenario);
        inOrder.Start();
        foreach (var s in signals)
        {
            long before = inOrder.SignalsProcessed;
            inOrder.Submit(s);
            Assert.True(WaitFor(() => inOrder.SignalsProcessed > before), "an in-order signal was not processed");
        }

        // Queued before the owner thread exists: the host drains every start and stop first,
        // which is what it does with any burst it cannot keep up with.
        var burst = ReplayStyleHost(scenario);
        foreach (var s in signals) burst.Submit(s);
        burst.Start();
        Assert.True(WaitFor(() => burst.SignalsProcessed >= signals.Count), "the burst was not drained");

        var expected = Assert.Single(inOrder.ListProfiles(onlyContained: false), p => p.Pid == 4816);
        var actual = Assert.Single(burst.ListProfiles(onlyContained: false), p => p.Pid == 4816);
        Assert.Equal(expected.Score, actual.Score);
        Assert.Contains(actual.Reasons, r => r.Contains("Unusual parent/child: winword.exe -> powershell.exe"));
        Assert.Contains(actual.Reasons, r => r.Contains("Command-line IOC '-enc'"));
        Assert.Equal(expected.Reasons, actual.Reasons);
        Assert.True(actual.Exited);
        Assert.True(actual.ContainmentSkipped, "a replayed verdict was treated as a real containment");
        Assert.Equal(Profiles(inOrder), Profiles(burst));
    }

    [Fact]
    public void Beacon_replay_still_detects_the_beacon_after_time_compression()
    {
        var session = Play("rat-beacon", new RecordingSink());

        Assert.Equal(ReplaySession.MaxSpeed, session.Speed);
        Assert.Contains(session.Host.SurfaceEndpoints(), e => e.Pid == 6620 && e.Beaconing);
        var rat = Assert.Single(session.Host.ListProfiles(onlyContained: false), p => p.Pid == 6620);
        Assert.True(rat.Score >= 40, $"score {rat.Score}");
    }

    [Theory]
    [InlineData(5, 1)]
    [InlineData(41.5, 2.075)]
    [InlineData(334.7, 15)]
    [InlineData(3600, 15)]
    public void Speed_targets_twenty_seconds_within_bounds(double seconds, double expected)
        => Assert.Equal(expected, ReplaySession.SpeedFor(TimeSpan.FromSeconds(seconds)), 3);

    [Fact]
    public void Dispose_stops_playback_mid_trace()
    {
        var session = ReplaySession.Start(new BruceConfig(), TraceFormat.Load(ScenarioPath("rat-beacon")),
            new RecordingSink(), new ManualClock(DateTime.UtcNow), (_, ct) => Task.Delay(Timeout.Infinite, ct));
        _sessions.Add(session);

        session.Dispose();

        Assert.True(session.Completion.IsCompleted);
        Assert.True(session.Fed < session.Total);
    }
}
