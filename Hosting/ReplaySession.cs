using BruceEDR.Api;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Intel;
using BruceEDR.Memory;
using BruceEDR.Replay;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;

namespace BruceEDR.Hosting;

/// <summary>
/// Plays a recorded trace through a real <see cref="BruceHost"/> in real time, so the desktop
/// app can show detections without watching this machine. The host starts no monitor, runs
/// in monitor mode with auto-kill off, scans no memory, hashes and parses no image, and
/// resolves process names from the trace only. Its pids are fiction and must stay that way.
/// </summary>
public sealed class ReplaySession : IDisposable
{
    /// <summary>Playback aims at roughly this long, so a five-minute beacon trace stays watchable.</summary>
    public const double TargetSeconds = 20;

    /// <summary>
    /// Compression cap. Beacon detection ignores gaps under one second, and the shipped beacon
    /// trace calls every 30 s, so anything faster would hide the beacon it exists to show.
    /// </summary>
    public const double MaxSpeed = 15;

    private readonly CancellationTokenSource _cts = new();
    private readonly IClock _clock;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private int _fed;
    private int _disposed;

    public BruceHost Host { get; }
    public BruceConfig Config { get; }
    public TraceScenario Scenario { get; }
    public RuleSet Rules { get; }
    public IocFeed Intel { get; }
    public double Speed { get; }
    public int Total => Scenario.Events.Count;
    public int Fed => Volatile.Read(ref _fed);
    public Task Completion { get; }

    public static double SpeedFor(TimeSpan duration)
        => Math.Clamp(duration.TotalSeconds / TargetSeconds, 1, MaxSpeed);

    private ReplaySession(BruceHost host, BruceConfig cfg, TraceScenario scenario, RuleSet rules, IocFeed intel,
        IClock clock, Func<TimeSpan, CancellationToken, Task> delay)
    {
        Host = host;
        Config = cfg;
        Scenario = scenario;
        Rules = rules;
        Intel = intel;
        _clock = clock;
        _delay = delay;
        Speed = SpeedFor(scenario.Duration);
        Completion = Task.Run(PlayAsync);
    }

    /// <summary>Loads the operator's config and plays <paramref name="scenarioPath"/> through it.</summary>
    public static ReplaySession Start(string configPath, string scenarioPath, IEventSink sink)
        => Start(ConfigLoader.Load(configPath), TraceFormat.Load(scenarioPath), sink);

    /// <param name="clock">Engine clock; tests pass a manual one.</param>
    /// <param name="delay">Waits out a compressed gap; tests advance their clock instead of sleeping.</param>
    public static ReplaySession Start(BruceConfig cfg, TraceScenario scenario, IEventSink sink,
        IClock? clock = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        ArgumentNullException.ThrowIfNull(cfg);
        ArgumentNullException.ThrowIfNull(scenario);
        var c = clock ?? SystemClock.Instance;
        var log = new Logger(sink);

        var rules = Composition.LoadRules(cfg.Detection, log);
        var intel = Composition.LoadIntel(cfg.Intel, log);
        var watchlist = Composition.LoadWatchlist(cfg.Watchlist, log);
        var playbook = Composition.LoadPlaybook(cfg.Response, log);
        var ruleEngine = new RuleEngine(rules);

        var names = new Dictionary<int, string>();
        foreach (var step in scenario.Events)
            if (step?.Signal is { Pid: > 0 } s && !string.IsNullOrEmpty(s.ProcessName))
                names[s.Pid] = s.ProcessName;

        var tree = new ProcessTree(c);
        var surface = cfg.Api.EnableSurfaceInventory ? new ApiSurfaceInventory(c) : null;
        var deps = new EngineDependencies
        {
            Clock = c,
            Tree = tree,
            Beacons = cfg.Detection.EnableBeaconDetection
                ? new BeaconAnalyzer(c, cfg.Detection.BeaconMinConnections)
                : null,
            RulesProvider = () => ruleEngine,
            IntelProvider = () => intel,
            WatchlistProvider = () => watchlist,
            Surface = surface,
            ResolveProcessName = pid => names.TryGetValue(pid, out var n) ? n : null,
            ImageHash = null,
            AnalyzeImage = null,
        };
        var engine = new DetectionEngine(Composition.BuildEngineOptions(cfg, autoKill: false), _ => false, deps);
        var response = new ResponseManager(log, new AuthenticodeVerifier(cfg.Allowlist));
        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            AutoKill = false,
            MonitorOnly = true,
            StartMonitors = false,
            EnableExtendedMonitors = false,
            Tree = tree,
            Surface = surface,
            Playbook = playbook,
            Metrics = new BruceMetrics(c),
        });
        host.Start();

        log.Info($"replay: '{scenario.Name}', {scenario.Events.Count} signals over " +
                 $"{scenario.Duration.TotalSeconds:F0} s at {SpeedFor(scenario.Duration):F1}x. " +
                 "Nothing on this machine is monitored or touched.");
        return new ReplaySession(host, cfg, scenario, rules, intel, c,
            delay ?? ((t, ct) => Task.Delay(t, ct)));
    }

    private async Task PlayAsync()
    {
        var ct = _cts.Token;
        var cursor = TimeSpan.Zero;
        try
        {
            foreach (var step in Scenario.Events)
            {
                if (step?.Signal is null) continue;
                if (step.At > cursor)
                {
                    await _delay(TimeSpan.FromTicks((long)((step.At - cursor).Ticks / Speed)), ct).ConfigureAwait(false);
                    cursor = step.At;
                }
                ct.ThrowIfCancellationRequested();
                Host.Submit(step.Signal with { TimestampUtc = _clock.UtcNow });
                Interlocked.Increment(ref _fed);
            }
        }
        catch (OperationCanceledException) { }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
        _cts.Cancel();
        try { Completion.Wait(TimeSpan.FromSeconds(5)); } catch { }
        Host.Dispose();
        _cts.Dispose();
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }
}
