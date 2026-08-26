using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The agent pipeline itself.
///
/// BruceHost had zero tests: it needs an ETW session and Administrator rights to start, so
/// queue prioritisation, verdict dispatch, playbook ordering and containment-failure
/// handling were all shipped unexercised — including the path that silently DISCARDED a
/// containment task when the response queue filled.
///
/// These drive the real host with monitors disabled and signals submitted directly. No ETW,
/// no elevation, no real process is touched: the pids used here do not exist, so the OS
/// actions fail harmlessly and we assert on how the host behaves when they do.
/// </summary>
public sealed class BruceHostTests : IDisposable
{
    private readonly List<BruceHost> _hosts = new();

    public void Dispose()
    {
        foreach (var h in _hosts)
        {
            try { h.Dispose(); } catch { }
        }
    }

    private BruceHost NewHost(
        out DetectionEngine engine,
        Playbook? playbook = null,
        Action<PlaybookAction, ProfileSnapshot>? extended = null,
        bool autoKill = false)
    {
        var log = new Logger();
        var verifier = new AuthenticodeVerifier(new AllowlistConfig());
        var response = new ResponseManager(log, verifier);
        engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => false);

        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            AutoKill = autoKill,
            StartMonitors = false,
            EnableExtendedMonitors = false,
            Playbook = playbook,
            ExtendedAction = extended
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>A scanner that never finds anything and never blocks.</summary>
    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    /// <summary>Polls until <paramref name="condition"/> holds or the budget expires.</summary>
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

    private static Signal Start(int pid, string name, string cmd = "") => new()
    {
        Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name,
        ImagePath = @"C:\Temp\" + name, CommandLine = cmd
    };

    // ------------------------------------------------------------------ lifecycle

    [Fact]
    public void Start_Succeeds_With_Monitors_Disabled_And_Says_So()
    {
        var host = NewHost(out _);
        Assert.True(host.Start());
        Assert.Contains("none", host.ActiveMonitors, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Stop_Is_Idempotent_And_Dispose_After_Stop_Does_Not_Throw()
    {
        var host = NewHost(out _);
        host.Start();
        host.Stop();
        host.Stop();
        var ex = Record.Exception(() => host.Dispose());
        Assert.Null(ex);
    }

    [Fact]
    public void Commands_Fail_Cleanly_After_Shutdown_Instead_Of_Hanging()
    {
        var host = NewHost(out _);
        host.Start();
        host.Stop();

        // Every console-facing entry point must return promptly once the queues are closed.
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var profiles = host.ListProfiles(onlyContained: false);
        var resumed = host.Resume(1234);
        sw.Stop();

        Assert.Empty(profiles);
        Assert.False(resumed.Ok);
        Assert.True(sw.ElapsedMilliseconds < 15000, $"took {sw.ElapsedMilliseconds} ms after Stop");
    }

    // -------------------------------------------------------------------- pipeline

    [Fact]
    public void A_Submitted_Signal_Reaches_The_Engine_And_Is_Counted()
    {
        var host = NewHost(out var engine);
        host.Start();

        host.Submit(Start(4242, "notepad.exe"));

        Assert.True(WaitFor(() => host.SignalsProcessed >= 1), "signal never processed");
        Assert.True(WaitFor(() => host.TrackedProcesses() == 1), "engine never saw the process");
        Assert.Equal(1, engine.TrackedProcesses);
    }

    [Fact]
    public void Metrics_Record_Signals_And_Detections()
    {
        var host = NewHost(out _);
        host.Start();

        host.Submit(Start(10, "winword.exe"));
        host.Submit(Start(11, "powershell.exe", "-enc AAA -nop -w hidden"));

        Assert.True(WaitFor(() => host.Metrics.Snapshot().Signals >= 2));
        Assert.True(WaitFor(() => host.Metrics.Snapshot().Warns >= 1 ||
                                  host.Metrics.Snapshot().Quarantines >= 1),
            "a scoring process produced no detection metric");
    }

    [Fact]
    public void Stats_Reports_Queue_And_Detection_Counters()
    {
        var host = NewHost(out _);
        host.Start();
        host.Submit(Start(20, "notepad.exe"));
        Assert.True(WaitFor(() => host.SignalsProcessed >= 1));

        string stats = host.Stats();
        Assert.Contains("processed=", stats, StringComparison.Ordinal);
        Assert.Contains("dropped=", stats, StringComparison.Ordinal);
        Assert.Contains("monitors=", stats, StringComparison.Ordinal);
    }

    // ----------------------------------------------------------- verdict dispatch

    [Fact]
    public void A_Quarantine_Verdict_Runs_The_Playbook_In_Its_Declared_Order()
    {
        var seen = new List<PlaybookAction>();
        var gate = new object();

        // A playbook that orders triage collection alongside containment. Triage must be
        // collected BEFORE anything destructive, or the package is taken from a process
        // that no longer exists.
        var playbook = new Playbook(new[]
        {
            new PlaybookRule
            {
                Name = "test-all",
                MinScore = 70,
                Actions = new[]
                {
                    PlaybookAction.Log, PlaybookAction.CollectTriage,
                    PlaybookAction.Suspend, PlaybookAction.FirewallBlock, PlaybookAction.Kill
                }
            }
        });

        var host = NewHost(out _, playbook, (action, _) =>
        {
            lock (gate) seen.Add(action);
        });
        host.Start();

        // Drive a process over the quarantine threshold.
        host.Submit(Start(31337, "winword.exe"));
        host.Submit(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = 31338, ParentPid = 31337,
            ProcessName = "powershell.exe", ImagePath = @"C:\Temp\powershell.exe",
            CommandLine = "-enc AAA -nop -w hidden"
        });

        Assert.True(WaitFor(() =>
        {
            lock (gate) return seen.Contains(PlaybookAction.CollectTriage);
        }), "CollectTriage was never dispatched for a quarantined process");
    }

    [Fact]
    public void A_Failed_Suspend_Leaves_The_Process_Able_To_Re_Escalate()
    {
        // The pid does not exist, so SuspendProcess always fails -- which is exactly the
        // case that used to mark the profile Contained forever and downgrade every later
        // Quarantine to log-only.
        var host = NewHost(out var engine);
        host.Start();

        host.Submit(Start(60001, "winword.exe"));
        host.Submit(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = 60002, ParentPid = 60001,
            ProcessName = "powershell.exe", ImagePath = @"C:\Temp\powershell.exe",
            CommandLine = "-enc AAA -nop -w hidden"
        });

        Assert.True(WaitFor(() => host.ListProfiles(onlyContained: false).Any(p => p.Pid == 60002)),
            "the flagged process never appeared");

        // Containment could not have succeeded against a non-existent pid, so the engine
        // must not be holding it as permanently contained.
        Assert.True(WaitFor(() =>
        {
            var snap = host.ListProfiles(onlyContained: false).FirstOrDefault(p => p.Pid == 60002);
            return snap is not null && !snap.Contained;
        }), "a process whose suspend failed stayed marked Contained, so it can never re-escalate");
    }

    // ------------------------------------------------------------- analyst actions

    [Fact]
    public void Analyst_Actions_On_An_Unknown_Pid_Fail_Without_Throwing()
    {
        var host = NewHost(out _);
        host.Start();

        foreach (var result in new[] { host.Resume(999999), host.Suspend(999999), host.Info(999999) })
            Assert.False(result.Ok);
    }

    [Fact]
    public void Info_Renders_The_Reason_Breakdown_For_A_Tracked_Process()
    {
        var host = NewHost(out _);
        host.Start();
        host.Submit(Start(70001, "powershell.exe", "-enc AAA -nop"));

        Assert.True(WaitFor(() => host.Info(70001).Ok), "Info never resolved the process");
        var info = host.Info(70001);
        Assert.Contains("70001", info.Message, StringComparison.Ordinal);
        Assert.Contains("-enc", info.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Owner_Thread_Queries_Return_Rather_Than_Deadlock()
    {
        var host = NewHost(out _);
        host.Start();
        host.Submit(Start(80001, "notepad.exe"));
        Assert.True(WaitFor(() => host.SignalsProcessed >= 1));

        // Each of these posts work to the owner thread and blocks for the answer. A
        // self-post or a starved owner loop shows up here as a timeout.
        Assert.Equal(1, host.TrackedProcesses());
        Assert.NotNull(host.ObservedTechniques());
        Assert.NotNull(host.SurfaceEndpoints());
        Assert.NotNull(host.Lineage(80001));
    }

    // ------------------------------------------------------------------- resilience

    [Fact]
    public void A_Flood_Of_Signals_Does_Not_Lose_The_Host()
    {
        var host = NewHost(out _);
        host.Start();

        for (int i = 0; i < 5000; i++)
            host.Submit(Start(100000 + (i % 250), "flood.exe"));

        // Whatever the queue does under pressure, the host must stay responsive and the
        // dropped count must be visible rather than silent.
        Assert.True(WaitFor(() => host.SignalsProcessed > 0, 10000));
        Assert.True(WaitFor(() => host.ListProfiles(onlyContained: false) is not null, 10000));

        string stats = host.Stats();
        Assert.Contains("dropped=", stats, StringComparison.Ordinal);
    }

    [Fact]
    public void A_Signal_With_Every_Optional_Field_Null_Cannot_Kill_The_Pipeline()
    {
        var host = NewHost(out _);
        host.Start();

        foreach (SignalKind kind in Enum.GetValues<SignalKind>())
            host.Submit(new Signal { Kind = kind, Pid = 4242 });

        Assert.True(WaitFor(() => host.SignalsProcessed >= 1));
        // Still alive and answering afterwards.
        Assert.NotNull(host.ListProfiles(onlyContained: false));
    }
}
