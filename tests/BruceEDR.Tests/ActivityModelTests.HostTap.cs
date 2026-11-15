using BruceEDR.Activity;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Monitoring;
using BruceEDR.Replay;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>The host hands every signal to the activity model's observer.</summary>
public sealed partial class ActivityModelTests
{
    // ================================================================ the host's tap

    private sealed class NullScanner : IMemoryScanner { public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>(); }

    private static BruceHost NewHost(Action<Signal> observer)
    {
        var log = new Logger();
        var response = new ResponseManager(log, new AuthenticodeVerifier(new AllowlistConfig()));
        var engine = new DetectionEngine(new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 }, _ => false);
        return new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            StartMonitors = false, EnableExtendedMonitors = false, MonitorOnly = true, SignalObserver = observer
        });
    }

    private static bool WaitFor(Func<bool> cond)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < 5000) { if (cond()) return true; Thread.Sleep(10); }
        return cond();
    }

    [Fact]
    public void The_host_hands_every_signal_to_the_observer_starts_and_stops_included()
    {
        var model = new ActivityModel();
        int seen = 0;
        using var host = NewHost(sig => { model.Observe(sig); Interlocked.Increment(ref seen); });
        Assert.True(host.Start());
        host.Submit(Start(910_001, 4, "a.exe", 0));
        host.Submit(Create(910_001, @"C:\x\a.bin", 1));
        host.Submit(Delete(910_001, @"C:\x\a.bin", 2));
        host.Submit(Stop(910_001, 3));

        // Starts and stops travel on their own queue, ahead of file telemetry, so they can be seen first:
        // wait for all four signals rather than for the stop.
        Assert.True(WaitFor(() => Volatile.Read(ref seen) == 4));
        var s = model.Snapshot();
        Assert.Equal(1, s.Total(ActivityKind.ProcessStop));
        Assert.True(s.Files.Single().Deleted);
        Assert.NotNull(Proc(s, 910_001).ExitUtc);
    }

    [Fact]
    public void An_observer_that_throws_cannot_stop_detection_and_is_only_reported_once()
    {
        int calls = 0;
        var model = new ActivityModel();
        using var host = NewHost(s => { calls++; model.Observe(s); throw new InvalidOperationException("boom"); });
        Assert.True(host.Start());
        for (int i = 0; i < 5; i++) host.Submit(Start(910_100 + i, 4, "x.exe", i));

        Assert.True(WaitFor(() => calls == 5));
        Assert.True(WaitFor(() => host.StatsSnapshot().SignalsProcessed == 5));
    }

    [Fact]
    public void New_signal_kinds_survive_a_trace_round_trip()
    {
        var scenario = TraceFormat.FromSignals(new[]
        {
            Delete(100, @"C:\x\a.exe", 1, "on-close"), Rename(100, @"C:\x\a.exe", @"C:\x\b.exe", 2), Rename(100, @"C:\x\c.exe", null, 3)
        }, "kinds");
        var back = TraceFormat.Parse(TraceFormat.Write(scenario), "kinds", out var warnings);

        Assert.Empty(warnings);
        Assert.Equal(new[] { SignalKind.FileDelete, SignalKind.FileRename, SignalKind.FileRename }, back.Events.Select(e => e.Signal.Kind));
        Assert.Equal("on-close", back.Events[0].Signal.Detail);
        Assert.Equal(@"C:\x\b.exe", back.Events[1].Signal.Detail);
        Assert.Null(back.Events[2].Signal.Detail);
    }
}
