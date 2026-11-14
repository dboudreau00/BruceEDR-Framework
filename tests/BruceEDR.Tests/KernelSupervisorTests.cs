using BruceEDR.Core;
using BruceEDR.Driver;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The agent's link to the driver when the driver goes away: when it warns, the reconnect
/// schedule, the re-arm of a reloaded driver, and the stop on dispose. A fake port and a fake
/// delay stand in for the driver and the clock, so nothing here needs BruceFilter.
/// </summary>
public sealed class KernelSupervisorTests
{
    private sealed class FakePort : IKernelPort
    {
        public bool Disposed;
        public Action<string>? Lost;
        public KernelConnect Result;
        public KernelConnect Connect() => Result;
        public void Dispose() => Disposed = true;
    }

    private sealed class Harness : IDisposable
    {
        public readonly List<string> Warns = new();
        public readonly List<string> Infos = new();
        public readonly List<TimeSpan> Delays = new();
        public readonly List<FakePort> Ports = new();
        public readonly List<FakePort> Armed = new();
        public readonly Queue<KernelConnect> Connects = new();
        public readonly Queue<bool> ArmResults = new();
        public bool HangDelays;
        public Action<int, Action<string>>? DuringArm;
        public KernelSupervisor<FakePort> Sup { get; }

        public Harness()
        {
            Sup = new KernelSupervisor<FakePort>(Create, Arm, m => { lock (Warns) Warns.Add(m); }, m => { lock (Infos) Infos.Add(m); }, Delay);
        }

        private FakePort Create()
        {
            var port = new FakePort { Result = Connects.Count > 0 ? Connects.Dequeue() : KernelConnect.Connected };
            lock (Ports) Ports.Add(port);
            return port;
        }

        private bool Arm(FakePort port, Action<string> lost)
        {
            port.Lost = lost;
            int index;
            lock (Armed) { index = Armed.Count; Armed.Add(port); }
            DuringArm?.Invoke(index, lost);
            return ArmResults.Count == 0 || ArmResults.Dequeue();
        }

        private Task Delay(TimeSpan span, CancellationToken stop)
        {
            lock (Delays) Delays.Add(span);
            if (HangDelays) return Task.Delay(Timeout.Infinite, stop);
            return stop.IsCancellationRequested ? Task.FromCanceled(stop) : Task.CompletedTask;
        }

        public void Finish() => Assert.True(Sup.Loop!.Wait(TimeSpan.FromSeconds(10)), "the reconnect loop did not finish");

        public void Dispose() => Sup.Dispose();
    }

    [Fact]
    public void The_Schedule_Starts_At_Five_Seconds_Doubles_And_Stops_At_Five_Minutes()
    {
        var seconds = Enumerable.Range(0, 9).Select(i => KernelBackoff.Delay(i).TotalSeconds).ToArray();
        Assert.Equal(new double[] { 5, 10, 20, 40, 80, 160, 300, 300, 300 }, seconds);
        Assert.Equal(300, KernelBackoff.Delay(1000).TotalSeconds);
        Assert.Equal(5, KernelBackoff.Delay(-3).TotalSeconds);
    }

    [Fact]
    public void A_Driver_That_Is_Not_There_At_Start_Is_Ordinary_And_Starts_No_Loop()
    {
        using var h = new Harness();
        h.Connects.Enqueue(KernelConnect.NotLoaded);

        Assert.False(h.Sup.Start());

        Assert.Null(h.Sup.Current);
        Assert.Null(h.Sup.Loop);
        Assert.Empty(h.Warns);
        Assert.Empty(h.Armed);
        Assert.True(h.Ports[0].Disposed);
    }

    [Fact]
    public void A_Connected_Driver_Is_Armed_Once_And_Nothing_Is_Warned()
    {
        using var h = new Harness();

        Assert.True(h.Sup.Start());

        Assert.Same(h.Ports[0], h.Sup.Current);
        Assert.Single(h.Armed);
        Assert.Empty(h.Warns);
        Assert.Null(h.Sup.Loop);
    }

    [Fact]
    public void A_Lost_Link_Warns_Plainly_Then_Reconnects_And_Arms_The_New_Driver_Again()
    {
        using var h = new Harness();
        h.Sup.Start();
        var first = h.Ports[0];

        first.Lost!("a read of the driver's port failed (hr=0x80070006)");
        h.Finish();

        var warn = Assert.Single(h.Warns);
        Assert.Contains("kernel enforcement is OFF", warn);
        Assert.Contains("hr=0x80070006", warn);
        Assert.Contains("5 s", warn);
        Assert.Contains("5 min", warn);

        Assert.Equal(new[] { TimeSpan.FromSeconds(5) }, h.Delays);
        Assert.True(first.Disposed);
        Assert.Equal(2, h.Armed.Count);              // the policy and blocking go in again
        Assert.NotSame(first, h.Armed[1]);
        Assert.Same(h.Armed[1], h.Sup.Current);
        Assert.Contains(h.Infos, m => m.Contains("kernel enforcement RESTORED"));
    }

    [Fact]
    public void An_Unloaded_Driver_Is_Waited_For_On_The_Backoff_Schedule_With_One_Further_Warning()
    {
        using var h = new Harness();
        h.Sup.Start();
        h.Connects.Enqueue(KernelConnect.NotLoaded);
        h.Connects.Enqueue(KernelConnect.NotLoaded);
        h.Connects.Enqueue(KernelConnect.Failed);
        h.Connects.Enqueue(KernelConnect.NotLoaded);

        h.Ports[0].Lost!("the driver closed the port");
        h.Finish();

        Assert.Equal(new double[] { 5, 10, 20, 40, 80 }, h.Delays.Select(d => d.TotalSeconds).ToArray());
        Assert.Equal(2, h.Warns.Count);              // the loss, then "not loaded" once
        Assert.Contains("kernel enforcement is OFF", h.Warns[0]);
        Assert.Contains("not loaded", h.Warns[1]);
        Assert.NotNull(h.Sup.Current);
        Assert.Equal(2, h.Armed.Count);
        Assert.All(h.Ports.Skip(1).Take(4), p => Assert.True(p.Disposed));   // every failed attempt closes its port
    }

    [Fact]
    public void A_Driver_That_Connects_But_Cannot_Be_Armed_Is_Retried_Not_Trusted()
    {
        using var h = new Harness();
        h.Sup.Start();
        h.ArmResults.Enqueue(false);
        h.ArmResults.Enqueue(false);
        h.ArmResults.Enqueue(true);

        h.Ports[0].Lost!("lost");
        h.Finish();

        Assert.Equal(4, h.Armed.Count);              // the first arm, two refused, one accepted
        Assert.Equal(3, h.Delays.Count);
        Assert.Same(h.Armed[3], h.Sup.Current);
        Assert.True(h.Armed[1].Disposed);
        Assert.True(h.Armed[2].Disposed);
        Assert.False(h.Armed[3].Disposed);
        Assert.Single(h.Infos, m => m.Contains("RESTORED"));
    }

    [Fact]
    public void A_Driver_That_Cannot_Be_Armed_At_Start_Is_Treated_As_Lost()
    {
        using var h = new Harness();
        h.ArmResults.Enqueue(false);

        Assert.True(h.Sup.Start());
        h.Finish();

        Assert.Single(h.Warns);
        Assert.Equal(2, h.Armed.Count);
        Assert.Same(h.Armed[1], h.Sup.Current);
    }

    [Fact]
    public void A_Link_That_Drops_While_It_Is_Being_Armed_Is_Retried()
    {
        using var h = new Harness();
        h.Sup.Start();
        // The second driver's reader stops before its arming returns.
        h.DuringArm = (index, lost) => { if (index == 1) lost("stopped at once"); };

        h.Ports[0].Lost!("lost");
        h.Finish();

        Assert.Equal(3, h.Armed.Count);
        Assert.True(h.Armed[1].Disposed);            // not kept: its reader was already gone
        Assert.Same(h.Armed[2], h.Sup.Current);
        Assert.Equal(2, h.Warns.Count);
        Assert.Single(h.Infos, m => m.Contains("RESTORED"));
    }

    [Fact]
    public void A_Late_Report_From_A_Replaced_Port_Is_Ignored()
    {
        using var h = new Harness();
        h.Sup.Start();
        var first = h.Ports[0];
        first.Lost!("lost");
        h.Finish();
        int warns = h.Warns.Count;

        first.Lost!("the old reader, late");

        Assert.Equal(warns, h.Warns.Count);
        Assert.Same(h.Armed[1], h.Sup.Current);
    }

    [Fact]
    public void A_Second_Loss_After_A_Restore_Starts_Another_Loop_And_Warns_Again()
    {
        using var h = new Harness();
        h.Sup.Start();
        h.Ports[0].Lost!("first");
        h.Finish();
        var second = h.Armed[1];

        second.Lost!("second");
        h.Finish();

        Assert.Equal(2, h.Warns.Count);
        Assert.Equal(3, h.Armed.Count);
        Assert.Same(h.Armed[2], h.Sup.Current);
        Assert.Equal(2, h.Infos.Count(m => m.Contains("RESTORED")));
    }

    [Fact]
    public void Dispose_Stops_A_Waiting_Loop_Without_Another_Attempt()
    {
        var h = new Harness { HangDelays = true };
        h.Sup.Start();
        h.Ports[0].Lost!("lost");
        var loop = h.Sup.Loop!;
        Assert.False(loop.IsCompleted);

        h.Sup.Dispose();

        Assert.True(loop.IsCompleted);               // Dispose waits for it
        Assert.Single(h.Ports);                      // no reconnect was tried
        Assert.Null(h.Sup.Current);
        Assert.Empty(h.Infos);
    }

    [Fact]
    public void A_Reader_That_Ends_Because_Of_Dispose_Is_Not_A_Loss()
    {
        var h = new Harness();
        h.Sup.Start();
        var port = h.Ports[0];

        h.Sup.Dispose();
        port.Lost!("late report while shutting down");

        Assert.True(port.Disposed);
        Assert.Empty(h.Warns);
        Assert.Null(h.Sup.Loop);
        Assert.Null(h.Sup.Current);
    }

    [Fact]
    public void Dispose_Twice_Is_Harmless()
    {
        var h = new Harness { HangDelays = true };
        h.Sup.Start();
        h.Ports[0].Lost!("lost");

        h.Sup.Dispose();
        h.Sup.Dispose();

        Assert.Single(h.Armed);
        Assert.Empty(h.Infos);
    }

    [Fact]
    public void A_Warning_Is_A_WARN_System_Event()
    {
        var sink = new CaptureSink();
        var log = new Logger(sink, new StringWriter(), () => 0);

        log.Warn("kernel enforcement is OFF: test");

        var e = Assert.Single(sink.Events);
        Assert.Equal("WARN", e.Level);
        Assert.Equal("system", e.Category);
        Assert.Equal("kernel enforcement is OFF: test", e.Message);
    }

    private sealed class CaptureSink : IEventSink
    {
        public readonly List<BruceEvent> Events = new();
        public void Emit(BruceEvent e) => Events.Add(e);
        public void Dispose() { }
    }
}
