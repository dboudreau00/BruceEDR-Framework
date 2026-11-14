using System.Diagnostics;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Driver;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The guard in front of every suspend and kill. In the lab VMs enforce mode suspended csrss
/// and svchost on verdicts it could not name, and Windows froze within minutes.
/// </summary>
public sealed class ContainmentGuardTests : IDisposable
{
    private readonly List<BruceHost> _hosts = new();
    private readonly List<Process> _children = new();
    private readonly List<string> _dirs = new();

    public void Dispose()
    {
        foreach (var h in _hosts) { try { h.Dispose(); } catch { } }
        foreach (var c in _children)
        {
            try { if (!c.HasExited) c.Kill(); c.WaitForExit(2000); } catch { }
            c.Dispose();
        }
        foreach (var d in _dirs) { try { Directory.Delete(d, true); } catch { } }
    }

    private static readonly Func<string, string?> AdminOnly = _ => null;
    private static readonly Func<string, string?> UserWritable = p => p + " can be changed by Users";

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void The_System_and_Idle_pids_are_never_contained(int pid)
        => Assert.Contains("System or Idle", ContainmentGuard.Refusal(pid, 9999, null, AdminOnly));

    [Fact]
    public void The_agent_never_contains_itself()
        => Assert.Contains("agent itself", ContainmentGuard.Refusal(4242, 4242, new LiveProcess("BruceEDR", null), AdminOnly));

    [Theory]
    [InlineData("svchost")]
    [InlineData("csrss.exe")]
    [InlineData("LSASS")]
    [InlineData("Memory Compression")]
    [InlineData("explorer")]
    public void A_protected_Windows_process_in_an_admin_only_folder_is_refused(string name)
    {
        var refusal = ContainmentGuard.Refusal(1000, 9999, new LiveProcess(name, @"C:\Windows\System32\x.exe"), AdminOnly);
        Assert.Contains("protected Windows process", refusal);
    }

    [Fact]
    public void A_process_running_protected_is_refused_whatever_its_name_or_folder()
        => Assert.Contains("runs as a protected process", ContainmentGuard.Refusal(1000, 9999,
            new LiveProcess("ekrn", @"C:\Program Files\Vendor\ekrn.exe", Protected: true), UserWritable));

    [Fact]
    public void A_protected_name_whose_image_cannot_be_read_is_refused()
        => Assert.Contains("could not be read", ContainmentGuard.Refusal(1000, 9999, new LiveProcess("csrss", null), AdminOnly));

    [Fact]
    public void A_look_alike_a_user_could_have_planted_is_still_contained()
        => Assert.Null(ContainmentGuard.Refusal(1000, 9999,
            new LiveProcess("svchost", @"C:\Users\Public\svchost.exe"), UserWritable));

    [Fact]
    public void An_ordinary_process_or_one_already_gone_is_not_refused()
    {
        Assert.Null(ContainmentGuard.Refusal(1000, 9999, new LiveProcess("stealer", @"C:\Windows\System32\stealer.exe"), AdminOnly));
        Assert.Null(ContainmentGuard.Refusal(1000, 9999, null, AdminOnly));
    }

    [Fact]
    public void The_real_System32_copy_is_admin_only_and_a_temp_copy_is_not()
    {
        string real = Path.Combine(Environment.SystemDirectory, "svchost.exe");
        Assert.Contains("protected Windows process",
            ContainmentGuard.Refusal(1000, 9999, new LiveProcess("svchost", real), KernelPolicy.WriteRisk));

        // Only the path's permissions are read, so the planted file needs no svchost name of its own.
        string fake = Path.Combine(NewDir(), "planted.bin");
        File.WriteAllBytes(fake, new byte[] { 0x4D, 0x5A });
        Assert.Null(ContainmentGuard.Refusal(1000, 9999, new LiveProcess("svchost", fake), KernelPolicy.WriteRisk));
    }

    [Fact]
    public void Live_lookups_refuse_System_this_process_and_csrss()
    {
        Assert.NotNull(ContainmentGuard.Refusal(4));
        Assert.Contains("agent itself", ContainmentGuard.Refusal(Environment.ProcessId));
        foreach (var csrss in Process.GetProcessesByName("csrss"))
            using (csrss) Assert.NotNull(ContainmentGuard.Refusal(csrss.Id));
    }

    [Fact]
    public void Live_lookup_reads_the_name_and_image_and_lets_an_ordinary_process_be_contained()
    {
        var child = Start(Path.Combine(Environment.SystemDirectory, "ping.exe"));

        var live = ContainmentGuard.Describe(child.Id);

        Assert.NotNull(live);
        Assert.Equal("ping", live!.Name, ignoreCase: true);
        Assert.EndsWith(@"\ping.exe", live.ImagePath, StringComparison.OrdinalIgnoreCase);
        Assert.Null(ContainmentGuard.Refusal(child.Id));
    }

    // ------------------------------------------------------------------ the host

    [Fact]
    public void An_automatic_verdict_on_a_refused_pid_suspends_nothing_but_still_collects_triage()
    {
        const int pid = 80001;
        var sink = new RecordingSink();
        var seen = new List<PlaybookAction>();
        var playbook = new Playbook(new[]
        {
            new PlaybookRule
            {
                Name = "contain", MinScore = 70,
                Actions = new[] { PlaybookAction.CollectTriage, PlaybookAction.Suspend, PlaybookAction.FirewallBlock, PlaybookAction.Kill }
            }
        });
        var host = NewHost(sink, playbook, p => p == pid ? "it is a test stand-in for csrss" : null, monitorOnly: false,
            extended: (a, _) => { lock (seen) seen.Add(a); });
        host.Start();
        Flag(host, pid, "csrss.exe");

        Assert.True(WaitFor(() => sink.Any(e => e.Level == "ACTION" && e.Message.Contains("refused because it is a test stand-in"))),
            "the refusal was not logged");
        Assert.True(WaitFor(() => { lock (seen) return seen.Contains(PlaybookAction.CollectTriage); }), "triage was withheld");
        Assert.False(sink.Any(e => e.Level == "ACTION" &&
                (e.Message.StartsWith($"pid {pid} suspend") || e.Message.Contains("' -> "))),
            "the playbook ran against a refused pid");
        lock (seen) Assert.DoesNotContain(PlaybookAction.Kill, seen);
        var snap = Assert.Single(host.ListProfiles(onlyContained: false), p => p.Pid == pid);
        Assert.True(snap.ContainmentSkipped);
        Assert.Equal(0, host.VerdictsInBackoff);
    }

    [Fact]
    public void Monitor_mode_says_enforce_would_refuse()
    {
        const int pid = 80003;
        var sink = new RecordingSink();
        var host = NewHost(sink, null, _ => "it is a test stand-in", monitorOnly: true);
        host.Start();
        Flag(host, pid, "svchost.exe");

        Assert.True(WaitFor(() => sink.Any(e => e.Level == "ACTION" && e.Message.Contains("enforce would refuse"))));
    }

    [Fact]
    public void Analyst_suspend_and_kill_are_refused_and_the_process_keeps_running()
    {
        var child = Start(Path.Combine(Environment.SystemDirectory, "ping.exe"));
        var sink = new RecordingSink();
        var host = NewHost(sink, null, p => p == child.Id ? "it is a test stand-in" : null, monitorOnly: true);
        host.Start();

        var suspended = host.Suspend(child.Id);
        var killed = host.Kill(child.Id);

        Assert.False(suspended.Ok);
        Assert.StartsWith("refused:", suspended.Message);
        Assert.False(killed.Ok);
        Assert.StartsWith("refused:", killed.Message);
        Assert.False(child.WaitForExit(300), "the refused process was killed");
    }

    // ------------------------------------------------------------------ helpers

    private BruceHost NewHost(RecordingSink sink, Playbook? playbook, Func<int, string?> refuse, bool monitorOnly,
        Action<PlaybookAction, ProfileSnapshot>? extended = null)
    {
        var log = new Logger(sink);
        var response = new ResponseManager(log, new AuthenticodeVerifier(new AllowlistConfig()));
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => false,
            new EngineDependencies { ResolveProcessName = null });
        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            StartMonitors = false,
            EnableExtendedMonitors = false,
            MonitorOnly = monitorOnly,
            Playbook = playbook,
            ExtendedAction = extended,
            RefuseContainment = refuse,
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>Scores 90: a browser credential store read, then an archive staged.</summary>
    private static void Flag(BruceHost host, int pid, string name)
    {
        var t = DateTime.UtcNow;
        host.Submit(new Signal { Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name, ImagePath = @"C:\Temp\" + name, TimestampUtc = t });
        host.Submit(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = pid, ProcessName = name, TimestampUtc = t.AddSeconds(1),
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        });
        host.Submit(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = pid, ProcessName = name, TimestampUtc = t.AddSeconds(2),
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip"
        });
    }

    private Process Start(string image)
    {
        var child = Process.Start(new ProcessStartInfo(image, "-n 120 127.0.0.1")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("could not start " + image);
        _children.Add(child);
        return child;
    }

    private string NewDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "bruce-guard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        return dir;
    }

    private static bool WaitFor(Func<bool> condition, int millis = 5000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < millis)
        {
            if (condition()) return true;
            Thread.Sleep(10);
        }
        return condition();
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    private sealed class RecordingSink : IEventSink
    {
        private readonly List<BruceEvent> _events = new();
        public void Emit(BruceEvent e) { lock (_events) _events.Add(e); }
        public void Dispose() { }
        public bool Any(Func<BruceEvent, bool> match) { lock (_events) return _events.Any(match); }
    }
}
