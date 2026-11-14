using System.Diagnostics;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Memory;
using BruceEDR.Response;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Analyst Suspend/Resume/Kill from the GUI, console or control API act on a row that can
/// outlive its process. These run against a real child process the test owns, tracked under
/// a different name, so a regression can only ever touch that child.
/// </summary>
public sealed class AnalystActionIdentityTests : IDisposable
{
    private readonly List<BruceHost> _hosts = new();
    private readonly List<Process> _children = new();

    public void Dispose()
    {
        foreach (var h in _hosts) { try { h.Dispose(); } catch { } }
        foreach (var c in _children)
        {
            try { ResponseManager.ResumeProcess(c.Id); } catch { }
            try { if (!c.HasExited) c.Kill(entireProcessTree: true); } catch { }
            c.Dispose();
        }
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    private Process StartBystander()
    {
        var child = Process.Start(new ProcessStartInfo("ping.exe", "-n 120 127.0.0.1")
        {
            CreateNoWindow = true,
            UseShellExecute = false,
        }) ?? throw new InvalidOperationException("could not start ping.exe");
        _children.Add(child);
        return child;
    }

    private BruceHost NewHost()
    {
        var log = new Logger();
        var response = new ResponseManager(log, new AuthenticodeVerifier(new AllowlistConfig()));
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => false,
            new EngineDependencies { ResolveProcessName = null });
        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            StartMonitors = false,
            EnableExtendedMonitors = false,
            MonitorOnly = true,
        });
        _hosts.Add(host);
        host.Start();
        return host;
    }

    private static void Track(BruceHost host, int pid, string name)
    {
        host.Submit(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name,
            ImagePath = @"C:\t\" + name, TimestampUtc = DateTime.UtcNow,
        });
        var sw = Stopwatch.StartNew();
        while (!host.Info(pid).Ok && sw.ElapsedMilliseconds < 5000) Thread.Sleep(10);
        Assert.True(host.Info(pid).Ok, $"pid {pid} was never tracked");
    }

    [Fact]
    public void Analyst_kill_refuses_a_pid_now_owned_by_another_process()
    {
        var child = StartBystander();
        var host = NewHost();
        Track(host, child.Id, "stealer.exe");

        var r = host.Kill(child.Id);

        Assert.False(r.Ok);
        Assert.Contains("pid reused", r.Message);
        Assert.False(child.WaitForExit(300), "the bystander process was killed");
    }

    [Fact]
    public void Analyst_suspend_and_resume_refuse_a_pid_now_owned_by_another_process()
    {
        var child = StartBystander();
        var host = NewHost();
        Track(host, child.Id, "stealer.exe");

        var suspended = host.Suspend(child.Id);
        var resumed = host.Resume(child.Id);

        Assert.False(suspended.Ok);
        Assert.Contains("pid reused", suspended.Message);
        Assert.False(resumed.Ok);
        Assert.Contains("pid reused", resumed.Message);
    }

    [Fact]
    public void Analyst_kill_still_ends_the_process_it_is_tracking()
    {
        var child = StartBystander();
        var host = NewHost();
        Track(host, child.Id, "PING.EXE");

        var r = host.Kill(child.Id);

        Assert.True(r.Ok, r.Message);
        Assert.True(child.WaitForExit(5000));
    }
}
