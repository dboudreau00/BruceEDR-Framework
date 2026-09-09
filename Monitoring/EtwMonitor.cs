using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using BruceEDR.Core;

namespace BruceEDR.Monitoring;

/// <summary>
/// Primary telemetry source: one real-time kernel session yielding PID-attributed
/// process starts (with command line), image loads, file creates, and outbound TCP
/// connects. Requires Administrator and x64 Win8+.
///
/// Hardening: clears a leaked session from a prior crash before starting, disposes
/// the session if wiring fails (so the host can fall back to WMI), guards every
/// event handler so one malformed event cannot tear down the pump, and logs if the
/// pump stops unexpectedly. If FileName is ever empty on your build, also enable
/// KernelTraceEventParser.Keywords.FileIO so name-rundown events are captured.
/// </summary>
public sealed class EtwMonitor : IDisposable
{
    private const string SessionName = "BruceEDR-Kernel";

    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private TraceEventSession? _session;
    private Thread? _pump;
    private volatile bool _disposed;
    private int _restarts;
    private const int MaxRestarts = 5;

    public EtwMonitor(Action<Signal> emit, Logger log)
    {
        _emit = emit;
        _log = log;
    }

    public void Start()
    {
        CleanupStaleSession();

        TraceEventSession? session = null;
        try
        {
            session = new TraceEventSession(SessionName) { StopOnDispose = true };
            session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.Process |
                KernelTraceEventParser.Keywords.ImageLoad |
                KernelTraceEventParser.Keywords.FileIOInit |
                KernelTraceEventParser.Keywords.NetworkTCPIP);

            var k = session.Source.Kernel;

            k.ProcessStart += d => Guard(() => _emit(new Signal
            {
                Kind = SignalKind.ProcessStart,
                Pid = d.ProcessID,
                ParentPid = d.ParentID,
                ProcessName = Path.GetFileName(d.ImageFileName),
                ImagePath = d.ImageFileName,
                CommandLine = d.CommandLine ?? "",
                TimestampUtc = d.TimeStamp.ToUniversalTime()
            }));

            // The other half of pid lifecycle. Without it the engine's PID-reuse handling
            // (replace the profile on start, ignore signals for an exited pid) only ever
            // ran in replay, never on a live host.
            k.ProcessStop += d => Guard(() => _emit(new Signal
            {
                Kind = SignalKind.ProcessStop,
                Pid = d.ProcessID,
                ProcessName = Path.GetFileName(d.ImageFileName),
                TimestampUtc = d.TimeStamp.ToUniversalTime()
            }));

            k.ImageLoad += d => Guard(() => _emit(new Signal
            {
                Kind = SignalKind.ImageLoad,
                Pid = d.ProcessID,
                FilePath = d.FileName,
                Detail = d.FileName,
                TimestampUtc = d.TimeStamp.ToUniversalTime()
            }));

            k.FileIOCreate += d => Guard(() => _emit(new Signal
            {
                Kind = SignalKind.FileCreate,
                Pid = d.ProcessID,
                FilePath = d.FileName,
                TimestampUtc = d.TimeStamp.ToUniversalTime()
            }));

            k.TcpIpConnect += d => Guard(() => _emit(new Signal
            {
                Kind = SignalKind.NetworkConnect,
                Pid = d.ProcessID,
                RemoteAddress = d.daddr?.ToString(),
                RemotePort = d.dport,
                TimestampUtc = d.TimeStamp.ToUniversalTime()
            }));

            // IPv6 outbound connects fire a separate event; without this, IPv6 C2/exfil
            // traffic produces no NetworkConnect signal and evades the network rules.
            k.TcpIpConnectIPV6 += d => Guard(() => _emit(new Signal
            {
                Kind = SignalKind.NetworkConnect,
                Pid = d.ProcessID,
                RemoteAddress = d.daddr?.ToString(),
                RemotePort = d.dport,
                TimestampUtc = d.TimeStamp.ToUniversalTime()
            }));

            _session = session;
            _pump = new Thread(PumpEvents) { IsBackground = true, Name = "BruceEDR-ETW" };
            _pump.Start();
        }
        catch
        {
            try { session?.Dispose(); } catch { }
            throw;   // let the host fall back to WMI
        }
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            if (_disposed) return;
            int n = Interlocked.Increment(ref _restarts);
            if (n > MaxRestarts)
            {
                _log.Error($"ETW pump stopped and will NOT be restarted ({MaxRestarts} restarts exhausted); " +
                           "kernel telemetry is DOWN until the agent restarts", ex);
                return;
            }
            _log.Error($"ETW pump stopped; restarting in 5s (attempt {n}/{MaxRestarts})", ex);
            Thread.Sleep(5000);
            if (_disposed) return;
            try
            {
                var old = _session;
                _session = null;
                try { old?.Dispose(); } catch { }
                Start();
                _log.Info("ETW pump restarted");
            }
            catch (Exception ex2) { _log.Error("ETW restart failed; kernel telemetry is DOWN", ex2); }
        }
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) { _log.Error("ETW event handler", ex); }
    }

    private void CleanupStaleSession()
    {
        try
        {
            foreach (var name in TraceEventSession.GetActiveSessionNames())
            {
                if (!string.Equals(name, SessionName, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    new TraceEventSession(SessionName).Stop();
                    _log.Info("cleared a leaked ETW session from a prior run");
                }
                catch (Exception ex) { _log.Error("clear stale ETW session", ex); }
            }
        }
        catch (Exception ex)
        {
            _log.Error("enumerate ETW sessions", ex);
        }
    }

    public void Dispose()
    {
        _disposed = true;
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
