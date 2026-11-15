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
    private readonly FileNameCache _fileNames = new();

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

            k.FileIOCreate += d => Guard(() =>
            {
                var at = d.TimeStamp.ToUniversalTime();
                _fileNames.Put(d.FileObject, d.FileName);
                _emit(new Signal
                {
                    Kind = SignalKind.FileCreate,
                    Pid = d.ProcessID,
                    FilePath = d.FileName,
                    Detail = FileEvents.CreateDetail((int)d.CreateDisposition, (uint)d.CreateOptions),
                    TimestampUtc = at
                });
                // A program that removes itself opens its own file delete-on-close, so the removal
                // is known at the open, before any delete event exists.
                if (FileEvents.IsDeleteOnClose((uint)d.CreateOptions))
                    _emit(new Signal
                    {
                        Kind = SignalKind.FileDelete,
                        Pid = d.ProcessID,
                        FilePath = d.FileName,
                        Detail = "on-close",
                        TimestampUtc = at
                    });
            });

            // The delete and rename events name the file object; the name is what the open said, and
            // TraceEvent's own lookup is empty for a file it never saw opened.
            k.FileIODelete += d => Guard(() => EmitFileChange(SignalKind.FileDelete, d.ProcessID,
                string.IsNullOrEmpty(d.FileName) ? _fileNames.Get(d.FileObject) : d.FileName, "delete", d.TimeStamp));

            // The kernel's rename event carries no new name, so only the old one is known here.
            k.FileIORename += d => Guard(() => EmitFileChange(SignalKind.FileRename, d.ProcessID,
                string.IsNullOrEmpty(d.FileName) ? _fileNames.Get(d.FileObject) : d.FileName, null, d.TimeStamp));

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

    private void EmitFileChange(SignalKind kind, int pid, string? path, string? detail, DateTime stamp)
    {
        if (string.IsNullOrEmpty(path)) return;   // nothing to show for a file nobody named
        _emit(new Signal
        {
            Kind = kind,
            Pid = pid,
            FilePath = path,
            Detail = detail,
            TimestampUtc = stamp.ToUniversalTime()
        });
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
