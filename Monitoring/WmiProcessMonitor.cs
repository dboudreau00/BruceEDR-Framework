using System.Management;
using BruceEDR.Core;

namespace BruceEDR.Monitoring;

/// <summary>
/// Dependency-free fallback used when the ETW kernel session cannot start. Reports
/// process starts (command line + parent PID) via WMI. No file or network events,
/// so the exfil-chain correlation is limited. Every callback is guarded.
/// </summary>
public sealed class WmiProcessMonitor : IDisposable
{
    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private ManagementEventWatcher? _watcher;

    public WmiProcessMonitor(Action<Signal> emit, Logger log)
    {
        _emit = emit;
        _log = log;
    }

    public void Start()
    {
        var query = new WqlEventQuery(
            "__InstanceCreationEvent",
            TimeSpan.FromMilliseconds(500),
            "TargetInstance ISA 'Win32_Process'");

        _watcher = new ManagementEventWatcher(query);
        _watcher.EventArrived += OnArrived;
        _watcher.Start();

        // Deletions too, so the fallback source also drives pid lifecycle.
        var stopQuery = new WqlEventQuery(
            "__InstanceDeletionEvent",
            TimeSpan.FromMilliseconds(500),
            "TargetInstance ISA 'Win32_Process'");
        _stopWatcher = new ManagementEventWatcher(stopQuery);
        _stopWatcher.EventArrived += OnStopped;
        _stopWatcher.Start();
    }

    private ManagementEventWatcher? _stopWatcher;

    private void OnStopped(object sender, EventArrivedEventArgs e)
    {
        try
        {
            using var ev = e.NewEvent;
            using var target = (ManagementBaseObject)ev["TargetInstance"];
            _emit(new Signal
            {
                Kind = SignalKind.ProcessStop,
                Pid = ToInt(target["ProcessId"]),
                ProcessName = target["Name"] as string ?? ""
            });
        }
        catch (Exception ex)
        {
            _log.Error("WMI stop event", ex);
        }
    }

    private void OnArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            // Dispose BOTH the outer event and the embedded instance -- each wraps an
            // IWbemClassObject COM object that leaks otherwise, once per process start.
            using var ev = e.NewEvent;
            using var target = (ManagementBaseObject)ev["TargetInstance"];
            _emit(new Signal
            {
                Kind = SignalKind.ProcessStart,
                Pid = ToInt(target["ProcessId"]),
                ParentPid = ToInt(target["ParentProcessId"]),
                ProcessName = target["Name"] as string ?? "",
                ImagePath = target["ExecutablePath"] as string ?? "",
                CommandLine = target["CommandLine"] as string ?? ""
            });
        }
        catch (Exception ex)
        {
            _log.Error("WMI event", ex);
        }
    }

    private static int ToInt(object? o)
    {
        try { return o is null ? 0 : Convert.ToInt32(o); }
        catch { return 0; }
    }

    public void Dispose()
    {
        if (_stopWatcher is not null)
        {
            try { _stopWatcher.EventArrived -= OnStopped; _stopWatcher.Stop(); } catch { }
            try { _stopWatcher.Dispose(); } catch { }
            _stopWatcher = null;
        }
        if (_watcher is null) return;
        try { _watcher.EventArrived -= OnArrived; _watcher.Stop(); } catch { }
        try { _watcher.Dispose(); } catch { }
        _watcher = null;
    }
}
