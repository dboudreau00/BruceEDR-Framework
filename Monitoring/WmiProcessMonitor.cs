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
        if (_watcher is null) return;
        try { _watcher.EventArrived -= OnArrived; _watcher.Stop(); } catch { }
        try { _watcher.Dispose(); } catch { }
        _watcher = null;
    }
}
