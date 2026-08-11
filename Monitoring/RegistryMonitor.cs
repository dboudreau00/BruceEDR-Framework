using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using ProcessShield.Core;

namespace ProcessShield.Monitoring;

/// <summary>
/// Watches registry writes for persistence and defence-evasion changes, using the
/// kernel Registry keyword in its OWN real-time session.
///
/// Why a separate session from <c>EtwMonitor</c>: the Registry keyword is one of the
/// loudest sources on Windows -- tens of thousands of events per second on a busy
/// desktop. Sharing the primary kernel session would put that volume on the same
/// buffer pool and the same pump thread as process starts and network connects, and
/// a burst would drop the events that matter most. Windows 8 and later allow several
/// independently named kernel sessions, which is what makes this split possible; on
/// older builds only the singleton "NT Kernel Logger" exists and this monitor cannot
/// start at all.
///
/// Two honest limitations:
/// <list type="bullet">
/// <item><description>Names are frequently PARTIAL. The provider reports a Key Control
/// Block handle plus a KCB-relative name, and the parent path is only recoverable when
/// the session observed the matching KCB creation. Keys that were already open when we
/// started resolve to a fragment. That is why the filter matches substrings -- and why
/// a write whose reported name is only a leaf is missed entirely.</description></item>
/// <item><description>Events are reported AFTER the fact. This monitor observes; it
/// cannot block a write. Blocking needs the kernel minifilter.</description></item>
/// </list>
///
/// Hardening follows the same discipline as <c>EtwMonitor</c>: clear a leaked session
/// from a prior crash, dispose the session if wiring fails so the host can run without
/// registry telemetry, guard every handler, and log if the pump stops.
/// </summary>
public sealed class RegistryMonitor : IDisposable
{
    private const string SessionName = "ProcessShield-Registry";

    /// <summary>
    /// Installers and even Explorer rewrite the same value repeatedly. Five seconds of
    /// suppression per (pid, action, path) keeps a single benign burst from inflating a
    /// process score while still letting genuinely repeated persistence re-surface.
    /// </summary>
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Non-persistence keys that are still worth an alert because writing them weakens
    /// the machine's defences. Matched as case-insensitive substrings for the same
    /// partial-name reason as the persistence list.
    /// </summary>
    private static readonly string[] DefenceEvasionFragments =
    {
        @"\windows defender\exclusions\",                    // exclusion added before the drop
        @"\windows defender\real-time protection\",          // realtime monitoring toggles
        @"\policies\microsoft\windows defender",             // policy-level disable
        @"\control\safeboot\",                               // safe-mode service planting
        @"\sharedaccess\parameters\firewallpolicy\",         // firewall profile changes
        @"\policies\system\enablelua",                       // UAC off
        @"\policies\system\consentpromptbehavioradmin",      // silent elevation
        @"\control\terminal server\fdenytsconnections",      // enabling RDP
        @"\services\eventlog\"                               // event log tampering
    };

    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private readonly SignalDeduplicator _dedupe;
    private TraceEventSession? _session;
    private Thread? _pump;

    /// <param name="emit">Sink for produced signals. Called on the ETW pump thread.</param>
    /// <param name="log">Diagnostics.</param>
    /// <param name="clock">
    /// Time source for duplicate suppression. Defaults to the wall clock; injected in
    /// tests and replay so the window is exercised without sleeping.
    /// </param>
    public RegistryMonitor(Action<Signal> emit, Logger log, IClock? clock = null)
    {
        _emit = emit;
        _log = log;
        _dedupe = new SignalDeduplicator(clock ?? SystemClock.Instance, DedupeWindow);
    }

    /// <summary>
    /// Starts the session and the pump. Throws only when registry telemetry genuinely
    /// cannot be collected (not elevated, pre-Win8, session slots exhausted, keyword
    /// unavailable) so the host can log the degradation and carry on without it.
    /// </summary>
    public void Start()
    {
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("registry ETW requires Administrator");

        EtwSessionSupport.ClearStaleSession(SessionName, _log);

        TraceEventSession? session = null;
        try
        {
            // A larger buffer pool than the default: registry bursts are the one place
            // where the default quantum reliably loses events.
            session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 64 };
            session.EnableKernelProvider(KernelTraceEventParser.Keywords.Registry);

            var k = session.Source.Kernel;

            // Only mutating operations. Open/Query/Enumerate are an order of magnitude
            // louder again and say nothing about intent.
            k.RegistrySetValue += d => Guard(() => OnRegistry(d, "set-value"));
            k.RegistryCreate += d => Guard(() => OnRegistry(d, "create-key"));
            k.RegistryDeleteValue += d => Guard(() => OnRegistry(d, "delete-value"));
            k.RegistryDelete += d => Guard(() => OnRegistry(d, "delete-key"));

            _session = session;
            _pump = new Thread(PumpEvents) { IsBackground = true, Name = "ProcessShield-ETW-Registry" };
            _pump.Start();
        }
        catch
        {
            try { session?.Dispose(); } catch { }
            throw;   // let the host continue without registry telemetry
        }
    }

    private void OnRegistry(RegistryTraceData d, string action)
    {
        string path = MonitorSupport.NormalizeRegistryKey(d.KeyName, d.ValueName);
        if (path.Length == 0) return;
        if (!IsInteresting(path)) return;

        // Our own writes (config, quarantine bookkeeping) would otherwise feed back
        // into the engine as evidence against the agent itself.
        if (d.ProcessID == Environment.ProcessId) return;

        if (!_dedupe.ShouldEmit($"{d.ProcessID}|{action}|{path}")) return;

        _emit(new Signal
        {
            Kind = SignalKind.RegistryWrite,
            Pid = d.ProcessID,
            ProcessName = d.ProcessName ?? "",
            RegistryKey = path,
            RegistryValue = string.IsNullOrEmpty(d.ValueName) ? null : d.ValueName,
            Detail = action,
            // The event's own timestamp beats reading the clock here: it is the time the
            // kernel recorded the operation, not the time our pump got round to it.
            TimestampUtc = d.TimeStamp.ToUniversalTime()
        });
    }

    private static bool IsInteresting(string path)
    {
        if (MonitorSupport.IsPersistenceKey(path)) return true;
        foreach (string fragment in DefenceEvasionFragments)
            if (path.Contains(fragment, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            _log.Error("registry ETW pump stopped", ex);
        }
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) { _log.Error("registry ETW event handler", ex); }
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
