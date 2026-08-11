using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using ProcessShield.Core;

namespace ProcessShield.Monitoring;

/// <summary>
/// Reports one process opening a handle to another, from the
/// <c>Microsoft-Windows-Kernel-Audit-API-Calls</c> provider. This is the telemetry
/// that catches credential dumping (anything opening <c>lsass.exe</c> for VM_READ)
/// and cross-process injection (VM_WRITE plus CREATE_THREAD), neither of which leaves
/// a file or a network trace.
///
/// It is a manifest (user-mode) provider, so it needs its own user-mode session
/// separate from the kernel session in <c>EtwMonitor</c>.
///
/// The provider's schema is UNDOCUMENTED and version dependent. Event IDs and payload
/// field names have changed between Windows releases, and there is no contract that
/// they will not change again. Two consequences are baked into this class:
/// <list type="bullet">
/// <item><description>Every field is read by NAME with several fallbacks, and events
/// are classified by event name first with the historical IDs used only as a
/// backstop.</description></item>
/// <item><description>If the fields simply are not there, the monitor DEGRADES TO A
/// NO-OP: after a run of unparseable events it logs once and stops doing per-event
/// work, rather than throwing, spamming the log, or emitting garbage signals.</description></item>
/// </list>
///
/// Further honest limits: the provider records the REQUESTED access, so a request that
/// the kernel refused still appears (useful -- a failed LSASS open is a strong signal,
/// but it is not proof of a successful read). Handles obtained by duplication from
/// another process, or by a kernel driver, do not appear at all. And an implant that
/// injects via an already-open handle inherited at creation produces no event here.
/// </summary>
public sealed class ProcessAccessMonitor : IDisposable
{
    private const string SessionName = "ProcessShield-ProcAccess";

    /// <summary>Microsoft-Windows-Kernel-Audit-API-Calls.</summary>
    private static readonly Guid AuditApiProvider = new("E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23");

    // Historical event IDs, used only when the event name is unavailable (an
    // unresolvable manifest renders names as "EventID(n)"). Treated as a hint, never
    // as a guarantee.
    private const int IdTerminateProcess = 2;
    private const int IdOpenProcess = 5;
    private const int IdOpenThread = 6;

    /// <summary>PROCESS_TERMINATE, synthesised when a terminate event carries no mask.</summary>
    private const uint ProcessTerminateRight = 0x0001;

    /// <summary>
    /// Sentinel for "the payload had no access mask". Distinguishable from a genuine
    /// zero mask, which is a valid (if useless) request.
    /// </summary>
    private const uint AccessAbsent = 0xFFFF_FFFF;

    /// <summary>
    /// How many consecutive unparseable events to tolerate before concluding the
    /// schema on this build is not one we understand. Generous, because a handful of
    /// unrelated events from the same provider (image-notify registrations) legitimately
    /// carry none of our fields.
    /// </summary>
    private const int UnparseableBudget = 256;

    /// <summary>
    /// Handle opens repeat constantly for the same pair. Suppressing an identical
    /// (actor, target, mask) for five seconds keeps a debugger or a monitoring tool
    /// from drowning the engine while still showing a repeated injection attempt.
    /// </summary>
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(5);

    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private readonly SignalDeduplicator _dedupe;
    private readonly int _selfPid;
    private TraceEventSession? _session;
    private Thread? _pump;

    // Touched only from the single pump thread.
    private int _unparseable;
    private bool _degraded;

    /// <param name="emit">Sink for produced signals. Called on the ETW pump thread.</param>
    /// <param name="log">Diagnostics.</param>
    /// <param name="clock">Time source for duplicate suppression; defaults to the wall clock.</param>
    public ProcessAccessMonitor(Action<Signal> emit, Logger log, IClock? clock = null)
    {
        _emit = emit;
        _log = log;
        _dedupe = new SignalDeduplicator(clock ?? SystemClock.Instance, DedupeWindow);
        _selfPid = Environment.ProcessId;
    }

    /// <summary>
    /// Starts a user-mode session bound to the audit provider. Throws only when the
    /// session cannot be created at all; an unrecognised schema is handled at runtime
    /// by degrading, not by failing the start, because the failure is not detectable
    /// until events actually arrive.
    /// </summary>
    public void Start()
    {
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("process-access ETW requires Administrator");

        EtwSessionSupport.ClearStaleSession(SessionName, _log);

        TraceEventSession? session = null;
        try
        {
            session = new TraceEventSession(SessionName) { StopOnDispose = true };
            session.EnableProvider(AuditApiProvider, TraceEventLevel.Informational);
            session.Source.Dynamic.All += data => Guard(() => OnEvent(data));

            _session = session;
            _pump = new Thread(PumpEvents) { IsBackground = true, Name = "ProcessShield-ETW-ProcAccess" };
            _pump.Start();
        }
        catch
        {
            try { session?.Dispose(); } catch { }
            throw;   // let the host continue without process-access telemetry
        }
    }

    private void OnEvent(TraceEvent data)
    {
        if (_degraded) return;
        if (data.ProviderGuid != AuditApiProvider) return;

        AccessKind kind = Classify(data);
        if (kind == AccessKind.Other) return;

        int targetPid = ReadTargetPid(data, kind);
        uint access = EtwSessionSupport.GetUInt32(data, AccessAbsent,
            "DesiredAccess", "desiredAccess", "AccessMask", "GrantedAccess", "Access");

        if (targetPid <= 0 || (access == AccessAbsent && kind != AccessKind.Terminate))
        {
            NoteUnparseable();
            return;
        }

        _unparseable = 0;

        // A terminate event without a mask still means exactly one thing.
        if (access == AccessAbsent) access = ProcessTerminateRight;

        // Self-access is constant and benign: almost every API that takes a process
        // handle is called on GetCurrentProcess() first.
        if (targetPid == data.ProcessID) return;

        // Our own handle opens (signature checks, memory scans, containment) would
        // otherwise be fed back to the engine as evidence against the agent.
        if (data.ProcessID == _selfPid) return;

        bool sensitive = MonitorSupport.IsSensitiveProcessAccess(access);
        if (!sensitive && kind != AccessKind.Terminate) return;

        if (!_dedupe.ShouldEmit($"{data.ProcessID}|{targetPid}|{kind}|{access}")) return;

        string detail = kind switch
        {
            AccessKind.Terminate => "terminate:" + MonitorSupport.DescribeAccessMask(access),
            AccessKind.OpenThread => "open-thread:" + MonitorSupport.DescribeAccessMask(access),
            _ => "open-process:" + MonitorSupport.DescribeAccessMask(access)
        };

        _emit(new Signal
        {
            Kind = SignalKind.ProcessAccess,
            Pid = data.ProcessID,
            ProcessName = data.ProcessName ?? "",
            TargetPid = targetPid,
            DesiredAccess = access,
            Detail = detail,
            TimestampUtc = data.TimeStamp.ToUniversalTime()
        });
    }

    /// <summary>What the audit event describes, as far as we can tell on this build.</summary>
    private enum AccessKind { Other, OpenProcess, OpenThread, Terminate }

    /// <summary>
    /// Classifies by event name where possible (stable across ID renumbering) and falls
    /// back to the historical IDs when the manifest could not be resolved.
    /// </summary>
    private static AccessKind Classify(TraceEvent data)
    {
        string name = data.EventName ?? "";
        if (name.Length > 0)
        {
            if (name.Contains("terminate", StringComparison.OrdinalIgnoreCase)) return AccessKind.Terminate;
            if (name.Contains("openprocess", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("open_process", StringComparison.OrdinalIgnoreCase)) return AccessKind.OpenProcess;
            if (name.Contains("openthread", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("open_thread", StringComparison.OrdinalIgnoreCase)) return AccessKind.OpenThread;
        }

        return (int)data.ID switch
        {
            IdTerminateProcess => AccessKind.Terminate,
            IdOpenProcess => AccessKind.OpenProcess,
            IdOpenThread => AccessKind.OpenThread,
            _ => AccessKind.Other
        };
    }

    /// <summary>
    /// Finds the victim PID. The explicit target names are tried first; the bare
    /// <c>ProcessId</c> field is only consulted for terminate events, where the
    /// manifest historically used that name for the victim, and only when it differs
    /// from the emitting process (otherwise it is the actor and would be wrong).
    /// </summary>
    private static int ReadTargetPid(TraceEvent data, AccessKind kind)
    {
        int pid = EtwSessionSupport.GetInt32(data, 0,
            "TargetProcessId", "TargetProcessID", "TargetPid", "TargetProcessIdentifier");
        if (pid > 0) return pid;

        if (kind == AccessKind.Terminate)
        {
            int candidate = EtwSessionSupport.GetInt32(data, 0, "ProcessId", "ProcessID");
            if (candidate > 0 && candidate != data.ProcessID) return candidate;
        }

        if (EtwSessionSupport.PayloadLike(data, "targetprocess") is { } value &&
            int.TryParse(value.ToString(), out int scanned) && scanned > 0) return scanned;

        return 0;
    }

    /// <summary>
    /// Counts events we could not make sense of and, past the budget, shuts the monitor
    /// down to a no-op. Failing quiet is the right call here: an unrecognised schema is
    /// a coverage gap, not a fault the operator can fix at runtime, and an event handler
    /// that logs on every event would itself become the problem.
    /// </summary>
    private void NoteUnparseable()
    {
        if (++_unparseable < UnparseableBudget) return;
        _degraded = true;
        _log.Info(
            "process-access monitor disabled: Kernel-Audit-API-Calls payload fields " +
            "were not recognised on this Windows build (no target PID / access mask)");
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            _log.Error("process-access ETW pump stopped", ex);
        }
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) { _log.Error("process-access ETW event handler", ex); }
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
