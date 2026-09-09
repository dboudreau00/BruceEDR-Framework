using System.Collections.Concurrent;
using System.Text;
using BruceEDR.Analysis;
using BruceEDR.Api;
using BruceEDR.Detection;
using BruceEDR.Monitoring;
using BruceEDR.Response;
using BruceEDR.Telemetry;

namespace BruceEDR.Core;

/// <summary>
/// Everything the host needs beyond the four core collaborators. All optional, so a
/// minimal embedding (a test, the replay harness) can construct a host with the v1
/// signature and get exactly the v1 behaviour.
/// </summary>
public sealed class BruceHostOptions
{
    public bool AutoKill { get; init; }
    /// <summary>Start the registry / DNS / AMSI / process-access ETW sessions.</summary>
    public bool EnableExtendedMonitors { get; init; } = true;
    /// <summary>Shared with the engine; the host feeds it and reads lineage for alerts.</summary>
    public ProcessTree? Tree { get; init; }
    /// <summary>Shared with the engine; queried by the console, the GUI and the control API.</summary>
    public ApiSurfaceInventory? Surface { get; init; }
    /// <summary>Decides which response actions a verdict triggers. Null uses the built-in default.</summary>
    public Playbook? Playbook { get; init; }
    public BruceMetrics? Metrics { get; init; }
    /// <summary>
    /// Start the telemetry sources. False starts the owner and response threads but no
    /// monitors, so the pipeline can be driven by directly submitted signals.
    ///
    /// This exists because every monitor needs an ETW session and Administrator rights, and
    /// without a seam the entire host -- queue prioritisation, verdict dispatch, playbook
    /// ordering, containment-failure handling -- had no tests at all.
    /// </summary>
    public bool StartMonitors { get; init; } = true;

    /// <summary>Invoked on the response worker for playbook actions the host does not implement itself.</summary>
    public Action<PlaybookAction, ProfileSnapshot>? ExtendedAction { get; init; }
}

/// <summary>
/// Single-owner (actor) orchestrator. Exactly ONE thread reads and mutates
/// detection state; monitors and the console feed the same queue. Slow containment
/// runs on a separate response worker, which prioritises containment over best-effort
/// memory scans. Detection posture is hot-reloadable via a ConfigCommand routed through
/// the same owner thread.
/// </summary>
public sealed class BruceHost : IDisposable
{
    private abstract class Command { }

    private sealed class SignalCommand : Command
    {
        public required Signal Signal { get; init; }
    }

    private sealed class ListCommand : Command
    {
        public required bool OnlyContained { get; init; }
        public required TaskCompletionSource<IReadOnlyList<ProfileSnapshot>> Result { get; init; }
    }

    private enum ActionKind { Resume, Suspend, Kill, Info }

    private sealed class ActionCommand : Command
    {
        public required ActionKind Kind { get; init; }
        public required int Pid { get; init; }
        public required TaskCompletionSource<ActionResult> Result { get; init; }
    }

    private sealed class ConfigCommand : Command
    {
        public required int Warn { get; init; }
        public required int Quarantine { get; init; }
        public required int WindowSeconds { get; init; }
        public required int TrustDiscount { get; init; }
        public required bool AutoKill { get; init; }
    }

    // Follow-up commands posted BACK to the owner thread after off-thread work, so all
    // engine-state mutation stays single-threaded (no lock on the profile store).
    private sealed class KillDoneCommand : Command
    {
        public required int Pid { get; init; }
        public required TaskCompletionSource<ActionResult> Result { get; init; }
        public required ActionResult Outcome { get; init; }
    }

    private sealed class MemScanResultCommand : Command
    {
        public required int Pid { get; init; }
        public required IReadOnlyList<string> Hits { get; init; }
        /// <summary>Profile generation the scan was claimed under; a mismatch on apply means pid reuse.</summary>
        public long Generation { get; init; }
    }

    private sealed class ImageAnalysisCommand : Command
    {
        public required int Pid { get; init; }
        public required FileAnalysis Analysis { get; init; }
        public long Generation { get; init; }
    }

    // Arbitrary read-only work that must run on the owner thread because it touches
    // engine-owned state (the profile store, the surface inventory, the process tree).
    // Keeping it a command is what lets the console, the GUI and the HTTP control plane
    // all read that state without a single lock.
    private sealed class QueryCommand : Command
    {
        public required Func<object?> Work { get; init; }
        public required TaskCompletionSource<object?> Result { get; init; }
    }

    private readonly DetectionEngine _engine;
    private readonly ResponseManager _response;
    private readonly IMemoryScanner _scanner;
    private readonly Logger _log;

    // Telemetry (high-volume) and analyst/config control commands use SEPARATE queues so
    // a telemetry flood can never starve or delay an operator action. The owner thread
    // drains the control queue with priority over signals.
    private readonly BlockingCollection<Command> _signalQueue = new(boundedCapacity: 8192);
    private readonly BlockingCollection<Command> _controlQueue = new(boundedCapacity: 1024);

    // ProcessStart/ProcessStop travel on their own queue, drained ahead of telemetry.
    // The kernel FileIO provider is unfiltered (every create on the box), so a build or
    // an indexer could fill the 8192-deep signal queue and drop the one event that is the
    // PID-reuse barrier: the ProcessStart that tells the engine a pid has a new owner.
    // Lose that and the new process inherits the old profile -- Contained, Score, forced
    // verdict and all -- which is a fail-open. Lifecycle events are rare relative to file
    // IO, so this queue is never the one under pressure.
    private readonly BlockingCollection<Command> _lifecycleQueue = new(boundedCapacity: 4096);

    // Response work is split for the same reason, and it matters more here. Containment
    // (firewall, vaulting, kill, triage) MUST run; a memory scan is best-effort and can
    // occupy the worker for up to ~2s. With one shared queue a burst of processes claiming
    // scans delayed real containment by minutes and, once the queue hit its cap, the
    // containment task itself was the work that got discarded -- leaving a malicious
    // process merely suspended. The worker now drains _responseQueue to empty before it
    // looks at _scanQueue, so a scan backlog can only ever cost scans.
    private readonly BlockingCollection<Action> _responseQueue = new(boundedCapacity: 1024);
    private readonly BlockingCollection<Action> _scanQueue = new(boundedCapacity: 1024);

    private Thread? _ownerThread;
    private Thread? _responseThread;

    private EtwMonitor? _etw;
    private WmiProcessMonitor? _wmi;
    private FileActivityMonitor? _files;
    private RegistryMonitor? _registry;
    private DnsMonitor? _dns;
    private AmsiMonitor? _amsi;
    private ProcessAccessMonitor? _procAccess;

    private readonly BruceHostOptions _options;
    private readonly Playbook _playbook;

    private volatile bool _autoKill;
    private long _signalsProcessed;
    private long _signalsDropped;
    private long _responsesRun;
    private long _responseErrors;
    private long _responsesDropped;
    private long _scansDropped;
    private int _stopped;

    public string ActiveMonitors { get; private set; } = "none";

    /// <summary>Counters and latency percentiles, safe to read from any thread.</summary>
    public BruceMetrics Metrics { get; }

    /// <summary>
    /// Handles playbook actions the host does not implement itself (host isolation, triage
    /// collection, escalation). Settable because the composition root that implements these
    /// is built around the host and cannot be passed into its constructor.
    /// </summary>
    public Action<PlaybookAction, ProfileSnapshot>? ExtendedAction { get; set; }

    /// <summary>
    /// Supplies the PE analyzer used by <see cref="ScheduleImageAnalysis"/>. Set by the
    /// composition root; null disables static image analysis entirely.
    /// </summary>
    public Func<string, FileAnalysis?>? ImageAnalyzer
    {
        get => _analyzeImage;
        set => _analyzeImage = value;
    }

    private volatile Func<string, FileAnalysis?>? _analyzeImage;

    public BruceHost(bool autoKill, DetectionEngine engine, ResponseManager response,
        IMemoryScanner scanner, Logger log)
        : this(engine, response, scanner, log, new BruceHostOptions { AutoKill = autoKill }) { }

    public BruceHost(DetectionEngine engine, ResponseManager response,
        IMemoryScanner scanner, Logger log, BruceHostOptions options)
    {
        _options = options;
        _autoKill = options.AutoKill;
        _engine = engine;
        _response = response;
        _scanner = scanner;
        _log = log;
        _playbook = options.Playbook ?? Playbook.Default();
        Metrics = options.Metrics ?? new BruceMetrics();
        ExtendedAction = options.ExtendedAction;
    }

    // ---------------------------------------------------------------- lifecycle

    public bool Start()
    {
        _ownerThread = new Thread(OwnerLoop) { IsBackground = true, Name = "Bruce-Owner" };
        _ownerThread.Start();

        _responseThread = new Thread(ResponseLoop) { IsBackground = true, Name = "Bruce-Response" };
        _responseThread.Start();

        var active = new List<string>();

        if (!_options.StartMonitors)
        {
            // Threads are up and the pipeline is live; there is simply no telemetry source.
            // Report success, because "no monitor could start" is a fatal condition the
            // console acts on and this is a deliberate configuration, not a failure.
            ActiveMonitors = "none (signals submitted directly)";
            return true;
        }

        try
        {
            _etw = new EtwMonitor(EnqueueSignal, _log);
            _etw.Start();
            active.Add("ETW(process,image,file,network)");
        }
        catch (Exception ex)
        {
            _log.Error("ETW start failed; trying WMI fallback", ex);
            SafeDispose(ref _etw);
            try
            {
                _wmi = new WmiProcessMonitor(EnqueueSignal, _log);
                _wmi.Start();
                active.Add("WMI(process)");
            }
            catch (Exception ex2)
            {
                _log.Error("WMI start failed", ex2);
                SafeDispose(ref _wmi);
            }
        }

        try
        {
            _files = new FileActivityMonitor(EnqueueSignal, _log);
            _files.Start();
            active.Add("FileStaging");
        }
        catch (Exception ex)
        {
            _log.Error("file monitor start failed (continuing)", ex);
            SafeDispose(ref _files);
        }

        // Extended monitors are each independently optional. They need their own ETW
        // sessions (a kernel session cannot host user-mode providers) and any of them can
        // be unavailable on a given build or SKU, so each failure is logged and skipped
        // rather than degrading the agent as a whole.
        if (_options.EnableExtendedMonitors)
        {
            TryStartMonitor(active, "Registry",
                () => { _registry = new RegistryMonitor(EnqueueSignal, _log); _registry.Start(); },
                () => SafeDispose(ref _registry));
            TryStartMonitor(active, "DNS",
                () => { _dns = new DnsMonitor(EnqueueSignal, _log); _dns.Start(); },
                () => SafeDispose(ref _dns));
            TryStartMonitor(active, "AMSI",
                () => { _amsi = new AmsiMonitor(EnqueueSignal, _log); _amsi.Start(); },
                () => SafeDispose(ref _amsi));
            TryStartMonitor(active, "ProcessAccess",
                () => { _procAccess = new ProcessAccessMonitor(EnqueueSignal, _log); _procAccess.Start(); },
                () => SafeDispose(ref _procAccess));
        }

        ActiveMonitors = active.Count > 0 ? string.Join(", ", active) : "none";
        return active.Count > 0;
    }

    private void TryStartMonitor(List<string> active, string name, Action start, Action cleanup)
    {
        try { start(); active.Add(name); }
        catch (Exception ex)
        {
            _log.Error($"{name} monitor unavailable (continuing without it)", ex);
            try { cleanup(); } catch { }
        }
    }

    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 1) return;

        SafeDispose(ref _etw);
        SafeDispose(ref _wmi);
        SafeDispose(ref _files);
        SafeDispose(ref _registry);
        SafeDispose(ref _dns);
        SafeDispose(ref _amsi);
        SafeDispose(ref _procAccess);

        try { _signalQueue.CompleteAdding(); } catch { }
        try { _lifecycleQueue.CompleteAdding(); } catch { }
        try { _controlQueue.CompleteAdding(); } catch { }
        _ownerThread?.Join(TimeSpan.FromSeconds(5));

        // Both response queues must be completed or the worker blocks forever waiting on
        // the one that is still open, and the join below just times out.
        try { _responseQueue.CompleteAdding(); } catch { }
        try { _scanQueue.CompleteAdding(); } catch { }
        _responseThread?.Join(TimeSpan.FromSeconds(8));

        _log.Info($"shutdown complete. processed={Interlocked.Read(ref _signalsProcessed)} " +
                  $"dropped={Interlocked.Read(ref _signalsDropped)} " +
                  $"responses={Interlocked.Read(ref _responsesRun)} " +
                  $"responseErrors={Interlocked.Read(ref _responseErrors)} " +
                  $"responsesDropped={Interlocked.Read(ref _responsesDropped)} " +
                  $"scansDropped={Interlocked.Read(ref _scansDropped)}");
    }

    public void Dispose()
    {
        Stop();
        try { _signalQueue.Dispose(); } catch { }
        try { _lifecycleQueue.Dispose(); } catch { }
        try { _controlQueue.Dispose(); } catch { }
        try { _responseQueue.Dispose(); } catch { }
        try { _scanQueue.Dispose(); } catch { }
    }

    // --------------------------------------------------------------- producers

    /// <summary>
    /// Feeds one signal into the pipeline exactly as a monitor would. Used by tests and by
    /// callers that supply their own telemetry instead of an ETW session.
    /// </summary>
    internal void Submit(Signal s) => EnqueueSignal(s);

    /// <summary>Signals accepted since start, for tests that need to wait for drain.</summary>
    internal long SignalsProcessed => Interlocked.Read(ref _signalsProcessed);

    /// <summary>Containment tasks completed, for tests that need to wait for the worker.</summary>
    internal long ResponsesRun => Interlocked.Read(ref _responsesRun);

    private void EnqueueSignal(Signal s)
    {
        try
        {
            var queue = s.Kind is SignalKind.ProcessStart or SignalKind.ProcessStop
                ? _lifecycleQueue
                : _signalQueue;
            if (!queue.TryAdd(new SignalCommand { Signal = s }))
            {
                Interlocked.Increment(ref _signalsDropped);
                Metrics.IncDropped();
            }
        }
        catch (InvalidOperationException) { /* shutting down */ }
    }

    // ----------------------------------------------------- console-facing API

    public IReadOnlyList<ProfileSnapshot> ListProfiles(bool onlyContained)
    {
        var tcs = new TaskCompletionSource<IReadOnlyList<ProfileSnapshot>>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        if (!TryPost(new ListCommand { OnlyContained = onlyContained, Result = tcs }))
            return Array.Empty<ProfileSnapshot>();
        return Wait(tcs.Task, Array.Empty<ProfileSnapshot>());
    }

    public ActionResult Resume(int pid) => PostAction(ActionKind.Resume, pid);
    public ActionResult Suspend(int pid) => PostAction(ActionKind.Suspend, pid);
    public ActionResult Kill(int pid) => PostAction(ActionKind.Kill, pid);
    public ActionResult Info(int pid) => PostAction(ActionKind.Info, pid);

    /// <summary>Apply a hot-reloaded detection posture on the owner thread.</summary>
    public void ApplyDetectionConfig(int warn, int quarantine, int windowSeconds, int trustDiscount, bool autoKill)
    {
        bool posted = TryPost(new ConfigCommand
        {
            Warn = warn,
            Quarantine = quarantine,
            WindowSeconds = windowSeconds,
            TrustDiscount = trustDiscount,
            AutoKill = autoKill
        });
        // Posting is bounded now (see TryPost), so a saturated control queue or a shutdown
        // in flight means the new posture was NOT applied. Say so rather than letting the
        // operator believe a reload that never happened took effect.
        if (!posted)
            _log.Error("detection config reload not applied",
                new InvalidOperationException("control queue full or agent shutting down"));
    }

    /// <summary>
    /// Structured counterpart of <see cref="Stats"/> for programmatic consumers (the GUI
    /// status bar). Reading is lock-free; the numbers are the same ones Stats() formats.
    /// </summary>
    public HostStats StatsSnapshot()
    {
        var m = Metrics.Snapshot();
        return new HostStats
        {
            SignalsProcessed = Interlocked.Read(ref _signalsProcessed),
            SignalsDropped = Interlocked.Read(ref _signalsDropped),
            SignalsQueued = _signalQueue.Count + _lifecycleQueue.Count,
            ResponsesRun = Interlocked.Read(ref _responsesRun),
            ResponseErrors = Interlocked.Read(ref _responseErrors),
            Warns = m.Warns,
            Quarantines = m.Quarantines,
            LatencyP95Ms = m.LatencyP95Ms,
            AutoKill = _autoKill,
            Monitors = ActiveMonitors,
        };
    }

    public string Stats()
    {
        var m = Metrics.Snapshot();
        return $"processed={Interlocked.Read(ref _signalsProcessed)} " +
               $"dropped={Interlocked.Read(ref _signalsDropped)} " +
               $"queued={_signalQueue.Count} " +
               $"responsesRun={Interlocked.Read(ref _responsesRun)} " +
               $"responseErrors={Interlocked.Read(ref _responseErrors)} " +
               $"responsesDropped={Interlocked.Read(ref _responsesDropped)} " +
               $"responseQueued={_responseQueue.Count} " +
               $"scansDropped={Interlocked.Read(ref _scansDropped)} " +
               $"warns={m.Warns} quarantines={m.Quarantines} " +
               $"p95={m.LatencyP95Ms:F2}ms " +
               $"autoKill={_autoKill} monitors=[{ActiveMonitors}]";
    }

    // ------------------------------------------------- owner-thread read queries

    /// <summary>
    /// Runs <paramref name="work"/> on the owner thread and returns its result. This is the
    /// only safe way for another thread to read engine-owned state; everything the console,
    /// the GUI and the control API expose goes through here.
    /// </summary>
    private T Query<T>(Func<T> work, T fallback)
    {
        var tcs = new TaskCompletionSource<object?>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!TryPost(new QueryCommand { Work = () => work(), Result = tcs })) return fallback;
        var boxed = Wait<object?>(tcs.Task, null);
        return boxed is T typed ? typed : fallback;
    }

    /// <summary>The observed network/API surface, newest activity first.</summary>
    public IReadOnlyList<SurfaceEndpoint> SurfaceEndpoints(int pid = 0)
    {
        var surface = _options.Surface;
        if (surface is null) return Array.Empty<SurfaceEndpoint>();
        return Query<IReadOnlyList<SurfaceEndpoint>>(
            () => pid > 0 ? surface.ForPid(pid) : surface.All(),
            Array.Empty<SurfaceEndpoint>());
    }

    /// <summary>Distinct ATT&amp;CK techniques observed, mapped to the number of processes citing each.</summary>
    public IReadOnlyDictionary<string, int> ObservedTechniques()
        => Query<IReadOnlyDictionary<string, int>>(
            () => _engine.ObservedTechniques(),
            new Dictionary<string, int>());

    /// <summary>Rendered process ancestry for an alert, e.g. "winword.exe (900) -&gt; powershell.exe (4242)".</summary>
    public string Lineage(int pid)
    {
        var tree = _options.Tree;
        if (tree is null) return "";
        return Query(() => tree.Lineage(pid), "");
    }

    /// <summary>Number of process profiles the engine is currently tracking.</summary>
    public int TrackedProcesses() => Query(() => _engine.TrackedProcesses, 0);

    private ActionResult PostAction(ActionKind kind, int pid)
    {
        var tcs = new TaskCompletionSource<ActionResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!TryPost(new ActionCommand { Kind = kind, Pid = pid, Result = tcs }))
            return ActionResult.Fail("agent is busy or shutting down; command not queued");
        return Wait(tcs.Task, ActionResult.Fail("timed out waiting for the engine"));
    }

    /// <summary>
    /// How long a producer will wait for room in the control queue before giving up. The
    /// control plane and the console are single-threaded, so an unbounded wait on a full
    /// queue hangs them outright; the callers all have a failure path, and every caller
    /// that waits on a result already allows 10s, so this stays well inside their budget.
    /// </summary>
    private static readonly TimeSpan ControlPostTimeout = TimeSpan.FromSeconds(2);

    private bool TryPost(Command cmd)
    {
        // ObjectDisposedException derives from InvalidOperationException, so the more
        // derived type has to come first or the compiler rejects it as unreachable.
        try { return _controlQueue.TryAdd(cmd, ControlPostTimeout); }
        catch (ObjectDisposedException) { return false; /* disposed during shutdown */ }
        catch (InvalidOperationException) { return false; /* CompleteAdding called */ }
    }

    private static T Wait<T>(Task<T> task, T fallback)
    {
        try { return task.Wait(TimeSpan.FromSeconds(10)) ? task.Result : fallback; }
        catch { return fallback; }
    }

    // ------------------------------------------------------------ owner thread

    private void OwnerLoop()
    {
        var queues = new[] { _controlQueue, _lifecycleQueue, _signalQueue };
        try
        {
            while (true)
            {
                // Drain ALL pending control commands before touching a signal, so analyst
                // actions and config reloads are never delayed behind queued telemetry.
                while (_controlQueue.TryTake(out var ctrl))
                    DispatchSafe(ctrl);
                // Then every pending start/stop, so a pid's ownership is settled before any
                // of its telemetry is scored.
                while (_lifecycleQueue.TryTake(out var life))
                    DispatchSafe(life);

                Command? cmd;
                int idx;
                try { idx = BlockingCollection<Command>.TakeFromAny(queues, out cmd); }
                catch (Exception) { break; }   // a queue was completed/disposed during shutdown
                if (idx < 0 || cmd is null) break;   // both queues completed and empty
                DispatchSafe(cmd);
            }
        }
        catch (Exception ex) { _log.Error("owner loop terminated", ex); }
    }

    private void DispatchSafe(Command cmd)
    {
        try { Dispatch(cmd); }
        catch (Exception ex) { _log.Error("owner dispatch", ex); FailCommand(cmd); }
    }

    private void Dispatch(Command cmd)
    {
        switch (cmd)
        {
            case SignalCommand sc:
            {
                Interlocked.Increment(ref _signalsProcessed);
                Metrics.IncSignals();
                long startTicks = System.Diagnostics.Stopwatch.GetTimestamp();
                foreach (var verdict in _engine.Ingest(sc.Signal))
                    OnVerdict(verdict);
                Metrics.ObserveDetectionLatency(System.Diagnostics.Stopwatch.GetElapsedTime(startTicks));
                // Offload the (up to ~2s) memory scan to the response worker's best-effort
                // scan queue so it never stalls the detection loop and never delays or
                // displaces containment; hits fold back in via MemScanResultCommand.
                if (sc.Signal.Pid > 0 && _engine.TryClaimMemoryScan(sc.Signal.Pid, out long scanGen))
                    ScheduleMemoryScan(sc.Signal.Pid, scanGen);
                // Same treatment for the PE parse: it reads the image off disk, so it goes
                // on the droppable scan queue rather than the detection thread.
                if (sc.Signal.Pid > 0 && _engine.TryClaimImageAnalysis(sc.Signal.Pid, out string imagePath, out long imageGen))
                    ScheduleImageAnalysis(sc.Signal.Pid, imagePath, imageGen);
                break;
            }

            case QueryCommand qc:
                try { qc.Result.TrySetResult(qc.Work()); }
                catch (Exception ex) { _log.Error("owner query", ex); qc.Result.TrySetResult(null); }
                break;

            case ListCommand lc:
                lc.Result.TrySetResult(_engine.Snapshot(lc.OnlyContained));
                break;

            case ActionCommand ac:
                DispatchAction(ac);
                break;

            case KillDoneCommand kd:
                if (kd.Outcome.Ok) _engine.SetTerminated(kd.Pid);
                kd.Result.TrySetResult(kd.Outcome);
                break;

            case ImageAnalysisCommand ia:
                foreach (var verdict in _engine.ApplyImageAnalysis(ia.Pid, ia.Analysis, ia.Generation))
                    OnVerdict(verdict);
                break;

            case MemScanResultCommand mr:
                foreach (var verdict in _engine.ApplyMemoryHits(mr.Pid, mr.Hits, mr.Generation))
                    OnVerdict(verdict);
                break;

            case ConfigCommand cc:
                _engine.UpdateThresholds(cc.Warn, cc.Quarantine, cc.WindowSeconds, cc.TrustDiscount);
                _autoKill = cc.AutoKill;
                _log.Info($"config applied: warn>={cc.Warn} quarantine>={cc.Quarantine} autoKill={cc.AutoKill}");
                break;
        }
    }

    // The blocking analyst kill (WaitForExit up to 3s) must not run on the detection
    // thread. Offload it to the response worker and complete the caller's result on the
    // owner thread via a KillDoneCommand, keeping all engine mutation single-threaded.
    private void DispatchAction(ActionCommand ac)
    {
        if (ac.Kind != ActionKind.Kill)
        {
            ac.Result.TrySetResult(ExecuteAction(ac.Kind, ac.Pid));
            return;
        }

        var tcs = ac.Result;
        int pid = ac.Pid;
        bool scheduled = EnqueueResponse(() =>
        {
            var r = ResponseManager.KillProcess(pid);
            // If the follow-up cannot be queued the engine's Terminated flag stays unset,
            // but the analyst still gets the real outcome instead of a 10s timeout.
            if (!TryPost(new KillDoneCommand { Pid = pid, Result = tcs, Outcome = r }))
                tcs.TrySetResult(r);
        });
        if (!scheduled)
            tcs.TrySetResult(ActionResult.Fail("response queue full; kill not scheduled"));
    }

    /// <summary>
    /// Runs the PE parse on the best-effort scan queue. The analyzer itself is supplied by
    /// the composition root (cached, size-capped); a null result just means "nothing useful
    /// to say about this image", which is the normal outcome for a script host or a path
    /// that no longer exists.
    /// </summary>
    private void ScheduleImageAnalysis(int pid, string imagePath, long generation)
    {
        var analyze = _analyzeImage;
        if (analyze is null) return;

        EnqueueScan(() =>
        {
            FileAnalysis? analysis;
            try { analysis = analyze(imagePath); }
            catch { return; }
            if (analysis is null) return;
            if (!TryPost(new ImageAnalysisCommand { Pid = pid, Analysis = analysis, Generation = generation }))
                _log.Info($"pid {pid}: image analysis discarded; control queue full");
        });
    }

    private void ScheduleMemoryScan(int pid, long generation)
    {
        EnqueueScan(() =>
        {
            IReadOnlyList<string> hits;
            try { hits = _scanner.Scan(pid); }
            catch { return; }
            if (hits.Count > 0 && !TryPost(new MemScanResultCommand { Pid = pid, Hits = hits, Generation = generation }))
                _log.Info($"pid {pid}: memory scan hits discarded; control queue full");
        });
    }

    private static void FailCommand(Command cmd)
    {
        switch (cmd)
        {
            case ListCommand lc: lc.Result.TrySetResult(Array.Empty<ProfileSnapshot>()); break;
            case ActionCommand ac: ac.Result.TrySetResult(ActionResult.Fail("engine error")); break;
            case KillDoneCommand kd: kd.Result.TrySetResult(ActionResult.Fail("engine error")); break;
            case QueryCommand qc: qc.Result.TrySetResult(null); break;
        }
    }

    private void OnVerdict(DetectionResult verdict)
    {
        if (verdict.Verdict == Verdict.Warn)
        {
            Metrics.IncDetections("WARN");
            _log.Warn(verdict);
            return;
        }

        Metrics.IncDetections("QUARANTINE");
        _log.Quarantine(verdict);

        var snap = verdict.Snapshot;
        var decision = _playbook.Decide(snap);
        var actions = new List<PlaybookAction>(decision.Actions);
        string matched = decision.MatchedRule;

        // The seam this used to fall through. A watchlist conviction reaches here as a
        // Quarantine verdict at score 0 with ContainmentRequired set. The playbook only
        // sees score and trust, so no rule matched, the action list was empty, and the
        // process the operator had named by hand was never frozen -- while its profile
        // sat marked Contained. Operator policy is not subject to the playbook's filters:
        // it gets the containment primitives unconditionally, and the playbook may still
        // ADD triage, isolation or notification on top.
        if (snap.ContainmentRequired)
        {
            if (!actions.Contains(PlaybookAction.Suspend)) actions.Insert(0, PlaybookAction.Suspend);
            if (!actions.Contains(PlaybookAction.FirewallBlock)) actions.Add(PlaybookAction.FirewallBlock);
            matched = matched.Length == 0 ? "watchlist:" + snap.ForcedBy : matched + " + watchlist:" + snap.ForcedBy;
        }

        if (actions.Count == 0)
        {
            // The playbook chose not to contain a behavioural verdict. Say so plainly:
            // Contained stays set (it gates the incident-update path) but nothing froze.
            _log.Action($"pid {snap.Pid}: playbook '{matched}' selected no containment action; " +
                        "the process is NOT frozen (verdict recorded, incident updates continue)");
            return;
        }
        _log.Action($"pid {snap.Pid}: playbook '{matched}' -> " + string.Join(", ", actions));

        // Suspend runs inline on the owner thread, exactly as it did in v1: freezing the
        // target first is what makes every later step safe against PID reuse. Everything
        // slower is handed to the response worker.
        bool alreadySuspended = false;
        if (actions.Contains(PlaybookAction.Suspend))
        {
            // Identity-checked: the pid must still belong to the process the verdict was
            // about. Between the verdict and this call the pid can be recycled, and a
            // suspend by number alone would freeze whatever now runs under it.
            var suspend = ResponseManager.SuspendProcess(snap.Pid, snap.ProcessName);
            alreadySuspended = suspend.Ok;
            _engine.SetSuspendedByAnalyst(snap.Pid, suspend.Ok);
            _log.Action(suspend.Ok
                ? $"pid {snap.Pid} suspended"
                : $"pid {snap.Pid} suspend failed: {suspend.Message}");
            // Contained is set the moment the Quarantine verdict is emitted, i.e. before
            // containment is attempted. If the freeze failed (access denied, a protected
            // process) the process is NOT contained, and leaving the flag set would
            // downgrade every later Quarantine for this pid to log-only -- it could never
            // be contained again. Clear it so fresh evidence can re-escalate.
            if (!suspend.Ok) _engine.MarkContainmentFailed(snap.Pid);
        }

        bool firewall = actions.Contains(PlaybookAction.FirewallBlock);
        bool quarantineFiles = actions.Contains(PlaybookAction.QuarantineFiles);
        bool kill = _autoKill || actions.Contains(PlaybookAction.Kill);

        // The playbook's action list is ORDERED, and that order carries a real guarantee:
        // triage (and host isolation) are collected before anything destructive runs. The
        // host implements firewall/quarantine/kill as one Contain() call, so the actions it
        // delegates are split at the ordered Kill: everything the playbook placed before it
        // runs BEFORE Contain, everything after it runs after. Running them all afterwards
        // meant CollectTriage packaged a process that had already been killed. When no Kill
        // is ordered but auto-kill is on, Contain still kills, so every delegated action
        // runs first.
        int destructiveAt = actions.Count;
        for (int i = 0; i < actions.Count; i++)
        {
            if (actions[i] != PlaybookAction.Kill) continue;
            destructiveAt = i;
            break;
        }

        var beforeContain = new List<PlaybookAction>();
        var afterContain = new List<PlaybookAction>();
        for (int i = 0; i < actions.Count; i++)
        {
            var a = actions[i];
            if (a is not (PlaybookAction.IsolateHost or PlaybookAction.CollectTriage or PlaybookAction.NotifyWebhook))
                continue;
            (i < destructiveAt ? beforeContain : afterContain).Add(a);
        }
        var extendedAction = ExtendedAction;

        bool queued = EnqueueResponse(() =>
        {
            RunExtendedActions(beforeContain, snap, extendedAction);
            _response.Contain(snap, alreadySuspended, kill, firewall, quarantineFiles);
            RunExtendedActions(afterContain, snap, extendedAction);
        });
        if (!queued)
        {
            // The response queue was full, so firewall/quarantine/kill never ran -- and the
            // suspend, if it happened, is the only containment this process got. Do not
            // leave it marked Contained on the strength of a task that was discarded: clear
            // the flag so fresh evidence re-escalates and the containment is retried.
            _engine.MarkContainmentFailed(snap.Pid);
            _log.Action($"pid {snap.Pid}: containment task DROPPED (response queue full); " +
                        (alreadySuspended ? "process is suspended but not firewalled/quarantined; " : "process is NOT contained; ") +
                        "it will be re-evaluated on its next signal");
        }
    }

    /// <summary>
    /// Runs delegated playbook actions in order on the response worker. A handler that
    /// throws is logged and skipped so one bad sink cannot abort the rest of the response.
    /// </summary>
    private void RunExtendedActions(IReadOnlyList<PlaybookAction> actions, ProfileSnapshot snap,
        Action<PlaybookAction, ProfileSnapshot>? handler)
    {
        if (handler is null || actions.Count == 0) return;
        foreach (var a in actions)
        {
            try { handler(a, snap); }
            catch (Exception ex) { _log.Error($"playbook action {a}", ex); }
        }
    }

    private ActionResult ExecuteAction(ActionKind kind, int pid)
    {
        switch (kind)
        {
            case ActionKind.Info:
            {
                var snap = _engine.SnapshotOne(pid);
                return snap is null
                    ? ActionResult.Fail($"no tracked process with pid {pid}")
                    : ActionResult.Success(RenderInfo(snap));
            }
            case ActionKind.Resume:
            {
                // The console advertises resume as "release a false positive", so it has to
                // undo BOTH halves of containment. Un-suspending alone left the binary
                // permanently blocked by the outbound firewall rule with no route to remove
                // it -- the analyst got a running process that silently could not reach the
                // network, which looks exactly like the app being broken.
                var snap = _engine.SnapshotOne(pid);
                var r = ResponseManager.ResumeProcess(pid);
                if (r.Ok) _engine.SetSuspendedByAnalyst(pid, false);

                if (!string.IsNullOrEmpty(snap?.ImagePath))
                {
                    var unblock = ResponseManager.RemoveOutboundFirewallBlock(pid, snap!.ImagePath);
                    _log.Action(unblock.Ok
                        ? $"pid {pid}: {unblock.Message}"
                        : $"pid {pid}: firewall block NOT removed -- {unblock.Message}");
                    if (r.Ok && !unblock.Ok)
                        return ActionResult.Success(
                            r.Message + "; WARNING: the outbound firewall block could not be " +
                            "removed, so this binary still has no network access");
                }
                return r;
            }
            case ActionKind.Suspend:
            {
                // NtSuspendProcess is COUNTED, but we model suspension as a boolean and a
                // single Resume issues one NtResumeProcess. A redundant suspend would then
                // need two resumes to thaw. Skip if this profile is already suspended so
                // "SuspendedByAnalyst==true" stays 1:1 with one outstanding OS suspend.
                var snap = _engine.SnapshotOne(pid);
                if (snap is not null && snap.SuspendedByAnalyst)
                    return ActionResult.Success($"pid {pid} already suspended");
                var r = ResponseManager.SuspendProcess(pid);
                if (r.Ok) _engine.SetSuspendedByAnalyst(pid, true);
                return r;
            }
            // ActionKind.Kill is handled asynchronously in DispatchAction (offloaded to
            // the response worker), so it never reaches here.
            default:
                return ActionResult.Fail("unknown action");
        }
    }

    private static string RenderInfo(ProfileSnapshot s)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"pid {s.Pid}  {s.ProcessName}  score={s.Score}");
        sb.AppendLine($"  trusted={s.Trusted} contained={s.Contained} " +
                      $"suspended={s.SuspendedByAnalyst} terminated={s.Terminated}");
        sb.AppendLine($"  image: {s.ImagePath}");
        if (s.StagedArchives.Count > 0)
            sb.AppendLine("  staged: " + string.Join(", ", s.StagedArchives));
        sb.AppendLine("  reasons:");
        foreach (var r in s.Reasons) sb.AppendLine("    " + r);
        return sb.ToString().TrimEnd();
    }

    // --------------------------------------------------------- response thread

    /// <summary>
    /// Queues containment work on the priority response queue. A drop here means real
    /// containment was discarded, so it is counted in Metrics as a failed response (and in
    /// a dropped gauge) as well as in the local counter -- reporting zero failures while
    /// throwing containment away is worse than the backlog itself.
    /// </summary>
    private bool EnqueueResponse(Action work)
    {
        try
        {
            if (_responseQueue.TryAdd(work)) return true;
            Interlocked.Increment(ref _responseErrors);
            long dropped = Interlocked.Increment(ref _responsesDropped);
            Metrics.IncResponses(false);
            Metrics.SetGauge("response_containment_dropped", dropped);
            _log.Error("response backlog", new InvalidOperationException("queue full; dropped a containment task"));
            return false;
        }
        catch (InvalidOperationException) { return false; /* shutting down */ }
    }

    /// <summary>
    /// Queues a best-effort memory scan. This queue is the droppable one: losing a scan
    /// costs enrichment, never containment. Drops are counted and exposed rather than
    /// silently swallowed, so an operator can see the scanner falling behind.
    /// </summary>
    private bool EnqueueScan(Action work)
    {
        try
        {
            if (_scanQueue.TryAdd(work)) return true;
            long dropped = Interlocked.Increment(ref _scansDropped);
            Metrics.SetGauge("response_scans_dropped", dropped);
            return false;
        }
        catch (InvalidOperationException) { return false; /* shutting down */ }
    }

    // One worker owns both response queues, so containment steps still execute one at a
    // time in the order they were ordered. Containment is drained to empty before a scan
    // is even considered; TakeFromAny then blocks until either queue has work, and ends
    // the loop only when both are completed and empty (shutdown still drains what is
    // already queued).
    private void ResponseLoop()
    {
        var queues = new[] { _responseQueue, _scanQueue };
        try
        {
            while (true)
            {
                while (_responseQueue.TryTake(out var containment))
                    RunResponse(containment);

                Action? work;
                int idx;
                try { idx = BlockingCollection<Action>.TakeFromAny(queues, out work); }
                catch (Exception) { break; }   // a queue was completed/disposed during shutdown
                if (idx < 0 || work is null) break;
                RunResponse(work);
            }
        }
        catch (Exception ex) { _log.Error("response loop terminated", ex); }
    }

    private void RunResponse(Action work)
    {
        try { work(); Interlocked.Increment(ref _responsesRun); Metrics.IncResponses(true); }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _responseErrors);
            Metrics.IncResponses(false);
            _log.Error("response task", ex);
        }
    }

    private static void SafeDispose<T>(ref T? disposable) where T : class, IDisposable
    {
        try { disposable?.Dispose(); } catch { }
        disposable = null;
    }
}

/// <summary>
/// Lock-free counter snapshot for programmatic consumers. String-free so a UI can
/// format (and localise) the numbers itself instead of parsing <see cref="BruceHost.Stats"/>.
/// </summary>
public sealed record HostStats
{
    public long SignalsProcessed { get; init; }
    public long SignalsDropped { get; init; }
    public int SignalsQueued { get; init; }
    public long ResponsesRun { get; init; }
    public long ResponseErrors { get; init; }
    public long Warns { get; init; }
    public long Quarantines { get; init; }
    public double LatencyP95Ms { get; init; }
    public bool AutoKill { get; init; }
    public string Monitors { get; init; } = "";
}
