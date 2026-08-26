using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using ProcessShield.Api;
using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Hosting;
using ProcessShield.Gui.Services;
using ProcessShield.Telemetry;

namespace ProcessShield.Gui.ViewModels;

public sealed class MainViewModel : ViewModelBase, IDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly string _configPath;

    private Composition? _composition;
    private ShieldHost? _host;
    private DispatcherTimer? _timer;
    private int _refreshing;   // guards against overlapping refreshes
    private bool _started;     // Start() is one-shot even if the window reloads

    private DateTime _startedUtc;
    private long _lastSignals;          // for the events/sec estimate
    private DateTime _lastSignalsAtUtc;

    public ObservableCollection<ThreatRow> Threats { get; } = new();
    public ObservableCollection<EventRow> Events { get; } = new();
    /// <summary>Endpoints this host has actually been observed talking to.</summary>
    public ObservableCollection<SurfaceRow> Surface { get; } = new();
    /// <summary>ATT&amp;CK techniques the loaded rules cover, and what has been seen.</summary>
    public ObservableCollection<TechniqueRow> Techniques { get; } = new();
    public SettingsViewModel Settings { get; }

    /// <summary>Raised for tray balloons: (title, message). Fired on containment and monitor loss.</summary>
    public event Action<string, string>? AlertRaised;

    // Events held back while the feed is paused, flushed in arrival order on resume.
    private readonly List<ShieldEvent> _pendingWhilePaused = new();
    private const int FeedCap = 250;

    public MainViewModel(string configPath)
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        _configPath = configPath;
        Settings = new SettingsViewModel(configPath);

        ReleaseCommand = new RelayCommand(() => Act(p => _host!.Resume(p)), () => HasSelection && IsRunning);
        SuspendCommand = new RelayCommand(() => Act(p => _host!.Suspend(p)), () => HasSelection && IsRunning);
        EndCommand     = new RelayCommand(EndSelected,                      () => HasSelection && IsRunning);
        RefreshCommand = new RelayCommand(() => _ = RefreshAsync());
        ClearEventsCommand = new RelayCommand(ClearEvents);
        TogglePauseCommand = new RelayCommand(TogglePause);
        ExportEventsCommand = new RelayCommand(ExportEvents, () => Events.Count > 0);
        ExportSurfaceCommand = new RelayCommand(ExportSurface, () => Surface.Count > 0);
        CopyReportCommand = new RelayCommand(CopyReport, () => HasSelection);
        CopyPathCommand = new RelayCommand(CopyPath, () => HasSelection);
        OpenLocationCommand = new RelayCommand(OpenLocation,
            () => HasSelection && !string.IsNullOrEmpty(SelectedThreat?.ImagePath));
        OpenUrlCommand = new RelayCommandP(p => OpenUrl(p as string));
        CopyEventCommand = new RelayCommandP(p => CopyEvent(p as EventRow));
        SetEventFilterCommand = new RelayCommandP(p => EventFilter = p as string ?? "ALL");
        SelectTabCommand = new RelayCommandP(p =>
        {
            if (int.TryParse(p as string, out var i)) SelectedTabIndex = Math.Clamp(i, 0, 4);
        });

        // The default collection views are what the XAML binds to, so installing a
        // filter here filters every consumer without touching the source collections.
        _threatsView = CollectionViewSource.GetDefaultView(Threats);
        _threatsView.Filter = o => o is ThreatRow t && t.Matches(_threatSearch.Trim());
        _eventsView = CollectionViewSource.GetDefaultView(Events);
        _eventsView.Filter = o => o is EventRow r && EventPasses(r);
        _surfaceView = CollectionViewSource.GetDefaultView(Surface);
        _surfaceView.Filter = o => o is SurfaceRow s && SurfacePasses(s);
    }

    private readonly ICollectionView _threatsView;
    private readonly ICollectionView _eventsView;
    private readonly ICollectionView _surfaceView;

    // -------------------------------------------------------------- lifecycle
    public void Start()
    {
        if (_started) return;
        _started = true;
        try
        {
            _startedUtc = DateTime.UtcNow;
            _lastSignalsAtUtc = _startedUtc;

            var sink = new UiEventSink(OnEvent);
            _composition = Composition.Build(_configPath, sink);
            _host = _composition.Host;

            IsRunning = _host.Start();
            Monitors = _host.ActiveMonitors;

            try { Settings.LoadFrom(_composition.Config); }
            catch (Exception ex) { AppLog.Error("settings load", ex); }

            try
            {
                // Rule coverage is fixed until a reload, so compute it once here rather
                // than rebuilding the ATT&CK matrix on every 1.5 s refresh tick.
                _ruleCoverage = new RuleEngine(_composition.Rules).TechniqueCoverage();
                RuleCount = _composition.Rules.Rules.Count;
                IndicatorCount = _composition.Intel.Count;
                CoveredTechniqueCount = _ruleCoverage.Count;
            }
            catch (Exception ex) { AppLog.Error("rule coverage", ex); }

            if (!IsRunning)
            {
                SetProblem("No monitor could be started. Make sure ProcessShield is running as Administrator.");
                AlertRaised?.Invoke("Not monitoring", "No monitor could be started. Run as Administrator.");
            }
            else
            {
                ClearProblem();
                AppLog.Info("Engine started. Monitors: " + Monitors);
            }

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
            _timer.Tick += (_, _) => _ = RefreshAsync();
            _timer.Start();
            _ = RefreshAsync();
        }
        catch (Exception ex)
        {
            AppLog.Error("engine start", ex);
            IsRunning = false;
            SetProblem("ProcessShield could not start its engine: " + ex.Message);
        }
    }

    public void Dispose()
    {
        try { _timer?.Stop(); } catch (Exception ex) { AppLog.Error("timer stop", ex); }
        try { _composition?.Dispose(); } catch (Exception ex) { AppLog.Error("dispose", ex); }
    }

    // -------------------------------------------------------------- commands
    public ICommand ReleaseCommand { get; }
    public ICommand SuspendCommand { get; }
    public ICommand EndCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand ClearEventsCommand { get; }
    public ICommand TogglePauseCommand { get; }
    public ICommand ExportEventsCommand { get; }
    public ICommand ExportSurfaceCommand { get; }
    public ICommand CopyReportCommand { get; }
    public ICommand CopyPathCommand { get; }
    public ICommand OpenLocationCommand { get; }
    public ICommand OpenUrlCommand { get; }
    public ICommand CopyEventCommand { get; }
    public ICommand SetEventFilterCommand { get; }
    public ICommand SelectTabCommand { get; }

    private void EndSelected()
    {
        var row = SelectedThreat;
        if (row is null) return;
        try
        {
            var res = MessageBox.Show(
                $"End process pid {row.Pid} ({row.Name}) and its child tree?\nThis cannot be undone.",
                "Confirm end process", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (res == MessageBoxResult.Yes) Act(p => _host!.Kill(p));
        }
        catch (Exception ex) { AppLog.Error("confirm end", ex); }
    }

    private void Act(Func<int, ActionResult> action)
    {
        var row = SelectedThreat;
        var host = _host;
        if (row is null || host is null) return;
        int pid = row.Pid;

        _ = Task.Run(() =>
        {
            ActionResult r;
            try { r = action(pid); }
            catch (Exception ex) { AppLog.Error("action", ex); r = ActionResult.Fail(ex.Message); }

            _dispatcher.BeginInvoke(() =>
            {
                try
                {
                    LastMessage = r.Ok ? r.Message : "Error: " + r.Message;
                    _ = RefreshAsync();
                }
                catch (Exception ex) { AppLog.Error("action-continuation", ex); }
            });
        });
    }

    private void CopyReport()
    {
        var row = SelectedThreat;
        if (row is null) return;
        try { Clipboard.SetText(row.ToReport()); LastMessage = "Incident report copied."; }
        catch (Exception ex) { AppLog.Error("copy report", ex); LastMessage = "Clipboard is busy — try again."; }
    }

    private void CopyPath()
    {
        var row = SelectedThreat;
        if (row is null || string.IsNullOrEmpty(row.ImagePath)) return;
        try { Clipboard.SetText(row.ImagePath); LastMessage = "Image path copied."; }
        catch (Exception ex) { AppLog.Error("copy path", ex); LastMessage = "Clipboard is busy — try again."; }
    }

    private void OpenLocation()
    {
        var path = SelectedThreat?.ImagePath;
        if (string.IsNullOrEmpty(path)) return;
        try
        {
            if (File.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
            else
                LastMessage = "Image no longer exists on disk.";
        }
        catch (Exception ex) { AppLog.Error("open location", ex); LastMessage = "Could not open Explorer: " + ex.Message; }
    }

    private void CopyEvent(EventRow? row)
    {
        if (row is null) return;
        try { Clipboard.SetText(row.ToClipboardLine()); }
        catch (Exception ex) { AppLog.Error("copy event", ex); }
    }

    private static void OpenUrl(string? url)
    {
        // Only MITRE technique pages ever reach this; still, never shell out to an
        // arbitrary scheme from a row payload.
        if (string.IsNullOrEmpty(url) || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return;
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch (Exception ex) { AppLog.Error("open url", ex); }
    }

    // -------------------------------------------------------------- event feed
    private void OnEvent(ShieldEvent e)
    {
        try
        {
            _dispatcher.BeginInvoke(() =>
            {
                try
                {
                    if (e.Level == "QUARANTINE")
                        AlertRaised?.Invoke("Threat contained",
                            e.Pid > 0 ? $"pid {e.Pid} {e.Process} — {(string.IsNullOrEmpty(e.Trigger) ? e.Message : e.Trigger)}" : e.Message);

                    if (IsPaused)
                    {
                        _pendingWhilePaused.Add(e);
                        // A paused feed must not hoard unbounded history; keep the newest.
                        if (_pendingWhilePaused.Count > FeedCap) _pendingWhilePaused.RemoveAt(0);
                        PendingCount = _pendingWhilePaused.Count;
                        return;
                    }
                    InsertEvent(e);
                }
                catch (Exception ex) { AppLog.Error("event insert", ex); }
            });
        }
        catch (Exception ex) { AppLog.Error("event dispatch", ex); }
    }

    private void InsertEvent(ShieldEvent e)
    {
        Events.Insert(0, new EventRow(e));
        BumpCount(e.Level, +1);
        while (Events.Count > FeedCap)
        {
            BumpCount(Events[^1].Level, -1);
            Events.RemoveAt(Events.Count - 1);
        }
    }

    private void ClearEvents()
    {
        try
        {
            Events.Clear();
            _pendingWhilePaused.Clear();
            PendingCount = 0;
            CountAll = CountQuarantine = CountWarn = CountAction = CountInfo = CountError = 0;
        }
        catch (Exception ex) { AppLog.Error("clear events", ex); }
    }

    private void TogglePause()
    {
        IsPaused = !IsPaused;
        if (!IsPaused)
        {
            foreach (var e in _pendingWhilePaused) InsertEvent(e);
            _pendingWhilePaused.Clear();
            PendingCount = 0;
        }
    }

    private void BumpCount(string level, int delta)
    {
        CountAll += delta;
        switch (level)
        {
            case "QUARANTINE": CountQuarantine += delta; break;
            case "WARN": CountWarn += delta; break;
            case "ACTION": CountAction += delta; break;
            case "ERROR": CountError += delta; break;
            default: CountInfo += delta; break;
        }
    }

    private bool EventPasses(EventRow r)
    {
        if (_eventFilter != "ALL" && !string.Equals(r.Level, _eventFilter, StringComparison.Ordinal))
            return false;
        var needle = _eventSearch.Trim();
        return needle.Length == 0 || r.SearchText.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    private bool SurfacePasses(SurfaceRow s)
    {
        if (OnlyBeaconing && !s.Beaconing) return false;
        var needle = _surfaceSearch.Trim();
        return needle.Length == 0
            || s.Endpoint.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || s.Process.Contains(needle, StringComparison.OrdinalIgnoreCase)
            || s.Address.Contains(needle, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------- export
    private void ExportEvents()
    {
        try
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export events (current filter)",
                FileName = $"processshield-events-{DateTime.Now:yyyyMMdd-HHmmss}",
                Filter = "CSV file (*.csv)|*.csv|JSON file (*.json)|*.json",
            };
            if (dlg.ShowDialog() != true) return;

            var rows = _eventsView.Cast<EventRow>().ToArray();
            if (dlg.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                var json = JsonSerializer.Serialize(rows.Select(r => r.Raw),
                    new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(dlg.FileName, json);
            }
            else
            {
                var sb = new StringBuilder();
                sb.AppendLine("time_utc,level,category,pid,process,score,trigger,message,techniques,rule_ids,incident_id");
                foreach (var r in rows)
                {
                    var e = r.Raw;
                    sb.AppendLine(string.Join(',',
                        e.TimeUtc.ToString("o", CultureInfo.InvariantCulture), Csv(e.Level), Csv(e.Category),
                        e.Pid.ToString(CultureInfo.InvariantCulture), Csv(e.Process),
                        e.Score.ToString(CultureInfo.InvariantCulture), Csv(e.Trigger), Csv(e.Message),
                        Csv(string.Join(';', e.Techniques)), Csv(string.Join(';', e.RuleIds)), Csv(e.IncidentId)));
                }
                File.WriteAllText(dlg.FileName, sb.ToString());
            }
            LastMessage = $"Exported {rows.Length} event(s).";
        }
        catch (Exception ex) { AppLog.Error("export events", ex); LastMessage = "Export failed: " + ex.Message; }
    }

    private void ExportSurface()
    {
        try
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title = "Export observed endpoints",
                FileName = $"processshield-surface-{DateTime.Now:yyyyMMdd-HHmmss}",
                Filter = "CSV file (*.csv)|*.csv",
            };
            if (dlg.ShowDialog() != true) return;

            var rows = _surfaceView.Cast<SurfaceRow>().ToArray();
            var sb = new StringBuilder();
            sb.AppendLine("pid,process,host,address,port,scheme,connections,beaconing,trusted,last_seen");
            foreach (var s in rows)
                sb.AppendLine(string.Join(',',
                    s.Pid.ToString(CultureInfo.InvariantCulture), Csv(s.Process), Csv(s.Host), Csv(s.Address),
                    s.Port.ToString(CultureInfo.InvariantCulture), Csv(s.Scheme),
                    s.Connections.ToString(CultureInfo.InvariantCulture),
                    s.Beaconing ? "true" : "false", s.Trusted ? "true" : "false", Csv(s.LastSeen)));
            File.WriteAllText(dlg.FileName, sb.ToString());
            LastMessage = $"Exported {rows.Length} endpoint(s).";
        }
        catch (Exception ex) { AppLog.Error("export surface", ex); LastMessage = "Export failed: " + ex.Message; }
    }

    private static string Csv(string s)
        => s.Contains(',') || s.Contains('"') || s.Contains('\n')
            ? "\"" + s.Replace("\"", "\"\"") + "\""
            : s;

    // -------------------------------------------------------------- refresh
    private async Task RefreshAsync()
    {
        var host = _host;
        if (host is null) return;
        if (Interlocked.Exchange(ref _refreshing, 1) == 1) return;   // skip if one is already running
        try
        {
            IReadOnlyList<ProfileSnapshot> snaps;
            try { snaps = await Task.Run(() => host.ListProfiles(onlyContained: false)); }
            catch (Exception ex) { AppLog.Error("list profiles", ex); return; }

            MergeThreats(snaps);

            IReadOnlyList<SurfaceEndpoint> endpoints;
            try { endpoints = await Task.Run(() => host.SurfaceEndpoints()); }
            catch (Exception ex) { AppLog.Error("surface", ex); endpoints = Array.Empty<SurfaceEndpoint>(); }
            MergeSurface(endpoints);
            MergeTechniques(host);

            ContainedCount = snaps.Count(s => s.Contained && !s.Terminated);
            FlaggedCount = snaps.Count;
            EndpointCount = endpoints.Count;
            BeaconCount = endpoints.Count(e => e.Beaconing);
            UpdateStats(host);

            if (!IsRunning)
            {
                StatusLevel = "threat";
                StatusText = "Not monitoring";
            }
            else
            {
                StatusLevel = snaps.Any(s => s.Contained && !s.Terminated) ? "threat"
                            : snaps.Count > 0 ? "watch"
                            : "none";
                StatusText = StatusLevel == "threat" ? "Threat contained"
                           : StatusLevel == "watch" ? "Watching activity"
                           : "All clear";
            }
        }
        catch (Exception ex) { AppLog.Error("refresh", ex); }
        finally { Interlocked.Exchange(ref _refreshing, 0); }
    }

    private void UpdateStats(ShieldHost host)
    {
        try
        {
            var s = host.StatsSnapshot();
            Throughput = host.Stats();

            var now = DateTime.UtcNow;
            var dt = (now - _lastSignalsAtUtc).TotalSeconds;
            if (dt >= 1)
            {
                var rate = (s.SignalsProcessed - _lastSignals) / dt;
                SignalRate = rate >= 100 ? $"{rate:F0}/s" : $"{rate:F1}/s";
                _lastSignals = s.SignalsProcessed;
                _lastSignalsAtUtc = now;
            }

            SignalsProcessed = s.SignalsProcessed.ToString("N0", CultureInfo.CurrentCulture);
            DroppedSignals = s.SignalsDropped;
            LatencyP95 = s.LatencyP95Ms >= 100 ? $"{s.LatencyP95Ms:F0} ms" : $"{s.LatencyP95Ms:F1} ms";

            var up = now - _startedUtc;
            Uptime = up.TotalHours >= 1 ? $"{(int)up.TotalHours}h {up.Minutes:D2}m"
                   : up.TotalMinutes >= 1 ? $"{up.Minutes}m {up.Seconds:D2}s"
                   : $"{up.Seconds}s";
        }
        catch (Exception ex) { AppLog.Error("stats", ex); }
    }

    private void MergeThreats(IReadOnlyList<ProfileSnapshot> snaps)
    {
        try
        {
            foreach (var s in snaps)
            {
                var row = Threats.FirstOrDefault(r => r.Pid == s.Pid);
                if (row is null) Threats.Add(new ThreatRow(s));
                else row.Update(s);
            }
            for (int i = Threats.Count - 1; i >= 0; i--)
                if (!snaps.Any(s => s.Pid == Threats[i].Pid))
                {
                    if (ReferenceEquals(Threats[i], SelectedThreat)) SelectedThreat = null;
                    Threats.RemoveAt(i);
                }
        }
        catch (Exception ex) { AppLog.Error("merge", ex); }
    }

    private void MergeSurface(IReadOnlyList<SurfaceEndpoint> endpoints)
    {
        try
        {
            // Beaconing first, then busiest: the row an analyst most needs stays at the top
            // instead of scrolling away as ordinary traffic accumulates.
            var ordered = endpoints
                .OrderByDescending(e => e.Beaconing)
                .ThenByDescending(e => e.Connections)
                .Take(300)
                .ToArray();

            foreach (var e in ordered)
            {
                var row = Surface.FirstOrDefault(r => r.Key == e.Key);
                if (row is null) Surface.Add(new SurfaceRow(e));
                else row.Update(e);
            }
            for (int i = Surface.Count - 1; i >= 0; i--)
                if (!ordered.Any(e => e.Key == Surface[i].Key))
                    Surface.RemoveAt(i);
        }
        catch (Exception ex) { AppLog.Error("merge surface", ex); }
    }

    private void MergeTechniques(ShieldHost host)
    {
        try
        {
            var observed = host.ObservedTechniques();
            var covered = _ruleCoverage;

            var ids = new SortedSet<string>(covered.Keys, StringComparer.OrdinalIgnoreCase);
            foreach (var id in observed.Keys) ids.Add(id);

            var rows = ids
                .Select(id => new TechniqueRow(id,
                    covered.TryGetValue(id, out var r) ? r : 0,
                    observed.TryGetValue(id, out var o) ? o : 0))
                .OrderBy(t => Array.IndexOf(AttackCatalog.Tactics, t.Tactic))
                .ThenByDescending(t => t.Observed)
                .ThenBy(t => t.Id, StringComparer.Ordinal)
                .ToArray();

            // The technique list is small and changes rarely, so a straight rebuild is
            // simpler than a diff and cheap enough at the 1.5 s refresh cadence.
            if (rows.Length == Techniques.Count &&
                rows.Zip(Techniques).All(p => p.First.Id == p.Second.Id && p.First.Observed == p.Second.Observed))
                return;

            Techniques.Clear();
            foreach (var t in rows) Techniques.Add(t);
            CoveredTechniqueCount = covered.Count;
            ObservedTechniqueCount = rows.Count(t => t.Observed > 0);
        }
        catch (Exception ex) { AppLog.Error("merge techniques", ex); }
    }

    // -------------------------------------------------------------- state
    private IReadOnlyDictionary<string, int> _ruleCoverage = new Dictionary<string, int>();
    private ThreatRow? _selected;
    public ThreatRow? SelectedThreat
    {
        get => _selected;
        set { if (Set(ref _selected, value)) { OnPropertyChanged(nameof(HasSelection)); CommandManager.InvalidateRequerySuggested(); } }
    }
    public bool HasSelection => _selected is not null;

    private bool _isRunning;
    public bool IsRunning { get => _isRunning; set { if (Set(ref _isRunning, value)) CommandManager.InvalidateRequerySuggested(); } }

    private string _monitors = "starting…";
    public string Monitors { get => _monitors; set => Set(ref _monitors, value); }

    private int _containedCount;
    public int ContainedCount { get => _containedCount; set => Set(ref _containedCount, value); }

    private int _flaggedCount;
    public int FlaggedCount { get => _flaggedCount; set => Set(ref _flaggedCount, value); }

    private int _endpointCount;
    public int EndpointCount { get => _endpointCount; set => Set(ref _endpointCount, value); }

    private int _beaconCount;
    public int BeaconCount { get => _beaconCount; set => Set(ref _beaconCount, value); }

    private int _ruleCount;
    public int RuleCount { get => _ruleCount; set => Set(ref _ruleCount, value); }

    private int _coveredTechniqueCount;
    public int CoveredTechniqueCount { get => _coveredTechniqueCount; set => Set(ref _coveredTechniqueCount, value); }

    private int _observedTechniqueCount;
    public int ObservedTechniqueCount { get => _observedTechniqueCount; set => Set(ref _observedTechniqueCount, value); }

    private int _indicatorCount;
    public int IndicatorCount { get => _indicatorCount; set => Set(ref _indicatorCount, value); }

    private string _throughput = "";
    public string Throughput { get => _throughput; set => Set(ref _throughput, value); }

    private string _statusText = "Starting…";
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    private string _statusLevel = "none";
    public string StatusLevel { get => _statusLevel; set => Set(ref _statusLevel, value); }

    private string _lastMessage = "";
    public string LastMessage { get => _lastMessage; set => Set(ref _lastMessage, value); }

    // ---- status bar ----
    private string _signalRate = "0/s";
    public string SignalRate { get => _signalRate; set => Set(ref _signalRate, value); }

    private string _signalsProcessed = "0";
    public string SignalsProcessed { get => _signalsProcessed; set => Set(ref _signalsProcessed, value); }

    private long _droppedSignals;
    public long DroppedSignals
    {
        get => _droppedSignals;
        set { if (Set(ref _droppedSignals, value)) OnPropertyChanged(nameof(HasDroppedSignals)); }
    }
    public bool HasDroppedSignals => _droppedSignals > 0;

    private string _latencyP95 = "—";
    public string LatencyP95 { get => _latencyP95; set => Set(ref _latencyP95, value); }

    private string _uptime = "0s";
    public string Uptime { get => _uptime; set => Set(ref _uptime, value); }

    // ---- feed filtering ----
    private bool _isPaused;
    public bool IsPaused
    {
        get => _isPaused;
        set { if (Set(ref _isPaused, value)) OnPropertyChanged(nameof(PauseLabel)); }
    }

    private int _pendingCount;
    public int PendingCount
    {
        get => _pendingCount;
        set { if (Set(ref _pendingCount, value)) OnPropertyChanged(nameof(PauseLabel)); }
    }

    public string PauseLabel => !IsPaused ? "Pause"
                              : PendingCount > 0 ? $"Resume ({PendingCount})"
                              : "Resume";

    private string _eventFilter = "ALL";
    public string EventFilter
    {
        get => _eventFilter;
        set { if (Set(ref _eventFilter, value)) _eventsView.Refresh(); }
    }

    private string _eventSearch = "";
    public string EventSearch
    {
        get => _eventSearch;
        set { if (Set(ref _eventSearch, value)) _eventsView.Refresh(); }
    }

    private string _threatSearch = "";
    public string ThreatSearch
    {
        get => _threatSearch;
        set { if (Set(ref _threatSearch, value)) _threatsView.Refresh(); }
    }

    private string _surfaceSearch = "";
    public string SurfaceSearch
    {
        get => _surfaceSearch;
        set { if (Set(ref _surfaceSearch, value)) _surfaceView.Refresh(); }
    }

    private bool _onlyBeaconing;
    public bool OnlyBeaconing
    {
        get => _onlyBeaconing;
        set { if (Set(ref _onlyBeaconing, value)) _surfaceView.Refresh(); }
    }

    // ---- severity chip counts ----
    private int _countAll;
    public int CountAll { get => _countAll; set => Set(ref _countAll, value); }
    private int _countQuarantine;
    public int CountQuarantine { get => _countQuarantine; set => Set(ref _countQuarantine, value); }
    private int _countWarn;
    public int CountWarn { get => _countWarn; set => Set(ref _countWarn, value); }
    private int _countAction;
    public int CountAction { get => _countAction; set => Set(ref _countAction, value); }
    private int _countInfo;
    public int CountInfo { get => _countInfo; set => Set(ref _countInfo, value); }
    private int _countError;
    public int CountError { get => _countError; set => Set(ref _countError, value); }

    private int _selectedTabIndex;
    public int SelectedTabIndex { get => _selectedTabIndex; set => Set(ref _selectedTabIndex, value); }

    // problem banner
    private bool _hasProblem;
    public bool HasProblem { get => _hasProblem; set => Set(ref _hasProblem, value); }

    private string _problemText = "";
    public string ProblemText { get => _problemText; set => Set(ref _problemText, value); }

    private void SetProblem(string message)
    {
        ProblemText = message;
        HasProblem = true;
        StatusText = "Not monitoring";
        StatusLevel = "threat";
    }

    private void ClearProblem()
    {
        HasProblem = false;
        ProblemText = "";
    }
}
