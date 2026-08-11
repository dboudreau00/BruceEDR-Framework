using System.Collections.ObjectModel;
using System.Windows;
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

    public ObservableCollection<ThreatRow> Threats { get; } = new();
    public ObservableCollection<EventRow> Events { get; } = new();
    /// <summary>Endpoints this host has actually been observed talking to.</summary>
    public ObservableCollection<SurfaceRow> Surface { get; } = new();
    /// <summary>ATT&amp;CK techniques the loaded rules cover, and what has been seen.</summary>
    public ObservableCollection<TechniqueRow> Techniques { get; } = new();
    public SettingsViewModel Settings { get; }

    public MainViewModel(string configPath)
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        _configPath = configPath;
        Settings = new SettingsViewModel(configPath);

        ReleaseCommand = new RelayCommand(() => Act(p => _host!.Resume(p)), () => HasSelection && IsRunning);
        SuspendCommand = new RelayCommand(() => Act(p => _host!.Suspend(p)), () => HasSelection && IsRunning);
        EndCommand     = new RelayCommand(EndSelected,                      () => HasSelection && IsRunning);
        RefreshCommand = new RelayCommand(() => _ = RefreshAsync());
        ClearEventsCommand = new RelayCommand(() => { try { Events.Clear(); } catch { } });
    }

    // -------------------------------------------------------------- lifecycle
    public void Start()
    {
        try
        {
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
                SetProblem("No monitor could be started. Make sure ProcessShield is running as Administrator.");
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

    // -------------------------------------------------------------- event feed
    private void OnEvent(ShieldEvent e)
    {
        try
        {
            _dispatcher.BeginInvoke(() =>
            {
                try
                {
                    Events.Insert(0, new EventRow(e));
                    while (Events.Count > 250) Events.RemoveAt(Events.Count - 1);
                }
                catch (Exception ex) { AppLog.Error("event insert", ex); }
            });
        }
        catch (Exception ex) { AppLog.Error("event dispatch", ex); }
    }

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
            Throughput = host.Stats();

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
                .OrderByDescending(t => t.Observed)
                .ThenBy(t => Array.IndexOf(AttackCatalog.Tactics, t.Tactic))
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

    private string _monitors = "starting\u2026";
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

    private int _indicatorCount;
    public int IndicatorCount { get => _indicatorCount; set => Set(ref _indicatorCount, value); }

    private string _throughput = "";
    public string Throughput { get => _throughput; set => Set(ref _throughput, value); }

    private string _statusText = "Starting\u2026";
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    private string _statusLevel = "none";
    public string StatusLevel { get => _statusLevel; set => Set(ref _statusLevel, value); }

    private string _lastMessage = "";
    public string LastMessage { get => _lastMessage; set => Set(ref _lastMessage, value); }

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
