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
using BruceEDR.Analysis;
using BruceEDR.Api;
using BruceEDR.Assistant;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Hosting;
using BruceEDR.Replay;
using BruceEDR.Gui.Services;
using BruceEDR.Telemetry;

namespace BruceEDR.Gui.ViewModels;

public sealed class MainViewModel : ViewModelBase, IDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly string _configPath;

    private Composition? _composition;
    private BruceHost? _host;
    private DispatcherTimer? _timer;
    private int _refreshing;   // guards against overlapping refreshes
    private bool _stopping;    // a Stop is disposing the previous engine off the UI thread
    private Task? _stopTask;

    private GeoIpDatabase _geo = GeoIpDatabase.Empty;

    private DateTime _startedUtc;
    private long _lastSignals;          // for the events/sec estimate
    private DateTime _lastSignalsAtUtc;

    private ReplaySession? _replay;
    private Func<DetectionConfig>? _detection;
    private readonly ActivityTimeline _timeline = new();
    private DateTime _timelinePublishedUtc;
    private readonly List<double> _rateSamples = new();
    private readonly DispatcherTimer _toastTimer;

    public ObservableCollection<ThreatRow> Threats { get; } = new();
    public ObservableCollection<EventRow> Events { get; } = new();
    /// <summary>Endpoints this host has actually been observed talking to.</summary>
    public ObservableCollection<SurfaceRow> Surface { get; } = new();
    /// <summary>ATT&amp;CK techniques the loaded rules cover, and what has been seen.</summary>
    public ObservableCollection<TechniqueRow> Techniques { get; } = new();
    /// <summary>Observed destinations aggregated by country, for the network map.</summary>
    public ObservableCollection<MapMarker> Markers { get; } = new();
    /// <summary>Traffic the map cannot place (local network, IPv6, unallocated space).</summary>
    public UnplacedGroup Unplaced { get; } = new();
    /// <summary>Simplified world outline. Empty when the asset is missing; the map still draws.</summary>
    public WorldMap World { get; private set; } = WorldMap.Empty;
    public SettingsViewModel Settings { get; }
    /// <summary>The set-up stage shown before anything is monitored.</summary>
    public SetupViewModel Setup { get; }
    /// <summary>Editor for the operator watchlist; writes the same config the engine reloads.</summary>
    public WatchlistViewModel WatchlistEditor { get; }
    /// <summary>Recorded detections, replayed as a scene and explained by the configured model.</summary>
    public TriageViewModel Triage { get; }
    public AssistantSettings Assistant { get; }

    /// <summary>Raised for tray balloons: (title, message). Fired on containment and monitor loss.</summary>
    public event Action<string, string>? AlertRaised;

    // Events held back while the feed is paused, flushed in arrival order on resume.
    private readonly List<BruceEvent> _pendingWhilePaused = new();
    private const int FeedCap = 250;

    public MainViewModel(string configPath, UiState? ui = null)
    {
        _dispatcher = Dispatcher.CurrentDispatcher;
        _configPath = configPath;
        Settings = new SettingsViewModel(configPath);
        WatchlistEditor = new WatchlistViewModel(configPath);
        Setup = new SetupViewModel(configPath);
        Setup.Load();
        Assistant = new AssistantSettings(ui, CreateKeyStore());
        Triage = new TriageViewModel(CreateTriageStore(), Assistant);
        Settings.AttachAssistant(Assistant);
        // Settings and the watchlist edit the config file, so they work before an engine
        // exists. Opening the window builds nothing and monitors nothing.
        try
        {
            var initial = ConfigLoader.Load(configPath);
            Settings.LoadFrom(initial);
            WatchlistEditor.LoadFrom(initial);
        }
        catch (Exception ex) { AppLog.Error("initial config load", ex); }

        StartCommand = new RelayCommand(StartFromSetup, () => !IsLive && !_stopping && !_starting && Setup.CanStart);
        StartReplayCommand = new RelayCommand(StartReplay,
            () => !IsLive && !_stopping && !_starting && Setup.CanStart && Setup.SelectedScenario is not null);
        SetCoverageModeCommand = new RelayCommandP(p => CoverageMode = p as string == "list" ? "list" : "matrix");
        StopCommand = new RelayCommand(StopEngine, () => IsLive);
        OpenSetupCommand = new RelayCommand(() => { Setup.Load(); IsSetupOpen = true; }, () => !IsLive);
        ReviewSettingsCommand = new RelayCommand(ReviewSettings);

        ReleaseCommand = new RelayCommand(() => Act(p => _host!.Resume(p)), () => HasSelection && IsRunning && !IsReplay);
        SuspendCommand = new RelayCommand(() => Act(p => _host!.Suspend(p)), () => HasSelection && IsRunning && !IsReplay);
        EndCommand     = new RelayCommand(EndSelected,                      () => HasSelection && IsRunning && !IsReplay);
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
            if (int.TryParse(p as string, out var i)) SelectedTabIndex = Math.Clamp(i, 0, TabCount - 1);
        });

        // The default collection views are what the XAML binds to, so installing a
        // filter here filters every consumer without touching the source collections.
        _threatsView = CollectionViewSource.GetDefaultView(Threats);
        _threatsView.Filter = o => o is ThreatRow t && t.Matches(_threatSearch.Trim());
        _eventsView = CollectionViewSource.GetDefaultView(Events);
        _eventsView.Filter = o => o is EventRow r && EventPasses(r);
        _surfaceView = CollectionViewSource.GetDefaultView(Surface);
        _surfaceView.Filter = o => o is SurfaceRow s && SurfacePasses(s);

        _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3.5) };
        _toastTimer.Tick += (_, _) => { _toastTimer.Stop(); ToastVisible = false; };

        // Coverage is a property of the rules, so it is shown before anything goes live.
        ApplyRuleCoverage(Setup.Rules, 0);
        MergeTechniques(null);
        PublishTimeline(force: true);
    }

    private static ApiKeyStore CreateKeyStore()
    {
        try { return new ApiKeyStore(AppPaths.KeyRoot); }
        catch (Exception ex)
        {
            AppLog.Error("key store", ex);
            return new ApiKeyStore(Path.Combine(Path.GetTempPath(), "BruceEDR-assistant"));
        }
    }

    private static TriageStore CreateTriageStore()
    {
        try { return new TriageStore(AppPaths.TriageRoot); }
        catch (Exception ex)
        {
            AppLog.Error("triage store", ex);
            return new TriageStore(Path.Combine(Path.GetTempPath(), "BruceEDR-triage"));
        }
    }

    /// <summary>Every flagged profile becomes (or refreshes) a library entry the analyst can replay later.</summary>
    private void CaptureIncidents(IReadOnlyList<ProfileSnapshot> snaps)
    {
        try
        {
            string source = IsReplay ? "Replay · " + ReplayName : "Live";
            foreach (var s in snaps)
                if ((s.Contained || s.Score >= WarnAt) && s.ReasonLog.Count > 0)
                    Triage.Upsert(IncidentCase.From(s, source, IsReplay, _startedUtc, ContainAt, IsMonitorOnly));
        }
        catch (Exception ex) { AppLog.Error("capture incidents", ex); }
    }

    private readonly ICollectionView _threatsView;
    private readonly ICollectionView _eventsView;
    private readonly ICollectionView _surfaceView;

    // -------------------------------------------------------------- lifecycle
    /// <summary>
    /// Builds the engine and goes live. Reached only through the Start button
    /// (<see cref="StartFromSetup"/>); opening the window never calls it.
    /// </summary>
    private async Task StartAsync()
    {
        if (_composition is not null || _stopping) return;

        // Building the engine and starting ETW can take seconds: keep the window responsive.
        ResetFeed();
        var sink = new UiEventSink(OnEvent);
        Composition? built = null;
        bool running;
        try
        {
            running = await Task.Run(() =>
            {
                built = Composition.Build(_configPath, sink);
                return built.Host.Start();
            });
        }
        catch (Exception ex)
        {
            AppLog.Error("engine start", ex);
            AbandonStart(built, "BruceEDR could not start its engine: " + ex.Message);
            return;
        }

        try
        {
            _startedUtc = DateTime.UtcNow;
            _lastSignalsAtUtc = _startedUtc;
            _lastSignals = 0;

            _composition = built!;
            _host = _composition.Host;
            var comp = _composition;
            _detection = () => comp.Config.Detection;
            IsLive = true;
            IsMonitorOnly = _host.MonitorOnly;

            IsRunning = running;
            Monitors = _host.ActiveMonitors;

            try { Settings.LoadFrom(_composition.Config); }
            catch (Exception ex) { AppLog.Error("settings load", ex); }

            try { WatchlistEditor.LoadFrom(_composition.Config); }
            catch (Exception ex) { AppLog.Error("watchlist load", ex); }

            ApplyRuleCoverage(_composition.Rules, _composition.Intel.Count);
            LoadGeo();

            if (!IsRunning)
            {
                // A live state that watches nothing is worse than none: go back to set-up.
                AbandonStart(_composition, "No monitor could be started. BruceEDR has to run as Administrator.");
                return;
            }
            ClearProblem();
            AppLog.Info("Engine started. Monitors: " + Monitors +
                        (IsMonitorOnly ? " (monitor mode)" : " (ENFORCE mode)"));

            StartRefreshTimer();
        }
        catch (Exception ex)
        {
            AppLog.Error("engine start", ex);
            AbandonStart(_composition, "BruceEDR could not start its engine: " + ex.Message);
        }
    }

    private void StartRefreshTimer()
    {
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
        _timer.Tick += (_, _) => _ = RefreshAsync();
        _timer.Start();
        _ = RefreshAsync();
    }

    /// <summary>Rule coverage is fixed until a reload, so it is computed once, not per refresh.</summary>
    private void ApplyRuleCoverage(RuleSet? rules, int indicators)
    {
        try
        {
            _ruleCoverage = rules is null ? new Dictionary<string, int>() : new RuleEngine(rules).TechniqueCoverage();
            RuleCount = rules?.Rules.Count ?? 0;
            IndicatorCount = indicators;
            CoveredTechniqueCount = _ruleCoverage.Count;
        }
        catch (Exception ex) { AppLog.Error("rule coverage", ex); }
    }

    /// <summary>Offline assets only: the map must never cause a network call.</summary>
    private void LoadGeo()
    {
        try
        {
            var geoDir = Path.Combine(AppContext.BaseDirectory, "intel", "geo");
            _geo = GeoIpDatabase.Load(geoDir, m => AppLog.Info("geo: " + m));
            World = WorldMap.Load(Path.Combine(geoDir, "world.txt"), m => AppLog.Info("geo: " + m));
            OnPropertyChanged(nameof(World));
            GeoReady = _geo.IsLoaded;
            // The Windows region setting stands in for "here": arcs start from it, and the map
            // says so. It is a convenience, never a measurement.
            var home = _geo.Country(RegionInfo.CurrentRegion.TwoLetterISORegionName);
            Home = home.CountryCode.Length > 0 ? new MapHome(home.CountryCode, home.Country, home.Latitude, home.Longitude) : null;
        }
        catch (Exception ex) { AppLog.Error("geo load", ex); }
    }

    private MapHome? _home;
    public MapHome? Home { get => _home; private set => Set(ref _home, value); }

    /// <summary>
    /// Plays a shipped trace through a real engine that watches nothing on this machine. The
    /// host runs in monitor mode with no monitors, and analyst actions stay off, because the
    /// pids in a trace are fiction that may collide with real processes here.
    /// </summary>
    private async void StartReplay()
    {
        var pick = Setup.SelectedScenario;
        if (IsLive || _stopping || _starting || pick is null) return;
        _starting = true;
        Setup.Message = "Starting the replay...";
        CommandManager.InvalidateRequerySuggested();
        // Reset before the session exists: its first events arrive while Start is still returning.
        ResetFeed();
        ReplaySession? session = null;
        try
        {
            var sink = new UiEventSink(OnEvent);
            session = await Task.Run(() => ReplaySession.Start(_configPath, pick.Path, sink));
        }
        catch (Exception ex)
        {
            AppLog.Error("replay start", ex);
            Setup.Message = "The replay could not start: " + ex.Message;
        }
        finally
        {
            _starting = false;
            CommandManager.InvalidateRequerySuggested();
        }
        if (session is null) return;

        try
        {
            _startedUtc = DateTime.UtcNow;
            _lastSignalsAtUtc = _startedUtc;
            _lastSignals = 0;

            _replay = session;
            _host = session.Host;
            _detection = () => session.Config.Detection;
            ReplayName = pick.Title;
            IsReplay = true;
            IsLive = true;
            IsMonitorOnly = true;
            IsRunning = true;
            Monitors = "none (replay)";
            ApplyRuleCoverage(session.Rules, session.Intel.Count);
            LoadGeo();
            ClearProblem();
            AppLog.Info($"Replay started: {pick.Name}");

            StartRefreshTimer();
            Setup.Message = "";
            IsSetupOpen = false;
            SelectedTabIndex = DashboardTabIndex;
        }
        catch (Exception ex)
        {
            AppLog.Error("replay start", ex);
            _replay = null;
            _host = null;
            IsReplay = false;
            IsLive = false;
            IsRunning = false;
            try { session.Dispose(); } catch (Exception dex) { AppLog.Error("replay dispose", dex); }
            Setup.Message = "The replay could not start: " + ex.Message;
        }
    }

    /// <summary>Tears down a half-started engine, off the UI thread, so a retry starts clean.</summary>
    private void AbandonStart(Composition? comp, string why)
    {
        _composition = null;
        _host = null;
        _detection = null;
        try { _timer?.Stop(); } catch (Exception ex) { AppLog.Error("timer stop", ex); }
        _timer = null;
        if (comp is not null)
        {
            _stopping = true;
            _stopTask = Task.Run(() =>
            {
                try { comp.Dispose(); }
                catch (Exception ex) { AppLog.Error("abandon start", ex); }
                _dispatcher.BeginInvoke(() =>
                {
                    _stopping = false;
                    CommandManager.InvalidateRequerySuggested();
                });
            });
        }
        IsRunning = false;
        IsLive = false;
        Monitors = "not started";
        ResetLiveViews();
        IsSetupOpen = true;
        Setup.Message = why;
        SetProblem(why);
    }

    private bool _starting;

    /// <summary>The Start button: save the set-up choices, confirm enforce mode, go live.</summary>
    private async void StartFromSetup()
    {
        if (IsLive || _stopping || _starting) return;
        Setup.Message = "";
        var problem = Setup.ValidateThresholds();
        if (problem is not null)
        {
            Setup.Message = "Not saved. " + problem;
            return;
        }
        if (Setup.Enforce && !SetupViewModel.ConfirmEnforceMode("Start in enforce mode")) return;
        if (!Setup.Save()) return;

        _starting = true;
        Setup.Message = "Starting...";
        CommandManager.InvalidateRequerySuggested();
        try { await StartAsync(); }
        catch (Exception ex) { AppLog.Error("start", ex); }      // async void: nothing may escape
        finally
        {
            _starting = false;
            CommandManager.InvalidateRequerySuggested();
        }
        if (!IsLive) return;
        Setup.Message = "";
        IsSetupOpen = false;
        SelectedTabIndex = DashboardTabIndex;
    }

    /// <summary>
    /// Stopping or closing never resumes what BruceEDR suspended, so a frozen process would
    /// stay frozen with nothing left to release it. Offer to resume those first. Returns
    /// false when the operator chooses to keep monitoring.
    /// </summary>
    public bool ConfirmLeavingFrozen(string title)
    {
        var host = _host;
        if (host is null) return true;
        List<ProfileSnapshot> frozen;
        try { frozen = host.ListProfiles(onlyContained: false).Where(p => p.SuspendedByAnalyst && !p.Terminated).ToList(); }
        catch (Exception ex) { AppLog.Error("list suspended", ex); return true; }
        if (frozen.Count == 0) return true;

        var answer = MessageBox.Show(
            $"BruceEDR has {frozen.Count} process(es) suspended, and stopping does not resume them.\n\n" +
            "Yes: resume them (and lift their firewall blocks), then stop.\n" +
            "No: stop and leave them suspended.\n" +
            "Cancel: keep monitoring.",
            title, MessageBoxButton.YesNoCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel);
        if (answer == MessageBoxResult.Cancel) return false;
        if (answer == MessageBoxResult.Yes)
        {
            foreach (var p in frozen)
            {
                var r = host.Resume(p.Pid);
                AppLog.Info($"resume pid {p.Pid} before stopping: {(r.Ok ? "ok" : r.Message)}");
            }
        }
        return true;
    }

    /// <summary>Clears what the previous engine showed, so a stopped app shows no stale state.</summary>
    private void ResetLiveViews()
    {
        try
        {
            SelectedThreat = null;
            Threats.Clear();
            Surface.Clear();
            Markers.Clear();
            ContainedCount = FlaggedCount = 0;
            EndpointCount = TotalEndpointCount = BeaconCount = 0;
            HiddenEndpointCount = PlaintextCount = MappedCount = 0;
            Unplaced.Set(0, 0);
            SignalRate = "0/s";
            SignalsProcessed = "0";
            LatencyP95 = "n/a";
            DroppedSignals = 0;
            Uptime = "0s";
            RateHistory = Array.Empty<double>();
            RuleCount = IndicatorCount = CoveredTechniqueCount = ObservedTechniqueCount = 0;
        }
        catch (Exception ex) { AppLog.Error("reset views", ex); }
    }

    /// <summary>Hands over from set-up to the full Settings tab without starting anything.</summary>
    private void ReviewSettings()
    {
        if (!IsLive && Setup.HasLoadError)
        {
            // Nothing can be saved over a broken file; Settings still offers "Open config file".
            IsSetupOpen = false;
            SelectedTabIndex = TabCount - 1;
            return;
        }
        if (!IsLive)
        {
            var problem = Setup.ValidateThresholds();
            if (problem is not null)
            {
                Setup.Message = "Not saved. " + problem;
                return;
            }
            // Saving here writes the mode too, so enforce gets the same confirmation as Start.
            if (Setup.Enforce && !Setup.EnforceOnDisk && !SetupViewModel.ConfirmEnforceMode("Turn on enforce mode"))
                Setup.Enforce = false;
            if (!Setup.Save()) return;
            try { Settings.LoadFrom(ConfigLoader.Load(_configPath)); }
            catch (Exception ex) { AppLog.Error("settings reload", ex); }
        }
        IsSetupOpen = false;
        SelectedTabIndex = TabCount - 1;
    }

    /// <summary>
    /// Stops monitoring and returns to set-up. Disposing the engine stops the ETW sessions
    /// and joins its threads, which can take a moment, so it runs off the UI thread.
    /// </summary>
    private void StopEngine()
    {
        IDisposable? comp = (IDisposable?)_composition ?? _replay;
        if (comp is null || _stopping) return;
        bool wasReplay = IsReplay;
        if (!wasReplay && !ConfirmLeavingFrozen("Stop monitoring")) return;
        _stopping = true;
        try { _timer?.Stop(); } catch (Exception ex) { AppLog.Error("timer stop", ex); }
        _timer = null;
        _composition = null;
        _replay = null;
        _host = null;
        _detection = null;
        IsRunning = false;
        IsReplay = false;
        IsLive = false;
        Monitors = "not started";
        ClearProblem();
        StatusLevel = "off";
        StatusText = "Not monitoring";
        ResetLiveViews();
        Setup.Load();
        ApplyRuleCoverage(Setup.Rules, 0);
        MergeTechniques(null);
        Setup.Message = wasReplay ? "Ending the replay..." : "Stopping...";
        IsSetupOpen = true;
        Triage.FlushSaves();

        _stopTask = Task.Run(() =>
        {
            try { comp.Dispose(); }
            catch (Exception ex) { AppLog.Error("engine stop", ex); }
            _dispatcher.BeginInvoke(() =>
            {
                _stopping = false;
                Setup.Message = wasReplay ? "Replay ended. Nothing is being monitored." : "Stopped. Nothing is being monitored.";
                AppLog.Info(wasReplay ? "Replay ended by the operator." : "Engine stopped by the operator.");
                CommandManager.InvalidateRequerySuggested();
            });
        });
    }

    public void Dispose()
    {
        try { _timer?.Stop(); } catch (Exception ex) { AppLog.Error("timer stop", ex); }
        // A Stop still in flight must finish, or its ETW sessions could outlive the app.
        try { _stopTask?.Wait(TimeSpan.FromSeconds(20)); } catch (Exception ex) { AppLog.Error("stop wait", ex); }
        try { _composition?.Dispose(); } catch (Exception ex) { AppLog.Error("dispose", ex); }
        try { _replay?.Dispose(); } catch (Exception ex) { AppLog.Error("dispose replay", ex); }
        try { Triage.CancelAll(); } catch (Exception ex) { AppLog.Error("triage shutdown", ex); }
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
    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand OpenSetupCommand { get; }
    public ICommand ReviewSettingsCommand { get; }
    public ICommand StartReplayCommand { get; }
    public ICommand SetCoverageModeCommand { get; }

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
        if (IsReplay)
        {
            LastMessage = "Actions are off during a replay. These processes are not on this machine.";
            return;
        }
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
        catch (Exception ex) { AppLog.Error("copy report", ex); LastMessage = "Clipboard is busy. Try again."; }
    }

    private void CopyPath()
    {
        var row = SelectedThreat;
        if (row is null || string.IsNullOrEmpty(row.ImagePath)) return;
        try { Clipboard.SetText(row.ImagePath); LastMessage = "Image path copied."; }
        catch (Exception ex) { AppLog.Error("copy path", ex); LastMessage = "Clipboard is busy. Try again."; }
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
        try { Clipboard.SetText(row.ToClipboardLine()); LastMessage = "Event copied."; }
        catch (Exception ex) { AppLog.Error("copy event", ex); LastMessage = "Clipboard is busy. Try again."; }
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
    private void OnEvent(BruceEvent e)
    {
        try
        {
            _dispatcher.BeginInvoke(() =>
            {
                try
                {
                    _timeline.Record(e.Level, e.TimeUtc);
                    TotalEvents++;
                    if (SelectedTabIndex != EventsTabIndex && e.Level is "QUARANTINE" or "WARN")
                    {
                        UnreadAlerts++;
                        if (e.Level == "QUARANTINE") UnreadLevel = "threat";
                    }
                    PublishTimeline(force: false);

                    // A replay's verdicts are about processes that are not on this machine.
                    if (e.Level == "QUARANTINE" && !IsReplay)
                        AlertRaised?.Invoke(IsMonitorOnly ? "Threat detected (monitor only)" : "Threat contained",
                            e.Pid > 0 ? $"pid {e.Pid} {e.Process}: {(string.IsNullOrEmpty(e.Trigger) ? e.Message : e.Trigger)}" : e.Message);

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

    private void InsertEvent(BruceEvent e)
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
            UnreadAlerts = 0;
            UnreadLevel = "watch";
        }
        catch (Exception ex) { AppLog.Error("clear events", ex); }
    }

    /// <summary>A new session starts with an empty feed, chart and counters.</summary>
    private void ResetFeed()
    {
        ClearEvents();
        _timeline.Clear();
        _rateSamples.Clear();
        RateHistory = Array.Empty<double>();
        TotalEvents = 0;
        ResetLiveViews();
        PublishTimeline(force: true);
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
                FileName = $"bruceedr-events-{DateTime.Now:yyyyMMdd-HHmmss}",
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
                FileName = $"bruceedr-surface-{DateTime.Now:yyyyMMdd-HHmmss}",
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
            if (!ReferenceEquals(host, _host)) return;   // stopped meanwhile: do not repaint stale state

            // Settings can switch the mode live, so follow the host rather than the start value.
            IsMonitorOnly = host.MonitorOnly;
            var detection = _detection?.Invoke();
            if (detection is not null)
            {
                WarnAt = detection.WarnThreshold;
                ContainAt = detection.QuarantineThreshold;
            }
            MergeThreats(snaps);
            CaptureIncidents(snaps);

            IReadOnlyList<SurfaceEndpoint> endpoints;
            try { endpoints = await Task.Run(() => host.SurfaceEndpoints()); }
            catch (Exception ex) { AppLog.Error("surface", ex); endpoints = Array.Empty<SurfaceEndpoint>(); }
            if (!ReferenceEquals(host, _host)) return;
            MergeSurface(endpoints);
            MergeTechniques(host);

            // Real containment and what monitor mode only reported are counted apart: after a
            // switch to enforce, a skipped one must never be shown as contained.
            int contained = snaps.Count(s => s.Contained && !s.Terminated && !s.ContainmentSkipped);
            int wouldContain = snaps.Count(s => s.Contained && !s.Terminated && s.ContainmentSkipped);
            ContainedCount = IsMonitorOnly ? wouldContain : contained;
            FlaggedCount = snaps.Count;
            // Counts what is actually on screen, so the header, the map and the tray agree.
            // TotalEndpointCount keeps the true figure.
            EndpointCount = Math.Min(endpoints.Count, SurfaceDisplayCap);
            TotalEndpointCount = endpoints.Count;
            BeaconCount = endpoints.Count(e => e.Beaconing);
            PlaintextCount = Surface.Count(r => r.IsPlaintext);
            UpdateStats(host);
            UpdateReplayProgress();
            PublishTimeline(force: true);

            if (!IsRunning)
            {
                StatusLevel = "off";
                StatusText = "Not monitoring";
            }
            else
            {
                StatusLevel = contained + wouldContain > 0 ? "threat"
                            : snaps.Count > 0 ? "watch"
                            : "none";
                StatusText = StatusLevel == "threat" ? (contained > 0 ? "Threat contained" : "Threat detected")
                           : StatusLevel == "watch" ? "Watching activity"
                           : "All clear";
                RaiseBadges();
            }
        }
        catch (Exception ex) { AppLog.Error("refresh", ex); }
        finally { Interlocked.Exchange(ref _refreshing, 0); }
    }

    private void UpdateStats(BruceHost host)
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
                _rateSamples.Add(Math.Max(0, rate));
                if (_rateSamples.Count > 40) _rateSamples.RemoveAt(0);
                RateHistory = _rateSamples.ToArray();
            }

            SignalsProcessed = s.SignalsProcessed.ToString("N0", CultureInfo.CurrentCulture);
            DroppedSignals = s.SignalsDropped;
            LatencyP95 = s.LatencyP95Ms >= 100 ? $"{s.LatencyP95Ms:F0} ms" : $"{s.LatencyP95Ms:F1} ms";

            var up = now - _startedUtc;
            Uptime = up.TotalHours >= 1 ? $"{(int)up.TotalHours}h {up.Minutes:D2}m"
                   : up.TotalMinutes >= 1 ? $"{up.Minutes}m {up.Seconds:D2}s"
                   : $"{up.Seconds}s";
            RaiseRail();
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
                if (row is null) Threats.Add(new ThreatRow(s, ContainAt));
                else row.Update(s, ContainAt);
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
                .Take(SurfaceDisplayCap)
                .ToArray();

            // The cap is a display bound, not a measurement. Anything it drops is reported
            // rather than silently missing -- a destination absent from the map is exactly
            // what an analyst must not be misled about.
            HiddenEndpointCount = Math.Max(0, endpoints.Count - ordered.Length);

            foreach (var e in ordered)
            {
                var row = Surface.FirstOrDefault(r => r.Key == e.Key);
                if (row is null) Surface.Add(new SurfaceRow(e, _geo));
                else row.Update(e, _geo);
            }
            for (int i = Surface.Count - 1; i >= 0; i--)
                if (!ordered.Any(e => e.Key == Surface[i].Key))
                    Surface.RemoveAt(i);

            double busiest = Math.Max(1, Surface.Count == 0 ? 1 : Surface.Max(r => r.Connections));
            foreach (var r in Surface) r.Share = 100.0 * r.Connections / busiest;

            MergeMarkers();
        }
        catch (Exception ex) { AppLog.Error("merge surface", ex); }
    }

    /// <summary>
    /// Folds the observed endpoints into one marker per country. Markers are kept as stable
    /// objects across refreshes so a hover highlight survives the 1.5 s tick -- rebuilding
    /// the collection would drop the highlight out from under the analyst's cursor.
    /// </summary>
    private void MergeMarkers()
    {
        try
        {
            var placed = new Dictionary<string, List<SurfaceRow>>(StringComparer.OrdinalIgnoreCase);
            int local = 0, unknown = 0;

            foreach (var row in Surface)
            {
                if (row.Geo.IsPrivate) { local++; continue; }
                if (row.Geo.CountryCode.Length == 0) { unknown++; continue; }

                if (!placed.TryGetValue(row.Geo.CountryCode, out var bucket))
                    placed[row.Geo.CountryCode] = bucket = new List<SurfaceRow>();
                bucket.Add(row);
            }

            Unplaced.Set(local, unknown);

            foreach (var kv in placed)
            {
                var marker = Markers.FirstOrDefault(m => m.CountryCode == kv.Key);
                if (marker is null)
                {
                    var g = kv.Value[0].Geo;
                    marker = new MapMarker(g.CountryCode, g.Country, g.Latitude, g.Longitude);
                    Markers.Add(marker);
                }
                // Worst-first, so the tooltip's truncated list shows what matters.
                kv.Value.Sort((a, b) =>
                {
                    int s = Rank(b.Severity).CompareTo(Rank(a.Severity));
                    return s != 0 ? s : b.Connections.CompareTo(a.Connections);
                });
                marker.Update(kv.Value);
            }

            for (int i = Markers.Count - 1; i >= 0; i--)
                if (!placed.ContainsKey(Markers[i].CountryCode))
                    Markers.RemoveAt(i);

            MappedCount = placed.Count;
        }
        catch (Exception ex) { AppLog.Error("merge markers", ex); }
    }

    private static int Rank(string severity) => severity switch
    {
        "threat" => 2,
        "watch" => 1,
        _ => 0,
    };

    /// <summary>
    /// Highlights a marker and every endpoint row folded into it (or clears the highlight
    /// when <paramref name="marker"/> is null). This is the two-way hover link between the
    /// map and the endpoint list.
    /// </summary>
    public void HighlightMarker(MapMarker? marker)
    {
        try
        {
            foreach (var m in Markers) m.IsHighlighted = ReferenceEquals(m, marker);
            foreach (var r in Surface)
                r.IsHighlighted = marker is not null && marker.Endpoints.Contains(r);
            HoveredMarker = marker;
        }
        catch (Exception ex) { AppLog.Error("highlight marker", ex); }
    }

    /// <summary>Highlights the marker that owns an endpoint row, for hovering the list side.</summary>
    public void HighlightEndpoint(SurfaceRow? row)
    {
        try
        {
            if (row is null) { HighlightMarker(null); return; }
            var marker = Markers.FirstOrDefault(m => m.Endpoints.Contains(row));
            foreach (var m in Markers) m.IsHighlighted = ReferenceEquals(m, marker);
            foreach (var r in Surface) r.IsHighlighted = ReferenceEquals(r, row);
            HoveredMarker = marker;
        }
        catch (Exception ex) { AppLog.Error("highlight endpoint", ex); }
    }

    private void MergeTechniques(BruceHost? host)
    {
        try
        {
            var observed = host?.ObservedTechniques() ?? new Dictionary<string, int>();
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
            BuildMatrix(covered, observed);
        }
        catch (Exception ex) { AppLog.Error("merge techniques", ex); }
    }

    /// <summary>
    /// Every catalogued technique by tactic, so gaps show as plainly as coverage. Observed
    /// techniques the catalogue does not know still get a column rather than vanishing.
    /// </summary>
    private void BuildMatrix(IReadOnlyDictionary<string, int> covered, IReadOnlyDictionary<string, int> observed)
    {
        var byTactic = AttackCatalog.ByTactic();
        var columns = new List<TacticColumn>();
        foreach (var tactic in AttackCatalog.Tactics)
        {
            if (!byTactic.TryGetValue(tactic, out var list) || list.Count == 0) continue;
            columns.Add(new TacticColumn(tactic, list
                .Select(t => new MatrixCell(t.Id, t.Name, t.Url,
                    covered.TryGetValue(t.Id, out var r) ? r : 0,
                    observed.TryGetValue(t.Id, out var o) ? o : 0))
                .ToArray()));
        }
        var unknown = covered.Keys.Concat(observed.Keys)
            .Where(id => !AttackCatalog.IsKnown(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(id => new MatrixCell(id.ToUpperInvariant(), "(not in the bundled catalogue)", AttackCatalog.Lookup(id).Url,
                covered.TryGetValue(id, out var r) ? r : 0, observed.TryGetValue(id, out var o) ? o : 0))
            .ToArray();
        if (unknown.Length > 0) columns.Add(new TacticColumn("Other", unknown));
        TacticColumns = columns;
        CatalogTechniqueCount = columns.Sum(c => c.Cells.Count);
        CoveragePercent = CatalogTechniqueCount == 0 ? 0 : 100.0 * columns.Sum(c => c.Covered) / CatalogTechniqueCount;
    }

    private void PublishTimeline(bool force)
    {
        var now = DateTime.UtcNow;
        if (!force && now - _timelinePublishedUtc < TimeSpan.FromMilliseconds(400)) return;
        _timelinePublishedUtc = now;
        var buckets = _timeline.Snapshot(now);
        TimelineBuckets = buckets;
        EventHistory = buckets.Skip(buckets.Length - 40).Select(b => (double)b.Total).ToArray();
    }

    private void UpdateReplayProgress()
    {
        var r = _replay;
        if (r is null) return;
        ReplayProgress = r.Total == 0 ? 100 : 100.0 * r.Fed / r.Total;
        ReplayDetail = r.Completion.IsCompleted
            ? $"{ReplayName} · finished"
            : $"{ReplayName} · {r.Fed} of {r.Total}";
        ReplayFinished = r.Completion.IsCompleted;
    }

    private void RaiseRail()
    {
        OnPropertyChanged(nameof(RailStatus));
        OnPropertyChanged(nameof(RailDetail));
    }

    private void RaiseBadges()
    {
        OnPropertyChanged(nameof(DashboardBadgeLevel));
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
    public bool IsRunning
    {
        get => _isRunning;
        set { if (Set(ref _isRunning, value)) { CommandManager.InvalidateRequerySuggested(); RaiseRail(); } }
    }

    private bool _isReplay;
    /// <summary>True while a recorded trace drives the engine instead of this machine.</summary>
    public bool IsReplay
    {
        get => _isReplay;
        private set
        {
            if (!Set(ref _isReplay, value)) return;
            OnPropertyChanged(nameof(StopLabel));
            OnPropertyChanged(nameof(ActionsEnabled));
            RaiseRail();
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public bool ActionsEnabled => !_isReplay;
    public string StopLabel => _isReplay ? "End replay" : "Stop monitoring";

    private string _replayName = "";
    public string ReplayName { get => _replayName; private set => Set(ref _replayName, value); }

    private string _replayDetail = "";
    public string ReplayDetail { get => _replayDetail; private set { if (Set(ref _replayDetail, value)) RaiseRail(); } }

    private double _replayProgress;
    public double ReplayProgress { get => _replayProgress; private set => Set(ref _replayProgress, value); }

    private bool _replayFinished;
    public bool ReplayFinished { get => _replayFinished; private set => Set(ref _replayFinished, value); }

    public string RailStatus => _isReplay ? "Replay" : _isLive ? (_isRunning ? "Monitoring" : "Starting") : "Not monitoring";
    public string RailDetail => _isReplay ? _replayDetail
                              : _isLive ? $"{(_isMonitorOnly ? "monitor only" : "enforcing")} · up {_uptime}"
                              : "set-up open";

    // ---- charts ----
    private ActivityBucket[] _timelineBuckets = Array.Empty<ActivityBucket>();
    public ActivityBucket[] TimelineBuckets { get => _timelineBuckets; private set => Set(ref _timelineBuckets, value); }

    private double[] _eventHistory = Array.Empty<double>();
    public double[] EventHistory { get => _eventHistory; private set => Set(ref _eventHistory, value); }

    private double[] _rateHistory = Array.Empty<double>();
    public double[] RateHistory { get => _rateHistory; private set => Set(ref _rateHistory, value); }

    private long _totalEvents;
    /// <summary>Every event since start; the feed itself keeps only the newest few hundred.</summary>
    public long TotalEvents { get => _totalEvents; private set => Set(ref _totalEvents, value); }

    private int _warnAt = 40;
    public int WarnAt { get => _warnAt; private set => Set(ref _warnAt, value); }

    private int _containAt = 70;
    public int ContainAt { get => _containAt; private set => Set(ref _containAt, value); }

    // ---- nav badges ----
    public const int TriageTabIndex = 0;
    public const int DashboardTabIndex = 1;
    public const int EventsTabIndex = 2;

    private int _unreadAlerts;
    /// <summary>Warn and quarantine events that arrived while the feed was not on screen.</summary>
    public int UnreadAlerts { get => _unreadAlerts; private set => Set(ref _unreadAlerts, value); }

    private string _unreadLevel = "watch";
    public string UnreadLevel { get => _unreadLevel; private set => Set(ref _unreadLevel, value); }

    public string DashboardBadgeLevel => _containedCount > 0 ? "threat" : "watch";

    private int _plaintextCount;
    public int PlaintextCount { get => _plaintextCount; private set => Set(ref _plaintextCount, value); }

    // ---- coverage matrix ----
    private IReadOnlyList<TacticColumn> _tacticColumns = Array.Empty<TacticColumn>();
    public IReadOnlyList<TacticColumn> TacticColumns { get => _tacticColumns; private set => Set(ref _tacticColumns, value); }

    private int _catalogTechniqueCount;
    public int CatalogTechniqueCount { get => _catalogTechniqueCount; private set => Set(ref _catalogTechniqueCount, value); }

    private double _coveragePercent;
    public double CoveragePercent
    {
        get => _coveragePercent;
        private set { if (Set(ref _coveragePercent, value)) OnPropertyChanged(nameof(CoveragePercentRounded)); }
    }
    public int CoveragePercentRounded => (int)Math.Round(_coveragePercent);

    private string _coverageMode = "matrix";
    public string CoverageMode
    {
        get => _coverageMode;
        set { if (Set(ref _coverageMode, value)) OnPropertyChanged(nameof(IsMatrixMode)); }
    }
    public bool IsMatrixMode => _coverageMode == "matrix";

    // ---- toast ----
    private string _toastText = "";
    public string ToastText { get => _toastText; private set => Set(ref _toastText, value); }

    private bool _toastVisible;
    public bool ToastVisible { get => _toastVisible; private set => Set(ref _toastVisible, value); }

    private bool _toastIsError;
    public bool ToastIsError { get => _toastIsError; private set => Set(ref _toastIsError, value); }

    private bool _isLive;
    /// <summary>True while an engine exists, between Start and Stop.</summary>
    public bool IsLive
    {
        get => _isLive;
        private set
        {
            if (!Set(ref _isLive, value)) return;
            OnPropertyChanged(nameof(ShowSetup));
            OnPropertyChanged(nameof(ShowStartPrompt));
            OnPropertyChanged(nameof(TabsEnabled));
            RaiseRail();
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private bool _isSetupOpen = true;
    public bool IsSetupOpen
    {
        get => _isSetupOpen;
        set
        {
            if (!Set(ref _isSetupOpen, value)) return;
            OnPropertyChanged(nameof(ShowSetup));
            OnPropertyChanged(nameof(ShowStartPrompt));
            OnPropertyChanged(nameof(TabsEnabled));
        }
    }
    /// <summary>The tabs under the set-up panel must not be reachable by keyboard or screen reader.</summary>
    public bool TabsEnabled => !ShowSetup;
    /// <summary>The set-up and start screen covers the app whenever nothing is live.</summary>
    public bool ShowSetup => !_isLive && _isSetupOpen;
    /// <summary>Not live while the operator browses settings: offer the way back to Start.</summary>
    public bool ShowStartPrompt => !_isLive && !_isSetupOpen;

    private bool _isMonitorOnly = true;
    public bool IsMonitorOnly
    {
        get => _isMonitorOnly;
        private set
        {
            if (!Set(ref _isMonitorOnly, value)) return;
            OnPropertyChanged(nameof(ModeText));
            OnPropertyChanged(nameof(ContainedLabel));
            RaiseRail();
        }
    }
    public string ModeText => _isMonitorOnly ? "MONITOR ONLY" : "ENFORCING";

    private static readonly string s_appVersion = FormatVersion(typeof(MainViewModel).Assembly.GetName().Version);
    /// <summary>Product version for the sidebar, from the assembly (set once in Directory.Build.props).</summary>
    public string AppVersion => s_appVersion;

    private static string FormatVersion(Version? v) => v is null ? "" : $"v{v.Major}.{v.Minor}.{Math.Max(v.Build, 0)}";
    public string ContainedLabel => _isMonitorOnly ? "WOULD CONTAIN" : "CONTAINED";

    private string _monitors = "not started";
    public string Monitors { get => _monitors; set => Set(ref _monitors, value); }

    private int _containedCount;
    public int ContainedCount { get => _containedCount; set { if (Set(ref _containedCount, value)) OnPropertyChanged(nameof(DashboardBadgeLevel)); } }

    private int _flaggedCount;
    public int FlaggedCount { get => _flaggedCount; set => Set(ref _flaggedCount, value); }

    /// <summary>Most rows the surface table and map will hold, so a busy host cannot flood the UI.</summary>
    public const int SurfaceDisplayCap = 300;

    private int _endpointCount;
    /// <summary>Endpoints currently displayed (capped at <see cref="SurfaceDisplayCap"/>).</summary>
    public int EndpointCount { get => _endpointCount; set => Set(ref _endpointCount, value); }

    private int _totalEndpointCount;
    /// <summary>Every endpoint observed, including those the display cap hides.</summary>
    public int TotalEndpointCount { get => _totalEndpointCount; set => Set(ref _totalEndpointCount, value); }

    private int _hiddenEndpointCount;
    public int HiddenEndpointCount
    {
        get => _hiddenEndpointCount;
        set { if (Set(ref _hiddenEndpointCount, value)) OnPropertyChanged(nameof(HasHiddenEndpoints)); }
    }
    public bool HasHiddenEndpoints => _hiddenEndpointCount > 0;

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

    private string _statusText = "Not monitoring";
    public string StatusText { get => _statusText; set => Set(ref _statusText, value); }

    private string _statusLevel = "off";   // off (nothing live) | none (all clear) | watch | threat
    public string StatusLevel { get => _statusLevel; set => Set(ref _statusLevel, value); }

    private string _lastMessage = "";
    /// <summary>Outcome of the last analyst action; shown as a toast.</summary>
    public string LastMessage
    {
        get => _lastMessage;
        set
        {
            if (!Set(ref _lastMessage, value) || string.IsNullOrEmpty(value)) return;
            ToastText = value;
            ToastIsError = value.StartsWith("Error", StringComparison.OrdinalIgnoreCase)
                        || value.Contains("failed", StringComparison.OrdinalIgnoreCase)
                        || value.StartsWith("Could not", StringComparison.OrdinalIgnoreCase)
                        || value.Contains("no longer exists", StringComparison.OrdinalIgnoreCase)
                        || value.StartsWith("Clipboard is busy", StringComparison.OrdinalIgnoreCase)
                        || value.StartsWith("Actions are off", StringComparison.OrdinalIgnoreCase);
            ToastVisible = true;
            _toastTimer.Stop();
            _toastTimer.Start();
        }
    }

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

    private string _latencyP95 = "n/a";
    public string LatencyP95 { get => _latencyP95; set => Set(ref _latencyP95, value); }

    private string _uptime = "0s";
    public string Uptime { get => _uptime; set { if (Set(ref _uptime, value)) RaiseRail(); } }

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

    // ---- network map ----
    private bool _geoReady;
    /// <summary>False when the offline geo table is missing; the view says so instead of lying.</summary>
    public bool GeoReady
    {
        get => _geoReady;
        set { if (Set(ref _geoReady, value)) OnPropertyChanged(nameof(GeoMissing)); }
    }
    public bool GeoMissing => !_geoReady;

    private int _mappedCount;
    /// <summary>Distinct countries currently plotted.</summary>
    public int MappedCount { get => _mappedCount; set => Set(ref _mappedCount, value); }

    private MapMarker? _hoveredMarker;
    public MapMarker? HoveredMarker
    {
        get => _hoveredMarker;
        set { if (Set(ref _hoveredMarker, value)) OnPropertyChanged(nameof(HasHoveredMarker)); }
    }
    public bool HasHoveredMarker => _hoveredMarker is not null;

    /// <summary>Number of nav items, so shortcut clamping and saved state agree with the XAML.</summary>
    public const int TabCount = 8;

    private int _selectedTabIndex;
    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set
        {
            if (!Set(ref _selectedTabIndex, value)) return;
            if (value == EventsTabIndex) { UnreadAlerts = 0; UnreadLevel = "watch"; }
        }
    }

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
