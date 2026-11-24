using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using BruceEDR.Configuration;
using BruceEDR.Detection;
using BruceEDR.Gui.Services;
using BruceEDR.Replay;
using BruceEDR.Security;

namespace BruceEDR.Gui.ViewModels;

/// <summary>A shipped replay trace offered on the set-up screen.</summary>
public sealed class ScenarioInfo
{
    public string Path { get; }
    public string Name { get; }
    public string Title { get; }
    public string Description { get; }
    public int Signals { get; }
    public TimeSpan Duration { get; }
    public bool IsBenign => Name.Contains("benign", StringComparison.OrdinalIgnoreCase);
    public string Kind => IsBenign ? "BENIGN" : "ATTACK";
    public string Facts => $"{Signals} signals · {FormatDuration(Duration)} recorded · plays in about " +
                           $"{FormatDuration(TimeSpan.FromSeconds(Duration.TotalSeconds / Hosting.ReplaySession.SpeedFor(Duration)))}";

    public ScenarioInfo(string path, string name, string description, int signals, TimeSpan duration)
    {
        Path = path;
        Name = name;
        Title = name.Length == 0 ? System.IO.Path.GetFileNameWithoutExtension(path)
              : char.ToUpperInvariant(name[0]) + name[1..].Replace('-', ' ');
        Description = description;
        Signals = signals;
        Duration = duration;
    }

    private static string FormatDuration(TimeSpan t)
        => t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes}m {t.Seconds:D2}s" : $"{Math.Max(1, (int)Math.Round(t.TotalSeconds))} s";
}

/// <summary>Clickable signing-authority chip discovered during the baseline scan.</summary>
public sealed class BaselinePublisherRow : ViewModelBase
{
    private readonly Action<BaselinePublisherRow> _onToggle;
    private bool _isTrusted;

    public BaselinePublisherRow(BaselinePublisher pub, bool isTrusted, Action<BaselinePublisherRow> onToggle)
    {
        Name = pub.Name;
        AdminInstalledCount = pub.AdminInstalledCount;
        TotalCount = pub.TotalCount;
        VerifiedAdminInstall = pub.VerifiedAdminInstall;
        _isTrusted = isTrusted;
        _onToggle = onToggle;
        TogglePublisherCommand = new RelayCommand(() => _onToggle(this));
    }

    public string Name { get; }
    public int AdminInstalledCount { get; }
    public int TotalCount { get; }
    public bool VerifiedAdminInstall { get; }

    public string ChipLabel => $"{Name} ({TotalCount})";
    public string ChipTooltip => VerifiedAdminInstall
        ? $"{Name}: {AdminInstalledCount} admin-installed binary(s), {TotalCount} total on this PC. Click to toggle in Trusted publishers."
        : $"{Name}: {TotalCount} user-space binary(s) on this PC. Click to toggle in Trusted publishers.";

    public bool IsTrusted
    {
        get => _isTrusted;
        internal set => Set(ref _isTrusted, value);
    }

    public ICommand TogglePublisherCommand { get; }
}

/// <summary>One discovered process or installed program offered for Trusted / Default / Untrusted selection.</summary>
public sealed class BaselineItemRow : ViewModelBase
{
    private readonly BaselineEntry _entry;
    private readonly Action _onChanged;
    private BaselineTrustChoice _choice;
    private BaselineTrustChoice _loadedChoice;

    public BaselineItemRow(BaselineEntry entry, BaselineTrustChoice initialChoice, Action onChanged)
    {
        _entry = entry;
        _choice = initialChoice;
        _loadedChoice = initialChoice;
        _onChanged = onChanged;

        SetTrustedCommand = new RelayCommand(() => Choice = Choice == BaselineTrustChoice.Trusted ? BaselineTrustChoice.Default : BaselineTrustChoice.Trusted);
        SetDefaultCommand = new RelayCommand(() => Choice = BaselineTrustChoice.Default);
        SetUntrustedCommand = new RelayCommand(
            () => { if (CanMarkUntrusted) Choice = Choice == BaselineTrustChoice.Untrusted ? BaselineTrustChoice.Default : BaselineTrustChoice.Untrusted; },
            () => CanMarkUntrusted);
    }

    internal BaselineEntry Entry => _entry;
    internal BaselineTrustChoice LoadedChoice => _loadedChoice;
    internal void CommitLoadedChoice() => _loadedChoice = _choice;

    public string DisplayName => _entry.DisplayName;
    public string ProcessName => _entry.ProcessName;
    public string ImagePath => _entry.ImagePath;
    public string SourceBadge => _entry.SourceBadge;
    public string TreeSummary => _entry.TreeSummary;
    public string SignatureSummary => _entry.SignatureSummary;
    public bool Signed => _entry.Signed;
    public bool IsRunning => _entry.IsRunning;
    public bool IsInstalledApp => _entry.IsInstalledApp;
    public bool ProtectedSystem => _entry.ProtectedSystem;
    public bool CanMarkUntrusted => !_entry.ProtectedSystem;

    public string UntrustedTooltip => _entry.ProtectedSystem
        ? "Core signed Windows system process; cannot be marked untrusted."
        : "Mark untrusted: adds a watchlist containment rule (reported in monitor mode, contained in enforce mode).";

    public BaselineTrustChoice Choice
    {
        get => _choice;
        set
        {
            if (value == BaselineTrustChoice.Untrusted && _entry.ProtectedSystem) return;
            if (!Set(ref _choice, value)) return;
            OnPropertyChanged(nameof(IsTrustedChoice));
            OnPropertyChanged(nameof(IsDefaultChoice));
            OnPropertyChanged(nameof(IsUntrustedChoice));
            _onChanged();
        }
    }

    public bool IsTrustedChoice => _choice == BaselineTrustChoice.Trusted;
    public bool IsDefaultChoice => _choice == BaselineTrustChoice.Default;
    public bool IsUntrustedChoice => _choice == BaselineTrustChoice.Untrusted;

    public bool Matches(string query, string filter)
    {
        bool passesFilter = filter switch
        {
            "RUNNING" => _entry.IsRunning,
            "APPS" => _entry.IsInstalledApp,
            "UNSIGNED" => !_entry.Signed,
            "MARKED" => _choice != BaselineTrustChoice.Default,
            _ => true
        };
        if (!passesFilter) return false;
        if (query.Length == 0) return true;

        return _entry.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || _entry.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || _entry.Publisher.Contains(query, StringComparison.OrdinalIgnoreCase)
            || _entry.ImagePath.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    public ICommand SetTrustedCommand { get; }
    public ICommand SetDefaultCommand { get; }
    public ICommand SetUntrustedCommand { get; }
}

/// <summary>
/// The set-up stage shown before the engine exists. It only reads and writes
/// bruce.config.json; nothing here can touch a process. Going live is a separate,
/// explicit Start on <see cref="MainViewModel"/>.
/// </summary>
public sealed class SetupViewModel : ViewModelBase
{
    private readonly string _configPath;
    private readonly Dispatcher _dispatcher;
    private readonly ICollectionView _baselineView;
    private UiState? _ui;
    private bool _syncingPublishers;

    public SetupViewModel(string configPath)
    {
        _configPath = configPath;
        _dispatcher = Dispatcher.CurrentDispatcher;

        ScanBaselineCommand = new RelayCommand(() => _ = ScanBaselineAsync(autoPrepopulatePublishers: false), () => !IsScanningBaseline && CanStart);
        TrustVerifiedPublishersCommand = new RelayCommand(TrustAllVerifiedPublishers, () => DiscoveredPublishers.Count > 0);
        TrustSignedAppsCommand = new RelayCommand(TrustSignedNonSystemApps, () => BaselineItems.Count > 0);
        ResetBaselineChoicesCommand = new RelayCommand(ResetBaselineChoices, () => TrustedItemCount > 0 || UntrustedItemCount > 0);
        SetBaselineFilterCommand = new RelayCommandP(p => BaselineFilter = (p as string) ?? "ALL");

        _baselineView = CollectionViewSource.GetDefaultView(BaselineItems);
        _baselineView.Filter = o => o is BaselineItemRow row && row.Matches(_baselineSearch.Trim(), _baselineFilter);
    }

    public string ConfigPath => _configPath;

    public ObservableCollection<BaselinePublisherRow> DiscoveredPublishers { get; } = new();
    public ObservableCollection<BaselineItemRow> BaselineItems { get; } = new();

    public ICommand ScanBaselineCommand { get; }
    public ICommand TrustVerifiedPublishersCommand { get; }
    public ICommand TrustSignedAppsCommand { get; }
    public ICommand ResetBaselineChoicesCommand { get; }
    public ICommand SetBaselineFilterCommand { get; }

    /// <summary>
    /// Attaches persisted UI state and automatically runs the initial process-tree + installed-apps
    /// scan in the background. On very first launch, verified admin-installed signing authorities
    /// are pre-populated into <see cref="Publishers"/> automatically.
    /// </summary>
    public void AttachUiState(UiState ui)
    {
        _ui = ui;
        bool firstStart = !ui.BaselineInitialized;
        _ = ScanBaselineAsync(autoPrepopulatePublishers: firstStart);
    }

    /// <summary>
    /// Re-reads the config from disk. A file that exists but cannot be parsed blocks Start,
    /// the same way the console refuses to start on a truncated config.
    /// </summary>
    public void Load()
    {
        if (Scenarios.Count == 0) LoadScenarios();
        DetectionConfig detection;
        WatchlistEntryConfig[] watchlistEntries;
        try
        {
            var c = ConfigLoader.Load(_configPath);
            Enforce = _loadedEnforce = c.Response.IsEnforcing;
            Publishers = _loadedPublishers = string.Join(Environment.NewLine, c.Allowlist.Publishers);
            WarnThreshold = _loadedWarn = c.Detection.WarnThreshold;
            QuarantineThreshold = _loadedQuarantine = c.Detection.QuarantineThreshold;
            detection = c.Detection;
            watchlistEntries = c.Watchlist.Entries ?? Array.Empty<WatchlistEntryConfig>();
            LoadError = "";
        }
        catch (Exception ex)
        {
            LoadError = "bruce.config.json could not be read: " + ex.Message;
            return;
        }

        // Refresh existing trust states if baseline items were already scanned.
        if (BaselineItems.Count > 0)
        {
            foreach (var item in BaselineItems)
            {
                var inferred = BaselineScanner.InferExistingChoice(item.Entry, watchlistEntries);
                item.Choice = inferred;
                item.CommitLoadedChoice();
            }
            UpdateBaselineSelectionCounts();
        }
        SyncPublisherChips();

        // A rules-folder problem is not a config problem: the engine starts without packs.
        try { DescribeRules(detection); }
        catch (Exception ex)
        {
            RulesMissing = true;
            RulesSummary = "The detection rules folder could not be read: " + ex.Message;
        }
    }

    public async Task ScanBaselineAsync(bool autoPrepopulatePublishers)
    {
        if (IsScanningBaseline) return;
        IsScanningBaseline = true;
        BaselineSummary = "Scanning running process tree, installed applications and digital signatures...";
        CommandManager.InvalidateRequerySuggested();

        try
        {
            var result = await Task.Run(() => BaselineScanner.Scan());
            WatchlistEntryConfig[] existingWatchlist = Array.Empty<WatchlistEntryConfig>();
            try { existingWatchlist = ConfigLoader.Load(_configPath).Watchlist.Entries ?? Array.Empty<WatchlistEntryConfig>(); }
            catch { }

            await _dispatcher.InvokeAsync(() => ApplyScanResult(result, existingWatchlist, autoPrepopulatePublishers));
        }
        catch (Exception ex)
        {
            AppLog.Error("baseline scan", ex);
            BaselineSummary = "Baseline scan could not complete: " + ex.Message;
        }
        finally
        {
            IsScanningBaseline = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    internal void ApplyScanResult(BaselineScanResult result, IReadOnlyList<WatchlistEntryConfig> existingWatchlist, bool autoPrepopulatePublishers)
    {
        if (autoPrepopulatePublishers)
        {
            MergeVerifiedPublishers(result.Publishers);
            if (_ui is not null && !_ui.BaselineInitialized)
            {
                _ui.BaselineInitialized = true;
                _ui.Save();
            }
        }

        var activePubs = new HashSet<string>(SplitLines(Publishers), StringComparer.OrdinalIgnoreCase);
        DiscoveredPublishers.Clear();
        foreach (var p in result.Publishers)
            DiscoveredPublishers.Add(new BaselinePublisherRow(p, activePubs.Contains(p.Name), TogglePublisherChip));

        BaselineItems.Clear();
        foreach (var entry in result.Entries)
        {
            var choice = BaselineScanner.InferExistingChoice(entry, existingWatchlist);
            BaselineItems.Add(new BaselineItemRow(entry, choice, OnBaselineItemChanged));
        }

        int unsignedCount = result.Entries.Count(e => !e.Signed);
        BaselineSummary = $"{result.Entries.Count} unique programs ({result.RunningProcessCount} live processes, " +
                          $"{result.InstalledAppCount} installed apps, {unsignedCount} unsigned) · " +
                          $"{result.Publishers.Count} signing authorit{(result.Publishers.Count == 1 ? "y" : "ies")}.";

        OnPropertyChanged(nameof(HasBaselineItems));
        OnPropertyChanged(nameof(HasDiscoveredPublishers));
        UpdateBaselineSelectionCounts();
        _baselineView.Refresh();
        CommandManager.InvalidateRequerySuggested();
    }

    private void MergeVerifiedPublishers(IReadOnlyList<BaselinePublisher> publishers)
    {
        var list = SplitLines(Publishers).ToList();
        var seen = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
        bool addedAny = false;

        foreach (var p in publishers)
        {
            if (!p.VerifiedAdminInstall) continue;
            if (seen.Add(p.Name))
            {
                list.Add(p.Name);
                addedAny = true;
            }
        }

        if (addedAny)
            Publishers = string.Join(Environment.NewLine, list);
    }

    private void TrustAllVerifiedPublishers()
    {
        var list = SplitLines(Publishers).ToList();
        var seen = new HashSet<string>(list, StringComparer.OrdinalIgnoreCase);
        int added = 0;
        foreach (var chip in DiscoveredPublishers)
        {
            if (!chip.VerifiedAdminInstall) continue;
            if (seen.Add(chip.Name))
            {
                list.Add(chip.Name);
                added++;
            }
        }
        if (added > 0)
        {
            Publishers = string.Join(Environment.NewLine, list);
            Message = $"Added {added} verified signing authorit{(added == 1 ? "y" : "ies")} to Trusted publishers.";
        }
        else
        {
            Message = "All verified admin-installed signing authorities are already listed.";
        }
    }

    private void TogglePublisherChip(BaselinePublisherRow chip)
    {
        var list = SplitLines(Publishers).ToList();
        int idx = list.FindIndex(x => string.Equals(x, chip.Name, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0)
            list.RemoveAt(idx);
        else
            list.Add(chip.Name);

        Publishers = string.Join(Environment.NewLine, list);
    }

    private void SyncPublisherChips()
    {
        if (_syncingPublishers || DiscoveredPublishers.Count == 0) return;
        _syncingPublishers = true;
        try
        {
            var active = new HashSet<string>(SplitLines(_publishers), StringComparer.OrdinalIgnoreCase);
            foreach (var chip in DiscoveredPublishers)
                chip.IsTrusted = active.Contains(chip.Name);
        }
        finally { _syncingPublishers = false; }
    }

    private void TrustSignedNonSystemApps()
    {
        int count = 0;
        foreach (var row in BaselineItems)
        {
            if (row.ProtectedSystem || !row.Signed) continue;
            if (row.Entry.Publisher.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)) continue;
            if (row.Choice != BaselineTrustChoice.Trusted)
            {
                row.Choice = BaselineTrustChoice.Trusted;
                count++;
            }
        }
        Message = count > 0
            ? $"Marked {count} signed third-party app{(count == 1 ? "" : "s")} as Trusted."
            : "All discovered signed third-party apps are already marked Trusted.";
    }

    private void ResetBaselineChoices()
    {
        foreach (var row in BaselineItems)
            row.Choice = BaselineTrustChoice.Default;
        Message = "Cleared per-program Trusted/Untrusted overrides (publisher allowlist unchanged).";
    }

    private void OnBaselineItemChanged()
    {
        UpdateBaselineSelectionCounts();
        if (_baselineFilter == "MARKED") _baselineView.Refresh();
        CommandManager.InvalidateRequerySuggested();
    }

    private void UpdateBaselineSelectionCounts()
    {
        TrustedItemCount = BaselineItems.Count(r => r.Choice == BaselineTrustChoice.Trusted);
        UntrustedItemCount = BaselineItems.Count(r => r.Choice == BaselineTrustChoice.Untrusted);
        OnPropertyChanged(nameof(BaselineSelectionSummary));
    }

    private bool _loadedEnforce;
    private string _loadedPublishers = "";
    private int _loadedWarn, _loadedQuarantine;

    /// <summary>What the file says now, as opposed to what is ticked on screen.</summary>
    public bool EnforceOnDisk => _loadedEnforce;

    private bool HasBaselineChanges => BaselineItems.Any(r => r.Choice != r.LoadedChoice);

    private bool IsDirty
        => Enforce != _loadedEnforce
        || WarnThreshold != _loadedWarn
        || QuarantineThreshold != _loadedQuarantine
        || !SplitLines(Publishers).SequenceEqual(SplitLines(_loadedPublishers))
        || HasBaselineChanges;

    /// <summary>The config would silently clamp these, so say what is wrong before saving.</summary>
    public string? ValidateThresholds()
    {
        if (WarnThreshold < 1 || WarnThreshold > 99) return "Warn at score must be between 1 and 99.";
        if (QuarantineThreshold <= WarnThreshold) return "Contain at score must be higher than warn at score.";
        if (QuarantineThreshold > 100) return "Contain at score cannot be above 100.";
        return null;
    }

    /// <summary>
    /// Writes the set-up choices back (read-modify-write, like Settings). Unchanged choices
    /// are not written: a rewrite drops the file's comments, and a read-only file would
    /// otherwise block Start for nothing. False on failure.
    /// </summary>
    public bool Save()
    {
        if (LoadError.Length > 0) return false;
        var problem = ValidateThresholds();
        if (problem is not null)
        {
            Message = "Not saved. " + problem;
            return false;
        }
        if (!IsDirty) return true;
        try
        {
            var onDisk = ConfigLoader.Load(_configPath);
            onDisk.Response.Mode = Enforce ? ResponseModes.Enforce : ResponseModes.Monitor;
            onDisk.Allowlist.Publishers = SplitLines(Publishers);
            onDisk.Detection.WarnThreshold = WarnThreshold;
            onDisk.Detection.QuarantineThreshold = QuarantineThreshold;

            if (HasBaselineChanges && BaselineItems.Count > 0)
            {
                onDisk.Watchlist.Entries = BaselineScanner.MergeWatchlistEntries(
                    onDisk.Watchlist.Entries,
                    BaselineItems.Select(r => (r.Entry, r.Choice)));

                if (BaselineItems.Any(r => r.Choice != BaselineTrustChoice.Default))
                    onDisk.Watchlist.Enabled = true;
            }

            ConfigLoader.Save(onDisk, _configPath);
            Load();   // show any clamping the save applied
            return LoadError.Length == 0;
        }
        catch (Exception ex)
        {
            Message = "Could not save the settings: " + ex.Message;
            return false;
        }
    }

    private void DescribeRules(DetectionConfig d)
    {
        Rules = null;
        if (!d.EnableRuleEngine)
        {
            RulesSummary = "Rule packs are turned off in the config; only built-in detections will run.";
            RulesMissing = true;
            return;
        }
        string dir = Path.IsPathRooted(d.RulesPath) ? d.RulesPath : Path.Combine(AppContext.BaseDirectory, d.RulesPath);
        int packs = Directory.Exists(dir) ? Directory.GetFiles(dir, "*.json", SearchOption.AllDirectories).Length : 0;
        RulesMissing = packs == 0;
        if (packs > 0)
        {
            try { Rules = RuleEngine.LoadDirectory(dir); }
            catch { Rules = null; }
        }
        int rules = Rules?.Rules.Count ?? 0;
        RulesSummary = packs == 0
            ? $"No detection rule packs were found in {dir}. Only built-in detections will run."
            : rules > 0
                ? $"{rules} detection rules in {packs} pack{(packs == 1 ? "" : "s")}."
                : $"{packs} detection rule pack{(packs == 1 ? "" : "s")} found.";
    }

    /// <summary>Rules as the engine would load them, for the coverage view before going live.</summary>
    public RuleSet? Rules { get; private set; }

    public IReadOnlyList<ScenarioInfo> Scenarios { get; private set; } = Array.Empty<ScenarioInfo>();

    private ScenarioInfo? _selectedScenario;
    public ScenarioInfo? SelectedScenario { get => _selectedScenario; set => Set(ref _selectedScenario, value); }
    public bool HasScenarios => Scenarios.Count > 0;

    private void LoadScenarios()
    {
        var found = new List<ScenarioInfo>();
        try
        {
            string dir = Path.Combine(AppContext.BaseDirectory, "Replay", "scenarios");
            if (Directory.Exists(dir))
                foreach (var file in Directory.GetFiles(dir, "*.jsonl").OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
                {
                    try
                    {
                        var t = TraceFormat.Load(file);
                        if (t.Events.Count > 0) found.Add(new ScenarioInfo(file, t.Name, t.Description, t.Events.Count, t.Duration));
                    }
                    catch { }
                }
        }
        catch { }
        Scenarios = found.OrderBy(s => s.IsBenign).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToArray();
        SelectedScenario = Scenarios.FirstOrDefault(s => s.Name == _selectedScenario?.Name) ?? Scenarios.FirstOrDefault();
        OnPropertyChanged(nameof(Scenarios));
        OnPropertyChanged(nameof(HasScenarios));
    }

    /// <summary>
    /// The one place enforce mode is confirmed, from set-up and from Settings alike.
    /// Defaults to No so Enter cannot arm it by accident.
    /// </summary>
    internal static bool ConfirmEnforceMode(string title)
        => MessageBox.Show(
               "Enforce mode lets BruceEDR act without asking. It can suspend processes, block " +
               "their network access with firewall rules, quarantine files and, if auto-kill is " +
               "on, end processes.\n\nRun it in monitor mode on this machine first if you have " +
               "not: false positives are likely on developer and gaming PCs.\n\nTurn on enforce mode?",
               title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
           == MessageBoxResult.Yes;

    private static string[] SplitLines(string s)
        => s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // -------- bound fields --------
    private bool _enforce;
    public bool Enforce
    {
        get => _enforce;
        set { if (Set(ref _enforce, value)) OnPropertyChanged(nameof(Monitor)); }
    }
    /// <summary>Bound to the "Monitor only" card. Unchecking it (by picking Enforce) is a no-op here.</summary>
    public bool Monitor
    {
        get => !_enforce;
        set { if (value) Enforce = false; }
    }

    private string _publishers = "";
    public string Publishers
    {
        get => _publishers;
        set
        {
            if (Set(ref _publishers, value))
                SyncPublisherChips();
        }
    }

    private int _warn; public int WarnThreshold { get => _warn; set => Set(ref _warn, value); }
    private int _quar; public int QuarantineThreshold { get => _quar; set => Set(ref _quar, value); }

    private bool _isScanningBaseline;
    public bool IsScanningBaseline { get => _isScanningBaseline; private set => Set(ref _isScanningBaseline, value); }

    public bool HasBaselineItems => BaselineItems.Count > 0;
    public bool HasDiscoveredPublishers => DiscoveredPublishers.Count > 0;

    private string _baselineSummary = "Scan your running process tree and installed programs to pre-trust apps or flag untrusted ones.";
    public string BaselineSummary { get => _baselineSummary; private set => Set(ref _baselineSummary, value); }

    private int _trustedItemCount;
    public int TrustedItemCount { get => _trustedItemCount; private set => Set(ref _trustedItemCount, value); }

    private int _untrustedItemCount;
    public int UntrustedItemCount { get => _untrustedItemCount; private set => Set(ref _untrustedItemCount, value); }

    public string BaselineSelectionSummary => (_trustedItemCount, _untrustedItemCount) switch
    {
        (0, 0) => "Mark specific processes or installed programs Trusted (allowlist) or Untrusted (contain on sight).",
        (> 0, 0) => $"{_trustedItemCount} marked Trusted (saved to watchlist when monitoring starts).",
        (0, > 0) => $"{_untrustedItemCount} marked Untrusted (saved to watchlist when monitoring starts).",
        _ => $"{_trustedItemCount} marked Trusted · {_untrustedItemCount} marked Untrusted (saved to watchlist on start)."
    };

    private string _baselineSearch = "";
    public string BaselineSearch
    {
        get => _baselineSearch;
        set
        {
            if (Set(ref _baselineSearch, value))
                _baselineView.Refresh();
        }
    }

    private string _baselineFilter = "ALL";
    public string BaselineFilter
    {
        get => _baselineFilter;
        set
        {
            string norm = (value ?? "ALL").ToUpperInvariant();
            if (!Set(ref _baselineFilter, norm)) return;
            OnPropertyChanged(nameof(FilterAll));
            OnPropertyChanged(nameof(FilterRunning));
            OnPropertyChanged(nameof(FilterApps));
            OnPropertyChanged(nameof(FilterUnsigned));
            OnPropertyChanged(nameof(FilterMarked));
            _baselineView.Refresh();
        }
    }

    public bool FilterAll => _baselineFilter == "ALL";
    public bool FilterRunning => _baselineFilter == "RUNNING";
    public bool FilterApps => _baselineFilter == "APPS";
    public bool FilterUnsigned => _baselineFilter == "UNSIGNED";
    public bool FilterMarked => _baselineFilter == "MARKED";

    private string _rulesSummary = ""; public string RulesSummary { get => _rulesSummary; set => Set(ref _rulesSummary, value); }
    private bool _rulesMissing; public bool RulesMissing { get => _rulesMissing; set => Set(ref _rulesMissing, value); }

    private string _loadError = "";
    public string LoadError
    {
        get => _loadError;
        set
        {
            if (!Set(ref _loadError, value)) return;
            OnPropertyChanged(nameof(HasLoadError));
            OnPropertyChanged(nameof(CanStart));
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public bool HasLoadError => _loadError.Length > 0;
    public bool CanStart => _loadError.Length == 0;

    private string _message = "";
    public string Message
    {
        get => _message;
        set
        {
            if (!Set(ref _message, value)) return;
            OnPropertyChanged(nameof(HasMessage));
            OnPropertyChanged(nameof(MessageIsError));
        }
    }
    public bool HasMessage => _message.Length > 0;
    public bool MessageIsError => _message.StartsWith("Not saved", StringComparison.Ordinal)
                               || _message.StartsWith("No monitor", StringComparison.Ordinal)
                               || _message.Contains("could not", StringComparison.OrdinalIgnoreCase);
}
