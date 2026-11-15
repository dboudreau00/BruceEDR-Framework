using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using BruceEDR.Activity;
using BruceEDR.Gui.Services;
using BruceEDR.Gui.Views;

namespace BruceEDR.Gui.ViewModels;

/// <summary>A labelled number with a bar behind it, for the counts in a detail panel.</summary>
public sealed record StatBar(string Label, int Value, double Fraction, string Level);

/// <summary>One line of a story (a file's history, a process's reasons) for a list in a detail panel.</summary>
public sealed record StoryRow(string Time, string Text, string Level);

/// <summary>Everything the detail panel shows about the selected process.</summary>
public sealed class ProcessDetail
{
    public int Id { get; init; }
    public string Name { get; init; } = "";
    public string Subtitle { get; init; } = "";
    public string Level { get; init; } = "info";
    public string State { get; init; } = "";
    public int Score { get; init; }
    public bool HasScore => Score > 0;
    public string Image { get; init; } = "";
    public bool HasImage => Image.Length > 0;
    public string CommandLine { get; init; } = "";
    public bool HasCommandLine => CommandLine.Length > 0;
    public string Parent { get; init; } = "";
    public string Timing { get; init; } = "";
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public bool HasReasons => Reasons.Count > 0;
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();
    public bool HasTechniques => Techniques.Count > 0;
    public IReadOnlyList<StatBar> Activity { get; init; } = Array.Empty<StatBar>();
    public bool HasActivity => Activity.Count > 0;
    public string Files { get; init; } = "";
    public bool HasFiles => Files.Length > 0;
    public int FileCount { get; init; }
    public string Children { get; init; } = "";
}

/// <summary>
/// The process map: the lineage of every process as a mind map, with what the engine flagged and what dropped
/// or removed a file standing out. Filter, search, fold, scrub back in time, click for the detail panel.
/// </summary>
public sealed class ProcessMapViewModel : ViewModelBase
{
    private readonly ActivityHub _hub;
    private readonly HashSet<string> _collapsed = new();
    private readonly HashSet<string> _expanded = new();
    private readonly DispatcherTimer _debounce;
    private readonly DispatcherTimer _play;
    private ActivitySnapshot _snap = ActivitySnapshot.Empty;
    private Dictionary<int, ProcessInfo> _byId = new();

    public ProcessMapViewModel(ActivityHub hub)
    {
        _hub = hub;
        _debounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
        _debounce.Tick += (_, _) => { _debounce.Stop(); Rebuild(); };
        _play = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(60) };
        _play.Tick += (_, _) => StepPlay();
        hub.Changed += OnHubChanged;

        SetFilterCommand = new RelayCommandP(p => { if (Enum.TryParse<ProcessFilter>(p as string, out var f)) Filter = f; });
        SetLayoutCommand = new RelayCommandP(p => { if (Enum.TryParse<MapShape>(p as string, true, out var s)) Shape = s; });
        FitCommand = new RelayCommand(() => FitAllRequested?.Invoke());
        ExpandAllCommand = new RelayCommand(ExpandAll);
        CollapseAllCommand = new RelayCommand(CollapseAll);
        ClearSearchCommand = new RelayCommand(() => Search = "", () => Search.Length > 0);
        ShowFilesCommand = new RelayCommand(() => { if (Selected is { } s) _hub.ShowFilesOf?.Invoke(s.Id); }, () => Selected is { FileCount: > 0 });
        CopyCommandLineCommand = new RelayCommand(CopyCommandLine, () => Selected is { HasCommandLine: true });
        PlayCommand = new RelayCommand(TogglePlay, () => CanScrub);
        NowCommand = new RelayCommand(() => { StopPlay(); ScrubValue = ScrubMax; }, () => CanScrub && !AtNow);
        OnHubChanged();
    }

    public ActivityHub Hub => _hub;

    public ICommand SetFilterCommand { get; }
    public ICommand SetLayoutCommand { get; }
    public ICommand FitCommand { get; }
    public ICommand ExpandAllCommand { get; }
    public ICommand CollapseAllCommand { get; }
    public ICommand ClearSearchCommand { get; }
    public ICommand ShowFilesCommand { get; }
    public ICommand CopyCommandLineCommand { get; }
    public ICommand PlayCommand { get; }
    public ICommand NowCommand { get; }

    /// <summary>The view frames the map at a readable size when this fires (a filter changed, a branch folded).</summary>
    public event Action? FitRequested;

    /// <summary>The Fit button: the view shows the whole map, however small.</summary>
    public event Action? FitAllRequested;

    private MapNode? _root;
    public MapNode? Root { get => _root; private set => Set(ref _root, value); }

    private ProcessFilter _filter = ProcessFilter.Flagged;
    public ProcessFilter Filter
    {
        get => _filter;
        set { if (Set(ref _filter, value)) { OnPropertyChanged(nameof(FilterKey)); Rebuild(); FitRequested?.Invoke(); } }
    }
    public string FilterKey => _filter.ToString();

    // A process chain is deep, so the outline is the default: it stays readable at any depth.
    private MapShape _shape = MapShape.Outline;
    public MapShape Shape
    {
        get => _shape;
        set { if (Set(ref _shape, value)) OnPropertyChanged(nameof(LayoutKey)); }
    }
    public string LayoutKey => _shape.ToString().ToLowerInvariant();

    private string _search = "";
    public string Search
    {
        get => _search;
        set { if (Set(ref _search, value ?? "")) { OnPropertyChanged(nameof(HasSearch)); _debounce.Stop(); _debounce.Start(); } }
    }
    public bool HasSearch => _search.Length > 0;

    private string _note = "";
    public string Note { get => _note; private set { if (Set(ref _note, value)) OnPropertyChanged(nameof(HasNote)); } }
    public bool HasNote => _note.Length > 0;

    private string _summary = "";
    public string Summary { get => _summary; private set => Set(ref _summary, value); }

    public bool IsEmpty => _snap.Processes.Count == 0;
    public bool HasData => !IsEmpty;

    private string? _selectedKey;
    public string? SelectedKey
    {
        get => _selectedKey;
        set { if (Set(ref _selectedKey, value)) UpdateSelected(); }
    }

    private ProcessDetail? _selected;
    public ProcessDetail? Selected
    {
        get => _selected;
        private set { if (Set(ref _selected, value)) { OnPropertyChanged(nameof(HasSelection)); CommandManager.InvalidateRequerySuggested(); } }
    }
    public bool HasSelection => _selected is not null;

    public IReadOnlyList<LegendItem> Legend { get; } = new LegendItem[]
    {
        new("threat", "Over the contain threshold"), new("watch", "Flagged"), new("safe", "Trusted or ended"), new("info", "Running")
    };

    // ------------------------------------------------------------------ time scrubber

    public const double ScrubMax = 1000;
    private double _scrub = ScrubMax;
    public double ScrubValue
    {
        get => _scrub;
        set
        {
            if (!Set(ref _scrub, Math.Clamp(value, 0, ScrubMax))) return;
            OnPropertyChanged(nameof(AtNow));
            OnPropertyChanged(nameof(ScrubLabel));
            _debounce.Stop();
            _debounce.Start();
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public bool AtNow => _scrub >= ScrubMax;
    public bool CanScrub => _snap.Span.TotalSeconds >= 2 && !IsEmpty;

    private DateTime? AtUtc
    {
        get
        {
            if (AtNow || !CanScrub) return null;
            return _snap.StartedUtc + TimeSpan.FromTicks((long)(_snap.Span.Ticks * (_scrub / ScrubMax)));
        }
    }

    public string ScrubLabel => AtUtc is { } at
        ? $"{at.ToLocalTime():HH:mm:ss}  ·  {ProcessMapBuilder.Duration(at - _snap.StartedUtc)} in"
        : "now";

    private void TogglePlay()
    {
        if (_play.IsEnabled) { StopPlay(); return; }
        if (AtNow) _scrub = 0;
        OnPropertyChanged(nameof(IsPlaying));
        _play.Start();
    }

    private void StepPlay()
    {
        // The whole session in about twelve seconds, however long it was.
        ScrubValue += ScrubMax * 0.06 / 12;
        if (AtNow) StopPlay();
    }

    private void StopPlay()
    {
        _play.Stop();
        OnPropertyChanged(nameof(IsPlaying));
    }

    public bool IsPlaying => _play.IsEnabled;

    // ------------------------------------------------------------------ building

    private void OnHubChanged()
    {
        _snap = _hub.Snapshot;
        _byId = _snap.Processes.ToDictionary(p => p.Id);
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasData));
        OnPropertyChanged(nameof(CanScrub));
        if (!CanScrub && !AtNow) { StopPlay(); _scrub = ScrubMax; OnPropertyChanged(nameof(ScrubValue)); OnPropertyChanged(nameof(AtNow)); OnPropertyChanged(nameof(ScrubLabel)); }
        if (_hub.IsViewing) { _collapsed.Clear(); _expanded.Clear(); }
        Rebuild();
    }

    private void Rebuild()
    {
        var result = ProcessMapBuilder.Build(_snap, new ProcessMapOptions
        {
            Filter = _filter, Search = _search, AtUtc = AtUtc, Collapsed = _collapsed, Expanded = _expanded
        });
        Root = result.Root;
        Note = result.Note;
        Summary = IsEmpty ? ""
            : $"{result.Shown:N0} of {result.Total:N0} process{(result.Total == 1 ? "" : "es")} shown" +
              (_snap.Processes.Count(p => p.Flagged) is var f and > 0 ? $"  ·  {f} flagged" : "");
        UpdateSelected();
    }

    /// <summary>Folds or unfolds the node that was double-clicked.</summary>
    public void Toggle(MapNode node)
    {
        if (node.Kind != MapKind.Process || node.Children.Count == 0) return;
        if (node.Collapsed) { _expanded.Add(node.Key); _collapsed.Remove(node.Key); }
        else { _collapsed.Add(node.Key); _expanded.Remove(node.Key); }
        Rebuild();
    }

    private void ExpandAll()
    {
        _collapsed.Clear();
        if (Root is null) return;
        foreach (var n in Root.Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process && n.Children.Count > 0)) _expanded.Add(n.Key);
        Rebuild();
        FitRequested?.Invoke();
    }

    private void CollapseAll()
    {
        _expanded.Clear();
        if (Root is null) return;
        foreach (var n in Root.Walk(includeHidden: true).Where(n => n.Kind == MapKind.Process && n.Children.Count > 0)) _collapsed.Add(n.Key);
        Rebuild();
        FitRequested?.Invoke();
    }

    /// <summary>Selects a process by node id, widening the view first if it is not in it (the jump from the file map).</summary>
    public void Select(int processId)
    {
        if (!_byId.ContainsKey(processId)) return;
        string key = ProcessMapBuilder.KeyOf(processId);
        if (Root is null || !Root.Walk(includeHidden: true).Any(n => n.Key == key))
        {
            _filter = ProcessFilter.All;
            _search = "";
            OnPropertyChanged(nameof(Filter)); OnPropertyChanged(nameof(FilterKey)); OnPropertyChanged(nameof(Search)); OnPropertyChanged(nameof(HasSearch));
            Rebuild();
        }
        // Open the branches above it so it is on screen.
        for (var up = _byId[processId]; up.ParentId != 0 && _byId.TryGetValue(up.ParentId, out var parent); up = parent)
        {
            _collapsed.Remove(ProcessMapBuilder.KeyOf(parent.Id));
            _expanded.Add(ProcessMapBuilder.KeyOf(parent.Id));
        }
        Rebuild();
        SelectedKey = key;
    }

    // ------------------------------------------------------------------ selection

    public string? Describe(MapNode n)
    {
        if (n.Tag is not ProcessInfo p) return n.Sub;
        var lines = new List<string>();
        if (p.CommandLine.Length > 0) lines.Add(Clip(p.CommandLine, 260));
        else if (p.Image.Length > 0) lines.Add(p.Image);
        lines.Add(n.Sub);
        if (p.Reasons.Count > 0) lines.Add("» " + Clip(p.Reasons[^1], 120));
        return string.Join("\n", lines);
    }

    private static string Clip(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private void UpdateSelected()
    {
        if (_selectedKey is null || !_selectedKey.StartsWith('p') || !int.TryParse(_selectedKey.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out int id)
            || !_byId.TryGetValue(id, out var p))
        {
            Selected = null;
            return;
        }
        Selected = DetailOf(p);
    }

    private ProcessDetail DetailOf(ProcessInfo p)
    {
        var fileOps = _snap.Files.Where(f => f.CreatorId == p.Id || f.RunnerId == p.Id || f.DeleterId == p.Id).ToList();
        int made = fileOps.Count(f => f.CreatorId == p.Id), ran = fileOps.Count(f => f.RunnerId == p.Id);
        int gone = fileOps.Count(f => f.DeleterId == p.Id), melted = fileOps.Count(f => f.IsMelted);
        var parts = new List<string>();
        if (made > 0) parts.Add($"made {made}");
        if (ran > 0) parts.Add($"ran {ran}");
        if (gone > 0) parts.Add($"deleted {gone}");
        if (melted > 0) parts.Add($"{melted} melted");

        int max = Math.Max(1, new[] { ActivityKind.FileCreate, ActivityKind.FileDelete, ActivityKind.FileRename, ActivityKind.Network, ActivityKind.Dns,
            ActivityKind.Registry, ActivityKind.ProcessAccess, ActivityKind.ImageLoad, ActivityKind.ProcessStart }.Max(k => p.Count(k)));
        var bars = new List<StatBar>();
        foreach (var (kind, level) in new[]
                 {
                     (ActivityKind.ProcessStart, "info"), (ActivityKind.FileCreate, "created"), (ActivityKind.FileDelete, "deleted"),
                     (ActivityKind.FileRename, "renamed"), (ActivityKind.Network, "watch"), (ActivityKind.Dns, "watch"),
                     (ActivityKind.Registry, "drop"), (ActivityKind.ProcessAccess, "threat"), (ActivityKind.ImageLoad, "info")
                 })
            if (p.Count(kind) > 0)
                bars.Add(new StatBar(ActivityKinds.Label(kind) + (kind == ActivityKind.ProcessStart ? "s (children)" : ""), p.Count(kind), p.Count(kind) / (double)max, level));

        var parent = p.ParentId != 0 && _byId.TryGetValue(p.ParentId, out var pp) ? pp : null;
        int kids = _snap.Processes.Count(c => c.ParentId == p.Id);
        string timing = p.PreExisting ? "Started before monitoring began"
            : $"Started {p.StartUtc.ToLocalTime():HH:mm:ss}" + (p.ExitUtc is { } e ? $", ended {e.ToLocalTime():HH:mm:ss} (ran {ProcessMapBuilder.Duration(e - p.StartUtc)})" : ", still running");

        return new ProcessDetail
        {
            Id = p.Id,
            Name = p.Name.Length > 0 ? p.Name : $"pid {p.Pid}",
            Subtitle = $"pid {p.Pid}" + (p.User.Length > 0 ? " · " + p.User : ""),
            Level = p.Level, State = p.State, Score = p.Score, Image = p.Image, CommandLine = p.CommandLine,
            Parent = parent is null ? (p.ParentPid > 0 ? $"pid {p.ParentPid} (not seen)" : "") : $"{(parent.Name.Length > 0 ? parent.Name : "process")} (pid {parent.Pid})",
            Timing = timing, Reasons = p.Reasons, Techniques = p.Techniques, Activity = bars,
            Files = string.Join(" · ", parts), FileCount = fileOps.Count,
            Children = kids == 0 ? "" : $"Started {kids} process{(kids == 1 ? "" : "es")}"
        };
    }

    private void CopyCommandLine()
    {
        if (Selected is not { HasCommandLine: true } s) return;
        try { Clipboard.SetText(s.CommandLine); }
        catch (Exception ex) { AppLog.Error("copy command line", ex); }
    }
}
