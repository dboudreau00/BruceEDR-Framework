using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using BruceEDR.Activity;
using BruceEDR.Gui.Services;
using BruceEDR.Gui.Views;

namespace BruceEDR.Gui.ViewModels;

public sealed class FileDetail
{
    public int Id { get; init; }
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public string Folder { get; init; } = "";
    public string Fate { get; init; } = "";
    public string Level { get; init; } = "info";
    public string MeltNote { get; init; } = "";
    public bool HasMelt => MeltNote.Length > 0;
    public bool IsMelted { get; init; }
    public IReadOnlyList<StoryRow> Story { get; init; } = Array.Empty<StoryRow>();
    /// <summary>The process that ran it, else the one that removed it, else the one that made it (node id); 0 when none is known.</summary>
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = "";
    public bool HasProcess => ProcessId != 0;
}

/// <summary>One of the filter chips above the file map: its count, and whether it is on.</summary>
public sealed class FateChip : ViewModelBase
{
    private int _count;
    private bool _on;
    public FateChip(FileFate fate, FileFilter flag) { Fate = fate; Flag = flag; Title = FileMapBuilder.Title(fate); Level = FileMapBuilder.LevelOf(fate); }
    public FileFate Fate { get; }
    public FileFilter Flag { get; }
    public string Title { get; }
    public string Level { get; }
    public int Count { get => _count; set => Set(ref _count, value); }
    public bool IsOn { get => _on; set => Set(ref _on, value); }
}

/// <summary>
/// The file map: what was made, run, moved and deleted, as a mind map, with the programs that removed
/// themselves ("melted") standing out. Group by what happened, by program or by folder; filter, search,
/// click a file for its history.
/// </summary>
public sealed class FileMapViewModel : ViewModelBase
{
    private readonly ActivityHub _hub;
    private readonly HashSet<string> _expanded = new();
    private readonly HashSet<string> _folded = new();
    private readonly DispatcherTimer _debounce;
    private ActivitySnapshot _snap = ActivitySnapshot.Empty;
    private Dictionary<int, ProcessInfo> _procs = new();
    private Dictionary<int, FileTrail> _files = new();
    private FileFilter _filter = FileFilter.Default;

    public FileMapViewModel(ActivityHub hub)
    {
        _hub = hub;
        _debounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(180) };
        _debounce.Tick += (_, _) => { _debounce.Stop(); Rebuild(); };
        Chips = new[]
        {
            new FateChip(FileFate.Melted, FileFilter.Melted), new FateChip(FileFate.AfterRun, FileFilter.AfterRun),
            new FateChip(FileFate.Dropped, FileFilter.Dropped), new FateChip(FileFate.Deleted, FileFilter.Deleted),
            new FateChip(FileFate.Renamed, FileFilter.Renamed), new FateChip(FileFate.Created, FileFilter.Created)
        };
        ToggleChipCommand = new RelayCommandP(p => { if (p is FateChip c) ToggleChip(c); });
        SetGroupCommand = new RelayCommandP(p => { if (Enum.TryParse<FileGroupBy>(p as string, out var g)) GroupBy = g; });
        SetLayoutCommand = new RelayCommandP(p => { if (Enum.TryParse<MapShape>(p as string, true, out var s)) Shape = s; });
        FitCommand = new RelayCommand(() => FitAllRequested?.Invoke());
        ClearFocusCommand = new RelayCommand(() => SetFocus(0), () => FocusId != 0);
        ClearSearchCommand = new RelayCommand(() => Search = "", () => Search.Length > 0);
        ShowProcessCommand = new RelayCommand(() => { if (Selected is { HasProcess: true } s) _hub.ShowProcess?.Invoke(s.ProcessId); }, () => Selected is { HasProcess: true });
        CopyPathCommand = new RelayCommand(CopyPath, () => Selected is not null);
        hub.Changed += OnHubChanged;
        OnHubChanged();
    }

    public ActivityHub Hub => _hub;
    public IReadOnlyList<FateChip> Chips { get; }

    public ICommand ToggleChipCommand { get; }
    public ICommand SetGroupCommand { get; }
    public ICommand SetLayoutCommand { get; }
    public ICommand FitCommand { get; }
    public ICommand ClearFocusCommand { get; }
    public ICommand ClearSearchCommand { get; }
    public ICommand ShowProcessCommand { get; }
    public ICommand CopyPathCommand { get; }

    /// <summary>The view frames the map at a readable size when this fires (a filter changed, a group folded).</summary>
    public event Action? FitRequested;

    /// <summary>The Fit button: the view shows the whole map, however small.</summary>
    public event Action? FitAllRequested;

    private MapNode? _root;
    public MapNode? Root { get => _root; private set => Set(ref _root, value); }

    private FileGroupBy _groupBy = FileGroupBy.Operation;
    public FileGroupBy GroupBy
    {
        get => _groupBy;
        set { if (Set(ref _groupBy, value)) { _expanded.Clear(); _folded.Clear(); OnPropertyChanged(nameof(GroupKey)); Rebuild(); FitRequested?.Invoke(); } }
    }
    public string GroupKey => _groupBy.ToString();

    private MapShape _shape = MapShape.Flow;
    public MapShape Shape { get => _shape; set { if (Set(ref _shape, value)) OnPropertyChanged(nameof(LayoutKey)); } }
    public string LayoutKey => _shape.ToString().ToLowerInvariant();

    private bool _showNoise;
    public bool ShowNoise { get => _showNoise; set { if (Set(ref _showNoise, value)) { Rebuild(); FitRequested?.Invoke(); } } }

    private int _noisy;
    public string NoiseLabel => _noisy == 0 ? "Cache and churn" : $"Cache and churn ({_noisy:N0})";

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

    public bool IsEmpty => _snap.Files.Count == 0;
    public bool HasData => !IsEmpty;
    /// <summary>The headline over the map when something melted: what is worth looking at first.</summary>
    public bool HasMelted { get; private set; }
    public string MeltedBanner { get; private set; } = "";

    private int _focusId;
    public int FocusId { get => _focusId; private set { if (Set(ref _focusId, value)) { OnPropertyChanged(nameof(HasFocus)); CommandManager.InvalidateRequerySuggested(); } } }
    public bool HasFocus => _focusId != 0;
    private string _focusName = "";
    public string FocusName { get => _focusName; private set => Set(ref _focusName, value); }

    private string? _selectedKey;
    public string? SelectedKey { get => _selectedKey; set { if (Set(ref _selectedKey, value)) UpdateSelected(); } }

    private FileDetail? _selected;
    public FileDetail? Selected
    {
        get => _selected;
        private set { if (Set(ref _selected, value)) { OnPropertyChanged(nameof(HasSelection)); CommandManager.InvalidateRequerySuggested(); } }
    }
    public bool HasSelection => _selected is not null;

    public IReadOnlyList<LegendItem> Legend { get; } = new LegendItem[]
    {
        new("ember", "Melted: deleted itself"), new("watch", "Ran, then deleted"), new("drop", "Dropped by another program"),
        new("deleted", "Deleted"), new("renamed", "Renamed"), new("created", "Created")
    };

    // ------------------------------------------------------------------ filters and focus

    private void ToggleChip(FateChip c)
    {
        _filter ^= c.Flag;
        c.IsOn = (_filter & c.Flag) != 0;
        Rebuild();
        FitRequested?.Invoke();
    }

    /// <summary>Only the files this process (node id) touched; 0 clears it. Used by the jump from the process map.</summary>
    public void SetFocus(int processId)
    {
        FocusId = processId;
        FocusName = processId != 0 && _procs.TryGetValue(processId, out var p) ? (p.Name.Length > 0 ? p.Name : $"pid {p.Pid}") : "";
        if (processId != 0) { _filter = FileFilter.All; SyncChips(); }
        Rebuild();
        FitRequested?.Invoke();
    }

    /// <summary>Opens the file in the map by its path (the jump from a flagged event).</summary>
    public void SelectFile(int fileId)
    {
        if (!_files.TryGetValue(fileId, out var f)) return;
        _search = "";
        _filter = FileFilter.All;
        if (f.Noisy) _showNoise = true;
        OnPropertyChanged(nameof(Search)); OnPropertyChanged(nameof(HasSearch)); OnPropertyChanged(nameof(ShowNoise));
        SyncChips();
        Rebuild();
        SelectedKey = FileMapBuilder.KeyOf(f);
    }

    private void SyncChips() { foreach (var c in Chips) c.IsOn = (_filter & c.Flag) != 0; }

    // ------------------------------------------------------------------ building

    private void OnHubChanged()
    {
        _snap = _hub.Snapshot;
        _procs = _snap.Processes.ToDictionary(p => p.Id);
        _files = _snap.Files.ToDictionary(f => f.Id);
        if (_hub.IsViewing) { _expanded.Clear(); _folded.Clear(); _focusId = 0; FocusName = ""; OnPropertyChanged(nameof(FocusId)); OnPropertyChanged(nameof(HasFocus)); }
        var c = FileMapBuilder.Count(_snap);
        _noisy = c.Noisy;
        OnPropertyChanged(nameof(NoiseLabel));
        foreach (var chip in Chips)
        {
            chip.Count = chip.Fate switch
            {
                FileFate.Melted => c.Melted, FileFate.AfterRun => c.AfterRun, FileFate.Dropped => c.Dropped,
                FileFate.Deleted => c.Deleted, FileFate.Renamed => c.Renamed, _ => c.Created
            };
            chip.IsOn = (_filter & chip.Flag) != 0;
        }
        HasMelted = c.Melted > 0;
        MeltedBanner = c.Melted switch
        {
            0 => "",
            1 => "1 program removed itself after it ran",
            _ => $"{c.Melted} programs removed themselves after they ran"
        };
        OnPropertyChanged(nameof(HasMelted));
        OnPropertyChanged(nameof(MeltedBanner));
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasData));
        Rebuild();
    }

    private void Rebuild()
    {
        var result = FileMapBuilder.Build(_snap, new FileMapOptions
        {
            GroupBy = _groupBy, Filter = _filter, ShowNoise = _showNoise, Search = _search, FocusProcessId = _focusId, Expanded = _expanded, Collapsed = _folded
        });
        Root = result.Root;
        Note = result.Note;
        Summary = IsEmpty ? "" : $"{result.Shown:N0} file{(result.Shown == 1 ? "" : "s")} shown";
        UpdateSelected();
    }

    /// <summary>Double-click: a "+N more" node opens its whole group; a group node does nothing else, a file selects itself.</summary>
    public void Activate(MapNode node)
    {
        if (node.Kind == MapKind.More && node.Tag is string group) { _expanded.Add(group); Rebuild(); return; }
        if (node.Kind == MapKind.Group && node.Children.Count > 0)
        {
            if (!_folded.Remove(node.Key)) _folded.Add(node.Key);
            Rebuild();
        }
    }

    // ------------------------------------------------------------------ selection

    public string? Describe(MapNode n) => n.Tag switch
    {
        FileTrail f => f.Path + (f.MeltNote.Length > 0 ? "\n" + f.MeltNote : ""),
        _ => n.Sub
    };

    private void UpdateSelected()
    {
        if (_selectedKey is null || !_selectedKey.StartsWith('f') || !int.TryParse(_selectedKey.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out int id)
            || !_files.TryGetValue(id, out var f))
        {
            Selected = null;
            return;
        }
        var fate = FileMapBuilder.FateOf(f);
        int who = f.RunnerId != 0 ? f.RunnerId : f.DeleterId != 0 ? f.DeleterId : f.CreatorId;
        if (who != 0 && !_procs.ContainsKey(who)) who = 0;
        Selected = new FileDetail
        {
            Id = f.Id, Name = f.Name, Path = f.Path, Folder = f.Folder, Fate = FileMapBuilder.Title(fate), Level = FileMapBuilder.LevelOf(fate),
            MeltNote = f.MeltNote, IsMelted = f.IsMelted,
            Story = FileStory.Lines(f, _snap.Processes).Select(l => new StoryRow(l.AtUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture), l.Text, l.Level)).ToList(),
            ProcessId = who, ProcessName = who != 0 ? (_procs[who].Name.Length > 0 ? _procs[who].Name : $"pid {_procs[who].Pid}") : ""
        };
    }

    private void CopyPath()
    {
        if (Selected is null) return;
        try { Clipboard.SetText(Selected.Path); }
        catch (Exception ex) { AppLog.Error("copy path", ex); }
    }
}
