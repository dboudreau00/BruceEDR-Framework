using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using BruceEDR.Activity;
using BruceEDR.Gui.Services;
using Microsoft.Win32;

namespace BruceEDR.Gui.ViewModels;

/// <summary>
/// Where the process map, the file map and Insights get their data, and which data that is: this
/// session as it happens, a session saved by an earlier run, or a trace file. They all draw
/// <see cref="Snapshot"/> and rebuild when <see cref="Changed"/> fires, so none of them knows or cares
/// which one it is showing; the source bar at the top of each is the only part that does.
/// </summary>
public sealed class ActivityHub : ViewModelBase
{
    private ActivityModel? _live;
    private ActivitySnapshot _liveLast = ActivitySnapshot.Empty;
    private ActivitySnapshot? _viewed;
    private long _lastVersion = -1;
    private int _busy;

    public ActivityHub()
    {
        UseLiveCommand = new RelayCommand(UseLive);
        OpenSessionCommand = new RelayCommandP(p => { if (p is SessionEntry e) OpenSession(e); });
        DeleteSessionCommand = new RelayCommandP(p => { if (p is SessionEntry e) DeleteSession(e); });
        OpenFileCommand = new RelayCommand(OpenFile);
        SaveNowCommand = new RelayCommand(() => SaveNow(), () => IsLive && !Snapshot.IsEmpty);
        RefreshSessions();
    }

    /// <summary>What the views draw.</summary>
    public ActivitySnapshot Snapshot => _viewed ?? _liveLast;

    public bool IsLive => _viewed is null;
    public bool IsViewing => _viewed is not null;
    public bool HasLiveModel => _live is not null;

    public string SourceTitle => _viewed is null
        ? (_live is not null ? (_liveLast.Name.Length > 0 && _liveLast.Name != "Live session" ? _liveLast.Name : "This session") : "This session")
        : _viewed.Name;

    public string SourceDetail
    {
        get
        {
            var s = Snapshot;
            if (s.IsEmpty) return _viewed is null ? (_live is null ? "nothing is being monitored" : "nothing seen yet") : "empty";
            string when = s.StartedUtc == default ? "" : s.StartedUtc.ToLocalTime().ToString("d MMM HH:mm") + " · ";
            string span = s.Span.TotalSeconds >= 1 ? ProcessMapBuilder.Duration(s.Span) + " · " : "";
            return $"{when}{span}{s.Processes.Count:N0} processes · {s.Files.Count:N0} files";
        }
    }

    public string SourceKind => _viewed switch { null => "live", { Source: "trace" } => "trace", _ => "session" };

    private string _message = "";
    /// <summary>The last thing that went wrong opening or saving, shown in the source bar.</summary>
    public string Message { get => _message; private set { if (Set(ref _message, value)) OnPropertyChanged(nameof(HasMessage)); } }
    public bool HasMessage => _message.Length > 0;

    public ObservableCollection<SessionEntry> Sessions { get; } = new();
    public bool HasSessions => Sessions.Count > 0;

    /// <summary>Raised on the UI thread when <see cref="Snapshot"/> is a different snapshot.</summary>
    public event Action? Changed;

    /// <summary>Asks the main view model to show the process map with this process selected (node id).</summary>
    public Action<int>? ShowProcess { get; set; }
    /// <summary>Asks the main view model to show the file map filtered to what this process did (node id).</summary>
    public Action<int>? ShowFilesOf { get; set; }

    public ICommand UseLiveCommand { get; }
    public ICommand OpenSessionCommand { get; }
    public ICommand DeleteSessionCommand { get; }
    public ICommand OpenFileCommand { get; }
    public ICommand SaveNowCommand { get; }

    // ------------------------------------------------------------------ live

    /// <summary>Starts following a model (a new run or a replay). The previous run's last picture goes.</summary>
    public void AttachLive(ActivityModel? model)
    {
        _live = model;
        _lastVersion = -1;
        _liveLast = ActivitySnapshot.Empty;
        if (_viewed is null) Raise();
        OnPropertyChanged(nameof(HasLiveModel));
    }

    /// <summary>The run ended. Keeps its final picture on screen until the next one starts.</summary>
    public void Freeze()
    {
        if (_live is not null)
        {
            try { _liveLast = _live.Snapshot(); } catch (Exception ex) { AppLog.Error("activity freeze", ex); }
        }
        _live = null;
        if (_viewed is null) Raise();
        OnPropertyChanged(nameof(HasLiveModel));
    }

    /// <summary>Pulls a fresh snapshot of the live model when it changed and someone is looking. Cheap otherwise.</summary>
    public async Task RefreshAsync(bool wanted)
    {
        var model = _live;
        if (model is null || !wanted) return;
        long version = model.Version;
        if (version == _lastVersion) return;
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var snap = await Task.Run(() => model.Snapshot());
            if (!ReferenceEquals(model, _live)) return;
            _lastVersion = version;
            _liveLast = snap;
            if (_viewed is null) Raise();
        }
        catch (Exception ex) { AppLog.Error("activity refresh", ex); }
        finally { Interlocked.Exchange(ref _busy, 0); }
    }

    // ------------------------------------------------------------------ history

    public void UseLive()
    {
        if (_viewed is null) return;
        _viewed = null;
        Message = "";
        Raise();
    }

    public void View(ActivitySnapshot snapshot)
    {
        _viewed = snapshot;
        Message = "";
        Raise();
    }

    public void OpenSession(SessionEntry entry)
    {
        try { View(SessionStore.Load(entry.Path)); }
        catch (Exception ex)
        {
            AppLog.Error("open session", ex);
            Message = "Could not open that session: " + ex.Message;
        }
    }

    public void DeleteSession(SessionEntry entry)
    {
        try { SessionStore.Delete(entry.Path); }
        catch (Exception ex) { AppLog.Error("delete session", ex); Message = "Could not delete it: " + ex.Message; }
        RefreshSessions();
    }

    private void OpenFile()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a saved session or a trace",
            Filter = "Sessions and traces (*.gz;*.jsonl)|*.gz;*.jsonl|Saved sessions (*.gz)|*.gz|Traces (*.jsonl)|*.jsonl|All files|*.*",
            InitialDirectory = Directory.Exists(AppPaths.SessionRoot) ? AppPaths.SessionRoot : null
        };
        if (dialog.ShowDialog() != true) return;
        OpenPath(dialog.FileName);
    }

    public void OpenPath(string path)
    {
        try
        {
            var snap = path.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase) ? SessionStore.FromTrace(path) : SessionStore.Load(path);
            View(snap);
        }
        catch (Exception ex)
        {
            AppLog.Error("open activity file", ex);
            Message = "Could not open that file: " + ex.Message;
        }
    }

    /// <summary>Saves the live picture now, as a session, so it can be looked at after the run. Null when there is nothing to save.</summary>
    public string? SaveNow()
    {
        var snap = Snapshot;
        if (!IsLive || snap.IsEmpty) return null;
        try
        {
            var path = SessionStore.Save(AppPaths.SessionRoot, snap, label: "Saved " + DateTime.Now.ToString("d MMM HH:mm"),
                                         requireAdministrativeOwner: BruceEDR.Security.SafePaths.ProcessIsAdministrative,
                                         allowCurrentUserOwner: true);
            RefreshSessions();
            Message = "";
            return path;
        }
        catch (Exception ex)
        {
            AppLog.Error("save session", ex);
            Message = "Could not save the session: " + ex.Message;
            return null;
        }
    }

    public void RefreshSessions()
    {
        try
        {
            var list = SessionStore.List(AppPaths.SessionRoot);
            Sessions.Clear();
            foreach (var e in list.Take(40)) Sessions.Add(e);
        }
        catch (Exception ex) { AppLog.Error("list sessions", ex); }
        OnPropertyChanged(nameof(HasSessions));
    }

    private void Raise()
    {
        OnPropertyChanged(nameof(Snapshot));
        OnPropertyChanged(nameof(IsLive));
        OnPropertyChanged(nameof(IsViewing));
        OnPropertyChanged(nameof(SourceTitle));
        OnPropertyChanged(nameof(SourceDetail));
        OnPropertyChanged(nameof(SourceKind));
        Changed?.Invoke();
        CommandManager.InvalidateRequerySuggested();
    }
}
