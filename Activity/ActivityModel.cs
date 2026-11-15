using BruceEDR.Core;

namespace BruceEDR.Activity;

public sealed class ActivityModelOptions
{
    /// <summary>Processes kept. Exited ones with nothing flagged go first.</summary>
    public int MaxProcesses { get; init; } = 8192;
    /// <summary>Files followed. Cache churn and plain creations go before deletes, renames and runs.</summary>
    public int MaxFiles { get; init; } = 20_000;
    /// <summary>Seconds of per-second counts kept (12 hours).</summary>
    public int MaxSeconds { get; init; } = 43_200;
    public int MaxEventsPerFile { get; init; } = 16;
    /// <summary>How long after a program ran (or ended) a delete still counts as "ran, then deleted".</summary>
    public TimeSpan MeltWindow { get; init; } = TimeSpan.FromMinutes(10);
    /// <summary>Turns the kernel's device paths into drive-letter paths. Identity when null.</summary>
    public Func<string, string>? NormalizePath { get; init; }
    /// <summary>What the session is called in lists and banners.</summary>
    public string Name { get; init; } = "Live session";
    /// <summary>Names a process the model only knows by pid (one that started before monitoring). Called once per pid.</summary>
    public Func<int, string?>? ResolveName { get; init; }
}

/// <summary>
/// The process tree and the files' histories, built from the signals the host sees, for the views that
/// draw them (process map, file map, insights) and for saving a session to look at later.
///
/// Read-only to the detection engine: it never scores or acts. Fed from the host's owner thread, read
/// from the UI thread, so every entry point takes one lock and holds it briefly; reading is a copy
/// (<see cref="Snapshot"/>), cached until something changes.
///
/// Bounded on every axis, because a machine opens a hundred thousand files a minute and a session can
/// run for days: processes, files, per-file events, and the per-second counts all have caps, and what
/// the caps drop is chosen (cache churn and exited, unflagged processes first), not whatever is oldest.
/// </summary>
public sealed class ActivityModel
{
    private const long UnixEpochTicks = 621_355_968_000_000_000;

    private sealed class Proc
    {
        public int Id, Pid, ParentPid, ParentId;
        public string Name = "", Image = "", CommandLine = "", User = "";
        public DateTime Start;
        public DateTime? Exit;
        public bool PreExisting, ImagePending;
        /// <summary>Made on the spot for a pid the model had not seen start. Its own start event may still arrive: see <see cref="StartProcess"/>.</summary>
        public bool Inferred;
        public int Score, PeakScore;
        public string Level = "info", State = "";
        public bool Trusted;
        public IReadOnlyList<string> Reasons = Array.Empty<string>(), Techniques = Array.Empty<string>();
        public readonly int[] Counts = new int[ActivityKinds.Count];
    }

    private sealed class Track
    {
        public int Id;
        public string Path = "", Name = "", Folder = "", Ext = "";
        public DateTime First, Last;
        public readonly List<FileEvent> Events = new(4);
        public readonly List<int> Runners = new(2);
        public bool Created, Executed, Renamed, Deleted, Noisy;
        public MeltKind Melt;
        public string MeltNote = "";
        public int CreatorId, DeleterId;
    }

    private readonly object _gate = new();
    private readonly ActivityModelOptions _o;
    private readonly Dictionary<int, Proc> _nodes = new();
    private readonly Dictionary<int, Proc> _live = new();          // latest node per pid, exited ones included
    private readonly Dictionary<string, Track> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly SortedDictionary<long, int[]> _series = new();
    private readonly Dictionary<string, int> _destinations = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _domains = new(StringComparer.OrdinalIgnoreCase);
    private readonly long[] _totals = new long[ActivityKinds.Count];
    private readonly HashSet<int> _named = new();
    private int _nextProc, _nextFile, _melted, _flagged;
    private long _version, _cachedVersion = -1;
    private ActivitySnapshot _cached = ActivitySnapshot.Empty;
    private DateTime _first = DateTime.MaxValue, _last = DateTime.MinValue;
    private long _curSecond = long.MinValue;
    private int[]? _curBucket;
    private string _name;

    private const int MaxDestinations = 4096;

    public ActivityModel(ActivityModelOptions? options = null)
    {
        _o = options ?? new ActivityModelOptions();
        _name = _o.Name;
    }

    /// <summary>Changes whenever anything the snapshot shows changes. Cheap to read, so a view can poll it.</summary>
    public long Version => Interlocked.Read(ref _version);

    /// <summary>Totals for the sidebar badges, without building a snapshot: processes known, processes the engine scored, files that melted.</summary>
    public (int Processes, int Flagged, int Melted) Counters { get { lock (_gate) return (_nodes.Count, _flagged, _melted); } }

    public string Name { get { lock (_gate) return _name; } set { lock (_gate) { _name = value; _version++; } } }

    // ------------------------------------------------------------------ feeding

    public void Observe(Signal s)
    {
        if (s is null) return;
        lock (_gate)
        {
            try { ObserveLocked(s); }
            catch (Exception) { /* a malformed path or an odd signal must not take the host's owner thread down */ }
        }
    }

    private void ObserveLocked(Signal s)
    {
        var at = s.TimestampUtc;
        if (at < _first) _first = at;
        if (at > _last) _last = at;
        _version++;

        switch (s.Kind)
        {
            case SignalKind.ProcessStart: StartProcess(s); return;
            case SignalKind.ProcessStop: StopProcess(s); return;
            case SignalKind.FileDelete: DeleteFile(s); return;
            case SignalKind.FileRename: RenameFile(s); return;
        }

        // A directory being opened or made is not a file: nothing for the maps or the charts.
        if (s.Kind == SignalKind.FileCreate && string.Equals(s.Detail, "dir", StringComparison.Ordinal)) return;

        var kind = KindOf(s);
        var p = s.Pid > 0 ? Known(s) : null;
        Count(p, kind, at);

        switch (s.Kind)
        {
            case SignalKind.ImageLoad: LoadImage(p, s); break;
            case SignalKind.FileCreate:
                if (kind == ActivityKind.FileCreate) CreateFile(p, s);
                break;
            case SignalKind.NetworkConnect:
                if (!string.IsNullOrEmpty(s.RemoteAddress)) Tally(_destinations, $"{s.RemoteAddress}:{s.RemotePort}");
                break;
            case SignalKind.DnsQuery:
                if (!string.IsNullOrEmpty(s.Domain)) Tally(_domains, s.Domain);
                break;
        }
    }

    private static ActivityKind KindOf(Signal s) => s.Kind switch
    {
        SignalKind.ProcessStart => ActivityKind.ProcessStart,
        SignalKind.ProcessStop => ActivityKind.ProcessStop,
        SignalKind.ImageLoad => ActivityKind.ImageLoad,
        SignalKind.FileCreate => string.Equals(s.Detail, "open", StringComparison.Ordinal) ? ActivityKind.FileOpen : ActivityKind.FileCreate,
        SignalKind.FileDelete => ActivityKind.FileDelete,
        SignalKind.FileRename => ActivityKind.FileRename,
        SignalKind.NetworkConnect => ActivityKind.Network,
        SignalKind.DnsQuery => ActivityKind.Dns,
        SignalKind.RegistryWrite => ActivityKind.Registry,
        SignalKind.ProcessAccess => ActivityKind.ProcessAccess,
        SignalKind.ScriptContent => ActivityKind.Script,
        SignalKind.NamedPipe => ActivityKind.Pipe,
        SignalKind.KernelRefusal => ActivityKind.Refusal,
        _ => ActivityKind.MemoryMatch
    };

    private void Count(Proc? p, ActivityKind kind, DateTime at)
    {
        _totals[(int)kind]++;
        if (p is not null) p.Counts[(int)kind]++;
        long sec = (at.Ticks - UnixEpochTicks) / TimeSpan.TicksPerSecond;
        if (sec != _curSecond || _curBucket is null)
        {
            if (!_series.TryGetValue(sec, out var bucket))
            {
                bucket = new int[ActivityKinds.Count];
                _series[sec] = bucket;
                if (_series.Count > _o.MaxSeconds) _series.Remove(_series.First().Key);
            }
            _curSecond = sec;
            _curBucket = bucket;
        }
        _curBucket[(int)kind]++;
    }

    private static void Tally(Dictionary<string, int> map, string key)
    {
        if (map.TryGetValue(key, out var n)) map[key] = n + 1;
        else if (map.Count < MaxDestinations) map[key] = 1;
    }

    // ------------------------------------------------------------------ processes

    private string? Norm(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Trim();
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        if (_o.NormalizePath is not null) p = _o.NormalizePath(p);
        return p.Length == 0 ? null : p;
    }

    private static bool IsDosPath(string p) => p.Length > 3 && p[1] == ':' && p[2] == '\\';

    private static bool SamePath(string a, string b)
        => a.Length > 0 && b.Length > 0 && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static string FileNameOf(string path)
    {
        int i = path.LastIndexOfAny(new[] { '\\', '/' });
        return i < 0 ? path : path[(i + 1)..];
    }

    private static string FolderOf(string path)
    {
        int i = path.LastIndexOfAny(new[] { '\\', '/' });
        return i <= 0 ? "" : path[..i];
    }

    /// <summary>A name for a process the model never saw start: the system's own, else whatever the host can look up (once per pid).</summary>
    private string NameOfUnseen(int pid)
    {
        if (pid == 4) return "System";
        return _named.Add(pid) ? _o.ResolveName?.Invoke(pid) ?? "" : "";
    }

    private Proc NewProc(int pid, int parentPid, string name, string image, DateTime start, bool preExisting)
    {
        var p = new Proc
        {
            Id = ++_nextProc, Pid = pid, ParentPid = parentPid, Name = name, Image = image, Start = start,
            PreExisting = preExisting
        };
        _nodes[p.Id] = p;
        _live[pid] = p;
        if (_nodes.Count > _o.MaxProcesses) PruneProcesses();
        return p;
    }

    /// <summary>The node for a pid the signal names, made on the spot for a process that started before monitoring.</summary>
    private Proc Known(Signal s)
    {
        if (_live.TryGetValue(s.Pid, out var p))
        {
            if (p.Name.Length == 0 && !string.IsNullOrEmpty(s.ProcessName)) p.Name = s.ProcessName;
            return p;
        }
        string name = !string.IsNullOrEmpty(s.ProcessName) ? s.ProcessName : "";
        if (name.Length == 0) name = NameOfUnseen(s.Pid);
        var image = Norm(s.ImagePath) ?? "";
        var made = NewProc(s.Pid, s.ParentPid, name, image, s.TimestampUtc, preExisting: true);
        made.Inferred = true;
        return made;
    }

    /// <summary>How long after a process was first seen its own start event is still taken to be that same process.</summary>
    private static readonly TimeSpan LateStart = TimeSpan.FromSeconds(15);

    private void StartProcess(Signal s)
    {
        if (s.Pid <= 0) return;
        var image = Norm(s.ImagePath) ?? "";
        string name = !string.IsNullOrEmpty(s.ProcessName) ? s.ProcessName : FileNameOf(image);

        Proc p;
        _live.TryGetValue(s.Pid, out var old);
        // The kernel delivers a process's start event after some of its own file and image events, so a pid
        // can be seen doing things a moment before it is seen starting. That is one process, not a pid reused:
        // the node made for it on the spot takes the start event, and is no longer "before monitoring".
        if (old is { Inferred: true, Exit: null } && (s.TimestampUtc - old.Start).Duration() <= LateStart &&
            (old.Name.Length == 0 || name.Length == 0 || string.Equals(old.Name, name, StringComparison.OrdinalIgnoreCase)))
        {
            p = old;
            p.Inferred = false;
            p.PreExisting = false;
            p.ParentPid = s.ParentPid;
            if (name.Length > 0) p.Name = name;
            if (image.Length > 0) p.Image = image;
            if (s.TimestampUtc < p.Start) p.Start = s.TimestampUtc;
        }
        else
        {
            if (old is { Exit: null })
                old.Exit = s.TimestampUtc >= old.Start ? s.TimestampUtc : old.Start;   // the pid was reused: the old one is gone
            p = NewProc(s.Pid, s.ParentPid, name, image, s.TimestampUtc, preExisting: false);
        }
        p.CommandLine = s.CommandLine ?? "";
        p.User = s.User ?? "";
        p.ParentId = ParentFor(p)?.Id ?? 0;
        Count(p, ActivityKind.ProcessStart, s.TimestampUtc);

        // The kernel's start event carries only the file name; the full path arrives with the image load.
        if (IsDosPath(p.Image)) RegisterRun(p);
        else p.ImagePending = true;
    }

    private void StopProcess(Signal s)
    {
        if (s.Pid <= 0) return;
        if (_live.TryGetValue(s.Pid, out var p) && p.Exit is null && s.TimestampUtc >= p.Start.AddSeconds(-1))
        {
            p.Exit = s.TimestampUtc < p.Start ? p.Start : s.TimestampUtc;
            Count(p, ActivityKind.ProcessStop, s.TimestampUtc);
        }
        else Count(null, ActivityKind.ProcessStop, s.TimestampUtc);
    }

    /// <summary>The node that was this process's parent when it started: the live one with that pid, or a stand-in.</summary>
    private Proc? ParentFor(Proc child)
    {
        int ppid = child.ParentPid;
        if (ppid <= 0 || ppid == child.Pid) return null;
        if (_live.TryGetValue(ppid, out var parent) && parent.Id != child.Id &&
            parent.Start <= child.Start.AddSeconds(1) && (parent.Exit is null || parent.Exit >= child.Start.AddSeconds(-5)))
            return parent;
        if (_live.ContainsKey(ppid)) return null;   // the pid has since moved on to another process: no honest parent to show
        return NewProc(ppid, 0, NameOfUnseen(ppid), "", child.Start, preExisting: true);
    }

    private Proc? ParentOf(Proc p) => p.ParentId != 0 && _nodes.TryGetValue(p.ParentId, out var parent) ? parent : null;

    private void LoadImage(Proc? p, Signal s)
    {
        var path = Norm(s.FilePath);
        if (path is null) return;
        if (p is not null && p.ImagePending && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(FileNameOf(path), p.Name, StringComparison.OrdinalIgnoreCase))
        {
            p.Image = path;
            p.ImagePending = false;
            RegisterRun(p);
            return;
        }
        // A dropped module being loaded is worth a line in its history; every system DLL is not.
        if (p is not null && _files.TryGetValue(path, out var t))
            AddEvent(t, new FileEvent(s.TimestampUtc, FileOp.Loaded, s.Pid, p.Id));
    }

    private void PruneProcesses()
    {
        int target = _o.MaxProcesses * 9 / 10;
        foreach (var p in _nodes.Values.Where(p => p.Exit is not null && p.Score == 0).OrderBy(p => p.Id).ToList())
        {
            if (_nodes.Count <= target) return;
            Remove(p);
        }
        foreach (var p in _nodes.Values.Where(p => p.Exit is not null).OrderBy(p => p.Id).ToList())
        {
            if (_nodes.Count <= target) return;
            Remove(p);
        }
    }

    private void Remove(Proc p)
    {
        _nodes.Remove(p.Id);
        if (_live.TryGetValue(p.Pid, out var cur) && cur.Id == p.Id) _live.Remove(p.Pid);
    }

    // ------------------------------------------------------------------ files

    private static readonly string[] NoiseHints =
    {
        @"\cache\", @"\code cache\", @"\gpucache\", @"\inetcache\", @"\windows\prefetch\", @"\windows\winsxs\",
        @"\windows\servicing\", @"\$recycle.bin\", @"\windows\system32\logfiles\", @"\windows\logs\",
        @"\microsoft\windows\notifications\", @"\microsoft\windows defender\", @"\crashpad\", @"\service worker\",
        @"\__psscriptpolicytest_"   // PowerShell probes the execution policy with a file it makes and removes at every start
    };

    private static bool IsNoise(string path)
    {
        foreach (var hint in NoiseHints)
            if (path.Contains(hint, StringComparison.OrdinalIgnoreCase)) return true;
        return path.EndsWith(".etl", StringComparison.OrdinalIgnoreCase);
    }

    private Track? Trail(string? rawPath, DateTime at, bool create)
    {
        var path = Norm(rawPath);
        if (path is null) return null;
        if (_files.TryGetValue(path, out var t)) { if (at > t.Last) t.Last = at; return t; }
        if (!create) return null;
        if (_files.Count >= _o.MaxFiles) PruneFiles();
        t = new Track
        {
            Id = ++_nextFile, Path = path, Name = FileNameOf(path), Folder = FolderOf(path),
            Ext = System.IO.Path.GetExtension(FileNameOf(path)).ToLowerInvariant(), First = at, Last = at, Noisy = IsNoise(path)
        };
        _files[path] = t;
        return t;
    }

    private void AddEvent(Track t, FileEvent e)
    {
        if (t.Events.Count >= _o.MaxEventsPerFile)
        {
            // Keep the story: drop the oldest plain creation, else the oldest anything but the first.
            int victim = t.Events.FindIndex(x => x.Op is FileOp.Created or FileOp.Loaded);
            t.Events.RemoveAt(victim >= 0 ? victim : Math.Min(1, t.Events.Count - 1));
        }
        t.Events.Add(e);
        if (e.AtUtc > t.Last) t.Last = e.AtUtc;
    }

    private void CreateFile(Proc? p, Signal s)
    {
        var t = Trail(s.FilePath, s.TimestampUtc, create: true);
        if (t is null) return;
        // A program that opens a file for writing fifty times is one creation.
        if (t.Events.Count > 0 && t.Events[^1] is { Op: FileOp.Created } last && last.Pid == s.Pid &&
            (s.TimestampUtc - last.AtUtc).Duration() < TimeSpan.FromSeconds(2)) return;
        bool first = !t.Created;
        t.Created = true;
        if (first) t.CreatorId = p?.Id ?? 0;
        AddEvent(t, new FileEvent(s.TimestampUtc, FileOp.Created, s.Pid, p?.Id ?? 0));
    }

    private void RegisterRun(Proc p)
    {
        var t = Trail(p.Image, p.Start, create: true);
        if (t is null) return;
        t.Executed = true;
        if (t.Runners.Count < 8) t.Runners.Add(p.Id);
        AddEvent(t, new FileEvent(p.Start, FileOp.Executed, p.Pid, p.Id));
    }

    private void DeleteFile(Signal s)
    {
        var p = s.Pid > 0 ? Known(s) : null;
        var t = Trail(s.FilePath, s.TimestampUtc, create: true);
        if (t is null) { Count(p, ActivityKind.FileDelete, s.TimestampUtc); return; }
        bool onClose = string.Equals(s.Detail, "on-close", StringComparison.Ordinal);

        // The same removal reported twice: by the kernel with a process and by the folder watcher
        // without, or as delete-on-close and then as the delete. Keep the one with the name on it,
        // and count it once.
        for (int i = t.Events.Count - 1; i >= 0; i--)
        {
            var e = t.Events[i];
            if (e.Op is not (FileOp.Deleted or FileOp.DeletedOnClose)) continue;
            if ((s.TimestampUtc - e.AtUtc).Duration() > TimeSpan.FromSeconds(3)) break;
            if (e.Pid == s.Pid || s.Pid == 0)
            {
                if (onClose && e.Op == FileOp.Deleted) t.Events[i] = e with { Op = FileOp.DeletedOnClose };
                return;
            }
            if (e.Pid == 0)
            {
                t.Events[i] = e with { Op = onClose ? FileOp.DeletedOnClose : FileOp.Deleted, Pid = s.Pid, ProcId = p?.Id ?? 0 };
                t.DeleterId = p?.Id ?? 0;
                if (p is not null) p.Counts[(int)ActivityKind.FileDelete]++;
                EvaluateMelt(t, t.Events[i], p);
                return;
            }
            break;
        }

        Count(p, ActivityKind.FileDelete, s.TimestampUtc);
        t.Deleted = true;
        var ev = new FileEvent(s.TimestampUtc, onClose ? FileOp.DeletedOnClose : FileOp.Deleted, s.Pid, p?.Id ?? 0);
        AddEvent(t, ev);
        t.DeleterId = p?.Id ?? 0;
        EvaluateMelt(t, ev, p);

        // A temp file the same process made and removed within moments, of a kind nobody runs or reads (the
        // shell's jump-list temp files, say), is churn, not something that happened: it starts hidden.
        if (!t.Noisy && !t.Executed && !t.Renamed && p is not null && t.CreatorId == p.Id &&
            (s.TimestampUtc - t.First).Duration() <= TimeSpan.FromSeconds(2) &&
            !Monitoring.FileEvents.IsWatched(t.Path) && InTempArea(t.Path))
            t.Noisy = true;
    }

    private static bool InTempArea(string path)
        => path.Contains(@"\appdata\", StringComparison.OrdinalIgnoreCase) || path.Contains(@"\temp\", StringComparison.OrdinalIgnoreCase);

    private void RenameFile(Signal s)
    {
        var p = s.Pid > 0 ? Known(s) : null;
        Count(p, ActivityKind.FileRename, s.TimestampUtc);
        var t = Trail(s.FilePath, s.TimestampUtc, create: true);
        if (t is null) return;
        var to = Norm(s.Detail);
        t.Renamed = true;
        AddEvent(t, new FileEvent(s.TimestampUtc, FileOp.Renamed, s.Pid, p?.Id ?? 0, to));
        if (to is null) return;
        var moved = Trail(to, s.TimestampUtc, create: true);
        if (moved is not null)
        {
            moved.Renamed = true;
            AddEvent(moved, new FileEvent(s.TimestampUtc, FileOp.RenamedFrom, s.Pid, p?.Id ?? 0, t.Path));
            // The program that moves itself is still that program.
            if (t.Executed && !moved.Executed) { moved.Executed = true; foreach (var r in t.Runners.Take(4)) moved.Runners.Add(r); }
        }
    }

    /// <summary>Decides whether a delete is a program removing itself. Keeps the strongest verdict a file earns.</summary>
    private void EvaluateMelt(Track t, FileEvent del, Proc? actor)
    {
        if (t.Melt is MeltKind.SelfDelete or MeltKind.ChildDelete) return;
        MeltKind kind = MeltKind.None;
        string note = "";

        if (actor is not null && (SamePath(actor.Image, t.Path) || t.Runners.Contains(actor.Id)))
        {
            kind = MeltKind.SelfDelete;
            note = $"{Label(actor)} deleted its own file.";
        }
        else if (actor is not null)
        {
            var anc = ParentOf(actor);
            for (int depth = 1; depth <= 3 && anc is not null; depth++, anc = ParentOf(anc))
            {
                if (!SamePath(anc.Image, t.Path) && !t.Runners.Contains(anc.Id)) continue;
                kind = MeltKind.ChildDelete;
                note = $"{Label(actor)}, started by {Label(anc)}{(depth > 1 ? " (through a shell)" : "")}, deleted it.";
                break;
            }
        }

        if (kind == MeltKind.None)
        {
            foreach (var id in t.Runners)
            {
                if (!_nodes.TryGetValue(id, out var r)) continue;
                var until = (r.Exit ?? del.AtUtc) + _o.MeltWindow;
                if (del.AtUtc >= r.Start.AddSeconds(-1) && del.AtUtc <= until)
                {
                    kind = MeltKind.AfterRun;
                    var ran = (del.AtUtc - r.Start).Duration();
                    note = $"It ran as {Label(r)} and was deleted {Span(ran)} later" +
                           (actor is null ? "." : $", by {Label(actor)}.");
                    break;
                }
            }
        }

        if (kind != MeltKind.None)
        {
            bool wasMelted = t.Melt is MeltKind.SelfDelete or MeltKind.ChildDelete;
            t.Melt = kind;
            t.MeltNote = note;
            if (!wasMelted && kind is MeltKind.SelfDelete or MeltKind.ChildDelete) _melted++;
        }
    }

    private static string Label(Proc p) => p.Name.Length > 0 ? $"{p.Name} (pid {p.Pid})" : $"pid {p.Pid}";

    private static string Span(TimeSpan t)
        => t.TotalSeconds < 1 ? "under a second" : t.TotalMinutes < 1 ? $"{t.TotalSeconds:0} s" : $"{t.TotalMinutes:0.#} min";

    private void PruneFiles()
    {
        // Cache churn and plain creations first, oldest first; deletes, renames and runs last.
        int target = _o.MaxFiles * 9 / 10;
        foreach (var t in _files.Values
                     .OrderBy(t => t.Melt != MeltKind.None ? 3 : t.Deleted || t.Renamed || t.Executed ? 2 : t.Noisy ? 0 : 1)
                     .ThenBy(t => t.Last).ToList())
        {
            if (_files.Count <= target) return;
            _files.Remove(t.Path);
        }
    }

    // ------------------------------------------------------------------ scores

    /// <summary>
    /// Lays the engine's verdicts over the processes: score, level, reasons, ATT&amp;CK ids. The engine owns
    /// scoring and the model never computes one, so this is how a node turns amber or red.
    /// </summary>
    public void ApplyProfiles(IEnumerable<ProfileSnapshot> profiles, int containAt)
    {
        lock (_gate)
        {
            foreach (var s in profiles)
            {
                if (!_live.TryGetValue(s.Pid, out var p)) continue;
                if (p.Name.Length == 0) p.Name = s.ProcessName;
                if (p.Image.Length == 0 && !string.IsNullOrEmpty(s.ImagePath)) p.Image = Norm(s.ImagePath) ?? "";
                if (p.CommandLine.Length == 0) p.CommandLine = s.CommandLine;
                p.Score = s.Score;
                p.PeakScore = Math.Max(p.PeakScore, Math.Max(s.PeakScore, s.Score));
                p.Trusted = s.Trusted;
                p.Reasons = s.Reasons.TakeLast(8).ToArray();
                p.Techniques = s.Techniques;
                p.State = s.Terminated ? "Terminated" : s.SuspendedByAnalyst ? "Suspended"
                        : s.Contained ? (s.ContainmentSkipped ? "Would contain" : "Contained") : s.Score > 0 ? "Flagged" : "";
                p.Level = s.Terminated ? "safe" : s.Contained ? "threat" : s.Trusted ? "safe"
                        : s.Score >= containAt ? "threat" : s.Score > 0 ? "watch" : "info";
            }
            _flagged = _nodes.Values.Count(n => n.Score > 0);
            _version++;
        }
    }

    // ------------------------------------------------------------------ reading

    public void Reset()
    {
        lock (_gate)
        {
            _nodes.Clear(); _live.Clear(); _files.Clear(); _series.Clear(); _destinations.Clear(); _domains.Clear();
            _named.Clear();
            Array.Clear(_totals);
            _first = DateTime.MaxValue; _last = DateTime.MinValue;
            _curSecond = long.MinValue; _curBucket = null;
            _nextProc = _nextFile = _melted = _flagged = 0;
            _version++;
        }
    }

    /// <summary>A frozen copy of everything, cached until the model changes.</summary>
    public ActivitySnapshot Snapshot()
    {
        lock (_gate)
        {
            if (_cachedVersion == _version) return _cached;
            var procs = _nodes.Values.OrderBy(p => p.Id).Select(p => new ProcessInfo
            {
                Id = p.Id, Pid = p.Pid, ParentPid = p.ParentPid, ParentId = p.ParentId, Name = p.Name, Image = p.Image,
                CommandLine = p.CommandLine, User = p.User, StartUtc = p.Start, ExitUtc = p.Exit, PreExisting = p.PreExisting,
                Score = p.Score, PeakScore = p.PeakScore, Level = p.Level, State = p.State, Trusted = p.Trusted,
                Reasons = p.Reasons, Techniques = p.Techniques, Counts = (int[])p.Counts.Clone()
            }).ToArray();

            var files = _files.Values.Where(Worth).OrderBy(t => t.First).Select(t => new FileTrail
            {
                Id = t.Id, Path = t.Path, Name = t.Name, Folder = t.Folder, Ext = t.Ext, FirstUtc = t.First, LastUtc = t.Last,
                Events = t.Events.ToArray(), Created = t.Created, Executed = t.Executed, Renamed = t.Renamed, Deleted = t.Deleted,
                Melt = t.Melt, MeltNote = t.MeltNote, CreatorId = t.CreatorId, DeleterId = t.DeleterId,
                RunnerId = t.Runners.Count > 0 ? t.Runners[0] : 0, Noisy = t.Noisy
            }).ToArray();

            var series = _series.Select(kv => new SeriesPoint(kv.Key, (int[])kv.Value.Clone())).ToArray();
            _cached = new ActivitySnapshot
            {
                Name = _name, Source = "live", Version = _version,
                StartedUtc = _first == DateTime.MaxValue ? default : _first,
                EndedUtc = _last == DateTime.MinValue ? default : _last,
                Processes = procs, Files = files, Series = series,
                Destinations = Top(_destinations, 200), Domains = Top(_domains, 200), Totals = (long[])_totals.Clone()
            };
            _cachedVersion = _version;
            return _cached;
        }
    }

    /// <summary>Only a file that has a story is worth a row: it was made, moved or removed. A program's own image is a node in the process tree already.</summary>
    private static bool Worth(Track t) => t.Created || t.Deleted || t.Renamed;

    private static IReadOnlyList<Destination> Top(Dictionary<string, int> map, int n)
        => map.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
              .Take(n).Select(kv => new Destination(kv.Key, kv.Value)).ToArray();
}
