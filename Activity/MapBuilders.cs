using System.Globalization;

namespace BruceEDR.Activity;

public enum ProcessFilter { Flagged, Live, All }

public sealed class ProcessMapOptions
{
    /// <summary>Flagged: what the engine scored, what dropped or removed a file, and the lineage around it.</summary>
    public ProcessFilter Filter { get; init; } = ProcessFilter.Flagged;
    /// <summary>Matches name, command line, image path or pid; shows the matches with their ancestors and descendants.</summary>
    public string Search { get; init; } = "";
    /// <summary>Show the tree as it stood at this moment (the scrubber). Null: as it is now.</summary>
    public DateTime? AtUtc { get; init; }
    public int MaxNodes { get; init; } = 1500;
    /// <summary>A node with more children than this starts collapsed, unless something flagged is under it.</summary>
    public int AutoCollapseOver { get; init; } = 10;
    public IReadOnlySet<string>? Collapsed { get; init; }
    public IReadOnlySet<string>? Expanded { get; init; }
}

public sealed record MapResult(MapNode Root, int Shown, int Total, string Note);

/// <summary>Builds the process-lineage mind map from a snapshot.</summary>
public static class ProcessMapBuilder
{
    public static string KeyOf(int id) => "p" + id.ToString(CultureInfo.InvariantCulture);

    public static MapResult Build(ActivitySnapshot snap, ProcessMapOptions? options = null)
    {
        var o = options ?? new ProcessMapOptions();
        var all = snap.Processes;
        var byId = all.ToDictionary(p => p.Id);
        var kids = all.Where(p => p.ParentId != 0 && byId.ContainsKey(p.ParentId))
                      .GroupBy(p => p.ParentId).ToDictionary(g => g.Key, g => g.OrderBy(p => p.StartUtc).ThenBy(p => p.Id).ToList());

        bool AliveAt(ProcessInfo p) => o.AtUtc is not { } at || (p.StartUtc <= at && (p.ExitUtc is null || p.ExitUtc >= at));

        var pool = all.Where(AliveAt).ToList();
        var chosen = new HashSet<int>();
        string note = "";
        string needle = o.Search.Trim();

        if (needle.Length > 0)
        {
            foreach (var p in pool.Where(p => Matches(p, needle)))
            {
                chosen.Add(p.Id);
                foreach (var d in Descendants(p.Id, kids)) chosen.Add(d);
            }
            if (chosen.Count == 0) note = $"No process matches \"{needle}\".";
        }
        else if (o.Filter == ProcessFilter.All) foreach (var p in pool) chosen.Add(p.Id);
        else if (o.Filter == ProcessFilter.Live) foreach (var p in pool.Where(p => p.ExitUtc is null)) chosen.Add(p.Id);
        else
        {
            var related = FileRelated(snap);
            foreach (var p in pool.Where(p => p.Flagged || related.Contains(p.Id)))
            {
                chosen.Add(p.Id);
                // What a flagged process started is the other half of the story, a few at a time.
                if (kids.TryGetValue(p.Id, out var started))
                    foreach (var c in started.Where(AliveAt).Take(8)) chosen.Add(c.Id);
            }
            if (chosen.Count == 0)
            {
                note = pool.Count == 0 ? "" : "Nothing is flagged, so this shows every process.";
                foreach (var p in pool) chosen.Add(p.Id);
            }
        }

        // Ancestors, so a chosen process is never an orphan floating off the root. They may be gone by now.
        foreach (var id in chosen.ToList())
            for (var up = byId.GetValueOrDefault(id); up is not null && up.ParentId != 0; up = byId.GetValueOrDefault(up.ParentId))
                chosen.Add(up.ParentId);

        int total = all.Count;
        var nodes = new Dictionary<int, MapNode>();
        foreach (var id in chosen.Where(byId.ContainsKey).OrderBy(id => byId[id].StartUtc).ThenBy(id => id))
            nodes[id] = NodeFor(byId[id], o.AtUtc);

        var root = new MapNode { Key = "root", Kind = MapKind.Root, Label = "This computer", Mark = "PC", Level = "info" };
        int budget = Math.Max(10, o.MaxNodes);
        var order = nodes.Values.OrderBy(n => ((ProcessInfo)n.Tag!).StartUtc).ThenBy(n => ((ProcessInfo)n.Tag!).Id).ToList();
        foreach (var n in order)
        {
            var p = (ProcessInfo)n.Tag!;
            var parent = p.ParentId != 0 && nodes.TryGetValue(p.ParentId, out var pn) ? pn : root;
            parent.Add(n);
        }
        if (nodes.Count > budget)
        {
            Trim(root, budget);
            note = $"Showing {budget:N0} of {nodes.Count:N0} processes. Search or filter to narrow it.";
        }

        Collapse(root, o, needle.Length > 0);
        root.Sub = $"{root.Count() - 1:N0} process{(root.Count() == 2 ? "" : "es")}";
        return new MapResult(root, root.Count() - 1, total, note);
    }

    private static HashSet<int> FileRelated(ActivitySnapshot snap)
    {
        var ids = new HashSet<int>();
        foreach (var f in snap.Files.Where(f => f.Melt != MeltKind.None || f.Dropped))
        {
            if (f.CreatorId != 0) ids.Add(f.CreatorId);
            if (f.RunnerId != 0) ids.Add(f.RunnerId);
            if (f.DeleterId != 0) ids.Add(f.DeleterId);
        }
        return ids;
    }

    private static IEnumerable<int> Descendants(int id, Dictionary<int, List<ProcessInfo>> kids)
    {
        if (!kids.TryGetValue(id, out var list)) yield break;
        foreach (var c in list)
        {
            yield return c.Id;
            foreach (var d in Descendants(c.Id, kids)) yield return d;
        }
    }

    private static bool Matches(ProcessInfo p, string needle)
        => p.Name.Contains(needle, StringComparison.OrdinalIgnoreCase)
        || p.CommandLine.Contains(needle, StringComparison.OrdinalIgnoreCase)
        || p.Image.Contains(needle, StringComparison.OrdinalIgnoreCase)
        || p.Pid.ToString(CultureInfo.InvariantCulture).Equals(needle, StringComparison.Ordinal);

    public static MapNode NodeFor(ProcessInfo p, DateTime? at = null)
    {
        string name = p.Name.Length > 0 ? p.Name : $"pid {p.Pid}";
        var sub = new List<string> { $"pid {p.Pid}" };
        if (p.PreExisting) sub.Add("before monitoring");
        else sub.Add(p.StartUtc.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture));
        bool gone = p.ExitUtc is { } exit && (at is null || exit <= at);
        if (gone && !p.PreExisting) sub.Add("ran " + Duration(p.ExitUtc!.Value - p.StartUtc));
        else if (gone) sub.Add("exited");
        return new MapNode
        {
            Key = KeyOf(p.Id), Kind = MapKind.Process, Label = name, Sub = string.Join(" · ", sub),
            Mark = name.Length > 0 && char.IsLetterOrDigit(name[0]) ? char.ToUpperInvariant(name[0]).ToString() : "?",
            Level = p.Level, Ghost = gone, Badge = p.Score > 0 ? p.Score.ToString(CultureInfo.InvariantCulture) : "", Tag = p
        };
    }

    private static void Trim(MapNode root, int budget)
    {
        int seen = 0;
        var queue = new Queue<MapNode>();
        queue.Enqueue(root);
        while (queue.Count > 0)
        {
            var n = queue.Dequeue();
            var keep = new List<MapNode>();
            foreach (var c in n.Children.ToList())
            {
                if (seen < budget) { seen++; keep.Add(c); queue.Enqueue(c); }
            }
            foreach (var c in n.Children.Except(keep).ToList()) n.Children.Remove(c);
        }
    }

    private static void Collapse(MapNode root, ProcessMapOptions o, bool searching)
    {
        foreach (var n in root.Walk(includeHidden: true))
        {
            if (n.Kind != MapKind.Process || n.Children.Count == 0) continue;
            if (o.Collapsed?.Contains(n.Key) == true) n.Collapsed = true;
            else if (o.Expanded?.Contains(n.Key) == true) n.Collapsed = false;
            else if (!searching && n.Children.Count > o.AutoCollapseOver && !n.Walk(includeHidden: true).Any(d => d != n && FlaggedNode(d)))
                n.Collapsed = true;
        }
    }

    private static bool FlaggedNode(MapNode n) => n.Level is "threat" or "watch";

    public static string Duration(TimeSpan t)
        => t.TotalSeconds < 1 ? "under a second" : t.TotalMinutes < 1 ? $"{t.TotalSeconds:0.#} s"
         : t.TotalHours < 1 ? $"{t.TotalMinutes:0.#} min" : $"{t.TotalHours:0.#} h";
}

public enum FileFate { Melted, AfterRun, Dropped, Deleted, Renamed, Created }

public enum FileGroupBy { Operation, Process, Folder }

[Flags]
public enum FileFilter
{
    Melted = 1, AfterRun = 2, Dropped = 4, Deleted = 8, Renamed = 16, Created = 32,
    Default = Melted | AfterRun | Dropped | Deleted | Renamed,
    All = Default | Created
}

public sealed class FileMapOptions
{
    public FileGroupBy GroupBy { get; init; } = FileGroupBy.Operation;
    public FileFilter Filter { get; init; } = FileFilter.Default;
    /// <summary>Show cache and churn folders too.</summary>
    public bool ShowNoise { get; init; }
    public string Search { get; init; } = "";
    /// <summary>Files shown under a group before "+N more".</summary>
    public int MaxPerGroup { get; init; } = 24;
    /// <summary>Only files this process (node id) made, ran, moved or deleted. 0: all.</summary>
    public int FocusProcessId { get; init; }
    /// <summary>Group keys the user opened to see every file.</summary>
    public IReadOnlySet<string>? Expanded { get; init; }
    /// <summary>Group keys the user folded.</summary>
    public IReadOnlySet<string>? Collapsed { get; init; }
}

public sealed record FileCounts(int Melted, int AfterRun, int Dropped, int Deleted, int Renamed, int Created, int Noisy)
{
    public int Total => Melted + AfterRun + Dropped + Deleted + Renamed + Created;
}

/// <summary>Builds the file-activity mind map and what it says about a file.</summary>
public static class FileMapBuilder
{
    public static FileFate FateOf(FileTrail f)
        => f.IsMelted ? FileFate.Melted
         : f.Melt == MeltKind.AfterRun ? FileFate.AfterRun
         : f.Deleted ? FileFate.Deleted
         : f.Dropped ? FileFate.Dropped
         // The old name carries the rename ("renamed to x"); the name it moved to is just a file that appeared.
         : f.Events.Any(e => e.Op == FileOp.Renamed) ? FileFate.Renamed
         : FileFate.Created;

    public static string LevelOf(FileFate fate) => fate switch
    {
        FileFate.Melted => "ember",
        FileFate.AfterRun => "watch",
        FileFate.Dropped => "drop",
        FileFate.Deleted => "deleted",
        FileFate.Renamed => "renamed",
        _ => "created"
    };

    public static string Title(FileFate fate) => fate switch
    {
        FileFate.Melted => "Melted",
        FileFate.AfterRun => "Ran, then deleted",
        FileFate.Dropped => "Created, then run",
        FileFate.Deleted => "Deleted",
        FileFate.Renamed => "Renamed or moved",
        _ => "Created"
    };

    public static string Explain(FileFate fate) => fate switch
    {
        FileFate.Melted => "programs that removed themselves",
        FileFate.AfterRun => "run, and deleted soon after",
        FileFate.Dropped => "made by one program, run by another",
        FileFate.Deleted => "removed",
        FileFate.Renamed => "moved or given another name",
        _ => "made or overwritten"
    };

    private static FileFilter FlagOf(FileFate fate) => fate switch
    {
        FileFate.Melted => FileFilter.Melted, FileFate.AfterRun => FileFilter.AfterRun, FileFate.Dropped => FileFilter.Dropped,
        FileFate.Deleted => FileFilter.Deleted, FileFate.Renamed => FileFilter.Renamed, _ => FileFilter.Created
    };

    public static FileCounts Count(ActivitySnapshot snap)
    {
        int[] n = new int[6];
        int noisy = 0;
        foreach (var f in snap.Files)
        {
            if (f.Noisy) { noisy++; continue; }
            n[(int)FateOf(f)]++;
        }
        return new FileCounts(n[(int)FileFate.Melted], n[(int)FileFate.AfterRun], n[(int)FileFate.Dropped],
            n[(int)FileFate.Deleted], n[(int)FileFate.Renamed], n[(int)FileFate.Created], noisy);
    }

    public static string KeyOf(FileTrail f) => "f" + f.Id.ToString(CultureInfo.InvariantCulture);

    public static MapResult Build(ActivitySnapshot snap, FileMapOptions? options = null)
    {
        var o = options ?? new FileMapOptions();
        var procs = snap.Processes.ToDictionary(p => p.Id);
        string needle = o.Search.Trim();

        var files = snap.Files.Where(f =>
            (o.ShowNoise || !f.Noisy) &&
            (o.Filter & FlagOf(FateOf(f))) != 0 &&
            (o.FocusProcessId == 0 || Involves(f, o.FocusProcessId)) &&
            (needle.Length == 0 || f.Path.Contains(needle, StringComparison.OrdinalIgnoreCase))).ToList();

        var root = new MapNode { Key = "root", Kind = MapKind.Root, Label = "File activity", Mark = "◎", Level = "info" };
        switch (o.GroupBy)
        {
            case FileGroupBy.Process: ByProcess(root, files, procs, o); break;
            case FileGroupBy.Folder: ByFolder(root, files, procs, o); break;
            default: ByOperation(root, files, procs, o); break;
        }
        foreach (var g in root.Children)
        {
            g.Level = Strongest(g);
            g.Collapsed = o.Collapsed?.Contains(g.Key) == true;
        }

        root.Sub = $"{files.Count:N0} file{(files.Count == 1 ? "" : "s")}";
        string note = files.Count == 0
            ? snap.Files.Count == 0 ? "No file was made, moved or removed yet." : "Nothing matches these filters."
            : "";
        return new MapResult(root, files.Count, snap.Files.Count, note);
    }

    private static bool Involves(FileTrail f, int procId)
        => f.CreatorId == procId || f.RunnerId == procId || f.DeleterId == procId || f.Events.Any(e => e.ProcId == procId);

    private static string Strongest(MapNode group)
    {
        string[] order = { "ember", "watch", "drop", "deleted", "renamed", "created" };
        foreach (var level in order)
            if (group.Children.Any(c => c.Level == level)) return level;
        return group.Level;
    }

    private static void ByOperation(MapNode root, List<FileTrail> files, Dictionary<int, ProcessInfo> procs, FileMapOptions o)
    {
        foreach (FileFate fate in Enum.GetValues<FileFate>())
        {
            var members = files.Where(f => FateOf(f) == fate).OrderByDescending(f => f.LastUtc).ToList();
            if (members.Count == 0) continue;
            var g = root.Add(new MapNode
            {
                Key = "g:" + fate, Kind = MapKind.Group, Label = Title(fate), Mark = members.Count.ToString(CultureInfo.InvariantCulture),
                Sub = Explain(fate), Level = LevelOf(fate), Tag = fate, Melt = fate == FileFate.Melted
            });
            Fill(g, members, procs, o);
        }
    }

    private static void ByProcess(MapNode root, List<FileTrail> files, Dictionary<int, ProcessInfo> procs, FileMapOptions o)
    {
        var groups = files.GroupBy(f => ActorOf(f, procs)).OrderByDescending(g => g.Count(f => f.IsMelted))
                          .ThenByDescending(g => g.Count()).ToList();
        foreach (var grp in groups)
        {
            var members = grp.OrderByDescending(f => FateOf(f) == FileFate.Melted).ThenByDescending(f => f.LastUtc).ToList();
            MapNode g;
            if (grp.Key != 0 && procs.TryGetValue(grp.Key, out var p))
                g = root.Add(new MapNode
                {
                    Key = "g:p" + p.Id, Kind = MapKind.Group, Label = p.Name.Length > 0 ? p.Name : $"pid {p.Pid}",
                    Mark = p.Name.Length > 0 ? char.ToUpperInvariant(p.Name[0]).ToString() : "?",
                    Sub = $"pid {p.Pid} · {members.Count} file{(members.Count == 1 ? "" : "s")}", Tag = p, Level = p.Level, Ghost = p.ExitUtc.HasValue
                });
            else
                g = root.Add(new MapNode
                {
                    Key = "g:none", Kind = MapKind.Group, Label = "Unattributed", Mark = "?",
                    Sub = $"folder watcher, no process · {members.Count}", Tag = null
                });
            Fill(g, members, procs, o);
        }
    }

    private static void ByFolder(MapNode root, List<FileTrail> files, Dictionary<int, ProcessInfo> procs, FileMapOptions o)
    {
        var groups = files.GroupBy(f => f.Folder, StringComparer.OrdinalIgnoreCase).OrderByDescending(g => g.Count(f => f.IsMelted))
                          .ThenByDescending(g => g.Count()).ToList();
        foreach (var grp in groups.Take(20))
        {
            var members = grp.OrderByDescending(f => FateOf(f) == FileFate.Melted).ThenByDescending(f => f.LastUtc).ToList();
            var g = root.Add(new MapNode
            {
                Key = "g:d:" + grp.Key.ToLowerInvariant(), Kind = MapKind.Group, Label = ShortFolder(grp.Key), Mark = "▭",
                Sub = $"{members.Count} file{(members.Count == 1 ? "" : "s")}", Tag = grp.Key
            });
            Fill(g, members, procs, o);
        }
        var rest = groups.Skip(20).SelectMany(g => g).OrderByDescending(f => f.LastUtc).ToList();
        if (rest.Count > 0)
        {
            var g = root.Add(new MapNode { Key = "g:d:other", Kind = MapKind.Group, Label = "Other folders", Mark = "▭", Sub = $"{rest.Count} files in {groups.Count - 20} more" });
            Fill(g, rest, procs, o);
        }
    }

    private static int ActorOf(FileTrail f, Dictionary<int, ProcessInfo> procs)
    {
        foreach (var id in new[] { f.RunnerId, f.DeleterId, f.CreatorId })
            if (id != 0 && procs.ContainsKey(id)) return id;
        var last = f.Events.LastOrDefault(e => e.ProcId != 0 && procs.ContainsKey(e.ProcId));
        return last?.ProcId ?? 0;
    }

    private static void Fill(MapNode group, List<FileTrail> members, Dictionary<int, ProcessInfo> procs, FileMapOptions o)
    {
        bool all = o.Expanded?.Contains(group.Key) == true;
        foreach (var f in members.Take(all ? int.MaxValue : o.MaxPerGroup)) group.Add(LeafFor(f, procs));
        if (!all && members.Count > o.MaxPerGroup)
            group.Add(new MapNode
            {
                Key = group.Key + ":more", Kind = MapKind.More, Label = $"+{members.Count - o.MaxPerGroup} more", Mark = "…",
                Sub = "double-click to show all", Level = group.Level, Tag = group.Key
            });
    }

    public static MapNode LeafFor(FileTrail f, Dictionary<int, ProcessInfo> procs)
    {
        var fate = FateOf(f);
        return new MapNode
        {
            Key = KeyOf(f), Kind = MapKind.File, Label = f.Name, Sub = ShortStory(f, fate, procs),
            Mark = f.Ext.Length > 1 ? f.Ext[1..Math.Min(f.Ext.Length, 4)].ToUpperInvariant() : "·",
            Level = LevelOf(fate), Ghost = f.Deleted && fate != FileFate.Melted, Melt = fate == FileFate.Melted,
            Strike = f.Deleted && fate != FileFate.Melted, Tag = f
        };
    }

    private static string Who(int id, Dictionary<int, ProcessInfo> procs)
        => id != 0 && procs.TryGetValue(id, out var p) ? (p.Name.Length > 0 ? p.Name : $"pid {p.Pid}") : "";

    private static string ShortStory(FileTrail f, FileFate fate, Dictionary<int, ProcessInfo> procs)
    {
        string by = Who(f.DeleterId, procs);
        return fate switch
        {
            FileFate.Melted => by.Length > 0 ? "melted by " + by : "melted",
            FileFate.AfterRun => by.Length > 0 ? "ran, deleted by " + by : "ran, then deleted",
            FileFate.Dropped => "made by " + (Who(f.CreatorId, procs) is { Length: > 0 } c ? c : "?") + ", run as " + (Who(f.RunnerId, procs) is { Length: > 0 } r ? r : "?"),
            FileFate.Deleted => by.Length > 0 ? "deleted by " + by : "deleted",
            FileFate.Renamed => f.Events.LastOrDefault(e => e.Op == FileOp.Renamed)?.Other is { Length: > 0 } to
                ? "renamed to " + to[(to.LastIndexOfAny(new[] { '\\', '/' }) + 1)..] : "renamed",
            _ => Who(f.CreatorId, procs) is { Length: > 0 } maker ? "created by " + maker : "created"
        };
    }

    public static string ShortFolder(string folder)
    {
        if (string.IsNullOrEmpty(folder)) return "(root)";
        var parts = folder.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length <= 2 ? folder : "…\\" + string.Join("\\", parts[^2..]);
    }
}

/// <summary>One line of a file's history for the detail panel.</summary>
public sealed record StoryLine(DateTime AtUtc, string Text, string Level);

public static class FileStory
{
    public static IReadOnlyList<StoryLine> Lines(FileTrail f, IReadOnlyList<ProcessInfo> processes)
    {
        var procs = processes.ToDictionary(p => p.Id);
        string Who(int id, int pid)
        {
            if (id != 0 && procs.TryGetValue(id, out var p)) return $"{(p.Name.Length > 0 ? p.Name : "process")} (pid {p.Pid})";
            return pid > 0 ? $"pid {pid}" : "an unknown process (the folder watcher cannot say who)";
        }

        var lines = new List<StoryLine>();
        foreach (var e in f.Events.OrderBy(e => e.AtUtc))
        {
            string text = e.Op switch
            {
                FileOp.Created => $"Created by {Who(e.ProcId, e.Pid)}",
                FileOp.Executed => $"Run as {Who(e.ProcId, e.Pid)}",
                FileOp.Loaded => $"Loaded as a module by {Who(e.ProcId, e.Pid)}",
                FileOp.Renamed => e.Other is { Length: > 0 } to ? $"Renamed to {to} by {Who(e.ProcId, e.Pid)}" : $"Renamed by {Who(e.ProcId, e.Pid)}",
                FileOp.RenamedFrom => $"Moved here from {e.Other} by {Who(e.ProcId, e.Pid)}",
                _ => $"Deleted by {Who(e.ProcId, e.Pid)}"
            };
            string level = e.Op switch
            {
                FileOp.Deleted or FileOp.DeletedOnClose => f.IsMelted ? "ember" : "deleted",
                FileOp.Executed => "watch",
                FileOp.Created => "created",
                _ => "renamed"
            };
            lines.Add(new StoryLine(e.AtUtc, text, level));
        }
        return lines;
    }
}
