namespace BruceEDR.Activity;

/// <summary>What a count in the activity views counts. File opens and creates are separate: opens are
/// the bulk of a machine's file traffic and the file views are about what was made, moved or removed.</summary>
public enum ActivityKind : byte
{
    ProcessStart,
    ProcessStop,
    ImageLoad,
    FileCreate,
    FileOpen,
    FileDelete,
    FileRename,
    Network,
    Dns,
    Registry,
    ProcessAccess,
    Script,
    Pipe,
    Refusal,
    MemoryMatch
}

public static class ActivityKinds
{
    public static readonly int Count = Enum.GetValues<ActivityKind>().Length;

    public static string Label(ActivityKind k) => k switch
    {
        ActivityKind.ProcessStart => "Process start",
        ActivityKind.ProcessStop => "Process exit",
        ActivityKind.ImageLoad => "Module load",
        ActivityKind.FileCreate => "File created",
        ActivityKind.FileOpen => "File opened",
        ActivityKind.FileDelete => "File deleted",
        ActivityKind.FileRename => "File renamed",
        ActivityKind.Network => "Network",
        ActivityKind.Dns => "DNS",
        ActivityKind.Registry => "Registry",
        ActivityKind.ProcessAccess => "Process access",
        ActivityKind.Script => "Script",
        ActivityKind.Pipe => "Named pipe",
        ActivityKind.Refusal => "Kernel refusal",
        ActivityKind.MemoryMatch => "Memory match",
        _ => k.ToString()
    };
}

/// <summary>What happened to a file, as seen.</summary>
public enum FileOp : byte
{
    Created,
    Renamed,
    RenamedFrom,
    Deleted,
    DeletedOnClose,
    Executed,
    Loaded
}

/// <summary>
/// Whether a deleted program removed itself, which malware builders call "melting". A program cannot
/// normally delete the file it is running from, so the real thing is done by delete-on-close, by a
/// rename trick, or by a child (<c>cmd /c ping ... &amp; del</c>) that outlives it.
/// </summary>
public enum MeltKind : byte
{
    None,
    /// <summary>The running program deleted its own image.</summary>
    SelfDelete,
    /// <summary>A process the program started (usually cmd.exe) deleted it.</summary>
    ChildDelete,
    /// <summary>It ran, and something else deleted it within minutes. Weaker: an installer's cleanup looks the same.</summary>
    AfterRun
}

public sealed record FileEvent(DateTime AtUtc, FileOp Op, int Pid, int ProcId, string? Other = null);

/// <summary>One process as the activity model knows it. <see cref="ParentId"/> is the node that was the
/// parent when this one started (0 for none); pids are reused, node ids are not.</summary>
public sealed record ProcessInfo
{
    public int Id { get; init; }
    public int Pid { get; init; }
    public int ParentPid { get; init; }
    public int ParentId { get; init; }
    public string Name { get; init; } = "";
    public string Image { get; init; } = "";
    public string CommandLine { get; init; } = "";
    public string User { get; init; } = "";
    public DateTime StartUtc { get; init; }
    public DateTime? ExitUtc { get; init; }
    /// <summary>Seen only through its telemetry or as someone's parent: it started before monitoring.</summary>
    public bool PreExisting { get; init; }
    public int Score { get; init; }
    public int PeakScore { get; init; }
    /// <summary>safe | info | watch | threat, the colour the views use.</summary>
    public string Level { get; init; } = "info";
    public string State { get; init; } = "";
    public bool Trusted { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();
    /// <summary>Counts per <see cref="ActivityKind"/>, indexed by its value.</summary>
    public IReadOnlyList<int> Counts { get; init; } = Array.Empty<int>();

    public bool Exited => ExitUtc.HasValue;
    public bool Flagged => Score > 0 || Level == "threat" || Level == "watch";
    public int Count(ActivityKind k) => (int)k < Counts.Count ? Counts[(int)k] : 0;
}

/// <summary>One file the model followed: when it was made, run, moved, removed.</summary>
public sealed record FileTrail
{
    public int Id { get; init; }
    public string Path { get; init; } = "";
    public string Name { get; init; } = "";
    public string Folder { get; init; } = "";
    public string Ext { get; init; } = "";
    public DateTime FirstUtc { get; init; }
    public DateTime LastUtc { get; init; }
    public IReadOnlyList<FileEvent> Events { get; init; } = Array.Empty<FileEvent>();
    public bool Created { get; init; }
    public bool Executed { get; init; }
    public bool Renamed { get; init; }
    public bool Deleted { get; init; }
    public MeltKind Melt { get; init; }
    /// <summary>One sentence on why the file counts as melted, for the detail panel.</summary>
    public string MeltNote { get; init; } = "";
    /// <summary>The process (node id) that made the file, 0 when unknown.</summary>
    public int CreatorId { get; init; }
    /// <summary>The process (node id) that deleted it, 0 when unknown.</summary>
    public int DeleterId { get; init; }
    /// <summary>The process (node id) that ran it, 0 when it never did.</summary>
    public int RunnerId { get; init; }
    /// <summary>Cache and churn folders: kept in counts, hidden from the file views unless asked for.</summary>
    public bool Noisy { get; init; }

    public bool IsMelted => Melt is MeltKind.SelfDelete or MeltKind.ChildDelete;
    /// <summary>Made by one process, run later: dropped, whether or not it was meant to be.</summary>
    public bool Dropped => Created && Executed;
}

public sealed record SeriesPoint(long Second, IReadOnlyList<int> Counts);

public sealed record Destination(string Name, int Count);

/// <summary>Everything the activity views draw, frozen: the live model hands one out per refresh, a saved
/// session or an opened trace is one.</summary>
public sealed record ActivitySnapshot
{
    public const int CurrentFormat = 1;

    public int Format { get; init; } = CurrentFormat;
    public string Name { get; init; } = "";
    /// <summary>live | session | trace: where it came from, for the banner above the views.</summary>
    public string Source { get; init; } = "live";
    public long Version { get; init; }
    public DateTime StartedUtc { get; init; }
    public DateTime EndedUtc { get; init; }
    public IReadOnlyList<ProcessInfo> Processes { get; init; } = Array.Empty<ProcessInfo>();
    public IReadOnlyList<FileTrail> Files { get; init; } = Array.Empty<FileTrail>();
    /// <summary>Counts per second, oldest first; the charts rebin it to whatever width they need.</summary>
    public IReadOnlyList<SeriesPoint> Series { get; init; } = Array.Empty<SeriesPoint>();
    public IReadOnlyList<Destination> Destinations { get; init; } = Array.Empty<Destination>();
    public IReadOnlyList<Destination> Domains { get; init; } = Array.Empty<Destination>();
    /// <summary>Signals seen per kind over the whole session, including what the caps dropped from the lists.</summary>
    public IReadOnlyList<long> Totals { get; init; } = Array.Empty<long>();

    public static ActivitySnapshot Empty { get; } = new();

    public bool IsEmpty => Processes.Count == 0 && Files.Count == 0 && Series.Count == 0;
    public long Total(ActivityKind k) => (int)k < Totals.Count ? Totals[(int)k] : 0;
    public TimeSpan Span => EndedUtc > StartedUtc ? EndedUtc - StartedUtc : TimeSpan.Zero;
}
