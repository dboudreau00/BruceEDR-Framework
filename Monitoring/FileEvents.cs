namespace BruceEDR.Monitoring;

/// <summary>
/// The decisions the file monitors make, apart from the ETW and FileSystemWatcher plumbing, so
/// they can be tested without a trace session.
/// </summary>
public static class FileEvents
{
    /// <summary>NT <c>FILE_DELETE_ON_CLOSE</c>: the file goes when its last handle closes.</summary>
    public const uint DeleteOnClose = 0x0000_1000;

    /// <summary>
    /// Detail of a <see cref="Core.SignalKind.FileCreate"/> from the kernel: <c>create</c> when the
    /// open makes the file or replaces its content (supersede, create-new, truncate, create-always),
    /// else <c>open</c>. Open-always is left as <c>open</c>: the event cannot say whether the file
    /// already existed, and calling every one a creation would flood the file views with reads.
    /// The numbers are the NT dispositions, which TraceEvent names after their Win32 equivalents.
    /// </summary>
    public static string CreateDetail(int disposition) => disposition is 0 or 2 or 4 or 5 ? "create" : "open";

    public static bool IsDeleteOnClose(uint createOptions) => (createOptions & DeleteOnClose) != 0;

    private static readonly HashSet<string> WatchedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".jar",
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk",
        ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".iso", ".img",
        ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".pdf"
    };

    /// <summary>
    /// Whether the folder watcher reports a delete or rename of this file. The watcher cannot say who
    /// did it, so it stays to the kinds of file an intrusion drops, runs or stages; the kernel
    /// monitor, which names the process, reports every delete.
    /// </summary>
    public static bool IsWatched(string? path)
        => !string.IsNullOrEmpty(path) && WatchedExtensions.Contains(Path.GetExtension(path));
}

/// <summary>
/// Remembers the name each file object was opened under. The kernel's delete and rename events
/// carry the file object and not always a name, but the open that made the object did, so the
/// monitor keeps the last names it saw and looks them up when a delete arrives.
///
/// Direct-mapped and lock-free on purpose: this sits on the path of every file open on the machine.
/// A collision overwrites the older entry, which costs a missing name for a file object that has been
/// quiet while 65,536 others were opened, the same trade the kernel's own name tables make.
/// </summary>
public sealed class FileNameCache
{
    private readonly ulong[] _keys;
    private readonly string?[] _names;
    private readonly int _mask;

    public FileNameCache(int slots = 1 << 16)
    {
        if (slots < 2 || (slots & (slots - 1)) != 0) throw new ArgumentException("slots must be a power of two", nameof(slots));
        _keys = new ulong[slots];
        _names = new string?[slots];
        _mask = slots - 1;
    }

    private int Slot(ulong fileObject) => (int)((fileObject >> 4) * 0x9E3779B1UL >> 8) & _mask;

    public void Put(ulong fileObject, string? name)
    {
        if (fileObject == 0 || string.IsNullOrEmpty(name)) return;
        int i = Slot(fileObject);
        _names[i] = name;
        _keys[i] = fileObject;
    }

    /// <summary>The name last stored for this file object, or null.</summary>
    public string? Get(ulong fileObject)
    {
        if (fileObject == 0) return null;
        int i = Slot(fileObject);
        var name = _names[i];
        return name is not null && _keys[i] == fileObject ? name : null;
    }
}
