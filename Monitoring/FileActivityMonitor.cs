using BruceEDR.Core;

namespace BruceEDR.Monitoring;

/// <summary>
/// Watches common staging directories for archive creation. Complements ETW and
/// still works when ETW is unavailable. FileSystemWatcher cannot attribute the
/// writing process, so emitted signals carry Pid = 0 and the engine correlates
/// them by time against recently-flagged processes.
///
/// Hardening: skips missing/duplicate directories, guards each callback, handles
/// the watcher Error event (internal buffer overflow), and throws from Start only
/// if nothing at all could be watched (so the host can note the degraded state).
/// </summary>
public sealed class FileActivityMonitor : IDisposable
{
    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private readonly List<FileSystemWatcher> _watchers = new();

    public FileActivityMonitor(Action<Signal> emit, Logger log)
    {
        _emit = emit;
        _log = log;
    }

    public void Start()
    {
        foreach (var dir in CandidateDirectories())
        {
            try
            {
                var w = new FileSystemWatcher(dir)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                    EnableRaisingEvents = true
                };
                w.Created += OnChanged;
                w.Renamed += OnChanged;
                w.Error += OnError;
                _watchers.Add(w);
            }
            catch (Exception ex)
            {
                _log.Error($"watch '{dir}'", ex);
            }
        }

        if (_watchers.Count == 0)
            throw new InvalidOperationException("no staging directories could be watched");
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        try
        {
            var ext = Path.GetExtension(e.FullPath);
            bool isArchive = Array.Exists(
                IocDatabase.ArchiveExtensions,
                x => string.Equals(x, ext, StringComparison.OrdinalIgnoreCase));
            if (!isArchive) return;

            _emit(new Signal
            {
                Kind = SignalKind.FileCreate,
                Pid = 0,
                FilePath = e.FullPath,
                Detail = "archive-in-staging"
            });
        }
        catch (Exception ex)
        {
            _log.Error("file event", ex);
        }
    }

    private void OnError(object sender, ErrorEventArgs e)
    {
        var ex = e.GetException();
        // The watcher's buffer overflowed and Windows DROPPED creates it never delivered.
        // Say what that means -- archive staging in that window went unseen -- instead of
        // a generic "file watcher" error that reads like a hiccup.
        if (ex is InternalBufferOverflowException)
            _log.Error("file watcher overflow: file creations were DROPPED (staged archives in that " +
                       "window were not seen); a build or indexer is flooding a watched directory", ex);
        else
            _log.Error("file watcher", ex);
    }

    private static IEnumerable<string> CandidateDirectories()
    {
        // Normalize + de-dupe, then keep a directory only if it is NOT nested under
        // another kept directory. Each watcher uses IncludeSubdirectories=true, so a
        // child (e.g. %TEMP%, under LocalAppData) would otherwise be covered twice and
        // every archive would fire two identical Pid=0 signals -> double scoring.
        var dirs = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in Enumerate())
        {
            if (string.IsNullOrEmpty(d)) continue;
            string full;
            try { full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(d)); }
            catch { continue; }
            if (Directory.Exists(full) && seen.Add(full)) dirs.Add(full);
        }

        foreach (var d in dirs)
            if (!dirs.Any(other => !ReferenceEquals(other, d) && IsUnder(d, other)))
                yield return d;

        static bool IsUnder(string child, string parent) =>
            child.StartsWith(parent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

        static IEnumerable<string> Enumerate()
        {
            yield return Path.GetTempPath();
            yield return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            yield return Environment.GetEnvironmentVariable("ProgramData") ?? "";
            yield return @"C:\Users\Public";
        }
    }

    public void Dispose()
    {
        foreach (var w in _watchers)
        {
            try { w.EnableRaisingEvents = false; w.Dispose(); } catch { }
        }
        _watchers.Clear();
    }
}
