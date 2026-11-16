using System.IO.Compression;
using System.Text.Json;
using BruceEDR.Replay;
using BruceEDR.Security;

namespace BruceEDR.Activity;

/// <summary>One saved session in the list the views offer, read from a small side file so the list
/// never has to unpack the sessions themselves.</summary>
public sealed record SessionEntry
{
    public string Name { get; init; } = "";
    public string Path { get; init; } = "";
    public DateTime SavedUtc { get; init; }
    public DateTime StartedUtc { get; init; }
    public DateTime EndedUtc { get; init; }
    public int Processes { get; init; }
    public int Flagged { get; init; }
    public int Files { get; init; }
    public int Melted { get; init; }
    public long SizeBytes { get; init; }

    public TimeSpan Span => EndedUtc > StartedUtc ? EndedUtc - StartedUtc : TimeSpan.Zero;

    /// <summary>When it was saved, in local time, for the list.</summary>
    public string SavedText => SavedUtc.ToLocalTime().ToString("d MMM HH:mm");

    /// <summary>What is in it, in a line.</summary>
    public string Summary
    {
        get
        {
            var parts = new List<string> { $"{Processes:N0} processes" };
            if (Flagged > 0) parts.Add($"{Flagged} flagged");
            if (Melted > 0) parts.Add($"{Melted} melted");
            if (Span.TotalSeconds >= 1) parts.Add(ProcessMapBuilder.Duration(Span));
            return string.Join(" · ", parts);
        }
    }
}

/// <summary>
/// Saved sessions: the process tree, the files' histories and the activity counts of a run, written when
/// monitoring stops so they can be opened and looked at later. Also turns a replay trace into the same
/// thing, so an old trace and an old session open the same way.
///
/// A session holds command lines and paths, so the folder is locked to SYSTEM, Administrators and the
/// account that made it, like the incident store. Gzip-compressed JSON, written to a temporary name and
/// moved into place, so a crash mid-save leaves the previous sessions and no half file.
/// </summary>
public static class SessionStore
{
    public const string Extension = ".bruce-session.gz";
    private const string MetaExtension = ".meta.json";

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Saves a snapshot and keeps only the newest <paramref name="keep"/> sessions. Returns the path.
    /// The folder must not be, or sit behind, a junction or symbolic link, and every file is
    /// created and deleted through a handle whose final path was checked: the agent saves here as
    /// SYSTEM and the desktop app elevated, and both used to follow a link planted in the
    /// folder's place. <paramref name="requireAdministrativeOwner"/> also refuses a folder (or
    /// its parent) that a standard user owns, which is how a ProgramData folder created by a
    /// user ahead of the agent looks.
    /// </summary>
    public static string Save(string directory, ActivitySnapshot snapshot, int keep = 30, string? label = null,
        bool requireAdministrativeOwner = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(snapshot);
        SafePaths.RequirePrivateDirectory(directory, requireAdministrativeOwner);

        var when = snapshot.EndedUtc == default ? DateTime.UtcNow : snapshot.EndedUtc;
        string stem = $"{when.ToLocalTime():yyyy-MM-dd_HHmmss}{(string.IsNullOrWhiteSpace(label) ? "" : "_" + Slug(label))}";
        string path = System.IO.Path.Combine(directory, stem + Extension);
        for (int n = 2; File.Exists(path); n++) path = System.IO.Path.Combine(directory, $"{stem}-{n}{Extension}");

        var saved = snapshot with { Source = "session", Name = string.IsNullOrWhiteSpace(label) ? snapshot.Name : label!.Trim() };
        using (var buffer = new MemoryStream())
        {
            using (var gz = new GZipStream(buffer, CompressionLevel.Optimal, leaveOpen: true))
                JsonSerializer.Serialize(gz, saved, Json);
            // Written in place under its unique name: a temp file renamed over the target was
            // a second path-based step a swapped folder could redirect.
            SecretFiles.CreateProtected(path, buffer.ToArray());
        }

        var meta = new SessionEntry
        {
            Name = saved.Name, SavedUtc = DateTime.UtcNow, StartedUtc = saved.StartedUtc, EndedUtc = saved.EndedUtc,
            Processes = saved.Processes.Count, Flagged = saved.Processes.Count(p => p.Flagged),
            Files = saved.Files.Count, Melted = saved.Files.Count(f => f.IsMelted)
        };
        try { SecretFiles.CreateProtected(path + MetaExtension, JsonSerializer.SerializeToUtf8Bytes(meta, Json)); }
        catch { /* the list falls back to the file name; the session itself is saved */ }

        Prune(directory, keep);
        return path;
    }

    public static ActivitySnapshot Load(string path)
    {
        using var file = File.OpenRead(path);
        using var gz = new GZipStream(file, CompressionMode.Decompress);
        ActivitySnapshot? s;
        try { s = JsonSerializer.Deserialize<ActivitySnapshot>(gz, Json); }
        catch (JsonException ex) { throw new InvalidDataException("the file is not a BruceEDR session: " + ex.Message, ex); }
        if (s is null) throw new InvalidDataException("the file holds no session");
        if (s.Format > ActivitySnapshot.CurrentFormat)
            throw new InvalidDataException($"this session was saved by a newer BruceEDR (format {s.Format})");
        return s with { Source = "session", Name = s.Name.Length > 0 ? s.Name : System.IO.Path.GetFileName(path) };
    }

    /// <summary>The sessions in a folder, newest first. A missing folder is an empty list.</summary>
    public static IReadOnlyList<SessionEntry> List(string directory)
    {
        if (!Directory.Exists(directory)) return Array.Empty<SessionEntry>();
        var entries = new List<SessionEntry>();
        foreach (var path in Directory.EnumerateFiles(directory, "*" + Extension))
        {
            try
            {
                var info = new System.IO.FileInfo(path);
                SessionEntry? meta = null;
                if (File.Exists(path + MetaExtension))
                    meta = JsonSerializer.Deserialize<SessionEntry>(File.ReadAllBytes(path + MetaExtension), Json);
                entries.Add((meta ?? new SessionEntry { Name = System.IO.Path.GetFileNameWithoutExtension(info.Name) }) with
                {
                    Path = path, SizeBytes = info.Length, SavedUtc = meta?.SavedUtc is { } d && d != default ? d : info.LastWriteTimeUtc
                });
            }
            catch { /* a file that is not ours, or half written: not listed */ }
        }
        return entries.OrderByDescending(e => e.SavedUtc).ToArray();
    }

    public static void Delete(string path)
    {
        SafePaths.DeleteFile(path);
        SafePaths.DeleteFile(path + MetaExtension);
    }

    /// <summary>Replays a trace file into a fresh model and freezes it: every signal in the file, in order.</summary>
    public static ActivitySnapshot FromTrace(string path, ActivityModelOptions? options = null)
    {
        var scenario = TraceFormat.Load(path);
        var model = new ActivityModel(options) { Name = string.IsNullOrWhiteSpace(scenario.Name) ? System.IO.Path.GetFileNameWithoutExtension(path) : scenario.Name };
        foreach (var step in scenario.Events) model.Observe(step.Signal);
        return model.Snapshot() with { Source = "trace" };
    }

    private static void Prune(string directory, int keep)
    {
        foreach (var old in List(directory).Skip(Math.Max(1, keep)))
        {
            try { Delete(old.Path); } catch { /* in use or protected: next save tries again */ }
        }
    }

    private static string Slug(string s)
    {
        var chars = s.Trim().Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        var slug = new string(chars).Trim('-');
        while (slug.Contains("--")) slug = slug.Replace("--", "-");
        return slug.Length > 40 ? slug[..40] : slug;
    }
}
