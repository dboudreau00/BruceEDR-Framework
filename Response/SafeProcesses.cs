using System.Text.Json;

namespace BruceEDR.Response;

/// <summary>
/// Programs the agent never suspends, firewalls or kills, read from every *.json file in
/// <c>response.safeProcessesPath</c> (the safe-processes folder beside the agent). Detection still
/// scores and reports them; only the response is withheld, by <see cref="ContainmentGuard"/>.
///
/// An entry is a full image path (environment variables expand), never a name: a name is anyone's
/// to use. The guard honours an entry only for the real file (no account other than SYSTEM,
/// Administrators or TrustedInstaller could replace it) running under a service account, so a copy
/// a user starts and hollows out is still contained. A list file a non-administrator could edit is
/// not loaded at all, and script hosts are refused outright: everything a listed powershell.exe ran
/// would be beyond containment.
/// </summary>
public sealed class SafeProcesses
{
    public static SafeProcesses Empty { get; } = new(Array.Empty<string>());

    /// <summary>Programs that run whatever they are given inside their own process.</summary>
    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "powershell_ise.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
        "rundll32.exe", "regsvr32.exe", "dllhost.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
        "regsvcs.exe", "wmic.exe", "python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe",
    };

    private readonly HashSet<string> _images;

    private SafeProcesses(IEnumerable<string> images) => _images = new(images, StringComparer.OrdinalIgnoreCase);

    public int Count => _images.Count;

    public IReadOnlyCollection<string> Images => _images;

    /// <summary>True when the image path, expanded and made full, is on the list.</summary>
    public bool Contains(string? imagePath) => Normalize(imagePath) is { } path && _images.Contains(path);

    /// <summary>
    /// Loads every *.json file in <paramref name="directory"/>, in name order. <paramref name="writeRisk"/>
    /// is null for a file only administrators can change; any other file is skipped and noted.
    /// </summary>
    public static SafeProcesses Load(string directory, Func<string, string?> writeRisk, Action<string> note)
    {
        var images = new List<string>();
        foreach (var file in Directory.GetFiles(directory, "*.json").Order(StringComparer.OrdinalIgnoreCase))
        {
            string name = Path.GetFileName(file);
            if (writeRisk(file) is { } risk)
            {
                note($"{name} not loaded: {risk}");
                continue;
            }
            try { images.AddRange(Parse(name, File.ReadAllText(file), note)); }
            catch (IOException ex) { note($"{name} not loaded: {ex.Message}"); }
            catch (UnauthorizedAccessException ex) { note($"{name} not loaded: {ex.Message}"); }
        }
        return new SafeProcesses(images);
    }

    internal static SafeProcesses Of(params string[] images) => new(images.Select(Normalize).OfType<string>());

    /// <summary>The image paths of one list file: <c>{ "processes": [ { "image": "...", "why": "..." } ] }</c>.</summary>
    internal static IReadOnlyList<string> Parse(string source, string json, Action<string> note)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
        }
        catch (JsonException ex)
        {
            note($"{source} not loaded: not valid JSON ({ex.Message})");
            return Array.Empty<string>();
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object ||
                !doc.RootElement.TryGetProperty("processes", out var list) || list.ValueKind != JsonValueKind.Array)
            {
                note($"{source} not loaded: it has no \"processes\" array");
                return Array.Empty<string>();
            }

            var found = new List<string>();
            foreach (var entry in list.EnumerateArray())
            {
                string? image = entry.ValueKind == JsonValueKind.Object &&
                                entry.TryGetProperty("image", out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString()
                    : null;
                var path = Normalize(image);
                if (path is null)
                {
                    note($"{source}: an entry is not a full image path ({image ?? "none"}); ignored");
                    continue;
                }
                if (ScriptHosts.Contains(Path.GetFileName(path)))
                {
                    note($"{source}: {path} runs whatever it is given, so it can never be safe; ignored");
                    continue;
                }
                found.Add(path);
            }
            return found;
        }
    }

    /// <summary>Environment variables expanded, then the full path; null unless that is fully qualified.</summary>
    internal static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        string expanded = Environment.ExpandEnvironmentVariables(path.Trim());
        if (expanded.Contains('%') || !Path.IsPathFullyQualified(expanded)) return null;
        try { return Path.GetFullPath(expanded); }
        catch (Exception) { return null; }
    }
}
