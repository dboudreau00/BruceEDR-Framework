namespace BruceEDR.Detection;

/// <summary>
/// Decides whether a file sits in a folder that belongs to the process touching it: an Electron or
/// WebView program keeps its cookies, logins and local state in <c>AppData\Roaming\&lt;its name&gt;</c>, and
/// only it reads them. The store rules cannot tell that from an infostealer reading someone else's
/// browser, so they ask here.
///
/// It is by name: a folder under AppData or ProgramData whose name is the program's own name (or the
/// name of the folder it is installed in). A program that reads a folder named after a different
/// program, or after a browser, is not exempt. A stealer named after the folder it reads is, but only
/// for a folder that is its own.
/// </summary>
public static class OwnStores
{
    // Folder names that say nothing about who owns them, and the ones a browser or Windows uses.
    private static readonly HashSet<string> Generic = new(StringComparer.Ordinal)
    {
        "users", "user", "appdata", "local", "locallow", "roaming", "programdata", "temp", "tmp", "windows", "microsoft", "google",
        "mozilla", "chrome", "chromium", "edge", "brave", "opera", "firefox", "default", "profile", "profiles", "network", "cache",
        "data", "userdata", "cookies", "storage", "program", "programs", "files", "application", "applications", "bin", "app",
        "system32", "syswow64", "public", "packages", "crashpad", "logs", "config", "settings",
    };

    private static readonly string[] Roots = { "appdata", "programdata" };

    /// <summary>True when <paramref name="filePath"/> lies under an AppData or ProgramData folder named after this process.</summary>
    public static bool IsOwn(string? processName, string? imagePath, string? filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;
        var keys = OwnerKeys(processName, imagePath);
        if (keys.Count == 0) return false;

        var segments = filePath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
        int root = -1;
        for (int i = 0; i < segments.Length; i++)
            if (Array.IndexOf(Roots, segments[i].ToLowerInvariant()) >= 0) { root = i; break; }
        if (root < 0) return false;

        // The folder is named by what follows the root, past "Roaming" or "Local" (AppData\Roaming\Example Bot).
        // The last segment is the file; a program is not "owner" of a file only because it is named like it.
        for (int i = root + 1; i < segments.Length - 1; i++)
        {
            string key = Key(segments[i]);
            if (key.Length < 4 || Generic.Contains(key)) continue;
            if (keys.Contains(key)) return true;
        }
        return false;
    }

    /// <summary>The process's own name, and the folder it is installed in, normalised.</summary>
    private static HashSet<string> OwnerKeys(string? processName, string? imagePath)
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);
        Add(Path.GetFileNameWithoutExtension(processName ?? ""));
        if (!string.IsNullOrEmpty(imagePath))
        {
            Add(Path.GetFileNameWithoutExtension(imagePath));
            // The install folder, unless it is a generic one such as "bin" or "Application".
            Add(Path.GetFileName(Path.GetDirectoryName(imagePath.TrimEnd('\\', '/')) ?? ""));
        }
        return keys;

        void Add(string name)
        {
            string key = Key(name);
            if (key.Length >= 4 && !Generic.Contains(key)) keys.Add(key);
        }
    }

    /// <summary>Lower case letters and digits only, so "Example Bot", "example-bot" and "ExampleBot" are one name.</summary>
    internal static string Key(string name)
    {
        var sb = new System.Text.StringBuilder(name.Length);
        foreach (char c in name)
            if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
        return sb.ToString();
    }
}
