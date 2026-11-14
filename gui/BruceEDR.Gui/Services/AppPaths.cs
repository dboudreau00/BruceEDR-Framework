using System.IO;

namespace BruceEDR.Gui.Services;

/// <summary>Where the desktop app keeps per-analyst data: %LOCALAPPDATA%\BruceEDR.</summary>
public static class AppPaths
{
    private static string? _root;

    /// <summary>The offscreen harness points this at a throwaway folder before building the window.</summary>
    public static string DataRoot
    {
        get => _root ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "BruceEDR");
        set => _root = value;
    }

    public static string TriageRoot => Path.Combine(DataRoot, "triage");
    public static string KeyRoot => Path.Combine(DataRoot, "assistant");
}
