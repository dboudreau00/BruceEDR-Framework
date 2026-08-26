using System.IO;

namespace BruceEDR.Gui.Services;

/// <summary>
/// Minimal, crash-proof file logger so beta testers can share what went wrong.
/// Writes to %LOCALAPPDATA%\BruceEDR\gui.log (falls back next to the exe).
/// Every method swallows its own errors - logging must never take the app down.
/// </summary>
public static class AppLog
{
    private static readonly object Gate = new();
    public static string LogPath { get; } = BuildPath();

    private static string BuildPath()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "BruceEDR");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "gui.log");
        }
        catch
        {
            try { return Path.Combine(AppContext.BaseDirectory, "gui.log"); }
            catch { return "gui.log"; }
        }
    }

    public static void Info(string message) => Write("INFO", message);

    public static void Error(string context, Exception ex) => Write("ERROR", context + " :: " + ex);

    private static void Write(string level, string message)
    {
        try
        {
            lock (Gate)
                File.AppendAllText(LogPath,
                    $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}");
        }
        catch { /* logging is best-effort */ }
    }
}
