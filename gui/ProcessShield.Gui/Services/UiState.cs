using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcessShield.Gui.Services;

/// <summary>
/// Small persisted bag of interface preferences (window placement, last tab, tray
/// behaviour). Lives next to the GUI log in %LOCALAPPDATA%\ProcessShield, NOT in
/// shield.config.json: these are per-analyst conveniences, not detection posture,
/// and must never dirty the engine config file.
/// Load/save are best-effort — a corrupt or missing file just means defaults.
/// </summary>
public sealed class UiState
{
    public double WindowLeft { get; set; } = double.NaN;
    public double WindowTop { get; set; } = double.NaN;
    public double WindowWidth { get; set; }
    public double WindowHeight { get; set; }
    public bool WindowMaximized { get; set; }
    public int LastTabIndex { get; set; }
    public bool MinimizeToTray { get; set; } = true;

    [JsonIgnore]
    public static string FilePath { get; } = BuildPath();

    private static string BuildPath()
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "ProcessShield");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "ui-state.json");
        }
        catch
        {
            try { return Path.Combine(AppContext.BaseDirectory, "ui-state.json"); }
            catch { return "ui-state.json"; }
        }
    }

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        // Tolerate hand-edits and forward/backward version drift.
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static UiState Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<UiState>(File.ReadAllText(FilePath), Options) ?? new UiState();
        }
        catch (Exception ex) { AppLog.Error("ui-state load", ex); }
        return new UiState();
    }

    public void Save()
    {
        try { File.WriteAllText(FilePath, JsonSerializer.Serialize(this, Options)); }
        catch (Exception ex) { AppLog.Error("ui-state save", ex); }
    }
}
