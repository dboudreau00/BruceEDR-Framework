using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using BruceEDR.Configuration;
using BruceEDR.Detection;
using BruceEDR.Gui.Services;

namespace BruceEDR.Gui.ViewModels;

/// <summary>One editable watchlist row.</summary>
public sealed class WatchRow : ViewModelBase
{
    private string _value = "";
    private string _match = "name";
    private string _action = "quarantine";
    private int _score = 50;
    private string _note = "";
    private bool _enabled = true;

    /// <summary>
    /// ATT&amp;CK ids the operator attached to this entry. The editor has no UI for them, so
    /// they are carried through verbatim -- without this, opening the tab and pressing Save
    /// silently stripped the techniques off every hand-authored entry.
    /// </summary>
    public string[] Techniques { get; set; } = Array.Empty<string>();

    /// <summary>The name / path / hash / command-line fragment to look for.</summary>
    public string Value { get => _value; set { if (Set(ref _value, value)) Revalidate(); } }
    public string Match { get => _match; set { if (Set(ref _match, value)) Revalidate(); } }
    public string Action
    {
        get => _action;
        set { if (Set(ref _action, value)) { OnPropertyChanged(nameof(IsScoreAction)); Revalidate(); } }
    }
    public int Score { get => _score; set => Set(ref _score, Math.Clamp(value, 0, 100)); }
    public string Note { get => _note; set => Set(ref _note, value); }
    public bool Enabled { get => _enabled; set => Set(ref _enabled, value); }

    /// <summary>Points only matter for the <c>score</c> action; the field is hidden otherwise.</summary>
    public bool IsScoreAction => string.Equals(_action, "score", StringComparison.OrdinalIgnoreCase);

    private string _problem = "";
    /// <summary>Why this entry would be rejected, or "" when it compiles cleanly.</summary>
    public string Problem { get => _problem; private set { if (Set(ref _problem, value)) OnPropertyChanged(nameof(HasProblem)); } }
    public bool HasProblem => _problem.Length > 0;

    private string _warning = "";
    /// <summary>Non-fatal caution, e.g. aiming containment at a protected Windows process.</summary>
    public string Warning { get => _warning; private set { if (Set(ref _warning, value)) OnPropertyChanged(nameof(HasWarning)); } }
    public bool HasWarning => _warning.Length > 0;

    public WatchRow() { }

    public WatchRow(WatchlistEntryConfig c)
    {
        _value = c.Value ?? "";
        _match = (c.Match ?? "name").ToLowerInvariant();
        _action = (c.Action ?? "quarantine").ToLowerInvariant();
        _score = Math.Clamp(c.Score, 0, 100);
        _note = c.Note ?? "";
        _enabled = c.Enabled;
        Techniques = c.Techniques ?? Array.Empty<string>();
        Revalidate();
    }

    public WatchlistEntryConfig ToConfig() => new()
    {
        Value = Value.Trim(),
        Match = Match,
        Action = Action,
        Score = Score,
        Note = Note.Trim(),
        Techniques = Techniques,
        Enabled = Enabled,
    };

    /// <summary>
    /// Compiles this single row through the real <see cref="Watchlist"/> compiler, so the
    /// editor rejects exactly what the engine would reject -- no second, drifting copy of
    /// the validation rules.
    /// </summary>
    public void Revalidate()
    {
        Problem = "";
        Warning = "";

        if (Value.Trim().Length == 0) { Problem = "Enter a value."; return; }

        // Validate the row as if it were enabled, so a disabled row still shows its errors
        // instead of looking clean until the day someone switches it on.
        var probe = ToConfig();
        probe.Enabled = true;

        string? err = null;
        var compiled = Watchlist.Compile(new[] { probe }, m => err ??= m);
        if (compiled.Count == 0)
        {
            // Strip the compiler's "entry 'x' skipped: " prefix for a tidier inline message.
            int colon = err?.IndexOf(": ", StringComparison.Ordinal) ?? -1;
            Problem = colon >= 0 ? char.ToUpperInvariant(err![colon + 2]) + err[(colon + 3)..] : (err ?? "Invalid entry.");
            return;
        }

        if (IsScoreAction && Score == 0)
            Warning = "Zero points does nothing on its own; the hit is still reported.";
        else if (string.Equals(Action, "quarantine", StringComparison.OrdinalIgnoreCase)
                 && Watchlist.IsProtected(Value))
            Warning = "Protected Windows process. BruceEDR will report it but refuse to contain it.";
        else if (string.Equals(Action, "allow", StringComparison.OrdinalIgnoreCase)
                 && string.Equals(Match, "path", StringComparison.OrdinalIgnoreCase)
                 && Driver.KernelPolicy.WriteRisk(Value.Trim()) is not null)
            Warning = "A standard user could put another file at this path and it would be allowed too. Allow it by hash instead.";
    }
}

/// <summary>
/// Editor for the operator watchlist. Reads and writes the same bruce.config.json the
/// engine hot-reloads, so saving here arms the entry within a second or two — no restart.
/// </summary>
public sealed class WatchlistViewModel : ViewModelBase
{
    private readonly string _configPath;
    private BruceConfig _config = new();

    public ObservableCollection<WatchRow> Rows { get; } = new();

    /// <summary>Match kinds offered in the row editor. Values are what the config expects.</summary>
    public string[] MatchKinds { get; } = { "name", "path", "hash", "cmdline" };
    public string[] Actions { get; } = { "quarantine", "warn", "score", "allow" };

    public WatchlistViewModel(string configPath)
    {
        _configPath = configPath;
        AddCommand = new RelayCommand(Add);
        RemoveCommand = new RelayCommandP(p => Remove(p as WatchRow));
        SaveCommand = new RelayCommand(Save);
        ReloadCommand = new RelayCommand(ReloadFromDisk);
        Rows.CollectionChanged += (_, e) =>
        {
            foreach (WatchRow r in e.NewItems ?? Array.Empty<WatchRow>())
                r.PropertyChanged += (_, pe) =>
                {
                    if (pe.PropertyName is nameof(WatchRow.Action) or nameof(WatchRow.Enabled))
                        OnPropertyChanged(nameof(ContainCount));
                };
        };
    }

    public ICommand AddCommand { get; }
    public ICommand RemoveCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand ReloadCommand { get; }

    public void LoadFrom(BruceConfig c)
    {
        _config = c;
        Rows.Clear();
        foreach (var e in c.Watchlist.Entries ?? Array.Empty<WatchlistEntryConfig>())
            Rows.Add(new WatchRow(e));

        Enabled = c.Watchlist.Enabled;
        AlertOnEveryHit = c.Watchlist.AlertOnEveryHit;
        Message = "";
        ArmedCount = c.Watchlist.Enabled ? Rows.Count(r => r.Enabled) : 0;
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(ContainCount));
    }

    private void Add()
    {
        Rows.Add(new WatchRow());
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(ContainCount));
    }

    private void Remove(WatchRow? row)
    {
        if (row is null) return;
        Rows.Remove(row);
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(ContainCount));
    }

    private void ReloadFromDisk()
    {
        try
        {
            LoadFrom(ConfigLoader.Load(_configPath));
            Message = "Reloaded from disk.";
        }
        catch (Exception ex)
        {
            AppLog.Error("watchlist reload", ex);
            Message = "Reload failed: " + ex.Message;
        }
    }

    private void Save()
    {
        try
        {
            foreach (var r in Rows) r.Revalidate();
            var bad = Rows.Count(r => r.HasProblem);
            if (bad > 0)
            {
                Message = $"{bad} entr{(bad == 1 ? "y" : "ies")} still invalid. Fix or remove them first.";
                return;
            }

            // Containment on sight is destructive and easy to mistype, so name the count
            // and make the operator confirm rather than burying it behind a Save button.
            var containing = Rows.Where(r => r.Enabled &&
                string.Equals(r.Action, "quarantine", StringComparison.OrdinalIgnoreCase)).ToList();
            int contain = containing.Count;
            if (contain > 0)
            {
                // Name every entry with its match KIND. "windows" as a name is one process;
                // "windows" as a path fragment is most of the machine, and the operator has
                // to see which one they are about to arm.
                string listing = string.Join("\n", containing.Take(12).Select(r => $"    {r.Match}: {r.Value}"));
                if (contain > 12) listing += $"\n    ... and {contain - 12} more";
                bool enforcing;
                try { enforcing = ConfigLoader.Load(_configPath).Response.IsEnforcing; }
                catch { enforcing = true; }   // unreadable: describe the worst case
                var answer = MessageBox.Show(
                    $"{contain} entr{(contain == 1 ? "y is" : "ies are")} set to CONTAIN ON SIGHT:\n\n{listing}\n\n" +
                    (enforcing
                        ? "Any process matching one will be suspended and network-blocked immediately, " +
                          "even if it is signed by a trusted publisher."
                        : "Monitor mode is on, so a match is reported as 'would contain' and nothing is " +
                          "suspended. Once you switch to enforce, matches are suspended and network-blocked " +
                          "immediately, even if signed by a trusted publisher.") +
                    "\n\nArm the watchlist?",
                    "Confirm watchlist", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes) { Message = "Not saved."; return; }
            }

            // Read-modify-write against the file, NOT against the snapshot this editor was
            // opened with. Two editors (Settings and Watchlist) each hold their own config
            // object loaded from the same path; saving a stale snapshot would silently roll
            // back whatever the other one had already written.
            var onDisk = ConfigLoader.Load(_configPath);
            onDisk.Watchlist.Enabled = Enabled;
            onDisk.Watchlist.AlertOnEveryHit = AlertOnEveryHit;
            onDisk.Watchlist.Entries = Rows.Select(r => r.ToConfig()).ToArray();

            ConfigLoader.Save(onDisk, _configPath);
            _config = onDisk;
            LoadFrom(_config);
            Message = Enabled
                ? "Saved. The watchlist is armed within a couple of seconds, no restart needed."
                : "Saved. The watchlist is turned off.";
        }
        catch (Exception ex)
        {
            AppLog.Error("watchlist save", ex);
            Message = "Save failed: " + ex.Message;
        }
    }

    /// <summary>
    /// Adds an allow entry for one program and saves it at once: the dashboard's Allow button. A program
    /// in a folder only administrators can write to is allowed by its path, which survives its updates.
    /// Anything else is allowed by the SHA-256 of the file as it is now, because a standard user could put
    /// another file at that path and it must not inherit the allowance. Other rows being edited here are
    /// left as they are; the new entry is written to the file directly.
    /// </summary>
    public (bool Ok, string Message) AllowProgram(string imagePath, string name)
    {
        try
        {
            if (!Path.IsPathFullyQualified(imagePath) || !File.Exists(imagePath))
                return (false, $"Not allowed: {name}'s file could not be found, so there is nothing exact to allow.");

            bool adminOnly = Driver.KernelPolicy.WriteRisk(imagePath) is null;
            string match = adminOnly ? "path" : "hash";
            string value = adminOnly ? imagePath : Sha256(imagePath);

            var onDisk = ConfigLoader.Load(_configPath);
            var entries = (onDisk.Watchlist.Entries ?? Array.Empty<WatchlistEntryConfig>()).ToList();
            if (entries.Any(e => e.Enabled
                                 && string.Equals(e.Action, "allow", StringComparison.OrdinalIgnoreCase)
                                 && string.Equals(e.Match, match, StringComparison.OrdinalIgnoreCase)
                                 && string.Equals(e.Value, value, StringComparison.OrdinalIgnoreCase)))
                return (true, $"{name} is already allowed.");

            var entry = new WatchlistEntryConfig
            {
                Match = match, Value = value, Action = "allow", Score = 0, Enabled = true,
                Note = adminOnly
                    ? $"Allowed from the dashboard on {DateTime.Now:yyyy-MM-dd}"
                    : $"{imagePath}, allowed from the dashboard on {DateTime.Now:yyyy-MM-dd}",
            };
            entries.Add(entry);
            onDisk.Watchlist.Entries = entries.ToArray();
            ConfigLoader.Save(onDisk, _configPath);
            _config = onDisk;

            Rows.Add(new WatchRow(entry));
            ArmedCount = onDisk.Watchlist.Enabled ? onDisk.Watchlist.Entries.Count(e => e.Enabled) : 0;
            OnPropertyChanged(nameof(IsEmpty));

            string how = adminOnly ? "by its path" : "by the file's SHA-256, so it needs allowing again after an update";
            return (true, onDisk.Watchlist.Enabled
                ? $"{name} is allowed {how}. Undo it on the Watchlist tab."
                : $"{name} is allowed {how}, but the watchlist is turned off, so the entry is not in force yet. Turn it on in the Watchlist tab.");
        }
        catch (Exception ex)
        {
            AppLog.Error("allow program", ex);
            return (false, "Not allowed: " + ex.Message);
        }
    }

    private static string Sha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).ToLowerInvariant();
    }

    private bool _enabled = true;
    public bool Enabled { get => _enabled; set => Set(ref _enabled, value); }

    private bool _alertOnEveryHit = true;
    public bool AlertOnEveryHit { get => _alertOnEveryHit; set => Set(ref _alertOnEveryHit, value); }

    public bool IsEmpty => Rows.Count == 0;

    private int _armedCount;
    /// <summary>Entries armed in the saved config, for the sidebar badge.</summary>
    public int ArmedCount { get => _armedCount; private set => Set(ref _armedCount, value); }

    public int ContainCount => Rows.Count(r => r.Enabled && string.Equals(r.Action, "quarantine", StringComparison.OrdinalIgnoreCase));

    private string _message = "";
    public string Message { get => _message; set { if (Set(ref _message, value)) OnPropertyChanged(nameof(MessageIsError)); } }
    public bool MessageIsError => _message.StartsWith("Not saved", StringComparison.Ordinal)
                               || _message.StartsWith("Save failed", StringComparison.Ordinal)
                               || _message.StartsWith("Reload failed", StringComparison.Ordinal)
                               || _message.Contains("still invalid", StringComparison.Ordinal);
}
