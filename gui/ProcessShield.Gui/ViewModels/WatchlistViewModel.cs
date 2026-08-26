using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using ProcessShield.Configuration;
using ProcessShield.Detection;
using ProcessShield.Gui.Services;

namespace ProcessShield.Gui.ViewModels;

/// <summary>One editable watchlist row.</summary>
public sealed class WatchRow : ViewModelBase
{
    private string _value = "";
    private string _match = "name";
    private string _action = "quarantine";
    private int _score = 50;
    private string _note = "";
    private bool _enabled = true;

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
        Revalidate();
    }

    public WatchlistEntryConfig ToConfig() => new()
    {
        Value = Value.Trim(),
        Match = Match,
        Action = Action,
        Score = Score,
        Note = Note.Trim(),
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
            Warning = "Protected Windows process — ProcessShield will report it but refuse to contain it.";
    }
}

/// <summary>
/// Editor for the operator watchlist. Reads and writes the same shield.config.json the
/// engine hot-reloads, so saving here arms the entry within a second or two — no restart.
/// </summary>
public sealed class WatchlistViewModel : ViewModelBase
{
    private readonly string _configPath;
    private ShieldConfig _config = new();

    public ObservableCollection<WatchRow> Rows { get; } = new();

    /// <summary>Match kinds offered in the row editor. Values are what the config expects.</summary>
    public string[] MatchKinds { get; } = { "name", "path", "hash", "cmdline" };
    public string[] Actions { get; } = { "quarantine", "warn", "score" };

    public WatchlistViewModel(string configPath)
    {
        _configPath = configPath;
        AddCommand = new RelayCommand(Add);
        RemoveCommand = new RelayCommandP(p => Remove(p as WatchRow));
        SaveCommand = new RelayCommand(Save);
        ReloadCommand = new RelayCommand(() => LoadFrom(ConfigLoader.Load(_configPath)));
    }

    public ICommand AddCommand { get; }
    public ICommand RemoveCommand { get; }
    public ICommand SaveCommand { get; }
    public ICommand ReloadCommand { get; }

    public void LoadFrom(ShieldConfig c)
    {
        _config = c;
        Rows.Clear();
        foreach (var e in c.Watchlist.Entries ?? Array.Empty<WatchlistEntryConfig>())
            Rows.Add(new WatchRow(e));

        Enabled = c.Watchlist.Enabled;
        AlertOnEveryHit = c.Watchlist.AlertOnEveryHit;
        Message = "";
        OnPropertyChanged(nameof(IsEmpty));
    }

    private void Add()
    {
        Rows.Add(new WatchRow());
        OnPropertyChanged(nameof(IsEmpty));
    }

    private void Remove(WatchRow? row)
    {
        if (row is null) return;
        Rows.Remove(row);
        OnPropertyChanged(nameof(IsEmpty));
    }

    private void Save()
    {
        try
        {
            foreach (var r in Rows) r.Revalidate();
            var bad = Rows.Count(r => r.HasProblem);
            if (bad > 0)
            {
                Message = $"{bad} entr{(bad == 1 ? "y" : "ies")} still invalid — fix or remove them first.";
                return;
            }

            // Containment on sight is destructive and easy to mistype, so name the count
            // and make the operator confirm rather than burying it behind a Save button.
            int contain = Rows.Count(r => r.Enabled &&
                string.Equals(r.Action, "quarantine", StringComparison.OrdinalIgnoreCase));
            if (contain > 0)
            {
                var answer = MessageBox.Show(
                    $"{contain} entr{(contain == 1 ? "y is" : "ies are")} set to CONTAIN ON SIGHT.\n\n" +
                    "Any process matching one will be suspended and network-blocked immediately, " +
                    "even if it is signed by a trusted publisher.\n\nArm the watchlist?",
                    "Confirm watchlist", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (answer != MessageBoxResult.Yes) { Message = "Not saved."; return; }
            }

            _config.Watchlist.Enabled = Enabled;
            _config.Watchlist.AlertOnEveryHit = AlertOnEveryHit;
            _config.Watchlist.Entries = Rows.Select(r => r.ToConfig()).ToArray();

            ConfigLoader.Save(_config, _configPath);
            LoadFrom(_config);
            Message = Enabled
                ? "Saved. The watchlist is armed within a couple of seconds — no restart needed."
                : "Saved. The watchlist is turned off.";
        }
        catch (Exception ex)
        {
            AppLog.Error("watchlist save", ex);
            Message = "Save failed: " + ex.Message;
        }
    }

    private bool _enabled = true;
    public bool Enabled { get => _enabled; set => Set(ref _enabled, value); }

    private bool _alertOnEveryHit = true;
    public bool AlertOnEveryHit { get => _alertOnEveryHit; set => Set(ref _alertOnEveryHit, value); }

    public bool IsEmpty => Rows.Count == 0;

    private string _message = "";
    public string Message { get => _message; set => Set(ref _message, value); }
}
