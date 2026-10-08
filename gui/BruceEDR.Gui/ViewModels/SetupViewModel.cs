using System.IO;
using System.Windows;
using System.Windows.Input;
using BruceEDR.Configuration;

namespace BruceEDR.Gui.ViewModels;

/// <summary>
/// The set-up stage shown before the engine exists. It only reads and writes
/// bruce.config.json; nothing here can touch a process. Going live is a separate,
/// explicit Start on <see cref="MainViewModel"/>.
/// </summary>
public sealed class SetupViewModel : ViewModelBase
{
    private readonly string _configPath;

    public SetupViewModel(string configPath) => _configPath = configPath;

    public string ConfigPath => _configPath;

    /// <summary>
    /// Re-reads the config from disk. A file that exists but cannot be parsed blocks Start,
    /// the same way the console refuses to start on a truncated config.
    /// </summary>
    public void Load()
    {
        DetectionConfig detection;
        try
        {
            var c = ConfigLoader.Load(_configPath);
            Enforce = _loadedEnforce = c.Response.IsEnforcing;
            Publishers = _loadedPublishers = string.Join(Environment.NewLine, c.Allowlist.Publishers);
            WarnThreshold = _loadedWarn = c.Detection.WarnThreshold;
            QuarantineThreshold = _loadedQuarantine = c.Detection.QuarantineThreshold;
            detection = c.Detection;
            LoadError = "";
        }
        catch (Exception ex)
        {
            LoadError = "bruce.config.json could not be read: " + ex.Message;
            return;
        }

        // A rules-folder problem is not a config problem: the engine starts without packs.
        try { DescribeRules(detection); }
        catch (Exception ex)
        {
            RulesMissing = true;
            RulesSummary = "The detection rules folder could not be read: " + ex.Message;
        }
    }

    private bool _loadedEnforce;
    private string _loadedPublishers = "";
    private int _loadedWarn, _loadedQuarantine;

    /// <summary>What the file says now, as opposed to what is ticked on screen.</summary>
    public bool EnforceOnDisk => _loadedEnforce;

    private bool IsDirty
        => Enforce != _loadedEnforce
        || WarnThreshold != _loadedWarn
        || QuarantineThreshold != _loadedQuarantine
        || !SplitLines(Publishers).SequenceEqual(SplitLines(_loadedPublishers));

    /// <summary>
    /// Writes the set-up choices back (read-modify-write, like Settings). Unchanged choices
    /// are not written: a rewrite drops the file's comments, and a read-only file would
    /// otherwise block Start for nothing. False on failure.
    /// </summary>
    public bool Save()
    {
        if (LoadError.Length > 0) return false;
        if (!IsDirty) return true;
        try
        {
            var onDisk = ConfigLoader.Load(_configPath);
            onDisk.Response.Mode = Enforce ? ResponseModes.Enforce : ResponseModes.Monitor;
            onDisk.Allowlist.Publishers = SplitLines(Publishers);
            onDisk.Detection.WarnThreshold = WarnThreshold;
            onDisk.Detection.QuarantineThreshold = QuarantineThreshold;
            ConfigLoader.Save(onDisk, _configPath);
            Load();   // show any clamping the save applied
            return LoadError.Length == 0;
        }
        catch (Exception ex)
        {
            Message = "Could not save the settings: " + ex.Message;
            return false;
        }
    }

    private void DescribeRules(DetectionConfig d)
    {
        if (!d.EnableRuleEngine)
        {
            RulesSummary = "Rule packs are turned off in the config; only built-in detections will run.";
            RulesMissing = true;
            return;
        }
        string dir = Path.IsPathRooted(d.RulesPath) ? d.RulesPath : Path.Combine(AppContext.BaseDirectory, d.RulesPath);
        int packs = Directory.Exists(dir) ? Directory.GetFiles(dir, "*.json", SearchOption.AllDirectories).Length : 0;
        RulesMissing = packs == 0;
        RulesSummary = packs == 0
            ? $"No detection rule packs were found in {dir}. Only built-in detections will run."
            : $"{packs} detection rule pack{(packs == 1 ? "" : "s")} found.";
    }

    /// <summary>
    /// The one place enforce mode is confirmed, from set-up and from Settings alike.
    /// Defaults to No so Enter cannot arm it by accident.
    /// </summary>
    internal static bool ConfirmEnforceMode(string title)
        => MessageBox.Show(
               "Enforce mode lets BruceEDR act without asking. It can suspend processes, block " +
               "their network access with firewall rules, quarantine files and, if auto-kill is " +
               "on, end processes.\n\nRun it in monitor mode on this machine first if you have " +
               "not: false positives are likely on developer and gaming PCs.\n\nTurn on enforce mode?",
               title, MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No)
           == MessageBoxResult.Yes;

    private static string[] SplitLines(string s)
        => s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // -------- bound fields --------
    private bool _enforce;
    public bool Enforce
    {
        get => _enforce;
        set { if (Set(ref _enforce, value)) OnPropertyChanged(nameof(Monitor)); }
    }
    /// <summary>Bound to the "Monitor only" card. Unchecking it (by picking Enforce) is a no-op here.</summary>
    public bool Monitor
    {
        get => !_enforce;
        set { if (value) Enforce = false; }
    }

    private string _publishers = ""; public string Publishers { get => _publishers; set => Set(ref _publishers, value); }
    private int _warn; public int WarnThreshold { get => _warn; set => Set(ref _warn, value); }
    private int _quar; public int QuarantineThreshold { get => _quar; set => Set(ref _quar, value); }

    private string _rulesSummary = ""; public string RulesSummary { get => _rulesSummary; set => Set(ref _rulesSummary, value); }
    private bool _rulesMissing; public bool RulesMissing { get => _rulesMissing; set => Set(ref _rulesMissing, value); }

    private string _loadError = "";
    public string LoadError
    {
        get => _loadError;
        set
        {
            if (!Set(ref _loadError, value)) return;
            OnPropertyChanged(nameof(HasLoadError));
            OnPropertyChanged(nameof(CanStart));
            CommandManager.InvalidateRequerySuggested();
        }
    }
    public bool HasLoadError => _loadError.Length > 0;
    public bool CanStart => _loadError.Length == 0;

    private string _message = "";
    public string Message
    {
        get => _message;
        set { if (Set(ref _message, value)) OnPropertyChanged(nameof(HasMessage)); }
    }
    public bool HasMessage => _message.Length > 0;
}
