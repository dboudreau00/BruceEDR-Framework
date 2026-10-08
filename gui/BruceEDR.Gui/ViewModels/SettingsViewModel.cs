using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Input;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Gui.Services;
using BruceEDR.Response;

namespace BruceEDR.Gui.ViewModels;

public sealed class SettingsViewModel : ViewModelBase
{
    private readonly string _configPath;
    private BruceConfig _config = new();
    private UiState? _ui;

    public SettingsViewModel(string configPath)
    {
        _configPath = configPath;
        SaveCommand = new RelayCommand(Save);
        ReloadCommand = new RelayCommand(() => LoadFrom(ConfigLoader.Load(_configPath)));
        OpenLogCommand = new RelayCommand(() => OpenFile(AppLog.LogPath));
        OpenConfigCommand = new RelayCommand(() => OpenFile(_configPath));
        RemoveFirewallRulesCommand = new RelayCommand(RemoveFirewallRules, () => !_cleaning);
    }

    private bool _cleaning;

    /// <summary>
    /// Outbound blocks stay in Windows Firewall after BruceEDR stops; this is the one-click
    /// way back when an app lost its network access. Runs off the UI thread (COM + netsh).
    /// </summary>
    private void RemoveFirewallRules()
    {
        var answer = MessageBox.Show(
            "This deletes every outbound firewall block BruceEDR added, and lifts host isolation " +
            "if BruceEDR put it in place. Any process BruceEDR cut off the network gets its " +
            "network access back.\n\nRemove BruceEDR's firewall rules?",
            "Remove BruceEDR firewall rules", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes) return;

        _cleaning = true;
        CommandManager.InvalidateRequerySuggested();
        FirewallMessage = "Removing firewall rules...";
        Task.Run(() => FirewallCleanup.RemoveAll(new Logger())).ContinueWith(t =>
        {
            var r = t.IsCompletedSuccessfully ? t.Result
                  : ActionResult.Fail(t.Exception?.GetBaseException().Message ?? "cleanup failed");
            AppLog.Info("firewall cleanup: " + r.Message);
            FirewallMessage = (r.Ok ? "Done: " : "Not finished: ") + r.Message;
            _cleaning = false;
            CommandManager.InvalidateRequerySuggested();
        }, TaskScheduler.FromCurrentSynchronizationContext());
    }

    /// <summary>Wire the persisted interface preferences (owned by the window).</summary>
    public void AttachUiState(UiState ui)
    {
        _ui = ui;
        _minimizeToTray = ui.MinimizeToTray;
        OnPropertyChanged(nameof(MinimizeToTray));
    }

    /// <summary>Interface preference, saved immediately — no Save button round-trip.</summary>
    private bool _minimizeToTray = true;
    public bool MinimizeToTray
    {
        get => _minimizeToTray;
        set
        {
            if (!Set(ref _minimizeToTray, value)) return;
            if (_ui is null) return;
            _ui.MinimizeToTray = value;
            _ui.Save();
        }
    }

    private static void OpenFile(string path)
    {
        try
        {
            if (File.Exists(path))
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { AppLog.Error("open file", ex); }
    }

    public ICommand SaveCommand { get; }
    public ICommand ReloadCommand { get; }
    public ICommand OpenLogCommand { get; }
    public ICommand OpenConfigCommand { get; }
    public ICommand RemoveFirewallRulesCommand { get; }

    public void LoadFrom(BruceConfig c)
    {
        _config = c;
        Enforce = c.Response.IsEnforcing;
        WarnThreshold = c.Detection.WarnThreshold;
        QuarantineThreshold = c.Detection.QuarantineThreshold;
        TrustDiscount = c.Detection.TrustDiscount;
        CorrelationWindowSeconds = c.Detection.CorrelationWindowSeconds;
        AutoKill = c.Detection.AutoKill;
        UseYara = string.Equals(c.Detection.MemoryScanEngine, "yara", StringComparison.OrdinalIgnoreCase);
        KernelBlocking = c.Detection.KernelBlocking;

        Publishers = string.Join(Environment.NewLine, c.Allowlist.Publishers);
        Thumbprints = string.Join(Environment.NewLine, c.Allowlist.Thumbprints);
        AllowSubjectMatch = c.Allowlist.AllowSubjectMatch;
        CheckRevocation = c.Allowlist.CheckRevocation;

        SyslogEnabled = c.Telemetry.Syslog.Enabled;
        SyslogHost = c.Telemetry.Syslog.Host;
        SyslogPort = c.Telemetry.Syslog.Port;
        SyslogTcp = string.Equals(c.Telemetry.Syslog.Protocol, "tcp", StringComparison.OrdinalIgnoreCase);
        WebhookEnabled = c.Telemetry.Webhook.Enabled;
        WebhookUrl = c.Telemetry.Webhook.Url;

        SaveMessage = "";
    }

    private void Save()
    {
        try
        {
            // Read-modify-write against the file. The Watchlist editor holds its own
            // config object loaded from the same path, so writing this editor's snapshot
            // wholesale would silently roll back entries it had already saved.
            var onDisk = ConfigLoader.Load(_configPath);
            // Declining enforce keeps monitor mode; the rest of the edits are still saved.
            bool declined = Enforce && !onDisk.Response.IsEnforcing && !SetupViewModel.ConfirmEnforceMode("Turn on enforce mode");
            if (declined) Enforce = false;
            onDisk.Response.Mode = Enforce ? ResponseModes.Enforce : ResponseModes.Monitor;
            onDisk.Detection.WarnThreshold = WarnThreshold;
            onDisk.Detection.QuarantineThreshold = QuarantineThreshold;
            onDisk.Detection.TrustDiscount = TrustDiscount;
            onDisk.Detection.CorrelationWindowSeconds = CorrelationWindowSeconds;
            onDisk.Detection.AutoKill = AutoKill;
            onDisk.Detection.MemoryScanEngine = UseYara ? "yara" : "builtin";
            onDisk.Detection.KernelBlocking = KernelBlocking;

            onDisk.Allowlist.Publishers = SplitLines(Publishers);
            onDisk.Allowlist.Thumbprints = SplitLines(Thumbprints);
            onDisk.Allowlist.AllowSubjectMatch = AllowSubjectMatch;
            onDisk.Allowlist.CheckRevocation = CheckRevocation;

            onDisk.Telemetry.Syslog.Enabled = SyslogEnabled;
            onDisk.Telemetry.Syslog.Host = SyslogHost;
            onDisk.Telemetry.Syslog.Port = SyslogPort;
            onDisk.Telemetry.Syslog.Protocol = SyslogTcp ? "tcp" : "udp";
            onDisk.Telemetry.Webhook.Enabled = WebhookEnabled;
            onDisk.Telemetry.Webhook.Url = WebhookUrl;

            ConfigLoader.Save(onDisk, _configPath);
            // reflect any clamping the save applied
            _config = onDisk;
            LoadFrom(_config);
            SaveMessage = declined
                ? "Saved, still in monitor mode: enforce mode was not turned on."
                : "Saved. Response mode, thresholds and allowlist apply live; scan engine and telemetry take effect on restart.";
        }
        catch (Exception ex)
        {
            SaveMessage = "Save failed: " + ex.Message;
        }
    }

    private static string[] SplitLines(string s)
        => s.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    // -------- bound fields --------
    private int _warn; public int WarnThreshold { get => _warn; set => Set(ref _warn, value); }
    private int _quar; public int QuarantineThreshold { get => _quar; set => Set(ref _quar, value); }
    private int _trust; public int TrustDiscount { get => _trust; set => Set(ref _trust, value); }
    private int _window; public int CorrelationWindowSeconds { get => _window; set => Set(ref _window, value); }
    private bool _enforce; public bool Enforce { get => _enforce; set => Set(ref _enforce, value); }
    private bool _autoKill; public bool AutoKill { get => _autoKill; set => Set(ref _autoKill, value); }
    private bool _useYara; public bool UseYara { get => _useYara; set => Set(ref _useYara, value); }
    private bool _kernelBlocking; public bool KernelBlocking { get => _kernelBlocking; set => Set(ref _kernelBlocking, value); }

    private string _publishers = ""; public string Publishers { get => _publishers; set => Set(ref _publishers, value); }
    private string _thumbprints = ""; public string Thumbprints { get => _thumbprints; set => Set(ref _thumbprints, value); }
    private bool _allowSubject = true; public bool AllowSubjectMatch { get => _allowSubject; set => Set(ref _allowSubject, value); }
    private bool _checkRevocation; public bool CheckRevocation { get => _checkRevocation; set => Set(ref _checkRevocation, value); }

    private bool _syslogEnabled; public bool SyslogEnabled { get => _syslogEnabled; set => Set(ref _syslogEnabled, value); }
    private string _syslogHost = "127.0.0.1"; public string SyslogHost { get => _syslogHost; set => Set(ref _syslogHost, value); }
    private int _syslogPort = 514; public int SyslogPort { get => _syslogPort; set => Set(ref _syslogPort, value); }
    private bool _syslogTcp; public bool SyslogTcp { get => _syslogTcp; set => Set(ref _syslogTcp, value); }
    private bool _webhookEnabled; public bool WebhookEnabled { get => _webhookEnabled; set => Set(ref _webhookEnabled, value); }
    private string _webhookUrl = ""; public string WebhookUrl { get => _webhookUrl; set => Set(ref _webhookUrl, value); }

    private string _saveMessage = ""; public string SaveMessage { get => _saveMessage; set => Set(ref _saveMessage, value); }
    private string _firewallMessage = ""; public string FirewallMessage { get => _firewallMessage; set => Set(ref _firewallMessage, value); }
}
