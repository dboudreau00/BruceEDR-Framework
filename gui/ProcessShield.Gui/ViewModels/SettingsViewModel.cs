using System.Diagnostics;
using System.IO;
using System.Windows.Input;
using ProcessShield.Configuration;
using ProcessShield.Gui.Services;

namespace ProcessShield.Gui.ViewModels;

public sealed class SettingsViewModel : ViewModelBase
{
    private readonly string _configPath;
    private ShieldConfig _config = new();
    private UiState? _ui;

    public SettingsViewModel(string configPath)
    {
        _configPath = configPath;
        SaveCommand = new RelayCommand(Save);
        ReloadCommand = new RelayCommand(() => LoadFrom(ConfigLoader.Load(_configPath)));
        OpenLogCommand = new RelayCommand(() => OpenFile(AppLog.LogPath));
        OpenConfigCommand = new RelayCommand(() => OpenFile(_configPath));
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

    public void LoadFrom(ShieldConfig c)
    {
        _config = c;
        WarnThreshold = c.Detection.WarnThreshold;
        QuarantineThreshold = c.Detection.QuarantineThreshold;
        TrustDiscount = c.Detection.TrustDiscount;
        CorrelationWindowSeconds = c.Detection.CorrelationWindowSeconds;
        AutoKill = c.Detection.AutoKill;
        UseYara = string.Equals(c.Detection.MemoryScanEngine, "yara", StringComparison.OrdinalIgnoreCase);
        KernelBlocking = c.Detection.KernelBlocking;

        Publishers = string.Join(Environment.NewLine, c.Allowlist.Publishers);
        Thumbprints = string.Join(Environment.NewLine, c.Allowlist.Thumbprints);
        RequireValidChain = c.Allowlist.RequireValidChain;
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
            _config.Detection.WarnThreshold = WarnThreshold;
            _config.Detection.QuarantineThreshold = QuarantineThreshold;
            _config.Detection.TrustDiscount = TrustDiscount;
            _config.Detection.CorrelationWindowSeconds = CorrelationWindowSeconds;
            _config.Detection.AutoKill = AutoKill;
            _config.Detection.MemoryScanEngine = UseYara ? "yara" : "builtin";
            _config.Detection.KernelBlocking = KernelBlocking;

            _config.Allowlist.Publishers = SplitLines(Publishers);
            _config.Allowlist.Thumbprints = SplitLines(Thumbprints);
            _config.Allowlist.RequireValidChain = RequireValidChain;
            _config.Allowlist.AllowSubjectMatch = AllowSubjectMatch;
            _config.Allowlist.CheckRevocation = CheckRevocation;

            _config.Telemetry.Syslog.Enabled = SyslogEnabled;
            _config.Telemetry.Syslog.Host = SyslogHost;
            _config.Telemetry.Syslog.Port = SyslogPort;
            _config.Telemetry.Syslog.Protocol = SyslogTcp ? "tcp" : "udp";
            _config.Telemetry.Webhook.Enabled = WebhookEnabled;
            _config.Telemetry.Webhook.Url = WebhookUrl;

            ConfigLoader.Save(_config, _configPath);
            // reflect any clamping the save applied
            LoadFrom(_config);
            SaveMessage = "Saved. Thresholds and allowlist apply live; scan engine and telemetry take effect on restart.";
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
    private bool _autoKill; public bool AutoKill { get => _autoKill; set => Set(ref _autoKill, value); }
    private bool _useYara; public bool UseYara { get => _useYara; set => Set(ref _useYara, value); }
    private bool _kernelBlocking; public bool KernelBlocking { get => _kernelBlocking; set => Set(ref _kernelBlocking, value); }

    private string _publishers = ""; public string Publishers { get => _publishers; set => Set(ref _publishers, value); }
    private string _thumbprints = ""; public string Thumbprints { get => _thumbprints; set => Set(ref _thumbprints, value); }
    private bool _requireChain = true; public bool RequireValidChain { get => _requireChain; set => Set(ref _requireChain, value); }
    private bool _allowSubject = true; public bool AllowSubjectMatch { get => _allowSubject; set => Set(ref _allowSubject, value); }
    private bool _checkRevocation; public bool CheckRevocation { get => _checkRevocation; set => Set(ref _checkRevocation, value); }

    private bool _syslogEnabled; public bool SyslogEnabled { get => _syslogEnabled; set => Set(ref _syslogEnabled, value); }
    private string _syslogHost = "127.0.0.1"; public string SyslogHost { get => _syslogHost; set => Set(ref _syslogHost, value); }
    private int _syslogPort = 514; public int SyslogPort { get => _syslogPort; set => Set(ref _syslogPort, value); }
    private bool _syslogTcp; public bool SyslogTcp { get => _syslogTcp; set => Set(ref _syslogTcp, value); }
    private bool _webhookEnabled; public bool WebhookEnabled { get => _webhookEnabled; set => Set(ref _webhookEnabled, value); }
    private string _webhookUrl = ""; public string WebhookUrl { get => _webhookUrl; set => Set(ref _webhookUrl, value); }

    private string _saveMessage = ""; public string SaveMessage { get => _saveMessage; set => Set(ref _saveMessage, value); }
}
