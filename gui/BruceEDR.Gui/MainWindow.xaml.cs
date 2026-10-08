using System.IO;
using System.Windows;
using BruceEDR.Gui.Services;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly UiState _ui;
    private TrayIcon? _tray;

    public MainWindow()
    {
        InitializeComponent();
        string configPath = ResolveConfigPath(Environment.GetCommandLineArgs());
        _ui = UiState.Load();
        _vm = new MainViewModel(configPath);
        DataContext = _vm;

        RestorePlacement();
        _vm.SelectedTabIndex = Math.Clamp(_ui.LastTabIndex, 0, MainViewModel.TabCount - 1);
        _vm.Settings.AttachUiState(_ui);

        Loaded += (_, _) =>
        {
            try
            {
                _tray = new TrayIcon(this, () => _vm.IsLive);
                UpdateTrayStatus();
                _vm.PropertyChanged += (_, e) =>
                {
                    if (e.PropertyName is nameof(MainViewModel.IsLive) or nameof(MainViewModel.IsMonitorOnly))
                        UpdateTrayStatus();
                };
                _vm.AlertRaised += OnAlert;
                // Deliberately no Start here: the window opens on the set-up stage and
                // nothing is monitored until the operator presses Start.
            }
            catch (Exception ex) { AppLog.Error("window start", ex); }
        };
        StateChanged += (_, _) =>
        {
            // Minimize keeps monitoring from the tray instead of cluttering the taskbar.
            if (WindowState == WindowState.Minimized && _ui.MinimizeToTray && _tray is not null)
                _tray.HideToTray();
        };
        Closing += (_, e) =>
        {
            // Closing stops the engine, which never resumes what it suspended.
            if (!_vm.ConfirmLeavingFrozen("Close BruceEDR")) { e.Cancel = true; return; }
            SavePlacement();
        };
        Closed += (_, _) =>
        {
            try { _vm.AlertRaised -= OnAlert; _tray?.Dispose(); }
            catch (Exception ex) { AppLog.Error("tray dispose", ex); }
            try { _vm.Dispose(); }
            catch (Exception ex) { AppLog.Error("window close", ex); }
        };
    }

    /// <summary>
    /// bruce.config.json beside the exe, or the path after --config. BruceEDR.exe forwards an
    /// explicit --config when a bare launch opens this app, so an old shortcut keeps its config.
    /// </summary>
    private static string ResolveConfigPath(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], "--config", StringComparison.OrdinalIgnoreCase))
                return Path.GetFullPath(args[i + 1]);
        return Path.Combine(AppContext.BaseDirectory, "bruce.config.json");
    }

    private void UpdateTrayStatus()
        => _tray?.SetStatus(!_vm.IsLive ? "BruceEDR: not monitoring"
                          : _vm.IsMonitorOnly ? "BruceEDR: monitoring (monitor only)"
                          : "BruceEDR: monitoring (enforcing)");

    private void OnAlert(string title, string message)
    {
        // Balloon only when the analyst cannot already see the window; otherwise the
        // posture ribbon and the feed carry the news without popup noise.
        if (_tray is null) return;
        if (!IsVisible || WindowState == WindowState.Minimized || !IsActive)
            _tray.Notify(title, message);
    }

    private void RestorePlacement()
    {
        try
        {
            if (_ui.WindowWidth >= 400 && _ui.WindowHeight >= 300)
            {
                Width = _ui.WindowWidth;
                Height = _ui.WindowHeight;
            }
            if (!double.IsNaN(_ui.WindowLeft) && !double.IsNaN(_ui.WindowTop))
            {
                // Only restore a position that is still on a connected screen, so an
                // unplugged monitor can never strand the window off-screen.
                var vs = new Rect(SystemParameters.VirtualScreenLeft, SystemParameters.VirtualScreenTop,
                                  SystemParameters.VirtualScreenWidth, SystemParameters.VirtualScreenHeight);
                var candidate = new Rect(_ui.WindowLeft, _ui.WindowTop, Math.Max(Width, 200), Math.Max(Height, 120));
                if (vs.IntersectsWith(candidate))
                {
                    WindowStartupLocation = WindowStartupLocation.Manual;
                    Left = _ui.WindowLeft;
                    Top = _ui.WindowTop;
                }
            }
            if (_ui.WindowMaximized) WindowState = WindowState.Maximized;
        }
        catch (Exception ex) { AppLog.Error("restore placement", ex); }
    }

    private void SavePlacement()
    {
        try
        {
            var b = RestoreBounds;   // normal-state bounds even when currently maximized
            if (b.Width >= 400 && b.Height >= 300)
            {
                _ui.WindowLeft = b.Left;
                _ui.WindowTop = b.Top;
                _ui.WindowWidth = b.Width;
                _ui.WindowHeight = b.Height;
            }
            _ui.WindowMaximized = WindowState == WindowState.Maximized;
            _ui.LastTabIndex = _vm.SelectedTabIndex;
            _ui.Save();
        }
        catch (Exception ex) { AppLog.Error("save placement", ex); }
    }
}
