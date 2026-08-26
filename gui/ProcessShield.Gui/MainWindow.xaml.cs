using System.IO;
using System.Windows;
using ProcessShield.Gui.Services;
using ProcessShield.Gui.ViewModels;

namespace ProcessShield.Gui;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly UiState _ui;
    private TrayIcon? _tray;

    public MainWindow()
    {
        InitializeComponent();
        string configPath = Path.Combine(AppContext.BaseDirectory, "shield.config.json");
        _ui = UiState.Load();
        _vm = new MainViewModel(configPath);
        DataContext = _vm;

        RestorePlacement();
        _vm.SelectedTabIndex = Math.Clamp(_ui.LastTabIndex, 0, 4);
        _vm.Settings.AttachUiState(_ui);

        Loaded += (_, _) =>
        {
            try
            {
                _tray = new TrayIcon(this);
                _vm.AlertRaised += OnAlert;
                _vm.Start();
            }
            catch (Exception ex) { AppLog.Error("window start", ex); }
        };
        StateChanged += (_, _) =>
        {
            // Minimize keeps monitoring from the tray instead of cluttering the taskbar.
            if (WindowState == WindowState.Minimized && _ui.MinimizeToTray && _tray is not null)
                _tray.HideToTray();
        };
        Closing += (_, _) => SavePlacement();
        Closed += (_, _) =>
        {
            try { _vm.AlertRaised -= OnAlert; _tray?.Dispose(); }
            catch (Exception ex) { AppLog.Error("tray dispose", ex); }
            try { _vm.Dispose(); }
            catch (Exception ex) { AppLog.Error("window close", ex); }
        };
    }

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
