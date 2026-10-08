using System.Windows;

namespace BruceEDR.Gui.Services;

/// <summary>
/// Tray icon so the agent can keep monitoring with the window out of the way.
/// Wraps a WinForms <see cref="System.Windows.Forms.NotifyIcon"/> (WPF has no native
/// tray support). All WinForms types are fully qualified: the project removes the
/// implicit <c>System.Windows.Forms</c> using so WPF's MessageBox/Application/Clipboard
/// stay unambiguous everywhere else.
/// </summary>
public sealed class TrayIcon : IDisposable
{
    private readonly System.Windows.Forms.NotifyIcon _icon;
    private readonly Window _window;
    private readonly Func<bool> _isLive;
    private bool _hiddenBalloonShown;   // educate once, then stay quiet
    private bool _disposed;

    /// <param name="isLive">Whether an engine is running. The tray must never claim to be
    /// watching while the app sits on its set-up screen or after Stop.</param>
    public TrayIcon(Window window, Func<bool> isLive)
    {
        _window = window;
        _isLive = isLive;

        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Open BruceEDR", null, (_, _) => Restore());
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) => _window.Close());

        _icon = new System.Windows.Forms.NotifyIcon
        {
            Text = "BruceEDR: not monitoring",
            ContextMenuStrip = menu,
            Visible = true,
        };
        _icon.DoubleClick += (_, _) => Restore();

        try
        {
            var uri = new Uri("pack://application:,,,/BruceEDR.Gui;component/Assets/bruce.ico");
            using var stream = System.Windows.Application.GetResourceStream(uri)?.Stream;
            if (stream is not null) _icon.Icon = new System.Drawing.Icon(stream);
        }
        catch (Exception ex) { AppLog.Error("tray icon load", ex); }
    }

    /// <summary>Hide the window to the tray (called on minimize when the pref is on).</summary>
    public void HideToTray()
    {
        try
        {
            _window.Hide();
            if (!_isLive())
                Notify("Not monitoring", "BruceEDR is in the tray but nothing is being watched. Double-click the tray icon to set it up and start it.");
            else if (!_hiddenBalloonShown)
            {
                _hiddenBalloonShown = true;
                Notify("Still monitoring", "BruceEDR keeps watching from the tray. Double-click the tray icon to reopen.");
            }
        }
        catch (Exception ex) { AppLog.Error("hide to tray", ex); }
    }

    /// <summary>Balloon notification (containments, monitor loss). Best-effort.</summary>
    public void Notify(string title, string message)
    {
        if (_disposed) return;
        try { _icon.ShowBalloonTip(4000, title, message, System.Windows.Forms.ToolTipIcon.Warning); }
        catch (Exception ex) { AppLog.Error("tray notify", ex); }
    }

    /// <summary>Tooltip text; NotifyIcon caps it, so keep it short.</summary>
    public void SetStatus(string text)
    {
        if (_disposed) return;
        try { _icon.Text = text.Length > 60 ? text[..60] : text; }
        catch (Exception ex) { AppLog.Error("tray status", ex); }
    }

    public bool WindowIsHidden => !_window.IsVisible;

    private void Restore()
    {
        try
        {
            _window.Show();
            if (_window.WindowState == WindowState.Minimized)
                _window.WindowState = WindowState.Normal;
            _window.Activate();
        }
        catch (Exception ex) { AppLog.Error("tray restore", ex); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try { _icon.Visible = false; _icon.Dispose(); } catch { }
    }
}
