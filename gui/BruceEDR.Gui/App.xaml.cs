using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;
using BruceEDR.Gui.Services;

namespace BruceEDR.Gui;

public partial class App : Application
{
    private DateTime _lastDialogUtc = DateTime.MinValue;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Register catch-alls BEFORE the window is built, so even a XAML parse error
        // during MainWindow construction is reported cleanly instead of crashing raw.
        DispatcherUnhandledException += OnUiThreadException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainException;
        TaskScheduler.UnobservedTaskException += OnTaskException;

        base.OnStartup(e);

        try
        {
            AppLog.Info("GUI starting.");
            new MainWindow().Show();
        }
        catch (Exception ex)
        {
            AppLog.Error("startup", ex);
            MessageBox.Show(
                "BruceEDR could not start.\n\n" + ex.Message +
                "\n\nA detailed log was written to:\n" + AppLog.LogPath,
                "BruceEDR", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private void OnUiThreadException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        AppLog.Error("ui-thread", e.Exception);
        e.Handled = true;                    // keep the monitoring session alive
        NotifyThrottled(e.Exception.Message);
    }

    private void OnDomainException(object sender, UnhandledExceptionEventArgs e)
    {
        var ex = e.ExceptionObject as Exception ?? new Exception(e.ExceptionObject?.ToString() ?? "unknown");
        AppLog.Error(e.IsTerminating ? "domain-fatal" : "domain", ex);
    }

    private void OnTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        AppLog.Error("task", e.Exception);
        e.SetObserved();
    }

    // Log every error, but surface a dialog at most once per 10s to avoid spam.
    private void NotifyThrottled(string message)
    {
        var now = DateTime.UtcNow;
        if (now - _lastDialogUtc < TimeSpan.FromSeconds(10)) return;
        _lastDialogUtc = now;
        try
        {
            MessageBox.Show(
                "A background error occurred; BruceEDR is still running.\n\n" + message +
                "\n\nMore detail: " + AppLog.LogPath,
                "BruceEDR", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch { }
    }
}
