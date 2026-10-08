namespace BruceEDR.Hosting;

/// <summary>What one start of BruceEDR.exe does.</summary>
public enum LaunchMode
{
    Help,
    SelfTest,
    Install,
    Uninstall,
    Watchdog,
    /// <summary>Remove every firewall rule BruceEDR created, then exit.</summary>
    Cleanup,
    Service,
    /// <summary>Open BruceEDR.Gui.exe and exit. Never monitors.</summary>
    DesktopApp,
    /// <summary>Run the live agent in this console. Only ever reached through --console.</summary>
    Console
}

public static class LaunchModes
{
    /// <summary>
    /// Decides the mode from the arguments alone, in the precedence Program.cs applies.
    /// It lives here so it can be tested: a bare launch (a double-click, or an old shortcut
    /// that passes only --config) must resolve to the desktop app, and only an explicit
    /// --console may run the live agent in a console window.
    /// </summary>
    public static LaunchMode Resolve(IReadOnlyList<string> args, bool runningAsService)
    {
        if (Has(args, "--help") || Has(args, "-h")) return LaunchMode.Help;
        if (Has(args, "--selftest")) return LaunchMode.SelfTest;
        if (Has(args, "--install")) return LaunchMode.Install;
        if (Has(args, "--uninstall")) return LaunchMode.Uninstall;
        if (Has(args, "--watchdog")) return LaunchMode.Watchdog;
        if (Has(args, "--cleanup")) return LaunchMode.Cleanup;
        if (runningAsService) return LaunchMode.Service;
        return Has(args, "--console") ? LaunchMode.Console : LaunchMode.DesktopApp;
    }

    private static bool Has(IReadOnlyList<string> args, string flag)
        => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));
}
