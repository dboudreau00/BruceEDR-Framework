using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using BruceEDR.ConsoleUi;
using BruceEDR.Configuration;
using BruceEDR.Hosting;

// ----------------------------------------------------------- startup guards
if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("BruceEDR targets Windows only.");
    return 1;
}
if (!Environment.Is64BitProcess)
{
    Console.Error.WriteLine("Build and run as x64 (the memory scanner assumes a 64-bit address space).");
    return 1;
}

string configPath = ResolveConfigPath(args);

// ------------------------------------------------------------------- modes
if (HasFlag(args, "--help") || HasFlag(args, "-h"))
{
    PrintUsage();
    return 0;
}

// Offline verification: validate the shipped rule packs and replay every detection
// scenario. Needs no elevation and starts no monitor, so it is safe in CI and is the
// inner loop for anyone authoring a rule.
if (HasFlag(args, "--selftest"))
    return BruceEDR.Hosting.SelfTest.Run(
        OptionValue(args, "--rules"),
        OptionValue(args, "--scenarios"));

if (HasFlag(args, "--install"))
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    int rc = ServiceControl.Install(ConfigLoader.Load(configPath));
    WaitForKeyIfOwnConsole();
    return rc;
}
if (HasFlag(args, "--uninstall"))
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    int rc = ServiceControl.Uninstall(ConfigLoader.Load(configPath));
    WaitForKeyIfOwnConsole();
    return rc;
}
if (HasFlag(args, "--watchdog"))
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    return Watchdog.Run(configPath);
}

// Running under the SCM -> Windows Service host (no interactive console).
if (WindowsServiceHelpers.IsWindowsService())
{
    var svcCfg = ConfigLoader.Load(configPath);
    Host.CreateDefaultBuilder(args)
        .UseWindowsService(o => o.ServiceName = svcCfg.Service.ServiceName)
        .ConfigureServices(services =>
        {
            services.AddSingleton(new WorkerOptions(configPath));
            services.AddHostedService<BruceWorker>();
        })
        .Build()
        .Run();
    return 0;
}

// ---------------------------------------------------- interactive console mode
// Not elevated (e.g. double-clicked from Explorer): request UAC and relaunch,
// so the app doesn't just flash a console and vanish.
if (!IsElevated())
{
    Console.WriteLine("BruceEDR needs administrator rights (ETW, process access, quarantine).");
    Console.WriteLine("Requesting elevation - please accept the UAC prompt...");
    if (RelaunchElevated(args))
        return 0;   // an elevated instance is starting in a new window

    Console.Error.WriteLine();
    Console.Error.WriteLine("Elevation was declined or unavailable.");
    Console.Error.WriteLine("Start BruceEDR from an elevated terminal, or right-click");
    Console.Error.WriteLine("BruceEDR.exe -> \"Run as administrator\".");
    WaitForKeyIfOwnConsole();
    return 1;
}

Composition? composition = null;
int shuttingDown = 0;
void Shutdown()
{
    if (Interlocked.Exchange(ref shuttingDown, 1) == 1) return;
    try { composition?.Dispose(); }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); }
}

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    Console.WriteLine();
    Console.WriteLine("Shutting down...");
    Shutdown();
    Environment.Exit(0);
};
AppDomain.CurrentDomain.ProcessExit += (_, _) => Shutdown();

try
{
    composition = Composition.Build(configPath);

    if (!composition.Host.Start())
    {
        Console.Error.WriteLine("No monitor could be started; nothing to do. Exiting.");
        Shutdown();
        WaitForKeyIfOwnConsole();
        return 2;
    }

    composition.Log.Info($"BruceEDR active (console mode). Monitors: {composition.Host.ActiveMonitors}.");
    composition.Log.Info($"Config: {configPath}");
    composition.Log.Info("Type 'help' for commands, 'quit' to exit.");

    var console = new AnalystConsole(composition.Host, composition.Log,
        reloadConfig: composition.ReloadConfig,
        verifyAudit: composition.VerifyAudit,
        composition: composition);
    console.Run();

    Shutdown();
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("Fatal error during startup:");
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(ex.StackTrace);
    Shutdown();
    WaitForKeyIfOwnConsole();
    return 3;
}

// -------------------------------------------------------------------- locals
static bool HasFlag(string[] args, string flag)
    => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

static string ResolveConfigPath(string[] args)
    => OptionValue(args, "--config") ?? Path.Combine(AppContext.BaseDirectory, "bruce.config.json");

/// <summary>Value that follows <paramref name="name"/>, or null when the flag is absent.</summary>
static string? OptionValue(string[] args, string name)
{
    for (int i = 0; i < args.Length - 1; i++)
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            return args[i + 1];
    return null;
}

static bool IsElevated()
{
    if (!OperatingSystem.IsWindows()) return false;
    try
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
    catch { return false; }
}

static bool RequireElevation()
{
    if (IsElevated()) return true;
    Console.Error.WriteLine("Run as Administrator (ETW kernel session, process access, and service control require elevation).");
    return false;
}

// Relaunch this exe elevated via the UAC "runas" verb. Returns true if a new
// (elevated) process was started; false if the user declined UAC or it failed.
static bool RelaunchElevated(string[] args)
{
    try
    {
        string? exe = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exe)) return false;

        // Resolve a relative --config against the CALLER's cwd here, in the non-elevated
        // parent, before relaunch. The elevated child's working directory is forced to the
        // exe folder (a "runas" child does not inherit our cwd -- it defaults to System32),
        // so a forwarded relative path would otherwise resolve to the wrong place and the
        // elevated instance would silently run with the default posture.
        var forwarded = (string[])args.Clone();
        for (int i = 0; i < forwarded.Length - 1; i++)
            if (string.Equals(forwarded[i], "--config", StringComparison.OrdinalIgnoreCase))
                forwarded[i + 1] = Path.GetFullPath(forwarded[i + 1]);

        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = AppContext.BaseDirectory,
            Arguments = string.Join(' ', forwarded.Select(a => a.Contains(' ') ? $"\"{a}\"" : a))
        };
        Process.Start(psi);
        return true;
    }
    catch (System.ComponentModel.Win32Exception) { return false; }  // 1223 = UAC declined
    catch { return false; }
}

// Keep a double-clicked window open long enough to read the message. If we were
// launched from an existing terminal, don't block (the shell window persists).
static void WaitForKeyIfOwnConsole()
{
    try
    {
        if (Console.IsInputRedirected) return;
        if (!ConsoleOwnedBySelf()) return;
        Console.WriteLine();
        Console.Write("Press Enter to close...");
        Console.ReadLine();
    }
    catch { /* never fail on the way out */ }
}

static bool ConsoleOwnedBySelf()
{
    try
    {
        var buf = new uint[8];
        uint count = NativeConsole.GetConsoleProcessList(buf, (uint)buf.Length);
        return count <= 1;   // only this process attached => fresh console (double-click)
    }
    catch { return false; }
}

static void PrintUsage()
{
    Console.WriteLine(
        "BruceEDR - user-mode behavioural EDR agent\n" +
        "Usage:\n" +
        "  BruceEDR.exe                    run interactively with the analyst console\n" +
        "  BruceEDR.exe --install          install + start the Windows Service (+ watchdog task)\n" +
        "  BruceEDR.exe --uninstall        stop + remove the service and watchdog task\n" +
        "  BruceEDR.exe --watchdog         run the heartbeat watchdog (used by the scheduled task)\n" +
        "  BruceEDR.exe --selftest         validate rule packs + replay detection scenarios (no admin)\n" +
        "      --rules <dir>                    override the detection rule directory\n" +
        "      --scenarios <dir>                override the replay scenario directory\n" +
        "  BruceEDR.exe --config <path>    use a specific bruce.config.json\n" +
        "  (started by the SCM)                 runs as a Windows Service automatically\n");
}

static class NativeConsole
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetConsoleProcessList(uint[] lpdwProcessList, uint dwProcessCount);
}
