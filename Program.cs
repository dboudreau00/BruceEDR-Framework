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
// Precedence lives in LaunchModes.Resolve so it is tested; each branch below handles one mode.
var mode = LaunchModes.Resolve(args, WindowsServiceHelpers.IsWindowsService());

if (mode == LaunchMode.Help)
{
    PrintUsage();
    return 0;
}

// Offline verification: validate the shipped rule packs and replay every detection
// scenario. Needs no elevation and starts no monitor, so it is safe in CI and is the
// inner loop for anyone authoring a rule.
if (mode == LaunchMode.SelfTest)
    return BruceEDR.Hosting.SelfTest.Run(
        OptionValue(args, "--rules"),
        OptionValue(args, "--scenarios"));

if (mode == LaunchMode.Install)
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    int rc = ServiceControl.Install(ConfigLoader.Load(configPath), configPath);
    WaitForKeyIfOwnConsole();
    return rc;
}
if (mode == LaunchMode.Uninstall)
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    // Not strict: a broken config must not leave a service and a SYSTEM task registered
    // against an exe the uninstaller is about to delete.
    int rc = ServiceControl.Uninstall(ConfigLoader.Load(configPath, strict: false));
    WaitForKeyIfOwnConsole();
    return rc;
}
if (mode == LaunchMode.Watchdog)
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    return Watchdog.Run(configPath);
}
// Outbound blocks outlive the agent. This removes every rule BruceEDR created (and lifts
// isolation BruceEDR applied); the MSI uninstaller runs it too.
if (mode == LaunchMode.Cleanup)
{
    if (!RequireElevation()) { WaitForKeyIfOwnConsole(); return 1; }
    var cleaned = BruceEDR.Response.FirewallCleanup.RemoveAll(new BruceEDR.Core.Logger());
    Console.WriteLine(cleaned.Ok ? cleaned.Message : "cleanup incomplete: " + cleaned.Message);
    WaitForKeyIfOwnConsole();
    return cleaned.Ok ? 0 : 1;
}

// Running under the SCM -> Windows Service host (no interactive console).
if (mode == LaunchMode.Service)
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

// A bare launch (a double-click in Explorer) never starts monitoring. It opens the
// desktop app, which has its own set-up and Start steps. The live console agent is
// opt-in with --console.
if (mode == LaunchMode.DesktopApp)
    return OpenDesktopApp(OptionValue(args, "--config"));
// Default deny: only an explicit --console reaches the live agent below.
if (mode != LaunchMode.Console)
    return 1;

// ---------------------------------------------------- interactive console mode
// Not elevated (e.g. --console from a normal terminal): request UAC and relaunch,
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

// One click in a QuickEdit console starts a selection that blocks every console write,
// and the agent's threads write while they work: the whole agent would stall until Esc.
// The previous mode is restored on the way out, since the console may be the caller's.
uint? savedInputMode = NativeConsole.DisableQuickEdit();

Composition? composition = null;
int shuttingDown = 0;
void Shutdown()
{
    if (Interlocked.Exchange(ref shuttingDown, 1) == 1) return;
    try { composition?.Dispose(); }
    catch (Exception ex) { Console.Error.WriteLine(ex.Message); }
    NativeConsole.RestoreInputMode(savedInputMode);
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
    if (savedInputMode is not null)
        composition.Log.Info("QuickEdit selection is off while the agent runs, so a click in this window cannot pause it.");

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

// Opens BruceEDR.Gui.exe from beside this exe (installed layout) or from gui\ (older
// release zips). The GUI's manifest asks for elevation itself. An explicit --config is
// forwarded, so an old shortcut that names a config still gets that config.
static int OpenDesktopApp(string? explicitConfig)
{
    string dir = AppContext.BaseDirectory;
    string? gui = new[] { Path.Combine(dir, "BruceEDR.Gui.exe"), Path.Combine(dir, "gui", "BruceEDR.Gui.exe") }
        .FirstOrDefault(File.Exists);
    if (gui is not null)
    {
        try
        {
            Process.Start(new ProcessStartInfo(gui)
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(gui)!,
                Arguments = explicitConfig is null ? "" : $"--config \"{Path.GetFullPath(explicitConfig)}\""
            });
            if (!ConsoleOwnedBySelf())
                Console.WriteLine("Opened the BruceEDR desktop app. To run the agent in this terminal instead, use --console.");
            return 0;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Console.WriteLine("The administrator prompt was declined; BruceEDR was not opened.");
            WaitForKeyIfOwnConsole();
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Could not open the BruceEDR desktop app: " + ex.Message);
        }
    }

    Console.WriteLine("BruceEDR does not start monitoring from a double-click.");
    Console.WriteLine("Open BruceEDR.Gui.exe to set it up and start it, or run");
    Console.WriteLine("  BruceEDR.exe --console");
    Console.WriteLine("from an elevated terminal for the live console agent. --help lists every option.");
    WaitForKeyIfOwnConsole();
    return 1;
}

// Keep a double-clicked window open long enough to read the message. If we were
// launched from an existing terminal, don't block (the shell window persists).
static void WaitForKeyIfOwnConsole()
{
    try
    {
        // Installers and scripts: an MSI custom action can run us on a hidden console that
        // nobody can press Enter on, which would hang the uninstall.
        if (Console.IsInputRedirected || Console.IsOutputRedirected) return;
        if (Environment.GetCommandLineArgs().Any(a => string.Equals(a, "--no-pause", StringComparison.OrdinalIgnoreCase))) return;
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
        "  BruceEDR.exe                    open the desktop app (never starts monitoring by itself)\n" +
        "  BruceEDR.exe --console          run the live agent here with the analyst console\n" +
        "  BruceEDR.exe --install          install + start the Windows Service (+ watchdog task)\n" +
        "  BruceEDR.exe --uninstall        stop + remove the service and watchdog task\n" +
        "  BruceEDR.exe --watchdog         run the heartbeat watchdog (used by the scheduled task)\n" +
        "  BruceEDR.exe --cleanup          remove every firewall rule BruceEDR created (admin)\n" +
        "  BruceEDR.exe --selftest         validate rule packs + replay detection scenarios (no admin)\n" +
        "      --rules <dir>                    override the detection rule directory\n" +
        "      --scenarios <dir>                override the replay scenario directory\n" +
        "  BruceEDR.exe --config <path>    use a specific bruce.config.json\n" +
        "      --no-pause                       never wait for Enter on exit (installers, scripts)\n" +
        "  (started by the SCM)                 runs as a Windows Service automatically\n");
}

static class NativeConsole
{
    private const int StdInputHandle = -10;
    private const uint EnableQuickEditMode = 0x0040;
    private const uint EnableExtendedFlags = 0x0080;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint GetConsoleProcessList(uint[] lpdwProcessList, uint dwProcessCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    /// <summary>Turns QuickEdit off. Returns the mode to restore, or null when nothing changed.</summary>
    public static uint? DisableQuickEdit()
    {
        try
        {
            IntPtr h = GetStdHandle(StdInputHandle);
            if (h == IntPtr.Zero || h == new IntPtr(-1)) return null;
            if (!GetConsoleMode(h, out uint mode) || (mode & EnableQuickEditMode) == 0) return null;
            return SetConsoleMode(h, (mode & ~EnableQuickEditMode) | EnableExtendedFlags) ? mode : null;
        }
        catch { return null; }
    }

    public static void RestoreInputMode(uint? mode)
    {
        if (mode is null) return;
        // QuickEdit changes are ignored unless ENABLE_EXTENDED_FLAGS accompanies them.
        try { SetConsoleMode(GetStdHandle(StdInputHandle), mode.Value | EnableExtendedFlags); } catch { }
    }
}
