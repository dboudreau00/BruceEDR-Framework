using System.Collections.Concurrent;
using BruceEDR.Driver;
using static BruceEDR.Native.NativeMethods;

namespace BruceEDR.Security;

/// <summary>
/// Tells a genuine Windows component from a process that only carries its name. A process
/// is one when its image sits at the exact location Windows puts that component AND no
/// account other than SYSTEM, Administrators or TrustedInstaller could have planted the file
/// there (<see cref="KernelPolicy.WriteRisk"/>). The name alone proves nothing: a standard
/// user can copy any program to any name.
///
/// This is not trust in the Authenticode sense, and it is deliberately not a discount. It
/// answers one question for a handful of detections that Windows itself trips constantly
/// (csrss opening every new process with full rights, WMI reading process details through
/// LSASS, the Defender engine reading LSASS, svchost duplicating handles): is this the
/// operating system doing what it always does. The table is an allowlist of components that
/// are services of the system. Anything that can run attacker-chosen code on request
/// (powershell, cmd, rundll32, mshta, regsvr32, wscript, msbuild and the rest of the
/// LOLBins) is absent from it on purpose, so it never gains an exemption from its path.
///
/// Residual risk, stated plainly: a standard user cannot place a file in these folders and
/// cannot open LSASS at all. A standard user can start one of these files and hollow it out, so
/// the instance counts too (<see cref="IsWindowsInstance"/>): a service component only under a
/// service account, svchost only when services.exe started it. The user's own shell programs
/// (conhost, explorer, sihost and the like) run as the user, so a hollowed copy of one still
/// passes for the rules that consult this table. An administrator who can run code inside one of these processes
/// (a WMI provider DLL loaded into WmiPrvSE, an injected svchost) inherits its exemption for
/// the rules that consult this table; injecting into it is still scored against the injector.
/// </summary>
public static class PlatformImages
{
    internal sealed record Roots(string Windows, string ProgramFiles, string ProgramFilesX86, string ProgramData)
    {
        public static Roots Current() => new(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
    }

    /// <summary>
    /// A component: the image name, the folders it may live in ("%win%", "%pf%", "%pf86%" and
    /// "%pd%" stand for the Windows, Program Files, Program Files (x86) and ProgramData
    /// folders; a segment ending in * matches any single segment with that prefix, which is
    /// how a version folder is written), and whether it legitimately reads LSASS memory.
    /// </summary>
    private sealed record Component(string Name, string[] Dirs, bool ReadsLsass = false);

    private static readonly string[] System32 = { @"%win%\System32" };

    private static readonly Component[] Table =
    {
        new("csrss.exe", System32), new("smss.exe", System32), new("wininit.exe", System32),
        new("winlogon.exe", System32), new("services.exe", System32), new("lsass.exe", System32),
        new("svchost.exe", System32), new("conhost.exe", System32), new("sihost.exe", System32),
        new("dwm.exe", System32), new("fontdrvhost.exe", System32), new("ctfmon.exe", System32),
        new("searchindexer.exe", System32), new("lsaiso.exe", System32), new("logonui.exe", System32),
        new("runtimebroker.exe", System32), new("securityhealthservice.exe", System32), new("sgrmbroker.exe", System32),
        new("explorer.exe", new[] { "%win%" }),
        // The Windows 11 shell hosts, installed as system apps.
        new("searchhost.exe", new[] { @"%win%\SystemApps\MicrosoftWindows.Client.CBS_*" }),
        new("startmenuexperiencehost.exe", new[] { @"%win%\SystemApps\Microsoft.Windows.StartMenuExperienceHost_*" }),
        new("mssense.exe", new[] { @"%pf%\Windows Defender Advanced Threat Protection" }),
        // WMI provider host. Win32_Process and friends read process details through it.
        new("wmiprvse.exe", new[] { @"%win%\System32\wbem", @"%win%\SysWOW64\wbem" }, ReadsLsass: true),
        // Microsoft Defender: the engine and the network inspection service.
        new("msmpeng.exe", new[] { @"%pd%\Microsoft\Windows Defender\Platform\*", @"%pf%\Windows Defender" }, ReadsLsass: true),
        new("nissrv.exe", new[] { @"%pd%\Microsoft\Windows Defender\Platform\*", @"%pf%\Windows Defender" }, ReadsLsass: true),
        // The WebView2 runtime that Widgets, Search and the Start menu host their pages in.
        new("msedgewebview2.exe", new[] { @"%pf86%\Microsoft\EdgeWebView\Application\*", @"%pf%\Microsoft\EdgeWebView\Application\*" }),
        new("widgets.exe", new[] { @"%pf%\WindowsApps\MicrosoftWindows.Client.WebExperience_*\Dashboard" }),
    };

    /// <summary>Canonical names (lower case) of every component in the table.</summary>
    public static IReadOnlyList<string> Names { get; } = Table.Select(c => c.Name).Append("system").ToArray();

    /// <summary>True for a component that legitimately reads LSASS memory (WMI, the Defender engine).</summary>
    public static bool ReadsLsass(string? name)
        => !string.IsNullOrEmpty(name) && Table.Any(c => c.ReadsLsass && c.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

    /// <summary>The canonical name of the Windows component running as <paramref name="pid"/>, or null.</summary>
    public static string? Identify(int pid)
    {
        // The System process is always pid 4 and has no image file to check.
        if (pid == 4) return "system";
        if (pid <= 4) return null;
        try
        {
            var live = Response.ContainmentGuard.Describe(pid);
            string? name = live?.ImagePath is null ? null : IdentifyCached(live.ImagePath);
            return name is not null && IsWindowsInstance(name, live!) ? name : null;
        }
        catch { return null; }
    }

    /// <summary>
    /// The user's own shell programs, which run as the signed-in user: the account tells a real
    /// one from a copy no better than the path does.
    /// </summary>
    private static readonly HashSet<string> UserSession = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "explorer.exe", "searchhost.exe",
        "startmenuexperiencehost.exe", "msedgewebview2.exe", "widgets.exe",
    };

    /// <summary>
    /// The file is the component's own, but any user can start it and hollow it out, which only
    /// the instance gives away: svchost counts when the protected services.exe started it, the
    /// other services under a service account or protected, the user's own shell programs as they
    /// are (the residual the type summary states).
    /// </summary>
    internal static bool IsWindowsInstance(string name, Response.LiveProcess live) => name switch
    {
        "svchost.exe" => live.StartedByServices,
        _ when UserSession.Contains(name) => true,
        _ => live.Protected || live.ServiceAccount == true,
    };

    private static readonly ConcurrentDictionary<string, (string? Name, long Tick)> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly long CacheTtlMs = (long)TimeSpan.FromMinutes(10).TotalMilliseconds;
    private const int CacheLimit = 512;

    private static string? IdentifyCached(string path)
    {
        long now = Environment.TickCount64;
        if (Cache.TryGetValue(path, out var hit) && now - hit.Tick < CacheTtlMs) return hit.Name;
        string? name = Identify(path, Roots.Current(), KernelPolicy.WriteRisk);
        if (Cache.Count >= CacheLimit) Cache.Clear();
        Cache[path] = (name, now);
        return name;
    }

    /// <summary>The canonical name when <paramref name="imagePath"/> is a component's own file in its own folder, or null.</summary>
    internal static string? Identify(string imagePath, Roots roots, Func<string, string?> writeRisk)
    {
        if (string.IsNullOrWhiteSpace(imagePath) || !Path.IsPathFullyQualified(imagePath)) return null;
        if (imagePath.StartsWith(@"\\", StringComparison.Ordinal) || imagePath.Contains(@"\..", StringComparison.Ordinal)) return null;

        string file = Path.GetFileName(imagePath);
        string dir = Path.GetDirectoryName(imagePath) ?? "";
        foreach (var c in Table)
        {
            if (!c.Name.Equals(file, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var template in c.Dirs)
            {
                if (!DirectoryMatches(dir, Expand(template, roots))) continue;
                return writeRisk(imagePath) is null ? c.Name : null;
            }
        }
        return null;
    }

    private static string Expand(string template, Roots r) => template
        .Replace("%win%", r.Windows, StringComparison.Ordinal)
        .Replace("%pf86%", r.ProgramFilesX86, StringComparison.Ordinal)
        .Replace("%pf%", r.ProgramFiles, StringComparison.Ordinal)
        .Replace("%pd%", r.ProgramData, StringComparison.Ordinal);

    private static bool DirectoryMatches(string dir, string template)
    {
        var have = dir.TrimEnd('\\').Split('\\');
        var want = template.TrimEnd('\\').Split('\\');
        if (have.Length != want.Length) return false;
        for (int i = 0; i < want.Length; i++)
        {
            string w = want[i];
            if (w.Length > 0 && w[^1] == '*')
            {
                string prefix = w[..^1];
                if (have[i].Length <= prefix.Length || !have[i].StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            }
            else if (!string.Equals(have[i], w, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

}
