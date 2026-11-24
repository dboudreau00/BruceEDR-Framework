using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using BruceEDR.Configuration;
using BruceEDR.Core;

namespace BruceEDR.Driver;

/// <summary>A program the minifilter lets into one guarded store, or into every store when StoreIndex is -1.</summary>
public sealed record KernelTrustedImage(string Path, string NtPath, int StoreIndex, string Source);

/// <summary>The policy pushed to the driver: guarded stores in driver order, trusted images, and what was left out and why.</summary>
public sealed record KernelPolicyPlan(IReadOnlyList<KernelGuard> Stores, IReadOnlyList<KernelTrustedImage> Trusted,
    IReadOnlyList<string> Notes);

/// <summary>The machine facts a plan depends on; tests replace them.</summary>
public sealed class KernelPolicyEnvironment
{
    /// <summary>Full paths registered for an executable name.</summary>
    public required Func<string, IReadOnlyList<string>> FindOwner { get; init; }
    /// <summary>A file's final path and its NT form, or why it has none.</summary>
    public required Func<string, (string? Path, string? NtPath, string? Problem)> Resolve { get; init; }
    /// <summary>Null when only administrators can change the file and the folders above it.</summary>
    public required Func<string, string?> WriteRisk { get; init; }

    public static KernelPolicyEnvironment Machine { get; } = new()
    {
        FindOwner = KernelPolicy.Owners,
        Resolve = KernelPolicy.ResolveImage,
        WriteRisk = KernelPolicy.WriteRisk
    };
}

/// <summary>
/// Builds the minifilter policy from <see cref="IocDatabase.KernelGuards"/> and the config.
///
/// The driver trusts a process by its image path, so a path is trusted only where no standard
/// user can put other code behind it: each store's owner is taken from HKLM App Paths (which
/// only administrators write) or its machine-wide install folder, and every image, the
/// operator's included, must pass
/// <see cref="WriteRisk"/>. A program installed per user fails that check by design; its store
/// is then guarded against everyone, the owner included, unless the operator exempts it.
/// </summary>
public static class KernelPolicy
{
    private const string AppPathsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\";

    public static KernelPolicyPlan Build(DetectionConfig detection, KernelPolicyEnvironment env)
    {
        var notes = new List<string>();
        var exempt = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in detection.KernelExemptStores)
        {
            var guard = IocDatabase.KernelGuards.FirstOrDefault(g => g.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (guard is not null) exempt.Add(guard.Name);
            else notes.Add($"detection.kernelExemptStores: '{name}' is not a guarded store; ignored");
        }
        var stores = IocDatabase.KernelGuards.Where(g => !exempt.Contains(g.Name)).Take(MinifilterClient.MaxStores).ToList();
        if (exempt.Count > 0)
            notes.Add("not guarded, by detection.kernelExemptStores: " + string.Join(", ", exempt.Order(StringComparer.Ordinal)));

        var trusted = new List<KernelTrustedImage>();
        void Trust(string path, int index, string source)
        {
            var (final, nt, problem) = env.Resolve(path);
            if (problem is not null || final is null || nt is null)
            {
                notes.Add($"{source}: {path} not trusted: {problem ?? "unresolved"}");
                return;
            }
            var risk = env.WriteRisk(final);
            if (risk is not null)
            {
                notes.Add($"{source}: {final} not trusted: {risk}");
                return;
            }
            if (!MinifilterClient.IsWireText(nt))
            {
                notes.Add($"{source}: {final} not trusted: its NT path is {MinifilterClient.MaxPath} characters or longer");
                return;
            }
            if (trusted.Any(t => t.StoreIndex == index && t.NtPath.Equals(nt, StringComparison.OrdinalIgnoreCase))) return;
            if (trusted.Count >= MinifilterClient.MaxTrusted)
            {
                notes.Add($"{source}: {final} not trusted: the driver holds {MinifilterClient.MaxTrusted} trusted images");
                return;
            }
            trusted.Add(new KernelTrustedImage(final, nt, index, source));
        }

        for (int i = 0; i < stores.Count; i++)
        {
            foreach (var owner in stores[i].Owners)
            {
                foreach (var candidate in env.FindOwner(owner))
                {
                    // App Paths may name another file than its key; only the owner itself is trusted.
                    if (!Path.GetFileName(candidate).Equals(owner, StringComparison.OrdinalIgnoreCase))
                        notes.Add($"{stores[i].Name} owner: App Paths for {owner} names {candidate}; not trusted");
                    else
                        Trust(candidate, i, stores[i].Name + " owner");
                }
            }
        }

        foreach (var entry in detection.KernelTrustedImages)
        {
            const string source = "detection.kernelTrustedImages";
            if (string.IsNullOrWhiteSpace(entry.Image))
            {
                notes.Add(source + ": an entry has no image; ignored");
                continue;
            }
            if (entry.Stores.Length == 0)
            {
                Trust(entry.Image, -1, source);
                continue;
            }
            foreach (var name in entry.Stores)
            {
                int index = stores.FindIndex(g => g.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (index >= 0) Trust(entry.Image, index, source);
                else if (!exempt.Contains(name ?? "")) notes.Add($"{source}: '{name}' is not a guarded store; ignored for {entry.Image}");
            }
        }

        for (int i = 0; i < stores.Count; i++)
        {
            if (!trusted.Any(t => t.StoreIndex == i || t.StoreIndex == -1))
                notes.Add($"{stores[i].Name}: nothing trusted, so with blocking on every process is refused it, " +
                          $"{string.Join(" and ", stores[i].Owners)} included");
        }
        return new KernelPolicyPlan(stores, trusted, notes);
    }

    // ------------------------------------------------------------------ owners

    /// <summary>
    /// Where the machine-wide installers put each owner, under Program Files or Program Files
    /// (x86). Edge registers no App Paths key on some builds: two lab VMs had msedge.exe there
    /// and no key in either view, so Edge was refused its own profile. A file found here is
    /// trusted only if it passes <see cref="WriteRisk"/>, like any other.
    /// </summary>
    private static readonly (string Exe, string Relative)[] InstallFolders =
    {
        ("msedge.exe", @"Microsoft\Edge\Application\msedge.exe"),
        ("chrome.exe", @"Google\Chrome\Application\chrome.exe"),
        ("firefox.exe", @"Mozilla Firefox\firefox.exe"),
    };

    /// <summary>App Paths entries for an executable name, then its machine-wide install folders.</summary>
    public static IReadOnlyList<string> Owners(string exe) => Owners(exe, AppPaths(exe),
        new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) },
        File.Exists);

    internal static IReadOnlyList<string> Owners(string exe, IReadOnlyList<string> appPaths,
        IReadOnlyList<string> programRoots, Func<string, bool> exists)
    {
        var found = new List<string>(appPaths);
        foreach (var root in programRoots.Where(r => !string.IsNullOrEmpty(r)))
        {
            foreach (var (name, relative) in InstallFolders)
            {
                if (!name.Equals(exe, StringComparison.OrdinalIgnoreCase)) continue;
                var path = Path.Combine(root, relative);
                if (exists(path) && !found.Contains(path, StringComparer.OrdinalIgnoreCase)) found.Add(path);
            }
        }
        return found;
    }

    /// <summary>HKLM App Paths entries for an executable name, from the 64-bit and 32-bit views.</summary>
    public static IReadOnlyList<string> AppPaths(string exe)
    {
        var found = new List<string>();
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = hklm.OpenSubKey(AppPathsKey + exe);
                var path = CleanAppPath(key?.GetValue(null) as string);
                if (path is not null && !found.Contains(path, StringComparer.OrdinalIgnoreCase)) found.Add(path);
            }
            catch (Exception)
            {
                // An unreadable view offers no candidate; the owner simply goes untrusted.
            }
        }
        return found;
    }

    /// <summary>An App Paths value as a full local path (quotes and variables resolved), or null.</summary>
    internal static string? CleanAppPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var path = Environment.ExpandEnvironmentVariables(value.Trim());
        if (path.StartsWith('"'))
        {
            int close = path.IndexOf('"', 1);
            if (close < 0) return null;
            path = path[1..close];
        }
        return Path.IsPathFullyQualified(path) && !path.StartsWith(@"\\", StringComparison.Ordinal) ? path : null;
    }

    // ------------------------------------------------------------------ paths

    private const uint VolumeNameDos = 0x0;   // with FILE_NAME_NORMALIZED (0)
    private const uint VolumeNameNt = 0x2;

    /// <summary>
    /// A file's final path, with links, junctions and 8.3 names resolved, and the NT form the
    /// driver sees for a process image (\Device\HarddiskVolume3\...).
    /// </summary>
    public static (string? Path, string? NtPath, string? Problem) ResolveImage(string path)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
                return (null, null, "not a full local path");
            if (!File.Exists(path)) return (null, null, "no such file");
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var nt = FinalPath(handle, VolumeNameNt);
            var dos = FinalPath(handle, VolumeNameDos);
            if (nt is null || dos is null) return (null, null, "its final path could not be read");
            if (!nt.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ||
                nt.StartsWith(@"\Device\Mup\", StringComparison.OrdinalIgnoreCase) ||
                dos.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                return (null, null, "not on a local volume");
            return (dos.StartsWith(@"\\?\", StringComparison.Ordinal) ? dos[4..] : dos, nt, null);
        }
        catch (Exception ex)
        {
            return (null, null, ex.GetType().Name + ": " + ex.Message);
        }
    }

    private static string? FinalPath(SafeFileHandle handle, uint flags)
    {
        var buffer = new char[1024];
        for (int attempt = 0; attempt < 3; attempt++)
        {
            uint n = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, flags);
            if (n == 0) return null;
            if (n < buffer.Length) return new string(buffer, 0, (int)n);
            if (n > 32768) return null;
            buffer = new char[n + 1];   // n is the size needed, terminator included
        }
        return null;
    }

    // ------------------------------------------------------------------ permissions

    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");
    private static readonly SecurityIdentifier OwnerRights = new("S-1-3-4");

    private const FileSystemRights GenericWrite = (FileSystemRights)0x40000000;
    private const FileSystemRights GenericAll = (FileSystemRights)0x10000000;
    private const FileSystemRights Takeover =
        FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership | GenericAll;
    // Rewrite the image, or delete it and put another in its place.
    private const FileSystemRights ImageRights = Takeover | FileSystemRights.WriteData | FileSystemRights.AppendData | GenericWrite;
    // Plant a DLL beside the image, or swap the folder's contents.
    private const FileSystemRights FolderRights = Takeover | FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories |
                                                  FileSystemRights.DeleteSubdirectoriesAndFiles | GenericWrite;
    // Move a folder above it aside and build a look-alike path in its place.
    private const FileSystemRights AncestorRights = Takeover | FileSystemRights.DeleteSubdirectoriesAndFiles;

    /// <summary>
    /// Null when no account other than SYSTEM, Administrators or TrustedInstaller owns or can
    /// change the image, plant a file beside it, or move a folder above it; otherwise what one
    /// could do. Trust by path is sound only that far. An allow entry is enough to refuse,
    /// whatever deny entries say.
    /// </summary>
    public static string? WriteRisk(string path)
    {
        try
        {
            var file = new FileInfo(path);
            var problem = Risk(file.GetAccessControl(), ImageRights);
            if (problem is not null) return $"{file.FullName} {problem}";
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string windowsApps = programFiles.Length > 0
                ? Path.TrimEndingDirectorySeparator(Path.Combine(programFiles, "WindowsApps"))
                : "";
            var rights = FolderRights;
            for (var dir = file.Directory; dir is not null; dir = dir.Parent)
            {
                try
                {
                    problem = Risk(dir.GetAccessControl(), rights);
                    if (problem is not null) return $"{dir.FullName} {problem}";
                }
                catch (UnauthorizedAccessException) when (
                    windowsApps.Length > 0 &&
                    string.Equals(Path.TrimEndingDirectorySeparator(dir.FullName), windowsApps, StringComparison.OrdinalIgnoreCase))
                {
                    // C:\Program Files\WindowsApps is owned by TrustedInstaller and denies READ_CONTROL even to
                    // elevated Administrators; the file itself, its package folder, and C:\Program Files above it
                    // are still checked.
                }
                rights = AncestorRights;
            }
            return null;
        }
        catch (Exception ex)
        {
            return $"its permissions could not be read ({ex.GetType().Name})";
        }
    }

    /// <summary>
    /// <see cref="WriteRisk"/> for a file that may not exist yet. An existing file is checked
    /// as usual. For a missing one the nearest existing folder is checked as the file's folder
    /// (whoever can create files there can supply the file) and its ancestors as ancestors.
    /// </summary>
    public static string? WriteRiskOfNearest(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            if (File.Exists(full)) return WriteRisk(full);
            if (Directory.Exists(full)) return $"{full} is a directory";
            var dir = new FileInfo(full).Directory;
            while (dir is not null && !dir.Exists) dir = dir.Parent;
            var rights = FolderRights;
            for (; dir is not null; dir = dir.Parent)
            {
                var problem = Risk(dir.GetAccessControl(), rights);
                if (problem is not null) return $"{dir.FullName} {problem}";
                rights = AncestorRights;
            }
            return null;
        }
        catch (Exception ex)
        {
            return $"its permissions could not be read ({ex.GetType().Name})";
        }
    }

    private static string? Risk(FileSystemSecurity security, FileSystemRights dangerous)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !IsAdministrative(owner)) return "is owned by " + Describe(owner);
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow || rule.PropagationFlags.HasFlag(PropagationFlags.InheritOnly)) continue;
            if (rule.IdentityReference is not SecurityIdentifier sid || IsAdministrative(sid) || sid.Equals(OwnerRights)) continue;
            if ((rule.FileSystemRights & dangerous) != 0) return "can be changed by " + Describe(sid);
        }
        return null;
    }

    private static bool IsAdministrative(SecurityIdentifier sid) =>
        sid.Equals(LocalSystem) || sid.Equals(Administrators) || sid.Equals(TrustedInstaller);

    private static string Describe(SecurityIdentifier? sid)
    {
        if (sid is null) return "an unknown account";
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch (Exception) { return sid.Value; }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle hFile, [Out] char[] lpszFilePath, uint cchFilePath, uint dwFlags);
}

/// <summary>Turns the driver's \Device\HarddiskVolumeN\... names back into drive-letter paths for people to read.</summary>
public sealed class DosDeviceMap
{
    private readonly (string Device, string Drive)[] _map;

    internal DosDeviceMap(IEnumerable<(string Device, string Drive)> map) => _map = map.ToArray();

    public static DosDeviceMap Empty { get; } = new(Array.Empty<(string, string)>());

    /// <summary>The drive letters mapped to local devices right now; subst drives are left out.</summary>
    public static DosDeviceMap Current()
    {
        var map = new List<(string, string)>();
        var buffer = new char[1024];
        for (char letter = 'A'; letter <= 'Z'; letter++)
        {
            string drive = letter + ":";
            uint n = QueryDosDeviceW(drive, buffer, (uint)buffer.Length);
            if (n == 0) continue;
            var target = new string(buffer, 0, (int)n).Split('\0')[0];
            if (target.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) map.Add((target, drive));
        }
        return new DosDeviceMap(map);
    }

    public string ToDos(string ntPath)
    {
        foreach (var (device, drive) in _map)
        {
            if (ntPath.Length > device.Length && ntPath[device.Length] == '\\' &&
                ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return drive + ntPath[device.Length..];
        }
        return ntPath;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string lpDeviceName, [Out] char[] lpTargetPath, uint ucchMax);
}

/// <summary>
/// Keeps a refusal storm out of the sinks: one event per process, operation and path per
/// window, and no more than a fixed number per window in all. What it holds back is counted
/// and reported with the next event it lets through.
/// </summary>
public sealed class KernelDenialThrottle
{
    private readonly object _gate = new();
    private readonly TimeSpan _window;
    private readonly int _perWindow;
    private readonly Dictionary<string, DateTime> _lastLogged = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _windowStart = DateTime.MinValue;
    private int _loggedInWindow;
    private int _held;

    public KernelDenialThrottle(TimeSpan window, int perWindow)
    {
        _window = window;
        _perWindow = Math.Max(1, perWindow);
    }

    /// <summary>True when this refusal should be logged; <paramref name="heldBefore"/> is how many were held back since the last one.</summary>
    public bool Admit(string key, DateTime nowUtc, out int heldBefore)
    {
        lock (_gate)
        {
            heldBefore = 0;
            // A clock stepped back would otherwise hold every refusal until it caught up again.
            if (nowUtc - _windowStart >= _window || nowUtc < _windowStart)
            {
                _windowStart = nowUtc;
                _loggedInWindow = 0;
                foreach (var stale in _lastLogged.Where(kv => nowUtc - kv.Value >= _window).Select(kv => kv.Key).ToList())
                    _lastLogged.Remove(stale);
                if (_lastLogged.Count > 4096) _lastLogged.Clear();
            }
            if ((_lastLogged.TryGetValue(key, out var last) && nowUtc - last < _window && nowUtc >= last) || _loggedInWindow >= _perWindow)
            {
                _held++;
                return false;
            }
            _lastLogged[key] = nowUtc;
            _loggedInWindow++;
            heldBefore = _held;
            _held = 0;
            return true;
        }
    }

    /// <summary>The count held back since the last admitted refusal, reset to zero.</summary>
    public int TakeHeld()
    {
        lock (_gate)
        {
            int held = _held;
            _held = 0;
            return held;
        }
    }
}
