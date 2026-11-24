using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BruceEDR.Configuration;
using BruceEDR.Detection;
using BruceEDR.Driver;
using Microsoft.Win32;
using static BruceEDR.Native.NativeMethods;

namespace BruceEDR.Security;

/// <summary>Operator baseline posture chosen for a discovered process or installed program.</summary>
public enum BaselineTrustChoice
{
    /// <summary>No explicit watchlist override; normal behavioural rules and publisher trust apply.</summary>
    Default = 0,
    /// <summary>Trusted: adds an <c>allow</c> watchlist entry (by path if admin-only, SHA-256 if user-writable).</summary>
    Trusted = 1,
    /// <summary>Untrusted: adds a <c>quarantine</c> watchlist entry (reported in monitor mode, contained in enforce mode).</summary>
    Untrusted = 2,
}

/// <summary>One unique executable discovered in the live process tree or installed-programs inventory.</summary>
public sealed class BaselineEntry
{
    public required string ProcessName { get; init; }
    public required string DisplayName { get; init; }
    public required string ImagePath { get; init; }
    public bool IsRunning { get; init; }
    public bool IsInstalledApp { get; init; }
    public int InstanceCount { get; init; }
    public int SamplePid { get; init; }
    public int ParentPid { get; init; }
    public string ParentName { get; init; } = "";
    public bool Signed { get; init; }
    public string Publisher { get; init; } = "";
    public bool AdminOnly { get; init; }
    public bool ProtectedSystem { get; init; }

    public string SourceBadge => (IsRunning, IsInstalledApp) switch
    {
        (true, true) => InstanceCount > 1 ? $"Running ({InstanceCount}) + App" : "Running + App",
        (true, false) => InstanceCount > 1 ? $"Running ({InstanceCount})" : "Running",
        (false, true) => "Installed app",
        _ => "Discovered"
    };

    public string TreeSummary => !IsRunning
        ? "Not currently running"
        : ParentName.Length > 0 && ParentPid > 0
            ? $"PID {SamplePid} ← {ParentName} ({ParentPid})"
            : SamplePid > 0 ? $"PID {SamplePid}" : "Running";

    public string SignatureSummary => Signed
        ? $"signed by {Publisher}"
        : "unsigned";
}

/// <summary>A signing authority discovered on binaries present on this endpoint.</summary>
public sealed class BaselinePublisher
{
    public required string Name { get; init; }
    /// <summary>Count of binaries signed by this publisher in admin-protected install directories.</summary>
    public int AdminInstalledCount { get; init; }
    /// <summary>Total discovered binaries signed by this publisher on this endpoint.</summary>
    public int TotalCount { get; init; }
    /// <summary>True when at least one signed binary lives in an admin-protected install directory.</summary>
    public bool VerifiedAdminInstall => AdminInstalledCount > 0;
}

/// <summary>Snapshot returned by <see cref="BaselineScanner.Scan"/>.</summary>
public sealed class BaselineScanResult
{
    public required IReadOnlyList<BaselineEntry> Entries { get; init; }
    public required IReadOnlyList<BaselinePublisher> Publishers { get; init; }
    public int RunningProcessCount { get; init; }
    public int InstalledAppCount { get; init; }
}

/// <summary>
/// First-start and on-demand endpoint baseline scanner. Walks the live process tree and installed
/// Windows applications, verifies Authenticode signing authorities once per unique executable path,
/// and translates operator Trusted / Untrusted decisions into validated <see cref="WatchlistEntryConfig"/> rules.
/// </summary>
public static class BaselineScanner
{
    private const string BaselineNoteTag = "[baseline]";

    private static readonly HashSet<string> IgnoredInstallerExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "uninstall.exe", "unins000.exe", "unins001.exe", "uninst.exe", "msiexec.exe",
        "setup.exe", "update.exe", "updater.exe", "crashreporter.exe", "crashpad_handler.exe"
    };

    private sealed class CandidateAccumulator
    {
        public required string ImagePath { get; init; }
        public string ProcessName { get; set; } = "";
        public string DisplayName { get; set; } = "";
        public bool IsRunning { get; set; }
        public bool IsInstalledApp { get; set; }
        public int InstanceCount { get; set; }
        public int SamplePid { get; set; }
        public int ParentPid { get; set; }
        public string ParentName { get; set; } = "";
    }

    public static BaselineScanResult Scan(CancellationToken ct = default)
    {
        var byPath = new Dictionary<string, CandidateAccumulator>(StringComparer.OrdinalIgnoreCase);
        int selfPid = Environment.ProcessId;
        int totalRunning = 0;

        // 1. Snapshot the live process tree so parent names can be resolved without re-opening handles.
        var pidNames = new Dictionary<int, string>();
        var liveRows = new List<(int Pid, int ParentPid, string Name, string ImagePath)>();

        Process[] processes;
        try { processes = Process.GetProcesses(); }
        catch { processes = Array.Empty<Process>(); }

        foreach (var proc in processes)
        {
            using (proc)
            {
                if (ct.IsCancellationRequested) break;
                int pid;
                string rawName;
                try
                {
                    pid = proc.Id;
                    rawName = proc.ProcessName ?? "";
                }
                catch { continue; }

                string exeName = rawName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || rawName.Length == 0
                    ? rawName : rawName + ".exe";
                pidNames[pid] = exeName;

                if (pid <= 4 || pid == selfPid) continue;

                var (imgPath, ppid) = QueryProcessPathAndParent(pid);
                if (string.IsNullOrWhiteSpace(imgPath) || !File.Exists(imgPath)) continue;

                totalRunning++;
                liveRows.Add((pid, ppid, Path.GetFileName(imgPath), imgPath));
            }
        }

        foreach (var row in liveRows)
        {
            string normPath = NormalizePath(row.ImagePath);
            if (!byPath.TryGetValue(normPath, out var acc))
            {
                acc = new CandidateAccumulator
                {
                    ImagePath = normPath,
                    ProcessName = row.Name,
                    DisplayName = FriendlyFileTitle(normPath, row.Name),
                };
                byPath[normPath] = acc;
            }
            acc.IsRunning = true;
            acc.InstanceCount++;
            if (acc.SamplePid == 0)
            {
                acc.SamplePid = row.Pid;
                acc.ParentPid = row.ParentPid;
                if (row.ParentPid > 0 && pidNames.TryGetValue(row.ParentPid, out var pname))
                    acc.ParentName = pname;
            }
        }

        // 2. Discover installed applications from Windows Uninstall + App Paths + %LOCALAPPDATA%\Programs.
        int installedCount = 0;
        foreach (var (displayName, exePath) in EnumerateInstalledPrograms(ct))
        {
            if (ct.IsCancellationRequested) break;
            string normPath = NormalizePath(exePath);
            if (IsSelfExecutable(normPath)) continue;

            if (!byPath.TryGetValue(normPath, out var acc))
            {
                string procName = Path.GetFileName(normPath);
                acc = new CandidateAccumulator
                {
                    ImagePath = normPath,
                    ProcessName = procName,
                    DisplayName = displayName.Length > 0 ? displayName : FriendlyFileTitle(normPath, procName),
                };
                byPath[normPath] = acc;
            }
            else if (displayName.Length > 0 && string.Equals(acc.DisplayName, Path.GetFileNameWithoutExtension(normPath), StringComparison.OrdinalIgnoreCase))
            {
                acc.DisplayName = displayName;
            }

            if (!acc.IsInstalledApp)
            {
                acc.IsInstalledApp = true;
                installedCount++;
            }
        }

        // 3. Evaluate Authenticode signature + folder write-risk once per unique executable path.
        var standingByPath = new ConcurrentDictionary<string, (string? Publisher, bool AdminOnly)>(StringComparer.OrdinalIgnoreCase);
        var uniquePaths = byPath.Keys.ToArray();
        Parallel.ForEach(
            uniquePaths,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 6),
                CancellationToken = CancellationToken.None
            },
            path =>
            {
                if (ct.IsCancellationRequested) return;
                string? pub = null;
                bool adminOnly = false;
                try { pub = AuthenticodeVerifier.PublisherOf(path); } catch { }
                try { adminOnly = KernelPolicy.WriteRisk(path) is null; } catch { }
                standingByPath[path] = (pub, adminOnly);
            });

        // 4. Materialise entries and aggregate discovered signing authorities.
        var entries = new List<BaselineEntry>(byPath.Count);
        var pubCounts = new Dictionary<string, (int AdminInstalled, int Total)>(StringComparer.OrdinalIgnoreCase);
        var canonicalPubName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var acc in byPath.Values)
        {
            standingByPath.TryGetValue(acc.ImagePath, out var st);
            string pub = (st.Publisher ?? "").Trim();
            bool signed = pub.Length > 0;
            bool adminOnly = st.AdminOnly;
            bool protectedSys = signed && adminOnly && Watchlist.IsProtected(acc.ProcessName);

            entries.Add(new BaselineEntry
            {
                ProcessName = acc.ProcessName,
                DisplayName = acc.DisplayName.Length > 0 ? acc.DisplayName : acc.ProcessName,
                ImagePath = acc.ImagePath,
                IsRunning = acc.IsRunning,
                IsInstalledApp = acc.IsInstalledApp,
                InstanceCount = acc.InstanceCount,
                SamplePid = acc.SamplePid,
                ParentPid = acc.ParentPid,
                ParentName = acc.ParentName,
                Signed = signed,
                Publisher = pub,
                AdminOnly = adminOnly,
                ProtectedSystem = protectedSys,
            });

            if (signed)
            {
                if (!canonicalPubName.ContainsKey(pub))
                    canonicalPubName[pub] = pub;
                pubCounts.TryGetValue(pub, out var counts);
                pubCounts[pub] = (counts.AdminInstalled + (adminOnly ? 1 : 0), counts.Total + 1);
            }
        }

        // Sort: unsigned running first, then non-Windows running apps, then installed apps, then OS plumbing.
        var sortedEntries = entries
            .OrderBy(e => e.ProtectedSystem ? 1 : 0)
            .ThenByDescending(e => e.IsRunning && !e.Signed)
            .ThenByDescending(e => e.IsRunning && !IsMicrosoftPublisher(e.Publisher))
            .ThenByDescending(e => e.IsRunning)
            .ThenBy(e => e.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var sortedPublishers = pubCounts
            .Select(kv => new BaselinePublisher
            {
                Name = canonicalPubName[kv.Key],
                AdminInstalledCount = kv.Value.AdminInstalled,
                TotalCount = kv.Value.Total
            })
            .OrderByDescending(p => p.VerifiedAdminInstall)
            .ThenByDescending(p => p.AdminInstalledCount)
            .ThenByDescending(p => p.TotalCount)
            .ThenBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new BaselineScanResult
        {
            Entries = sortedEntries,
            Publishers = sortedPublishers,
            RunningProcessCount = totalRunning,
            InstalledAppCount = installedCount,
        };
    }

    /// <summary>
    /// Translates one operator baseline choice into a validated <see cref="WatchlistEntryConfig"/>,
    /// or <c>null</c> when <paramref name="choice"/> is <see cref="BaselineTrustChoice.Default"/>
    /// or the target cannot be safely represented.
    /// </summary>
    public static WatchlistEntryConfig? BuildWatchlistEntry(BaselineEntry entry, BaselineTrustChoice choice)
    {
        if (choice == BaselineTrustChoice.Default) return null;
        if (!Path.IsPathFullyQualified(entry.ImagePath)) return null;

        if (choice == BaselineTrustChoice.Trusted)
        {
            // Match WatchlistViewModel.AllowProgram: admin-only paths are allowed by path (surviving
            // app updates), while user-writable binaries are pinned by SHA-256 so another file dropped
            // at the same path never inherits the allowance.
            if (entry.AdminOnly)
            {
                return new WatchlistEntryConfig
                {
                    Match = "path",
                    Value = entry.ImagePath,
                    Action = "allow",
                    Score = 0,
                    Enabled = true,
                    Note = $"{BaselineNoteTag} Trusted by path ({entry.DisplayName})",
                };
            }

            if (!File.Exists(entry.ImagePath)) return null;
            string sha = ComputeSha256Hex(entry.ImagePath);
            if (sha.Length != 64) return null;

            return new WatchlistEntryConfig
            {
                Match = "hash",
                Value = sha,
                Action = "allow",
                Score = 0,
                Enabled = true,
                Note = $"{BaselineNoteTag} {entry.ImagePath} trusted by SHA-256 ({entry.DisplayName})",
            };
        }

        // Untrusted: refuse to build a containment rule for signed, admin-only protected OS processes.
        if (entry.ProtectedSystem) return null;

        return new WatchlistEntryConfig
        {
            Match = "path",
            Value = entry.ImagePath,
            Action = "quarantine",
            Score = 0,
            Enabled = true,
            Note = $"{BaselineNoteTag} Marked untrusted during setup ({entry.DisplayName})",
        };
    }

    /// <summary>
    /// Reads existing <see cref="WatchlistEntryConfig"/> rules to infer which discovered entries
    /// are already marked Trusted (<c>allow</c>) or Untrusted (<c>quarantine</c>/<c>warn</c>).
    /// </summary>
    public static BaselineTrustChoice InferExistingChoice(BaselineEntry entry, IReadOnlyList<WatchlistEntryConfig>? existing)
    {
        if (existing is null || existing.Count == 0) return BaselineTrustChoice.Default;

        string? lazyHash = null;
        foreach (var e in existing)
        {
            if (e is null || !e.Enabled) continue;
            string match = (e.Match ?? "").Trim();
            string val = (e.Value ?? "").Trim();
            string act = (e.Action ?? "").Trim();
            if (val.Length == 0) continue;

            bool matchesEntry = false;
            if (match.Equals("path", StringComparison.OrdinalIgnoreCase))
            {
                matchesEntry = string.Equals(NormalizePath(val), entry.ImagePath, StringComparison.OrdinalIgnoreCase);
            }
            else if (match.Equals("name", StringComparison.OrdinalIgnoreCase))
            {
                string normName = val.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? val : val + ".exe";
                matchesEntry = string.Equals(normName, entry.ProcessName, StringComparison.OrdinalIgnoreCase);
            }
            else if (match.Equals("hash", StringComparison.OrdinalIgnoreCase) && File.Exists(entry.ImagePath))
            {
                lazyHash ??= ComputeSha256Hex(entry.ImagePath);
                matchesEntry = lazyHash.Length == 64 && string.Equals(val, lazyHash, StringComparison.OrdinalIgnoreCase);
            }
            else if (e.Note?.Contains(entry.ImagePath, StringComparison.OrdinalIgnoreCase) == true &&
                     e.Note.Contains(BaselineNoteTag, StringComparison.OrdinalIgnoreCase))
            {
                matchesEntry = true;
            }

            if (!matchesEntry) continue;

            if (act.Equals("allow", StringComparison.OrdinalIgnoreCase))
                return BaselineTrustChoice.Trusted;
            if (act.Equals("quarantine", StringComparison.OrdinalIgnoreCase) ||
                act.Equals("warn", StringComparison.OrdinalIgnoreCase))
                return BaselineTrustChoice.Untrusted;
        }
        return BaselineTrustChoice.Default;
    }

    /// <summary>
    /// Merges operator baseline choices into <paramref name="existing"/> watchlist entries while
    /// preserving all hand-authored rules (such as the default disabled <c>mimikatz</c> / <c>-enc</c> templates).
    /// </summary>
    public static WatchlistEntryConfig[] MergeWatchlistEntries(
        IEnumerable<WatchlistEntryConfig>? existing,
        IEnumerable<(BaselineEntry Entry, BaselineTrustChoice Choice)> decisions)
    {
        var decisionList = decisions.ToList();
        var touchedPaths = new HashSet<string>(decisionList.Select(d => d.Entry.ImagePath), StringComparer.OrdinalIgnoreCase);

        var result = new List<WatchlistEntryConfig>();
        foreach (var old in existing ?? Array.Empty<WatchlistEntryConfig>())
        {
            if (old is null) continue;
            if (TouchesAnyBaselinePath(old, touchedPaths)) continue;
            result.Add(old);
        }

        var seenKeys = new HashSet<string>(
            result.Where(r => r.Enabled).Select(r => $"{(r.Match ?? "").ToLowerInvariant()}|{(r.Value ?? "").Trim().ToLowerInvariant()}"),
            StringComparer.OrdinalIgnoreCase);

        foreach (var (entry, choice) in decisionList)
        {
            var built = BuildWatchlistEntry(entry, choice);
            if (built is null) continue;

            // Validate against the real Watchlist compiler so an invalid entry can never reach disk.
            if (Watchlist.Compile(new[] { built }).Count == 0) continue;

            string key = $"{built.Match.ToLowerInvariant()}|{built.Value.Trim().ToLowerInvariant()}";
            if (seenKeys.Add(key))
                result.Add(built);
        }

        return result.ToArray();
    }

    private static bool TouchesAnyBaselinePath(WatchlistEntryConfig cfg, HashSet<string> touchedPaths)
    {
        if (touchedPaths.Count == 0) return false;
        string match = (cfg.Match ?? "").Trim();
        string val = (cfg.Value ?? "").Trim();
        string note = cfg.Note ?? "";

        if (match.Equals("path", StringComparison.OrdinalIgnoreCase) && val.Length > 0 && touchedPaths.Contains(NormalizePath(val)))
            return true;

        if (note.Contains(BaselineNoteTag, StringComparison.OrdinalIgnoreCase))
        {
            foreach (var p in touchedPaths)
                if (note.Contains(p, StringComparison.OrdinalIgnoreCase))
                    return true;
        }
        return false;
    }

    private static string ComputeSha256Hex(string path)
    {
        try
        {
            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch { return ""; }
    }

    private static (string? ImagePath, int ParentPid) QueryProcessPathAndParent(int pid)
    {
        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return (null, 0);
        try
        {
            var buffer = new char[4096];
            uint size = (uint)buffer.Length;
            string? path = QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0
                ? new string(buffer, 0, (int)size)
                : null;

            int ppid = 0;
            if (NtQueryInformationProcess(handle, 0, out PROCESS_BASIC_INFORMATION info,
                    Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) == 0)
            {
                long p = info.InheritedFromUniqueProcessId.ToInt64();
                if (p > 0 && p <= int.MaxValue) ppid = (int)p;
            }
            return (path, ppid);
        }
        finally { CloseHandle(handle); }
    }

    private static IEnumerable<(string DisplayName, string ExePath)> EnumerateInstalledPrograms(CancellationToken ct)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        (RegistryHive Hive, RegistryView View, string SubKey)[] uninstallRoots =
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser,  RegistryView.Default,    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        };

        foreach (var root in uninstallRoots)
        {
            if (ct.IsCancellationRequested) yield break;
            using var baseKey = TryOpenBaseKey(root.Hive, root.View);
            using var uninstall = TryOpenSubKey(baseKey, root.SubKey);
            if (uninstall is null) continue;

            string[] subNames;
            try { subNames = uninstall.GetSubKeyNames(); }
            catch { continue; }

            foreach (var sub in subNames)
            {
                if (ct.IsCancellationRequested) yield break;
                using var appKey = TryOpenSubKey(uninstall, sub);
                if (appKey is null) continue;

                if (ReadDword(appKey, "SystemComponent") == 1) continue;
                string displayName = ReadString(appKey, "DisplayName");
                if (displayName.Length == 0) continue;

                string? exe = TryResolveFromIcon(ReadString(appKey, "DisplayIcon"))
                           ?? TryResolveFromInstallLocation(ReadString(appKey, "InstallLocation"), displayName);
                if (exe is not null && seen.Add(exe))
                    yield return (displayName, exe);
            }
        }

        // App Paths catches registered executables (firefox.exe, chrome.exe, msedge.exe, WinWord.exe, etc.)
        // whose Uninstall entry only lists an MSI or non-exe icon.
        (RegistryHive Hive, string SubKey)[] appPathRoots =
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
            (RegistryHive.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"),
        };

        foreach (var root in appPathRoots)
        {
            if (ct.IsCancellationRequested) yield break;
            using var baseKey = TryOpenBaseKey(root.Hive, RegistryView.Registry64);
            using var appPaths = TryOpenSubKey(baseKey, root.SubKey);
            if (appPaths is null) continue;

            string[] subNames;
            try { subNames = appPaths.GetSubKeyNames(); }
            catch { continue; }

            foreach (var sub in subNames)
            {
                if (ct.IsCancellationRequested) yield break;
                using var k = TryOpenSubKey(appPaths, sub);
                if (k is null) continue;
                string? exe = CleanCandidateExePath(ReadString(k, ""));
                if (exe is not null && seen.Add(exe))
                    yield return (FriendlyFileTitle(exe, sub), exe);
            }
        }

        // Shallow scan of %LOCALAPPDATA%\Programs\<App>\*.exe for per-user installs (VS Code, Git, Python, etc.).
        string localPrograms = "";
        try
        {
            localPrograms = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs");
        }
        catch { }

        if (localPrograms.Length > 0 && Directory.Exists(localPrograms))
        {
            IEnumerable<string> appDirs;
            try { appDirs = Directory.EnumerateDirectories(localPrograms); }
            catch { appDirs = Array.Empty<string>(); }

            foreach (var dir in appDirs)
            {
                if (ct.IsCancellationRequested) yield break;
                string? exe = TryPickPrimaryExeInDirectory(dir, Path.GetFileName(dir));
                if (exe is not null && seen.Add(exe))
                    yield return (FriendlyFileTitle(exe, Path.GetFileName(dir)), exe);
            }
        }
    }

    private static RegistryKey? TryOpenBaseKey(RegistryHive hive, RegistryView view)
    {
        try { return RegistryKey.OpenBaseKey(hive, view); }
        catch { return null; }
    }

    private static RegistryKey? TryOpenSubKey(RegistryKey? parent, string name)
    {
        if (parent is null) return null;
        try { return parent.OpenSubKey(name, writable: false); }
        catch { return null; }
    }

    private static string ReadString(RegistryKey key, string valueName)
    {
        try { return (key.GetValue(valueName) as string)?.Trim() ?? ""; }
        catch { return ""; }
    }

    private static int ReadDword(RegistryKey key, string valueName)
    {
        try { return key.GetValue(valueName) is int v ? v : 0; }
        catch { return 0; }
    }

    private static string? TryResolveFromIcon(string rawIcon)
    {
        if (rawIcon.Length == 0) return null;
        string s = rawIcon.Trim();

        // Strip trailing ",0" / ",-101" icon resource index.
        int comma = s.LastIndexOf(',');
        if (comma > 0 && int.TryParse(s[(comma + 1)..].Trim(), out _))
            s = s[..comma].Trim();

        return CleanCandidateExePath(s);
    }

    private static string? TryResolveFromInstallLocation(string rawLocation, string hintName)
    {
        if (rawLocation.Length == 0) return null;
        string dir = rawLocation.Trim().Trim('"');
        if (dir.Length < 4 || !Path.IsPathFullyQualified(dir) || !Directory.Exists(dir)) return null;
        return TryPickPrimaryExeInDirectory(dir, hintName);
    }

    private static string? TryPickPrimaryExeInDirectory(string dir, string hintName)
    {
        try
        {
            var candidates = new List<string>();
            foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly))
            {
                string fileName = Path.GetFileName(file);
                if (IgnoredInstallerExeNames.Contains(fileName)) continue;
                candidates.Add(file);
                if (candidates.Count >= 24) break;
            }
            if (candidates.Count == 0) return null;
            if (candidates.Count == 1) return candidates[0];

            string compactHint = CompactAlphaNumeric(hintName);
            if (compactHint.Length >= 3)
            {
                var best = candidates.FirstOrDefault(c =>
                {
                    string stem = CompactAlphaNumeric(Path.GetFileNameWithoutExtension(c));
                    return stem.Length >= 3 && (compactHint.Contains(stem, StringComparison.OrdinalIgnoreCase)
                                             || stem.Contains(compactHint, StringComparison.OrdinalIgnoreCase));
                });
                if (best is not null) return best;
            }
            return candidates[0];
        }
        catch { return null; }
    }

    private static string? CleanCandidateExePath(string raw)
    {
        if (raw.Length == 0) return null;
        string s = Environment.ExpandEnvironmentVariables(raw.Trim());
        if (s.StartsWith('"'))
        {
            int endQuote = s.IndexOf('"', 1);
            s = endQuote > 1 ? s[1..endQuote] : s.Trim('"');
        }
        else
        {
            int exeIdx = s.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeIdx > 0 && exeIdx + 4 < s.Length && char.IsWhiteSpace(s[exeIdx + 4]))
                s = s[..(exeIdx + 4)];
        }

        s = s.Trim();
        if (!s.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        if (!Path.IsPathFullyQualified(s)) return null;
        string fileName = Path.GetFileName(s);
        if (IgnoredInstallerExeNames.Contains(fileName)) return null;
        try { return File.Exists(s) ? Path.GetFullPath(s) : null; }
        catch { return null; }
    }

    private static string FriendlyFileTitle(string path, string fallbackName)
    {
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            string desc = (info.FileDescription ?? "").Trim();
            if (desc.Length >= 2) return desc;
            string prod = (info.ProductName ?? "").Trim();
            if (prod.Length >= 2) return prod;
        }
        catch { }
        string stem = Path.GetFileNameWithoutExtension(fallbackName);
        return stem.Length > 0 ? stem : fallbackName;
    }

    private static string NormalizePath(string path)
    {
        try { return Path.GetFullPath(path.Trim()); }
        catch { return path.Trim(); }
    }

    private static bool IsSelfExecutable(string normPath)
    {
        string file = Path.GetFileName(normPath);
        return file.Equals("BruceEDR.exe", StringComparison.OrdinalIgnoreCase)
            || file.Equals("BruceEDR.Gui.exe", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsMicrosoftPublisher(string pub)
        => pub.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);

    private static string CompactAlphaNumeric(string s)
    {
        Span<char> buf = stackalloc char[Math.Min(s.Length, 128)];
        int n = 0;
        for (int i = 0; i < s.Length && n < buf.Length; i++)
            if (char.IsLetterOrDigit(s[i])) buf[n++] = char.ToLowerInvariant(s[i]);
        return new string(buf[..n]);
    }
}
