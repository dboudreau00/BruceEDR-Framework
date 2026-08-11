using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ProcessShield.Core;

namespace ProcessShield.Response;

/// <summary>Outcome of one triage collection.</summary>
public sealed record TriageResult
{
    /// <summary>True when a zip was produced. Individual missing artifacts do not clear this.</summary>
    public bool Ok { get; init; }
    public string ZipPath { get; init; } = "";
    /// <summary>Why no zip was produced. Empty when <see cref="Ok"/> is true.</summary>
    public string Error { get; init; } = "";
    /// <summary>Names of the artifacts that made it into the zip.</summary>
    public IReadOnlyList<string> Included { get; init; } = Array.Empty<string>();
    /// <summary>
    /// Artifacts that could not be collected, each with the reason. Access-denied
    /// entries land here rather than failing the run: a non-elevated agent, or one
    /// looking at a protected process, still produces a useful package.
    /// </summary>
    public IReadOnlyList<string> Skipped { get; init; } = Array.Empty<string>();
    /// <summary>Size of the finished zip in bytes.</summary>
    public long Bytes { get; init; }
}

/// <summary>
/// Captures a forensic snapshot of a process and its host into a single zip, so an
/// analyst still has evidence after containment has suspended, firewalled, quarantined
/// or killed the subject.
///
/// Every artifact is best-effort and independent: a failure is recorded in
/// <see cref="TriageResult.Skipped"/> and collection continues. That is the whole point
/// — triage runs during an incident, on a process that may be protected, exiting or
/// already gone, from an agent that may not be elevated, and a package with eight of
/// ten artifacts is worth far more than an exception.
///
/// What this is NOT: it does not dump process memory, it does not copy the image file,
/// and it does not capture packet data. Those need either much more privilege or much
/// more disk than a response action should take on its own.
/// </summary>
public sealed class TriageCollector
{
    /// <summary>Guard against an absurd number of same-second collisions on the zip name.</summary>
    private const int MaxNameAttempts = 100;

    private readonly IClock _clock;

    public TriageCollector(IClock? clock = null) => _clock = clock ?? SystemClock.Instance;

    /// <summary>
    /// Collects triage for <paramref name="pid"/> into a zip under
    /// <paramref name="outputDir"/>. Pass the detection <paramref name="snapshot"/> when
    /// one exists so the package carries the reasoning that led to the response, not
    /// just the machine state after it.
    /// </summary>
    public TriageResult Collect(int pid, string outputDir, ProfileSnapshot? snapshot = null)
    {
        DateTime now = _clock.UtcNow;

        if (string.IsNullOrWhiteSpace(outputDir))
            return new TriageResult { Error = "output directory is empty" };

        string zipPath;
        try
        {
            Directory.CreateDirectory(outputDir);
            zipPath = UniqueZipPath(outputDir, pid, now);
        }
        catch (Exception ex)
        {
            return new TriageResult { Error = $"cannot prepare output directory: {ex.GetType().Name}: {ex.Message}" };
        }

        string stagingDir = Path.Combine(Path.GetTempPath(),
            "ProcessShield-triage-" + Guid.NewGuid().ToString("n"));

        try
        {
            Directory.CreateDirectory(stagingDir);
            var stage = new TriageStage(stagingDir);
            Populate(stage, pid, now, snapshot);

            // The manifest is written last so it can describe what the rest of the run
            // managed to collect.
            stage.AddText("manifest.json", () => RenderManifest(pid, now, stage));

            try
            {
                ZipFile.CreateFromDirectory(stagingDir, zipPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            }
            catch (Exception ex)
            {
                return new TriageResult
                {
                    Error = $"zip creation failed: {ex.GetType().Name}: {ex.Message}",
                    Included = stage.Included,
                    Skipped = stage.Skipped
                };
            }

            long bytes = 0;
            try { bytes = new FileInfo(zipPath).Length; } catch { /* size is cosmetic */ }

            return new TriageResult
            {
                Ok = true,
                ZipPath = zipPath,
                Included = stage.Included,
                Skipped = stage.Skipped,
                Bytes = bytes
            };
        }
        catch (Exception ex)
        {
            return new TriageResult { Error = $"{ex.GetType().Name}: {ex.Message}" };
        }
        finally
        {
            // Staging holds command lines and module lists from a live incident; leaving
            // it behind in %TEMP% would both leak that and slowly fill the disk.
            try { if (Directory.Exists(stagingDir)) Directory.Delete(stagingDir, recursive: true); }
            catch { /* best effort; the zip is already written */ }
        }
    }

    private static void Populate(TriageStage stage, int pid, DateTime nowUtc, ProfileSnapshot? snapshot)
    {
        stage.AddText("process.txt", () => RenderProcessSummary(pid, nowUtc));
        stage.AddText("process-commandline.txt", () => RenderCommandLine(pid));
        stage.AddText("modules.txt", () => RenderModules(pid));

        if (snapshot is null)
            stage.Skip("profile-snapshot.json", "no detection profile was supplied to the collector");
        else
            stage.AddText("profile-snapshot.json", () => RenderSnapshot(snapshot));

        stage.AddText("network-tcp.txt", RenderTcpTable);
        stage.AddText("image-sha256.txt", () => RenderImageHash(pid, snapshot));
        stage.AddText("environment.txt", () => RenderEnvironment(nowUtc));
        stage.AddText("processes.csv", RenderProcessList);
    }

    // ------------------------------------------------------------- zip naming

    /// <summary>
    /// <c>triage-PID-yyyyMMddTHHmmssZ.zip</c>. Second resolution keeps the name readable;
    /// <see cref="UniqueZipPath"/> handles the collision that resolution allows.
    /// </summary>
    internal static string ZipFileName(int pid, DateTime nowUtc)
        => string.Format(CultureInfo.InvariantCulture, "triage-{0}-{1}.zip",
            pid, nowUtc.ToUniversalTime().ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture));

    /// <summary>
    /// The zip path, suffixed <c>-2</c>, <c>-3</c>... if a package for this pid and
    /// second already exists. Two collections a second apart must never silently
    /// overwrite each other's evidence.
    /// </summary>
    internal static string UniqueZipPath(string outputDir, int pid, DateTime nowUtc)
    {
        string baseName = ZipFileName(pid, nowUtc);
        string candidate = Path.Combine(outputDir, baseName);
        if (!File.Exists(candidate)) return candidate;

        string stem = baseName[..^4];   // strip ".zip"
        for (int i = 2; i <= MaxNameAttempts; i++)
        {
            candidate = Path.Combine(outputDir, $"{stem}-{i}.zip");
            if (!File.Exists(candidate)) return candidate;
        }

        // Beyond the attempt budget, fall back to a name that cannot collide.
        return Path.Combine(outputDir, $"{stem}-{Guid.NewGuid():n}.zip");
    }

    // ------------------------------------------------------------- collectors

    internal static string RenderProcessSummary(int pid, DateTime nowUtc)
    {
        var sb = new StringBuilder();
        sb.Append("collected_utc: ").AppendLine(nowUtc.ToString("O", CultureInfo.InvariantCulture));
        sb.Append("pid: ").Append(pid).AppendLine();

        using var p = Process.GetProcessById(pid);
        sb.Append("name: ").AppendLine(p.ProcessName);
        sb.Append("session_id: ").Append(p.SessionId).AppendLine();

        // Each of these can throw independently on a protected or exiting process, so
        // they are probed one at a time instead of in one try block that would lose the
        // fields after the first failure.
        Field(sb, "start_time_utc", () => p.StartTime.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Field(sb, "image_path", () => p.MainModule?.FileName ?? "(none)");
        Field(sb, "has_exited", () => p.HasExited.ToString());
        Field(sb, "threads", () => p.Threads.Count.ToString(CultureInfo.InvariantCulture));
        Field(sb, "handles", () => p.HandleCount.ToString(CultureInfo.InvariantCulture));
        Field(sb, "working_set_bytes", () => p.WorkingSet64.ToString(CultureInfo.InvariantCulture));
        Field(sb, "private_bytes", () => p.PrivateMemorySize64.ToString(CultureInfo.InvariantCulture));
        Field(sb, "total_processor_time", () => p.TotalProcessorTime.ToString());
        Field(sb, "priority_class", () => p.PriorityClass.ToString());

        return sb.ToString();
    }

    /// <summary>
    /// The command line, which .NET does not expose for another process. WMI is the only
    /// dependency-free route; it fails for protected processes and can be denied
    /// outright, in which case the artifact is skipped rather than the run aborted.
    /// </summary>
    internal static string RenderCommandLine(int pid)
    {
        using var searcher = new ManagementObjectSearcher(
            @"\\.\root\cimv2",
            "SELECT CommandLine, ExecutablePath, ParentProcessId, CreationDate FROM Win32_Process WHERE ProcessId = " +
            pid.ToString(CultureInfo.InvariantCulture),
            WmiOptions());

        using var results = searcher.Get();
        var sb = new StringBuilder();
        foreach (ManagementBaseObject mo in results)
        {
            using (mo)
            {
                sb.Append("executable_path: ").AppendLine(mo["ExecutablePath"] as string ?? "(unavailable)");
                sb.Append("parent_pid: ").AppendLine(Convert.ToString(mo["ParentProcessId"], CultureInfo.InvariantCulture) ?? "");
                sb.Append("creation_date: ").AppendLine(mo["CreationDate"] as string ?? "(unavailable)");
                sb.Append("command_line: ").AppendLine(mo["CommandLine"] as string ?? "(unavailable)");
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Loaded modules with their on-disk path and file version. Injected or reflectively
    /// loaded code frequently has no module entry at all, so an empty-looking list is
    /// evidence of nothing; and a 32-bit agent cannot enumerate a 64-bit target's
    /// modules (and vice versa), which surfaces here as an access failure.
    /// </summary>
    internal static string RenderModules(int pid)
    {
        using var p = Process.GetProcessById(pid);
        var sb = new StringBuilder();
        sb.AppendLine("module|path|file_version|product_version|size_bytes");

        foreach (ProcessModule m in p.Modules)
        {
            using (m)
            {
                string file = "";
                string product = "";
                try
                {
                    var vi = m.FileVersionInfo;
                    file = vi.FileVersion ?? "";
                    product = vi.ProductVersion ?? "";
                }
                catch { /* version resource missing or unreadable */ }

                sb.Append(m.ModuleName).Append('|')
                  .Append(m.FileName).Append('|')
                  .Append(file).Append('|')
                  .Append(product).Append('|')
                  .Append(m.ModuleMemorySize.ToString(CultureInfo.InvariantCulture))
                  .AppendLine();
            }
        }
        return sb.ToString();
    }

    internal static string RenderSnapshot(ProfileSnapshot? snapshot)
        => snapshot is null ? "" : JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });

    /// <summary>
    /// The full TCP table, both connections and listeners.
    ///
    /// System.Net.NetworkInformation exposes no owning PID — that needs
    /// GetExtendedTcpTable via P/Invoke — so the table CANNOT be filtered to the subject
    /// process here. The whole table is captured instead, which is arguably better
    /// evidence anyway: the analyst can correlate it against the process list in the
    /// same package, and it also preserves the C2 sockets of any sibling process the
    /// intrusion spawned.
    /// </summary>
    internal static string RenderTcpTable()
    {
        var props = IPGlobalProperties.GetIPGlobalProperties();
        var sb = new StringBuilder();

        sb.AppendLine("# active TCP connections (host-wide; no owning-pid column is available from this API)");
        sb.AppendLine("local|remote|state");
        foreach (var c in props.GetActiveTcpConnections())
            sb.Append(c.LocalEndPoint).Append('|').Append(c.RemoteEndPoint).Append('|').Append(c.State).AppendLine();

        sb.AppendLine();
        sb.AppendLine("# TCP listeners (host-wide)");
        foreach (var l in props.GetActiveTcpListeners())
            sb.AppendLine(l.ToString());

        return sb.ToString();
    }

    internal static string RenderImageHash(int pid, ProfileSnapshot? snapshot)
    {
        string path = "";
        try
        {
            using var p = Process.GetProcessById(pid);
            path = p.MainModule?.FileName ?? "";
        }
        catch { /* fall back to the snapshot below */ }

        if (string.IsNullOrEmpty(path) && snapshot is not null) path = snapshot.ImagePath;
        if (string.IsNullOrEmpty(path)) return "";

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        string hex = Convert.ToHexString(SHA256.HashData(fs));
        return $"path: {path}{Environment.NewLine}sha256: {hex}{Environment.NewLine}";
    }

    internal static string RenderEnvironment(DateTime nowUtc)
    {
        var sb = new StringBuilder();
        sb.Append("collected_utc: ").AppendLine(nowUtc.ToString("O", CultureInfo.InvariantCulture));
        sb.Append("machine: ").AppendLine(Environment.MachineName);
        sb.Append("os: ").AppendLine(Environment.OSVersion.VersionString);
        sb.Append("os_64bit: ").AppendLine(Environment.Is64BitOperatingSystem.ToString());
        sb.Append("process_64bit: ").AppendLine(Environment.Is64BitProcess.ToString());
        sb.Append("clr: ").AppendLine(Environment.Version.ToString());
        sb.Append("processor_count: ").Append(Environment.ProcessorCount).AppendLine();
        sb.Append("user: ").AppendLine(Environment.UserDomainName + "\\" + Environment.UserName);
        sb.Append("agent_pid: ").Append(Environment.ProcessId).AppendLine();
        sb.Append("system_uptime: ").AppendLine(TimeSpan.FromMilliseconds(Environment.TickCount64).ToString());

        Field(sb, "agent_elevated", IsElevated);
        Field(sb, "system_directory", () => Environment.SystemDirectory);
        Field(sb, "domain_joined_user_domain", () => Environment.UserDomainName);
        return sb.ToString();
    }

    private static string IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator).ToString();
    }

    /// <summary>
    /// Every running process with its parent, so the analyst can rebuild the tree the
    /// subject sat in. WMI is preferred because .NET's Process type has no parent-pid
    /// property; if WMI is unavailable the collector degrades to a parentless list
    /// rather than dropping the artifact entirely, and says so in the output.
    /// </summary>
    internal static string RenderProcessList()
    {
        var sb = new StringBuilder();
        sb.AppendLine("pid,parent_pid,name");

        try
        {
            using var searcher = new ManagementObjectSearcher(
                @"\\.\root\cimv2",
                "SELECT ProcessId, ParentProcessId, Name FROM Win32_Process",
                WmiOptions());
            using var results = searcher.Get();

            foreach (ManagementBaseObject mo in results)
            {
                using (mo)
                {
                    sb.Append(Convert.ToString(mo["ProcessId"], CultureInfo.InvariantCulture)).Append(',')
                      .Append(Convert.ToString(mo["ParentProcessId"], CultureInfo.InvariantCulture)).Append(',')
                      .AppendLine(Csv(mo["Name"] as string ?? ""));
                }
            }
            return sb.ToString();
        }
        catch (Exception ex)
        {
            sb.Clear();
            sb.Append("# WMI enumeration failed (").Append(ex.GetType().Name)
              .AppendLine("); parent pids are unavailable in this fallback listing");
            sb.AppendLine("pid,parent_pid,name");

            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    string name;
                    try { name = p.ProcessName; } catch { name = "(unavailable)"; }
                    sb.Append(p.Id.ToString(CultureInfo.InvariantCulture)).Append(",,").AppendLine(Csv(name));
                }
            }
            return sb.ToString();
        }
    }

    private static string RenderManifest(int pid, DateTime nowUtc, TriageStage stage)
    {
        var manifest = new
        {
            tool = "ProcessShield TriageCollector",
            format = 1,
            pid,
            collectedUtc = nowUtc.ToString("O", CultureInfo.InvariantCulture),
            machine = Environment.MachineName,
            included = stage.Included,
            skipped = stage.Skipped
        };
        return JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
    }

    // ----------------------------------------------------------------- helpers

    /// <summary>
    /// ReturnImmediately + a bounded timeout matter here: a wedged WMI provider is a
    /// real failure mode on a compromised host, and triage must not hang the response
    /// worker waiting for it.
    /// </summary>
    // Fully qualified: System.IO also has an EnumerationOptions, and both namespaces are
    // in scope in this file.
    private static System.Management.EnumerationOptions WmiOptions() => new()
    {
        ReturnImmediately = true,
        Rewindable = false,
        Timeout = TimeSpan.FromSeconds(20)
    };

    private static void Field(StringBuilder sb, string name, Func<string> value)
    {
        sb.Append(name).Append(": ");
        try { sb.AppendLine(value()); }
        catch (Exception ex) { sb.Append("(unavailable: ").Append(ex.GetType().Name).AppendLine(")"); }
    }

    private static string Csv(string value)
        => value.Contains(',') || value.Contains('"')
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;

    /// <summary>
    /// Accumulates artifacts into a staging directory, converting any producer failure
    /// into a Skipped entry. Kept internal (rather than inlined into Collect) so the
    /// included/skipped accounting is testable without collecting anything real.
    /// </summary>
    internal sealed class TriageStage
    {
        private readonly string _dir;
        private readonly List<string> _included = new();
        private readonly List<string> _skipped = new();

        public TriageStage(string directory) => _dir = directory;

        public IReadOnlyList<string> Included => _included;
        public IReadOnlyList<string> Skipped => _skipped;

        /// <summary>Records an artifact that was never attempted, with the reason.</summary>
        public void Skip(string fileName, string reason) => _skipped.Add($"{fileName}: {reason}");

        /// <summary>
        /// Runs <paramref name="produce"/> and writes the result. Empty output counts as
        /// skipped, not included: a zero-byte artifact in an evidence package reads as
        /// "there was nothing to see", which is a different and misleading claim from
        /// "this could not be collected".
        /// </summary>
        public void AddText(string fileName, Func<string> produce)
        {
            string content;
            try
            {
                content = produce() ?? "";
            }
            catch (UnauthorizedAccessException ex)
            {
                _skipped.Add($"{fileName}: access denied ({ex.Message})");
                return;
            }
            catch (Exception ex)
            {
                _skipped.Add($"{fileName}: {ex.GetType().Name}: {ex.Message}");
                return;
            }

            if (content.Length == 0)
            {
                _skipped.Add($"{fileName}: no data available");
                return;
            }

            try
            {
                File.WriteAllText(Path.Combine(_dir, fileName), content, Encoding.UTF8);
                _included.Add(fileName);
            }
            catch (Exception ex)
            {
                _skipped.Add($"{fileName}: write failed: {ex.GetType().Name}: {ex.Message}");
            }
        }
    }
}
