using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcessShield.Core;
using ProcessShield.Security;
using static ProcessShield.Native.NativeMethods;

namespace ProcessShield.Response;

/// <summary>
/// Executes containment. Raw process actions are static and return a typed
/// ActionResult with a reason on failure. Contain() runs the slower steps
/// (firewall, quarantine, optional kill) on the response worker and reads only an
/// immutable snapshot. Trust decisions are delegated to the AuthenticodeVerifier.
/// </summary>
public sealed class ResponseManager
{
    private const int NetshTimeoutMs = 5000;

    private readonly Logger _log;
    private readonly AuthenticodeVerifier _verifier;
    private readonly string _quarantineDir;
    private readonly QuarantineVault? _vault;

    public ResponseManager(Logger log, AuthenticodeVerifier verifier, QuarantineVault? vault = null)
    {
        _log = log;
        _verifier = verifier;
        _vault = vault;
        _quarantineDir = Path.Combine(AppContext.BaseDirectory, "quarantine");
        try { Directory.CreateDirectory(_quarantineDir); }
        catch (Exception ex) { _log.Error("create quarantine dir", ex); }
    }

    public bool IsTrusted(int pid) => _verifier.IsTrusted(pid);

    /// <summary>Slow containment steps. The initial suspend already ran on the owner thread.</summary>
    public void Contain(ProfileSnapshot snap, bool alreadySuspended, bool autoKill,
        bool firewall = true, bool quarantineFiles = true)
    {
        // If the target was NOT frozen by the initial suspend, its PID may already have
        // been recycled by an unrelated process by the time this runs on the response
        // worker. Never resolve or kill by live PID in that case -- act only on the
        // trusted snapshot image path -- or we could firewall/kill an innocent process.
        if (firewall)
        {
            string? imagePath = alreadySuspended
                ? ResolveImagePath(snap.Pid) ?? NullIfMissing(snap.ImagePath)
                : NullIfMissing(snap.ImagePath);
            if (imagePath is not null) AddOutboundFirewallBlock(imagePath, snap.Pid);
            else _log.Action($"pid {snap.Pid}: no resolvable image path; skipped firewall block");
        }

        if (quarantineFiles) QuarantineArchives(snap);

        if (autoKill && alreadySuspended)
        {
            var k = KillProcess(snap.Pid);
            _log.Action(k.Ok ? $"pid {snap.Pid} terminated (auto-kill)"
                             : $"pid {snap.Pid} auto-kill failed: {k.Message}");
        }
        else if (autoKill)
        {
            _log.Action($"pid {snap.Pid} not frozen (suspend failed); auto-kill skipped to avoid acting on a reused PID");
        }
        else
        {
            _log.Action($"pid {snap.Pid} contained; awaiting analyst (resume/kill in console)");
        }
    }

    public static ActionResult SuspendProcess(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return ActionResult.Fail(Win32("OpenProcess"));
        try
        {
            int status = NtSuspendProcess(h);
            return status == 0 ? ActionResult.Success($"pid {pid} suspended")
                               : ActionResult.Fail($"NtSuspendProcess status 0x{status:X8}");
        }
        finally { CloseHandle(h); }
    }

    public static ActionResult ResumeProcess(int pid)
    {
        IntPtr h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return ActionResult.Fail(Win32("OpenProcess"));
        try
        {
            int status = NtResumeProcess(h);
            return status == 0 ? ActionResult.Success($"pid {pid} resumed")
                               : ActionResult.Fail($"NtResumeProcess status 0x{status:X8}");
        }
        finally { CloseHandle(h); }
    }

    public static ActionResult KillProcess(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            p.Kill(entireProcessTree: true);
            p.WaitForExit(3000);
            return ActionResult.Success($"pid {pid} terminated");
        }
        catch (ArgumentException) { return ActionResult.Fail($"no process with pid {pid}"); }
        catch (Exception ex) { return ActionResult.Fail(ex.Message); }
    }

    /// <summary>
    /// The rule name used for the per-binary outbound block. Add and remove MUST derive
    /// the name the same way -- netsh cannot delete by wildcard, so a name that differs
    /// by one character leaves the binary blocked forever.
    /// </summary>
    public static string OutboundBlockRuleName(int pid, string imagePath)
        => FirewallRuleName.Sanitize($"ProcessShield Block {Path.GetFileName(imagePath)} {pid}");

    /// <summary>
    /// Removes the outbound block rule this class installs for a contained binary, so
    /// releasing a false positive actually restores its network access instead of only
    /// un-suspending it. Safe to call when no rule exists.
    ///
    /// Limitation: the rule name embeds the PID, so this only removes the rule added for
    /// THAT containment. A block left behind by an earlier agent instance (different PID)
    /// has to be removed by name from the firewall UI or netsh.
    /// </summary>
    public static ActionResult RemoveOutboundFirewallBlock(int pid, string imagePath)
    {
        string ruleName = OutboundBlockRuleName(pid, imagePath);
        var args = new[] { "advfirewall", "firewall", "delete", "rule", $"name={ruleName}" };

        if (RunNetsh(args, out string detail, out int exitCode))
            return ActionResult.Success($"firewall block '{ruleName}' removed");

        // netsh exits non-zero for "No rules match the specified criteria", which is the
        // normal outcome when the binary was never blocked (or was already released).
        // Only a netsh that could not be run at all (exit code unknown) is a real failure.
        return exitCode > 0
            ? ActionResult.Success($"no firewall block named '{ruleName}' to remove")
            : ActionResult.Fail($"firewall block '{ruleName}' not removed: {detail}");
    }

    private void AddOutboundFirewallBlock(string imagePath, int pid)
    {
        string ruleName = OutboundBlockRuleName(pid, imagePath);

        // Delete-then-add. netsh 'add rule' will happily create a SECOND rule with the
        // same name, so containing the same binary repeatedly would otherwise accumulate
        // duplicates that an analyst has to unpick by hand.
        var removed = RemoveOutboundFirewallBlock(pid, imagePath);
        if (!removed.Ok) _log.Action($"firewall: pre-add cleanup failed: {removed.Message}");

        var args = new[]
        {
            "advfirewall", "firewall", "add", "rule",
            $"name={ruleName}",
            "dir=out", "action=block", $"program={imagePath}", "enable=yes"
        };

        _log.Action(RunNetsh(args, out string detail, out _)
            ? "outbound firewall block added"
            : "firewall: " + detail);
    }

    /// <summary>
    /// Runs one netsh command. Arguments go through ArgumentList so each element is
    /// quoted by the runtime and a rule name containing spaces stays one argument;
    /// concatenating a command string here would be an injection bug.
    /// <paramref name="exitCode"/> is -1 when netsh could not be started, timed out, or
    /// threw, which is how callers tell "the command ran and said no" from "it never ran".
    /// </summary>
    private static bool RunNetsh(IReadOnlyList<string> args, out string detail, out int exitCode)
    {
        detail = "";
        exitCode = -1;
        try
        {
            var psi = new ProcessStartInfo("netsh")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi);
            if (proc is null) { detail = "failed to launch netsh"; return false; }

            // Drain both pipes concurrently with the wait; a full pipe buffer would
            // otherwise deadlock the wait against the child.
            _ = proc.StandardOutput.ReadToEndAsync();
            _ = proc.StandardError.ReadToEndAsync();

            if (!proc.WaitForExit(NetshTimeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                detail = $"netsh timed out after {NetshTimeoutMs} ms";
                return false;
            }

            exitCode = proc.ExitCode;
            if (exitCode == 0) return true;
            detail = $"netsh exit code {exitCode}";
            return false;
        }
        catch (Exception ex)
        {
            detail = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private void QuarantineArchives(ProfileSnapshot snap)
    {
        foreach (var archive in snap.StagedArchives)
        {
            try
            {
                if (!File.Exists(archive)) continue;

                // Preferred path: move the bytes into the encrypted vault, where the payload
                // is no longer a runnable file and cannot be re-detected by another scanner
                // as a live threat. Falls back to the historical plain move only if no vault
                // was configured.
                if (_vault is not null)
                {
                    var entry = _vault.Store(archive, $"staged by pid {snap.Pid}", snap.Pid, snap.ProcessName);
                    if (entry is not null)
                    {
                        _log.Action($"vaulted archive {Path.GetFileName(archive)} as {entry.Id}");
                        continue;
                    }
                    _log.Action($"vault store failed for {Path.GetFileName(archive)}; falling back to a plain move");
                }

                string dest = Path.Combine(_quarantineDir,
                    $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Path.GetFileName(archive)}");
                File.Move(archive, dest, overwrite: false);
                _log.Action($"quarantined archive: {Path.GetFileName(archive)}");
            }
            catch (Exception ex) { _log.Error($"quarantine {Path.GetFileName(archive)}", ex); }
        }
    }

    private static string? ResolveImagePath(int pid)
    {
        try { using var p = Process.GetProcessById(pid); return p.MainModule?.FileName; }
        catch { return null; }
    }

    private static string? NullIfMissing(string path)
        => !string.IsNullOrEmpty(path) && File.Exists(path) ? path : null;

    private static string Win32(string api)
        => $"{api} failed (Win32 error {Marshal.GetLastWin32Error()})";
}
