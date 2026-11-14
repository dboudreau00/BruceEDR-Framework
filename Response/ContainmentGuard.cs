using System.Diagnostics;
using BruceEDR.Detection;
using BruceEDR.Driver;
using static BruceEDR.Native.NativeMethods;

namespace BruceEDR.Response;

/// <summary>The live process behind a pid: its name, its image path when it can be read, and whether it runs protected (PPL).</summary>
internal sealed record LiveProcess(string Name, string? ImagePath, bool Protected = false);

/// <summary>
/// The last check before BruceEDR suspends, firewalls or kills a process. Windows keeps
/// running only while a handful of its own processes do: in enforce mode the agent froze two
/// lab VMs within minutes by suspending csrss and svchost on behavioural verdicts it could not
/// put a name to (and, on a later run, the Defender engine, after which nothing could start).
/// Those verdicts are still reported; only the response is refused. A process Windows runs
/// protected (PPL) is refused whatever its name. A protected name counts only when no account
/// other than SYSTEM, Administrators or TrustedInstaller could have planted the image, so a
/// svchost.exe started from a user's folder is still contained.
/// </summary>
public static class ContainmentGuard
{
    /// <summary>Why <paramref name="pid"/> must not be contained, or null when it may be.</summary>
    public static string? Refusal(int pid)
    {
        int self = Environment.ProcessId;
        try
        {
            return Refusal(pid, self, pid <= 4 || pid == self ? null : Describe(pid), KernelPolicy.WriteRisk);
        }
        catch (Exception ex)
        {
            return $"pid {pid} could not be identified ({ex.GetType().Name})";
        }
    }

    internal static string? Refusal(int pid, int selfPid, LiveProcess? live, Func<string, string?> writeRisk)
    {
        if (pid <= 4) return $"pid {pid} is the Windows System or Idle process";
        if (pid == selfPid) return "it is the BruceEDR agent itself";
        // Gone already: the action itself reports that the pid no longer exists.
        if (live is null) return null;
        // Only Windows and signed anti-malware services start protected, whatever their names:
        // this covers a third-party antivirus the name list cannot know about.
        if (live.Protected) return $"{live.Name} runs as a protected process, as only Windows and signed security software can";
        if (!Watchlist.IsProtected(live.Name)) return null;
        if (string.IsNullOrEmpty(live.ImagePath))
            return $"{live.Name} is a protected Windows process and its image could not be read to rule out a look-alike";
        // A file a non-administrator could have put there is a look-alike, whatever its name.
        return writeRisk(live.ImagePath) is null
            ? $"{live.Name} ({live.ImagePath}) is a protected Windows process; stopping it can hang or crash Windows"
            : null;
    }

    internal static LiveProcess? Describe(int pid)
    {
        string name;
        try
        {
            using var process = Process.GetProcessById(pid);
            name = process.ProcessName;
        }
        catch (ArgumentException) { return null; }
        catch (InvalidOperationException) { return null; }

        // PROCESS_QUERY_LIMITED_INFORMATION is still granted by protected processes (csrss, smss,
        // services, a PPL lsass, the antivirus). MainModule needs VM_READ and fails on exactly the
        // processes this guard exists for.
        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return new LiveProcess(name, null);
        try
        {
            var buffer = new char[32768];
            uint size = (uint)buffer.Length;
            string? image = QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0
                ? new string(buffer, 0, (int)size)
                : null;
            bool isProtected = GetProcessInformation(handle, ProcessProtectionLevelInfo, out uint level, sizeof(uint))
                               && level != PROTECTION_LEVEL_NONE;
            return new LiveProcess(name, image, isProtected);
        }
        finally { CloseHandle(handle); }
    }
}
