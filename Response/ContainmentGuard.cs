using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using BruceEDR.Detection;
using BruceEDR.Driver;
using static BruceEDR.Native.NativeMethods;

namespace BruceEDR.Response;

/// <summary>
/// The live process behind a pid. <c>ServiceAccount</c> is true when its token belongs to an account
/// no user can sign in as or start a program under (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, a service
/// SID, Window Manager, Font Driver Host), null when the token could not be read.
/// <c>StartedByServices</c> is true when its parent is the real, protected services.exe.
/// </summary>
internal sealed record LiveProcess(string Name, string? ImagePath, bool Protected = false,
    bool? ServiceAccount = null, bool StartedByServices = false);

/// <summary>
/// The last check before BruceEDR suspends, firewalls or kills a process. Windows keeps running only
/// while a handful of its own processes do: in enforce mode the agent froze two lab VMs within
/// minutes by suspending csrss and svchost on behavioural verdicts it could not put a name to (and,
/// on a later run, the Defender engine, after which nothing could start). Those verdicts are still
/// reported; only the response is refused.
///
/// Refused: System and Idle, the agent itself, and any process Windows runs protected (PPL), which
/// only Windows and signed security software can be. A protected Windows name, or an image on the
/// safe-process list (<see cref="SafeProcesses"/>), is refused only for the real file (no account
/// other than SYSTEM, Administrators or TrustedInstaller could have planted it) AND an instance no
/// standard user can have started: any user can launch System32\svchost.exe and hollow it out. So
/// svchost counts only when the protected services.exe started it, and the rest only under a service
/// account. The user's own shell programs (explorer, sihost, ctfmon and the like) run as the user,
/// where the account tells a real one from a copy no better than the name does; they are refused by
/// name and path, which leaves a hollowed copy of one uncontained.
/// </summary>
public static class ContainmentGuard
{
    /// <summary>Protected Windows programs that legitimately run as the signed-in user.</summary>
    private static readonly HashSet<string> ShellPrograms = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    };

    /// <summary>Why <paramref name="pid"/> must not be contained, or null when it may be.</summary>
    public static string? Refusal(int pid) => Refusal(pid, SafeProcesses.Empty);

    /// <summary>As <see cref="Refusal(int)"/>, with the operator's safe-process list.</summary>
    public static string? Refusal(int pid, SafeProcesses safe)
    {
        int self = Environment.ProcessId;
        try
        {
            return Refusal(pid, self, pid <= 4 || pid == self ? null : Describe(pid), KernelPolicy.WriteRisk, safe);
        }
        catch (Exception ex)
        {
            return $"pid {pid} could not be identified ({ex.GetType().Name})";
        }
    }

    internal static string? Refusal(int pid, int selfPid, LiveProcess? live, Func<string, string?> writeRisk,
        SafeProcesses? safe = null)
    {
        if (pid <= 4) return $"pid {pid} is the Windows System or Idle process";
        if (pid == selfPid) return "it is the BruceEDR agent itself";
        // Gone already: the action itself reports that the pid no longer exists.
        if (live is null) return null;
        if (live.Protected) return $"{live.Name} runs as a protected process, as only Windows and signed security software can";

        bool listed = safe?.Contains(live.ImagePath) == true;
        bool named = Watchlist.IsProtected(live.Name);
        if (!listed && !named) return null;
        if (string.IsNullOrEmpty(live.ImagePath))
            return named ? $"{live.Name} is a protected Windows process and its image could not be read to rule out a look-alike" : null;
        // A file a non-administrator could have put there is a look-alike, whatever its name.
        if (writeRisk(live.ImagePath) is not null) return null;

        string refusal = $"{live.Name} ({live.ImagePath}) " + (listed
            ? "is on the safe-process list"
            : "is a protected Windows process; stopping it can hang or crash Windows");
        string file = Path.GetFileName(live.ImagePath);
        if (file.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) return live.StartedByServices ? refusal : null;
        if (named && ShellPrograms.Contains(file)) return refusal;
        return live.ServiceAccount == true ? refusal : null;
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
            return new LiveProcess(name, ImagePath(handle), IsProtected(handle), IsServiceAccount(handle),
                IsStartedByServices(handle));
        }
        finally { CloseHandle(handle); }
    }

    private static string? ImagePath(IntPtr handle)
    {
        var buffer = new char[32768];
        uint size = (uint)buffer.Length;
        return QueryFullProcessImageNameW(handle, 0, buffer, ref size) && size > 0 ? new string(buffer, 0, (int)size) : null;
    }

    private static bool IsProtected(IntPtr handle)
        => GetProcessInformation(handle, ProcessProtectionLevelInfo, out uint level, sizeof(uint)) && level != PROTECTION_LEVEL_NONE;

    private static bool? IsServiceAccount(IntPtr handle)
    {
        if (!OpenProcessToken(handle, TOKEN_QUERY, out IntPtr token)) return null;
        IntPtr buffer = IntPtr.Zero;
        try
        {
            GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out int length);
            if (length <= 0) return null;
            buffer = Marshal.AllocHGlobal(length);
            if (!GetTokenInformation(token, TokenUser, buffer, length, out _)) return null;
            return IsServiceSid(new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value);
        }
        finally
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            CloseHandle(token);
        }
    }

    internal static bool IsServiceSid(string sid)
        => sid is "S-1-5-18" or "S-1-5-19" or "S-1-5-20"
           || sid.StartsWith("S-1-5-80-", StringComparison.Ordinal)    // NT SERVICE\<service>
           || sid.StartsWith("S-1-5-90-", StringComparison.Ordinal)    // Window Manager\DWM-n
           || sid.StartsWith("S-1-5-96-", StringComparison.Ordinal);   // Font Driver Host\UMFD-n

    /// <summary>
    /// True when the parent is the real services.exe: its image in System32 and protected, which no
    /// copy a user starts can be. services.exe never exits, so its pid cannot have been reused.
    /// </summary>
    private static bool IsStartedByServices(IntPtr handle)
    {
        if (NtQueryInformationProcess(handle, 0, out PROCESS_BASIC_INFORMATION info,
                Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) != 0) return false;
        long parent = info.InheritedFromUniqueProcessId.ToInt64();
        if (parent <= 4 || parent > int.MaxValue) return false;
        IntPtr parentHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, (int)parent);
        if (parentHandle == IntPtr.Zero) return false;
        try
        {
            return string.Equals(ImagePath(parentHandle), Path.Combine(Environment.SystemDirectory, "services.exe"),
                       StringComparison.OrdinalIgnoreCase)
                   && IsProtected(parentHandle);
        }
        finally { CloseHandle(parentHandle); }
    }
}
