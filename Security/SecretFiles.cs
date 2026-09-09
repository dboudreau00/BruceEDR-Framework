using System.Security.AccessControl;
using System.Security.Principal;

namespace BruceEDR.Security;

/// <summary>
/// Locks a file or directory down to SYSTEM + Administrators, inheritance off.
///
/// The agent creates several files whose only protection used to be whatever DACL the
/// parent directory handed down: the vault key, the audit-chain key, the control-plane
/// bearer token, triage packages, and plain-moved quarantine samples. Under Program Files
/// that inheritance is typically Users:RX, which makes every one of those readable by any
/// local account. Telling the operator to ACL the directory is not a control; the creator
/// setting the DACL at creation time is.
///
/// Every method is best-effort and never throws: an ACL that could not be applied is
/// reported to the caller's log, not allowed to take the agent down. Same-privilege
/// attackers are out of scope (an administrator can undo any of this), which the vault and
/// audit documentation already say.
/// </summary>
public static class SecretFiles
{
    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// The identity doing the creating. SYSTEM in production, an elevated administrator
    /// in a lab -- and a plain user under CI or a non-elevated test run, whose
    /// Administrators membership is deny-only in the token. Without this grant that user
    /// could create the secret and then never read it back.
    /// </summary>
    private static SecurityIdentifier? Creator
    {
        get
        {
            try { return WindowsIdentity.GetCurrent().User; }
            catch { return null; }
        }
    }

    private static void GrantCore(FileSystemSecurity sec, bool inherit)
    {
        var flags = inherit ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
        sec.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, flags, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, flags, PropagationFlags.None, AccessControlType.Allow));
        var me = Creator;
        if (me is not null && !me.Equals(LocalSystem))
            sec.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, flags, PropagationFlags.None, AccessControlType.Allow));
    }

    /// <summary>Restricts an existing file to SYSTEM + Administrators. Returns null on success, else the reason.</summary>
    public static string? Protect(string path)
    {
        if (!OperatingSystem.IsWindows()) return "not Windows";
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return "file does not exist";

            var sec = new FileSecurity();
            // Disable inheritance and DROP the inherited rules rather than copying them.
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            GrantCore(sec, inherit: false);
            info.SetAccessControl(sec);
            return null;
        }
        catch (Exception ex) { return ex.GetType().Name + ": " + ex.Message; }
    }

    /// <summary>
    /// Restricts a directory, and everything created under it, to SYSTEM + Administrators.
    /// Returns null on success, else the reason.
    /// </summary>
    public static string? ProtectDirectory(string path)
    {
        if (!OperatingSystem.IsWindows()) return "not Windows";
        try
        {
            var info = new DirectoryInfo(path);
            if (!info.Exists) return "directory does not exist";

            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            GrantCore(sec, inherit: true);
            info.SetAccessControl(sec);
            return null;
        }
        catch (Exception ex) { return ex.GetType().Name + ": " + ex.Message; }
    }

    /// <summary>
    /// Creates a file with the restrictive DACL applied atomically at creation, so there is
    /// no window in which it exists with inherited permissions. Overwrites are refused.
    /// </summary>
    public static void CreateProtected(string path, byte[] content)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.WriteAllBytes(path, content);
            return;
        }

        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        GrantCore(sec, inherit: false);

        var info = new FileInfo(path);
        using var fs = info.Create(FileMode.CreateNew, FileSystemRights.Write | FileSystemRights.ReadData,
                                   FileShare.None, 4096, FileOptions.None, sec);
        fs.Write(content, 0, content.Length);
    }

    /// <summary>True when the file's DACL is protected (inheritance disabled). Used by tests.</summary>
    public static bool IsProtected(string path)
    {
        if (!OperatingSystem.IsWindows()) return false;
        try { return new FileInfo(path).GetAccessControl().AreAccessRulesProtected; }
        catch { return false; }
    }
}
