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
    /// The identity doing the creating, when SYSTEM and Administrators do not already cover
    /// it: a plain user under CI or a non-elevated test run, whose Administrators membership
    /// is deny-only in the token. Without this grant that user could create the secret and
    /// then never read it back.
    ///
    /// An elevated process gets no creator grant. Its user SID is also the SID of every
    /// non-elevated process the same person runs, so granting it FullControl handed the
    /// folder (and, through a junction, whatever it pointed at) to medium-integrity code:
    /// the protection protected nothing from the malware it was meant to keep out.
    /// </summary>
    private static SecurityIdentifier? Creator
    {
        get
        {
            if (SafePaths.ProcessIsAdministrative) return null;
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
    /// Returns null on success, else the reason. The folder is created if missing; one that is,
    /// or sits behind, a junction or symbolic link is refused rather than followed, and the
    /// DACL goes on through a handle whose final path was checked (see
    /// <see cref="SafePaths.EnsurePrivateDirectory"/>). Setting it by path used to follow a
    /// junction planted in the folder's place and rewrite the DACL of whatever it pointed at.
    /// </summary>
    public static string? ProtectDirectory(string path)
        => SafePaths.EnsurePrivateDirectory(path, requireAdministrativeOwner: false);

    /// <summary>The DACL <see cref="ProtectDirectory"/> applies: SYSTEM, Administrators and the creator, inherited by children, nothing from the parent.</summary>
    internal static DirectorySecurity PrivateDirectorySecurity()
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        GrantCore(sec, inherit: true);
        return sec;
    }

    /// <summary>
    /// Creates a file with the restrictive DACL applied atomically at creation, so there is
    /// no window in which it exists with inherited permissions. Overwrites are refused.
    /// </summary>
    public static void CreateProtected(string path, byte[] content)
    {
        if (!OperatingSystem.IsWindows())
        {
            if (SafePaths.FindLink(path) is { } link) throw new IOException($"refusing to create {path}: {link} is a link");
            using var created = new FileStream(path, FileMode.CreateNew, FileAccess.Write);
            created.Write(content, 0, content.Length);
            return;
        }

        var sec = new FileSecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        GrantCore(sec, inherit: false);

        var info = new FileInfo(path);
        using var fs = info.Create(FileMode.CreateNew,
                                   FileSystemRights.Write | FileSystemRights.ReadData | FileSystemRights.Delete,
                                   FileShare.None, 4096, FileOptions.None, sec);
        // CreateNew never follows a link in the last component, but a folder above it can be a
        // junction swapped in a moment ago. Prove where the file landed before writing a secret
        // into it, and take it back through the same handle if it is not where it was meant to be.
        if (!SafePaths.HandleIs(fs.SafeFileHandle, path, out string? actual))
        {
            SafePaths.DeleteByHandle(fs.SafeFileHandle);
            throw new IOException($"refusing to write {path}: it resolves to {actual}");
        }
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
