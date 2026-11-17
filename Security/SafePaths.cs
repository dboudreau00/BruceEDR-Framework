using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace BruceEDR.Security;

/// <summary>
/// File-system primitives for code that runs as SYSTEM or elevated and touches a path some
/// other account can influence: a staged archive the suspect process chose, a folder under
/// ProgramData that a standard user can create first, a folder under the analyst's own
/// profile that non-elevated code can rearrange.
///
/// The rule is the same everywhere: open a handle once, prove where the handle really points
/// (its final path must be the path we meant, so no junction, symbolic link or mount point
/// sits anywhere on the way), then do the read, the write, the delete or the DACL change
/// through that handle. A path re-resolved between the check and the act is exactly the
/// window a link swap needs, so nothing here acts on a path a second time.
///
/// Off Windows (the test runs on Linux) the handle checks have no equivalent, so the methods
/// fall back to refusing any symbolic link on the path and then acting by path. That keeps
/// the decisions testable on every platform; the handle checks themselves need Windows.
/// </summary>
public static class SafePaths
{
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier TrustedInstaller =
        new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    /// <summary>
    /// The first component of <paramref name="path"/> (the path itself or any folder above it)
    /// that is a symbolic link or a junction, or null when there is none. Cloud-file and
    /// other non-link reparse points are not links and are not reported.
    /// </summary>
    public static string? FindLink(string path)
    {
        string full = Path.GetFullPath(path);
        for (string? p = full; !string.IsNullOrEmpty(p); p = Path.GetDirectoryName(p))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(p); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) == 0) continue;

            FileSystemInfo info = (attributes & FileAttributes.Directory) != 0 ? new DirectoryInfo(p) : new FileInfo(p);
            if (info.LinkTarget is not null) return p;
        }
        return null;
    }

    /// <summary>
    /// True when this process runs as SYSTEM or with an elevated Administrators token: the
    /// case in which a folder a standard account owns, or one under a user profile that
    /// medium-integrity code can rearrange, must not be trusted. False off Windows.
    /// </summary>
    public static bool ProcessIsAdministrative
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return id.IsSystem || new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    /// <summary>True for SYSTEM, Administrators and TrustedInstaller.</summary>
    internal static bool IsAdministrative(SecurityIdentifier? sid) =>
        sid is not null && (sid.Equals(LocalSystem) || sid.Equals(Administrators) || sid.Equals(TrustedInstaller));

    // ------------------------------------------------------------------ directories

    /// <summary>
    /// Creates <paramref name="path"/> if it is missing, with SYSTEM + Administrators (+ the
    /// creating account) as its only, non-inherited ACL, and returns null; or returns why the
    /// folder cannot be trusted and changes nothing. An existing folder is refused when it, or
    /// any folder above it, is a link, and, when <paramref name="requireAdministrativeOwner"/>,
    /// when it or its parent is owned by anyone but SYSTEM, Administrators or TrustedInstaller:
    /// a standard user who created the folder first owns it and could undo any ACL set on it.
    /// The DACL is applied through a handle whose final path was checked, so a junction swapped
    /// in after the check cannot redirect it.
    /// </summary>
    public static string? EnsurePrivateDirectory(string path, bool requireAdministrativeOwner, bool allowCurrentUserOwner = false)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) { return $"invalid path ({ex.Message})"; }

        try
        {
            if (FindLink(full) is { } link) return $"{link} is a link (junction or symbolic link)";

            string? parent = Path.GetDirectoryName(full);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);

            if (!OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(full);
                return FindLink(full) is { } late ? $"{late} is a link (junction or symbolic link)" : null;
            }

            // The parent's owner only matters for a folder SYSTEM shares with standard users (ProgramData).
            // The desktop app's folders sit under the analyst's own profile, whose parents the analyst owns.
            if (requireAdministrativeOwner && !allowCurrentUserOwner && !string.IsNullOrEmpty(parent) &&
                OwnerProblem(parent, directory: true) is { } parentProblem)
                return parentProblem;

            var sec = SecretFiles.PrivateDirectorySecurity();
            if (!Directory.Exists(full))
            {
                // Created with its DACL in one step: there is no moment in which the folder
                // exists with the parent's inherited (often Users: create files) rights.
                try { new DirectoryInfo(full).Create(sec); }
                catch (IOException) when (Directory.Exists(full)) { /* lost a creation race; verified below */ }
            }

            using var handle = OpenVerified(full, READ_CONTROL | WRITE_DAC, directory: true, out string? error);
            if (handle is null) return error;
            if (requireAdministrativeOwner && OwnerOf(handle) is var owner && !IsAdministrative(owner) &&
                !(allowCurrentUserOwner && IsCurrentUser(owner)))
                return $"{full} is owned by {Describe(owner)}, not SYSTEM or Administrators; delete it and restart";

            byte[] sd = sec.GetSecurityDescriptorBinaryForm();
            if (!SetKernelObjectSecurity(handle, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd))
                return $"{full}: the DACL could not be applied (Win32 error {Marshal.GetLastWin32Error()})";
            return null;
        }
        catch (Exception ex)
        {
            return $"{full}: {ex.GetType().Name}: {ex.Message}";
        }
    }

    /// <summary>As <see cref="EnsurePrivateDirectory"/>, throwing an <see cref="IOException"/> instead of returning the reason.</summary>
    public static void RequirePrivateDirectory(string path, bool requireAdministrativeOwner, bool allowCurrentUserOwner = false)
    {
        if (EnsurePrivateDirectory(path, requireAdministrativeOwner, allowCurrentUserOwner) is { } problem)
            throw new IOException("refusing to use " + path + ": " + problem);
    }

    // ------------------------------------------------------------------ files

    /// <summary>
    /// Deletes the file named by <paramref name="path"/>, and only that file: on Windows the
    /// delete goes through a handle whose final path is <paramref name="path"/>, so a folder
    /// above it swapped for a junction cannot turn the delete onto another file. Returns false
    /// when nothing is there, throws when the path does not lead where it says.
    /// </summary>
    public static bool DeleteFile(string path)
    {
        string full = Path.GetFullPath(path);
        if (!OperatingSystem.IsWindows())
        {
            if (!File.Exists(full) && new FileInfo(full).LinkTarget is null) return false;
            if (FindLink(Path.GetDirectoryName(full) ?? full) is { } link)
                throw new IOException($"refusing to delete {full}: {link} is a link");
            File.Delete(full);   // a link itself is removed, never its target
            return true;
        }

        // The last component may itself be a link: open the link, not its target, and delete it.
        using var handle = OpenRaw(full, DELETE | FILE_READ_ATTRIBUTES, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, out int error);
        if (handle is null)
        {
            if (error is ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND) return false;
            throw new IOException($"cannot open {full} to delete it (Win32 error {error})");
        }
        if (!FinalPathIs(handle, full, out string? actual))
            throw new IOException($"refusing to delete {full}: it resolves to {actual}");
        DeleteByHandle(handle);
        return true;
    }

    /// <summary>
    /// Opens <paramref name="path"/> for reading and deleting, proves it is the file it claims
    /// to be (final path equal to the path, a single hard link, not a directory), and returns
    /// the handle; or null with the reason. The caller reads with <see cref="RandomAccess"/> and
    /// deletes with <see cref="DeleteByHandle"/>, both on this handle, so the file read is the
    /// file deleted whatever happens to the path in between. Off Windows the handle is a plain
    /// read handle and the checks are the link refusal.
    /// </summary>
    public static SafeFileHandle? OpenForQuarantine(string path, out string? error)
    {
        error = null;
        string full = Path.GetFullPath(path);
        if (!OperatingSystem.IsWindows())
        {
            if (FindLink(full) is { } link) { error = $"{link} is a link (junction or symbolic link)"; return null; }
            try { return File.OpenHandle(full, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); }
            catch (Exception ex) { error = $"{ex.GetType().Name}: {ex.Message}"; return null; }
        }

        var handle = OpenVerified(full, GENERIC_READ | DELETE, directory: false, out error);
        if (handle is null) return null;
        if (!GetFileInformationByHandle(handle, out var info))
        {
            error = $"cannot query {full} (Win32 error {Marshal.GetLastWin32Error()})";
            handle.Dispose();
            return null;
        }
        if ((info.FileAttributes & (uint)FileAttributes.Directory) != 0 || info.NumberOfLinks != 1)
        {
            error = info.NumberOfLinks != 1
                ? $"{full} has {info.NumberOfLinks} hard links; quarantining one name would not remove the file and could touch another"
                : $"{full} is a directory";
            handle.Dispose();
            return null;
        }
        return handle;
    }

    /// <summary>
    /// Reads the whole file behind a handle from <see cref="OpenForQuarantine"/>, refusing one
    /// above <paramref name="maxBytes"/>. Reading through the handle is what makes the bytes
    /// stored the bytes of the file that is then deleted.
    /// </summary>
    public static byte[] ReadAll(SafeFileHandle handle, long maxBytes)
    {
        long length = RandomAccess.GetLength(handle);
        if (length > maxBytes)
            throw new IOException($"file is {length} bytes, above the {maxBytes}-byte single-item limit");
        var buffer = new byte[length];
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = RandomAccess.Read(handle, buffer.AsSpan(offset), offset);
            if (read == 0) break;               // truncated under us; keep what we got
            offset += read;
        }
        return offset == buffer.Length ? buffer : buffer[..offset];
    }

    /// <summary>
    /// Removes the file a quarantine handle names: through the handle on Windows, so it is the
    /// file that was read; off Windows by path, after the link refusal.
    /// </summary>
    public static void DeleteQuarantined(SafeFileHandle handle, string path)
    {
        if (OperatingSystem.IsWindows()) { DeleteByHandle(handle); return; }
        DeleteFile(path);
    }

    /// <summary>
    /// Creates <paramref name="path"/>, which must not exist, writes <paramref name="content"/>
    /// and keeps the folder's inherited DACL. The new file must land where its path says: if a
    /// junction above it sent the create elsewhere, the stray file is deleted through its own
    /// handle and the call throws, so nothing is ever written through a link. Used to restore
    /// a quarantined file into a folder that a standard user may control.
    /// </summary>
    public static void CreateNewFile(string path, byte[] content)
    {
        string full = Path.GetFullPath(path);
        if (FindLink(Path.GetDirectoryName(full) ?? full) is { } link)
            throw new IOException($"refusing to create {full}: {link} is a link (junction or symbolic link)");
        if (!OperatingSystem.IsWindows())
        {
            using var plain = new FileStream(full, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            plain.Write(content, 0, content.Length);
            return;
        }

        // CREATE_NEW fails on any existing name, a link included, so the last component can
        // never be followed; only a folder above it can redirect, and that is checked next.
        var handle = OpenRaw(full, GENERIC_WRITE | DELETE, CREATE_NEW, 0, out int error);
        if (handle is null) throw new IOException($"cannot create {full} (Win32 error {error})");
        using (handle)
        {
            if (!FinalPathIs(handle, full, out string? actual))
            {
                DeleteByHandle(handle);
                throw new IOException($"refusing to write {full}: it resolves to {actual}");
            }
            using var fs = new FileStream(handle, FileAccess.Write, bufferSize: 0);
            fs.Write(content, 0, content.Length);
            fs.Flush();
        }
    }

    /// <summary>Marks the file behind <paramref name="handle"/> for deletion. Off Windows this is a no-op the caller replaces with a path delete.</summary>
    public static void DeleteByHandle(SafeFileHandle handle)
    {
        if (!OperatingSystem.IsWindows()) return;
        byte delete = 1;   // FILE_DISPOSITION_INFO.DeleteFile
        if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref delete, 1))
            throw new IOException($"delete failed (Win32 error {Marshal.GetLastWin32Error()})");
    }

    /// <summary>
    /// Throws unless the file behind <paramref name="handle"/> is <paramref name="path"/>. Used
    /// right after a create, so a junction above the new file is caught before anything is
    /// written into it; the caller then deletes the file through the same handle.
    /// </summary>
    public static bool HandleIs(SafeFileHandle handle, string path, out string? actual)
    {
        actual = null;
        if (!OperatingSystem.IsWindows()) return FindLink(path) is null;
        return FinalPathIs(handle, Path.GetFullPath(path), out actual);
    }

    /// <summary>
    /// Writes <paramref name="content"/> over the private file <paramref name="path"/>, in a
    /// folder that <see cref="EnsurePrivateDirectory"/> accepted. An existing file is reused only
    /// when it is the file it claims to be, has one hard link and an administrative owner;
    /// anything else (a link, a hard link, a file a standard user planted before the folder
    /// was locked) is removed and the file is created afresh with a private DACL. Writing in
    /// place, rather than delete-and-create, keeps a reader (the watchdog) from ever finding
    /// the file missing.
    /// </summary>
    public static void WritePrivateFile(string path, byte[] content)
    {
        string full = Path.GetFullPath(path);
        if (!OperatingSystem.IsWindows())
        {
            if (FindLink(full) is { } link) throw new IOException($"refusing to write {full}: {link} is a link");
            File.WriteAllBytes(full, content);
            return;
        }

        var handle = OpenRaw(full, GENERIC_WRITE | DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES, OPEN_EXISTING,
                             FILE_FLAG_OPEN_REPARSE_POINT, out int error);
        if (handle is null)
        {
            if (error is not (ERROR_FILE_NOT_FOUND)) throw new IOException($"cannot open {full} (Win32 error {error})");
            SecretFiles.CreateProtected(full, content);
            return;
        }

        bool reuse;
        using (handle)
        {
            if (!FinalPathIs(handle, full, out string? actual))
                throw new IOException($"refusing to write {full}: it resolves to {actual}");
            reuse = GetFileInformationByHandle(handle, out var info)
                    && (info.FileAttributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) == 0
                    && info.NumberOfLinks == 1
                    && IsAdministrative(OwnerOf(handle));
            if (reuse)
            {
                using var fs = new FileStream(handle, FileAccess.Write, bufferSize: 0);
                fs.SetLength(0);
                fs.Write(content, 0, content.Length);
                fs.Flush();
                return;
            }
            DeleteByHandle(handle);        // removes the link or planted file itself, never a target
        }
        SecretFiles.CreateProtected(full, content);
    }

    // ------------------------------------------------------------------ internals

    /// <summary>True when <paramref name="sid"/> is the account this process runs as (an elevated token keeps the user's own SID).</summary>
    private static bool IsCurrentUser(SecurityIdentifier? sid)
    {
        if (sid is null) return false;
        try { using var id = WindowsIdentity.GetCurrent(); return id.User is { } me && sid.Equals(me); }
        catch { return false; }
    }

    private static string? OwnerProblem(string path, bool directory)
    {
        using var handle = OpenVerified(path, READ_CONTROL, directory, out string? error);
        if (handle is null) return error;
        var owner = OwnerOf(handle);
        return IsAdministrative(owner) ? null : $"{path} is owned by {Describe(owner)}, not SYSTEM or Administrators";
    }

    private static string Describe(SecurityIdentifier? sid)
    {
        if (sid is null) return "an unknown account";
        try { return sid.Translate(typeof(NTAccount)).Value; }
        catch { return sid.Value; }
    }

    /// <summary>Opens <paramref name="path"/> following links, then refuses the handle unless its final path is the path itself.</summary>
    internal static SafeFileHandle? OpenVerified(string path, uint access, bool directory, out string? error)
    {
        error = null;
        string full = Path.GetFullPath(path);
        var handle = OpenRaw(full, access, OPEN_EXISTING, directory ? FILE_FLAG_BACKUP_SEMANTICS : 0, out int code);
        if (handle is null) { error = $"cannot open {full} (Win32 error {code})"; return null; }
        if (!FinalPathIs(handle, full, out string? actual))
        {
            handle.Dispose();
            error = $"{full} resolves to {actual}: a junction, symbolic link or mount point is on the way";
            return null;
        }
        return handle;
    }

    private static SafeFileHandle? OpenRaw(string path, uint access, uint disposition, uint flags, out int error)
    {
        var h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, IntPtr.Zero,
                            disposition, flags, IntPtr.Zero);
        error = Marshal.GetLastWin32Error();
        if (h.IsInvalid) { h.Dispose(); return null; }
        return h;
    }

    private static bool FinalPathIs(SafeFileHandle handle, string expectedFull, out string? actual)
    {
        actual = FinalPath(handle);
        if (actual is null) return false;
        return string.Equals(Normalize(actual), Normalize(expectedFull), StringComparison.OrdinalIgnoreCase);
    }

    private static string? FinalPath(SafeFileHandle handle)
    {
        var buffer = new char[1024];
        uint n = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        if (n > buffer.Length)
        {
            buffer = new char[n];
            n = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
        }
        return n == 0 || n > buffer.Length ? null : new string(buffer, 0, (int)n);
    }

    /// <summary>Strips the \\?\ and \\?\UNC\ forms and a trailing separator, so a final path and a full path compare.</summary>
    internal static string Normalize(string path)
    {
        string p = path;
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p[8..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p[4..];
        if (p.Length > 3 && (p.EndsWith('\\') || p.EndsWith('/'))) p = p.TrimEnd('\\', '/');
        return p;
    }

    private static SecurityIdentifier? OwnerOf(SafeFileHandle handle)
    {
        uint rc = GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                  out IntPtr owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out IntPtr sd);
        if (rc != 0) return null;
        try { return owner == IntPtr.Zero ? null : new SecurityIdentifier(owner); }
        finally { if (sd != IntPtr.Zero) LocalFree(sd); }
    }

    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint DELETE = 0x00010000;
    private const uint READ_CONTROL = 0x00020000;
    private const uint WRITE_DAC = 0x00040000;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
    private const uint CREATE_NEW = 1, OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const int ERROR_FILE_NOT_FOUND = 2, ERROR_PATH_NOT_FOUND = 3;
    private const int FileDispositionInfo = 4;
    private const int SE_FILE_OBJECT = 1;
    private const uint OWNER_SECURITY_INFORMATION = 0x1;
    private const uint DACL_SECURITY_INFORMATION = 0x4;
    private const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;

    // Pack = 4 is the native layout: its times are FILETIMEs (two DWORDs), not 8-aligned longs, and the
    // default packing moved NumberOfLinks to the wrong offset (a fresh file read as 458752 links).
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public long CreationTime, LastAccessTime, LastWriteTime;
        public uint VolumeSerialNumber, FileSizeHigh, FileSizeLow, NumberOfLinks, FileIndexHigh, FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, [Out] char[] buffer, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref byte info, uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint securityInformation, byte[] descriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInfo,
        out IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr descriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}
