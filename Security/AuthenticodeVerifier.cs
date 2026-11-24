using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using BruceEDR.Configuration;

namespace BruceEDR.Security;

/// <summary>
/// Full Authenticode verification: validates the signature chain with
/// WinVerifyTrust (optionally with revocation), then authorises the file only if
/// its signer thumbprint is pinned, or (when enabled) its signer subject is on the
/// publisher allowlist. Replaces the earlier subject-name-only check. The allowlist
/// is swappable for hot-reload.
/// </summary>
public sealed class AuthenticodeVerifier
{
    private volatile AllowlistConfig _allow;

    public AuthenticodeVerifier(AllowlistConfig allow) => _allow = allow;

    public void UpdateAllowlist(AllowlistConfig allow) => _allow = allow;

    /// <summary>Resolve the image for a PID and evaluate it against the policy.</summary>
    public bool IsTrusted(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            string? path = p.MainModule?.FileName;
            return !string.IsNullOrEmpty(path) && IsTrustedFile(path);
        }
        catch { return false; }
    }

    public bool IsTrustedFile(string path)
    {
        var allow = _allow;
        try
        {
            if (!File.Exists(path)) return false;

            // Trust REQUIRES a cryptographically valid Authenticode chain. CreateFromSignedFile
            // only extracts the embedded signer cert; it does not prove the signature covers
            // this file's bytes. So without WinVerifyTrust an attacker can keep a trusted
            // cert's thumbprint/subject in a tampered binary. There is no setting that relaxes
            // this: the old requireValidChain flag never actually did (both matchers below
            // gate on chainOk regardless), so it was removed rather than left as a knob that
            // appeared to do something.
            var (chainOk, cert) = VerifyAndLoadSigner(path, allow.CheckRevocation);
            if (!chainOk || cert is null) { cert?.Dispose(); return false; }

            using (cert)
            {
                string thumb = cert.Thumbprint ?? "";
                string subject = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? "";

                if (allow.Thumbprints.Any(t =>
                        string.Equals(NormalizeThumbprint(t), thumb, StringComparison.OrdinalIgnoreCase)))
                    return true;

                if (allow.AllowSubjectMatch &&
                    !string.IsNullOrEmpty(subject) &&
                    allow.Publishers.Any(pub => string.Equals(pub, subject, StringComparison.OrdinalIgnoreCase)))
                    return true;

                return false;
            }
        }
        catch
        {
            return false;   // unsigned, tampered, or inaccessible
        }
    }

    /// <summary>
    /// The publisher a valid embedded Authenticode signature names, or null when the file has none, the
    /// chain does not verify, or the file cannot be read. No allowlist is consulted: this says who signed
    /// the file, not whether the operator trusts them. Revocation is not checked, which keeps the network
    /// off the detection path; that is the allowlist check's default too.
    /// </summary>
    public static string? PublisherOf(string path)
    {
        try
        {
            var (ok, cert) = VerifyAndLoadSigner(path, checkRevocation: false);
            if (!ok || cert is null) { cert?.Dispose(); return null; }
            using (cert)
            {
                string subject = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? "";
                return subject.Length > 0 ? subject : "an unnamed publisher";
            }
        }
        catch { return null; }
    }

    /// <summary>
    /// Verifies either an embedded PE Authenticode signature or a Windows security-catalog
    /// signature (used by most inbox System32 binaries such as notepad.exe, svchost.exe and cmd.exe)
    /// and returns the leaf signer certificate when valid.
    /// </summary>
    private static (bool Valid, X509Certificate2? Signer) VerifyAndLoadSigner(string path, bool checkRevocation)
    {
        if (!File.Exists(path)) return (false, null);

        if (ChainIsValid(path, checkRevocation))
        {
            try
            {
                return (true, new X509Certificate2(X509Certificate.CreateFromSignedFile(path)));
            }
            catch { /* embedded blob unreadable; try catalog below */ }
        }

        return VerifyCatalogSigner(path, checkRevocation);
    }

    // Keep only hex digits so a pinned thumbprint copied from certmgr (which can carry
    // an invisible U+200E left-to-right mark, spaces, or colon separators) still matches
    // the raw uppercase hex returned by X509Certificate2.Thumbprint.
    private static string NormalizeThumbprint(string s)
        => new string(s.Where(Uri.IsHexDigit).ToArray());

    // ---- WinVerifyTrust interop ----

    private static bool ChainIsValid(string path, bool checkRevocation)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = path,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        IntPtr pFile = Marshal.AllocHGlobal((int)fileInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = checkRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pUnion = pFile,
                dwStateAction = WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WTD_SAFER_FLAG | (checkRevocation ? 0u : WTD_REVOCATION_CHECK_NONE),
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            IntPtr pData = Marshal.AllocHGlobal((int)data.cbStruct);
            try
            {
                Marshal.StructureToPtr(data, pData, false);
                int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                // Re-read to obtain hWVTStateData, then close the state.
                data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, pData, false);
                WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                return result == 0;   // 0 == trusted
            }
            finally { Marshal.FreeHGlobal(pData); }
        }
        catch { return false; }
        finally
        {
            // Free the LPWStr that StructureToPtr marshaled inside the struct, then the block.
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;

    private static (bool Valid, X509Certificate2? Signer) VerifyCatalogSigner(string path, bool checkRevocation)
    {
        IntPtr hCatAdmin = IntPtr.Zero;
        IntPtr hCatInfo = IntPtr.Zero;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            IntPtr hFile = fs.SafeFileHandle.DangerousGetHandle();

            if (!CryptCATAdminAcquireContext2(out hCatAdmin, IntPtr.Zero, null, IntPtr.Zero, 0) &&
                !CryptCATAdminAcquireContext(out hCatAdmin, IntPtr.Zero, 0))
                return (false, null);

            uint hashLen = 0;
            bool useV2 = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, null, 0);
            if (!useV2 && hashLen == 0)
            {
                CryptCATAdminCalcHashFromFileHandle(hFile, ref hashLen, null, 0);
            }
            if (hashLen == 0 || hashLen > 512) return (false, null);

            byte[] hash = new byte[hashLen];
            bool hashed = useV2
                ? CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, ref hashLen, hash, 0)
                : CryptCATAdminCalcHashFromFileHandle(hFile, ref hashLen, hash, 0);
            if (!hashed || hashLen == 0) return (false, null);

            string memberTag = Convert.ToHexString(hash.AsSpan(0, (int)hashLen));
            var hHash = GCHandle.Alloc(hash, GCHandleType.Pinned);
            try
            {
                IntPtr pHash = hHash.AddrOfPinnedObject();
                while (true)
                {
                    // CryptCATAdminEnumCatalogFromHash releases the previous hCatInfo automatically.
                    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pHash, hashLen, 0, ref hCatInfo);
                    if (hCatInfo == IntPtr.Zero) break;

                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>(), wszCatalogFilePath = "" };
                    if (!CryptCATCatalogInfoFromContext(hCatInfo, ref info, 0) || string.IsNullOrEmpty(info.wszCatalogFilePath))
                        continue;

                    if (CatalogChainIsValid(info.wszCatalogFilePath, memberTag, path, hFile, pHash, hashLen, hCatAdmin, checkRevocation))
                    {
                        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                        hCatInfo = IntPtr.Zero;
                        return (true, new X509Certificate2(X509Certificate.CreateFromSignedFile(info.wszCatalogFilePath)));
                    }
                }
            }
            finally { hHash.Free(); }

            return (false, null);
        }
        catch { return (false, null); }
        finally
        {
            if (hCatInfo != IntPtr.Zero && hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            if (hCatAdmin != IntPtr.Zero)
                CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }

    private static bool CatalogChainIsValid(string catalogPath, string memberTag, string memberFilePath,
        IntPtr hMemberFile, IntPtr pbHash, uint cbHash, IntPtr hCatAdmin, bool checkRevocation)
    {
        var catInfo = new WINTRUST_CATALOG_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
            dwCatalogVersion = 0,
            pcwszCatalogFilePath = catalogPath,
            pcwszMemberTag = memberTag,
            pcwszMemberFilePath = memberFilePath,
            hMemberFile = hMemberFile,
            pbCalculatedFileHash = pbHash,
            cbCalculatedFileHash = cbHash,
            pcCatalogContext = IntPtr.Zero,
            hCatAdmin = hCatAdmin
        };

        IntPtr pCat = Marshal.AllocHGlobal((int)catInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(catInfo, pCat, false);

            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = checkRevocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_CATALOG,
                pUnion = pCat,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG | (checkRevocation ? 0u : WTD_REVOCATION_CHECK_NONE)
            };

            IntPtr pData = Marshal.AllocHGlobal((int)data.cbStruct);
            try
            {
                Marshal.StructureToPtr(data, pData, false);
                int result = WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                data = Marshal.PtrToStructure<WINTRUST_DATA>(pData);
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, pData, false);
                WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, pData);

                return result == 0;
            }
            finally { Marshal.FreeHGlobal(pData); }
        }
        catch { return false; }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat);
            Marshal.FreeHGlobal(pCat);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pUnion;              // -> WINTRUST_FILE_INFO for WTD_CHOICE_FILE
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFilePath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
        string? pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, IntPtr pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile,
        ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile,
        ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, IntPtr pbHash,
        uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
}
