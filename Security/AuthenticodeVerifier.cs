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
            bool chainOk = ChainIsValid(path, allow.CheckRevocation);
            if (!chainOk) return false;

            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            string thumb = cert.Thumbprint ?? "";
            string subject = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false) ?? "";

            if (chainOk && allow.Thumbprints.Any(t =>
                    string.Equals(NormalizeThumbprint(t), thumb, StringComparison.OrdinalIgnoreCase)))
                return true;

            if (chainOk && allow.AllowSubjectMatch &&
                !string.IsNullOrEmpty(subject) &&
                allow.Publishers.Any(pub => string.Equals(pub, subject, StringComparison.OrdinalIgnoreCase)))
                return true;

            return false;
        }
        catch
        {
            return false;   // unsigned, tampered, or inaccessible
        }
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
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x100;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x10;

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

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, IntPtr pWVTData);
}
