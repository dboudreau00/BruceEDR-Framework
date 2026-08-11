using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using ProcessShield.Core;

namespace ProcessShield.Monitoring;

/// <summary>
/// Pure transformations shared by the ETW monitors (registry, DNS, AMSI, process
/// access). Everything here is deterministic, allocation-conscious and free of any
/// dependency on a live trace session, so the interesting logic can be unit tested
/// while the ETW plumbing in the monitor classes stays thin enough to review by eye.
///
/// Nothing in this class talks to the network, the registry or the process table.
/// The one exception is <see cref="IsIgnorableDomain(string)"/>, which reads
/// <see cref="Environment.MachineName"/>; a machine-name-injecting overload exists
/// precisely so tests never depend on the host they run on.
/// </summary>
public static class MonitorSupport
{
    // ---------------------------------------------------------------- registry

    /// <summary>
    /// Rebuilds the best available printable name for a registry write.
    ///
    /// The kernel ETW Registry keyword does NOT hand out full paths. Each event
    /// carries a Key Control Block handle plus a name that is relative to that KCB,
    /// and TraceEvent only resolves the parent portion when it saw the matching
    /// KCBCreate/KCBRundown event. A real-time session that starts after the key was
    /// first opened therefore sees a PARTIAL name -- sometimes as little as the leaf.
    /// That limitation is the whole reason <see cref="IsPersistenceKey"/> matches on
    /// substrings instead of comparing against exact, anchored paths.
    ///
    /// What this method does do: trim whitespace and stray NULs (ETW strings are
    /// frequently NUL padded), fold forward slashes to backslashes, collapse repeated
    /// separators, map the NT object-manager hive prefixes onto the familiar Win32
    /// abbreviations, and append the value name when the event carried one. Case is
    /// preserved everywhere except the hive token, because the original casing is
    /// useful evidence in an alert and registry paths are case-insensitive anyway.
    /// </summary>
    /// <param name="keyName">Key name as reported by the event; may be partial or empty.</param>
    /// <param name="valueName">Value name as reported by the event; empty for key operations.</param>
    /// <returns>
    /// A normalised path, or an empty string when neither input carried anything.
    /// When the key is unknown but a value name is present, the value name alone is
    /// returned -- a deliberately honest "this is all we know" rather than inventing
    /// a hive we did not observe.
    /// </returns>
    public static string NormalizeRegistryKey(string? keyName, string? valueName)
    {
        string key = MapHive(CollapsePath(keyName));
        string value = CollapsePath(valueName).Trim('\\');

        if (key.Length == 0) return value;
        if (value.Length == 0) return key;
        return key + "\\" + value;
    }

    /// <summary>
    /// Trim, fold '/' to '\', collapse separator runs and drop a trailing separator.
    /// Leading separators are preserved because the NT prefix test below needs them.
    /// </summary>
    private static string CollapsePath(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return "";
        string s = raw.Trim().Trim('\0').Trim();
        if (s.Length == 0) return "";

        var sb = new StringBuilder(s.Length);
        bool lastWasSep = false;
        foreach (char c in s)
        {
            char ch = c == '/' ? '\\' : c;
            if (ch == '\\')
            {
                if (lastWasSep) continue;
                lastWasSep = true;
            }
            else
            {
                lastWasSep = false;
            }
            sb.Append(ch);
        }

        // A single trailing separator is noise; a path that is nothing but separators
        // collapses to "\" and then to the empty string, which callers treat as unknown.
        while (sb.Length > 0 && sb[^1] == '\\') sb.Length--;
        return sb.ToString();
    }

    /// <summary>
    /// Maps <c>\REGISTRY\MACHINE</c> to <c>HKLM</c> and <c>\REGISTRY\USER</c> to
    /// <c>HKU</c>. Any other <c>\REGISTRY\...</c> root (application hives, for
    /// example) is left verbatim rather than guessed at.
    /// </summary>
    private static string MapHive(string key)
    {
        if (key.Length == 0) return key;

        string rest;
        if (key.StartsWith(@"\REGISTRY\", StringComparison.OrdinalIgnoreCase)) rest = key[10..];
        else if (key.StartsWith(@"REGISTRY\", StringComparison.OrdinalIgnoreCase)) rest = key[9..];
        else return key;

        if (StartsWithToken(rest, "MACHINE")) return "HKLM" + rest[7..];
        if (StartsWithToken(rest, "USER")) return "HKU" + rest[4..];
        return key;

        static bool StartsWithToken(string s, string token) =>
            s.StartsWith(token, StringComparison.OrdinalIgnoreCase) &&
            (s.Length == token.Length || s[token.Length] == '\\');
    }

    /// <summary>
    /// Autostart / execution-hijack locations, matched as case-insensitive substrings
    /// against the output of <see cref="NormalizeRegistryKey"/>.
    ///
    /// Substring matching is a deliberate trade: ETW registry names are often partial
    /// (see <see cref="NormalizeRegistryKey"/>), so an anchored comparison would miss
    /// most real writes. The cost is that an unrelated key that merely contains one of
    /// these fragments will be flagged -- acceptable, because this predicate only
    /// decides whether an event is worth emitting as a signal, not whether it is
    /// malicious. Scoring happens later in the detection engine.
    /// </summary>
    private static readonly string[] PersistenceFragments =
    {
        @"\currentversion\run",                          // Run, RunOnce, RunOnceEx, RunServices*
        @"\currentversion\policies\explorer\run",        // policy-scoped autorun
        @"\currentversion\windows\load",                 // legacy Load= value
        @"\currentversion\windows\run",                  // legacy Run= value
        @"\image file execution options\",               // IFEO Debugger hijack
        @"\silentprocessexit\",                          // SilentProcessExit MonitorProcess
        @"\currentversion\winlogon",                     // Shell, Userinit, Notify, Taskman
        "appinit_dlls",                                  // AppInit_DLLs value (any hive)
        "appcertdlls",                                   // AppCertDlls value
        @"\currentversion\explorer\user shell folders",  // Startup folder redirection
        @"\currentversion\explorer\shell folders",
        @"\currentversion\explorer\browser helper objects",
        @"\currentversion\shellserviceobjectdelayload",
        @"\schedule\taskcache\",                         // scheduled task registration
        @"\shell\open\command",                          // file/protocol handler hijack
        @"\control\lsa\",                                // Security/Notification packages
        "userinitmprlogonscript"                         // logon script persistence
    };

    /// <summary>
    /// True when the (possibly partial) registry path looks like an autostart or
    /// execution-hijack location: Run keys, service registration, Image File Execution
    /// Options, Winlogon, AppInit/AppCert DLLs, or a COM server hijack.
    ///
    /// Known blind spot: if ETW handed us only a leaf name such as <c>Updater</c>, no
    /// fragment can match and the write is silently dropped. This monitor is a
    /// supplement to, not a replacement for, a kernel callback based registry filter.
    /// </summary>
    public static bool IsPersistenceKey(string keyPath)
    {
        if (string.IsNullOrWhiteSpace(keyPath)) return false;
        string p = keyPath.IndexOf('/') >= 0 ? keyPath.Replace('/', '\\') : keyPath;

        foreach (string fragment in PersistenceFragments)
            if (p.Contains(fragment, StringComparison.OrdinalIgnoreCase)) return true;

        // Service registration. Requires both tokens so that an unrelated path
        // containing "\Services\" (there are many) does not match on its own.
        if (p.Contains(@"\services\", StringComparison.OrdinalIgnoreCase) &&
            p.Contains("controlset", StringComparison.OrdinalIgnoreCase)) return true;

        // COM hijack: rewriting the server DLL/EXE behind a CLSID, or aliasing the
        // whole class with TreatAs. HKCU wins over HKLM for per-user hijacks.
        if (p.Contains(@"\clsid\", StringComparison.OrdinalIgnoreCase) &&
            (p.Contains(@"\inprocserver", StringComparison.OrdinalIgnoreCase) ||
             p.Contains(@"\localserver", StringComparison.OrdinalIgnoreCase) ||
             p.Contains(@"\treatas", StringComparison.OrdinalIgnoreCase))) return true;

        return false;
    }

    // --------------------------------------------------------------------- dns

    /// <summary>
    /// Canonicalises a DNS name for comparison and storage: trims surrounding
    /// whitespace, removes leading wildcard labels (<c>*.</c>) and the cookie-style
    /// leading dot, drops the trailing root dot, and lower-cases invariantly.
    ///
    /// Lower-casing is safe (DNS is case-insensitive) but it does destroy "0x20"
    /// randomised casing, so this function must not be used on anything where the
    /// original casing is evidence.
    /// </summary>
    /// <returns>The canonical name, or an empty string for null, blank, "." or "*".</returns>
    public static string NormalizeDomain(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        string s = name.Trim().Trim('\0').Trim();

        // Strip every leading wildcard/empty label. "*.*.example.com" and
        // "..example.com" both reduce to "example.com".
        while (s.Length > 0)
        {
            if (s.StartsWith("*.", StringComparison.Ordinal)) { s = s[2..]; continue; }
            if (s[0] == '.') { s = s[1..]; continue; }
            break;
        }

        if (s.Length == 0 || s == "*") return "";
        s = s.TrimEnd('.');
        return s.Length == 0 ? "" : s.ToLowerInvariant();
    }

    /// <summary>
    /// Uses the real machine name. Prefer the two-argument overload anywhere the
    /// result has to be reproducible (tests, replay of a trace captured elsewhere).
    /// </summary>
    public static bool IsIgnorableDomain(string domain) => IsIgnorableDomain(domain, Environment.MachineName);

    /// <summary>
    /// True for DNS names that are pure background noise, so the monitor can drop them
    /// before they reach the scoring engine. Each exclusion is a volume decision, and
    /// each one is also a hole an attacker could hide in -- they are listed explicitly
    /// so that trade is visible rather than buried:
    ///
    /// <list type="bullet">
    /// <item><description>empty -- nothing to attribute.</description></item>
    /// <item><description><c>*.in-addr.arpa</c> / <c>*.ip6.arpa</c> -- reverse lookups.
    /// The "name" is just an IP the process already has; the forward connection is
    /// covered by the NetworkConnect signal, so this would only double-count.</description></item>
    /// <item><description><c>*.local</c> -- mDNS/Bonjour. Extremely high volume on any
    /// network with printers or cast devices, and not routable off-link.</description></item>
    /// <item><description><c>wpad*</c> / <c>isatap*</c> -- proxy and tunnel
    /// autodiscovery. Windows queries these constantly and unprompted. Note that WPAD
    /// hijacking is itself an attack technique, so this exclusion is a genuine blind
    /// spot; detecting it needs the response, not the query.</description></item>
    /// <item><description><c>localhost</c> -- loopback.</description></item>
    /// <item><description>the machine's own name -- a host resolving itself. The
    /// prefix form (<c>machine.suffix</c>) is only honoured when the machine name is
    /// at least four characters, so a very short hostname cannot be abused to whitelist
    /// an attacker-registered domain such as <c>pc.evil.com</c>.</description></item>
    /// </list>
    /// </summary>
    /// <param name="domain">Name to test; re-normalised defensively.</param>
    /// <param name="machineName">Host short name, normally <see cref="Environment.MachineName"/>.</param>
    public static bool IsIgnorableDomain(string domain, string? machineName)
    {
        string d = NormalizeDomain(domain);
        if (d.Length == 0) return true;

        if (d == "localhost" || d.EndsWith(".localhost", StringComparison.Ordinal)) return true;
        if (d == "in-addr.arpa" || d.EndsWith(".in-addr.arpa", StringComparison.Ordinal)) return true;
        if (d == "ip6.arpa" || d.EndsWith(".ip6.arpa", StringComparison.Ordinal)) return true;
        if (d == "local" || d.EndsWith(".local", StringComparison.Ordinal)) return true;
        if (d == "wpad" || d.StartsWith("wpad.", StringComparison.Ordinal)) return true;
        if (d == "isatap" || d.StartsWith("isatap.", StringComparison.Ordinal)) return true;

        string m = NormalizeDomain(machineName);
        if (m.Length == 0) return false;
        if (d == m) return true;
        if (m.Length >= 4 && d.StartsWith(m + ".", StringComparison.Ordinal)) return true;

        return false;
    }

    // ------------------------------------------------------------------- pipes

    /// <summary>
    /// Prefixes that introduce a named pipe, longest first so that the bare device
    /// path does not shadow the qualified one.
    /// </summary>
    private static readonly string[] PipePrefixes =
    {
        @"\Device\NamedPipe\",
        @"\Device\NamedPipe",
        @"\??\pipe\",
        @"\\.\pipe\",
        @"\\?\pipe\",
        @"\pipe\"
    };

    /// <summary>
    /// Reduces any of the spellings Windows uses for a named pipe to the bare pipe
    /// name, so <c>\Device\NamedPipe\srvsvc</c>, <c>\\.\pipe\srvsvc</c> and
    /// <c>srvsvc</c> all compare equal. The remote form <c>\\HOST\pipe\name</c> is
    /// also handled, and the host is discarded -- the pipe name is what identifies the
    /// technique (for example <c>atsvc</c> or a Cobalt Strike style random name), and
    /// the peer host is carried on the network signal instead.
    ///
    /// Inner backslashes are left alone: pipe names legitimately contain them
    /// (<c>\\.\pipe\wkssvc\sub</c>), and stripping them would merge distinct pipes.
    /// An input that is already a bare name is returned unchanged.
    /// </summary>
    public static string NormalizePipeName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        string s = raw.Trim().Trim('\0').Trim();
        if (s.Length == 0) return "";
        if (s.IndexOf('/') >= 0) s = s.Replace('/', '\\');

        bool matched = false;
        foreach (string prefix in PipePrefixes)
        {
            if (!s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            s = s[prefix.Length..];
            matched = true;
            break;
        }

        // Remote UNC form: \\<host>\pipe\<name>. The host label is variable, so it
        // cannot live in the fixed prefix table above.
        if (!matched && s.StartsWith(@"\\", StringComparison.Ordinal))
        {
            int sep = s.IndexOf('\\', 2);
            if (sep > 2)
            {
                string rest = s[(sep + 1)..];
                if (rest.StartsWith(@"pipe\", StringComparison.OrdinalIgnoreCase)) s = rest[5..];
                else if (rest.Equals("pipe", StringComparison.OrdinalIgnoreCase)) s = "";
            }
        }

        return s.TrimStart('\\');
    }

    // ---------------------------------------------------------- process access

    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessCreateThread = 0x0002;
    private const uint ProcessSetSessionId = 0x0004;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessDupHandle = 0x0040;
    private const uint ProcessCreateProcess = 0x0080;
    private const uint ProcessSetQuota = 0x0100;
    private const uint ProcessSetInformation = 0x0200;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessSuspendResume = 0x0800;
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessSetLimitedInformation = 0x2000;

    private const uint StandardDelete = 0x0001_0000;
    private const uint StandardReadControl = 0x0002_0000;
    private const uint StandardWriteDac = 0x0004_0000;
    private const uint StandardWriteOwner = 0x0008_0000;
    private const uint StandardSynchronize = 0x0010_0000;

    private const uint AccessSystemSecurity = 0x0100_0000;
    private const uint MaximumAllowed = 0x0200_0000;
    private const uint GenericAll = 0x1000_0000;
    private const uint GenericExecute = 0x2000_0000;
    private const uint GenericWrite = 0x4000_0000;
    private const uint GenericRead = 0x8000_0000;

    /// <summary>PROCESS_ALL_ACCESS as defined for Vista and later (0x001FFFFF).</summary>
    private const uint ProcessAllAccess = 0x001F_FFFF;

    /// <summary>
    /// The rights that let one process read, write or execute inside another. Handle
    /// duplication is included because it is the standard way to launder a privileged
    /// handle (open LSASS via a third process, duplicate the handle back).
    /// </summary>
    private const uint SensitiveRights =
        ProcessCreateThread | ProcessVmOperation | ProcessVmRead | ProcessVmWrite | ProcessDupHandle;

    /// <summary>
    /// True when the requested access would allow credential theft or code injection.
    ///
    /// Beyond the explicit rights, three "wide" requests count as sensitive even though
    /// they name no specific bit: <c>MAXIMUM_ALLOWED</c>, <c>GENERIC_ALL</c> and the
    /// generic read/write mappings. Asking for MAXIMUM_ALLOWED is a real evasion --
    /// the caller receives PROCESS_VM_READ without ever writing 0x10 into the mask.
    /// <c>GENERIC_EXECUTE</c> maps only to SYNCHRONIZE on a process object and is
    /// therefore not treated as sensitive.
    ///
    /// PROCESS_TERMINATE alone is deliberately NOT sensitive here: killing a process is
    /// reported by the audit provider's own terminate event, which the monitor handles
    /// separately, and treating every terminate as an injection attempt would bury the
    /// real signal.
    /// </summary>
    public static bool IsSensitiveProcessAccess(uint desiredAccess)
    {
        if (desiredAccess == 0) return false;
        if ((desiredAccess & SensitiveRights) != 0) return true;
        if ((desiredAccess & ProcessAllAccess) == ProcessAllAccess) return true;
        if ((desiredAccess & (MaximumAllowed | GenericAll | GenericRead | GenericWrite)) != 0) return true;
        return false;
    }

    /// <summary>
    /// Named rights in the order they are rendered. Keeping this ordered (rather than
    /// deriving it from a dictionary) makes <see cref="DescribeAccessMask"/> output
    /// stable, which matters because alert text is diffed and grepped by analysts.
    /// </summary>
    private static readonly (uint Bit, string Name)[] AccessRights =
    {
        (ProcessTerminate, "PROCESS_TERMINATE"),
        (ProcessCreateThread, "PROCESS_CREATE_THREAD"),
        (ProcessSetSessionId, "PROCESS_SET_SESSIONID"),
        (ProcessVmOperation, "PROCESS_VM_OPERATION"),
        (ProcessVmRead, "PROCESS_VM_READ"),
        (ProcessVmWrite, "PROCESS_VM_WRITE"),
        (ProcessDupHandle, "PROCESS_DUP_HANDLE"),
        (ProcessCreateProcess, "PROCESS_CREATE_PROCESS"),
        (ProcessSetQuota, "PROCESS_SET_QUOTA"),
        (ProcessSetInformation, "PROCESS_SET_INFORMATION"),
        (ProcessQueryInformation, "PROCESS_QUERY_INFORMATION"),
        (ProcessSuspendResume, "PROCESS_SUSPEND_RESUME"),
        (ProcessQueryLimitedInformation, "PROCESS_QUERY_LIMITED_INFORMATION"),
        (ProcessSetLimitedInformation, "PROCESS_SET_LIMITED_INFORMATION"),
        (StandardDelete, "DELETE"),
        (StandardReadControl, "READ_CONTROL"),
        (StandardWriteDac, "WRITE_DAC"),
        (StandardWriteOwner, "WRITE_OWNER"),
        (StandardSynchronize, "SYNCHRONIZE"),
        (AccessSystemSecurity, "ACCESS_SYSTEM_SECURITY"),
        (MaximumAllowed, "MAXIMUM_ALLOWED"),
        (GenericAll, "GENERIC_ALL"),
        (GenericExecute, "GENERIC_EXECUTE"),
        (GenericWrite, "GENERIC_WRITE"),
        (GenericRead, "GENERIC_READ")
    };

    /// <summary>
    /// Renders a process access mask as a pipe-joined list of the rights it contains,
    /// for example <c>PROCESS_VM_READ|PROCESS_QUERY_INFORMATION</c>.
    ///
    /// A mask that contains every PROCESS_ALL_ACCESS bit collapses to the single token
    /// <c>PROCESS_ALL_ACCESS</c> rather than spelling out nineteen rights. Bits that
    /// belong to no documented right are appended once as a hex residue so nothing is
    /// silently dropped -- an undocumented bit in an access mask is exactly the kind of
    /// detail worth keeping in an alert. Returns <c>NONE</c> for a mask of zero.
    /// </summary>
    public static string DescribeAccessMask(uint mask)
    {
        var parts = new List<string>(6);
        uint rest = mask;

        if ((mask & ProcessAllAccess) == ProcessAllAccess)
        {
            parts.Add("PROCESS_ALL_ACCESS");
            rest &= ~ProcessAllAccess;
        }

        foreach ((uint bit, string name) in AccessRights)
        {
            if ((rest & bit) == 0) continue;
            parts.Add(name);
            rest &= ~bit;
        }

        if (rest != 0) parts.Add("0x" + rest.ToString("X8", CultureInfo.InvariantCulture));
        return parts.Count == 0 ? "NONE" : string.Join("|", parts);
    }

    // ------------------------------------------------------------------ script

    /// <summary>
    /// Marker appended by <see cref="TruncateScript"/>. Exposed so consumers can tell
    /// a truncated body from a short one without re-deriving the format string.
    /// </summary>
    public const string TruncationMarkerPrefix = "\n...[truncated, ";

    /// <summary>
    /// Bounds a script body before it is stored on a <c>Signal</c> or written to a log
    /// line. AMSI can surface megabyte-scale buffers, and an unbounded copy of every
    /// one of them per process is a trivial memory-pressure denial of service against
    /// the agent itself.
    ///
    /// Line endings are normalised to <c>\n</c> first so that a CRLF and an LF copy of
    /// the same script hash and compare identically. The reported length is therefore
    /// the length AFTER normalisation, which is the length of the text actually being
    /// truncated. The cut point is nudged back by one when it would fall between a
    /// surrogate pair, so the result is never invalid UTF-16.
    /// </summary>
    /// <param name="script">Raw script body; null and empty both yield an empty string.</param>
    /// <param name="max">Maximum characters to keep. Must not be negative.</param>
    public static string TruncateScript(string? script, int max = 4096)
    {
        if (max < 0) throw new ArgumentOutOfRangeException(nameof(max), max, "max must not be negative");
        if (string.IsNullOrEmpty(script)) return "";

        string text = NormalizeNewlines(script);
        if (text.Length <= max) return text;

        int cut = max;
        if (cut > 0 && char.IsHighSurrogate(text[cut - 1])) cut--;

        return string.Concat(
            text.AsSpan(0, cut),
            TruncationMarkerPrefix,
            text.Length.ToString(CultureInfo.InvariantCulture),
            " chars total]");
    }

    /// <summary>CRLF and lone CR both become LF. Skips the copy when there is no CR.</summary>
    private static string NormalizeNewlines(string s)
    {
        if (s.IndexOf('\r') < 0) return s;
        return s.Replace("\r\n", "\n").Replace('\r', '\n');
    }

    /// <summary>
    /// Only the first 64 KB is handed to the regular expressions. The character-ratio,
    /// backtick and line-length checks still walk the whole string, so padding a
    /// payload out to megabytes does not defeat the cheap structural heuristics.
    /// </summary>
    private const int MaxRegexScanChars = 64 * 1024;

    /// <summary>A single line longer than this is not something a human typed.</summary>
    private const int LongLineThreshold = 1000;

    /// <summary>Regex budget. Adversarial input must never be able to wedge the pump.</summary>
    private static readonly TimeSpan RegexBudget = TimeSpan.FromMilliseconds(250);

    private const RegexOptions ScriptRegexOptions =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;

    /// <summary>
    /// <c>-e</c> / <c>-enc</c> / <c>-EncodedCommand</c> (or the slash and en/em dash
    /// spellings PowerShell also accepts) followed by a base64 run. Requiring the blob
    /// keeps <c>-ExecutionPolicy</c> and similar benign switches from matching.
    /// </summary>
    private static readonly Regex EncodedCommandFlag =
        new(@"(?<![\w])[-/\u2013\u2014]e[a-z]*\s+[A-Za-z0-9+/=]{24,}", ScriptRegexOptions, RegexBudget);

    /// <summary>A long unbroken base64 run, with or without an encoded-command flag.</summary>
    private static readonly Regex Base64Blob =
        new(@"[A-Za-z0-9+/]{200,}={0,2}", ScriptRegexOptions, RegexBudget);

    /// <summary>
    /// Literal giveaways. Substring matching over the whole body, because these are
    /// cheap and an attacker who pads the payload cannot hide them behind a size limit.
    /// </summary>
    private static readonly string[] ObfuscationMarkers =
    {
        "frombase64string",
        "-encodedcommand",
        "[char[]]",
        "-bxor",
        "[reflection.assembly]::load",
        "invoke-obfuscation"
    };

    /// <summary>
    /// Heuristic: does this script body look deliberately obfuscated?
    ///
    /// Fires on any one of: an encoded-command flag with a base64 argument, a long
    /// base64 run, a known literal marker (<c>FromBase64String</c>, <c>[char[]]</c>,
    /// <c>-bxor</c>, reflective assembly loads), a char-array join, repeated
    /// brace-dollar variable constructs, heavy backtick escaping, a single line over
    /// 1000 characters, or a high ratio of punctuation to alphanumerics.
    ///
    /// This is an INPUT to scoring, not a verdict. Known false positives: minified
    /// JavaScript, embedded JSON or certificate blobs, and legitimate one-line
    /// deployment commands all trip the structural rules. Known false negatives: a
    /// payload that is merely fetched and executed (<c>IEX (iwr $u)</c>) contains none
    /// of these markers and looks perfectly ordinary, and an attacker who splits an
    /// encoded blob across many short lines beats both the base64 and line-length
    /// rules. Returns false for null, empty or whitespace input.
    /// </summary>
    public static bool LooksObfuscatedScript(string script)
    {
        if (string.IsNullOrWhiteSpace(script)) return false;

        foreach (string marker in ObfuscationMarkers)
            if (script.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;

        // Char-array reconstruction: -join is common on its own, so it only counts
        // when paired with a character source.
        if (script.Contains("-join", StringComparison.OrdinalIgnoreCase) &&
            (script.Contains("[char", StringComparison.OrdinalIgnoreCase) ||
             script.Contains("tochararray", StringComparison.OrdinalIgnoreCase))) return true;

        if (MaxLineLength(script) > LongLineThreshold) return true;

        int backticks = CountChar(script, '`');
        if (backticks >= 5 && backticks > script.Length * 0.02) return true;

        // ${...} is legal PowerShell but rare; obfuscators lean on it heavily to break
        // up identifiers, so several occurrences (or one wrapping an escape) is telling.
        int braceDollar = CountOccurrences(script, "${");
        if (braceDollar >= 3) return true;
        if (braceDollar >= 1 && backticks >= 1) return true;

        string head = script.Length <= MaxRegexScanChars ? script : script[..MaxRegexScanChars];

        if (HasHighPunctuationRatio(head)) return true;

        try
        {
            if (EncodedCommandFlag.IsMatch(head)) return true;
            if (Base64Blob.IsMatch(head)) return true;
        }
        catch (RegexMatchTimeoutException)
        {
            // Pathological input beat the budget. Fall through rather than guessing:
            // the structural checks above already ran over the whole body.
        }

        return false;
    }

    /// <summary>
    /// Punctuation-dense text is the signature of token-splitting obfuscation. Measured
    /// against non-whitespace characters only, and skipped for short fragments where
    /// the ratio is meaningless.
    /// </summary>
    private static bool HasHighPunctuationRatio(string s)
    {
        int significant = 0, punctuation = 0;
        foreach (char c in s)
        {
            if (char.IsWhiteSpace(c)) continue;
            significant++;
            if (!char.IsLetterOrDigit(c)) punctuation++;
        }
        return significant >= 64 && punctuation > significant * 0.40;
    }

    private static int MaxLineLength(string s)
    {
        int max = 0, current = 0;
        foreach (char c in s)
        {
            if (c == '\n' || c == '\r') { if (current > max) max = current; current = 0; }
            else current++;
        }
        return current > max ? current : max;
    }

    private static int CountChar(string s, char c)
    {
        int n = 0;
        foreach (char ch in s) if (ch == c) n++;
        return n;
    }

    private static int CountOccurrences(string s, string needle)
    {
        int n = 0, i = 0;
        while ((i = s.IndexOf(needle, i, StringComparison.Ordinal)) >= 0) { n++; i += needle.Length; }
        return n;
    }
}

/// <summary>
/// Time-windowed duplicate suppressor used by the high-volume monitors. Registry
/// writes in particular arrive in bursts -- a single installer can rewrite the same
/// Run value dozens of times in a second -- and forwarding every one of them both
/// floods the log and lets a benign process inflate its own score.
///
/// Deliberately NOT thread-safe: each monitor owns one instance and touches it only
/// from its own ETW pump thread. Adding a lock would put a contended monitor on the
/// hot path of a real-time session for no benefit.
/// </summary>
internal sealed class SignalDeduplicator
{
    private readonly Dictionary<string, DateTime> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly IClock _clock;
    private readonly TimeSpan _window;
    private readonly int _capacity;

    /// <param name="clock">Injected so the window can be exercised without sleeping.</param>
    /// <param name="window">How long a key stays suppressed after it is admitted.</param>
    /// <param name="capacity">Hard cap on retained keys; see <see cref="ShouldEmit"/>.</param>
    public SignalDeduplicator(IClock clock, TimeSpan window, int capacity = 4096)
    {
        if (window < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window), window, "window must not be negative");
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity), capacity, "capacity must be positive");
        _clock = clock;
        _window = window;
        _capacity = capacity;
    }

    /// <summary>Number of keys currently retained. Exposed for tests and diagnostics.</summary>
    public int Count => _seen.Count;

    /// <summary>
    /// True when the key has not been admitted within the window, in which case the
    /// admission time is recorded. A key that keeps repeating is admitted once per
    /// window rather than being suppressed forever, so a genuinely persistent
    /// behaviour still reaches the engine.
    ///
    /// Memory is bounded: at capacity the expired entries are pruned, and if that is
    /// not enough the whole table is dropped. Losing the table fails OPEN -- the worst
    /// case is a handful of duplicate signals, never a missed one.
    /// </summary>
    public bool ShouldEmit(string key)
    {
        DateTime now = _clock.UtcNow;

        if (_seen.TryGetValue(key, out DateTime last) && now - last < _window) return false;

        if (_seen.Count >= _capacity && !_seen.ContainsKey(key))
        {
            Prune(now);
            if (_seen.Count >= _capacity) _seen.Clear();
        }

        _seen[key] = now;
        return true;
    }

    private void Prune(DateTime now)
    {
        var expired = new List<string>();
        foreach (var kv in _seen)
            if (now - kv.Value >= _window) expired.Add(kv.Key);
        foreach (string k in expired) _seen.Remove(k);
    }
}

/// <summary>
/// Plumbing shared by the four ETW monitors. Everything here touches a live trace
/// session or a raw <see cref="TraceEvent"/>, so unlike <see cref="MonitorSupport"/>
/// it is not unit tested -- it is kept small and defensive instead, and lives beside
/// the pure helpers only so the four monitors do not each carry a private copy.
/// </summary>
internal static class EtwSessionSupport
{
    /// <summary>
    /// Stops a session of the same name left behind by a previous crash. ETW sessions
    /// outlive the process that created them, so without this a hard kill permanently
    /// burns one of the machine's limited session slots and the next start fails with
    /// "already exists".
    /// </summary>
    public static void ClearStaleSession(string sessionName, Logger log)
    {
        try
        {
            foreach (string name in TraceEventSession.GetActiveSessionNames())
            {
                if (!string.Equals(name, sessionName, StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    new TraceEventSession(sessionName).Stop();
                    log.Info($"cleared a leaked ETW session '{sessionName}' from a prior run");
                }
                catch (Exception ex) { log.Error($"clear stale ETW session '{sessionName}'", ex); }
            }
        }
        catch (Exception ex)
        {
            log.Error("enumerate ETW sessions", ex);
        }
    }

    /// <summary>
    /// Reads the first payload field that exists under any of the candidate names.
    /// Manifest field names for the providers used here are undocumented and differ
    /// between Windows builds, so every read is by name with fallbacks and every read
    /// is wrapped -- a decoding failure on one field must not kill the pump.
    /// </summary>
    public static object? Payload(TraceEvent data, params string[] names)
    {
        foreach (string name in names)
        {
            try
            {
                object? value = data.PayloadByName(name);
                if (value is not null) return value;
            }
            catch
            {
                // Malformed manifest or a field the decoder cannot render. Try the next.
            }
        }
        return null;
    }

    /// <summary>
    /// Last-resort lookup: the first payload field whose NAME contains the token.
    /// Used when a build renames a field entirely (QueryName -> Name, for example).
    /// </summary>
    public static object? PayloadLike(TraceEvent data, string token)
    {
        string[] names;
        try { names = data.PayloadNames; }
        catch { return null; }
        if (names is null) return null;

        foreach (string name in names)
        {
            if (name is null || name.IndexOf(token, StringComparison.OrdinalIgnoreCase) < 0) continue;
            try
            {
                object? value = data.PayloadByName(name);
                if (value is not null) return value;
            }
            catch { }
        }
        return null;
    }

    /// <summary>Payload field as a string, or null when absent or blank.</summary>
    public static string? GetString(TraceEvent data, params string[] names)
    {
        object? value = Payload(data, names);
        string? s = value as string ?? value?.ToString();
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    /// <summary>
    /// Payload field as an unsigned 32-bit value. Returns <paramref name="fallback"/>
    /// when the field is missing or is not convertible, which lets a caller distinguish
    /// "absent" from a legitimate zero.
    /// </summary>
    public static uint GetUInt32(TraceEvent data, uint fallback, params string[] names)
    {
        object? value = Payload(data, names);
        if (value is null) return fallback;
        try
        {
            return value switch
            {
                uint u => u,
                int i => unchecked((uint)i),
                ulong ul => unchecked((uint)ul),
                long l => unchecked((uint)l),
                ushort us => us,
                short sh => unchecked((uint)sh),
                byte b => b,
                string s => uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint p)
                    ? p
                    : (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                       uint.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint h)
                        ? h
                        : fallback),
                _ => Convert.ToUInt32(value, CultureInfo.InvariantCulture)
            };
        }
        catch
        {
            return fallback;
        }
    }

    /// <summary>Payload field as a signed 32-bit value, with the same fallback contract.</summary>
    public static int GetInt32(TraceEvent data, int fallback, params string[] names)
    {
        object? value = Payload(data, names);
        if (value is null) return fallback;
        try
        {
            return value switch
            {
                int i => i,
                uint u => unchecked((int)u),
                long l => unchecked((int)l),
                ulong ul => unchecked((int)ul),
                ushort us => us,
                short sh => sh,
                byte b => b,
                string s => int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int p) ? p : fallback,
                _ => Convert.ToInt32(value, CultureInfo.InvariantCulture)
            };
        }
        catch
        {
            return fallback;
        }
    }
}
