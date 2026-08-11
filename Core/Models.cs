namespace ProcessShield.Core;

public enum Verdict { Allow, Warn, Quarantine }

public enum SignalKind
{
    ProcessStart,
    ImageLoad,
    FileCreate,
    NetworkConnect,
    MemoryMatch,

    // --- extended telemetry (v2) -------------------------------------------
    /// <summary>A process exited. Lets the engine close out lineage and beacon state.</summary>
    ProcessStop,
    /// <summary>A registry value/key was written (persistence, defence evasion).</summary>
    RegistryWrite,
    /// <summary>A DNS name was resolved by a process (C2 domains, DGA, tunnelling).</summary>
    DnsQuery,
    /// <summary>One process opened a handle to another (credential theft, injection).</summary>
    ProcessAccess,
    /// <summary>Script/macro content surfaced by AMSI before execution.</summary>
    ScriptContent,
    /// <summary>A named pipe was created or connected to (C2 / lateral movement).</summary>
    NamedPipe
}

/// <summary>A single piece of telemetry emitted by any monitor.</summary>
public sealed record Signal
{
    public required SignalKind Kind { get; init; }
    public required int Pid { get; init; }
    public int ParentPid { get; init; }
    public string ProcessName { get; init; } = "";
    public string ImagePath { get; init; } = "";
    public string CommandLine { get; init; } = "";
    public string? FilePath { get; init; }          // FileCreate / ImageLoad
    public string? RemoteAddress { get; init; }      // NetworkConnect
    public int RemotePort { get; init; }
    public string? Detail { get; init; }
    public DateTime TimestampUtc { get; init; } = DateTime.UtcNow;

    // --- extended telemetry (v2). All optional, so every existing producer and
    //     every existing test keeps compiling unchanged. -----------------------

    /// <summary>ProcessAccess: the process being opened. 0 when not applicable.</summary>
    public int TargetPid { get; init; }
    /// <summary>ProcessAccess: the requested access mask (PROCESS_VM_READ etc.).</summary>
    public uint DesiredAccess { get; init; }
    /// <summary>RegistryWrite: full key path, e.g. <c>HKLM\...\Run</c>.</summary>
    public string? RegistryKey { get; init; }
    /// <summary>RegistryWrite: value name written under <see cref="RegistryKey"/>.</summary>
    public string? RegistryValue { get; init; }
    /// <summary>DnsQuery: the queried name, already lower-cased by the monitor.</summary>
    public string? Domain { get; init; }
    /// <summary>ScriptContent: the script/macro body AMSI handed to the scanner.</summary>
    public string? ScriptText { get; init; }
    /// <summary>NamedPipe: the pipe name, without the <c>\\.\pipe\</c> prefix.</summary>
    public string? PipeName { get; init; }
    /// <summary>Owning user (DOMAIN\user) when the monitor can attribute one.</summary>
    public string? User { get; init; }

    /// <summary>
    /// The single most descriptive path-like field for this signal, used by rule
    /// matching so one rule can target files, images, registry keys, pipes and
    /// domains without knowing which monitor produced the event.
    /// </summary>
    public string PrimaryTarget => Kind switch
    {
        SignalKind.RegistryWrite => RegistryKey ?? "",
        SignalKind.DnsQuery => Domain ?? "",
        SignalKind.NamedPipe => PipeName ?? "",
        SignalKind.NetworkConnect => RemoteAddress is null ? "" : $"{RemoteAddress}:{RemotePort}",
        SignalKind.ScriptContent => ScriptText ?? "",
        _ => FilePath ?? ImagePath
    };
}

/// <summary>Result of a single OS action, with a human-readable reason on failure.</summary>
public readonly struct ActionResult
{
    public bool Ok { get; }
    public string Message { get; }
    private ActionResult(bool ok, string message) { Ok = ok; Message = message; }
    public static ActionResult Success(string message = "ok") => new(true, message);
    public static ActionResult Fail(string message) => new(false, message);
}

/// <summary>
/// One scored observation, kept structured so alerts can carry ATT&amp;CK technique
/// IDs and the originating rule instead of only a rendered sentence.
/// </summary>
public sealed record ReasonEntry
{
    public required int Points { get; init; }
    public required string Text { get; init; }
    /// <summary>Rule id that fired, e.g. <c>lolbin-unusual-parent</c>. Empty for builtins.</summary>
    public string RuleId { get; init; } = "";
    /// <summary>MITRE ATT&amp;CK technique ids, e.g. <c>["T1059.001"]</c>.</summary>
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();
    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;

    /// <summary>The legacy one-line rendering used by the console and the log.</summary>
    public override string ToString()
    {
        string tech = Techniques.Count == 0 ? "" : " {" + string.Join(",", Techniques) + "}";
        return Points >= 0 ? $"[+{Points}] {Text}{tech}" : $"[{Points}] {Text}{tech}";
    }
}

/// <summary>
/// Immutable copy of a profile's state, safe to hand to other threads (the console
/// and the response worker) without touching the live, owner-thread-only object.
/// </summary>
public sealed record ProfileSnapshot
{
    public required int Pid { get; init; }
    public required string ProcessName { get; init; }
    public required string ImagePath { get; init; }
    public required int Score { get; init; }
    public required bool Trusted { get; init; }
    public required bool Contained { get; init; }
    public required bool SuspendedByAnalyst { get; init; }
    public required bool Terminated { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }
    public required IReadOnlyList<string> StagedArchives { get; init; }
    public required DateTime FirstSeenUtc { get; init; }
    public required DateTime LastUpdatedUtc { get; init; }

    // --- v2 additions. Defaulted so existing construction sites still compile. ---

    public int ParentPid { get; init; }
    public string CommandLine { get; init; } = "";
    /// <summary>Ancestry, nearest parent first. Populated by the process tree.</summary>
    public IReadOnlyList<string> Ancestry { get; init; } = Array.Empty<string>();
    /// <summary>Stable id grouping every alert raised for this process.</summary>
    public string IncidentId { get; init; } = "";
    /// <summary>Distinct MITRE ATT&amp;CK technique ids observed, sorted.</summary>
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();
    /// <summary>Structured form of <see cref="Reasons"/>.</summary>
    public IReadOnlyList<ReasonEntry> ReasonLog { get; init; } = Array.Empty<ReasonEntry>();
    /// <summary>Distinct remote endpoints this process contacted (<c>ip:port</c>).</summary>
    public IReadOnlyList<string> RemoteEndpoints { get; init; } = Array.Empty<string>();
    /// <summary>Distinct DNS names this process resolved.</summary>
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
    /// <summary>Peak score reached before any decay, for triage ordering.</summary>
    public int PeakScore { get; init; }
}

/// <summary>
/// Rolling risk state per process. Mutated ONLY by the single owner thread in
/// ShieldHost, so it needs no internal locking. Attack chains such as
/// collect -> archive -> exfil accumulate here so the combined score rises even
/// when each step looks benign alone.
/// </summary>
public sealed class ThreatProfile
{
    public int Pid { get; }
    public string ProcessName { get; set; } = "";
    public string ImagePath { get; set; } = "";
    public string CommandLine { get; set; } = "";
    public int ParentPid { get; set; }
    public int Score { get; set; }
    /// <summary>Highest score ever reached, unaffected by decay.</summary>
    public int PeakScore { get; set; }

    public bool Trusted { get; set; }
    public bool SignatureChecked { get; set; }
    public bool Contained { get; set; }
    public bool SuspendedByAnalyst { get; set; }
    public bool Terminated { get; set; }
    public bool MemoryScanned { get; set; }
    public bool Exited { get; set; }

    /// <summary>Rendered reason lines. Kept in lockstep with <see cref="ReasonLog"/>.</summary>
    public readonly List<string> Reasons = new();
    /// <summary>Structured reasons carrying rule id and ATT&amp;CK techniques.</summary>
    public readonly List<ReasonEntry> ReasonLog = new();
    /// <summary>Distinct ATT&amp;CK technique ids observed on this process.</summary>
    public readonly HashSet<string> Techniques = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Rule ids that have already fired, so a repeat cannot re-score.</summary>
    public readonly HashSet<string> FiredOnce = new(StringComparer.OrdinalIgnoreCase);

    public DateTime? SuspiciousSpawnUtc;
    public DateTime? CredentialAccessUtc;
    public DateTime? ArchiveStagedUtc;
    public readonly HashSet<string> StagedArchives = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Distinct <c>ip:port</c> destinations contacted.</summary>
    public readonly HashSet<string> RemoteEndpoints = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Distinct DNS names resolved.</summary>
    public readonly HashSet<string> Domains = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Stable incident id, assigned the first time this process is flagged.</summary>
    public string IncidentId { get; set; } = "";
    /// <summary>Last time decay was applied, so decay is charged once per interval.</summary>
    public DateTime LastDecayUtc { get; set; }

    public DateTime FirstSeenUtc { get; }
    public DateTime LastUpdatedUtc { get; set; }

    public ThreatProfile(int pid) : this(pid, DateTime.UtcNow) { }

    /// <summary>Clock-injectable ctor so replay and tests are deterministic.</summary>
    public ThreatProfile(int pid, DateTime nowUtc)
    {
        Pid = pid;
        FirstSeenUtc = nowUtc;
        LastUpdatedUtc = nowUtc;
        LastDecayUtc = nowUtc;
    }

    public void Add(int points, string reason) => Add(points, reason, "", Array.Empty<string>(), DateTime.UtcNow);

    /// <summary>
    /// Score an observation. <paramref name="ruleId"/> and <paramref name="techniques"/>
    /// are carried into the alert so downstream consumers get ATT&amp;CK context.
    /// </summary>
    public void Add(int points, string reason, string ruleId, IReadOnlyList<string> techniques, DateTime nowUtc)
    {
        var entry = new ReasonEntry
        {
            Points = points,
            Text = reason,
            RuleId = ruleId,
            Techniques = techniques,
            TimeUtc = nowUtc
        };
        Score += points;
        if (Score < 0) Score = 0;
        if (Score > PeakScore) PeakScore = Score;
        ReasonLog.Add(entry);
        Reasons.Add(entry.ToString());
        foreach (var t in techniques) Techniques.Add(t);
        LastUpdatedUtc = nowUtc;
    }
}

/// <summary>
/// Editable indicator sets. Ordinary DETECTION artifacts (as found in AV
/// signatures, MITRE ATT&amp;CK, and public Sigma/YARA rules). Replace or extend
/// with your own threat-intel feed.
/// </summary>
public static class IocDatabase
{
    public static readonly string[] LolBins =
    {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
        "bitsadmin.exe", "installutil.exe", "msbuild.exe", "curl.exe"
    };

    public static readonly string[] UnusualParents =
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "acrobat.exe", "acrord32.exe", "chrome.exe", "msedge.exe", "firefox.exe"
    };

    public static readonly string[] CommandLineIocs =
    {
        "-enc", "-encodedcommand", "-nop", "-w hidden", "-windowstyle hidden",
        "downloadstring", "downloadfile", "net.webclient", "invoke-webrequest",
        "invoke-expression", "iex(", "frombase64string", "-urlcache", "/transfer",
        "-executionpolicy bypass"
    };

    public static readonly string[] SensitiveFileFragments =
    {
        @"\google\chrome\user data\", @"\microsoft\edge\user data\",
        @"\mozilla\firefox\profiles\", "login data", "cookies.sqlite",
        "local state", "key4.db", "logins.json",
        "wallet.dat", @"\electrum\wallets\", @"\exodus\", @"\discord\leveldb\"
    };

    public static readonly string[] ArchiveExtensions =
    { ".zip", ".7z", ".rar", ".tar", ".gz", ".cab" };

    public static readonly string[] StagingDirFragments =
    { @"\temp\", @"\appdata\local\temp\", @"\programdata\", @"\public\", @"\windows\temp\" };

    public static readonly string[] MemoryStringIocs =
    {
        "select * from logins", "encrypted_key", @"chrome\user data",
        "grabber", "stealer", "exfil", "keylog",
        "setwindowshookex", "getasynckeystate", "keybd_event"
    };

    public static readonly string[] SuspiciousModuleFragments =
    { "vnc", "tightvnc", "hvnc", "remcos", "quasar", "asyncrat", "njrat", "meterpreter" };
}
