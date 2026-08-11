namespace ProcessShield.Detection;

/// <summary>
/// One MITRE ATT&amp;CK technique. Only the fields ProcessShield actually needs are
/// modelled — the id is the contract, the rest is presentation.
/// </summary>
public sealed record AttackTechnique
{
    public required string Id { get; init; }          // e.g. "T1059.001"
    public required string Name { get; init; }
    public required string Tactic { get; init; }      // primary tactic name
    public string Url => "https://attack.mitre.org/techniques/" + Id.Replace('.', '/') + "/";
}

/// <summary>
/// Static MITRE ATT&amp;CK (Enterprise) reference for the techniques ProcessShield's
/// rules can emit. Detection rules cite technique ids; this table turns an id into a
/// name + tactic for alerts, the ATT&amp;CK coverage report and the GUI.
///
/// Unknown ids are never an error: <see cref="Lookup"/> synthesises a placeholder so a
/// community rule can cite a technique this table has not been updated for yet.
/// </summary>
public static class AttackCatalog
{
    /// <summary>ATT&amp;CK Enterprise tactics, in kill-chain order.</summary>
    public static readonly string[] Tactics =
    {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact"
    };

    private static readonly Dictionary<string, AttackTechnique> Map = Build();

    public static IReadOnlyCollection<AttackTechnique> All => Map.Values;

    /// <summary>Resolve a technique id. Never returns null; unknown ids get a stub.</summary>
    public static AttackTechnique Lookup(string id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return new AttackTechnique { Id = "", Name = "(none)", Tactic = "Unknown" };
        if (Map.TryGetValue(id.Trim().ToUpperInvariant(), out var t)) return t;
        return new AttackTechnique { Id = id.Trim().ToUpperInvariant(), Name = "(unmapped technique)", Tactic = "Unknown" };
    }

    public static bool IsKnown(string id) =>
        !string.IsNullOrWhiteSpace(id) && Map.ContainsKey(id.Trim().ToUpperInvariant());

    /// <summary>Techniques grouped by tactic, for a coverage matrix.</summary>
    public static IReadOnlyDictionary<string, List<AttackTechnique>> ByTactic()
    {
        var d = new Dictionary<string, List<AttackTechnique>>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in Map.Values)
        {
            if (!d.TryGetValue(t.Tactic, out var list)) d[t.Tactic] = list = new List<AttackTechnique>();
            list.Add(t);
        }
        foreach (var list in d.Values) list.Sort((a, b) => string.CompareOrdinal(a.Id, b.Id));
        return d;
    }

    private static Dictionary<string, AttackTechnique> Build()
    {
        var d = new Dictionary<string, AttackTechnique>(StringComparer.OrdinalIgnoreCase);
        void T(string id, string name, string tactic) =>
            d[id] = new AttackTechnique { Id = id, Name = name, Tactic = tactic };

        // Initial Access / Execution
        T("T1204", "User Execution", "Execution");
        T("T1204.002", "User Execution: Malicious File", "Execution");
        T("T1059", "Command and Scripting Interpreter", "Execution");
        T("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution");
        T("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution");
        T("T1059.005", "Command and Scripting Interpreter: Visual Basic", "Execution");
        T("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution");
        T("T1106", "Native API", "Execution");
        T("T1053", "Scheduled Task/Job", "Execution");
        T("T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution");
        T("T1047", "Windows Management Instrumentation", "Execution");

        // Persistence
        T("T1547", "Boot or Logon Autostart Execution", "Persistence");
        T("T1547.001", "Registry Run Keys / Startup Folder", "Persistence");
        T("T1543", "Create or Modify System Process", "Persistence");
        T("T1543.003", "Create or Modify System Process: Windows Service", "Persistence");
        T("T1546", "Event Triggered Execution", "Persistence");
        T("T1546.012", "Image File Execution Options Injection", "Persistence");
        T("T1546.015", "Component Object Model Hijacking", "Persistence");
        T("T1197", "BITS Jobs", "Persistence");

        // Defense Evasion
        T("T1218", "System Binary Proxy Execution", "Defense Evasion");
        T("T1218.005", "System Binary Proxy Execution: Mshta", "Defense Evasion");
        T("T1218.010", "System Binary Proxy Execution: Regsvr32", "Defense Evasion");
        T("T1218.011", "System Binary Proxy Execution: Rundll32", "Defense Evasion");
        T("T1127", "Trusted Developer Utilities Proxy Execution", "Defense Evasion");
        T("T1127.001", "Trusted Developer Utilities Proxy Execution: MSBuild", "Defense Evasion");
        T("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion");
        T("T1027", "Obfuscated Files or Information", "Defense Evasion");
        T("T1027.002", "Obfuscated Files or Information: Software Packing", "Defense Evasion");
        T("T1027.010", "Obfuscated Files or Information: Command Obfuscation", "Defense Evasion");
        T("T1055", "Process Injection", "Defense Evasion");
        T("T1055.001", "Process Injection: DLL Injection", "Defense Evasion");
        T("T1055.012", "Process Injection: Process Hollowing", "Defense Evasion");
        T("T1620", "Reflective Code Loading", "Defense Evasion");
        T("T1112", "Modify Registry", "Defense Evasion");
        T("T1562", "Impair Defenses", "Defense Evasion");
        T("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion");
        T("T1562.004", "Impair Defenses: Disable or Modify System Firewall", "Defense Evasion");
        T("T1070", "Indicator Removal", "Defense Evasion");
        T("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion");
        T("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion");
        T("T1134", "Access Token Manipulation", "Defense Evasion");
        T("T1036", "Masquerading", "Defense Evasion");
        T("T1036.005", "Masquerading: Match Legitimate Name or Location", "Defense Evasion");
        T("T1564", "Hide Artifacts", "Defense Evasion");
        T("T1564.003", "Hide Artifacts: Hidden Window", "Defense Evasion");
        T("T1553", "Subvert Trust Controls", "Defense Evasion");
        T("T1553.002", "Subvert Trust Controls: Code Signing", "Defense Evasion");

        // Credential Access
        T("T1003", "OS Credential Dumping", "Credential Access");
        T("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access");
        T("T1555", "Credentials from Password Stores", "Credential Access");
        T("T1555.003", "Credentials from Web Browsers", "Credential Access");
        T("T1552", "Unsecured Credentials", "Credential Access");
        T("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access");
        T("T1539", "Steal Web Session Cookie", "Credential Access");
        T("T1056", "Input Capture", "Credential Access");
        T("T1056.001", "Input Capture: Keylogging", "Credential Access");

        // Discovery
        T("T1057", "Process Discovery", "Discovery");
        T("T1082", "System Information Discovery", "Discovery");
        T("T1083", "File and Directory Discovery", "Discovery");
        T("T1016", "System Network Configuration Discovery", "Discovery");
        T("T1518", "Software Discovery", "Discovery");
        T("T1518.001", "Software Discovery: Security Software Discovery", "Discovery");

        // Lateral Movement
        T("T1021", "Remote Services", "Lateral Movement");
        T("T1570", "Lateral Tool Transfer", "Lateral Movement");

        // Collection
        T("T1005", "Data from Local System", "Collection");
        T("T1074", "Data Staged", "Collection");
        T("T1074.001", "Data Staged: Local Data Staging", "Collection");
        T("T1119", "Automated Collection", "Collection");
        T("T1560", "Archive Collected Data", "Collection");
        T("T1560.001", "Archive Collected Data: Archive via Utility", "Collection");
        T("T1113", "Screen Capture", "Collection");
        T("T1115", "Clipboard Data", "Collection");

        // Command and Control
        T("T1071", "Application Layer Protocol", "Command and Control");
        T("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control");
        T("T1071.004", "Application Layer Protocol: DNS", "Command and Control");
        T("T1090", "Proxy", "Command and Control");
        T("T1095", "Non-Application Layer Protocol", "Command and Control");
        T("T1102", "Web Service", "Command and Control");
        T("T1105", "Ingress Tool Transfer", "Command and Control");
        T("T1219", "Remote Access Software", "Command and Control");
        T("T1568", "Dynamic Resolution", "Command and Control");
        T("T1568.002", "Dynamic Resolution: Domain Generation Algorithms", "Command and Control");
        T("T1571", "Non-Standard Port", "Command and Control");
        T("T1573", "Encrypted Channel", "Command and Control");
        T("T1572", "Protocol Tunneling", "Command and Control");
        T("T1008", "Fallback Channels", "Command and Control");
        T("T1104", "Multi-Stage Channels", "Command and Control");

        // Exfiltration
        T("T1041", "Exfiltration Over C2 Channel", "Exfiltration");
        T("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration");
        T("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "Exfiltration");
        T("T1567", "Exfiltration Over Web Service", "Exfiltration");
        T("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration");
        T("T1029", "Scheduled Transfer", "Exfiltration");
        T("T1030", "Data Transfer Size Limits", "Exfiltration");

        // Impact
        T("T1486", "Data Encrypted for Impact", "Impact");
        T("T1490", "Inhibit System Recovery", "Impact");
        T("T1489", "Service Stop", "Impact");

        return d;
    }
}
