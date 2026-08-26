using System.Text.Json;

namespace BruceEDR.Configuration;

public sealed class BruceConfig
{
    public DetectionConfig Detection { get; set; } = new();
    public AllowlistConfig Allowlist { get; set; } = new();
    public TelemetryConfig Telemetry { get; set; } = new();
    public ServiceConfig Service { get; set; } = new();
    public IntelConfig Intel { get; set; } = new();
    public ResponseConfig Response { get; set; } = new();
    public ApiConfig Api { get; set; } = new();
    public WatchlistConfig Watchlist { get; set; } = new();

    public void ClampAndValidate()
    {
        Detection.WarnThreshold = Math.Max(1, Detection.WarnThreshold);
        Detection.QuarantineThreshold = Math.Max(Detection.WarnThreshold + 1, Detection.QuarantineThreshold);
        if (Detection.CorrelationWindowSeconds <= 0) Detection.CorrelationWindowSeconds = 30;
        Detection.TrustDiscount = Math.Max(0, Detection.TrustDiscount);
        if (string.IsNullOrWhiteSpace(Detection.MemoryScanEngine)) Detection.MemoryScanEngine = "builtin";
        if (string.IsNullOrWhiteSpace(Detection.RulesPath)) Detection.RulesPath = "rules/detection";
        Detection.ScoreDecayPoints = Math.Max(0, Detection.ScoreDecayPoints);
        Detection.ScoreDecayIntervalSeconds = Math.Max(10, Detection.ScoreDecayIntervalSeconds);
        Detection.BeaconMinConnections = Math.Clamp(Detection.BeaconMinConnections, 3, 512);
        Detection.MaxTrackedProcesses = Math.Clamp(Detection.MaxTrackedProcesses, 128, 262144);

        Service.HeartbeatIntervalSeconds = Math.Max(1, Service.HeartbeatIntervalSeconds);
        Service.WatchdogStaleSeconds = Math.Max(Service.HeartbeatIntervalSeconds * 3, Service.WatchdogStaleSeconds);
        if (string.IsNullOrWhiteSpace(Service.ServiceName)) Service.ServiceName = "BruceEDR";

        if (string.IsNullOrWhiteSpace(Telemetry.Format)) Telemetry.Format = "native";
        if (string.IsNullOrWhiteSpace(Response.QuarantineVaultPath)) Response.QuarantineVaultPath = "quarantine";

        foreach (var w in Watchlist.Entries)
        {
            if (w is null) continue;
            // A Score entry is only meaningful with points; clamp so a hand-edited config
            // cannot make one worth more than the quarantine threshold by accident.
            w.Score = Math.Clamp(w.Score, 0, 100);
        }

        Api.Control.Port = Math.Clamp(Api.Control.Port, 1024, 65535);
        Api.Studio.MaxRequestsPerSecond = Math.Clamp(Api.Studio.MaxRequestsPerSecond, 0.1, 100.0);
        Api.Studio.MaxResponseBytes = Math.Clamp(Api.Studio.MaxResponseBytes, 4096L, 256L * 1024 * 1024);
    }
}

public sealed class DetectionConfig
{
    public int WarnThreshold { get; set; } = 40;
    public int QuarantineThreshold { get; set; } = 70;
    public int CorrelationWindowSeconds { get; set; } = 30;
    public bool AutoKill { get; set; } = false;
    public int TrustDiscount { get; set; } = 30;
    public string MemoryScanEngine { get; set; } = "builtin";   // "builtin" | "yara"
    public string YaraRulesPath { get; set; } = "rules";
    public bool KernelBlocking { get; set; } = false;           // enforce via minifilter if installed

    // --- v2 -----------------------------------------------------------------

    /// <summary>Directory of declarative JSON detection rules, hot-reloaded with the config.</summary>
    public string RulesPath { get; set; } = "rules/detection";
    /// <summary>Load the JSON rule packs at all. Off means builtin C# rules only.</summary>
    public bool EnableRuleEngine { get; set; } = true;
    /// <summary>
    /// Points shed per decay interval from a process that has gone quiet. Without decay a
    /// long-lived process accumulates score forever and eventually trips on noise alone.
    /// 0 disables decay (the pre-v2 behaviour).
    /// </summary>
    public int ScoreDecayPoints { get; set; } = 5;
    public int ScoreDecayIntervalSeconds { get; set; } = 300;
    /// <summary>Contained processes never decay; only un-contained ones cool off.</summary>
    public bool EnableScoreDecay { get; set; } = true;

    public bool EnableBeaconDetection { get; set; } = true;

    /// <summary>
    /// Statically analyse each process image (PE sections, entropy, imphash, packer
    /// indicators, suspicious imports). Runs off the detection thread and is cached per
    /// path, but it does read the binary, so it can be turned off on IO-constrained hosts.
    /// </summary>
    public bool EnablePeAnalysis { get; set; } = true;

    /// <summary>
    /// Score resolved DNS names for DGA, dynamic-DNS and tunnelling shape. Turn off if the
    /// heuristic is noisy against your estate's CDN or cloud hostnames -- it scores, it does
    /// not convict, but on some fleets it scores often.
    /// </summary>
    public bool EnableDomainAnalysis { get; set; } = true;
    public int BeaconMinConnections { get; set; } = 6;
    /// <summary>Score added once when a process is judged to be beaconing.</summary>
    public int BeaconScore { get; set; } = 35;

    /// <summary>Score added for a domain that scores as likely DGA.</summary>
    public int DgaScore { get; set; } = 25;

    /// <summary>Enable the registry / DNS / AMSI / process-access ETW monitors.</summary>
    public bool EnableExtendedMonitors { get; set; } = true;

    /// <summary>Hard cap on tracked process profiles, so telemetry floods cannot exhaust memory.</summary>
    public int MaxTrackedProcesses { get; set; } = 16384;
}

/// <summary>
/// Operator-defined "if you see this, act" list. This is the custom-detection surface:
/// the JSON rule packs describe behaviour, this names specific binaries an operator has
/// decided do not belong on their estate (red-team tooling, unapproved remote access,
/// a hash pulled from an incident report).
/// </summary>
public sealed class WatchlistConfig
{
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Emit an alert for a hit even when the action is only <c>score</c> and the process
    /// never crosses a threshold. Operators generally want to know their named binary ran,
    /// regardless of whether it earned enough points to be contained.
    /// </summary>
    public bool AlertOnEveryHit { get; set; } = true;

    public WatchlistEntryConfig[] Entries { get; set; } = Array.Empty<WatchlistEntryConfig>();
}

/// <summary>One watchlist rule as it appears in bruce.config.json.</summary>
public sealed class WatchlistEntryConfig
{
    /// <summary><c>name</c> | <c>path</c> | <c>hash</c> | <c>cmdline</c>.</summary>
    public string Match { get; set; } = "name";
    /// <summary>The process name, path fragment, SHA-256 or command-line fragment to look for.</summary>
    public string Value { get; set; } = "";
    /// <summary><c>quarantine</c> | <c>warn</c> | <c>score</c>.</summary>
    public string Action { get; set; } = "quarantine";
    /// <summary>Points added when <see cref="Action"/> is <c>score</c>.</summary>
    public int Score { get; set; } = 50;
    /// <summary>Why this is on the list. Carried into the alert and the audit log.</summary>
    public string Note { get; set; } = "";
    /// <summary>Optional ATT&amp;CK technique ids to attribute to a hit.</summary>
    public string[] Techniques { get; set; } = Array.Empty<string>();
    public bool Enabled { get; set; } = true;
}

public sealed class IntelConfig
{
    /// <summary>
    /// Directory of operator-supplied indicator feeds (*.txt / *.ioc / *.csv). Kept
    /// separate from the Intel/ source folder so an operator dropping files here can
    /// never collide with shipped code.
    /// </summary>
    public string FeedPath { get; set; } = "intel/feeds";
    public bool Enabled { get; set; } = true;
    /// <summary>Score added when an image hash, domain or address matches a loaded feed.</summary>
    public int HitScore { get; set; } = 60;
}

public sealed class ResponseConfig
{
    /// <summary>Encrypt quarantined files at rest so a payload cannot simply be re-run.</summary>
    public bool UseEncryptedVault { get; set; } = true;
    public string QuarantineVaultPath { get; set; } = "quarantine";
    /// <summary>Path to a JSON playbook. Empty uses the built-in default playbook.</summary>
    public string PlaybookPath { get; set; } = "";
    /// <summary>Where CollectTriage playbook actions write their forensic zip.</summary>
    public string TriageOutputPath { get; set; } = "triage";
    /// <summary>Addresses that stay reachable when the host is isolated (management/RDP/AD).</summary>
    public string[] IsolationAllowlist { get; set; } = Array.Empty<string>();
}

/// <summary>Configuration for both halves of the API feature: the control plane and API Studio.</summary>
public sealed class ApiConfig
{
    public ControlApiConfig Control { get; set; } = new();
    public ApiStudioConfig Studio { get; set; } = new();
    /// <summary>Build the observed endpoint inventory from network + DNS telemetry.</summary>
    public bool EnableSurfaceInventory { get; set; } = true;
}

public sealed class ControlApiConfig
{
    /// <summary>Off by default. The control plane is an attack surface; opt in deliberately.</summary>
    public bool Enabled { get; set; } = false;
    /// <summary>Loopback only. A non-loopback address is refused at startup.</summary>
    public string Address { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 8787;
    /// <summary>Bearer token. Empty means "generate a random one and log it once at startup".</summary>
    public string Token { get; set; } = "";
    /// <summary>Allow resume/suspend/kill over HTTP. Separate switch: read-only is the safe default.</summary>
    public bool AllowActions { get; set; } = false;
}

public sealed class ApiStudioConfig
{
    /// <summary>Hosts API Studio may send to. Nothing is reachable until this is populated.</summary>
    public string[] AllowedHosts { get; set; } = { "localhost", "127.0.0.1" };
    /// <summary>Permit POST/PUT/PATCH/DELETE. Read-only probing is the default.</summary>
    public bool AllowMutatingMethods { get; set; } = false;
    public bool AllowInsecureHttp { get; set; } = false;
    public double MaxRequestsPerSecond { get; set; } = 5.0;
    public long MaxResponseBytes { get; set; } = 8L * 1024 * 1024;
}

public sealed class AllowlistConfig
{
    public string[] Publishers { get; set; } = { "Microsoft Windows", "Microsoft Corporation" };
    public string[] Thumbprints { get; set; } = Array.Empty<string>();
    public bool AllowSubjectMatch { get; set; } = true;
    public bool RequireValidChain { get; set; } = true;
    public bool CheckRevocation { get; set; } = false;
}

public sealed class TelemetryConfig
{
    public string JsonlPath { get; set; } = "incidents.jsonl";
    public string AuditPath { get; set; } = "audit.log";
    public SyslogConfig Syslog { get; set; } = new();
    public WebhookConfig Webhook { get; set; } = new();

    /// <summary>
    /// Wire format for the JSONL/syslog/webhook sinks: <c>native</c>, <c>ecs</c>
    /// (Elastic Common Schema 8.x), <c>ocsf</c> (OCSF 1.1 Detection Finding) or <c>cef</c>.
    /// The audit chain always uses the native shape so its hashes stay comparable.
    /// </summary>
    public string Format { get; set; } = "native";

    /// <summary>Serve Prometheus metrics from the control API's /metrics route.</summary>
    public bool EnableMetrics { get; set; } = true;
}

public sealed class SyslogConfig
{
    public bool Enabled { get; set; } = false;
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 514;
    public string Protocol { get; set; } = "udp";   // "udp" | "tcp"
    public string AppName { get; set; } = "BruceEDR";
}

public sealed class WebhookConfig
{
    public bool Enabled { get; set; } = false;
    public string Url { get; set; } = "";
}

public sealed class ServiceConfig
{
    public string ServiceName { get; set; } = "BruceEDR";
    public string HeartbeatPath { get; set; } =
        Path.Combine(Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData",
                     "BruceEDR", "heartbeat");
    public int HeartbeatIntervalSeconds { get; set; } = 5;
    public int WatchdogStaleSeconds { get; set; } = 30;
}

public static class ConfigLoader
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true
    };

    public static BruceConfig Load(string path, Action<string>? warn = null)
    {
        try
        {
            if (!File.Exists(path))
            {
                warn?.Invoke($"config '{path}' not found; using defaults");
                var def = new BruceConfig();
                def.ClampAndValidate();
                return def;
            }
            var json = File.ReadAllText(path);
            var cfg = JsonSerializer.Deserialize<BruceConfig>(json, Options) ?? new BruceConfig();
            cfg.ClampAndValidate();
            return cfg;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"config load failed ({ex.Message}); using defaults");
            var def = new BruceConfig();
            def.ClampAndValidate();
            return def;
        }
    }

    /// <summary>
    /// Strict loader for hot-reload: returns false (and leaves <paramref name="config"/>
    /// as a throwaway default) when the file is missing, unparsable, or partially written,
    /// so the caller can KEEP its current tuned posture/allowlist instead of silently
    /// reverting to defaults. Use Load (not this) for first-time startup.
    /// </summary>
    public static bool TryLoad(string path, out BruceConfig config, Action<string>? warn = null)
    {
        try
        {
            if (!File.Exists(path))
            {
                warn?.Invoke($"config '{path}' missing on reload; keeping current config");
                config = new BruceConfig();
                return false;
            }
            var json = File.ReadAllText(path);
            var cfg = JsonSerializer.Deserialize<BruceConfig>(json, Options);
            if (cfg is null)
            {
                warn?.Invoke("config reload parsed to null; keeping current config");
                config = new BruceConfig();
                return false;
            }
            cfg.ClampAndValidate();
            config = cfg;
            return true;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"config reload parse failed ({ex.Message}); keeping current config");
            config = new BruceConfig();
            return false;
        }
    }

    public static void WriteTemplate(string path)
    {
        try { File.WriteAllText(path, JsonSerializer.Serialize(new BruceConfig(), Options)); }
        catch { /* best effort */ }
    }

    /// <summary>Persist a config to disk (used by the GUI settings editor). Throws on failure.</summary>
    public static void Save(BruceConfig config, string path)
    {
        config.ClampAndValidate();
        File.WriteAllText(path, JsonSerializer.Serialize(config, Options));
    }

    /// <summary>Debounced hot-reload watcher. Returns the watcher so the caller can dispose it.</summary>
    public static FileSystemWatcher? Watch(string path, Action<BruceConfig> onReload, Action<string>? warn = null)
    {
        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            var file = Path.GetFileName(path);
            if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(file)) return null;

            var w = new FileSystemWatcher(dir, file)
            {
                // FileName is required for Created/Renamed to ever fire -- editors that
                // save via write-temp-then-atomic-rename (VS Code, many others) only
                // surface as a Renamed/Created of the target, not a LastWrite/Size change.
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            DateTime last = DateTime.MinValue;
            void Handler(object _, FileSystemEventArgs __)
            {
                var now = DateTime.UtcNow;
                if (now - last < TimeSpan.FromMilliseconds(500)) return;   // debounce
                last = now;
                System.Threading.Thread.Sleep(150);                       // let the writer finish
                // Only push a successfully-parsed config; a malformed/partial edit keeps
                // the current posture instead of silently reverting to defaults.
                try { if (TryLoad(path, out var cfg, warn)) onReload(cfg); }
                catch (Exception ex) { warn?.Invoke($"config reload failed: {ex.Message}"); }
            }
            w.Changed += Handler;
            w.Created += Handler;
            w.Renamed += Handler;
            return w;
        }
        catch (Exception ex)
        {
            warn?.Invoke($"config watch failed: {ex.Message}");
            return null;
        }
    }
}
