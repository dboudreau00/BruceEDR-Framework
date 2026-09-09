using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using BruceEDR.Analysis;
using BruceEDR.Api;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Driver;
using BruceEDR.Intel;
using BruceEDR.Memory;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;

namespace BruceEDR.Hosting;

public sealed record WorkerOptions(string ConfigPath);

/// <summary>
/// Composition root: builds every component from a BruceConfig and wires hot
/// reload. Used by both the interactive console mode and the Windows Service.
/// </summary>
public sealed class Composition : IDisposable
{
    public BruceHost Host { get; }
    public Logger Log { get; }
    public BruceConfig Config { get; private set; }

    /// <summary>Declarative rules currently loaded. Replaced wholesale on hot reload.</summary>
    public RuleSet Rules { get; private set; } = new(Array.Empty<DetectionRule>(), Array.Empty<RuleValidationError>());
    /// <summary>Indicator feeds currently loaded.</summary>
    public IocFeed Intel { get; private set; } = new();
    /// <summary>Operator watchlist currently armed. Replaced wholesale on hot reload.</summary>
    public Watchlist Watchlist { get; private set; } = Watchlist.Empty;

    /// <summary>The tamper-evident audit sink, when one is running (null if it failed to open).</summary>
    public AuditLogSink? Audit { get; private set; }
    /// <summary>Observed network/API surface, shared with the engine.</summary>
    public ApiSurfaceInventory Surface { get; }
    /// <summary>Encrypted quarantine store, or null when the operator disabled it.</summary>
    public QuarantineVault? Vault { get; }
    /// <summary>Most recent events, for the GUI feed and the control API.</summary>
    public RingBufferSink Events { get; }
    public NetworkIsolation Isolation { get; }
    /// <summary>Safety policy governing every outbound API Studio request.</summary>
    public ApiSafetyPolicy ApiPolicy { get; private set; }

    private readonly string _configPath;
    private readonly AuthenticodeVerifier _verifier;
    private readonly CompositeSink _sink;
    private readonly IMemoryScanner _scanner;
    private readonly RuleEngineHolder _ruleHolder;
    private readonly IocFeedHolder _intelHolder;
    private readonly WatchlistHolder _watchHolder;
    private FileSystemWatcher? _configWatcher;
    private MinifilterClient? _minifilter;
    private ControlServer? _control;

    private Composition(string configPath, BruceConfig config, Logger log,
        AuthenticodeVerifier verifier, CompositeSink sink, IMemoryScanner scanner, BruceHost host,
        ApiSurfaceInventory surface, QuarantineVault? vault, RingBufferSink events,
        NetworkIsolation isolation, RuleEngineHolder ruleHolder, IocFeedHolder intelHolder,
        WatchlistHolder watchHolder, ApiSafetyPolicy apiPolicy)
    {
        _configPath = configPath;
        Config = config;
        Log = log;
        _verifier = verifier;
        _sink = sink;
        _scanner = scanner;
        Host = host;
        Surface = surface;
        Vault = vault;
        Events = events;
        Isolation = isolation;
        _ruleHolder = ruleHolder;
        _intelHolder = intelHolder;
        _watchHolder = watchHolder;
        ApiPolicy = apiPolicy;
    }

    public static Composition Build(string configPath, IEventSink? extraSink = null)
    {
        var log = new Logger();
        var cfg = ConfigLoader.Load(configPath, m => log.Info("config: " + m));
        var clock = SystemClock.Instance;

        var events = new RingBufferSink(512);
        var sink = BuildSink(cfg.Telemetry, log, extraSink, events, out var auditSink);
        log.SetSink(sink);

        var verifier = new AuthenticodeVerifier(cfg.Allowlist);
        var scanner = BuildScanner(cfg.Detection, log);

        // --- optional analytics -------------------------------------------------
        var ruleHolder = new RuleEngineHolder();
        var ruleSet = LoadRules(cfg.Detection, log);
        ruleHolder.BudgetExhaustedAlert = msg => log.Info("WARNING: " + msg);
        ruleHolder.Set(ruleSet);

        var intelHolder = new IocFeedHolder();
        var feed = LoadIntel(cfg.Intel, log);
        intelHolder.Set(feed);

        var watchHolder = new WatchlistHolder();
        var watchlist = LoadWatchlist(cfg.Watchlist, log);
        watchHolder.Set(watchlist);

        var tree = new ProcessTree(clock);
        var beacons = cfg.Detection.EnableBeaconDetection
            ? new BeaconAnalyzer(clock, cfg.Detection.BeaconMinConnections)
            : null;
        var surface = new ApiSurfaceInventory(clock);
        var hashes = new ImageHashCache();
        var images = new ImageAnalysisCache();

        var options = new EngineOptions
        {
            WarnThreshold = cfg.Detection.WarnThreshold,
            QuarantineThreshold = cfg.Detection.QuarantineThreshold,
            CorrelationWindow = TimeSpan.FromSeconds(cfg.Detection.CorrelationWindowSeconds),
            AutoKillOnQuarantine = cfg.Detection.AutoKill,
            TrustDiscount = cfg.Detection.TrustDiscount,
            EnableScoreDecay = cfg.Detection.EnableScoreDecay,
            ScoreDecayPoints = cfg.Detection.ScoreDecayPoints,
            ScoreDecayInterval = TimeSpan.FromSeconds(cfg.Detection.ScoreDecayIntervalSeconds),
            BeaconScore = cfg.Detection.BeaconScore,
            DgaScore = cfg.Detection.DgaScore,
            EnableDomainAnalysis = cfg.Detection.EnableDomainAnalysis,
            IntelHitScore = cfg.Intel.HitScore,
            MaxTrackedProcesses = cfg.Detection.MaxTrackedProcesses
        };

        var deps = new EngineDependencies
        {
            Clock = clock,
            Tree = tree,
            Beacons = beacons,
            // Providers, NOT direct references: a reload builds a NEW RuleEngine / IocFeed /
            // Watchlist, so an engine that captured the object at startup would keep using
            // the one it was born with and the reload would be a silent no-op.
            RulesProvider = () => ruleHolder.Engine,
            // LoadIntel already returns an empty feed when intel.enabled is false, so the
            // holder alone carries the on/off state across a reload.
            IntelProvider = () => intelHolder.Feed,
            WatchlistProvider = () => watchHolder.List,
            Surface = cfg.Api.EnableSurfaceInventory ? surface : null,
            // Wired unconditionally. This hasher serves BOTH indicator feeds and watchlist
            // hash entries; gating it on intel.enabled made every watchlist SHA-256 entry
            // silently inert while the log still reported it as armed. It is lazy and cached,
            // and MatchIndicators returns early on an empty feed, so an always-on hasher costs
            // nothing when intel is off.
            ImageHash = hashes.Sha256,
            AnalyzeImage = cfg.Detection.EnablePeAnalysis ? images.Analyze : null
        };

        // --- response ------------------------------------------------------------
        QuarantineVault? vault = null;
        if (cfg.Response.UseEncryptedVault)
        {
            try { vault = new QuarantineVault(ResolvePath(cfg.Response.QuarantineVaultPath), clock); }
            catch (Exception ex) { log.Error("quarantine vault unavailable; falling back to plain moves", ex); }
        }

        var isolation = new NetworkIsolation(log, clock);
        var response = new ResponseManager(log, verifier, vault);
        var engine = new DetectionEngine(options, response.IsTrusted, deps);
        var playbook = LoadPlaybook(cfg.Response, log);

        var hostOptions = new BruceHostOptions
        {
            AutoKill = cfg.Detection.AutoKill,
            EnableExtendedMonitors = cfg.Detection.EnableExtendedMonitors,
            Tree = tree,
            Surface = cfg.Api.EnableSurfaceInventory ? surface : null,
            Playbook = playbook,
            Metrics = new BruceMetrics(clock)
        };
        var host = new BruceHost(engine, response, scanner, log, hostOptions);

        var apiPolicy = BuildApiPolicy(cfg.Api.Studio);

        var comp = new Composition(configPath, cfg, log, verifier, sink, scanner, host,
            surface, vault, events, isolation, ruleHolder, intelHolder, watchHolder, apiPolicy)
        {
            Rules = ruleSet,
            Intel = feed,
            Audit = auditSink,
            Watchlist = watchlist
        };

        host.ExtendedAction = comp.RunExtendedAction;
        host.ImageAnalyzer = deps.AnalyzeImage;
        comp._configWatcher = ConfigLoader.Watch(configPath, comp.Apply, m => log.Info("config: " + m));
        comp.ConnectMinifilter(cfg);
        comp.StartControlServer(cfg);

        log.Info($"detection rules: {ruleSet.Rules.Count} loaded" +
                 (ruleSet.Errors.Count == 0 ? "" : $", {ruleSet.Errors.Count} rejected"));
        if (feed.Count > 0) log.Info($"indicator feeds: {feed.Count} indicator(s) loaded");
        return comp;
    }

    // ------------------------------------------------------------------- loading

    private static RuleSet LoadRules(DetectionConfig d, Logger log)
    {
        if (!d.EnableRuleEngine) return new RuleSet(Array.Empty<DetectionRule>(), Array.Empty<RuleValidationError>());
        var dir = ResolveContentDir(d.RulesPath, "rules", log);
        if (dir is null)
        {
            log.Info("rules: running with builtin detections only");
            return new RuleSet(Array.Empty<DetectionRule>(), Array.Empty<RuleValidationError>());
        }
        var set = RuleEngine.LoadDirectory(dir, m => log.Info("rules: " + m));
        foreach (var e in set.Errors.Where(e => e.IsBlocking).Take(20))
            log.Info($"rules: rejected [{e.RuleId}] {e.Message}");
        return set;
    }

    /// <summary>
    /// Compiles the operator watchlist. Rejected entries are logged individually -- an
    /// operator who mistypes one rule must be told which one, not silently given a shorter
    /// list than they wrote.
    /// </summary>
    private static Watchlist LoadWatchlist(WatchlistConfig w, Logger log)
    {
        if (!w.Enabled) return Watchlist.Empty;
        var list = Watchlist.Compile(w.Entries, m => log.Info("watchlist: " + m), w.AlertOnEveryHit);
        if (list.Count > 0)
        {
            int contain = list.Entries.Count(e => e.Action == WatchAction.Quarantine);
            log.Info($"watchlist: {list.Count} entr{(list.Count == 1 ? "y" : "ies")} armed" +
                     (contain > 0 ? $", {contain} set to contain on sight" : ""));
        }
        return list;
    }

    private static IocFeed LoadIntel(IntelConfig i, Logger log)
    {
        if (!i.Enabled) return new IocFeed();
        var dir = ResolveContentDir(i.FeedPath, "intel", log);
        if (dir is null) return new IocFeed();
        return IocFeed.LoadDirectory(dir, m => log.Info("intel: " + m));
    }

    /// <summary>
    /// Resolves a content directory (rule packs, indicator feeds) for the RUNNING agent, and
    /// logs which directory was chosen so an operator can see what is actually armed.
    ///
    /// Unlike <see cref="SelfTest.Resolve"/> this never ascends to parent directories. From
    /// an installed location such as C:\Program Files\BruceEDR\ an upward walk reaches
    /// the drive root and other user-writable places, so a standard user could plant a
    /// rules\detection folder that the SYSTEM-level agent would then load and enforce as
    /// detection policy. SelfTest keeps the walk deliberately: it is an explicit, offline,
    /// unprivileged developer tool, not the agent. Dropping it here costs little, because the
    /// project file copies rules/, Replay/scenarios/ and intel/feeds/ into the output
    /// directory; a layout that genuinely lives elsewhere needs an absolute path in the
    /// config, which is the honest way to say so.
    ///
    /// An absolute configured path is honoured as written: the config file is trusted input
    /// that only an administrator can edit. A relative path that escapes the agent directory
    /// via ".." is refused, because that is the same privilege boundary in disguise.
    /// </summary>
    private static string? ResolveContentDir(string configured, string what, Logger log)
    {
        if (string.IsNullOrWhiteSpace(configured)) return null;

        string dir;
        if (Path.IsPathRooted(configured))
        {
            dir = Path.GetFullPath(configured);
        }
        else
        {
            var baseDir = Path.GetFullPath(AppContext.BaseDirectory);
            dir = Path.GetFullPath(Path.Combine(baseDir, configured));
            if (!IsUnder(baseDir, dir))
            {
                log.Info($"{what}: '{configured}' resolves outside the agent directory; refused");
                return null;
            }
        }

        if (!Directory.Exists(dir))
        {
            log.Info($"{what}: '{dir}' not found");
            return null;
        }
        log.Info($"{what}: loading from '{dir}'");
        return dir;
    }

    /// <summary>True when <paramref name="candidate"/> is the base directory or sits below it.</summary>
    private static bool IsUnder(string baseDir, string candidate)
    {
        var b = baseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var c = candidate.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (string.Equals(b, c, StringComparison.OrdinalIgnoreCase)) return true;
        return c.StartsWith(b + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static Playbook LoadPlaybook(ResponseConfig r, Logger log)
    {
        if (string.IsNullOrWhiteSpace(r.PlaybookPath)) return Playbook.Default();
        try
        {
            var path = ResolvePath(r.PlaybookPath);
            if (!File.Exists(path))
            {
                log.Info($"playbook '{path}' not found; using the default playbook");
                return Playbook.Default();
            }
            var pb = Playbook.FromJson(File.ReadAllText(path), out var errors);
            foreach (var e in errors) log.Info("playbook: " + e);
            return pb;
        }
        catch (Exception ex)
        {
            log.Error("playbook load failed; using the default playbook", ex);
            return Playbook.Default();
        }
    }

    private static ApiSafetyPolicy BuildApiPolicy(ApiStudioConfig s) => new()
    {
        AllowedHosts = s.AllowedHosts ?? Array.Empty<string>(),
        AllowMutatingMethods = s.AllowMutatingMethods,
        AllowInsecureHttp = s.AllowInsecureHttp,
        MaxRequestsPerSecond = s.MaxRequestsPerSecond,
        MaxResponseBytes = s.MaxResponseBytes,
        FileBodyRoot = string.IsNullOrWhiteSpace(s.FileBodyRoot)
            ? ""
            : (Path.IsPathRooted(s.FileBodyRoot) ? s.FileBodyRoot : Path.Combine(AppContext.BaseDirectory, s.FileBodyRoot))
    };

    /// <summary>Resolves a config-relative path against the executable directory.</summary>
    internal static string ResolvePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return AppContext.BaseDirectory;
        return Path.IsPathRooted(path) ? path : Path.Combine(AppContext.BaseDirectory, path);
    }

    private static string BracketIfIpv6(string address)
    {
        string a = (address ?? "").Trim();
        return a.Contains(':') && !a.StartsWith('[') ? "[" + a + "]" : a;
    }

    /// <summary>
    /// The control plane reloads live: enabled/token/allowActions/address/port. An
    /// incident responder turning off "kill a process over HTTP" must not have to wait
    /// for a service restart for it to take effect.
    /// </summary>
    private void RestartControlServer(BruceConfig next)
    {
        try { _control?.Dispose(); } catch { }
        _control = null;
        StartControlServer(next);
        if (!next.Api.Control.Enabled) Log.Info("control server stopped (api.control.enabled is off)");
    }

    private static bool ControlChanged(ControlApiConfig a, ControlApiConfig b)
        => a.Enabled != b.Enabled || a.AllowActions != b.AllowActions || a.Port != b.Port ||
           !string.Equals(a.Address, b.Address, StringComparison.OrdinalIgnoreCase) ||
           !string.Equals(a.Token, b.Token, StringComparison.Ordinal);

    private void StartControlServer(BruceConfig cfg)
    {
        var c = cfg.Api.Control;
        if (!c.Enabled) return;
        try
        {
            var backend = new ControlBackend(this);
            var server = new ControlServer(
                new ControlServerOptions
                {
                    // An IPv6 literal must be bracketed in a listener prefix; "::1" written
                    // bare produced a prefix the parser rightly refused, and the operator got
                    // "enabled but not listening".
                    Prefix = $"http://{BracketIfIpv6(c.Address)}:{c.Port}/",
                    Token = c.Token,
                    Enabled = true,
                    AllowActions = c.AllowActions
                },
                backend, Log);
            if (server.Start()) _control = server;
            else server.Dispose();
        }
        catch (Exception ex) { Log.Error("control server", ex); }
    }

    // Best-effort kernel enforcement. If the BruceFilter driver isn't installed the
    // connect fails quietly and user-mode detection continues on its own. The client is
    // retained for the process lifetime so ApplyKernelBlocking can re-send the block
    // toggle on a config reload; the sensitive-path list below is sent only here.
    private void ConnectMinifilter(BruceConfig cfg)
    {
        try
        {
            var client = new MinifilterClient(Log);
            if (!client.TryConnect()) { client.Dispose(); return; }

            client.ClearPolicy();
            foreach (var fragment in IocDatabase.KernelBlockPrefixes)
                client.AddSensitivePath(fragment);
            client.SetBlocking(cfg.Detection.KernelBlocking);
            _minifilter = client;
            // "monitor mode" overstated the non-blocking case: the client only pushes policy
            // and never reads from the port, so with blocking off the driver reports nothing
            // to user mode at all -- it is not monitoring anything we can see.
            Log.Info(cfg.Detection.KernelBlocking
                ? "kernel enforcement ENABLED (driver denies sensitive-path opens; denials are " +
                  "logged by the driver only, not surfaced here)"
                : "minifilter connected, enforcement OFF (policy pushed; no kernel telemetry consumed)");
        }
        catch (Exception ex) { Log.Error("minifilter setup", ex); }
    }

    private static CompositeSink BuildSink(TelemetryConfig t, Logger log, IEventSink? extra,
        RingBufferSink events, out AuditLogSink? audit)
    {
        audit = null;
        // The wire format applies to the file/syslog/webhook sinks so BruceEDR can be
        // a drop-in producer for an existing SIEM. The audit chain deliberately keeps the
        // native shape: its HMACs are computed over that canonical form, and switching the
        // schema would silently invalidate every previously written chain.
        var formatter = EventFormatters.Resolve(t.Format);
        bool native = string.Equals(formatter.Name, "native", StringComparison.OrdinalIgnoreCase);

        // Both paths ship relative ("incidents.jsonl", "audit.log"). The console runs from
        // the install directory, but the Windows Service starts with a working directory of
        // C:\Windows\System32 -- so an unresolved relative path would drop evidence there and
        // start a SECOND audit chain unrelated to the console's. Resolve against the binary's
        // own directory, the way the vault, triage and heartbeat paths already are.
        var jsonlPath = ResolvePath(t.JsonlPath);
        var auditPath = ResolvePath(t.AuditPath);

        var sinks = new List<IEventSink>
        {
            native ? new JsonlSink(jsonlPath) : new FormattingSink(jsonlPath, formatter)
        };

        // Open the audit log defensively: if its file is genuinely unreadable (locked,
        // permissions), disable the audit sink LOUDLY and keep the agent running rather
        // than crashing startup or silently resetting the tamper-evident chain.
        try
        {
            // The integrity warning goes through the logger so it reaches every sink and
            // the console, not just stderr.
            var a = new AuditLogSink(auditPath, m => log.Info("AUDIT WARNING: " + m));
            sinks.Add(a);
            audit = a;
        }
        catch (Exception ex) { log.Error("audit log unavailable; audit sink disabled", ex); }

        if (t.Syslog.Enabled)
            sinks.Add(new SyslogSink(t.Syslog.Host, t.Syslog.Port, t.Syslog.Protocol, t.Syslog.AppName,
                native ? null : formatter.Format));
        if (t.Webhook.Enabled && !string.IsNullOrWhiteSpace(t.Webhook.Url))
            sinks.Add(new WebhookSink(t.Webhook.Url, native ? null : formatter.Format,
                string.Equals(formatter.Name, "cef", StringComparison.OrdinalIgnoreCase)
                    ? "text/plain" : "application/json"));

        sinks.Add(events);
        if (extra is not null)
            sinks.Add(extra);

        if (!native) log.Info($"telemetry format: {formatter.Name}");
        return new CompositeSink(sinks);
    }

    private static IMemoryScanner BuildScanner(DetectionConfig d, Logger log)
    {
        if (string.Equals(d.MemoryScanEngine, "yara", StringComparison.OrdinalIgnoreCase))
        {
            var yara = new YaraMemoryScanner(d.YaraRulesPath, log.Info);
            if (yara.Available) return yara;
            yara.Dispose();
            log.Info("yara unavailable; using builtin scanner");
        }
        return new MemoryScanner(IocDatabase.MemoryStringIocs);
    }

    /// <summary>Manual reload trigger (console 'reload'). Keeps the current config on a
    /// parse/read failure instead of failing open to defaults.</summary>
    public void ReloadConfig()
    {
        if (ConfigLoader.TryLoad(_configPath, out var next, m => Log.Info("config: " + m)))
            Apply(next);
        else
            Log.Info("config: reload skipped; keeping current config");
    }

    /// <summary>Apply the hot-reloadable subset (posture + allowlist + rules + intel).</summary>
    private void Apply(BruceConfig next)
    {
        try
        {
            _verifier.UpdateAllowlist(next.Allowlist);
            Host.ApplyDetectionConfig(
                next.Detection.WarnThreshold, next.Detection.QuarantineThreshold,
                next.Detection.CorrelationWindowSeconds, next.Detection.TrustDiscount,
                next.Detection.AutoKill);

            // Rules and indicator feeds reload live. The holders are what the engine holds
            // a reference to, so swapping their contents takes effect on the next signal
            // without the engine ever seeing a half-built rule set.
            // The swap is unconditional: setting enableRuleEngine:false must actually DISARM
            // the loaded packs. Keeping the previous set when the new one is empty would make
            // "turn the rule engine off" a silent no-op with the old rules still firing.
            var rules = LoadRules(next.Detection, Log);
            _ruleHolder.BudgetExhaustedAlert = msg => Log.Info("WARNING: " + msg);
            _ruleHolder.Set(rules);
            Rules = rules;
            Log.Info(next.Detection.EnableRuleEngine
                ? $"rules reloaded: {rules.Rules.Count} active"
                : "rules disarmed: enableRuleEngine is off, builtin detections only");

            var feed = LoadIntel(next.Intel, Log);
            _intelHolder.Set(feed);
            Intel = feed;

            // Same unconditional swap as the rule packs: disabling the watchlist, or
            // deleting an entry, has to actually disarm it.
            var watch = LoadWatchlist(next.Watchlist, Log);
            _watchHolder.Set(watch);
            Watchlist = watch;
            if (watch.Count == 0)
                Log.Info(next.Watchlist.Enabled ? "watchlist: empty" : "watchlist: disabled");

            ApiPolicy = BuildApiPolicy(next.Api.Studio);

            if (ControlChanged(Config.Api.Control, next.Api.Control))
                RestartControlServer(next);

            // The block toggle is the one minifilter setting that reloads live: the client is
            // held in _minifilter for the process lifetime, so the new value is a single
            // message to the driver. The sensitive-path policy around it is still startup-only.
            if (next.Detection.KernelBlocking != Config.Detection.KernelBlocking)
                ApplyKernelBlocking(next.Detection.KernelBlocking);

            // Everything else is consumed once, while the composition is built: sinks, the
            // control server, the scanner, the vault, the playbook, monitor selection and the
            // immutable half of EngineOptions. Warning about only a few of those taught
            // operators to trust a reload that had quietly ignored their edit, so name every
            // changed restart-only setting in one line.
            var pending = RestartRequiredChanges(Config, next);
            if (pending.Count > 0)
                Log.Info("note: change takes effect after restart: " + string.Join(", ", pending));

            Config = next;
        }
        catch (Exception ex) { Log.Error("apply config", ex); }
    }

    /// <summary>
    /// Pushes a changed detection.kernelBlocking value to the already-connected minifilter.
    /// Only the toggle travels: the sensitive-path list was sent once at connect time and is
    /// not re-sent here, so a reload cannot change WHICH paths the driver guards.
    /// If the driver was never connected the log says the setting was not applied, rather
    /// than implying kernel enforcement changed when no driver exists to enforce it.
    /// WARNING, unchanged by this: kernelBlocking:true makes the skeleton driver deny EVERY
    /// open of a sensitive path, from any process, trusted or not -- it is not
    /// process-selective. Enabling it on a reload has that effect immediately.
    /// </summary>
    private void ApplyKernelBlocking(bool enabled)
    {
        var mf = _minifilter;
        if (mf is null || !mf.Connected)
        {
            Log.Info($"detection.kernelBlocking={(enabled ? "true" : "false")} not applied: minifilter not connected");
            return;
        }
        try
        {
            mf.SetBlocking(enabled);
            Log.Info(enabled
                ? "kernel enforcement ENABLED live: the driver now denies ALL opens of sensitive paths, from any process"
                : "kernel enforcement switched live to monitor mode");
        }
        catch (Exception ex) { Log.Error("kernel blocking reload", ex); }
    }

    /// <summary>
    /// Names every setting that changed between two configs but is only read while the
    /// composition is built, so <see cref="Apply"/> can say plainly what a reload did not do.
    /// The list is maintained by hand against <see cref="Build"/>; anything genuinely
    /// hot-reloaded (thresholds, autoKill, allowlist, rules, indicator feeds, API Studio
    /// safety policy, detection.kernelBlocking, telemetry.enableMetrics, the isolation
    /// allowlist and triage output path) is deliberately absent.
    /// </summary>
    private static List<string> RestartRequiredChanges(BruceConfig old, BruceConfig next)
    {
        var changed = new List<string>();

        void Text(string name, string? a, string? b)
        {
            if (!string.Equals(a ?? "", b ?? "", StringComparison.OrdinalIgnoreCase)) changed.Add(name);
        }
        void Flag(string name, bool a, bool b) { if (a != b) changed.Add(name); }
        void Number(string name, long a, long b) { if (a != b) changed.Add(name); }

        var od = old.Detection; var nd = next.Detection;
        Text("detection.memoryScanEngine", od.MemoryScanEngine, nd.MemoryScanEngine);
        Text("detection.yaraRulesPath", od.YaraRulesPath, nd.YaraRulesPath);
        // detection.kernelBlocking is deliberately NOT listed: Apply pushes it to the
        // connected minifilter, so it does take effect on reload.
        Flag("detection.enableExtendedMonitors", od.EnableExtendedMonitors, nd.EnableExtendedMonitors);
        Flag("detection.enableBeaconDetection", od.EnableBeaconDetection, nd.EnableBeaconDetection);
        Number("detection.beaconMinConnections", od.BeaconMinConnections, nd.BeaconMinConnections);
        Number("detection.beaconScore", od.BeaconScore, nd.BeaconScore);
        Number("detection.dgaScore", od.DgaScore, nd.DgaScore);
        Flag("detection.enableScoreDecay", od.EnableScoreDecay, nd.EnableScoreDecay);
        // Both are consumed once while EngineOptions/EngineDependencies are built, so a
        // reload cannot change them. Naming them here is the whole contract of this method:
        // an operator must never be left believing a reload applied an edit it ignored.
        Flag("detection.enablePeAnalysis", od.EnablePeAnalysis, nd.EnablePeAnalysis);
        Flag("detection.enableDomainAnalysis", od.EnableDomainAnalysis, nd.EnableDomainAnalysis);
        Number("detection.scoreDecayPoints", od.ScoreDecayPoints, nd.ScoreDecayPoints);
        Number("detection.scoreDecayIntervalSeconds", od.ScoreDecayIntervalSeconds, nd.ScoreDecayIntervalSeconds);
        Number("detection.maxTrackedProcesses", od.MaxTrackedProcesses, nd.MaxTrackedProcesses);

        var ot = old.Telemetry; var nt = next.Telemetry;
        Text("telemetry.format", ot.Format, nt.Format);
        Text("telemetry.jsonlPath", ot.JsonlPath, nt.JsonlPath);
        Text("telemetry.auditPath", ot.AuditPath, nt.AuditPath);
        Flag("telemetry.syslog.enabled", ot.Syslog.Enabled, nt.Syslog.Enabled);
        Text("telemetry.syslog.host", ot.Syslog.Host, nt.Syslog.Host);
        Number("telemetry.syslog.port", ot.Syslog.Port, nt.Syslog.Port);
        Text("telemetry.syslog.protocol", ot.Syslog.Protocol, nt.Syslog.Protocol);
        Text("telemetry.syslog.appName", ot.Syslog.AppName, nt.Syslog.AppName);
        Flag("telemetry.webhook.enabled", ot.Webhook.Enabled, nt.Webhook.Enabled);
        Text("telemetry.webhook.url", ot.Webhook.Url, nt.Webhook.Url);

        var oi = old.Intel; var ni = next.Intel;
        // Turning intel OFF does take effect (the reload installs an empty feed); turning it
        // back ON does not, because the engine was wired with a null indicator source.
        Text("intel.feedPath", oi.FeedPath, ni.FeedPath);
        Number("intel.hitScore", oi.HitScore, ni.HitScore);

        var orr = old.Response; var nr = next.Response;
        Flag("response.useEncryptedVault", orr.UseEncryptedVault, nr.UseEncryptedVault);
        Text("response.quarantineVaultPath", orr.QuarantineVaultPath, nr.QuarantineVaultPath);
        Text("response.playbookPath", orr.PlaybookPath, nr.PlaybookPath);

        var oc = old.Api.Control; var nc = next.Api.Control;
        Flag("api.enableSurfaceInventory", old.Api.EnableSurfaceInventory, next.Api.EnableSurfaceInventory);

        Text("service.heartbeatPath", old.Service.HeartbeatPath, next.Service.HeartbeatPath);
        Text("service.serviceName", old.Service.ServiceName, next.Service.ServiceName);
        Number("service.heartbeatIntervalSeconds",
            old.Service.HeartbeatIntervalSeconds, next.Service.HeartbeatIntervalSeconds);

        return changed;
    }

    /// <summary>Verifies the chain the sinks actually write to, so the same path resolution
    /// used when opening the audit log is used when checking it.</summary>
    public string VerifyAudit()
        => AuditLogSink.Verify(ResolvePath(Config.Telemetry.AuditPath), out var err)
            ? "audit chain intact (local integrity only; an equal-privilege attacker with the key could re-forge it — off-box sinks are the true anchor)"
            : "AUDIT LOG TAMPERED/BROKEN: " + err;

    /// <summary>Runs playbook actions the host does not implement itself. Response worker thread.</summary>
    internal void RunExtendedAction(PlaybookAction action, ProfileSnapshot snapshot)
    {
        switch (action)
        {
            case PlaybookAction.IsolateHost:
            {
                var allow = Config.Response.IsolationAllowlist ?? Array.Empty<string>();
                var r = Isolation.Isolate(allow);
                Log.Action(r.Ok ? $"host isolated (allowlist: {allow.Length} entr(y/ies))"
                                : "host isolation failed: " + r.Message);
                break;
            }
            case PlaybookAction.CollectTriage:
            {
                var dir = ResolvePath(Config.Response.TriageOutputPath);
                var result = new TriageCollector().Collect(snapshot.Pid, dir, snapshot);
                Log.Action(result.Ok
                    ? $"triage package written: {result.ZipPath} ({result.Bytes} bytes, {result.Skipped.Count} item(s) skipped)"
                    : "triage collection failed: " + result.Error);
                break;
            }
            case PlaybookAction.NotifyWebhook:
                // The webhook sink already receives every event; a playbook NotifyWebhook is
                // only meaningful as an explicit, separate escalation. Emitting through the
                // logger routes it to every configured sink including that webhook.
                Log.Action($"escalation: incident {snapshot.IncidentId} pid {snapshot.Pid} " +
                           $"({snapshot.ProcessName}) score {snapshot.Score}");
                break;
        }
    }

    public void Dispose()
    {
        try { _configWatcher?.Dispose(); } catch { }
        try { _control?.Dispose(); } catch { }
        try { _minifilter?.Dispose(); } catch { }
        try { Host.Dispose(); } catch { }
        try { _sink.Dispose(); } catch { }
        try { Vault?.Dispose(); } catch { }
        if (_scanner is IDisposable d) { try { d.Dispose(); } catch { } }
    }
}

/// <summary>
/// Indirection so a hot reload can swap the whole rule set atomically while the engine
/// keeps one stable reference. The engine reads rules on the owner thread; the swap
/// happens on the config-watcher thread, so the field is volatile and the replacement is
/// a fully-built object, never mutated in place.
/// </summary>
internal sealed class RuleEngineHolder
{
    private volatile RuleEngine _engine = new(new RuleSet(Array.Empty<DetectionRule>(), Array.Empty<RuleValidationError>()));

    /// <summary>The stable façade handed to the detection engine.</summary>
    public RuleEngine Engine => _engine;

    /// <summary>Applied to every engine this holder compiles, so a reload keeps the alert.</summary>
    public Action<string>? BudgetExhaustedAlert { get; set; }

    public void Set(RuleSet set) => _engine = new RuleEngine(set) { BudgetExhaustedAlert = BudgetExhaustedAlert };
}

/// <summary>Same atomic-swap treatment for indicator feeds.</summary>
internal sealed class IocFeedHolder
{
    private volatile IocFeed _feed = new();
    public IocFeed Feed => _feed;
    public void Set(IocFeed feed) => _feed = feed;
}

/// <summary>
/// Same atomic-swap treatment for the operator watchlist, so adding "quarantine this
/// binary on sight" to the config takes effect on the next signal without a restart.
/// A compiled Watchlist is immutable, so the owner thread reads it without a lock.
/// </summary>
internal sealed class WatchlistHolder
{
    private volatile Watchlist _list = Watchlist.Empty;
    public Watchlist List => _list;
    public void Set(Watchlist list) => _list = list;
}

/// <summary>
/// Caches image-path to SHA-256 so hash indicators can be matched without re-reading a
/// binary on every process start. Bounded, and a hash failure is cached as "unknown" so a
/// permanently unreadable path is not re-attempted on every signal.
/// </summary>
/// <summary>
/// Caches PE analysis per image path so a machine launching the same binary hundreds of
/// times parses it once. Bounded, and a parse failure is cached as "nothing to say" so an
/// unreadable path is not retried on every process start.
/// </summary>
internal sealed class ImageAnalysisCache
{
    private const int MaxEntries = 2048;
    private const long MaxFileBytes = 64L * 1024 * 1024;

    private readonly Dictionary<string, FileAnalysis?> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public FileAnalysis? Analyze(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        lock (_gate)
        {
            if (_cache.TryGetValue(path, out var cached)) return cached;
        }

        FileAnalysis? result = null;
        try
        {
            var info = new FileInfo(path);
            if (info.Exists && info.Length <= MaxFileBytes)
                result = FileAnalyzer.Analyze(path, MaxFileBytes);
        }
        catch { result = null; }

        lock (_gate)
        {
            if (_cache.Count >= MaxEntries) _cache.Clear();
            _cache[path] = result;
        }
        return result;
    }
}

internal sealed class ImageHashCache
{
    private const int MaxEntries = 4096;
    private const long MaxFileBytes = 64L * 1024 * 1024;

    // Keyed on path + length + last-write so an overwrite at the same path (a dropper
    // that replaces its own binary) is re-hashed instead of answered from the cache
    // until the next 4096-entry wipe. Only SUCCESSFUL hashes are cached: a sharing
    // violation or a transient access denied used to be stored as "no hash, forever",
    // which made every hash watchlist entry and hash IOC inert for that image.
    private readonly Dictionary<string, string> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public string? Sha256(string path)
    {
        if (string.IsNullOrEmpty(path)) return null;

        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists || info.Length > MaxFileBytes) return null;
        }
        catch { return null; }

        string key = path + "|" + info.Length.ToString(System.Globalization.CultureInfo.InvariantCulture)
                          + "|" + info.LastWriteTimeUtc.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture);
        lock (_gate)
        {
            if (_cache.TryGetValue(key, out var cached)) return cached;
        }

        string hash;
        try
        {
            // FileShare.ReadWrite | Delete: an EDR must be able to hash an image that the
            // running process still holds open, and must not block a delete while doing
            // so. File.OpenRead (FileShare.Read) fails against a live image with a
            // sharing violation -- the common case, since the interesting binary is the
            // one that is running.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
            hash = Convert.ToHexString(SHA256.HashData(fs));
        }
        catch { return null; }   // transient; try again next time rather than remembering failure

        lock (_gate)
        {
            if (_cache.Count >= MaxEntries) _cache.Clear();   // simple, bounded, and rare
            _cache[key] = hash;
        }
        return hash;
    }
}

/// <summary>Windows Service worker: runs the agent and writes a heartbeat the watchdog reads.</summary>
public sealed class BruceWorker : BackgroundService
{
    private readonly WorkerOptions _options;
    private readonly IHostApplicationLifetime _lifetime;
    private Composition? _composition;

    public BruceWorker(WorkerOptions options, IHostApplicationLifetime lifetime)
    {
        _options = options;
        _lifetime = lifetime;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _composition = Composition.Build(_options.ConfigPath);
        if (!_composition.Host.Start())
        {
            _composition.Log.Error("startup", new InvalidOperationException("no monitor could start"));
            _lifetime.StopApplication();
            return;
        }

        _composition.Log.Info($"service running. monitors: {_composition.Host.ActiveMonitors}");
        var svc = _composition.Config.Service;
        var interval = TimeSpan.FromSeconds(svc.HeartbeatIntervalSeconds);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                WriteHeartbeat(svc.HeartbeatPath, _composition.Log);
                await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* normal stop */ }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _composition?.Dispose(); } catch { }
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void WriteHeartbeat(string path, Logger log)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(path, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        }
        catch (Exception ex) { log.Error("heartbeat", ex); }
    }
}

/// <summary>
/// Standalone watchdog (run with --watchdog, typically as a SYSTEM scheduled task).
/// Restarts the service if its heartbeat goes stale. NOTE: an attacker with admin
/// can still kill both the service and this watchdog; true kill-resistance requires
/// PPL/ELAM, which is gated behind Microsoft's anti-malware vendor program.
/// </summary>
public static class Watchdog
{
    public static int Run(string configPath)
    {
        // Not strict: the watchdog's job is to keep the service alive, and a malformed
        // config must not take the watchdog down with it.
        var cfg = ConfigLoader.Load(configPath, strict: false);
        var svc = cfg.Service.ServiceName;
        var hbPath = cfg.Service.HeartbeatPath;
        var stale = TimeSpan.FromSeconds(cfg.Service.WatchdogStaleSeconds);
        var interval = TimeSpan.FromSeconds(cfg.Service.HeartbeatIntervalSeconds);

        Console.WriteLine($"[watchdog] monitoring service '{svc}' via {hbPath} (stale>{stale.TotalSeconds}s)");

        using var stop = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; stop.Set(); };

        while (!stop.IsSet)
        {
            try
            {
                if (HeartbeatAge(hbPath) is not { } age || age > stale)
                {
                    Console.WriteLine($"[watchdog] heartbeat stale; restarting '{svc}'");
                    ServiceControl.Restart(svc);
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[watchdog] {ex.Message}"); }

            stop.Wait(interval);
        }
        return 0;
    }

    private static TimeSpan? HeartbeatAge(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            if (!long.TryParse(File.ReadAllText(path).Trim(), out var unix)) return null;
            var written = DateTimeOffset.FromUnixTimeSeconds(unix);
            return DateTimeOffset.UtcNow - written;
        }
        catch { return null; }
    }
}

/// <summary>Install/uninstall/start the Windows Service and its watchdog task via sc.exe / schtasks.</summary>
public static class ServiceControl
{
    private const string WatchdogTask = "BruceEDRWatchdog";

    public static int Install(BruceConfig cfg, string configPath)
    {
        string exe = Environment.ProcessPath ?? "";
        string fileName = Path.GetFileName(exe).ToLowerInvariant();
        if (string.IsNullOrEmpty(exe) || fileName is "dotnet.exe" or "dotnet")
        {
            Console.Error.WriteLine(
                "Install requires a self-contained executable. Publish first:\n" +
                "  dotnet publish -c Release -r win-x64 --self-contained true\n" +
                "then run \"BruceEDR.exe --install\" from the publish folder.");
            return 1;
        }

        // A service runs as LocalSystem from wherever its ImagePath points. Registering
        // an exe that lives in a user-writable folder (Downloads, a home directory, a
        // build tree) hands any local user a SYSTEM shell: replace the file, wait for the
        // restart. Only install from a location a standard user cannot write to.
        if (!IsProtectedInstallLocation(exe, out string why))
        {
            Console.Error.WriteLine(
                $"Refusing to install a SYSTEM service from '{Path.GetDirectoryName(exe)}': {why}\n" +
                "Copy the publish folder under Program Files (for example " +
                @"C:\Program Files\BruceEDR\" + ") and run --install from there.");
            return 1;
        }

        string svc = cfg.Service.ServiceName;
        string fullConfig = Path.GetFullPath(configPath);
        int rc = 0;
        // Quote the binPath value so the stored ImagePath is quoted (CWE-428). An
        // unquoted "C:\Program Files\...\BruceEDR.exe" lets a local user drop
        // C:\Program.exe and get it run as LocalSystem. sc.exe never adds quotes itself.
        // The config path travels with it so the service loads the file the operator
        // installed with, not whatever bruce.config.json sits next to the exe.
        rc |= Sc("create", svc, "binPath=", $"\"{exe}\" --config \"{fullConfig}\"",
                 "start=", "auto", "DisplayName=", "BruceEDR EDR");
        Sc("description", svc, "User-mode behavioural EDR agent for RAT / infostealer IOCs");
        Sc("failure", svc, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/5000");

        // Register the watchdog as a SYSTEM scheduled task that starts at boot.
        RunTool("schtasks", "/Create", "/TN", WatchdogTask,
            "/TR", $"\"{exe}\" --watchdog --config \"{fullConfig}\"",
            "/SC", "ONSTART", "/RL", "HIGHEST", "/RU", "SYSTEM", "/F");

        Sc("start", svc);
        Console.WriteLine(rc == 0 ? $"Service '{svc}' installed and started." : "Install completed with warnings.");
        return rc;
    }

    /// <summary>
    /// True when <paramref name="exe"/> lives under a directory tree a standard user
    /// cannot write to: Program Files (either), or the Windows directory. Anything else
    /// -- user profiles, Downloads, ProgramData, a repository checkout -- is refused.
    /// </summary>
    internal static bool IsProtectedInstallLocation(string exe, out string why)
    {
        why = "";
        string full;
        try { full = Path.GetFullPath(exe); }
        catch { why = "path could not be resolved"; return false; }

        var roots = new[]
        {
            Environment.GetEnvironmentVariable("ProgramFiles"),
            Environment.GetEnvironmentVariable("ProgramFiles(x86)"),
            Environment.GetEnvironmentVariable("ProgramW6432"),
            Environment.GetEnvironmentVariable("SystemRoot"),
        };
        foreach (var root in roots)
        {
            if (string.IsNullOrEmpty(root)) continue;
            string r = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            if (full.StartsWith(r, StringComparison.OrdinalIgnoreCase)) return true;
        }
        why = "standard users can write to that location, so a replaced exe would run as SYSTEM";
        return false;
    }

    public static int Uninstall(BruceConfig cfg)
    {
        string svc = cfg.Service.ServiceName;
        Sc("stop", svc);
        int rc = Sc("delete", svc);
        RunTool("schtasks", "/Delete", "/TN", WatchdogTask, "/F");
        Console.WriteLine($"Service '{svc}' removed.");
        return rc;
    }

    public static int Start(string serviceName) => Sc("start", serviceName);

    // SERVICE_STATUS.dwCurrentState values. These numbers are part of the Win32 ABI and are
    // printed verbatim by sc.exe on every locale, unlike the words next to them.
    private const int StateStopped = 1;
    private const int StateRunning = 4;

    /// <summary>
    /// Real restart for the watchdog: a bare `sc start` is a no-op (error 1056) when the
    /// service process is alive-but-hung, which is exactly the case a heartbeat watchdog
    /// exists to recover. Stop it (force-killing the PID if it won't honor STOP), wait for
    /// STOPPED, then start.
    /// </summary>
    public static int Restart(string serviceName)
    {
        if (IsRunning(serviceName))
        {
            Sc("stop", serviceName);
            if (!WaitForState(serviceName, StateStopped, TimeSpan.FromSeconds(20)))
            {
                ForceKill(serviceName);                       // hung: won't honor SERVICE_CONTROL_STOP
                WaitForState(serviceName, StateStopped, TimeSpan.FromSeconds(10));
            }
        }
        int rc = Sc("start", serviceName);
        // SCM failure-actions may have already restarted a crashed service; treat
        // ERROR_SERVICE_ALREADY_RUNNING (1056) as success so recovery isn't a "failure".
        return rc == 1056 ? 0 : rc;
    }

    private static bool IsRunning(string serviceName) => QueryState(serviceName) == StateRunning;

    private static bool WaitForState(string serviceName, int target, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (QueryState(serviceName) == target) return true;
            Thread.Sleep(500);
        }
        return QueryState(serviceName) == target;
    }

    private static int? QueryState(string serviceName)
    {
        var (rc, outp) = Capture("sc", "query", serviceName);
        if (rc != 0 || string.IsNullOrEmpty(outp)) return null;
        return ParseServiceState(outp);
    }

    /// <summary>
    /// Extracts the numeric SERVICE_STATUS state from `sc query` output, because sc.exe
    /// translates both its labels and its state words on a localized Windows (German prints
    /// "STATUS : 4  WIRD AUSGEFUEHRT"). Matching the English strings made the watchdog see
    /// every service as not-running, so Restart skipped the stop and issued a bare `sc start`
    /// that is a no-op for the alive-but-hung service it exists to recover: recovery never
    /// happened on any non-English install. The number is locale-invariant.
    /// Returns null when no state line can be identified. Internal purely so it can be unit
    /// tested without spawning sc.exe.
    /// </summary>
    /// <remarks>
    /// State codes: 1 STOPPED, 2 START_PENDING, 3 STOP_PENDING, 4 RUNNING,
    /// 5 CONTINUE_PENDING, 6 PAUSE_PENDING, 7 PAUSED.
    /// Identification is structural: sc prints numeric fields as "LABEL : &lt;n&gt;  &lt;WORD&gt;".
    /// Only TYPE and STATE have that shape (exit codes are followed by a parenthesised hex
    /// value, CHECKPOINT/WAIT_HINT print bare "0x0", queryex's PID has no trailing word), and
    /// sc always prints TYPE before STATE, so the last in-range match is the state. TYPE
    /// values for services are 10/20/110/120 and fall outside 1-7; a driver's TYPE of 1 or 2
    /// is in range but is overwritten by the STATE line that follows it. Limitation: this
    /// assumes the field order and "&lt;n&gt;  &lt;WORD&gt;" layout that every known Windows build of
    /// sc.exe uses; if nothing matches, the English label and state words are tried as a
    /// fallback and null is returned only when that fails too.
    /// </remarks>
    internal static int? ParseServiceState(string scQueryOutput)
    {
        if (string.IsNullOrEmpty(scQueryOutput)) return null;

        int? structural = null;
        string? labelledStateValue = null;

        foreach (var raw in scQueryOutput.Split('\n'))
        {
            string line = raw.Trim();
            int colon = line.IndexOf(':');
            if (colon < 0) continue;

            string label = line[..colon];
            string value = line[(colon + 1)..].Trim();

            int digits = 0;
            while (digits < value.Length && value[digits] is >= '0' and <= '9') digits++;
            if (digits > 0 && digits < value.Length && char.IsWhiteSpace(value[digits]))
            {
                string rest = value[digits..].TrimStart();
                // '(' means an exit-code line ("0  (0x0)"), not a state.
                if (rest.Length > 0 && rest[0] != '('
                    && int.TryParse(value[..digits], out int code) && code is >= 1 and <= 7)
                {
                    structural = code;
                }
            }

            if (label.Contains("STATE", StringComparison.OrdinalIgnoreCase)) labelledStateValue = value;
        }

        if (structural is not null) return structural;
        if (labelledStateValue is null) return null;

        // English fallback: a differently-formatted state line whose label we still recognise.
        string upper = labelledStateValue.ToUpperInvariant();
        if (upper.Contains("CONTINUE_PENDING")) return 5;
        if (upper.Contains("PAUSE_PENDING")) return 6;
        if (upper.Contains("START_PENDING")) return 2;
        if (upper.Contains("STOP_PENDING")) return 3;
        if (upper.Contains("RUNNING")) return StateRunning;
        if (upper.Contains("STOPPED")) return StateStopped;
        if (upper.Contains("PAUSED")) return 7;
        return null;
    }

    private static void ForceKill(string serviceName)
    {
        var (rc, outp) = Capture("sc", "queryex", serviceName);
        if (rc != 0 || string.IsNullOrEmpty(outp)) return;
        foreach (var line in outp.Split('\n'))
        {
            int idx = line.IndexOf("PID", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) continue;
            int colon = line.IndexOf(':', idx);
            if (colon >= 0 && int.TryParse(line[(colon + 1)..].Trim(), out int pid) && pid > 0)
                RunTool("taskkill", "/F", "/PID", pid.ToString());
            return;
        }
    }

    private static int Sc(params string[] args) => RunTool("sc", args);

    // Like RunTool but returns captured stdout for parsing `sc query`/`queryex`.
    private static (int code, string stdout) Capture(string tool, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(tool)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var p = Process.Start(psi);
            if (p is null) return (-1, "");
            string outp = p.StandardOutput.ReadToEnd();
            _ = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return (p.HasExited ? p.ExitCode : -1, outp);
        }
        catch { return (-1, ""); }
    }

    private static int RunTool(string tool, params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo(tool)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var p = Process.Start(psi);
            if (p is null) return -1;
            string outp = p.StandardOutput.ReadToEnd();
            string errp = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            if (!string.IsNullOrWhiteSpace(outp)) Console.WriteLine(outp.Trim());
            if (!string.IsNullOrWhiteSpace(errp)) Console.Error.WriteLine(errp.Trim());
            return p.HasExited ? p.ExitCode : -1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{tool} failed: {ex.Message}");
            return -1;
        }
    }
}
