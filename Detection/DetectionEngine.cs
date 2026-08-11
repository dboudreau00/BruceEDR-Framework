using ProcessShield.Api;
using ProcessShield.Core;
using ProcessShield.Intel;

namespace ProcessShield.Detection;

public sealed class EngineOptions
{
    public int WarnThreshold { get; init; } = 40;
    public int QuarantineThreshold { get; init; } = 70;
    public TimeSpan CorrelationWindow { get; init; } = TimeSpan.FromSeconds(30);
    public bool AutoKillOnQuarantine { get; init; } = false;
    public int TrustDiscount { get; init; } = 30;

    // --- v2 knobs. Defaults reproduce the v1 behaviour exactly, so an engine built
    //     the old way (options + isTrusted) scores identically to before. -----------

    /// <summary>Shed points from a quiet, un-contained process so score cannot only ever rise.</summary>
    public bool EnableScoreDecay { get; init; }
    public int ScoreDecayPoints { get; init; } = 5;
    public TimeSpan ScoreDecayInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Points added once when the beacon analyzer judges a process to be beaconing.</summary>
    public int BeaconScore { get; init; } = 35;
    /// <summary>Points added for a DNS name that scores as likely DGA or a DNS tunnel.</summary>
    public int DgaScore { get; init; } = 25;
    /// <summary>Points added when an indicator feed matches the process image, a domain or an address.</summary>
    public int IntelHitScore { get; init; } = 60;

    /// <summary>Hard ceiling on tracked profiles so a telemetry flood cannot exhaust memory.</summary>
    public int MaxTrackedProcesses { get; init; } = 16384;
}

/// <summary>
/// Optional collaborators. Every one is nullable and the engine degrades cleanly when a
/// collaborator is absent, so the console, the service, a unit test and the offline replay
/// harness can each wire up exactly as much machinery as they need.
/// </summary>
public sealed class EngineDependencies
{
    public static readonly EngineDependencies Empty = new();

    public IClock Clock { get; init; } = SystemClock.Instance;
    /// <summary>Declarative JSON rules. Null means builtin C# rules only.</summary>
    public RuleEngine? Rules { get; init; }
    /// <summary>Process lineage, used for ancestry-aware rules and richer alerts.</summary>
    public ProcessTree? Tree { get; init; }
    /// <summary>C2 cadence analysis over outbound connections.</summary>
    public BeaconAnalyzer? Beacons { get; init; }
    /// <summary>Operator-supplied indicator feeds.</summary>
    public IocFeed? Intel { get; init; }
    /// <summary>Observed endpoint inventory, fed from network and DNS signals.</summary>
    public ApiSurfaceInventory? Surface { get; init; }
    /// <summary>
    /// Resolves an image path to a SHA-256 so hash indicators can match. Hashing is slow
    /// and touches disk, so the host supplies a cached implementation and the engine
    /// treats a null result as "not known yet" rather than blocking.
    /// </summary>
    public Func<string, string?>? ImageHash { get; init; }
}

public sealed class DetectionResult
{
    public required Verdict Verdict { get; init; }
    public required string Trigger { get; init; }
    public required ProfileSnapshot Snapshot { get; init; }
}

/// <summary>
/// Pure detection state machine. Every public method is invoked ONLY from the
/// single ShieldHost owner thread, so the profile store needs no locking. Ingest
/// returns zero or more verdicts (a single archive signal can implicate several
/// processes). Thresholds are hot-updatable via UpdateThresholds (also owner-thread).
///
/// v2 keeps the v1 scoring path byte-for-byte and layers optional analytics on top:
/// declarative JSON rules, indicator feeds, beacon cadence, domain scoring, process
/// lineage and score decay. Anything not supplied via <see cref="EngineDependencies"/>
/// is simply skipped.
/// </summary>
public sealed class DetectionEngine
{
    private int _warn;
    private int _quarantine;
    private int _scanAt;
    private TimeSpan _window;
    private int _trustDiscount;

    private readonly Func<int, bool> _isTrusted;
    private readonly EngineOptions _opt;
    private readonly EngineDependencies _deps;
    private readonly IClock _clock;

    private readonly Dictionary<int, ThreatProfile> _profiles = new();
    private DateTime _lastPrune;
    private long _incidentCounter;

    public DetectionEngine(EngineOptions opt, Func<int, bool> isTrusted)
        : this(opt, isTrusted, EngineDependencies.Empty) { }

    public DetectionEngine(EngineOptions opt, Func<int, bool> isTrusted, EngineDependencies deps)
    {
        _opt = opt;
        _deps = deps;
        _clock = deps.Clock;
        _isTrusted = isTrusted;
        _lastPrune = _clock.UtcNow;
        Apply(opt.WarnThreshold, opt.QuarantineThreshold,
              (int)opt.CorrelationWindow.TotalSeconds, opt.TrustDiscount);
    }

    /// <summary>Number of processes currently tracked. Exposed for metrics and tests.</summary>
    public int TrackedProcesses => _profiles.Count;

    /// <summary>Hot-reload of detection posture. Owner thread only.</summary>
    public void UpdateThresholds(int warn, int quarantine, int windowSeconds, int trustDiscount)
        => Apply(warn, quarantine, windowSeconds, trustDiscount);

    private void Apply(int warn, int quarantine, int windowSeconds, int trustDiscount)
    {
        _warn = Math.Max(1, warn);
        _quarantine = Math.Max(_warn + 1, quarantine);
        _scanAt = Math.Max(20, _warn / 2);
        _window = TimeSpan.FromSeconds(windowSeconds > 0 ? windowSeconds : 30);
        _trustDiscount = Math.Max(0, trustDiscount);
    }

    public IReadOnlyList<DetectionResult> Ingest(Signal s)
    {
        var results = new List<DetectionResult>();
        MaybePrune();

        if (s.Kind == SignalKind.FileCreate && s.Pid == 0)
        {
            CorrelateUnattributedArchive(s, results);
            return results;
        }
        if (s.Pid <= 0) return results;

        // A second ProcessStart for a PID means Windows recycled it: drop any stale
        // profile so the reused PID starts clean and cannot inherit the prior process's
        // Contained/Terminated/Score state (which would suppress containment on a new,
        // possibly malicious, process -- a fail-open PID-reuse hole).
        if (s.Kind == SignalKind.ProcessStart)
        {
            _profiles.Remove(s.Pid);
            _deps.Beacons?.Forget(s.Pid);
            _deps.Surface?.Forget(s.Pid);
            _deps.Tree?.OnStart(s.Pid, s.ParentPid, s.ProcessName, s.ImagePath, s.CommandLine, s.TimestampUtc);
        }
        else if (s.Kind == SignalKind.ProcessStop)
        {
            _deps.Tree?.OnExit(s.Pid, s.TimestampUtc);
            _deps.Beacons?.Forget(s.Pid);
            if (_profiles.TryGetValue(s.Pid, out var gone)) gone.Exited = true;
            return results;   // a dead process cannot be contained; nothing further to score
        }

        var p = GetOrAdd(s.Pid);
        if (!string.IsNullOrEmpty(s.ProcessName)) p.ProcessName = s.ProcessName;
        if (!string.IsNullOrEmpty(s.ImagePath)) p.ImagePath = s.ImagePath;
        if (!string.IsNullOrEmpty(s.CommandLine)) p.CommandLine = s.CommandLine;
        if (s.ParentPid > 0) p.ParentPid = s.ParentPid;

        switch (s.Kind)
        {
            case SignalKind.ProcessStart:   RuleProcessStart(p, s); break;
            case SignalKind.ImageLoad:      RuleImageLoad(p, s);    break;
            case SignalKind.FileCreate:     RuleFileCreate(p, s);   break;
            case SignalKind.NetworkConnect: RuleNetwork(p, s);      break;
            case SignalKind.RegistryWrite:  RuleRegistry(p, s);     break;
            case SignalKind.DnsQuery:       RuleDns(p, s);          break;
            case SignalKind.ProcessAccess:  RuleProcessAccess(p, s); break;
            case SignalKind.ScriptContent:  RuleScript(p, s);       break;
            case SignalKind.NamedPipe:      RuleNamedPipe(p, s);    break;
        }

        EvaluateDeclarativeRules(p, s);
        MatchIndicators(p, s);
        _deps.Surface?.Observe(s);

        // NB: the memory scan is NOT run here. It can take up to ~2s per process, which
        // would stall the single detection thread. ShieldHost claims the scan via
        // TryClaimMemoryScan and runs it on the response worker, folding results back in
        // through ApplyMemoryHits. See fix for the concurrency-starvation issue.
        var r = Decide(p, s.Kind.ToString(), s.TimestampUtc);
        if (r is not null) results.Add(r);
        return results;
    }

    public IReadOnlyList<ProfileSnapshot> Snapshot(bool onlyContained)
    {
        var list = new List<ProfileSnapshot>();
        foreach (var p in _profiles.Values)
        {
            if (onlyContained) { if (!p.Contained) continue; }
            else if (p.Score < _warn) continue;
            list.Add(ToSnapshot(p));
        }
        list.Sort((a, b) => b.Score.CompareTo(a.Score));
        return list;
    }

    public ProfileSnapshot? SnapshotOne(int pid)
        => _profiles.TryGetValue(pid, out var p) ? ToSnapshot(p) : null;

    public bool SetSuspendedByAnalyst(int pid, bool value)
    {
        if (!_profiles.TryGetValue(pid, out var p)) return false;
        p.SuspendedByAnalyst = value;
        return true;
    }

    public bool SetTerminated(int pid)
    {
        if (!_profiles.TryGetValue(pid, out var p)) return false;
        p.Terminated = true;
        p.SuspendedByAnalyst = false;
        return true;
    }

    /// <summary>
    /// Every tracked pid mapped to its current score, including processes below the warn
    /// threshold. Used by the replay harness, which must assert on scores that never
    /// produced a verdict (the false-positive scenarios depend on exactly that).
    /// </summary>
    public IReadOnlyDictionary<int, int> AllScores()
    {
        var d = new Dictionary<int, int>(_profiles.Count);
        foreach (var kv in _profiles) d[kv.Key] = kv.Value.Score;
        return d;
    }

    /// <summary>Distinct ATT&amp;CK technique ids seen across every tracked process.</summary>
    public IReadOnlyDictionary<string, int> ObservedTechniques()
    {
        var d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in _profiles.Values)
            foreach (var t in p.Techniques)
                d[t] = d.TryGetValue(t, out var n) ? n + 1 : 1;
        return d;
    }

    // ------------------------------------------------------- builtin rules (v1)

    private void RuleProcessStart(ThreatProfile p, Signal s)
    {
        string name = s.ProcessName.ToLowerInvariant();
        string cmd = s.CommandLine.ToLowerInvariant();
        bool childIsLolBin = IocDatabase.LolBins.Contains(name);

        string parentName = _profiles.TryGetValue(s.ParentPid, out var pp)
            ? pp.ProcessName.ToLowerInvariant() : "";
        if (childIsLolBin && IocDatabase.UnusualParents.Contains(parentName))
        {
            p.SuspiciousSpawnUtc = s.TimestampUtc;
            Score(p, 45, $"Unusual parent/child: {parentName} -> {name}", "builtin-unusual-parent",
                  Tech("T1059", "T1204.002"), s.TimestampUtc);
        }

        foreach (var ioc in IocDatabase.CommandLineIocs)
            if (cmd.Contains(ioc))
                Score(p, 15, $"Command-line IOC '{ioc}'", "builtin-cmdline-ioc",
                      CommandLineTechniques(ioc), s.TimestampUtc);
    }

    private void RuleImageLoad(ThreatProfile p, Signal s)
    {
        string file = (s.FilePath ?? "").ToLowerInvariant();
        foreach (var frag in IocDatabase.SuspiciousModuleFragments)
            if (file.Contains(frag))
                Score(p, 50, $"Loaded remote-control/injection module '{frag}'", "builtin-rat-module",
                      Tech("T1219", "T1055"), s.TimestampUtc);
    }

    private void RuleFileCreate(ThreatProfile p, Signal s)
    {
        string file = (s.FilePath ?? "").ToLowerInvariant();
        if (file.Length == 0) return;

        if (IocDatabase.SensitiveFileFragments.Any(file.Contains))
        {
            p.CredentialAccessUtc = s.TimestampUtc;
            Score(p, 35, "Touched sensitive credential/secret store", "builtin-credential-store",
                  Tech("T1555.003", "T1539"), s.TimestampUtc);
        }

        string ext = Path.GetExtension(file);
        bool isArchive = IocDatabase.ArchiveExtensions.Contains(ext);
        bool inStaging = IocDatabase.StagingDirFragments.Any(file.Contains);
        // Gate the whole block on the de-dup insert so a repeated notification of the
        // SAME archive (e.g. two overlapping FileSystemWatchers, or ETW + watcher) can't
        // score the process twice.
        if (isArchive && inStaging && p.StagedArchives.Add(file))
        {
            p.ArchiveStagedUtc = s.TimestampUtc;
            Score(p, 30, "Created archive in a staging directory", "builtin-archive-staged",
                  Tech("T1560", "T1074.001"), s.TimestampUtc);

            if (p.CredentialAccessUtc is { } c && s.TimestampUtc - c <= _window)
                Score(p, 25, "Archive staged shortly after reading secrets", "builtin-collect-then-stage",
                      Tech("T1005", "T1074.001"), s.TimestampUtc);
        }
    }

    private void RuleNetwork(ThreatProfile p, Signal s)
    {
        if (!NetworkUtil.IsRoutableRemote(s.RemoteAddress)) return;

        string endpoint = $"{s.RemoteAddress}:{s.RemotePort}";
        p.RemoteEndpoints.Add(endpoint);

        if (p.ArchiveStagedUtc is { } t && s.TimestampUtc - t <= _window)
            Score(p, 45, $"Outbound to {endpoint} shortly after staging an archive (collect->exfil)",
                  "builtin-exfil-chain", Tech("T1041", "T1567"), s.TimestampUtc);
        else if (p.Score >= _warn)
            Score(p, 15, $"Outbound to {endpoint} from a flagged process",
                  "builtin-flagged-egress", Tech("T1071.001"), s.TimestampUtc);

        AnalyzeBeacon(p, endpoint, s.TimestampUtc);
    }

    // ------------------------------------------------------- builtin rules (v2)

    private void RuleRegistry(ThreatProfile p, Signal s)
    {
        string key = (s.RegistryKey ?? "").ToLowerInvariant();
        if (key.Length == 0) return;

        // ETW gives KCB-relative names that can be partial, so these are substring tests
        // rather than exact paths. See Monitoring/MonitorSupport.IsPersistenceKey.
        if (key.Contains(@"\currentversion\run") || key.Contains(@"\currentversion\runonce") ||
            key.Contains(@"\explorer\shell folders\startup"))
            Score(p, 40, $"Wrote an autostart registry key: {Trim(s.RegistryKey)}",
                  "builtin-run-key", Tech("T1547.001"), s.TimestampUtc);
        else if (key.Contains(@"\image file execution options\"))
            Score(p, 45, $"Wrote an IFEO debugger hook: {Trim(s.RegistryKey)}",
                  "builtin-ifeo", Tech("T1546.012"), s.TimestampUtc);
        else if (key.Contains(@"\services\") && key.Contains(@"\imagepath"))
            Score(p, 40, $"Created or repointed a service image path: {Trim(s.RegistryKey)}",
                  "builtin-service-persistence", Tech("T1543.003"), s.TimestampUtc);
        else if (key.Contains(@"\windows\currentversion\policies\system") ||
                 key.Contains(@"\windows defender\") || key.Contains(@"\policies\microsoft\windows defender"))
            Score(p, 35, $"Modified a security policy key: {Trim(s.RegistryKey)}",
                  "builtin-impair-defenses", Tech("T1562.001"), s.TimestampUtc);
    }

    private void RuleDns(ThreatProfile p, Signal s)
    {
        string domain = (s.Domain ?? "").Trim().ToLowerInvariant();
        if (domain.Length == 0) return;
        if (!p.Domains.Add(domain)) return;   // score each distinct name once per process

        var verdict = DomainAnalysis.Analyze(domain);

        if (verdict.IsDynamicDns)
            Score(p, 20, $"Resolved a dynamic-DNS host '{domain}'", "builtin-dyndns",
                  Tech("T1568"), s.TimestampUtc);

        if (verdict.LikelyDga)
            Score(p, _opt.DgaScore,
                  $"Resolved a likely algorithmically generated domain '{domain}' (score {verdict.DgaScore:F2})",
                  "builtin-dga", Tech("T1568.002"), s.TimestampUtc);

        if (verdict.LooksLikeDnsTunnel)
            Score(p, 40, $"DNS name '{Trim(domain)}' has the shape of DNS tunnelling",
                  "builtin-dns-tunnel", Tech("T1071.004", "T1572"), s.TimestampUtc);
    }

    private void RuleProcessAccess(ThreatProfile p, Signal s)
    {
        if (s.TargetPid <= 0) return;

        // PROCESS_VM_READ (0x10) / PROCESS_VM_WRITE (0x20) / PROCESS_VM_OPERATION (0x08) /
        // PROCESS_CREATE_THREAD (0x02) are the rights an injector or a credential dumper needs.
        const uint Sensitive = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040;
        bool sensitive = (s.DesiredAccess & Sensitive) != 0 || s.DesiredAccess == 0x1FFFFF;
        if (!sensitive) return;

        string target = (s.Detail ?? "").ToLowerInvariant();
        if (target.Contains("lsass"))
            Score(p, 60, $"Opened LSASS with memory-access rights (mask 0x{s.DesiredAccess:X})",
                  "builtin-lsass-access", Tech("T1003.001"), s.TimestampUtc);
        else
            Score(p, 25, $"Opened pid {s.TargetPid} with injection-capable rights (mask 0x{s.DesiredAccess:X})",
                  "builtin-cross-process-access", Tech("T1055"), s.TimestampUtc);
    }

    private void RuleScript(ThreatProfile p, Signal s)
    {
        string script = s.ScriptText ?? "";
        if (script.Length == 0) return;

        if (Monitoring.MonitorSupport.LooksObfuscatedScript(script))
            Score(p, 35, "AMSI surfaced obfuscated script content", "builtin-obfuscated-script",
                  Tech("T1027.010", "T1059.001"), s.TimestampUtc);

        string lower = script.ToLowerInvariant();
        if (lower.Contains("downloadstring") || lower.Contains("invoke-webrequest") ||
            lower.Contains("net.webclient") || lower.Contains("start-bitstransfer"))
            Score(p, 30, "Script content downloads and runs remote code", "builtin-script-download",
                  Tech("T1105", "T1059.001"), s.TimestampUtc);
    }

    private void RuleNamedPipe(ThreatProfile p, Signal s)
    {
        string pipe = (s.PipeName ?? "").ToLowerInvariant();
        if (pipe.Length == 0) return;

        // Pipe names used by well-known post-exploitation frameworks' default profiles.
        // Operators change these trivially, so this catches the lazy case only -- which is
        // still worth catching, but it is not a reliable detection on its own.
        string[] known = { "msagent_", "postex_", "status_", "mojo_shared", "atctl", "interprocess" };
        if (known.Any(pipe.Contains))
            Score(p, 35, $"Created a named pipe matching a known C2 default: {Trim(pipe)}",
                  "builtin-c2-pipe", Tech("T1071", "T1021"), s.TimestampUtc);
    }

    // ------------------------------------------------------- optional analytics

    private void EvaluateDeclarativeRules(ThreatProfile p, Signal s)
    {
        var engine = _deps.Rules;
        if (engine is null) return;

        var ctx = new RuleContext
        {
            ParentName = _profiles.TryGetValue(p.ParentPid, out var parent) ? parent.ProcessName : "",
            Ancestry = _deps.Tree is null
                ? Array.Empty<string>()
                : _deps.Tree.Ancestors(p.Pid).Select(a => a.Name).ToArray(),
            Score = p.Score,
            Trusted = p.Trusted
        };

        IReadOnlyList<RuleMatch> matches;
        try { matches = engine.Evaluate(s, ctx); }
        catch { return; }   // a rule pack must never be able to stop detection

        foreach (var m in matches)
        {
            if (m.Rule.OncePerProcess && !p.FiredOnce.Add(m.Rule.Id)) continue;
            Score(p, m.Rule.Score, m.Explanation, m.Rule.Id, m.Rule.Techniques, s.TimestampUtc);
        }
    }

    private void MatchIndicators(ThreatProfile p, Signal s)
    {
        var feed = _deps.Intel;
        if (feed is null || feed.Count == 0) return;

        if (s.Kind == SignalKind.DnsQuery && !string.IsNullOrEmpty(s.Domain))
        {
            var hit = feed.MatchDomain(s.Domain);
            if (hit is not null && p.FiredOnce.Add("intel-domain:" + hit.Indicator))
                Score(p, _opt.IntelHitScore, $"Indicator feed match on domain '{hit.Indicator}' ({hit.Label})",
                      "intel-domain", Tech("T1071"), s.TimestampUtc);
        }

        if (s.Kind == SignalKind.NetworkConnect && !string.IsNullOrEmpty(s.RemoteAddress))
        {
            var hit = feed.MatchIp(s.RemoteAddress);
            if (hit is not null && p.FiredOnce.Add("intel-ip:" + hit.Indicator))
                Score(p, _opt.IntelHitScore, $"Indicator feed match on address '{hit.Indicator}' ({hit.Label})",
                      "intel-ip", Tech("T1071"), s.TimestampUtc);
        }

        if (s.Kind == SignalKind.ProcessStart && _deps.ImageHash is { } hasher &&
            !string.IsNullOrEmpty(p.ImagePath))
        {
            string? sha;
            try { sha = hasher(p.ImagePath); } catch { sha = null; }
            if (sha is not null && feed.MatchHash(sha) is { } hit && p.FiredOnce.Add("intel-hash"))
                Score(p, _opt.IntelHitScore, $"Indicator feed match on image hash ({hit.Label})",
                      "intel-hash", Tech("T1204.002"), s.TimestampUtc);
        }
    }

    private void AnalyzeBeacon(ThreatProfile p, string endpoint, DateTime whenUtc)
    {
        var beacons = _deps.Beacons;
        if (beacons is null) return;

        beacons.Observe(p.Pid, endpoint, whenUtc);
        var verdict = beacons.AnalyzeEndpoint(p.Pid, endpoint);
        if (verdict is null || !verdict.IsBeaconing) return;
        if (!p.FiredOnce.Add("beacon:" + endpoint)) return;

        _deps.Surface?.MarkBeaconing(p.Pid, endpoint, verdict.Confidence);
        Score(p, _opt.BeaconScore, verdict.Explanation, "builtin-beacon",
              Tech("T1071", "T1008"), whenUtc);
    }

    private void CorrelateUnattributedArchive(Signal s, List<DetectionResult> results)
    {
        var now = s.TimestampUtc;
        string file = (s.FilePath ?? "").ToLowerInvariant();

        foreach (var p in _profiles.Values)
        {
            if (p.Score <= 0 || p.Contained) continue;
            if (now - p.LastUpdatedUtc > _window) continue;

            if (!p.StagedArchives.Add(file)) continue;   // score each distinct archive once
            p.ArchiveStagedUtc = now;
            Score(p, 25, $"Archive '{Path.GetFileName(s.FilePath)}' staged near flagged activity",
                  "builtin-archive-correlation", Tech("T1074.001"), now);

            var r = Decide(p, "ArchiveCorrelation", now);
            if (r is not null) results.Add(r);
        }
    }

    /// <summary>
    /// Owner-thread only. Returns true at most once per process, when its score first
    /// crosses the scan threshold, and marks it claimed so the scan isn't scheduled
    /// twice. The caller (ShieldHost) runs the actual scan off the detection thread.
    /// </summary>
    public bool TryClaimMemoryScan(int pid)
    {
        if (!_profiles.TryGetValue(pid, out var p)) return false;
        if (p.MemoryScanned || p.Score < _scanAt) return false;
        p.MemoryScanned = true;
        return true;
    }

    /// <summary>
    /// Owner-thread only. Folds memory-scan hits into the profile and re-decides, so a
    /// process that only crosses a threshold because of an in-memory IOC is still caught
    /// (a moment later than an inline scan would, which is the accepted trade-off).
    /// </summary>
    public IReadOnlyList<DetectionResult> ApplyMemoryHits(int pid, IReadOnlyList<string> hits)
    {
        var results = new List<DetectionResult>();
        if (hits.Count == 0) return results;
        if (!_profiles.TryGetValue(pid, out var p)) return results;

        var now = _clock.UtcNow;
        Score(p, 20 + 5 * Math.Min(hits.Count, 6), "Memory IOC(s): " + string.Join(", ", hits),
              "builtin-memory-ioc", Tech("T1055", "T1005"), now);
        var r = Decide(p, "MemoryScan", now);
        if (r is not null) results.Add(r);
        return results;
    }

    private void Score(ThreatProfile p, int points, string reason, string ruleId,
                       IReadOnlyList<string> techniques, DateTime nowUtc)
        => p.Add(points, reason, ruleId, techniques, nowUtc);

    private DetectionResult? Decide(ThreatProfile p, string trigger, DateTime nowUtc)
    {
        if (!p.SignatureChecked)
        {
            p.SignatureChecked = true;
            bool trusted;
            try { trusted = _isTrusted(p.Pid); } catch { trusted = false; }
            if (trusted)
            {
                p.Trusted = true;
                p.Reasons.Add($"[-{_trustDiscount}] Signed by allowlisted publisher");
                p.ReasonLog.Add(new ReasonEntry
                {
                    Points = -_trustDiscount,
                    Text = "Signed by allowlisted publisher",
                    RuleId = "builtin-trust-discount",
                    TimeUtc = nowUtc
                });
            }
        }

        // The trust discount is a PERSISTENT offset applied at verdict time, not a
        // one-shot subtraction from Score. Subtracting once (at the first Decide) burned
        // the whole cushion on a process whose first signal scored 0 (the normal
        // ProcessStart-first case), leaving all later scoring undiscounted -> a trusted
        // app could be quarantined. Evaluating an effective score each time fixes that.
        int eff = p.Trusted ? Math.Max(0, p.Score - _trustDiscount) : p.Score;

        Verdict v = eff >= _quarantine ? Verdict.Quarantine
                  : eff >= _warn ? Verdict.Warn
                  : Verdict.Allow;

        if (v == Verdict.Allow) return null;
        if (v == Verdict.Quarantine && p.Contained) return null;

        if (p.IncidentId.Length == 0) p.IncidentId = NewIncidentId(p, nowUtc);
        if (v == Verdict.Quarantine) p.Contained = true;
        return new DetectionResult { Verdict = v, Trigger = trigger, Snapshot = ToSnapshot(p) };
    }

    /// <summary>
    /// Incident ids are sortable, unique within a run, and carry the pid so an analyst can
    /// tie a SIEM row back to a process without a lookup.
    /// </summary>
    private string NewIncidentId(ThreatProfile p, DateTime nowUtc)
        => $"PS-{nowUtc:yyyyMMdd}-{++_incidentCounter:D5}-{p.Pid}";

    private ProfileSnapshot ToSnapshot(ThreatProfile p) => new()
    {
        Pid = p.Pid,
        ProcessName = p.ProcessName,
        ImagePath = p.ImagePath,
        Score = p.Score,
        Trusted = p.Trusted,
        Contained = p.Contained,
        SuspendedByAnalyst = p.SuspendedByAnalyst,
        Terminated = p.Terminated,
        Reasons = p.Reasons.ToArray(),
        StagedArchives = p.StagedArchives.ToArray(),
        FirstSeenUtc = p.FirstSeenUtc,
        LastUpdatedUtc = p.LastUpdatedUtc,
        ParentPid = p.ParentPid,
        CommandLine = p.CommandLine,
        Ancestry = _deps.Tree is null
            ? Array.Empty<string>()
            : _deps.Tree.Ancestors(p.Pid).Select(a => $"{a.Name} ({a.Pid})").ToArray(),
        IncidentId = p.IncidentId,
        Techniques = p.Techniques.OrderBy(t => t, StringComparer.Ordinal).ToArray(),
        ReasonLog = p.ReasonLog.ToArray(),
        RemoteEndpoints = p.RemoteEndpoints.ToArray(),
        Domains = p.Domains.ToArray(),
        PeakScore = p.PeakScore
    };

    private ThreatProfile GetOrAdd(int pid)
    {
        if (!_profiles.TryGetValue(pid, out var p))
        {
            EnforceProfileCap();
            p = new ThreatProfile(pid, _clock.UtcNow);
            _profiles[pid] = p;
        }
        return p;
    }

    /// <summary>
    /// Keeps the profile store bounded. A signal storm against thousands of short-lived
    /// pids would otherwise grow the dictionary without limit between prunes. Contained
    /// processes are never evicted -- losing one would silently release containment state.
    /// </summary>
    private void EnforceProfileCap()
    {
        if (_profiles.Count < _opt.MaxTrackedProcesses) return;

        int victim = 0;
        DateTime oldest = DateTime.MaxValue;
        foreach (var kv in _profiles)
        {
            if (kv.Value.Contained && !kv.Value.Terminated) continue;
            if (kv.Value.LastUpdatedUtc >= oldest) continue;
            oldest = kv.Value.LastUpdatedUtc;
            victim = kv.Key;
        }
        if (victim != 0) _profiles.Remove(victim);
    }

    private void MaybePrune()
    {
        var now = _clock.UtcNow;
        if (now - _lastPrune < TimeSpan.FromMinutes(1)) return;
        _lastPrune = now;

        ApplyDecay(now);
        _deps.Beacons?.Prune(TimeSpan.FromHours(6));
        _deps.Tree?.Prune(TimeSpan.FromMinutes(10));
        _deps.Surface?.Prune(TimeSpan.FromHours(12));

        var cutoff = now - TimeSpan.FromMinutes(10);
        List<int>? dead = null;
        foreach (var kv in _profiles)
        {
            bool retain = kv.Value.Contained && !kv.Value.Terminated;
            if (retain) continue;
            if (kv.Value.LastUpdatedUtc >= cutoff) continue;
            (dead ??= new List<int>()).Add(kv.Key);
        }
        if (dead is null) return;
        foreach (var pid in dead) _profiles.Remove(pid);
    }

    /// <summary>
    /// Cools off processes that have stopped doing anything interesting. Without this a
    /// long-lived, busy, benign process accrues points from low-value rules for weeks and
    /// eventually trips a threshold on accumulated noise alone. Contained processes never
    /// decay: containment is a decision an analyst releases, not something that expires.
    /// </summary>
    private void ApplyDecay(DateTime now)
    {
        if (!_opt.EnableScoreDecay || _opt.ScoreDecayPoints <= 0) return;
        var interval = _opt.ScoreDecayInterval;
        if (interval <= TimeSpan.Zero) return;

        foreach (var p in _profiles.Values)
        {
            if (p.Contained || p.Score <= 0) continue;
            var elapsed = now - p.LastDecayUtc;
            if (elapsed < interval) continue;

            // Only decay a process that has been quiet for at least one interval, so an
            // actively scoring process is never discounted mid-attack.
            if (now - p.LastUpdatedUtc < interval) { p.LastDecayUtc = now; continue; }

            long steps = (long)(elapsed.Ticks / interval.Ticks);
            int shed = (int)Math.Min(int.MaxValue, steps * _opt.ScoreDecayPoints);
            p.Score = Math.Max(0, p.Score - shed);
            p.LastDecayUtc = now;
        }
    }

    private static string[] Tech(params string[] ids) => ids;

    private static string[] CommandLineTechniques(string ioc) => ioc switch
    {
        "-enc" or "-encodedcommand" or "frombase64string" => new[] { "T1027.010", "T1140", "T1059.001" },
        "-w hidden" or "-windowstyle hidden" or "-nop" => new[] { "T1564", "T1059.001" },
        "downloadstring" or "downloadfile" or "net.webclient" or "invoke-webrequest" => new[] { "T1105" },
        "invoke-expression" or "iex(" => new[] { "T1059.001" },
        "-urlcache" => new[] { "T1105", "T1218" },
        "/transfer" => new[] { "T1197", "T1105" },
        "-executionpolicy bypass" => new[] { "T1059.001", "T1562.001" },
        _ => new[] { "T1059" }
    };

    private static string Trim(string? s, int max = 120)
        => s is null ? "" : s.Length <= max ? s : s[..max] + "...";
}
