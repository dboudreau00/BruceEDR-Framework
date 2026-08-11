using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Hosting;
using ProcessShield.Replay;
using ProcessShield.Response;

namespace ProcessShield.ConsoleUi;

/// <summary>
/// Interactive analyst REPL. Lists contained/flagged processes and resumes /
/// suspends / kills them by the number from the last listing. 'reload' re-reads
/// config; 'audit' verifies the tamper-evident log. Runs on the main thread.
/// </summary>
public sealed class AnalystConsole
{
    private readonly ShieldHost _host;
    private readonly Logger _log;
    private readonly Action? _reloadConfig;
    private readonly Func<string>? _verifyAudit;
    private readonly Composition? _composition;
    private readonly ApiStudioConsole? _api;
    private List<int> _listing = new();

    public AnalystConsole(ShieldHost host, Logger log,
        Action? reloadConfig = null, Func<string>? verifyAudit = null,
        Composition? composition = null)
    {
        _host = host;
        _log = log;
        _reloadConfig = reloadConfig;
        _verifyAudit = verifyAudit;
        _composition = composition;
        _api = composition is null ? null : new ApiStudioConsole(composition, log);
    }

    public void Run()
    {
        PrintHelp();
        while (true)
        {
            Console.Write("shield> ");
            string? line;
            try { line = Console.ReadLine(); }
            catch { break; }
            if (line is null) break;

            line = line.Trim();
            if (line.Length == 0) continue;

            var parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            string cmd = parts[0].ToLowerInvariant();
            string arg = parts.Length > 1 ? parts[1] : "";

            try
            {
                if (Handle(cmd, arg)) return;
            }
            catch (ConsoleInputException cie) { _log.Raw("  " + cie.Message); }
            catch (Exception ex) { _log.Error("console command", ex); }
        }
    }

    private bool Handle(string cmd, string arg)
    {
        switch (cmd)
        {
            case "help" or "?": PrintHelp(); return false;
            case "list" or "ls": RenderList(arg.Equals("all", StringComparison.OrdinalIgnoreCase)); return false;
            case "info": _log.Raw(_host.Info(ResolvePid(arg)).Message); return false;
            case "resume": Report(_host.Resume(ResolvePid(arg))); return false;
            case "suspend": Report(_host.Suspend(ResolvePid(arg))); return false;
            case "kill": KillWithConfirm(ResolvePid(arg)); return false;
            case "stats": _log.Raw("  " + _host.Stats()); return false;

            case "reload":
                if (_reloadConfig is null) { _log.Raw("  reload not available in this mode."); }
                else { _reloadConfig(); _log.Raw("  config reload requested."); }
                return false;

            case "audit":
                _log.Raw("  " + (_verifyAudit?.Invoke() ?? "audit verification not available."));
                return false;

            // --- v2 -----------------------------------------------------------
            case "tree" or "lineage": RenderLineage(ResolvePid(arg)); return false;
            case "attack" or "mitre": RenderAttack(); return false;
            case "rules": RenderRules(arg); return false;
            case "intel": RenderIntel(); return false;
            case "surface": RenderSurface(arg); return false;
            case "metrics": _log.Raw(_host.Metrics.ToPrometheusText()); return false;
            case "vault": Vault(arg); return false;
            case "isolate": Isolate(arg); return false;
            case "triage": Triage(ResolvePid(arg)); return false;
            case "replay": Replay(arg); return false;
            case "api":
                if (_api is null) _log.Raw("  API Studio is not available in this mode.");
                else _api.Handle(arg);
                return false;

            case "clear" or "cls": try { Console.Clear(); } catch { } return false;
            case "quit" or "exit" or "q": return true;
            default: _log.Raw($"  unknown command '{cmd}'. type 'help'."); return false;
        }
    }

    private void RenderList(bool showAll)
    {
        var snaps = _host.ListProfiles(onlyContained: !showAll);
        _listing = snaps.Select(s => s.Pid).ToList();
        if (_listing.Count == 0)
        {
            _log.Raw(showAll ? "  no flagged processes." : "  no contained processes.");
            return;
        }
        _log.Raw($"  {"#",-3} {"PID",-7} {"SCORE",-6} {"STATE",-20} NAME");
        for (int i = 0; i < snaps.Count; i++)
        {
            var s = snaps[i];
            string state = s.Terminated ? "terminated"
                         : s.SuspendedByAnalyst ? "suspended"
                         : s.Contained ? "contained" : "flagged";
            if (s.Trusted) state += "/trusted";
            _log.Raw($"  {i + 1,-3} {s.Pid,-7} {s.Score,-6} {state,-20} {s.ProcessName}");
        }
        _log.Raw("  (use: info N | resume N | suspend N | kill N)");
    }

    private void KillWithConfirm(int pid)
    {
        Console.Write($"  terminate pid {pid} and its child tree? type 'yes': ");
        string? confirm;
        try { confirm = Console.ReadLine(); } catch { confirm = null; }
        if (!string.Equals(confirm?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
        {
            _log.Raw("  cancelled.");
            return;
        }
        Report(_host.Kill(pid));
    }

    private int ResolvePid(string arg)
    {
        if (string.IsNullOrWhiteSpace(arg))
            throw new ConsoleInputException("missing number. run 'list', then e.g. 'kill 2'.");
        if (arg.StartsWith("pid:", StringComparison.OrdinalIgnoreCase))
        {
            if (int.TryParse(arg.AsSpan(4), out int rawPid) && rawPid > 0) return rawPid;
            throw new ConsoleInputException($"'{arg}' is not a valid pid.");
        }
        if (!int.TryParse(arg, out int index))
            throw new ConsoleInputException($"'{arg}' is not a number.");
        if (_listing.Count == 0)
            throw new ConsoleInputException("no listing yet. run 'list' first.");
        if (index < 1 || index > _listing.Count)
            throw new ConsoleInputException($"index {index} is out of range (1..{_listing.Count}).");
        return _listing[index - 1];
    }

    private void Report(ActionResult r) => _log.Raw("  " + (r.Ok ? r.Message : "error: " + r.Message));

    // ------------------------------------------------------------------ v2 views

    private void RenderLineage(int pid)
    {
        string lineage = _host.Lineage(pid);
        _log.Raw("  " + (string.IsNullOrEmpty(lineage)
            ? $"no lineage recorded for pid {pid} (the process tree only sees starts observed since the agent began)"
            : lineage));
    }

    private void RenderAttack()
    {
        var observed = _host.ObservedTechniques();
        var covered = _composition is null
            ? new Dictionary<string, int>()
            : new RuleEngine(_composition.Rules).TechniqueCoverage();

        if (covered.Count == 0 && observed.Count == 0)
        {
            _log.Raw("  no ATT&CK data: no rules loaded and nothing observed yet.");
            return;
        }

        _log.Raw($"  ATT&CK coverage -- {covered.Count} technique(s) across the loaded rules, " +
                 $"{observed.Count} observed on this host");
        var ids = new SortedSet<string>(covered.Keys, StringComparer.OrdinalIgnoreCase);
        foreach (var id in observed.Keys) ids.Add(id);

        foreach (var group in ids.Select(AttackCatalog.Lookup)
                                 .GroupBy(t => t.Tactic)
                                 .OrderBy(g => Array.IndexOf(AttackCatalog.Tactics, g.Key)))
        {
            _log.Raw($"  {group.Key}");
            foreach (var t in group.OrderBy(t => t.Id, StringComparer.Ordinal))
            {
                covered.TryGetValue(t.Id, out int rules);
                observed.TryGetValue(t.Id, out int seen);
                string mark = seen > 0 ? "*" : " ";
                _log.Raw($"   {mark} {t.Id,-12} {Clip(t.Name, 52),-52} rules={rules} seen={seen}");
            }
        }
        _log.Raw("  (* = observed on this host during this run)");
    }

    private void RenderRules(string arg)
    {
        if (_composition is null) { _log.Raw("  rule inspection is not available in this mode."); return; }
        var set = _composition.Rules;

        if (!string.IsNullOrWhiteSpace(arg))
        {
            var one = set.Rules.FirstOrDefault(r => string.Equals(r.Id, arg, StringComparison.OrdinalIgnoreCase));
            if (one is null) { _log.Raw($"  no rule with id '{arg}'"); return; }
            _log.Raw($"  {one.Id}  [{one.Severity}] +{one.Score}");
            _log.Raw($"  {one.Title}");
            if (!string.IsNullOrWhiteSpace(one.Description)) _log.Raw("  " + one.Description);
            _log.Raw("  techniques : " + string.Join(", ", one.Techniques));
            _log.Raw("  kinds      : " + (one.Kinds.Count == 0 ? "(any)" : string.Join(", ", one.Kinds)));
            foreach (var fp in one.FalsePositives) _log.Raw("  known FP   : " + fp);
            foreach (var r in one.References) _log.Raw("  reference  : " + r);
            return;
        }

        int blocking = set.Errors.Count(e => e.IsBlocking);
        _log.Raw($"  {set.Rules.Count} rule(s) loaded" + (blocking == 0 ? "" : $", {blocking} rejected"));
        foreach (var r in set.Rules.OrderBy(r => r.Id, StringComparer.OrdinalIgnoreCase))
            _log.Raw($"  {r.Id,-42} [{r.Severity,-13}] +{r.Score,-4} {string.Join(",", r.Techniques.Take(3))}");
        foreach (var e in set.Errors.Where(e => e.IsBlocking).Take(10))
            _log.Raw($"  REJECTED {e.RuleId}: {e.Message}");
        _log.Raw("  (use 'rules <id>' for detail; edit rules/detection/*.json and 'reload')");
    }

    private void RenderIntel()
    {
        if (_composition is null) { _log.Raw("  intel status is not available in this mode."); return; }
        int n = _composition.Intel.Count;
        _log.Raw(n == 0
            ? $"  no indicators loaded. drop feeds into '{_composition.Config.Intel.FeedPath}' and 'reload'."
            : $"  {n} indicator(s) loaded from '{_composition.Config.Intel.FeedPath}' " +
              $"(a match scores +{_composition.Config.Intel.HitScore})");
    }

    private void RenderSurface(string arg)
    {
        int pid = 0;
        if (!string.IsNullOrWhiteSpace(arg)) int.TryParse(arg.Trim(), out pid);

        var endpoints = _host.SurfaceEndpoints(pid);
        if (endpoints.Count == 0)
        {
            _log.Raw("  no endpoints observed yet (needs the ETW network/DNS monitors and some traffic).");
            return;
        }

        _log.Raw($"  {"PID",-7} {"PROCESS",-22} {"SCHEME",-7} {"CONNS",-6} {"BEACON",-7} ENDPOINT");
        foreach (var e in endpoints.OrderByDescending(e => e.Connections).Take(60))
        {
            string beacon = e.Beaconing ? $"{e.BeaconConfidence:F2}" : "-";
            string host = e.Host == e.Address ? e.Address : $"{e.Host} [{e.Address}]";
            _log.Raw($"  {e.Pid,-7} {Clip(e.ProcessName, 22),-22} {e.Scheme,-7} {e.Connections,-6} {beacon,-7} {host}:{e.Port}");
        }
        _log.Raw("  (use 'api surface' to turn these into an inspectable API collection)");
    }

    // ---------------------------------------------------------------- v2 actions

    private void Vault(string arg)
    {
        var vault = _composition?.Vault;
        if (vault is null) { _log.Raw("  the encrypted quarantine vault is disabled in config."); return; }

        var parts = arg.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string sub = parts.Length > 0 ? parts[0].ToLowerInvariant() : "list";

        switch (sub)
        {
            case "restore" when parts.Length >= 3:
                _log.Raw(vault.Restore(parts[1], Path.GetFullPath(parts[2]), out var rerr)
                    ? $"  restored {parts[1]} -> {parts[2]}"
                    : "  restore failed: " + rerr);
                return;
            case "purge" when parts.Length >= 2:
                _log.Raw(vault.Purge(parts[1], out var perr) ? $"  purged {parts[1]}" : "  purge failed: " + perr);
                return;
            case "verify" when parts.Length >= 2:
                _log.Raw(vault.VerifyIntegrity(parts[1], out var verr)
                    ? $"  {parts[1]}: intact (decrypts and re-hashes to the recorded digest)"
                    : $"  {parts[1]}: FAILED -- {verr}");
                return;
            default:
            {
                var entries = vault.List();
                if (entries.Count == 0) { _log.Raw("  vault is empty."); return; }
                _log.Raw($"  {entries.Count} item(s), {vault.TotalBytes / 1024} KiB encrypted at rest");
                _log.Raw($"  {"ID",-30} {"PID",-7} {"SIZE",-10} ORIGINAL");
                foreach (var e in entries)
                    _log.Raw($"  {e.Id,-30} {e.Pid,-7} {e.OriginalSize,-10} " +
                             $"{Clip(e.OriginalPath, 70)}{(e.Restored ? "  (restored)" : "")}");
                _log.Raw("  (vault restore <id> <path> | vault verify <id> | vault purge <id>)");
                return;
            }
        }
    }

    private void Isolate(string arg)
    {
        var isolation = _composition?.Isolation;
        if (isolation is null) { _log.Raw("  host isolation is not available in this mode."); return; }

        string sub = arg.Trim().ToLowerInvariant();
        if (sub is "off" or "release")
        {
            Report(isolation.Release());
            return;
        }
        if (sub is not ("on" or ""))
        {
            _log.Raw("  usage: isolate [on|off]");
            return;
        }

        var allow = _composition!.Config.Response.IsolationAllowlist ?? Array.Empty<string>();
        _log.Raw($"  This blocks ALL network traffic except {allow.Length} allowlisted address(es).");
        if (allow.Length == 0)
            _log.Raw("  The allowlist is EMPTY: you will lose any remote session to this machine.");
        Console.Write("  type 'yes' to isolate this host: ");
        string? confirm;
        try { confirm = Console.ReadLine(); } catch { confirm = null; }
        if (!string.Equals(confirm?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
        {
            _log.Raw("  cancelled.");
            return;
        }
        Report(isolation.Isolate(allow));
    }

    private void Triage(int pid)
    {
        if (_composition is null) { _log.Raw("  triage collection is not available in this mode."); return; }
        string dir = Composition.ResolvePath(_composition.Config.Response.TriageOutputPath);
        var snapshot = _host.ListProfiles(onlyContained: false).FirstOrDefault(p => p.Pid == pid);
        var result = new TriageCollector().Collect(pid, dir, snapshot);
        _log.Raw(result.Ok
            ? $"  triage package: {result.ZipPath} ({result.Bytes} bytes, " +
              $"{result.Included.Count} item(s), {result.Skipped.Count} skipped)"
            : "  triage failed: " + result.Error);
        foreach (var s in result.Skipped.Take(8)) _log.Raw("    skipped: " + s);
    }

    private void Replay(string arg)
    {
        if (string.IsNullOrWhiteSpace(arg))
        {
            _log.Raw("  usage: replay <scenario.jsonl>   (see Replay/scenarios/)");
            return;
        }
        string path = Path.GetFullPath(arg.Trim().Trim('"'));
        if (!File.Exists(path)) { _log.Raw($"  no such scenario: {path}"); return; }

        // Replay runs a throwaway engine against a simulated clock. It never touches the
        // live agent's state, so it is safe to run mid-incident.
        try
        {
            var scenario = TraceFormat.Load(path);
            var rules = _composition?.Rules;
            var replay = new TraceReplay(clock => new ConsoleReplayEngine(clock, rules));
            var result = replay.Run(scenario);
            foreach (var line in result.Summary.Split('\n')) _log.Raw("  " + line.TrimEnd());
        }
        catch (Exception ex) { _log.Raw("  replay failed: " + ex.Message); }
    }

    private static string Clip(string s, int max)
        => string.IsNullOrEmpty(s) ? "" : s.Length <= max ? s : s[..(max - 1)] + "…";

    private void PrintHelp()
    {
        _log.Raw(
            "\n  ProcessShield analyst console\n" +
            "  ---------------------------------------------------------------\n" +
            "  list [all]   show contained (or all flagged) processes\n" +
            "  info N       full reason breakdown for entry N\n" +
            "  resume N     un-suspend entry N (release a false positive)\n" +
            "  suspend N    re-suspend entry N\n" +
            "  kill N       terminate entry N (asks for confirmation)\n" +
            "  tree N       process ancestry for entry N\n" +
            "  stats        engine / queue counters\n" +
            "  metrics      Prometheus exposition of the same counters\n" +
            "  reload       re-read shield.config.json (incl. rules and intel feeds)\n" +
            "  audit        verify the tamper-evident audit log\n" +
            "\n" +
            "  attack       MITRE ATT&CK coverage vs. what has been observed\n" +
            "  rules [id]   list loaded detection rules, or show one in detail\n" +
            "  intel        indicator-feed status\n" +
            "  surface [pid] endpoints this host has been seen talking to\n" +
            "  api ...      API Studio: import, send, assert, grade, export ('api help')\n" +
            "\n" +
            "  vault ...    encrypted quarantine: list | restore <id> <path> | verify <id> | purge <id>\n" +
            "  isolate on|off   cut this host off the network except the config allowlist\n" +
            "  triage N     collect a forensic package for entry N\n" +
            "  replay <f>   replay a detection scenario offline against a throwaway engine\n" +
            "\n" +
            "  clear        clear the screen\n" +
            "  quit         stop the agent and exit\n" +
            "  (N is the number from the last 'list'; or use pid:1234)\n");
    }
}

/// <summary>
/// Throwaway engine used by the console's <c>replay</c> command. It mirrors the adapter in
/// <see cref="SelfTest"/> but is built from whatever rules the live agent currently has
/// loaded, so an analyst can check a rule edit against a scenario without restarting.
/// </summary>
internal sealed class ConsoleReplayEngine : IReplayEngine
{
    private readonly DetectionEngine _engine;

    public ConsoleReplayEngine(ManualClock clock, RuleSet? rules)
    {
        var deps = new EngineDependencies
        {
            Clock = clock,
            Tree = new ProcessTree(clock),
            Beacons = new BeaconAnalyzer(clock),
            Rules = rules is null ? null : new RuleEngine(rules)
        };
        _engine = new DetectionEngine(
            new EngineOptions
            {
                WarnThreshold = 40,
                QuarantineThreshold = 70,
                CorrelationWindow = TimeSpan.FromSeconds(30),
                TrustDiscount = 30
            },
            _ => false,
            deps);
    }

    public IReadOnlyList<ReplayVerdict> Feed(Signal signal)
    {
        var verdicts = _engine.Ingest(signal);
        if (verdicts.Count == 0) return Array.Empty<ReplayVerdict>();
        var list = new List<ReplayVerdict>(verdicts.Count);
        foreach (var v in verdicts)
            list.Add(new ReplayVerdict
            {
                AtUtc = signal.TimestampUtc,
                Pid = v.Snapshot.Pid,
                Verdict = v.Verdict.ToString(),
                Trigger = v.Trigger,
                Score = v.Snapshot.Score,
                Techniques = v.Snapshot.Techniques,
                Reasons = v.Snapshot.Reasons
            });
        return list;
    }

    public IReadOnlyDictionary<int, int> Scores() => _engine.AllScores();
}

internal sealed class ConsoleInputException : Exception
{
    public ConsoleInputException(string message) : base(message) { }
}
