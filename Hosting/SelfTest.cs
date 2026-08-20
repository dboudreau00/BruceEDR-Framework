using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Replay;

namespace ProcessShield.Hosting;

/// <summary>
/// Everything ProcessShield can verify about itself without Administrator rights, a live
/// ETW session or a real threat: the shipped detection rule packs parse and validate, and
/// every replay scenario still produces the verdicts it is supposed to.
///
/// This is what <c>tools/verify.ps1</c> and CI run, and it is the loop a rule author uses
/// while iterating: edit a JSON rule, run <c>ProcessShield.exe --selftest</c>, see whether
/// the malicious scenarios still fire and the benign one still stays quiet.
/// </summary>
public static class SelfTest
{
    /// <summary>
    /// Process exit code: 0 when everything passed.
    /// </summary>
    /// <param name="allowEmpty">
    /// Accept a run that found no rule directory and/or no scenarios. Off by default: a
    /// self-test that validated nothing must not report PASS, because CI and
    /// <c>tools/verify.ps1</c> read that exit code as "the shipped content is good". The
    /// same switch is honoured as <c>--allow-empty</c> on the process command line, since
    /// the argument dispatcher forwards only the two path options.
    /// </param>
    public static int Run(string? rulesPath = null, string? scenariosPath = null,
        TextWriter? outWriter = null, bool allowEmpty = false)
    {
        var w = outWriter ?? Console.Out;
        int failures = 0;
        bool allow = allowEmpty || CommandLineAllowsEmpty();

        w.WriteLine("ProcessShield self-test");
        w.WriteLine("=======================");
        w.WriteLine();

        var rulesDir = Resolve(rulesPath, "rules/detection");
        failures += CheckRules(rulesDir, w, allow);

        w.WriteLine();
        var scenarioDir = Resolve(scenariosPath, "Replay/scenarios");
        failures += CheckScenarios(scenarioDir, rulesDir, w, allow);

        w.WriteLine();
        w.WriteLine(failures == 0
            ? (allow ? "self-test PASSED (--allow-empty: missing content was tolerated)" : "self-test PASSED")
            : $"self-test FAILED with {failures} problem(s)");
        return failures == 0 ? 0 : 1;
    }

    /// <summary>True when the process was started with <c>--allow-empty</c>.</summary>
    private static bool CommandLineAllowsEmpty()
    {
        try
        {
            foreach (var a in Environment.GetCommandLineArgs())
                if (string.Equals(a, "--allow-empty", StringComparison.OrdinalIgnoreCase)) return true;
        }
        catch { /* nothing readable: treat as not set, i.e. the strict default */ }
        return false;
    }

    // ------------------------------------------------------------------- rules

    private static int CheckRules(string? dir, TextWriter w, bool allowEmpty)
    {
        w.WriteLine("[1] detection rule packs");
        if (dir is null)
        {
            if (allowEmpty)
            {
                w.WriteLine("    no rules/detection directory found; skipped (--allow-empty)");
                return 0;
            }
            w.WriteLine("    FAIL: no rules/detection directory found, so no rule pack was validated.");
            w.WriteLine("          Point --rules at the directory, or pass --allow-empty to accept this.");
            return 1;
        }

        var set = RuleEngine.LoadDirectory(dir, m => w.WriteLine("    warn: " + m));
        w.WriteLine($"    directory : {dir}");
        w.WriteLine($"    rules     : {set.Rules.Count}");

        // Only blocking errors fail the self-test. A note-level entry (an ATT&CK id this
        // build's table does not know yet, say) is surfaced but must not stop a rule
        // author whose technique is newer than the local catalog.
        var blocking = set.BlockingErrors.ToArray();
        var notes = set.Errors.Where(e => !e.IsBlocking).ToArray();

        w.WriteLine($"    errors    : {(blocking.Length == 0 ? "none" : blocking.Length.ToString())}");
        foreach (var e in blocking.Take(25))
            w.WriteLine($"      - [{e.RuleId}] {e.Message}");
        if (blocking.Length > 25) w.WriteLine($"      ... and {blocking.Length - 25} more");

        if (notes.Length > 0)
        {
            w.WriteLine($"    notes     : {notes.Length}");
            foreach (var e in notes.Take(10)) w.WriteLine($"      - [{e.RuleId}] {e.Message}");
        }

        int failures = blocking.Length;

        if (set.Rules.Count == 0)
        {
            w.WriteLine("    FAIL: the rule directory exists but produced zero usable rules");
            return failures + 1;
        }

        var engine = new RuleEngine(set);
        var coverage = engine.TechniqueCoverage();
        var tactics = coverage.Keys
            .Select(AttackCatalog.Lookup)
            .GroupBy(t => t.Tactic)
            .OrderBy(g => Array.IndexOf(AttackCatalog.Tactics, g.Key))
            .ToArray();

        w.WriteLine($"    ATT&CK    : {coverage.Count} technique(s) across {tactics.Length} tactic(s)");
        foreach (var g in tactics)
            w.WriteLine($"      {g.Key,-22} {string.Join(" ", g.Select(t => t.Id).OrderBy(x => x, StringComparer.Ordinal))}");

        var unmapped = coverage.Keys.Where(id => !AttackCatalog.IsKnown(id)).ToArray();
        if (unmapped.Length > 0)
            w.WriteLine($"    note      : {unmapped.Length} technique id(s) not in the local ATT&CK table: " +
                        string.Join(", ", unmapped));

        return failures;
    }

    // --------------------------------------------------------------- scenarios

    private static int CheckScenarios(string? dir, string? rulesDir, TextWriter w, bool allowEmpty)
    {
        w.WriteLine("[2] replay scenarios");
        if (dir is null)
        {
            if (allowEmpty)
            {
                w.WriteLine("    no Replay/scenarios directory found; skipped (--allow-empty)");
                return 0;
            }
            w.WriteLine("    FAIL: no Replay/scenarios directory found, so no detection was exercised.");
            w.WriteLine("          Point --scenarios at the directory, or pass --allow-empty to accept this.");
            return 1;
        }

        string[] files;
        try { files = Directory.GetFiles(dir, "*.jsonl", SearchOption.AllDirectories); }
        catch (Exception ex) { w.WriteLine("    FAIL: " + ex.Message); return 1; }

        if (files.Length == 0)
        {
            if (allowEmpty)
            {
                w.WriteLine($"    {dir} contains no .jsonl scenarios; skipped (--allow-empty)");
                return 0;
            }
            w.WriteLine($"    FAIL: {dir} contains no .jsonl scenarios, so no detection was exercised.");
            w.WriteLine("          Pass --allow-empty to accept this.");
            return 1;
        }

        Array.Sort(files, StringComparer.OrdinalIgnoreCase);

        RuleSet? rules = rulesDir is null ? null : RuleEngine.LoadDirectory(rulesDir);
        int failures = 0;

        foreach (var file in files)
        {
            TraceScenario scenario;
            try { scenario = TraceFormat.Load(file); }
            catch (Exception ex)
            {
                w.WriteLine($"    {Path.GetFileName(file),-32} PARSE FAILED: {ex.Message}");
                failures++;
                continue;
            }

            var replay = new TraceReplay(clock => new DetectionReplayEngine(clock, rules));
            var result = replay.Run(scenario);

            w.WriteLine($"    {Path.GetFileName(file),-32} {(result.Success ? "PASS" : "FAIL")} " +
                        $"({result.SignalsFed} signals, {result.Verdicts.Count} verdict(s))");
            if (result.Success) continue;

            failures++;
            foreach (var unmet in result.UnmetExpectations)
                w.WriteLine($"        unmet: {unmet}");
        }

        return failures;
    }

    /// <summary>
    /// Adapts the real <see cref="DetectionEngine"/> to the replay harness's narrow
    /// interface. The harness deliberately does not depend on the engine's concrete shape,
    /// so this adapter is the single place the two meet.
    /// </summary>
    private sealed class DetectionReplayEngine : IReplayEngine
    {
        private readonly DetectionEngine _engine;

        public DetectionReplayEngine(ManualClock clock, RuleSet? rules)
        {
            var tree = new ProcessTree(clock);
            var deps = new EngineDependencies
            {
                Clock = clock,
                Tree = tree,
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
                // Replay has no real processes, so nothing is Authenticode-trusted. A
                // scenario that needs a trusted process can model it with a negative-score
                // allowlist rule instead, which is deterministic.
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

    // ----------------------------------------------------------------- helpers

    /// <summary>
    /// Resolves a content directory. Prefers an explicit path, then the directory next to
    /// the executable (the published layout), then walks up from the executable looking for
    /// the repository layout, so the same command works from bin/ and from a source tree.
    ///
    /// The upward walk is safe HERE and only here: --selftest is an offline developer/CI
    /// command that starts no monitor and runs at the invoking user's own privilege. The
    /// running agent deliberately does NOT use this method (see Composition.ResolveContentDir),
    /// because a SYSTEM-level service walking up from C:\Program Files\ would happily load a
    /// rule pack planted by a standard user.
    /// </summary>
    internal static string? Resolve(string? explicitPath, string relative)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return Directory.Exists(explicitPath) ? Path.GetFullPath(explicitPath) : null;

        var candidate = Path.Combine(AppContext.BaseDirectory, relative);
        if (Directory.Exists(candidate)) return Path.GetFullPath(candidate);

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int depth = 0; depth < 8 && dir is not null; depth++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, relative);
            if (Directory.Exists(probe)) return Path.GetFullPath(probe);
        }
        return null;
    }
}
