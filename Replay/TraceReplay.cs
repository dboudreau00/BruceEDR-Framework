using System.Globalization;
using System.Text;
using ProcessShield.Core;

namespace ProcessShield.Replay;

/// <summary>
/// One verdict observed during a replay, flattened to primitives.
/// </summary>
/// <remarks>
/// Deliberately NOT <c>DetectionResult</c>. Replay is the harness that detection
/// contributions are reviewed with, so it must not force every adapter to construct the
/// engine's internal snapshot types; <see cref="Verdict"/> is a string for the same
/// reason (an adapter can report a verdict name the enum does not have yet without a
/// cast that throws).
/// </remarks>
public sealed record ReplayVerdict
{
    /// <summary>
    /// Simulated time the verdict was raised. Left at <c>default</c> by an adapter that
    /// does not track it; <see cref="TraceReplay.Run"/> then fills it from the replay clock.
    /// </summary>
    public DateTime AtUtc { get; init; }

    /// <summary>Process the verdict is about.</summary>
    public required int Pid { get; init; }

    /// <summary>Verdict name: <c>Allow</c>, <c>Warn</c> or <c>Quarantine</c>, case-insensitive.</summary>
    public required string Verdict { get; init; }

    /// <summary>What caused the engine to re-decide, e.g. the signal kind or a rule id.</summary>
    public string Trigger { get; init; } = "";

    /// <summary>Score at the moment of the verdict.</summary>
    public int Score { get; init; }

    /// <summary>MITRE ATT&amp;CK technique ids cited by this verdict.</summary>
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();

    /// <summary>Rendered reason lines, for the human-readable report.</summary>
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
}

/// <summary>Outcome of replaying one scenario: what happened, and whether it was expected.</summary>
public sealed record ReplayResult
{
    public string Scenario { get; init; } = "";

    /// <summary>Steps actually handed to the engine.</summary>
    public int SignalsFed { get; init; }

    /// <summary>Offset of the last step fed, i.e. how much simulated time elapsed.</summary>
    public TimeSpan SimulatedDuration { get; init; }

    public IReadOnlyList<ReplayVerdict> Verdicts { get; init; } = Array.Empty<ReplayVerdict>();

    /// <summary>Each failed expectation, as <c>"&lt;expectation&gt; -- &lt;reason&gt;"</c>.</summary>
    public IReadOnlyList<string> UnmetExpectations { get; init; } = Array.Empty<string>();

    /// <summary>Per-pid score at the end of the run, snapshotted away from the engine.</summary>
    public IReadOnlyDictionary<int, int> FinalScores { get; init; } = new Dictionary<int, int>();

    /// <summary>True only when every expectation held.</summary>
    public bool Success { get; init; }

    /// <summary>Multi-line report suitable for writing straight to a console or a CI log.</summary>
    public string Summary { get; init; } = "";
}

/// <summary>
/// The detection engine as replay needs to see it. Keeping the surface this small is what
/// lets a scenario be replayed against the real <c>DetectionEngine</c>, against a
/// rules-only engine, or against a stub in a unit test, without the trace files caring.
/// </summary>
public interface IReplayEngine
{
    /// <summary>Feed one signal and return any verdicts it produced (possibly none).</summary>
    IReadOnlyList<ReplayVerdict> Feed(Signal signal);

    /// <summary>
    /// Current score per pid. Read once, at the end of the run.
    /// </summary>
    /// <remarks>
    /// Implementations should report EVERY pid they built state for, including ones still
    /// scoring zero. A <c>score&lt;n:pid=…</c> expectation fails on a pid that is absent
    /// (see <see cref="Expectation"/>), so omitting quiet processes would make it
    /// impossible to assert that a benign process stayed quiet -- which is precisely what
    /// the false-positive regression scenario needs to say.
    /// </remarks>
    IReadOnlyDictionary<int, int> Scores();
}

/// <summary>
/// Replays a <see cref="TraceScenario"/> through an engine on a
/// <see cref="ManualClock"/>, so a multi-minute attack chain is evaluated in
/// milliseconds and always the same way.
/// </summary>
/// <remarks>
/// What this DOES prove: that the detection logic reaches the stated verdicts for the
/// stated signal sequence, deterministically, with no processes, no network and no admin
/// rights. What it does NOT prove: that the monitors would actually emit those signals on
/// a live host. Replay tests rule logic, not telemetry coverage -- a technique that ETW
/// never surfaces will pass here and miss in production. Recorded traces
/// (<see cref="TraceFormat.FromSignals"/>) narrow that gap; synthesised ones do not.
/// </remarks>
public sealed class TraceReplay
{
    private readonly Func<ManualClock, IReplayEngine> _engineFactory;

    /// <param name="engineFactory">
    /// Builds the engine under test around the replay clock. A factory (rather than an
    /// engine instance) is required so each run starts from clean state -- reusing one
    /// engine across scenarios would let a previous trace's profiles change the verdicts
    /// of the next, which is exactly the kind of order dependence a regression suite
    /// must not have.
    /// </param>
    public TraceReplay(Func<ManualClock, IReplayEngine> engineFactory)
        => _engineFactory = engineFactory ?? throw new ArgumentNullException(nameof(engineFactory));

    /// <summary>
    /// Run one scenario: advance the clock to each step's offset, feed the signal, collect
    /// verdicts, then evaluate the scenario's expectations.
    /// </summary>
    /// <remarks>
    /// An exception thrown by the engine is deliberately NOT caught. A crash inside
    /// detection is the most serious thing a replay can find, and swallowing it into a
    /// "failed expectation" would bury the stack trace that identifies it.
    /// </remarks>
    public ReplayResult Run(TraceScenario scenario)
    {
        ArgumentNullException.ThrowIfNull(scenario);

        var clock = new ManualClock(scenario.StartUtc);
        var engine = _engineFactory(clock)
            ?? throw new InvalidOperationException("the engine factory returned null; replay has nothing to feed");

        var verdicts = new List<ReplayVerdict>();
        var cursor = TimeSpan.Zero;
        int fed = 0;

        foreach (var step in scenario.Events)
        {
            if (step is null) continue;

            // Only ever forward. Parse guarantees non-decreasing offsets, but a scenario
            // built in code can violate that, and a rewound clock would corrupt every
            // correlation window in the engine rather than fail loudly.
            if (step.At > cursor)
            {
                clock.Advance(step.At - cursor);
                cursor = step.At;
            }

            fed++;
            var produced = engine.Feed(step.Signal);
            if (produced is null) continue;
            foreach (var v in produced)
            {
                if (v is null) continue;
                verdicts.Add(v.AtUtc == default ? v with { AtUtc = clock.UtcNow } : v);
            }
        }

        // Snapshot the scores: an engine may hand back a live view of its own dictionary,
        // and a ReplayResult that mutates after the run is useless as evidence.
        var scores = new Dictionary<int, int>();
        var reported = engine.Scores();
        if (reported is not null)
            foreach (var kv in reported) scores[kv.Key] = kv.Value;

        var unmet = new List<string>();
        foreach (var expectation in scenario.Expect)
        {
            string? reason = Expectation.Check(expectation, verdicts, scores);
            if (reason is not null) unmet.Add($"{expectation} -- {reason}");
        }

        var result = new ReplayResult
        {
            Scenario = scenario.Name,
            SignalsFed = fed,
            SimulatedDuration = cursor,
            Verdicts = verdicts,
            UnmetExpectations = unmet,
            FinalScores = scores,
            Success = unmet.Count == 0
        };

        return result with { Summary = BuildSummary(scenario, result) };
    }

    private const int MaxVerdictLines = 40;

    private static string BuildSummary(TraceScenario scenario, ReplayResult r)
    {
        var sb = new StringBuilder();
        sb.Append("Replay: ").AppendLine(string.IsNullOrEmpty(r.Scenario) ? "(unnamed)" : r.Scenario);
        if (!string.IsNullOrWhiteSpace(scenario.Description))
            sb.Append("  note       ").AppendLine(scenario.Description);
        sb.Append("  start      ").AppendLine(scenario.StartUtc.ToString("O", CultureInfo.InvariantCulture));
        sb.Append("  signals    ")
          .Append(r.SignalsFed.ToString(CultureInfo.InvariantCulture))
          .Append(" fed over ")
          .Append(Offset(r.SimulatedDuration))
          .AppendLine(" simulated");

        sb.Append("  verdicts   ").AppendLine(r.Verdicts.Count.ToString(CultureInfo.InvariantCulture));
        int shown = 0;
        foreach (var v in r.Verdicts)
        {
            if (shown++ == MaxVerdictLines)
            {
                sb.Append("    ... and ")
                  .Append((r.Verdicts.Count - MaxVerdictLines).ToString(CultureInfo.InvariantCulture))
                  .AppendLine(" more");
                break;
            }
            sb.Append("    +").Append(Offset(v.AtUtc - scenario.StartUtc))
              .Append("  ").Append(v.Verdict.ToUpperInvariant().PadRight(10))
              .Append(" pid ").Append(v.Pid.ToString(CultureInfo.InvariantCulture).PadRight(6))
              .Append(" score ").Append(v.Score.ToString(CultureInfo.InvariantCulture).PadRight(5));
            if (!string.IsNullOrEmpty(v.Trigger)) sb.Append(" trigger=").Append(v.Trigger);
            if (v.Techniques.Count != 0) sb.Append(' ').Append(string.Join(",", v.Techniques));
            sb.AppendLine();
        }

        sb.Append("  scores     ").AppendLine(
            r.FinalScores.Count == 0
                ? "(none reported)"
                : string.Join(", ", r.FinalScores.OrderBy(kv => kv.Key)
                    .Select(kv => $"{kv.Key}={kv.Value}")));

        int checkedCount = scenario.Expect.Count;
        sb.Append("  expect     ")
          .Append(checkedCount.ToString(CultureInfo.InvariantCulture))
          .Append(" checked, ")
          .Append(r.UnmetExpectations.Count.ToString(CultureInfo.InvariantCulture))
          .AppendLine(" unmet");
        foreach (var u in r.UnmetExpectations) sb.Append("    FAIL  ").AppendLine(u);

        sb.Append("  RESULT: ").Append(r.Success ? "PASS" : "FAIL");
        if (!r.Success)
            sb.Append(" (").Append(r.UnmetExpectations.Count.ToString(CultureInfo.InvariantCulture))
              .Append(r.UnmetExpectations.Count == 1 ? " expectation unmet)" : " expectations unmet)");
        sb.AppendLine();
        return sb.ToString();
    }

    private static string Offset(TimeSpan t)
        => (t < TimeSpan.Zero ? "-" : "") + t.Duration().ToString(@"hh\:mm\:ss\.fff", CultureInfo.InvariantCulture);
}

/// <summary>
/// The expectation mini-language a scenario asserts itself with.
///
/// <code>
///   quarantine:pid=4242     a Quarantine verdict was raised for that pid
///   warn:pid=4242           a Warn-or-higher verdict was raised for that pid
///   no-quarantine:pid=900   no Quarantine verdict for that pid
///   score&gt;=70:pid=4242      final score comparison; &gt;=, &gt;, &lt;=, &lt;, == (and = as an alias)
///   technique:T1059.001     some verdict cited that ATT&amp;CK technique
///   verdicts&lt;=3             bound on the total number of verdicts
/// </code>
///
/// Design decisions worth knowing:
/// <list type="bullet">
///   <item><description><c>warn:</c> is satisfied by a Quarantine too. An expectation that
///   said "warn and nothing stronger" would break every time a rule was legitimately
///   sharpened; use <c>no-quarantine:</c> when the point really is that it must not escalate.</description></item>
///   <item><description>A <c>score</c> expectation on a pid the engine never scored FAILS,
///   rather than treating the missing pid as 0. A typo in a pid must never make a
///   regression test pass, and <c>score&lt;40:pid=&lt;typo&gt;</c> would otherwise be vacuously
///   true forever.</description></item>
///   <item><description>An unparsable expectation FAILS with an explanation. Silently
///   ignoring a misspelt assertion is the worst outcome available to a test harness.</description></item>
/// </list>
/// </summary>
public static class Expectation
{
    private static readonly IReadOnlyDictionary<int, int> NoScores = new Dictionary<int, int>();
    private static readonly IReadOnlyList<ReplayVerdict> NoVerdicts = Array.Empty<ReplayVerdict>();

    private enum Op { Ge, Gt, Le, Lt, Eq }

    private enum Form { Quarantine, Warn, NoQuarantine, Score, Technique, VerdictCount }

    private readonly record struct Parsed(Form Form, int Pid, Op Op, int Value, string Technique);

    /// <summary>
    /// Grammar check only, with no verdicts to evaluate against. Used by the scenario
    /// linter so a pull request that misspells an expectation is caught at review time
    /// rather than becoming an assertion that can never hold.
    /// </summary>
    public static bool IsWellFormed(string expectation, out string error)
        => TryParse(expectation, out _, out error);

    /// <summary>
    /// Evaluate one expectation. Returns <c>null</c> when it holds, or a short human
    /// explanation of why it did not (including "this is not valid syntax").
    /// </summary>
    public static string? Check(
        string expectation,
        IReadOnlyList<ReplayVerdict>? verdicts,
        IReadOnlyDictionary<int, int>? finalScores)
    {
        verdicts ??= NoVerdicts;
        finalScores ??= NoScores;

        if (!TryParse(expectation, out var p, out string error)) return error;

        switch (p.Form)
        {
            case Form.Quarantine:
                foreach (var v in verdicts)
                    if (v.Pid == p.Pid && Rank(v.Verdict) == 2) return null;
                return $"no Quarantine verdict for pid {p.Pid} (highest seen for that pid: {Highest(verdicts, p.Pid)})";

            case Form.Warn:
                foreach (var v in verdicts)
                    if (v.Pid == p.Pid && Rank(v.Verdict) >= 1) return null;
                return $"no Warn-or-higher verdict for pid {p.Pid} (highest seen for that pid: {Highest(verdicts, p.Pid)})";

            case Form.NoQuarantine:
                foreach (var v in verdicts)
                    if (v.Pid == p.Pid && Rank(v.Verdict) == 2)
                        return $"pid {p.Pid} WAS quarantined at {v.AtUtc.ToString("O", CultureInfo.InvariantCulture)} " +
                               $"(trigger '{v.Trigger}', score {v.Score})";
                return null;

            case Form.Score:
                if (!finalScores.TryGetValue(p.Pid, out int score))
                    return $"no final score recorded for pid {p.Pid}; the engine never scored that process " +
                           "(check the pid -- a typo here would otherwise pass silently)";
                return Compare(score, p.Op, p.Value)
                    ? null
                    : $"final score for pid {p.Pid} is {score}, expected {Symbol(p.Op)}{p.Value}";

            case Form.Technique:
                foreach (var v in verdicts)
                    foreach (var t in v.Techniques)
                        if (string.Equals(t, p.Technique, StringComparison.OrdinalIgnoreCase)) return null;
                return $"no verdict cited technique {p.Technique} (cited: {Cited(verdicts)})";

            default:
                int n = verdicts.Count;
                return Compare(n, p.Op, p.Value)
                    ? null
                    : $"verdict count is {n}, expected {Symbol(p.Op)}{p.Value}";
        }
    }

    // ------------------------------------------------------------------ parsing

    private static bool TryParse(string? raw, out Parsed parsed, out string error)
    {
        parsed = default;
        error = "";

        string e = (raw ?? "").Trim();
        if (e.Length == 0) { error = "empty expectation"; return false; }

        int colon = e.IndexOf(':');
        string head = (colon < 0 ? e : e[..colon]).Trim();
        string tail = colon < 0 ? "" : e[(colon + 1)..].Trim();
        string h = head.ToLowerInvariant();

        switch (h)
        {
            case "quarantine":
            case "warn":
            case "no-quarantine":
            {
                if (!TryPid(tail, out int pid, out error)) return false;
                var form = h switch
                {
                    "quarantine" => Form.Quarantine,
                    "warn" => Form.Warn,
                    _ => Form.NoQuarantine
                };
                parsed = new Parsed(form, pid, Op.Ge, 0, "");
                return true;
            }

            case "technique":
            {
                if (tail.Length == 0) { error = "expected 'technique:<ATT&CK id>'"; return false; }
                if (tail.Any(char.IsWhiteSpace)) { error = $"'{tail}' is not a single technique id"; return false; }
                parsed = new Parsed(Form.Technique, 0, Op.Ge, 0, tail.ToUpperInvariant());
                return true;
            }
        }

        if (h.StartsWith("score", StringComparison.Ordinal))
        {
            if (!TryComparison(head, "score", out var op, out int value, out error)) return false;
            if (!TryPid(tail, out int pid, out error)) return false;
            parsed = new Parsed(Form.Score, pid, op, value, "");
            return true;
        }

        if (h.StartsWith("verdicts", StringComparison.Ordinal))
        {
            if (!TryComparison(head, "verdicts", out var op, out int value, out error)) return false;
            if (tail.Length != 0)
            {
                error = $"'verdicts' counts every verdict and takes no ':' suffix (found ':{tail}')";
                return false;
            }
            parsed = new Parsed(Form.VerdictCount, 0, op, value, "");
            return true;
        }

        error = $"unrecognised expectation keyword '{head}'; expected one of " +
                "quarantine, warn, no-quarantine, score<op><n>, technique, verdicts<op><n>";
        return false;
    }

    private static bool TryComparison(string head, string keyword, out Op op, out int value, out string error)
    {
        op = Op.Ge;
        value = 0;
        error = "";

        string rest = head[keyword.Length..].Trim();
        int opLen;
        if (rest.StartsWith(">=", StringComparison.Ordinal)) { op = Op.Ge; opLen = 2; }
        else if (rest.StartsWith("<=", StringComparison.Ordinal)) { op = Op.Le; opLen = 2; }
        else if (rest.StartsWith("==", StringComparison.Ordinal)) { op = Op.Eq; opLen = 2; }
        else if (rest.StartsWith(">", StringComparison.Ordinal)) { op = Op.Gt; opLen = 1; }
        else if (rest.StartsWith("<", StringComparison.Ordinal)) { op = Op.Lt; opLen = 1; }
        else if (rest.StartsWith("=", StringComparison.Ordinal)) { op = Op.Eq; opLen = 1; }
        else
        {
            error = $"'{keyword}' needs a comparison operator: >=, >, <=, < or == (found '{rest}')";
            return false;
        }

        string num = rest[opLen..].Trim();
        if (num.Length == 0)
        {
            error = $"'{keyword}{rest}' is missing the number to compare against";
            return false;
        }
        if (!int.TryParse(num, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
        {
            error = $"'{num}' is not a whole number";
            return false;
        }
        return true;
    }

    private static bool TryPid(string tail, out int pid, out string error)
    {
        pid = 0;
        error = "";
        if (tail.Length == 0) { error = "expected ':pid=<number>'"; return false; }

        int eq = tail.IndexOf('=');
        if (eq < 0) { error = $"expected 'pid=<number>', found '{tail}'"; return false; }

        string key = tail[..eq].Trim();
        string val = tail[(eq + 1)..].Trim();
        if (!key.Equals("pid", StringComparison.OrdinalIgnoreCase))
        {
            error = $"expected 'pid=', found '{key}='";
            return false;
        }
        if (!int.TryParse(val, NumberStyles.Integer, CultureInfo.InvariantCulture, out pid) || pid < 0)
        {
            error = $"'{val}' is not a valid pid";
            return false;
        }
        return true;
    }

    // ------------------------------------------------------------------ evaluation helpers

    private static bool Compare(int actual, Op op, int expected) => op switch
    {
        Op.Ge => actual >= expected,
        Op.Gt => actual > expected,
        Op.Le => actual <= expected,
        Op.Lt => actual < expected,
        _ => actual == expected
    };

    private static string Symbol(Op op) => op switch
    {
        Op.Ge => ">=",
        Op.Gt => ">",
        Op.Le => "<=",
        Op.Lt => "<",
        _ => "=="
    };

    /// <summary>Allow=0, Warn=1, Quarantine=2; anything unrecognised is -1 and satisfies nothing.</summary>
    private static int Rank(string? verdict) => (verdict ?? "").Trim().ToLowerInvariant() switch
    {
        "quarantine" => 2,
        "warn" => 1,
        "allow" => 0,
        _ => -1
    };

    private static string Highest(IReadOnlyList<ReplayVerdict> verdicts, int pid)
    {
        string best = "none";
        int bestRank = int.MinValue;
        foreach (var v in verdicts)
        {
            if (v.Pid != pid) continue;
            int r = Rank(v.Verdict);
            if (r <= bestRank) continue;
            bestRank = r;
            best = string.IsNullOrWhiteSpace(v.Verdict) ? "(blank)" : v.Verdict;
        }
        return best;
    }

    private static string Cited(IReadOnlyList<ReplayVerdict> verdicts)
    {
        var seen = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in verdicts)
            foreach (var t in v.Techniques)
                if (!string.IsNullOrWhiteSpace(t)) seen.Add(t.Trim());
        if (seen.Count == 0) return "none";
        return seen.Count <= 12
            ? string.Join(", ", seen)
            : string.Join(", ", seen.Take(12)) + ", ...";
    }
}
