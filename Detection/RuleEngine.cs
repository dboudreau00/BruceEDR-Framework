using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BruceEDR.Core;

namespace BruceEDR.Detection;

/// <summary>One rule firing on one signal, with the evidence that made it fire.</summary>
public sealed record RuleMatch(DetectionRule Rule, string Explanation);

/// <summary>
/// Evaluates JSON-authored <see cref="DetectionRule"/>s against a <see cref="Signal"/>.
///
/// WHY THIS EXISTS: every other detection in BruceEDR is hard-coded C# in
/// <c>DetectionEngine</c>. That is fine for the core exfil-chain state machine, which needs
/// cross-signal memory, but it means nobody who does not write C# and rebuild the agent can
/// contribute a detection. This engine covers the large majority of detections that are
/// really just "these fields look like this", and moves them into files an analyst can edit,
/// review in a pull request, and reload without restarting the agent.
///
/// JSON rather than YAML (which Sigma uses) purely because the project takes no new NuGet
/// dependencies and .NET has no YAML parser in the BCL. The schema is Sigma-shaped so the
/// concepts transfer; it is not Sigma-compatible and does not claim to be.
///
/// THREADING: an instance is immutable after construction and <see cref="Evaluate"/> is
/// pure, so any number of threads may evaluate concurrently. Hot reload is therefore just an
/// atomic reference swap by the owner -- see the rules README.
///
/// WHAT IT CANNOT DO: no cross-signal correlation, no timers, no counting, no state. A rule
/// sees exactly one signal plus the small <see cref="RuleContext"/>. Detections that need
/// "X then Y within N seconds" still belong in <c>DetectionEngine</c>.
/// </summary>
public sealed class RuleEngine
{
    private long _budgetExhausted;

    /// <summary>
    /// How many signals had rule evaluation cut short by <see cref="EvaluationBudget"/>.
    /// Non-zero means a rule pack is too slow and some rules never got to run on those
    /// signals -- a silent detection gap, so it is counted rather than swallowed.
    /// </summary>
    public long BudgetExhaustedCount => System.Threading.Interlocked.Read(ref _budgetExhausted);

    /// <summary>
    /// Invoked (at most once a minute) when a signal's evaluation ran out of budget. A
    /// counter nobody reads is not an alert: one pathological regex can starve every pack
    /// behind it -- C2, exfil -- on every signal, and that needs to be visible.
    /// </summary>
    public Action<string>? BudgetExhaustedAlert { get; set; }
    private long _lastBudgetAlertTicks;

    /// <summary>
    /// Wall-clock ceiling for evaluating ALL rules against ONE signal. Distinct from the
    /// per-match Regex timeout, which bounds a single pattern rather than the whole pack.
    /// </summary>
    internal static readonly TimeSpan EvaluationBudget = TimeSpan.FromMilliseconds(250);

    /// <summary>
    /// Regex match budget. A catastrophically backtracking pattern in a community rule must
    /// degrade one evaluation, not wedge the detection thread; 250 ms is far above any
    /// legitimate pattern on a command line or script body and far below a stall an operator
    /// would notice.
    /// </summary>
    internal static readonly TimeSpan RegexBudget = TimeSpan.FromMilliseconds(250);

    private static readonly string[] Severities =
        { "informational", "low", "medium", "high", "critical" };

    private readonly CompiledRule[] _compiled;
    private readonly Dictionary<string, int> _coverage;

    /// <summary>
    /// Builds the executable form of a rule set. Rules that cannot be compiled (a regex that
    /// does not build, a field name that does not resolve) are dropped rather than thrown on:
    /// a hand-built <see cref="RuleSet"/> that skipped <see cref="Validate"/> must not be able
    /// to crash the agent at start-up. Sets produced by <see cref="LoadDirectory"/> or
    /// <see cref="ParseJson"/> are already validated, so nothing is dropped here in practice.
    /// </summary>
    public RuleEngine(RuleSet set)
    {
        ArgumentNullException.ThrowIfNull(set);

        var compiled = new List<CompiledRule>(set.Rules.Count);
        var kept = new List<DetectionRule>(set.Rules.Count);
        var coverage = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in set.Rules)
        {
            if (rule is null) continue;
            var cr = TryCompile(rule);
            if (cr is null) continue;

            compiled.Add(cr);
            kept.Add(rule);

            // Coverage reports what is actually detecting, so a disabled rule contributes
            // nothing -- claiming coverage you have switched off is exactly the kind of
            // comfortable lie a security tool must not tell.
            if (!rule.Enabled) continue;
            foreach (var t in rule.Techniques)
            {
                if (string.IsNullOrWhiteSpace(t)) continue;
                string key = t.Trim().ToUpperInvariant();
                coverage[key] = coverage.TryGetValue(key, out int n) ? n + 1 : 1;
            }
        }

        _compiled = compiled.ToArray();
        _coverage = coverage;
        Rules = kept;
    }

    /// <summary>Rules the engine holds, including any that are disabled.</summary>
    public IReadOnlyList<DetectionRule> Rules { get; }

    /// <summary>Number of rules held, including disabled ones.</summary>
    public int RuleCount => Rules.Count;

    /// <summary>
    /// ATT&amp;CK technique id to the number of ENABLED rules citing it. Feeds the coverage
    /// report and the GUI matrix. The returned dictionary is the engine's own, never mutated
    /// after construction.
    /// </summary>
    public IReadOnlyDictionary<string, int> TechniqueCoverage() => _coverage;

    // ------------------------------------------------------------------ loading

    /// <summary>
    /// Loads every <c>*.json</c> under <paramref name="dir"/> (recursively), in ordinal
    /// filename order so a numeric prefix such as <c>00-</c> gives contributors a predictable
    /// load order and a deterministic duplicate-id winner.
    ///
    /// Files whose name starts with <c>_</c> or ends with <c>.schema.json</c> are skipped, so
    /// a pack can ship examples and schemas beside its rules.
    ///
    /// A missing directory, an unreadable file, a syntactically broken file and an invalid
    /// rule are all recorded in <see cref="RuleSet.Errors"/>; none of them stops the rest of
    /// the corpus from loading.
    /// </summary>
    /// <param name="warn">Optional per-problem callback, for logging as loading proceeds.</param>
    public static RuleSet LoadDirectory(string dir, Action<string>? warn = null)
    {
        var rules = new List<DetectionRule>();
        var errors = new List<RuleValidationError>();

        void Record(RuleValidationError e)
        {
            errors.Add(e);
            try { warn?.Invoke(e.ToString()); } catch { /* a logging sink must not break loading */ }
        }

        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            Record(new RuleValidationError("", $"rule directory not found: {dir}"));
            return new RuleSet(rules, errors);
        }

        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.json", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            Record(new RuleValidationError("", $"cannot enumerate rule directory {dir}: {ex.Message}"));
            return new RuleSet(rules, errors);
        }
        Array.Sort(files, StringComparer.OrdinalIgnoreCase);

        // id -> file that claimed it first. First writer wins, which combined with the sorted
        // order makes the result of a load reproducible.
        var owners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (string file in files)
        {
            string name = Path.GetFileName(file);
            if (name.StartsWith('_') || name.EndsWith(".schema.json", StringComparison.OrdinalIgnoreCase))
                continue;

            string text;
            try
            {
                text = File.ReadAllText(file);
            }
            catch (Exception ex)
            {
                Record(new RuleValidationError("", $"{name}: cannot read file ({ex.Message})"));
                continue;
            }

            var set = ParseJson(text, name);
            foreach (var e in set.Errors) Record(e);

            foreach (var rule in set.Rules)
            {
                if (owners.TryGetValue(rule.Id, out string? first))
                {
                    Record(new RuleValidationError(rule.Id,
                        $"duplicate rule id, already defined in {first}; the copy in {name} was dropped"));
                    continue;
                }
                owners[rule.Id] = name;
                rules.Add(rule);
            }
        }

        return new RuleSet(rules, errors);
    }

    /// <summary>
    /// Parses one rule document. Accepts <c>{ "rules": [ ... ] }</c>, a bare array of rule
    /// objects, or a single rule object. Trailing commas and <c>//</c> comments are allowed
    /// because rule files are read and edited by humans far more often than by machines.
    /// Never throws: every failure becomes a <see cref="RuleValidationError"/>.
    /// </summary>
    /// <param name="source">Label used in error messages, normally the file name.</param>
    public static RuleSet ParseJson(string json, string source)
    {
        var rules = new List<DetectionRule>();
        var errors = new List<RuleValidationError>();
        source = string.IsNullOrWhiteSpace(source) ? "(inline)" : source;

        if (string.IsNullOrWhiteSpace(json))
        {
            errors.Add(new RuleValidationError("", $"{source}: file is empty"));
            return new RuleSet(rules, errors);
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
                MaxDepth = 32
            });
        }
        catch (Exception ex)
        {
            errors.Add(new RuleValidationError("", $"{source}: invalid JSON ({ex.Message})"));
            return new RuleSet(rules, errors);
        }

        using (doc)
        {
            var root = doc.RootElement;
            List<JsonElement> entries = new();

            if (root.ValueKind == JsonValueKind.Array)
            {
                entries.AddRange(root.EnumerateArray());
            }
            else if (root.ValueKind == JsonValueKind.Object &&
                     TryGetProp(root, "rules", out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                entries.AddRange(arr.EnumerateArray());
            }
            else if (root.ValueKind == JsonValueKind.Object && TryGetProp(root, "id", out _))
            {
                entries.Add(root);
            }
            else
            {
                errors.Add(new RuleValidationError("",
                    $"{source}: expected an object with a \"rules\" array, a bare array of rules, or a single rule object"));
                return new RuleSet(rules, errors);
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < entries.Count; i++)
            {
                var el = entries[i];
                if (el.ValueKind != JsonValueKind.Object)
                {
                    errors.Add(new RuleValidationError("",
                        $"{source}: rules[{i}] is {el.ValueKind}, expected an object"));
                    continue;
                }

                DetectionRule? rule;
                var shape = new List<RuleValidationError>();
                try
                {
                    rule = ReadRule(el, source, i, shape);
                }
                catch (Exception ex)
                {
                    // Defence in depth: no malformed document should ever escape as an exception.
                    rule = null;
                    shape.Add(new RuleValidationError("", $"{source}: rules[{i}] could not be read ({ex.Message})"));
                }

                errors.AddRange(shape);
                if (rule is null) continue;

                bool blocked = false;
                foreach (var e in Validate(rule))
                {
                    errors.Add(new RuleValidationError(e.RuleId, $"{e.Message} ({source})"));
                    if (e.IsBlocking) blocked = true;
                }
                if (blocked) continue;

                if (!seen.Add(rule.Id))
                {
                    errors.Add(new RuleValidationError(rule.Id,
                        $"duplicate rule id within {source}; the later copy was dropped"));
                    continue;
                }
                rules.Add(rule);
            }
        }

        return new RuleSet(rules, errors);
    }

    // ------------------------------------------------------------------ validation

    /// <summary>
    /// Checks one rule in isolation. Returns every problem found rather than the first, so a
    /// contributor fixes their file in one pass instead of ten.
    ///
    /// Everything here is blocking EXCEPT an unrecognised ATT&amp;CK technique id, which is
    /// reported as a note: the catalog in <see cref="AttackCatalog"/> is a static table and
    /// MITRE ships new sub-techniques between our releases. Duplicate ids cannot be seen from
    /// a single rule and are detected by <see cref="ParseJson"/> / <see cref="LoadDirectory"/>.
    /// </summary>
    public static IReadOnlyList<RuleValidationError> Validate(DetectionRule rule)
    {
        var errors = new List<RuleValidationError>();
        if (rule is null)
        {
            errors.Add(new RuleValidationError("", "rule is null"));
            return errors;
        }

        string id = rule.Id ?? "";
        if (string.IsNullOrWhiteSpace(id))
            errors.Add(new RuleValidationError("", "rule has no id; an alert with no stable rule id cannot be tuned or suppressed"));
        else if (id.AsSpan().IndexOfAny(" \t\r\n") >= 0)
            errors.Add(new RuleValidationError(id, "rule id must not contain whitespace"));

        if (string.IsNullOrWhiteSpace(rule.Title))
            errors.Add(new RuleValidationError(id, "rule has no title; the title is the sentence an analyst reads in the alert"));

        if (!Array.Exists(Severities, s => string.Equals(s, rule.Severity, StringComparison.OrdinalIgnoreCase)))
            errors.Add(new RuleValidationError(id,
                $"unknown severity '{rule.Severity}'; expected one of {string.Join(", ", Severities)}"));

        if (rule.Score is < -100 or > 100)
            errors.Add(new RuleValidationError(id, $"score {rule.Score} is outside the supported range -100..100"));

        foreach (string kind in rule.Kinds)
        {
            if (!TryParseKind(kind, out _))
                errors.Add(new RuleValidationError(id,
                    $"unknown signal kind '{kind}'; expected one of {string.Join(", ", Enum.GetNames<SignalKind>())}"));
        }

        if (rule.Detection.Count == 0)
        {
            errors.Add(new RuleValidationError(id, "rule has no detection clauses, so it can never fire"));
        }
        else
        {
            for (int i = 0; i < rule.Detection.Count; i++)
            {
                var clause = rule.Detection[i];
                if (clause is null)
                {
                    errors.Add(new RuleValidationError(id, $"detection[{i}] is null"));
                    continue;
                }
                if (clause.All.Count == 0)
                {
                    errors.Add(new RuleValidationError(id,
                        $"detection[{i}] has no 'all' conditions; a clause built only from 'none' matches every signal on the endpoint"));
                }
                for (int j = 0; j < clause.All.Count; j++)
                    ValidateCondition(id, $"detection[{i}].all[{j}]", clause.All[j], errors);
                for (int j = 0; j < clause.None.Count; j++)
                    ValidateCondition(id, $"detection[{i}].none[{j}]", clause.None[j], errors);
            }
        }

        if (rule.FalsePositives.Count == 0)
            errors.Add(new RuleValidationError(id, RuleValidationError.NotePrefix +
                "no falsePositives listed; every real detection has at least one benign cause worth naming"));

        foreach (string t in rule.Techniques)
        {
            if (string.IsNullOrWhiteSpace(t)) continue;
            if (!AttackCatalog.IsKnown(t))
                errors.Add(new RuleValidationError(id, RuleValidationError.NotePrefix +
                    $"ATT&CK technique '{t}' is not in the local catalog; the rule still loads, but alerts will show it unmapped"));
        }

        return errors;
    }

    private static void ValidateCondition(string ruleId, string where, RuleCondition? c, List<RuleValidationError> errors)
    {
        if (c is null)
        {
            errors.Add(new RuleValidationError(ruleId, $"{where} is null"));
            return;
        }

        if (!RuleFields.TryResolve(c.Field, out _))
        {
            errors.Add(new RuleValidationError(ruleId,
                $"{where} names unknown field '{c.Field}'; known fields: {string.Join(", ", RuleFields.KnownNames)}"));
        }

        if (!Enum.IsDefined(c.Op))
        {
            errors.Add(new RuleValidationError(ruleId, $"{where} uses unknown operator '{(int)c.Op}'"));
            return;
        }

        switch (c.Op)
        {
            case MatchOp.Regex:
                if (string.IsNullOrEmpty(c.Value))
                {
                    errors.Add(new RuleValidationError(ruleId, $"{where} uses regex with an empty pattern"));
                    break;
                }
                try
                {
                    // Parse-only here. Emitting IL for every pattern twice (once to validate,
                    // once to compile) would double an already noticeable rule-load cost.
                    _ = BuildRegex(c, compiled: false);
                }
                catch (ArgumentException ex)
                {
                    errors.Add(new RuleValidationError(ruleId, $"{where} regex does not compile: {ex.Message}"));
                }
                break;

            case MatchOp.In:
            case MatchOp.NotIn:
                if (c.Values.Count == 0)
                    errors.Add(new RuleValidationError(ruleId,
                        $"{where} uses {c.Op.ToString().ToLowerInvariant()} with an empty 'values' list, which can never match"));
                break;

            case MatchOp.CidrIn:
            {
                int parsed = 0;
                foreach (string v in EnumerateOperands(c))
                {
                    if (CidrRange.TryParse(v, out _)) parsed++;
                    else errors.Add(new RuleValidationError(ruleId, $"{where} has invalid CIDR '{v}'"));
                }
                if (parsed == 0)
                    errors.Add(new RuleValidationError(ruleId, $"{where} uses cidrIn with no usable prefix"));
                break;
            }

            case MatchOp.GreaterThan:
            case MatchOp.LessThan:
                if (!RuleFields.TryParseNumber(c.Value, out _))
                    errors.Add(new RuleValidationError(ruleId,
                        $"{where} uses {c.Op.ToString().ToLowerInvariant()} with non-numeric value '{c.Value}'"));
                break;

            case MatchOp.Contains:
            case MatchOp.NotContains:
            case MatchOp.StartsWith:
            case MatchOp.EndsWith:
                // An empty needle is a substring of everything, so these would match (or, in
                // the negated form, suppress) every signal. Always an authoring mistake.
                if (string.IsNullOrEmpty(c.Value))
                    errors.Add(new RuleValidationError(ruleId,
                        $"{where} uses {c.Op.ToString().ToLowerInvariant()} with an empty value, which matches everything"));
                break;
        }
    }

    private static IEnumerable<string> EnumerateOperands(RuleCondition c)
    {
        if (c.Values.Count > 0)
        {
            foreach (string v in c.Values) yield return v;
            yield break;
        }
        if (!string.IsNullOrEmpty(c.Value)) yield return c.Value;
    }

    // ------------------------------------------------------------------ evaluation

    /// <summary>
    /// Evaluates every enabled rule against one signal. Returns an empty array when nothing
    /// fires, which is the overwhelmingly common case, so a quiet endpoint costs no
    /// allocations beyond the per-field string work the matched conditions require.
    ///
    /// Guaranteed not to throw for any input, including a signal whose every optional field
    /// is null: this runs on the single detection thread, and one bad community rule must not
    /// be able to stop the agent from monitoring.
    /// </summary>
    public IReadOnlyList<RuleMatch> Evaluate(Signal signal, RuleContext context)
    {
        if (signal is null) return Array.Empty<RuleMatch>();
        var ctx = context ?? RuleContext.Empty;

        List<RuleMatch>? hits = null;
        var kind = signal.Kind;

        // The 250 ms Regex timeout is PER MATCH. A pack with many regex rules -- or one
        // pathological pattern hit by many rules -- could therefore burn seconds on a single
        // signal, and this runs on the single detection thread, so telemetry backs up and the
        // bounded queue starts dropping events. Bound the whole evaluation instead: once the
        // budget is spent, stop and keep what matched. Losing the tail of one signal's rules
        // is strictly better than stalling detection for every process on the box.
        var budget = System.Diagnostics.Stopwatch.StartNew();
        bool exhausted = false;

        foreach (var cr in _compiled)
        {
            if (!cr.Enabled) continue;
            if (cr.Kinds is not null && !ContainsKind(cr.Kinds, kind)) continue;
            if (budget.Elapsed > EvaluationBudget) { exhausted = true; break; }

            try
            {
                string? explanation = MatchRule(cr, signal, ctx);
                if (explanation is null) continue;
                (hits ??= new List<RuleMatch>(2)).Add(new RuleMatch(cr.Rule, explanation));
            }
            catch
            {
                // Belt and braces. Every known failure mode (regex timeout, unparsable
                // operand) is already handled as "no match"; this catch exists so an
                // unanticipated one degrades to a missed detection rather than a dead agent.
            }
        }

        if (exhausted)
        {
            long n = System.Threading.Interlocked.Increment(ref _budgetExhausted);
            var alert = BudgetExhaustedAlert;
            if (alert is not null)
            {
                long now = DateTime.UtcNow.Ticks;
                long last = System.Threading.Interlocked.Read(ref _lastBudgetAlertTicks);
                if (now - last > TimeSpan.TicksPerMinute &&
                    System.Threading.Interlocked.CompareExchange(ref _lastBudgetAlertTicks, now, last) == last)
                {
                    try
                    {
                        alert($"rule evaluation exceeded its {EvaluationBudget.TotalMilliseconds:F0} ms budget on a " +
                              $"{kind} signal; later packs were skipped for it ({n} signal(s) affected so far). " +
                              "A rule with a pathological regex is the usual cause.");
                    }
                    catch { }
                }
            }
        }
        return hits ?? (IReadOnlyList<RuleMatch>)Array.Empty<RuleMatch>();
    }

    private static bool ContainsKind(SignalKind[] kinds, SignalKind kind)
    {
        for (int i = 0; i < kinds.Length; i++)
            if (kinds[i] == kind) return true;
        return false;
    }

    private static string? MatchRule(CompiledRule cr, Signal s, RuleContext ctx)
    {
        foreach (var clause in cr.Clauses)
        {
            string? firstField = null, firstValue = null, lastField = null, lastValue = null;
            bool matched = true;

            foreach (var c in clause.All)
            {
                var r = Test(c, s, ctx, out string? evidence);
                if (r == Tri.Error) return null;          // regex timeout: skip the whole rule
                if (r == Tri.No) { matched = false; break; }

                if (firstField is null) { firstField = c.FieldName; firstValue = evidence; }
                else { lastField = c.FieldName; lastValue = evidence; }
            }
            if (!matched) continue;

            foreach (var c in clause.None)
            {
                var r = Test(c, s, ctx, out _);
                if (r == Tri.Error) return null;
                if (r == Tri.Yes) { matched = false; break; }
            }
            if (!matched) continue;

            return Explain(cr.Rule.Title, firstField, firstValue, lastField, lastValue);
        }
        return null;
    }

    private enum Tri { No, Yes, Error }

    private static Tri Test(CompiledCondition c, Signal s, RuleContext ctx, out string? evidence)
    {
        evidence = null;

        switch (c.Op)
        {
            case MatchOp.Exists:
            case MatchOp.NotExists:
            {
                var fv = RuleFields.Resolve(c.Field, s, ctx);
                bool present = fv.HasContent;
                if (present) evidence = fv.FirstNonEmpty();
                return (c.Op == MatchOp.Exists) == present ? Tri.Yes : Tri.No;
            }

            case MatchOp.GreaterThan:
            case MatchOp.LessThan:
            {
                if (!RuleFields.TryResolveNumber(c.Field, s, ctx, out long actual)) return Tri.No;
                bool ok = c.Op == MatchOp.GreaterThan ? actual > c.Number : actual < c.Number;
                if (ok) evidence = actual.ToString(CultureInfo.InvariantCulture);
                return ok ? Tri.Yes : Tri.No;
            }

            case MatchOp.CidrIn:
            {
                if (c.Cidrs is null || c.Cidrs.Length == 0) return Tri.No;
                var fv = RuleFields.Resolve(c.Field, s, ctx);
                int n = fv.Count;
                for (int i = 0; i < n; i++)
                {
                    string v = fv[i];
                    for (int k = 0; k < c.Cidrs.Length; k++)
                    {
                        if (!c.Cidrs[k].Contains(v)) continue;
                        evidence = v;
                        return Tri.Yes;
                    }
                }
                return Tri.No;
            }

            default:
            {
                var fv = RuleFields.Resolve(c.Field, s, ctx);
                bool negated = c.Op is MatchOp.NotEquals or MatchOp.NotContains or MatchOp.NotIn;
                int n = fv.Count;

                // An absent field satisfies a negated test vacuously: "filePath notContains
                // x" is true of a ProcessStart that has no file path at all. Positive tests
                // on an absent field are simply false.
                if (n == 0) return negated ? Tri.Yes : Tri.No;

                for (int i = 0; i < n; i++)
                {
                    string v = fv[i];
                    var r = TestPositive(c, v);
                    if (r == Tri.Error) return Tri.Error;
                    if (r != Tri.Yes) continue;
                    if (negated) return Tri.No;
                    evidence = v;
                    return Tri.Yes;
                }

                if (!negated) return Tri.No;
                evidence = fv.FirstNonEmpty() ?? fv[0];
                return Tri.Yes;
            }
        }
    }

    /// <summary>Applies the operator in its positive sense to one concrete field value.</summary>
    private static Tri TestPositive(CompiledCondition c, string value)
    {
        switch (c.Op)
        {
            case MatchOp.Equals:
            case MatchOp.NotEquals:
                return string.Equals(value, c.Value, c.Comparison) ? Tri.Yes : Tri.No;

            case MatchOp.Contains:
            case MatchOp.NotContains:
                return value.Contains(c.Value, c.Comparison) ? Tri.Yes : Tri.No;

            case MatchOp.StartsWith:
                return value.StartsWith(c.Value, c.Comparison) ? Tri.Yes : Tri.No;

            case MatchOp.EndsWith:
                return value.EndsWith(c.Value, c.Comparison) ? Tri.Yes : Tri.No;

            case MatchOp.In:
            case MatchOp.NotIn:
                return c.ValueSet is not null && c.ValueSet.Contains(value) ? Tri.Yes : Tri.No;

            case MatchOp.Regex:
                if (c.Rx is null) return Tri.No;
                try
                {
                    return c.Rx.IsMatch(value) ? Tri.Yes : Tri.No;
                }
                catch (RegexMatchTimeoutException)
                {
                    // Reported as Error, not No: for a condition under 'none' a silent "no"
                    // would let the clause fire, turning a timeout into a false positive.
                    return Tri.Error;
                }

            default:
                return Tri.No;
        }
    }

    /// <summary>
    /// Builds the analyst-facing evidence line: the rule title plus the concrete field values
    /// that matched, so triage does not require re-running anything. Capped at 200 characters
    /// because these land in alerts, syslog lines and the audit chain.
    /// </summary>
    private static string Explain(string title, string? f1, string? v1, string? f2, string? v2)
    {
        var sb = new StringBuilder(160);
        sb.Append(string.IsNullOrWhiteSpace(title) ? "(untitled rule)" : title);
        if (f1 is not null)
        {
            sb.Append(" [").Append(f1).Append('=').Append(Clip(v1, 80));
            if (f2 is not null) sb.Append("; ").Append(f2).Append('=').Append(Clip(v2, 80));
            sb.Append(']');
        }
        string text = sb.ToString();
        return text.Length <= 200 ? text : string.Concat(text.AsSpan(0, 197), "...");
    }

    /// <summary>
    /// Truncates and flattens one evidence value. Newlines and control characters are folded
    /// to spaces so a multi-line AMSI script body cannot forge extra lines in a log file.
    /// </summary>
    private static string Clip(string? value, int max)
    {
        if (string.IsNullOrEmpty(value)) return "(empty)";
        int take = Math.Min(value.Length, max);
        var buf = new char[take + (value.Length > max ? 3 : 0)];
        for (int i = 0; i < take; i++)
        {
            char ch = value[i];
            buf[i] = char.IsControl(ch) ? ' ' : ch;
        }
        if (value.Length > max)
        {
            buf[take] = '.';
            buf[take + 1] = '.';
            buf[take + 2] = '.';
        }
        return new string(buf);
    }

    // ------------------------------------------------------------------ compilation

    private sealed class CompiledRule
    {
        public required DetectionRule Rule { get; init; }
        public required bool Enabled { get; init; }
        /// <summary>Null means "any signal kind".</summary>
        public required SignalKind[]? Kinds { get; init; }
        public required CompiledClause[] Clauses { get; init; }
    }

    private sealed class CompiledClause
    {
        public required CompiledCondition[] All { get; init; }
        public required CompiledCondition[] None { get; init; }
    }

    private sealed class CompiledCondition
    {
        public required RuleField Field { get; init; }
        public required string FieldName { get; init; }
        public required MatchOp Op { get; init; }
        public required string Value { get; init; }
        public required StringComparison Comparison { get; init; }
        public HashSet<string>? ValueSet { get; init; }
        public Regex? Rx { get; init; }
        public CidrRange[]? Cidrs { get; init; }
        public long Number { get; init; }
    }

    private static CompiledRule? TryCompile(DetectionRule rule)
    {
        try
        {
            SignalKind[]? kinds = null;
            if (rule.Kinds.Count > 0)
            {
                var list = new List<SignalKind>(rule.Kinds.Count);
                foreach (string k in rule.Kinds)
                    if (TryParseKind(k, out var parsed)) list.Add(parsed);
                if (list.Count == 0) return null;   // every named kind was bogus: the rule is dead
                kinds = list.ToArray();
            }

            if (rule.Detection.Count == 0) return null;

            var clauses = new CompiledClause[rule.Detection.Count];
            for (int i = 0; i < rule.Detection.Count; i++)
            {
                var src = rule.Detection[i];
                if (src is null || src.All.Count == 0) return null;
                var all = CompileAll(src.All);
                var none = CompileAll(src.None);
                if (all is null || none is null) return null;
                clauses[i] = new CompiledClause { All = all, None = none };
            }

            return new CompiledRule
            {
                Rule = rule,
                Enabled = rule.Enabled,
                Kinds = kinds,
                Clauses = clauses
            };
        }
        catch
        {
            return null;
        }
    }

    private static CompiledCondition[]? CompileAll(IReadOnlyList<RuleCondition> conditions)
    {
        if (conditions.Count == 0) return Array.Empty<CompiledCondition>();
        var result = new CompiledCondition[conditions.Count];
        for (int i = 0; i < conditions.Count; i++)
        {
            var c = Compile(conditions[i]);
            if (c is null) return null;
            result[i] = c;
        }
        return result;
    }

    private static CompiledCondition? Compile(RuleCondition? c)
    {
        if (c is null) return null;
        if (!RuleFields.TryResolve(c.Field, out var field)) return null;
        if (!Enum.IsDefined(c.Op)) return null;

        var comparison = c.CaseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
        HashSet<string>? set = null;
        Regex? rx = null;
        CidrRange[]? cidrs = null;
        long number = 0;

        switch (c.Op)
        {
            case MatchOp.In:
            case MatchOp.NotIn:
                if (c.Values.Count == 0) return null;
                set = new HashSet<string>(c.CaseSensitive ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase);
                foreach (string v in c.Values) set.Add(v ?? "");
                break;

            case MatchOp.Regex:
                if (string.IsNullOrEmpty(c.Value)) return null;
                rx = BuildRegex(c);   // throws on a bad pattern; TryCompile turns that into a drop
                break;

            case MatchOp.CidrIn:
            {
                var list = new List<CidrRange>();
                foreach (string v in EnumerateOperands(c))
                    if (CidrRange.TryParse(v, out var r) && r is not null) list.Add(r);
                if (list.Count == 0) return null;
                cidrs = list.ToArray();
                break;
            }

            case MatchOp.GreaterThan:
            case MatchOp.LessThan:
                if (!RuleFields.TryParseNumber(c.Value, out number)) return null;
                break;
        }

        return new CompiledCondition
        {
            Field = field,
            FieldName = RuleFields.NameOf(field),
            Op = c.Op,
            Value = c.Value ?? "",
            Comparison = comparison,
            ValueSet = set,
            Rx = rx,
            Cidrs = cidrs,
            Number = number
        };
    }

    /// <summary>
    /// Every pattern is built exactly once, here. <see cref="RegexOptions.Compiled"/> pays its
    /// IL-emission cost at load time instead of on the detection thread;
    /// <see cref="RegexOptions.CultureInvariant"/> keeps <c>IgnoreCase</c> from depending on
    /// the machine locale (a Turkish-locale 'I' would otherwise change which rules fire).
    /// </summary>
    private static Regex BuildRegex(RuleCondition c, bool compiled = true)
    {
        var options = RegexOptions.CultureInvariant;
        if (compiled) options |= RegexOptions.Compiled;
        if (!c.CaseSensitive) options |= RegexOptions.IgnoreCase;
        return new Regex(c.Value, options, RegexBudget);
    }

    /// <summary>
    /// Strict signal-kind parse. <see cref="Enum.TryParse{TEnum}(string, bool, out TEnum)"/>
    /// happily accepts an undefined NUMBER ("999" becomes SignalKind 999), which would let a
    /// typo produce a rule that silently never fires. Require a defined member.
    /// </summary>
    private static bool TryParseKind(string? text, out SignalKind kind)
    {
        kind = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        return Enum.TryParse(text.Trim(), ignoreCase: true, out kind) && Enum.IsDefined(kind);
    }

    // ------------------------------------------------------------------ JSON reading

    private static readonly Dictionary<string, MatchOp> OpNames = BuildOpNames();

    private static Dictionary<string, MatchOp> BuildOpNames()
    {
        var d = new Dictionary<string, MatchOp>(StringComparer.OrdinalIgnoreCase);
        foreach (var op in Enum.GetValues<MatchOp>()) d[op.ToString()] = op;
        // Aliases, so a rule reads naturally whichever dialect the author came from.
        d["eq"] = MatchOp.Equals;
        d["is"] = MatchOp.Equals;
        d["ne"] = MatchOp.NotEquals;
        d["neq"] = MatchOp.NotEquals;
        d["isnot"] = MatchOp.NotEquals;
        d["has"] = MatchOp.Contains;
        d["matches"] = MatchOp.Regex;
        d["re"] = MatchOp.Regex;
        d["anyof"] = MatchOp.In;
        d["noneof"] = MatchOp.NotIn;
        d["gt"] = MatchOp.GreaterThan;
        d["lt"] = MatchOp.LessThan;
        d["missing"] = MatchOp.NotExists;
        d["cidr"] = MatchOp.CidrIn;
        return d;
    }

    private static bool TryParseOp(string? text, out MatchOp op)
    {
        op = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        // Bound the stack buffer: the operand comes from a file that may not be trustworthy,
        // and no real operator name is anywhere near this long.
        if (text.Length > 64) return false;
        // Fold the separators contributors reach for: not_contains, not-contains, "not in".
        Span<char> buf = stackalloc char[text.Length];
        int n = 0;
        foreach (char ch in text)
            if (ch is not ('_' or '-' or ' ')) buf[n++] = ch;
        return OpNames.TryGetValue(new string(buf[..n]), out op);
    }

    private static bool TryGetProp(JsonElement obj, string name, out JsonElement value)
    {
        if (obj.ValueKind == JsonValueKind.Object)
        {
            if (obj.TryGetProperty(name, out value)) return true;
            foreach (var p in obj.EnumerateObject())
            {
                if (!string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)) continue;
                value = p.Value;
                return true;
            }
        }
        value = default;
        return false;
    }

    private static string? ScalarText(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString(),
        JsonValueKind.Number => e.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => null
    };

    private static string ReadString(JsonElement obj, string name, string fallback = "")
        => TryGetProp(obj, name, out var el) ? (ScalarText(el) ?? fallback) : fallback;

    private static bool ReadBool(JsonElement obj, string name, bool fallback)
    {
        if (!TryGetProp(obj, name, out var el)) return fallback;
        return el.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.String => bool.TryParse(el.GetString(), out bool b) ? b : fallback,
            JsonValueKind.Number => el.TryGetInt64(out long n) && n != 0,
            _ => fallback
        };
    }

    private static int ReadInt(JsonElement obj, string name, int fallback)
    {
        if (!TryGetProp(obj, name, out var el)) return fallback;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out int v)) return v;
        if (el.ValueKind == JsonValueKind.String && int.TryParse(el.GetString(),
                NumberStyles.Integer, CultureInfo.InvariantCulture, out int s)) return s;
        return fallback;
    }

    /// <summary>Reads an array of scalars, tolerating a single scalar in place of a one-item array.</summary>
    private static IReadOnlyList<string> ReadStringList(JsonElement obj, string name)
    {
        if (!TryGetProp(obj, name, out var el)) return Array.Empty<string>();

        if (el.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>(el.GetArrayLength());
            foreach (var item in el.EnumerateArray())
            {
                string? t = ScalarText(item);
                if (t is not null) list.Add(t);
            }
            return list.Count == 0 ? Array.Empty<string>() : list;
        }

        string? single = ScalarText(el);
        return single is null ? Array.Empty<string>() : new[] { single };
    }

    private static DetectionRule? ReadRule(JsonElement el, string source, int index, List<RuleValidationError> errors)
    {
        string id = ReadString(el, "id").Trim();
        string label = id.Length > 0 ? id : $"{source}: rules[{index}]";

        var detection = ReadDetection(el, label, errors);
        if (detection is null) return null;   // a condition we could not read; dropping the whole
                                              // rule is the only safe answer, because dropping a
                                              // single condition would silently WIDEN the match.

        return new DetectionRule
        {
            Id = id,
            Title = ReadString(el, "title"),
            Description = ReadString(el, "description"),
            Author = ReadString(el, "author"),
            Severity = ReadString(el, "severity", "medium").Trim().ToLowerInvariant(),
            Score = ReadInt(el, "score", 0),
            Techniques = ReadStringList(el, "techniques"),
            References = ReadStringList(el, "references"),
            Enabled = ReadBool(el, "enabled", true),
            OncePerProcess = ReadBool(el, "oncePerProcess", false),
            Kinds = ReadStringList(el, "kinds"),
            Detection = detection,
            FalsePositives = ReadStringList(el, "falsePositives")
        };
    }

    private static IReadOnlyList<RuleClause>? ReadDetection(JsonElement ruleEl, string label, List<RuleValidationError> errors)
    {
        if (!TryGetProp(ruleEl, "detection", out var det))
            return Array.Empty<RuleClause>();   // Validate reports the empty detection

        var clauses = new List<RuleClause>();

        if (det.ValueKind == JsonValueKind.Object)
        {
            var clause = ReadClause(det, label, 0, errors);
            if (clause is null) return null;
            clauses.Add(clause);
        }
        else if (det.ValueKind == JsonValueKind.Array)
        {
            int i = 0;
            foreach (var item in det.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object)
                {
                    errors.Add(new RuleValidationError(label, $"detection[{i}] is {item.ValueKind}, expected an object"));
                    return null;
                }
                var clause = ReadClause(item, label, i, errors);
                if (clause is null) return null;
                clauses.Add(clause);
                i++;
            }
        }
        else
        {
            errors.Add(new RuleValidationError(label, $"detection must be an object or an array, got {det.ValueKind}"));
            return null;
        }

        return clauses;
    }

    private static RuleClause? ReadClause(JsonElement el, string label, int index, List<RuleValidationError> errors)
    {
        bool hasAll = TryGetProp(el, "all", out var allEl);
        bool hasNone = TryGetProp(el, "none", out var noneEl);

        // Shorthand: a clause written as a bare condition object. Common enough in practice
        // that rejecting it would just make simple rules noisier to write.
        if (!hasAll && !hasNone)
        {
            if (!TryGetProp(el, "field", out _))
            {
                errors.Add(new RuleValidationError(label,
                    $"detection[{index}] needs an 'all' list, a 'none' list, or a single condition with a 'field'"));
                return null;
            }
            var only = ReadCondition(el, label, $"detection[{index}]", errors);
            if (only is null) return null;
            return new RuleClause { All = new[] { only } };
        }

        var all = hasAll ? ReadConditions(allEl, label, $"detection[{index}].all", errors) : Array.Empty<RuleCondition>();
        if (all is null) return null;
        var none = hasNone ? ReadConditions(noneEl, label, $"detection[{index}].none", errors) : Array.Empty<RuleCondition>();
        if (none is null) return null;

        return new RuleClause { All = all, None = none };
    }

    private static IReadOnlyList<RuleCondition>? ReadConditions(JsonElement el, string label, string where, List<RuleValidationError> errors)
    {
        var list = new List<RuleCondition>();

        if (el.ValueKind == JsonValueKind.Object)
        {
            var one = ReadCondition(el, label, where, errors);
            if (one is null) return null;
            list.Add(one);
            return list;
        }

        if (el.ValueKind != JsonValueKind.Array)
        {
            errors.Add(new RuleValidationError(label, $"{where} must be an array of conditions, got {el.ValueKind}"));
            return null;
        }

        int i = 0;
        foreach (var item in el.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                errors.Add(new RuleValidationError(label, $"{where}[{i}] is {item.ValueKind}, expected an object"));
                return null;
            }
            var c = ReadCondition(item, label, $"{where}[{i}]", errors);
            if (c is null) return null;
            list.Add(c);
            i++;
        }
        return list;
    }

    private static RuleCondition? ReadCondition(JsonElement el, string label, string where, List<RuleValidationError> errors)
    {
        string field = ReadString(el, "field").Trim();
        if (field.Length == 0)
        {
            errors.Add(new RuleValidationError(label, $"{where} has no 'field'"));
            return null;
        }

        string opText = ReadString(el, "op").Trim();
        if (opText.Length == 0)
        {
            errors.Add(new RuleValidationError(label, $"{where} has no 'op'"));
            return null;
        }
        if (!TryParseOp(opText, out var op))
        {
            errors.Add(new RuleValidationError(label,
                $"{where} uses unknown operator '{opText}'; known operators: {string.Join(", ", Enum.GetNames<MatchOp>())}"));
            return null;
        }

        string value = ReadString(el, "value");
        var values = ReadStringList(el, "values");

        // Forgiving normalisation: `in` written with a single `value` becomes a one-item set
        // rather than an error, and `equals` written with a `values` list of one collapses the
        // other way. Validate() stays strict about the MODEL; the parser is the friendly front.
        if (op is MatchOp.In or MatchOp.NotIn && values.Count == 0 && value.Length > 0)
            values = new[] { value };
        if (op is not (MatchOp.In or MatchOp.NotIn or MatchOp.CidrIn) && value.Length == 0 && values.Count == 1)
            value = values[0];

        return new RuleCondition
        {
            Field = field,
            Op = op,
            Value = value,
            Values = values,
            CaseSensitive = ReadBool(el, "caseSensitive", false)
        };
    }
}
