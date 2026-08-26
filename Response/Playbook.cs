using System.Text;
using System.Text.Json;
using BruceEDR.Core;

namespace BruceEDR.Response;

/// <summary>
/// One step a playbook can order. The playbook only DECIDES; executing an action is
/// the caller's job, which keeps the decision layer pure and unit-testable with no
/// processes, no firewall and no disk.
/// </summary>
public enum PlaybookAction
{
    /// <summary>Record the detection and do nothing else. The safe default.</summary>
    Log,
    /// <summary>Freeze the process so the analyst decides, without killing evidence in memory.</summary>
    Suspend,
    /// <summary>Add an outbound Windows Firewall block for the process image.</summary>
    FirewallBlock,
    /// <summary>Move staged archives into the encrypted quarantine vault.</summary>
    QuarantineFiles,
    /// <summary>Terminate the process tree. Destroys volatile evidence, so order it after triage.</summary>
    Kill,
    /// <summary>Cut the whole host off the network except an operator allowlist. High blast radius.</summary>
    IsolateHost,
    /// <summary>Collect a forensic zip before anything destructive runs.</summary>
    CollectTriage,
    /// <summary>Push the incident to the configured webhook/SIEM sink.</summary>
    NotifyWebhook
}

/// <summary>
/// One config-driven rule. Every populated criterion must hold for the rule to match
/// (AND across criteria); an empty criterion is simply not applied.
/// </summary>
public sealed record PlaybookRule
{
    /// <summary>Operator-facing label. Reported back in <see cref="PlaybookDecision.MatchedRule"/>.</summary>
    public string Name { get; init; } = "";

    /// <summary>Minimum <see cref="ProfileSnapshot.Score"/>, inclusive. 0 matches everything.</summary>
    public int MinScore { get; init; }

    /// <summary>
    /// ATT&amp;CK technique ids that must ALL be present on the profile. Matching is
    /// case-insensitive and exact — <c>T1003</c> does NOT match <c>T1003.001</c>,
    /// because silently treating a parent id as a wildcard would make a narrowly
    /// scoped rule fire far more often than its author intended.
    /// </summary>
    public string[] RequiredTechniques { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Process-name patterns; ANY match satisfies the criterion. Supports <c>*</c> and
    /// <c>?</c>, case-insensitive, anchored at both ends.
    /// </summary>
    public string[] ProcessNameGlobs { get; init; } = Array.Empty<string>();

    /// <summary>When true the rule only fires on a process that failed the trust check.</summary>
    public bool RequireUntrusted { get; init; }

    /// <summary>Actions this rule contributes. May be empty — see <see cref="Stop"/>.</summary>
    public PlaybookAction[] Actions { get; init; } = Array.Empty<PlaybookAction>();

    /// <summary>
    /// Stop evaluating after this rule matches. Combined with an empty
    /// <see cref="Actions"/> this is the suppression idiom: a leading rule that matches
    /// a known-good process and orders nothing, shadowing every rule below it.
    /// </summary>
    public bool Stop { get; init; }
}

/// <summary>The response the playbook orders for one profile, plus why.</summary>
public sealed record PlaybookDecision
{
    /// <summary>Deduplicated, in the order the matching rules contributed them.</summary>
    public IReadOnlyList<PlaybookAction> Actions { get; init; } = Array.Empty<PlaybookAction>();
    /// <summary>Name of the first rule that matched. Empty when nothing matched.</summary>
    public string MatchedRule { get; init; } = "";
    /// <summary>Human-readable trace of what matched and why, for the audit trail.</summary>
    public string Explanation { get; init; } = "";

    /// <summary>Nothing matched: no action ordered.</summary>
    public static readonly PlaybookDecision None = new();

    public bool Orders(PlaybookAction action) => Actions.Contains(action);
}

/// <summary>
/// Ordered rule list turning a <see cref="ProfileSnapshot"/> into a response plan, so
/// an operator retunes containment by editing JSON instead of recompiling the agent.
///
/// Evaluation: rules are tried in the order given. Every matching rule contributes its
/// actions to a deduplicated union, until a matching rule has <see cref="PlaybookRule.Stop"/>
/// set — that rule still contributes, and evaluation ends there. Put the most specific
/// rules first.
///
/// The class is immutable and does no I/O, so a full response policy can be regression
/// tested without a single real process.
/// </summary>
public sealed class Playbook
{
    private readonly PlaybookRule[] _rules;

    public Playbook(IReadOnlyList<PlaybookRule> rules)
        => _rules = rules is null ? Array.Empty<PlaybookRule>() : rules.ToArray();

    /// <summary>The rules, in evaluation order.</summary>
    public IReadOnlyList<PlaybookRule> Rules => _rules;

    /// <summary>
    /// The built-in ladder used when no playbook file is configured.
    ///
    /// Deliberately conservative: it never orders <see cref="PlaybookAction.IsolateHost"/>.
    /// Full-host isolation can strand an administrator's remote session, so it is
    /// opt-in through configuration only — a default that can lock someone out of a
    /// production box is not a safe default. Triage is always collected before Kill so
    /// the volatile evidence survives the response.
    /// </summary>
    public static Playbook Default() => new(new[]
    {
        new PlaybookRule
        {
            Name = "credential-theft-critical",
            MinScore = 90,
            RequiredTechniques = new[] { "T1003" },
            RequireUntrusted = true,
            Actions = new[]
            {
                PlaybookAction.Suspend, PlaybookAction.CollectTriage, PlaybookAction.FirewallBlock,
                PlaybookAction.QuarantineFiles, PlaybookAction.NotifyWebhook, PlaybookAction.Kill
            },
            Stop = true
        },
        new PlaybookRule
        {
            Name = "high-score-untrusted",
            MinScore = 70,
            RequireUntrusted = true,
            Actions = new[]
            {
                PlaybookAction.Log, PlaybookAction.Suspend, PlaybookAction.CollectTriage,
                PlaybookAction.FirewallBlock, PlaybookAction.QuarantineFiles, PlaybookAction.NotifyWebhook
            }
        },
        new PlaybookRule
        {
            Name = "scripting-host-suspicious",
            MinScore = 40,
            ProcessNameGlobs = new[]
            {
                "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "rundll32.exe", "regsvr32.exe"
            },
            Actions = new[] { PlaybookAction.Log, PlaybookAction.FirewallBlock }
        },
        new PlaybookRule
        {
            Name = "observe",
            MinScore = 1,
            Actions = new[] { PlaybookAction.Log }
        }
    });

    /// <summary>
    /// Parses a playbook document. Accepts either a bare array of rules or an object
    /// with a <c>rules</c> array.
    ///
    /// Failure policy, chosen because this is a security control:
    ///  - A document that cannot be parsed at all falls back to <see cref="Default"/>
    ///    with an error recorded. Falling back to an EMPTY playbook would silently turn
    ///    off every response while the agent still looked healthy.
    ///  - An individual invalid rule is skipped with an error; the rest still load.
    ///  - A syntactically valid but empty rule list is honoured as written (no rules,
    ///    no errors) — that is a legitimate "detect only" posture.
    /// </summary>
    public static Playbook FromJson(string json, out IReadOnlyList<string> errors)
    {
        var errs = new List<string>();
        errors = errs;

        if (string.IsNullOrWhiteSpace(json))
        {
            errs.Add("playbook document is empty; falling back to the built-in default playbook");
            return Default();
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(json, new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
        }
        catch (JsonException ex)
        {
            errs.Add($"playbook is not valid JSON ({ex.Message}); falling back to the built-in default playbook");
            return Default();
        }

        using (doc)
        {
            JsonElement array;
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                array = doc.RootElement;
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                     doc.RootElement.TryGetProperty("rules", out var rulesProp) &&
                     rulesProp.ValueKind == JsonValueKind.Array)
            {
                array = rulesProp;
            }
            else
            {
                errs.Add("playbook must be a rule array or an object with a 'rules' array; " +
                         "falling back to the built-in default playbook");
                return Default();
            }

            var rules = new List<PlaybookRule>();
            var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int index = -1;

            foreach (var element in array.EnumerateArray())
            {
                index++;
                var rule = ParseRule(element, index, seenNames, errs);
                if (rule is not null)
                {
                    rules.Add(rule);
                    seenNames.Add(rule.Name);
                }
            }

            return new Playbook(rules);
        }
    }

    /// <summary>
    /// Evaluates the profile against the rules. Pure: no clock, no I/O, no side effects,
    /// so the same snapshot always yields the same plan.
    /// </summary>
    public PlaybookDecision Decide(ProfileSnapshot snapshot)
    {
        if (snapshot is null)
            return PlaybookDecision.None with { Explanation = "no snapshot supplied" };

        var actions = new List<PlaybookAction>();
        var seen = new HashSet<PlaybookAction>();
        var trace = new List<string>();
        string matched = "";
        bool stopped = false;

        foreach (var rule in _rules)
        {
            if (!Matches(rule, snapshot, out string why)) continue;

            if (matched.Length == 0) matched = rule.Name;
            trace.Add($"{rule.Name} [{why}]");

            foreach (var a in rule.Actions)
                if (seen.Add(a)) actions.Add(a);

            if (rule.Stop) { stopped = true; break; }
        }

        if (matched.Length == 0)
        {
            return PlaybookDecision.None with
            {
                Explanation = $"no rule matched (score={snapshot.Score}, trusted={snapshot.Trusted}, " +
                              $"process={Describe(snapshot.ProcessName)}, techniques={Join(snapshot.Techniques)})"
            };
        }

        var sb = new StringBuilder();
        sb.Append("matched ").Append(string.Join("; ", trace));
        if (stopped) sb.Append(" (stop)");
        sb.Append(" => ").Append(actions.Count == 0 ? "no action" : string.Join(", ", actions));

        return new PlaybookDecision
        {
            Actions = actions,
            MatchedRule = matched,
            Explanation = sb.ToString()
        };
    }

    // ---------------------------------------------------------------- matching

    private static bool Matches(PlaybookRule rule, ProfileSnapshot s, out string why)
    {
        why = "";
        var parts = new List<string>();

        if (s.Score < rule.MinScore) return false;
        if (rule.MinScore > 0) parts.Add($"score {s.Score}>={rule.MinScore}");

        if (rule.RequireUntrusted)
        {
            if (s.Trusted) return false;
            parts.Add("untrusted");
        }

        if (rule.RequiredTechniques.Length > 0)
        {
            foreach (var t in rule.RequiredTechniques)
            {
                if (!ContainsTechnique(s.Techniques, t)) return false;
            }
            parts.Add("techniques " + string.Join("+", rule.RequiredTechniques));
        }

        if (rule.ProcessNameGlobs.Length > 0)
        {
            string? hit = null;
            foreach (var g in rule.ProcessNameGlobs)
            {
                if (MatchesGlob(g, s.ProcessName)) { hit = g; break; }
            }
            if (hit is null) return false;
            parts.Add("name~" + hit);
        }

        why = parts.Count == 0 ? "unconditional" : string.Join(", ", parts);
        return true;
    }

    private static bool ContainsTechnique(IReadOnlyList<string> techniques, string wanted)
    {
        foreach (var t in techniques)
        {
            if (string.Equals(t, wanted, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    /// <summary>
    /// Anchored, case-insensitive glob match supporting <c>*</c> (any run, possibly
    /// empty) and <c>?</c> (exactly one character).
    ///
    /// Hand-written rather than translated to a Regex on purpose: an operator-supplied
    /// pattern reaching a regex engine is a ReDoS foot-gun, and translating would also
    /// mean escaping every other regex metacharacter correctly. This loop is linear in
    /// the common case and cannot backtrack catastrophically because it only ever
    /// remembers the single most recent <c>*</c>.
    /// </summary>
    internal static bool MatchesGlob(string pattern, string text)
    {
        pattern ??= "";
        text ??= "";

        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || CharEquals(pattern[p], text[t])))
            {
                p++; t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }

    private static bool CharEquals(char a, char b)
        => a == b || char.ToUpperInvariant(a) == char.ToUpperInvariant(b);

    // ----------------------------------------------------------------- parsing

    private static PlaybookRule? ParseRule(JsonElement element, int index,
                                           HashSet<string> seenNames, List<string> errs)
    {
        string label = $"rule[{index}]";

        if (element.ValueKind != JsonValueKind.Object)
        {
            errs.Add($"{label}: expected an object, found {element.ValueKind}; rule skipped");
            return null;
        }

        string name = GetString(element, "name");
        if (string.IsNullOrWhiteSpace(name))
        {
            errs.Add($"{label}: 'name' is required; rule skipped");
            return null;
        }
        name = name.Trim();
        label = $"rule[{index}] '{name}'";

        if (seenNames.Contains(name))
        {
            // Duplicates are rejected so PlaybookDecision.MatchedRule stays unambiguous
            // in the audit trail. The first rule with the name wins.
            errs.Add($"{label}: duplicate rule name; rule skipped (the first one wins)");
            return null;
        }

        int minScore = 0;
        if (element.TryGetProperty("minScore", out var scoreProp))
        {
            if (scoreProp.ValueKind != JsonValueKind.Number || !scoreProp.TryGetInt32(out minScore))
            {
                errs.Add($"{label}: 'minScore' must be an integer; rule skipped");
                return null;
            }
            if (minScore < 0)
            {
                errs.Add($"{label}: 'minScore' must be >= 0 (found {minScore}); rule skipped");
                return null;
            }
        }

        var techniques = GetStringArray(element, "requiredTechniques", label, errs);
        var globs = GetStringArray(element, "processNameGlobs", label, errs);

        bool requireUntrusted = false;
        if (element.TryGetProperty("requireUntrusted", out var untrustedProp))
        {
            if (untrustedProp.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                errs.Add($"{label}: 'requireUntrusted' must be a boolean; rule skipped");
                return null;
            }
            requireUntrusted = untrustedProp.GetBoolean();
        }

        bool stop = false;
        if (element.TryGetProperty("stop", out var stopProp))
        {
            if (stopProp.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            {
                errs.Add($"{label}: 'stop' must be a boolean; rule skipped");
                return null;
            }
            stop = stopProp.GetBoolean();
        }

        var actions = new List<PlaybookAction>();
        if (element.TryGetProperty("actions", out var actionsProp))
        {
            if (actionsProp.ValueKind != JsonValueKind.Array)
            {
                errs.Add($"{label}: 'actions' must be an array; rule skipped");
                return null;
            }
            foreach (var a in actionsProp.EnumerateArray())
            {
                if (a.ValueKind != JsonValueKind.String)
                {
                    errs.Add($"{label}: action entries must be strings; rule skipped");
                    return null;
                }
                string raw = (a.GetString() ?? "").Trim();
                // Enum.TryParse also accepts the underlying number ("4"), which would let a
                // typo silently select an unrelated action, so require a name.
                bool named = raw.Length > 0 && char.IsLetter(raw[0]);
                if (!named ||
                    !Enum.TryParse<PlaybookAction>(raw, ignoreCase: true, out var parsed) ||
                    !Enum.IsDefined(parsed))
                {
                    // The whole rule is dropped rather than the single bad action: running
                    // a partial response the operator never wrote (Suspend without Kill,
                    // Kill without CollectTriage) is worse than falling through to the
                    // next rule and reporting the config error loudly.
                    errs.Add($"{label}: unknown action '{raw}'; rule skipped");
                    return null;
                }
                if (!actions.Contains(parsed)) actions.Add(parsed);
            }
        }

        return new PlaybookRule
        {
            Name = name,
            MinScore = minScore,
            RequiredTechniques = techniques,
            ProcessNameGlobs = globs,
            RequireUntrusted = requireUntrusted,
            Actions = actions.ToArray(),
            Stop = stop
        };
    }

    private static string GetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString() ?? ""
            : "";

    /// <summary>
    /// Reads a string array, dropping blank entries with a recorded error. A blank glob
    /// or technique is a no-op typo, so unlike an unknown action it does not invalidate
    /// the whole rule — dropping it changes nothing about what the rule orders.
    /// </summary>
    private static string[] GetStringArray(JsonElement element, string property, string label, List<string> errs)
    {
        if (!element.TryGetProperty(property, out var prop)) return Array.Empty<string>();
        if (prop.ValueKind != JsonValueKind.Array)
        {
            errs.Add($"{label}: '{property}' must be an array; treated as empty");
            return Array.Empty<string>();
        }

        var values = new List<string>();
        foreach (var item in prop.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                errs.Add($"{label}: '{property}' entries must be strings; entry ignored");
                continue;
            }
            string v = (item.GetString() ?? "").Trim();
            if (v.Length == 0)
            {
                errs.Add($"{label}: '{property}' contains a blank entry; entry ignored");
                continue;
            }
            values.Add(v);
        }
        return values.ToArray();
    }

    private static string Describe(string s) => string.IsNullOrEmpty(s) ? "(unknown)" : s;

    private static string Join(IReadOnlyList<string> items)
        => items.Count == 0 ? "(none)" : string.Join(",", items);
}
