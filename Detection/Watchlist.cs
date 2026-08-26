using System.Text;
using BruceEDR.Configuration;

namespace BruceEDR.Detection;

/// <summary>How a watchlist entry identifies a process.</summary>
public enum WatchMatchKind
{
    /// <summary>Process image name, e.g. <c>mimikatz.exe</c>. Supports <c>*</c>/<c>?</c> globs.</summary>
    Name,
    /// <summary>Full image path. Substring by default; globs when the pattern contains <c>*</c>/<c>?</c>.</summary>
    Path,
    /// <summary>SHA-256 of the image, hex. Exact match.</summary>
    Hash,
    /// <summary>Substring of the process command line.</summary>
    CommandLine,
}

/// <summary>What BruceEDR does when a watchlist entry matches.</summary>
public enum WatchAction
{
    /// <summary>Add points and let the normal thresholds decide. The gentlest option.</summary>
    Score,
    /// <summary>Force at least a Warn verdict regardless of score.</summary>
    Warn,
    /// <summary>Force containment on sight, bypassing the trusted-publisher discount.</summary>
    Quarantine,
}

/// <summary>One compiled, validated watchlist rule.</summary>
public sealed class WatchlistEntry
{
    public required WatchMatchKind Kind { get; init; }
    /// <summary>Normalised pattern (lower-cased; names carry an implicit <c>.exe</c>).</summary>
    public required string Pattern { get; init; }
    /// <summary>The pattern exactly as the operator typed it, for display and audit.</summary>
    public required string RawPattern { get; init; }
    public required WatchAction Action { get; init; }
    /// <summary>Points added when <see cref="Action"/> is <see cref="WatchAction.Score"/>.</summary>
    public int Score { get; init; }
    /// <summary>Free-text operator note carried into the alert ("known red-team tool").</summary>
    public string Note { get; init; } = "";
    /// <summary>Stable rule id, e.g. <c>watchlist:name:mimikatz.exe</c>.</summary>
    public string RuleId { get; init; } = "";
    /// <summary>ATT&amp;CK techniques attributed to a hit, if the operator supplied any.</summary>
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();

    private readonly bool _isGlob;

    public WatchlistEntry() { }

    internal WatchlistEntry(bool isGlob) => _isGlob = isGlob;

    internal bool IsGlob => _isGlob;
}

/// <summary>A watchlist entry that fired, plus the human-readable reason.</summary>
public sealed record WatchHit(WatchlistEntry Entry, string Reason, WatchAction Action, bool Downgraded);

/// <summary>
/// Operator-defined "if you ever see this, act" list — the custom-detection surface.
///
/// The declarative JSON rule packs express behaviour ("a LOLBin spawned from Office"); this
/// expresses identity ("this exact tool is not allowed on my estate"), which is what an
/// operator reaches for when they already know the name of the thing they are hunting.
/// A hit does not have to out-score anything: <see cref="WatchAction.Quarantine"/> contains
/// on sight and deliberately bypasses the trusted-publisher discount, because "signed" is
/// not a defence when the operator has named the binary itself.
///
/// Immutable once compiled, so the owner thread reads it without a lock and a hot reload
/// swaps in a whole new instance.
/// </summary>
public sealed class Watchlist
{
    public static readonly Watchlist Empty = new(Array.Empty<WatchlistEntry>());

    private static int _nextVersion;

    private readonly WatchlistEntry[] _entries;
    /// <summary>True when any entry matches on hash, so the engine only pays for hashing then.</summary>
    public bool NeedsHash { get; }

    /// <summary>
    /// Identity of this compiled list, unique per instance. The engine caches which list it
    /// last evaluated a process against; without a version, a process that missed under the
    /// OLD list would never be re-checked against a newly loaded one, and a hot reload would
    /// silently fail to arm for everything already running.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// Report a <c>score</c>-action hit even when the process never crosses a threshold.
    /// Lives on the compiled list (not on the engine's start-up options) so that changing it
    /// takes effect on reload rather than at the next restart.
    /// </summary>
    public bool AlertOnEveryHit { get; private init; } = true;

    public IReadOnlyList<WatchlistEntry> Entries => _entries;
    public int Count => _entries.Length;

    private Watchlist(WatchlistEntry[] entries)
    {
        _entries = entries;
        NeedsHash = entries.Any(e => e.Kind == WatchMatchKind.Hash);
        Version = Interlocked.Increment(ref _nextVersion);
    }

    /// <summary>
    /// Windows processes that must never be suspended or killed. Suspending lsass, csrss,
    /// wininit, smss or services bugchecks the machine outright; the rest are close enough
    /// that stopping one takes the desktop with it. An operator can still watchlist these
    /// names -- the hit is reported -- but the action is downgraded to Warn so a typo in a
    /// containment rule cannot brick the host it is protecting.
    /// </summary>
    public static readonly IReadOnlySet<string> ProtectedProcesses =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "system", "idle", "registry", "memcompression", "memory compression",
            "ntoskrnl.exe", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe",
            "fontdrvhost.exe", "sihost.exe", "logonui.exe", "ctfmon.exe",
        };

    /// <summary>
    /// The same set put through <see cref="NormaliseName"/>, which is what lookups actually
    /// compare against. This matters: NormaliseName appends ".exe" to any name without a dot,
    /// so the five extension-less kernel processes above ("System", "Registry", "Memory
    /// Compression", ...) could never be found in the raw set and the guard silently did not
    /// cover them.
    /// </summary>
    private static readonly HashSet<string> ProtectedNormalised =
        ProtectedProcesses.Select(NormaliseName).ToHashSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Patterns so broad they would match most of the machine. Refused outright rather than
    /// compiled, because "quarantine *" is never what an operator meant to type.
    /// </summary>
    private static bool IsTooBroad(string pattern)
        => pattern is "*" or "*.*" or "*.exe" or "?" or "" || pattern.Trim('*', '?', '.').Length == 0;

    /// <summary>
    /// Compiles operator config into a validated watchlist. Bad entries are reported through
    /// <paramref name="onError"/> and skipped -- one typo must not discard the whole list.
    /// </summary>
    public static Watchlist Compile(IEnumerable<WatchlistEntryConfig>? config, Action<string>? onError = null,
                                    bool alertOnEveryHit = true)
    {
        if (config is null) return Empty;

        var list = new List<WatchlistEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var c in config)
        {
            if (c is null || !c.Enabled) continue;

            string raw = (c.Value ?? "").Trim();
            if (raw.Length == 0)
            {
                onError?.Invoke("watchlist entry skipped: empty value");
                continue;
            }

            if (!TryParseKind(c.Match, out var kind))
            {
                onError?.Invoke($"watchlist entry '{raw}' skipped: unknown match type '{c.Match}'");
                continue;
            }
            if (!TryParseAction(c.Action, out var action))
            {
                onError?.Invoke($"watchlist entry '{raw}' skipped: unknown action '{c.Action}'");
                continue;
            }

            string pattern = Normalise(kind, raw);

            if (kind == WatchMatchKind.Hash && !IsSha256(pattern))
            {
                onError?.Invoke($"watchlist entry '{raw}' skipped: not a SHA-256 hex digest");
                continue;
            }
            if (kind != WatchMatchKind.Hash && IsTooBroad(pattern))
            {
                onError?.Invoke($"watchlist entry '{raw}' skipped: pattern matches everything");
                continue;
            }

            string key = kind + "|" + pattern;
            if (!seen.Add(key))
            {
                onError?.Invoke($"watchlist entry '{raw}' skipped: duplicate of an earlier entry");
                continue;
            }

            bool glob = kind != WatchMatchKind.Hash && (pattern.Contains('*') || pattern.Contains('?'));
            list.Add(new WatchlistEntry(glob)
            {
                Kind = kind,
                Pattern = pattern,
                RawPattern = raw,
                Action = action,
                // A Score entry with no points would be a silent no-op; give it a sane default.
                Score = action == WatchAction.Score ? (c.Score > 0 ? c.Score : 50) : c.Score,
                Note = (c.Note ?? "").Trim(),
                RuleId = $"watchlist:{kind.ToString().ToLowerInvariant()}:{pattern}",
                Techniques = (c.Techniques ?? Array.Empty<string>())
                    .Where(t => !string.IsNullOrWhiteSpace(t))
                    .Select(t => t.Trim())
                    .ToArray(),
            });
        }

        // An empty list still gets a fresh instance when the policy differs, so the engine
        // sees a version change and re-evaluates.
        return list.Count == 0 && alertOnEveryHit
            ? Empty
            : new Watchlist(list.ToArray()) { AlertOnEveryHit = alertOnEveryHit };
    }

    /// <summary>
    /// First matching entry for a process identity, or null. Entries are evaluated in
    /// configured order, so an operator can put a specific allow-ish Score entry above a
    /// broader Quarantine one and have it win.
    /// </summary>
    public WatchHit? Match(string processName, string imagePath, string commandLine, string? sha256)
    {
        if (_entries.Length == 0) return null;

        string name = NormaliseName(processName);
        string path = (imagePath ?? "").ToLowerInvariant();
        string cmd = (commandLine ?? "").ToLowerInvariant();
        string hash = (sha256 ?? "").ToLowerInvariant();

        foreach (var e in _entries)
        {
            bool hit = e.Kind switch
            {
                WatchMatchKind.Name => name.Length > 0 && Matches(e, name),
                WatchMatchKind.Path => path.Length > 0 && Matches(e, path),
                WatchMatchKind.CommandLine => cmd.Length > 0 && Matches(e, cmd),
                WatchMatchKind.Hash => hash.Length > 0 && string.Equals(hash, e.Pattern, StringComparison.Ordinal),
                _ => false,
            };
            if (!hit) continue;

            // Safety valve: never hand a containment action for a core OS process to the
            // response worker. Report it, loudly, as a Warn instead.
            bool downgrade = e.Action == WatchAction.Quarantine && IsProtected(name);
            var action = downgrade ? WatchAction.Warn : e.Action;
            return new WatchHit(e, Describe(e, downgrade), action, downgrade);
        }
        return null;
    }

    /// <summary>True when the name is a Windows process that must never be contained.</summary>
    public static bool IsProtected(string processName)
        => ProtectedNormalised.Contains(NormaliseName(processName));

    private static bool Matches(WatchlistEntry e, string subject)
        => e.IsGlob
            ? Glob(e.Pattern, subject)
            : e.Kind == WatchMatchKind.Name
                ? string.Equals(subject, e.Pattern, StringComparison.Ordinal)
                : subject.Contains(e.Pattern, StringComparison.Ordinal);

    private static string Describe(WatchlistEntry e, bool downgraded)
    {
        var sb = new StringBuilder();
        sb.Append(e.Kind switch
        {
            WatchMatchKind.Name => "Watchlisted process name",
            WatchMatchKind.Path => "Watchlisted image path",
            WatchMatchKind.Hash => "Watchlisted image hash",
            WatchMatchKind.CommandLine => "Watchlisted command line",
            _ => "Watchlist match",
        });
        sb.Append(" '").Append(e.RawPattern).Append('\'');
        if (e.Note.Length > 0) sb.Append(" — ").Append(e.Note);
        if (downgraded)
            sb.Append(" [containment withheld: protected Windows process — reported only]");
        return sb.ToString();
    }

    /// <summary>
    /// Case-insensitive <c>*</c>/<c>?</c> glob. Iterative with backtracking, so it cannot
    /// blow the stack or go exponential on a hostile pattern the way a naive regex can.
    /// </summary>
    internal static bool Glob(string pattern, string subject)
    {
        int p = 0, s = 0, star = -1, mark = 0;
        while (s < subject.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == subject[s])) { p++; s++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = s; }
            else if (star >= 0) { p = star + 1; s = ++mark; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }

    private static string Normalise(WatchMatchKind kind, string raw)
    {
        string v = raw.ToLowerInvariant();
        return kind switch
        {
            WatchMatchKind.Name => NormaliseName(v),
            WatchMatchKind.Hash => v.Replace(" ", "").Replace(":", ""),
            _ => v,
        };
    }

    /// <summary>
    /// Reduces an image path or bare name to a comparable process name, and appends the
    /// implicit <c>.exe</c> so an operator can type either "mimikatz" or "mimikatz.exe".
    /// Glob patterns keep whatever the operator wrote.
    /// </summary>
    private static string NormaliseName(string value)
    {
        string v = (value ?? "").Trim().ToLowerInvariant();
        if (v.Length == 0) return "";
        int slash = v.LastIndexOfAny(new[] { '\\', '/' });
        if (slash >= 0) v = v[(slash + 1)..];
        if (v.Contains('*') || v.Contains('?')) return v;
        if (!v.Contains('.')) v += ".exe";
        return v;
    }

    private static bool IsSha256(string s)
        => s.Length == 64 && s.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));

    private static bool TryParseKind(string? s, out WatchMatchKind kind)
    {
        switch ((s ?? "name").Trim().ToLowerInvariant())
        {
            case "" or "name" or "process" or "processname": kind = WatchMatchKind.Name; return true;
            case "path" or "imagepath" or "image": kind = WatchMatchKind.Path; return true;
            case "hash" or "sha256": kind = WatchMatchKind.Hash; return true;
            case "cmdline" or "commandline" or "command": kind = WatchMatchKind.CommandLine; return true;
            default: kind = WatchMatchKind.Name; return false;
        }
    }

    private static bool TryParseAction(string? s, out WatchAction action)
    {
        switch ((s ?? "quarantine").Trim().ToLowerInvariant())
        {
            case "" or "quarantine" or "contain" or "block": action = WatchAction.Quarantine; return true;
            case "warn" or "alert": action = WatchAction.Warn; return true;
            case "score" or "points": action = WatchAction.Score; return true;
            default: action = WatchAction.Quarantine; return false;
        }
    }
}
