using System.Globalization;
using System.Net;
using System.Net.Sockets;
using ProcessShield.Core;

namespace ProcessShield.Detection;

/// <summary>
/// Comparison operators a <see cref="RuleCondition"/> may use.
///
/// The set is deliberately small and total: every operator can be evaluated against a
/// plain string (or a small list of strings) with no side effects, so a rule can never
/// read a file, spawn a process or block the detection thread. Anything richer than this
/// belongs in C#, not in a community-authored JSON file.
/// </summary>
public enum MatchOp
{
    /// <summary>Exact string equality.</summary>
    Equals,
    /// <summary>True when no value of the field equals <see cref="RuleCondition.Value"/>.</summary>
    NotEquals,
    /// <summary>Substring test.</summary>
    Contains,
    /// <summary>True when no value of the field contains <see cref="RuleCondition.Value"/>.</summary>
    NotContains,
    StartsWith,
    EndsWith,
    /// <summary>.NET regular expression, compiled once at load with a 250 ms match timeout.</summary>
    Regex,
    /// <summary>Set membership against <see cref="RuleCondition.Values"/>.</summary>
    In,
    /// <summary>True when no value of the field is in <see cref="RuleCondition.Values"/>.</summary>
    NotIn,
    /// <summary>Numeric comparison. Both sides accept decimal or <c>0x</c> hex.</summary>
    GreaterThan,
    /// <summary>Numeric comparison. Both sides accept decimal or <c>0x</c> hex.</summary>
    LessThan,
    /// <summary>Field is present and non-empty.</summary>
    Exists,
    /// <summary>Field is absent or empty.</summary>
    NotExists,
    /// <summary>IPv4/IPv6 prefix membership, e.g. <c>10.0.0.0/8</c>.</summary>
    CidrIn
}

/// <summary>
/// One field test. <see cref="Value"/> is used by the single-operand operators and
/// <see cref="Values"/> by <see cref="MatchOp.In"/> / <see cref="MatchOp.NotIn"/> /
/// <see cref="MatchOp.CidrIn"/>.
///
/// Matching is case-INSENSITIVE by default because almost everything a rule looks at on
/// Windows (paths, process names, registry keys, DNS names) is case-insensitive in
/// practice, and a rule that silently fails on <c>PowerShell.exe</c> vs
/// <c>powershell.exe</c> is worse than useless. Set <see cref="CaseSensitive"/> for the
/// rare case (base64 blobs, mixed-case tokens) where case actually carries signal.
/// </summary>
public sealed record RuleCondition
{
    /// <summary>Field name from the rule field table; resolved case-insensitively.</summary>
    public required string Field { get; init; }

    public required MatchOp Op { get; init; }

    /// <summary>Single operand. Ignored by <see cref="MatchOp.In"/>/<see cref="MatchOp.NotIn"/>.</summary>
    public string Value { get; init; } = "";

    /// <summary>Operand list for the set operators. Empty for everything else.</summary>
    public IReadOnlyList<string> Values { get; init; } = Array.Empty<string>();

    /// <summary>Opt in to ordinal, case-sensitive comparison.</summary>
    public bool CaseSensitive { get; init; }
}

/// <summary>
/// One alternative in a rule: an AND of <see cref="All"/> that is cancelled by any hit in
/// <see cref="None"/>. A rule fires when ANY of its clauses matches, so clauses give you OR
/// without a nested boolean grammar that contributors would have to learn.
///
/// A clause with an empty <see cref="All"/> is rejected by validation. A "none-only" clause
/// would match every signal on the endpoint, which is never what an author means and is an
/// easy way to accidentally ship an alert storm.
/// </summary>
public sealed record RuleClause
{
    /// <summary>Every condition here must match.</summary>
    public IReadOnlyList<RuleCondition> All { get; init; } = Array.Empty<RuleCondition>();

    /// <summary>If any condition here matches, the clause does not fire. Use for exclusions.</summary>
    public IReadOnlyList<RuleCondition> None { get; init; } = Array.Empty<RuleCondition>();
}

/// <summary>
/// A single JSON-authored detection. This is the whole contract a contributor has to learn:
/// identity and provenance at the top, the boolean test in <see cref="Detection"/>, and an
/// honest <see cref="FalsePositives"/> list so whoever tunes the deployment knows what they
/// are about to see.
/// </summary>
public sealed record DetectionRule
{
    /// <summary>Stable, unique, whitespace-free id. Appears in every alert and in the audit log.</summary>
    public required string Id { get; init; }

    /// <summary>One-line analyst-facing summary. This is what shows up in the alert.</summary>
    public string Title { get; init; } = "";

    /// <summary>Why this behaviour is suspicious and what an analyst should check next.</summary>
    public string Description { get; init; } = "";

    public string Author { get; init; } = "";

    /// <summary><c>informational</c> | <c>low</c> | <c>medium</c> | <c>high</c> | <c>critical</c>.</summary>
    public string Severity { get; init; } = "medium";

    /// <summary>
    /// Points added to the process's risk score when this fires. The engine deliberately
    /// scores rather than alerts outright: a single LOLBin launch is noise, the same launch
    /// plus a credential-store read plus an outbound connection is an incident.
    /// </summary>
    public int Score { get; init; }

    /// <summary>MITRE ATT&amp;CK technique ids, e.g. <c>["T1059.001"]</c>.</summary>
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();

    /// <summary>Public write-ups, ATT&amp;CK pages, vendor blogs backing the logic.</summary>
    public IReadOnlyList<string> References { get; init; } = Array.Empty<string>();

    public bool Enabled { get; init; } = true;

    /// <summary>
    /// When true the consumer should score this rule at most once per process. The engine
    /// itself is stateless across signals, so it only surfaces the flag; de-duplication lives
    /// in <c>ThreatProfile.FiredOnce</c>, which is the object that actually knows the process.
    /// </summary>
    public bool OncePerProcess { get; init; }

    /// <summary>
    /// <see cref="SignalKind"/> names this rule applies to. Empty means every kind. This is a
    /// pure performance gate -- a rule that names its kinds is skipped before any field is
    /// resolved, which matters when a busy endpoint pushes thousands of signals a second.
    /// </summary>
    public IReadOnlyList<string> Kinds { get; init; } = Array.Empty<string>();

    /// <summary>Clauses, OR-ed together.</summary>
    public IReadOnlyList<RuleClause> Detection { get; init; } = Array.Empty<RuleClause>();

    /// <summary>
    /// Known benign causes. Required by review: a detection whose author cannot name a false
    /// positive has usually not deployed it anywhere real.
    /// </summary>
    public IReadOnlyList<string> FalsePositives { get; init; } = Array.Empty<string>();
}

/// <summary>
/// One problem found in a rule. Messages that begin with <see cref="NotePrefix"/> are
/// advisory: they are surfaced to the operator but do not stop the rule from loading.
/// </summary>
public sealed record RuleValidationError(string RuleId, string Message)
{
    /// <summary>Marker for a non-blocking, advisory finding.</summary>
    public const string NotePrefix = "note: ";

    /// <summary>
    /// False for advisory findings. The main advisory case is an ATT&amp;CK technique id that
    /// the local <see cref="AttackCatalog"/> has not been updated for: new sub-techniques
    /// appear faster than a hard-coded table, and refusing to load an otherwise-correct rule
    /// over a stale lookup table would punish contributors for our lag.
    /// </summary>
    public bool IsBlocking => !Message.StartsWith(NotePrefix, StringComparison.Ordinal);

    public override string ToString() =>
        string.IsNullOrEmpty(RuleId) ? Message : RuleId + ": " + Message;
}

/// <summary>
/// The outcome of a load: the rules that survived validation plus every problem found.
/// A bad rule never fails the load -- an operator who fat-fingers one regex must not lose
/// the other sixty detections protecting the endpoint.
/// </summary>
public sealed record RuleSet(IReadOnlyList<DetectionRule> Rules, IReadOnlyList<RuleValidationError> Errors)
{
    public static readonly RuleSet Empty =
        new(Array.Empty<DetectionRule>(), Array.Empty<RuleValidationError>());

    /// <summary>Errors that actually cost you a rule, i.e. excluding advisory notes.</summary>
    public IEnumerable<RuleValidationError> BlockingErrors => Errors.Where(e => e.IsBlocking);

    /// <summary>Convenience for building an engine over a single hand-written rule.</summary>
    public static RuleSet Of(params DetectionRule[] rules) =>
        new(rules, Array.Empty<RuleValidationError>());
}

/// <summary>
/// The small amount of per-process state a rule may see beyond the signal itself.
/// Everything here is data the owning <c>ThreatProfile</c> already tracks; the rule engine
/// never reaches back into the process store, which keeps evaluation pure and testable.
/// </summary>
public sealed record RuleContext
{
    /// <summary>
    /// The subject process's own image name, carried from its ThreatProfile.
    ///
    /// This exists because most signals do NOT carry a process name -- a FileCreate,
    /// DnsQuery, RegistryWrite or ProcessAccess event has a pid and a target, nothing more.
    /// Resolving <c>processName</c> from the signal alone silently made every
    /// <c>none: processName in [...]</c> exclusion in the shipped rule packs inert, which is
    /// exactly the guard those packs use to avoid flagging a browser for reading its own
    /// profile.
    /// </summary>
    public string ProcessName { get; init; } = "";

    /// <summary>Immediate parent's image name, e.g. <c>winword.exe</c>. Empty when unknown.</summary>
    public string ParentName { get; init; } = "";

    /// <summary>Ancestor image names, nearest parent first.</summary>
    public IReadOnlyList<string> Ancestry { get; init; } = Array.Empty<string>();

    /// <summary>Current risk score of the subject process, before this signal is scored.</summary>
    public int Score { get; init; }

    /// <summary>True when the image is signed by an allowlisted publisher.</summary>
    public bool Trusted { get; init; }

    /// <summary>Context for a signal with no known process history.</summary>
    public static readonly RuleContext Empty = new();
}

/// <summary>Identifies one resolvable rule field. Kept as an enum so matching is a jump table.</summary>
internal enum RuleField
{
    Kind, Pid, ParentPid, TargetPid, ProcessName, ImagePath, CommandLine, FilePath,
    FileName, FileExtension, RemoteAddress, RemotePort, Domain, RegistryKey, RegistryValue,
    PipeName, ScriptText, User, Detail, PrimaryTarget, ParentName, Ancestry, Score,
    DesiredAccess, Trusted
}

/// <summary>
/// Zero-or-more string values for one field. Almost every field is single-valued, so the
/// common case is stored inline and costs no allocation; only <c>ancestry</c> and the
/// symbolic expansion of <c>desiredAccess</c> carry a list.
/// </summary>
internal readonly struct FieldValues
{
    private readonly string? _single;
    private readonly IReadOnlyList<string>? _many;

    private FieldValues(string? single, IReadOnlyList<string>? many)
    {
        _single = single;
        _many = many;
    }

    /// <summary>A single value. <c>null</c> means the field is not present on this signal.</summary>
    public static FieldValues One(string? value) => new(value, null);

    public static FieldValues Many(IReadOnlyList<string>? values) =>
        values is null || values.Count == 0 ? new(null, null) : new(null, values);

    public static readonly FieldValues None = new(null, null);

    public int Count => _many?.Count ?? (_single is null ? 0 : 1);

    public string this[int index] => _many is not null ? (_many[index] ?? "") : (_single ?? "");

    /// <summary>True when at least one value is a non-empty string.</summary>
    public bool HasContent
    {
        get
        {
            int n = Count;
            for (int i = 0; i < n; i++)
                if (!string.IsNullOrEmpty(this[i])) return true;
            return false;
        }
    }

    /// <summary>First non-empty value, or null. Used to quote evidence in an explanation.</summary>
    public string? FirstNonEmpty()
    {
        int n = Count;
        for (int i = 0; i < n; i++)
        {
            string v = this[i];
            if (!string.IsNullOrEmpty(v)) return v;
        }
        return null;
    }
}

/// <summary>
/// The rule field table: the complete vocabulary a JSON rule may name. Kept in one place so
/// validation can reject a typo at LOAD time rather than silently never matching at run
/// time -- a rule that quietly never fires is the worst failure mode a detection can have.
/// </summary>
internal static class RuleFields
{
    // Enum.ToString() allocates; signal kinds are resolved on the hot path, so cache them.
    private static readonly string[] KindNames = Enum.GetNames<SignalKind>();

    private static readonly Dictionary<string, RuleField> ByName = new(StringComparer.OrdinalIgnoreCase)
    {
        ["kind"] = RuleField.Kind,
        ["pid"] = RuleField.Pid,
        ["parentPid"] = RuleField.ParentPid,
        ["targetPid"] = RuleField.TargetPid,
        ["processName"] = RuleField.ProcessName,
        ["imagePath"] = RuleField.ImagePath,
        ["commandLine"] = RuleField.CommandLine,
        ["filePath"] = RuleField.FilePath,
        ["fileName"] = RuleField.FileName,
        ["fileExtension"] = RuleField.FileExtension,
        ["remoteAddress"] = RuleField.RemoteAddress,
        ["remotePort"] = RuleField.RemotePort,
        ["domain"] = RuleField.Domain,
        ["registryKey"] = RuleField.RegistryKey,
        ["registryValue"] = RuleField.RegistryValue,
        ["pipeName"] = RuleField.PipeName,
        ["scriptText"] = RuleField.ScriptText,
        ["user"] = RuleField.User,
        ["detail"] = RuleField.Detail,
        ["primaryTarget"] = RuleField.PrimaryTarget,
        ["parentName"] = RuleField.ParentName,
        ["ancestry"] = RuleField.Ancestry,
        ["score"] = RuleField.Score,
        ["desiredAccess"] = RuleField.DesiredAccess,
        ["trusted"] = RuleField.Trusted
    };

    private static readonly string[] Canonical = BuildCanonical();

    /// <summary>Every field name, canonically cased and sorted. Used in error messages and docs.</summary>
    public static IReadOnlyList<string> KnownNames => Canonical;

    public static bool TryResolve(string? name, out RuleField field)
    {
        field = default;
        return !string.IsNullOrWhiteSpace(name) && ByName.TryGetValue(name.Trim(), out field);
    }

    /// <summary>Canonical spelling of a field, for stable explanation text.</summary>
    public static string NameOf(RuleField field)
    {
        foreach (var kv in ByName)
            if (kv.Value == field) return kv.Key;
        return field.ToString();
    }

    /// <summary>
    /// Resolve a field against a signal plus its process context. Never throws and never
    /// returns null for a present-but-empty field: absent (Count 0) and empty (Count 1, "")
    /// are distinct, because <c>Exists</c> has to be able to tell them apart.
    /// </summary>
    public static FieldValues Resolve(RuleField field, Signal s, RuleContext ctx)
    {
        switch (field)
        {
            case RuleField.Kind: return FieldValues.One(KindNames[(int)s.Kind]);
            case RuleField.Pid: return FieldValues.One(s.Pid.ToString(CultureInfo.InvariantCulture));
            case RuleField.ParentPid: return FieldValues.One(s.ParentPid.ToString(CultureInfo.InvariantCulture));
            case RuleField.TargetPid: return FieldValues.One(s.TargetPid.ToString(CultureInfo.InvariantCulture));
            // Fall back to the profile's known name: most signal kinds carry no process
            // name of their own, and without this every processName exclusion is inert.
            case RuleField.ProcessName:
                return FieldValues.One(string.IsNullOrEmpty(s.ProcessName) ? ctx.ProcessName : s.ProcessName);
            case RuleField.ImagePath: return FieldValues.One(s.ImagePath);
            case RuleField.CommandLine: return FieldValues.One(s.CommandLine);
            case RuleField.FilePath: return FieldValues.One(s.FilePath);
            case RuleField.FileName: return FieldValues.One(LeafName(PathSource(s)));
            case RuleField.FileExtension: return FieldValues.One(Extension(PathSource(s)));
            case RuleField.RemoteAddress: return FieldValues.One(s.RemoteAddress);
            case RuleField.RemotePort: return FieldValues.One(s.RemotePort.ToString(CultureInfo.InvariantCulture));
            case RuleField.Domain: return FieldValues.One(s.Domain);
            case RuleField.RegistryKey: return FieldValues.One(s.RegistryKey);
            case RuleField.RegistryValue: return FieldValues.One(s.RegistryValue);
            case RuleField.PipeName: return FieldValues.One(s.PipeName);
            case RuleField.ScriptText: return FieldValues.One(s.ScriptText);
            case RuleField.User: return FieldValues.One(s.User);
            case RuleField.Detail: return FieldValues.One(s.Detail);
            case RuleField.PrimaryTarget: return FieldValues.One(s.PrimaryTarget);
            case RuleField.ParentName: return FieldValues.One(ctx.ParentName);
            case RuleField.Ancestry: return FieldValues.Many(ctx.Ancestry);
            case RuleField.Score: return FieldValues.One(ctx.Score.ToString(CultureInfo.InvariantCulture));
            case RuleField.DesiredAccess: return FieldValues.Many(ExpandAccessMask(s.DesiredAccess));
            case RuleField.Trusted: return FieldValues.One(ctx.Trusted ? "true" : "false");
            default: return FieldValues.None;
        }
    }

    /// <summary>
    /// Numeric view of a field for <c>greaterThan</c>/<c>lessThan</c>. Fields that are
    /// natively integers are read directly; anything else is parsed from its string form, so
    /// <c>remotePort greaterThan 1024</c> and <c>fileName greaterThan 5</c> both behave
    /// predictably (the latter simply never matches, which is the honest answer).
    /// </summary>
    public static bool TryResolveNumber(RuleField field, Signal s, RuleContext ctx, out long value)
    {
        switch (field)
        {
            case RuleField.Pid: value = s.Pid; return true;
            case RuleField.ParentPid: value = s.ParentPid; return true;
            case RuleField.TargetPid: value = s.TargetPid; return true;
            case RuleField.RemotePort: value = s.RemotePort; return true;
            case RuleField.Score: value = ctx.Score; return true;
            case RuleField.DesiredAccess: value = s.DesiredAccess; return true;
            default:
            {
                var fv = Resolve(field, s, ctx);
                int n = fv.Count;
                for (int i = 0; i < n; i++)
                    if (TryParseNumber(fv[i], out value)) return true;
                value = 0;
                return false;
            }
        }
    }

    /// <summary>Decimal or <c>0x</c>-prefixed hexadecimal, invariant culture, optional sign.</summary>
    public static bool TryParseNumber(string? text, out long value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        ReadOnlySpan<char> s = text.AsSpan().Trim();
        bool negative = false;
        if (s.Length > 0 && (s[0] == '-' || s[0] == '+'))
        {
            negative = s[0] == '-';
            s = s[1..];
        }
        if (s.Length > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X'))
        {
            if (!ulong.TryParse(s[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ulong hex)) return false;
            if (hex > long.MaxValue) return false;
            value = negative ? -(long)hex : (long)hex;
            return true;
        }
        if (!long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out long dec)) return false;
        value = negative ? -dec : dec;
        return true;
    }

    // FilePath is the specific artifact when a monitor supplies one; ImagePath is the
    // fallback so fileName/fileExtension still mean something on a ProcessStart.
    private static string PathSource(Signal s) =>
        string.IsNullOrEmpty(s.FilePath) ? s.ImagePath : s.FilePath!;

    private static string LeafName(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        int cut = path.LastIndexOfAny(PathSeparators);
        return cut < 0 ? path : path[(cut + 1)..];
    }

    private static string Extension(string path)
    {
        string leaf = LeafName(path);
        int dot = leaf.LastIndexOf('.');
        return dot <= 0 ? "" : leaf[dot..];
    }

    private static readonly char[] PathSeparators = { '\\', '/' };

    // Win32 process access rights. Expanding the mask into symbolic names lets a rule say
    // desiredAccess in ["PROCESS_VM_READ"] instead of forcing every author to reason about
    // bitwise arithmetic, which the operator set deliberately does not provide.
    private static readonly (uint Mask, string Name)[] AccessRights =
    {
        (0x0001u, "PROCESS_TERMINATE"),
        (0x0002u, "PROCESS_CREATE_THREAD"),
        (0x0004u, "PROCESS_SET_SESSIONID"),
        (0x0008u, "PROCESS_VM_OPERATION"),
        (0x0010u, "PROCESS_VM_READ"),
        (0x0020u, "PROCESS_VM_WRITE"),
        (0x0040u, "PROCESS_DUP_HANDLE"),
        (0x0080u, "PROCESS_CREATE_PROCESS"),
        (0x0100u, "PROCESS_SET_QUOTA"),
        (0x0200u, "PROCESS_SET_INFORMATION"),
        (0x0400u, "PROCESS_QUERY_INFORMATION"),
        (0x0800u, "PROCESS_SUSPEND_RESUME"),
        (0x1000u, "PROCESS_QUERY_LIMITED_INFORMATION"),
        (0x2000u, "PROCESS_SET_LIMITED_INFORMATION"),
        (0x00010000u, "DELETE"),
        (0x00020000u, "READ_CONTROL"),
        (0x00040000u, "WRITE_DAC"),
        (0x00080000u, "WRITE_OWNER"),
        (0x00100000u, "SYNCHRONIZE")
    };

    private const uint ProcessAllAccess = 0x1FFFFFu;   // Vista+ value

    /// <summary>
    /// Expand an access mask into [decimal, 0xhex, ...symbolic flag names]. A mask of 0 still
    /// yields its numeric forms so <c>desiredAccess exists</c> stays meaningful.
    /// </summary>
    private static string[] ExpandAccessMask(uint mask)
    {
        var list = new List<string>(6)
        {
            mask.ToString(CultureInfo.InvariantCulture),
            "0x" + mask.ToString("X", CultureInfo.InvariantCulture)
        };
        if ((mask & ProcessAllAccess) == ProcessAllAccess) list.Add("PROCESS_ALL_ACCESS");
        foreach (var (bit, name) in AccessRights)
            if ((mask & bit) == bit) list.Add(name);
        return list.ToArray();
    }

    private static string[] BuildCanonical()
    {
        var names = ByName.Keys.ToArray();
        Array.Sort(names, StringComparer.OrdinalIgnoreCase);
        return names;
    }
}

/// <summary>
/// A parsed CIDR prefix. Written by hand rather than pulled from a package because the
/// project takes no new dependencies, and prefix matching is twenty lines.
///
/// LIMITATION: an IPv4 address is never matched against an IPv6 prefix and vice versa, even
/// for IPv4-mapped forms such as <c>::ffff:1.2.3.4</c>. Write both prefixes if you need both.
/// </summary>
internal sealed class CidrRange
{
    private readonly byte[] _network;
    private readonly int _bits;
    private readonly AddressFamily _family;

    private CidrRange(byte[] network, int bits, AddressFamily family)
    {
        _network = network;
        _bits = bits;
        _family = family;
    }

    /// <summary>
    /// Parses <c>a.b.c.d/len</c>, <c>addr::/len</c> or a bare address (treated as a host
    /// route). Host bits outside the prefix are ignored, so <c>10.1.2.3/8</c> behaves as
    /// <c>10.0.0.0/8</c> instead of silently never matching.
    /// </summary>
    public static bool TryParse(string? text, out CidrRange? range)
    {
        range = null;
        if (string.IsNullOrWhiteSpace(text)) return false;
        string s = text.Trim();

        int slash = s.LastIndexOf('/');
        string addrPart = slash < 0 ? s : s[..slash];
        if (!IPAddress.TryParse(addrPart, out var addr)) return false;

        byte[] bytes = addr.GetAddressBytes();
        int maxBits = bytes.Length * 8;
        int bits = maxBits;
        if (slash >= 0)
        {
            if (!int.TryParse(s.AsSpan(slash + 1), NumberStyles.None, CultureInfo.InvariantCulture, out bits))
                return false;
            if (bits < 0 || bits > maxBits) return false;
        }

        MaskInPlace(bytes, bits);
        range = new CidrRange(bytes, bits, addr.AddressFamily);
        return true;
    }

    /// <summary>True when <paramref name="candidate"/> parses as an address inside this prefix.</summary>
    public bool Contains(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        if (!IPAddress.TryParse(candidate.Trim(), out var addr)) return false;
        if (addr.AddressFamily != _family) return false;

        byte[] bytes = addr.GetAddressBytes();
        if (bytes.Length != _network.Length) return false;

        int whole = _bits / 8;
        for (int i = 0; i < whole; i++)
            if (bytes[i] != _network[i]) return false;

        int remainder = _bits % 8;
        if (remainder == 0) return true;
        int mask = 0xFF << (8 - remainder);
        return (bytes[whole] & mask) == (_network[whole] & mask);
    }

    private static void MaskInPlace(byte[] bytes, int bits)
    {
        for (int i = 0; i < bytes.Length; i++)
        {
            int keep = bits - (i * 8);
            if (keep >= 8) continue;
            bytes[i] = keep <= 0 ? (byte)0 : (byte)(bytes[i] & (0xFF << (8 - keep)));
        }
    }
}
