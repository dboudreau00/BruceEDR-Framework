using System.Buffers;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Attack = ProcessShield.Detection.AttackCatalog;

namespace ProcessShield.Telemetry;

/// <summary>
/// Renders one <see cref="ShieldEvent"/> into a single line of some wire schema.
///
/// WHY: ProcessShield's native JSON is convenient for ProcessShield and useless to
/// everyone else -- every SIEM would need a bespoke parser before the first alert is
/// searchable. Implementations of this interface let the same sink pipeline emit
/// Elastic Common Schema, OCSF or ArcSight CEF instead, which is the difference
/// between "another agent I have to integrate" and "a drop-in producer".
///
/// CONTRACT for implementors: <see cref="Format"/> must be pure (no clock, no
/// environment reads that can change between calls, no IO), must never throw for any
/// input -- including an event whose collection properties are null because it was
/// round-tripped through a lenient JSON deserializer -- and must return exactly one
/// line, i.e. no embedded CR/LF.
/// </summary>
public interface IEventFormatter
{
    /// <summary>Lower-case, stable identifier used in configuration files.</summary>
    string Name { get; }

    /// <summary>Renders the event as one line. Never throws; never returns null.</summary>
    string Format(ShieldEvent e);
}

/// <summary>
/// Shared, allocation-conscious helpers for the formatters.
///
/// Every accessor here is defensive on purpose. A <see cref="ShieldEvent"/> can reach a
/// formatter after a JSON round-trip (audit-log replay, an API POST, a saved capture),
/// and <c>{"Reasons":null}</c> deserializes to a null list even though the record
/// declares a non-nullable default. Formatters must survive that rather than take the
/// whole sink pipeline down with a NullReferenceException.
/// </summary>
internal static class SchemaUtil
{
    private static readonly char[] PathSeparators = { '\\', '/' };

    /// <summary>Null-safe string accessor.</summary>
    internal static string S(string? s) => s ?? "";

    /// <summary>Null-safe list accessor that also drops null/blank elements.</summary>
    internal static IReadOnlyList<string> List(IReadOnlyList<string>? l)
    {
        if (l is null || l.Count == 0) return Array.Empty<string>();
        List<string>? kept = null;
        for (int i = 0; i < l.Count; i++)
        {
            string? v = l[i];
            if (string.IsNullOrWhiteSpace(v)) continue;
            (kept ??= new List<string>(l.Count)).Add(v);
        }
        return kept is null ? Array.Empty<string>() : kept;
    }

    /// <summary>Technique ids, upper-cased, de-duplicated and ordinal-sorted so two
    /// events carrying the same techniques in a different order render identically.</summary>
    internal static IReadOnlyList<string> Techniques(IReadOnlyList<string>? l)
    {
        var raw = List(l);
        if (raw.Count == 0) return Array.Empty<string>();
        var set = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var t in raw) set.Add(t.Trim().ToUpperInvariant());
        var arr = new string[set.Count];
        set.CopyTo(arr);
        return arr;
    }

    /// <summary>Normalised level token: trimmed and upper-cased.</summary>
    internal static string Level(ShieldEvent e) => S(e.Level).Trim().ToUpperInvariant();

    /// <summary>Normalised category token: trimmed and lower-cased.</summary>
    internal static string Category(ShieldEvent e) => S(e.Category).Trim().ToLowerInvariant();

    /// <summary>
    /// Interprets a <see cref="DateTime"/> as UTC. An Unspecified kind is *assumed* UTC
    /// rather than converted, because every producer in this codebase populates
    /// <c>TimeUtc</c> from a UTC clock; converting would silently shift such an event by
    /// the local offset.
    /// </summary>
    internal static DateTime AsUtc(DateTime t) => t.Kind switch
    {
        DateTimeKind.Utc => t,
        DateTimeKind.Local => t.ToUniversalTime(),
        _ => DateTime.SpecifyKind(t, DateTimeKind.Utc)
    };

    /// <summary>ISO-8601 with milliseconds and an explicit Z, the shape Elasticsearch's
    /// default date mapping accepts without a custom format.</summary>
    internal static string Iso(DateTime t) =>
        AsUtc(t).ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);

    /// <summary>
    /// Milliseconds since the Unix epoch. A pre-epoch value (an event whose TimeUtc was
    /// never set) is clamped to 0: the negative epoch it would otherwise produce is
    /// rejected outright by several lakes, which would drop the record instead of
    /// storing an obviously-wrong timestamp that an analyst can spot.
    /// </summary>
    internal static long UnixMs(DateTime t)
    {
        double ms = (AsUtc(t) - DateTime.UnixEpoch).TotalMilliseconds;
        if (double.IsNaN(ms) || ms <= 0) return 0;
        return ms >= long.MaxValue ? long.MaxValue : (long)ms;
    }

    /// <summary>Last path segment. Hand-rolled because it must never throw on the
    /// half-formed paths that ETW occasionally hands us.</summary>
    internal static string BaseName(string? path)
    {
        string p = S(path);
        int i = p.LastIndexOfAny(PathSeparators);
        return i < 0 ? p : p[(i + 1)..];
    }

    /// <summary>
    /// Splits an <c>address:port</c> endpoint as produced by
    /// <c>Signal.PrimaryTarget</c>. Bare IPv6 literals also contain colons, so the split
    /// is only accepted when the left half is unambiguous -- a parsable IP address, a
    /// bracketed literal, or a token with no colon at all. On failure
    /// <paramref name="address"/> is still set to the trimmed input so callers can emit
    /// the whole string as an opaque destination.
    /// </summary>
    internal static bool TrySplitEndpoint(string? endpoint, out string address, out int port)
    {
        address = S(endpoint).Trim();
        port = 0;
        if (address.Length == 0) return false;

        int i = address.LastIndexOf(':');
        if (i <= 0 || i == address.Length - 1) return false;

        string left = address[..i];
        string right = address[(i + 1)..];
        if (!int.TryParse(right, NumberStyles.None, CultureInfo.InvariantCulture, out int p)) return false;
        if (p < 1 || p > 65535) return false;

        if (left.Length > 2 && left[0] == '[' && left[^1] == ']') left = left[1..^1];
        if (left.Length == 0) return false;
        if (left.Contains(':') && !IPAddress.TryParse(left, out _)) return false;

        address = left;
        port = p;
        return true;
    }

    /// <summary>Lower-case, dash-separated token suitable for an <c>event.action</c> or a
    /// CEF signature id.</summary>
    internal static string Slug(string? s)
    {
        string src = S(s);
        if (src.Length == 0) return "";
        var sb = new StringBuilder(src.Length);
        foreach (char c in src)
        {
            if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
            else if (c is '-' or '_' or '.') sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '-') sb.Append('-');
        }
        return sb.ToString().Trim('-');
    }

    /// <summary>One-line human summary, used wherever a schema requires a message but the
    /// event carries none. An empty <c>message</c> column is the fastest way to make an
    /// analyst distrust a new data source.</summary>
    internal static string Summary(ShieldEvent e)
    {
        var sb = new StringBuilder(64);
        string lvl = Level(e);
        sb.Append(lvl.Length == 0 ? "EVENT" : lvl);
        string proc = S(e.Process);
        if (proc.Length > 0) sb.Append(' ').Append(proc);
        if (e.Pid != 0) sb.Append(" (pid ").Append(e.Pid.ToString(CultureInfo.InvariantCulture)).Append(')');
        string trigger = S(e.Trigger);
        if (trigger.Length > 0) sb.Append(": ").Append(trigger);
        return sb.ToString();
    }

    /// <summary>The event's message, or a synthesised summary when it has none.</summary>
    internal static string MessageOf(ShieldEvent e)
    {
        string m = S(e.Message);
        return m.Length > 0 ? m : Summary(e);
    }

    /// <summary>
    /// Stable 128-bit content id, hex encoded.
    ///
    /// LIMITATION, stated plainly: <see cref="ShieldEvent"/> has no unique identifier, so
    /// this is derived from the event's canonical JSON. Two byte-identical events
    /// therefore share an id. That is deliberate -- it makes re-ingesting the same log
    /// file idempotent in the SIEM -- but it means a genuinely repeated, identical event
    /// (same tick, same fields) collapses to one document. TimeUtc has 100 ns resolution,
    /// so in practice only a replayed file collides.
    /// </summary>
    internal static string EventId(ShieldEvent e)
    {
        string canonical;
        try { canonical = Json.Event(e); }
        catch { canonical = Summary(e); }
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash, 0, 16).ToLowerInvariant();
    }

    /// <summary>Escapes a CEF *header* field: only backslash and pipe are special, and a
    /// line break is illegal outright so it is folded to a space.</summary>
    internal static string CefHeader(string? value)
    {
        string src = S(value);
        var sb = new StringBuilder(src.Length + 8);
        foreach (char c in src)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '|': sb.Append("\\|"); break;
                case '\r':
                case '\n': sb.Append(' '); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    /// <summary>
    /// Escapes a CEF *extension* value. The rules differ from the header and this is
    /// where most CEF producers are wrong: backslash and equals must be escaped, line
    /// breaks become the two-character sequences <c>\n</c> / <c>\r</c>, and a pipe is
    /// NOT escaped (it is only a delimiter inside the header).
    /// </summary>
    internal static string CefValue(string? value)
    {
        string src = S(value);
        var sb = new StringBuilder(src.Length + 8);
        foreach (char c in src)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '=': sb.Append("\\="); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    /// <summary>Writes a JSON string array property.</summary>
    internal static void WriteArray(Utf8JsonWriter w, string property, IEnumerable<string> values)
    {
        w.WriteStartArray(property);
        foreach (var v in values) w.WriteStringValue(v);
        w.WriteEndArray();
    }

    /// <summary>
    /// Serialises an object body with a writer configured for log transport: not indented
    /// (one event per line) and using the relaxed encoder so command lines keep their
    /// literal ampersands, angle brackets and non-ASCII characters instead of turning into
    /// a wall of numeric escapes. The output is still strictly valid JSON -- quotes,
    /// backslashes and control characters are escaped either way; "unsafe" in the
    /// encoder's name refers only to embedding the result in HTML, which never happens here.
    /// </summary>
    internal static string WriteObject(Action<Utf8JsonWriter> body)
    {
        var buffer = new ArrayBufferWriter<byte>(1024);
        using (var w = new Utf8JsonWriter(buffer, WriterOptions))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        SkipValidation = false
    };
}

/// <summary>
/// ProcessShield's own JSON shape. This is the historical format: the audit chain and
/// the API Studio replay both assume it, so it stays the default and stays byte-identical
/// to what <see cref="JsonlSink"/> writes.
/// </summary>
public sealed class NativeFormatter : IEventFormatter
{
    public string Name => "native";

    public string Format(ShieldEvent e)
    {
        if (e is null) return "{}";
        try { return Json.Event(e); }
        catch { return SchemaUtil.WriteObject(w => w.WriteString("message", SchemaUtil.Summary(e))); }
    }
}

/// <summary>
/// Elastic Common Schema 8.11 mapping.
///
/// WHY these exact field names matter: ECS is only useful if the fields land where the
/// prebuilt Elastic/Kibana content expects them. Renaming <c>process.parent.pid</c> to
/// something friendlier would break every out-of-the-box detection rule and every SIEM
/// pivot, so the mapping below is deliberately literal and nested (ECS documents use
/// nested objects, not dotted keys -- dotted keys work on ingest but break
/// <c>copy_to</c> and runtime fields).
///
/// Fields ProcessShield carries that ECS has no home for (the reason lines, the staged
/// archive list, the ancestry) are preserved under a <c>processshield</c> custom
/// namespace rather than dropped or crammed into an ECS field with different semantics.
/// </summary>
public sealed class EcsFormatter : IEventFormatter
{
    /// <summary>The ECS release this mapping was written against.</summary>
    public const string EcsVersion = "8.11.0";

    private static readonly ShieldEvent Fallback = new() { TimeUtc = default };

    private readonly string _hostName;

    /// <summary>Uses the machine name for <c>host.name</c>.</summary>
    public EcsFormatter() : this(Environment.MachineName) { }

    /// <summary>Host name injection keeps the formatter pure and lets tests assert on a
    /// fixed value instead of whatever the build agent is called.</summary>
    public EcsFormatter(string hostName) => _hostName = SchemaUtil.S(hostName);

    public string Name => "ecs";

    public string Format(ShieldEvent e)
    {
        var ev = e ?? Fallback;
        return SchemaUtil.WriteObject(w => Write(w, ev));
    }

    private void Write(Utf8JsonWriter w, ShieldEvent e)
    {
        string level = SchemaUtil.Level(e);
        string category = SchemaUtil.Category(e);
        var reasons = SchemaUtil.List(e.Reasons);
        var techniques = SchemaUtil.Techniques(e.Techniques);
        var ruleIds = SchemaUtil.List(e.RuleIds);
        var domains = SchemaUtil.List(e.Domains);
        var endpoints = SchemaUtil.List(e.RemoteEndpoints);
        var ancestry = SchemaUtil.List(e.Ancestry);
        var archives = SchemaUtil.List(e.StagedArchives);

        w.WriteString("@timestamp", SchemaUtil.Iso(e.TimeUtc));

        w.WriteStartObject("ecs");
        w.WriteString("version", EcsVersion);
        w.WriteEndObject();

        w.WriteStartObject("event");
        w.WriteString("kind", IsAlert(level) ? "alert" : "event");
        SchemaUtil.WriteArray(w, "category", Categories(level, category));
        SchemaUtil.WriteArray(w, "type", Types(level, category));
        w.WriteString("action", Action(e, level, category));
        w.WriteNumber("severity", Severity(level));
        w.WriteNumber("risk_score", e.Score);
        w.WriteString("dataset", "processshield.detection");
        w.WriteString("module", "processshield");
        w.WriteString("provider", EventFormatters.ProductName);
        w.WriteString("id", SchemaUtil.EventId(e));
        if (reasons.Count > 0) w.WriteString("reason", string.Join("; ", reasons));
        w.WriteEndObject();

        w.WriteString("message", SchemaUtil.MessageOf(e));

        w.WriteStartObject("host");
        if (_hostName.Length > 0) w.WriteString("name", _hostName);
        w.WriteStartObject("os");
        w.WriteString("type", "windows");
        w.WriteEndObject();
        w.WriteEndObject();

        WriteProcess(w, e);

        string user = SchemaUtil.S(e.User);
        if (user.Length > 0)
        {
            w.WriteStartObject("user");
            w.WriteString("name", user);
            w.WriteEndObject();
        }

        if (techniques.Count > 0)
        {
            var names = new List<string>(techniques.Count);
            var tactics = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var id in techniques)
            {
                var t = Attack.Lookup(id);
                names.Add(t.Name);
                if (!string.IsNullOrWhiteSpace(t.Tactic)) tactics.Add(t.Tactic);
            }

            w.WriteStartObject("threat");
            w.WriteString("framework", "MITRE ATT&CK");
            w.WriteStartObject("technique");
            SchemaUtil.WriteArray(w, "id", techniques);
            SchemaUtil.WriteArray(w, "name", names);
            w.WriteEndObject();
            w.WriteStartObject("tactic");
            SchemaUtil.WriteArray(w, "name", tactics);
            w.WriteEndObject();
            w.WriteEndObject();
        }

        if (ruleIds.Count > 0)
        {
            // ProcessShield rule ids are human-readable slugs ("lolbin-unusual-parent"),
            // so the id doubles as the name. Emitting a separate prettified name would be
            // inventing data the agent does not have.
            w.WriteStartObject("rule");
            SchemaUtil.WriteArray(w, "id", ruleIds);
            SchemaUtil.WriteArray(w, "name", ruleIds);
            w.WriteEndObject();
        }

        // ECS destination.* is a single object, so it is only populated when exactly one
        // endpoint is in play. With several, the list stays in related.ip and in the
        // custom namespace; picking one arbitrarily would make a Kibana map lie.
        if (endpoints.Count == 1)
        {
            bool split = SchemaUtil.TrySplitEndpoint(endpoints[0], out string address, out int port);
            w.WriteStartObject("destination");
            w.WriteString("address", address);
            if (IPAddress.TryParse(address, out _)) w.WriteString("ip", address);
            if (split) w.WriteNumber("port", port);
            w.WriteEndObject();
        }

        if (domains.Count > 0)
        {
            w.WriteStartObject("dns");
            w.WriteStartObject("question");
            SchemaUtil.WriteArray(w, "name", domains);
            w.WriteEndObject();
            w.WriteEndObject();
        }

        string incident = SchemaUtil.S(e.IncidentId);
        if (incident.Length > 0)
        {
            // ECS labels are keyword/keyword, so the value must stay a string.
            w.WriteStartObject("labels");
            w.WriteString("incident_id", incident);
            w.WriteEndObject();
        }

        WriteRelated(w, e, endpoints, domains, user);

        if (level.Length > 0 || category.Length > 0 || reasons.Count > 0 ||
            archives.Count > 0 || ancestry.Count > 0 || endpoints.Count > 0 ||
            SchemaUtil.S(e.Trigger).Length > 0)
        {
            w.WriteStartObject("processshield");
            if (level.Length > 0) w.WriteString("level", level);
            if (category.Length > 0) w.WriteString("category", category);
            string trigger = SchemaUtil.S(e.Trigger);
            if (trigger.Length > 0) w.WriteString("trigger", trigger);
            if (reasons.Count > 0) SchemaUtil.WriteArray(w, "reasons", reasons);
            if (archives.Count > 0) SchemaUtil.WriteArray(w, "staged_archives", archives);
            if (ancestry.Count > 0) SchemaUtil.WriteArray(w, "ancestry", ancestry);
            if (endpoints.Count > 0) SchemaUtil.WriteArray(w, "remote_endpoints", endpoints);
            w.WriteEndObject();
        }
    }

    private static void WriteProcess(Utf8JsonWriter w, ShieldEvent e)
    {
        string name = SchemaUtil.S(e.Process);
        string image = SchemaUtil.S(e.Image);
        string cmd = SchemaUtil.S(e.CommandLine);
        string sha = SchemaUtil.S(e.Sha256);
        if (e.Pid == 0 && e.ParentPid == 0 && name.Length == 0 &&
            image.Length == 0 && cmd.Length == 0 && sha.Length == 0) return;

        w.WriteStartObject("process");
        if (e.Pid != 0) w.WriteNumber("pid", e.Pid);
        if (name.Length > 0) w.WriteString("name", name);
        if (image.Length > 0) w.WriteString("executable", image);
        if (cmd.Length > 0) w.WriteString("command_line", cmd);
        if (sha.Length > 0)
        {
            w.WriteStartObject("hash");
            w.WriteString("sha256", sha);
            w.WriteEndObject();
        }
        if (e.ParentPid != 0)
        {
            w.WriteStartObject("parent");
            w.WriteNumber("pid", e.ParentPid);
            w.WriteEndObject();
        }
        w.WriteEndObject();
    }

    private void WriteRelated(
        Utf8JsonWriter w, ShieldEvent e,
        IReadOnlyList<string> endpoints, IReadOnlyList<string> domains, string user)
    {
        // related.* is what makes "show me everything about this IP" work in Elastic
        // without knowing which field the value came from.
        var ips = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var ep in endpoints)
        {
            SchemaUtil.TrySplitEndpoint(ep, out string address, out _);
            if (IPAddress.TryParse(address, out _)) ips.Add(address);
        }

        var hosts = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in domains) hosts.Add(d);
        if (_hostName.Length > 0) hosts.Add(_hostName);

        var hashes = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        string sha = SchemaUtil.S(e.Sha256);
        if (sha.Length > 0) hashes.Add(sha);

        if (ips.Count == 0 && hosts.Count == 0 && hashes.Count == 0 && user.Length == 0) return;

        w.WriteStartObject("related");
        if (ips.Count > 0) SchemaUtil.WriteArray(w, "ip", ips);
        if (hosts.Count > 0) SchemaUtil.WriteArray(w, "hosts", hosts);
        if (hashes.Count > 0) SchemaUtil.WriteArray(w, "hash", hashes);
        if (user.Length > 0) SchemaUtil.WriteArray(w, "user", new[] { user });
        w.WriteEndObject();
    }

    private static bool IsAlert(string level) => level is "WARN" or "QUARANTINE";

    /// <summary>ECS constrains event.category to a closed vocabulary, so the agent's own
    /// category token is translated and the raw value is kept under
    /// <c>processshield.category</c>.</summary>
    private static string[] Categories(string level, string category) => category switch
    {
        "detection" => level == "QUARANTINE"
            ? new[] { "intrusion_detection", "malware" }
            : new[] { "intrusion_detection" },
        "response" => new[] { "process" },
        "api" => new[] { "api" },
        _ => new[] { "host" }
    };

    /// <summary>event.type is also a closed vocabulary. A response action mutates host
    /// state, everything else is informational.</summary>
    private static string[] Types(string level, string category) =>
        category == "response" || level == "ACTION" ? new[] { "change" } : new[] { "info" };

    private static string Action(ShieldEvent e, string level, string category)
    {
        string slug = SchemaUtil.Slug(e.Trigger);
        if (slug.Length > 0) return slug;
        string fallback = SchemaUtil.Slug(category + "-" + level);
        return fallback.Length > 0 ? fallback : "event";
    }

    /// <summary>
    /// ECS defines event.severity as "the numeric severity according to your source" and
    /// fixes no scale, so this is a ProcessShield-local ordinal, documented here so a
    /// dashboard author does not have to guess: 1 informational, 3 an action we took,
    /// 5 a warning, 8 a quarantine, 0 an unrecognised level.
    /// </summary>
    private static int Severity(string level) => level switch
    {
        "QUARANTINE" => 8,
        "WARN" => 5,
        "ACTION" => 3,
        "INFO" => 1,
        _ => 0
    };
}

/// <summary>
/// OCSF 1.1 Detection Finding (class_uid 2004).
///
/// HONEST SCOPE NOTE: every ShieldEvent is emitted as a Detection Finding, including
/// purely informational system events. Splitting the stream across several OCSF classes
/// would give a more faithful model but would fragment the mapping and force consumers
/// to handle three shapes from one file; instead the finding's <c>severity_id</c> and
/// <c>status_id</c> carry that distinction and a lake that only wants real detections
/// can filter on them.
///
/// Anything OCSF has no slot for is placed in <c>unmapped</c>, which is exactly what that
/// object exists for -- silently dropping the reason lines would make the finding
/// unactionable.
/// </summary>
public sealed class OcsfFormatter : IEventFormatter
{
    /// <summary>OCSF schema release this mapping targets.</summary>
    public const string OcsfVersion = "1.1.0";

    /// <summary>
    /// ATT&amp;CK revision the technique ids were authored against. It describes the
    /// framework revision, not a claim that the bundled catalog is complete -- the
    /// catalog is a curated subset of Enterprise ATT&amp;CK.
    /// </summary>
    public const string AttackVersion = "14.1";

    private const int ClassUid = 2004;
    private const int CategoryUid = 2;
    private const int ActivityId = 1;      // Create
    private const int TypeUid = ClassUid * 100 + ActivityId;

    private static readonly ShieldEvent Fallback = new() { TimeUtc = default };

    private readonly string _hostName;

    public OcsfFormatter() : this(Environment.MachineName) { }

    /// <summary>Host name injection keeps the formatter pure and testable.</summary>
    public OcsfFormatter(string hostName) => _hostName = SchemaUtil.S(hostName);

    public string Name => "ocsf";

    public string Format(ShieldEvent e)
    {
        var ev = e ?? Fallback;
        return SchemaUtil.WriteObject(w => Write(w, ev));
    }

    private void Write(Utf8JsonWriter w, ShieldEvent e)
    {
        string level = SchemaUtil.Level(e);
        string category = SchemaUtil.Category(e);
        var reasons = SchemaUtil.List(e.Reasons);
        var techniques = SchemaUtil.Techniques(e.Techniques);
        var ruleIds = SchemaUtil.List(e.RuleIds);
        var domains = SchemaUtil.List(e.Domains);
        var endpoints = SchemaUtil.List(e.RemoteEndpoints);
        var ancestry = SchemaUtil.List(e.Ancestry);
        var archives = SchemaUtil.List(e.StagedArchives);
        string eventId = SchemaUtil.EventId(e);

        w.WriteNumber("activity_id", ActivityId);
        w.WriteString("activity_name", "Create");
        w.WriteNumber("category_uid", CategoryUid);
        w.WriteString("category_name", "Findings");
        w.WriteNumber("class_uid", ClassUid);
        w.WriteString("class_name", "Detection Finding");
        w.WriteNumber("type_uid", TypeUid);
        w.WriteString("type_name", "Detection Finding: Create");

        int severityId = SeverityId(level);
        int statusId = StatusId(level, category);
        w.WriteNumber("severity_id", severityId);
        w.WriteString("severity", SeverityName(severityId));
        w.WriteNumber("status_id", statusId);
        w.WriteString("status", StatusName(statusId));
        w.WriteNumber("time", SchemaUtil.UnixMs(e.TimeUtc));
        w.WriteNumber("risk_score", e.Score);
        w.WriteString("message", SchemaUtil.MessageOf(e));

        w.WriteStartObject("metadata");
        w.WriteString("uid", eventId);
        w.WriteString("version", OcsfVersion);
        w.WriteString("logged_time", SchemaUtil.Iso(e.TimeUtc));
        w.WriteStartObject("product");
        w.WriteString("name", EventFormatters.ProductName);
        w.WriteString("vendor_name", EventFormatters.VendorName);
        w.WriteString("version", EventFormatters.AgentVersion);
        w.WriteEndObject();
        w.WriteEndObject();

        w.WriteStartObject("finding_info");
        // The incident id groups every event raised for one process, which is precisely
        // OCSF's notion of a finding uid. Without one, fall back to the content id so the
        // field is never empty (consumers key on it).
        string incident = SchemaUtil.S(e.IncidentId);
        w.WriteString("uid", incident.Length > 0 ? incident : eventId);
        w.WriteString("title", Title(e, level));
        w.WriteString("desc", reasons.Count > 0 ? string.Join("; ", reasons) : SchemaUtil.MessageOf(e));
        SchemaUtil.WriteArray(w, "types", ruleIds.Count > 0 ? ruleIds : new[] { category.Length > 0 ? category : "event" });
        w.WriteEndObject();

        WriteProcess(w, e);

        if (techniques.Count > 0)
        {
            w.WriteStartArray("attacks");
            foreach (var id in techniques)
            {
                var t = Attack.Lookup(id);
                w.WriteStartObject();
                w.WriteStartObject("technique");
                w.WriteString("uid", t.Id.Length > 0 ? t.Id : id);
                w.WriteString("name", t.Name);
                w.WriteEndObject();
                w.WriteStartObject("tactic");
                w.WriteString("name", t.Tactic);
                w.WriteEndObject();
                w.WriteString("version", AttackVersion);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }

        WriteObservables(w, e, endpoints, domains);

        w.WriteStartObject("unmapped");
        if (level.Length > 0) w.WriteString("level", level);
        if (category.Length > 0) w.WriteString("category", category);
        string trigger = SchemaUtil.S(e.Trigger);
        if (trigger.Length > 0) w.WriteString("trigger", trigger);
        if (_hostName.Length > 0) w.WriteString("hostname", _hostName);
        if (reasons.Count > 0) SchemaUtil.WriteArray(w, "reasons", reasons);
        if (archives.Count > 0) SchemaUtil.WriteArray(w, "staged_archives", archives);
        if (ancestry.Count > 0) SchemaUtil.WriteArray(w, "ancestry", ancestry);
        if (endpoints.Count > 0) SchemaUtil.WriteArray(w, "remote_endpoints", endpoints);
        if (domains.Count > 0) SchemaUtil.WriteArray(w, "domains", domains);
        if (ruleIds.Count > 0) SchemaUtil.WriteArray(w, "rule_ids", ruleIds);
        w.WriteEndObject();
    }

    private static void WriteProcess(Utf8JsonWriter w, ShieldEvent e)
    {
        string name = SchemaUtil.S(e.Process);
        string image = SchemaUtil.S(e.Image);
        string cmd = SchemaUtil.S(e.CommandLine);
        string sha = SchemaUtil.S(e.Sha256);
        string user = SchemaUtil.S(e.User);
        if (e.Pid == 0 && e.ParentPid == 0 && name.Length == 0 && image.Length == 0 &&
            cmd.Length == 0 && sha.Length == 0 && user.Length == 0) return;

        w.WriteStartObject("process");
        if (e.Pid != 0) w.WriteNumber("pid", e.Pid);
        if (name.Length > 0) w.WriteString("name", name);
        if (cmd.Length > 0) w.WriteString("cmd_line", cmd);

        if (image.Length > 0 || sha.Length > 0)
        {
            w.WriteStartObject("file");
            w.WriteNumber("type_id", 1);   // OCSF file type: Regular File
            w.WriteString("name", SchemaUtil.BaseName(image));
            if (image.Length > 0) w.WriteString("path", image);
            if (sha.Length > 0)
            {
                w.WriteStartArray("hashes");
                w.WriteStartObject();
                w.WriteNumber("algorithm_id", 3);   // OCSF hash algorithm: SHA-256
                w.WriteString("algorithm", "SHA-256");
                w.WriteString("value", sha);
                w.WriteEndObject();
                w.WriteEndArray();
            }
            w.WriteEndObject();
        }

        if (user.Length > 0)
        {
            w.WriteStartObject("user");
            w.WriteString("name", user);
            w.WriteEndObject();
        }

        if (e.ParentPid != 0)
        {
            w.WriteStartObject("parent_process");
            w.WriteNumber("pid", e.ParentPid);
            w.WriteEndObject();
        }

        w.WriteEndObject();
    }

    private static void WriteObservables(
        Utf8JsonWriter w, ShieldEvent e,
        IReadOnlyList<string> endpoints, IReadOnlyList<string> domains)
    {
        // OCSF observable type ids: 1 Hostname, 2 IP Address, 8 Hash, 9 Process Name.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var items = new List<(string Name, int TypeId, string Value)>();

        void Add(string name, int typeId, string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return;
            if (!seen.Add(name + " " + value)) return;
            items.Add((name, typeId, value));
        }

        foreach (var ep in endpoints)
        {
            SchemaUtil.TrySplitEndpoint(ep, out string address, out _);
            if (IPAddress.TryParse(address, out _)) Add("dst_endpoint.ip", 2, address);
            else Add("dst_endpoint.hostname", 1, address);
        }
        foreach (var d in domains) Add("dns_query.hostname", 1, d);
        Add("file.hashes", 8, SchemaUtil.S(e.Sha256));
        Add("process.name", 9, SchemaUtil.S(e.Process));

        if (items.Count == 0) return;

        w.WriteStartArray("observables");
        foreach (var (name, typeId, value) in items)
        {
            w.WriteStartObject();
            w.WriteString("name", name);
            w.WriteNumber("type_id", typeId);
            w.WriteString("value", value);
            w.WriteEndObject();
        }
        w.WriteEndArray();
    }

    private static string Title(ShieldEvent e, string level)
    {
        string trigger = SchemaUtil.S(e.Trigger);
        if (trigger.Length > 0) return trigger;
        string proc = SchemaUtil.S(e.Process);
        if (proc.Length > 0) return (level.Length > 0 ? level : "EVENT") + " on " + proc;
        return level.Length > 0 ? level : "ProcessShield event";
    }

    /// <summary>
    /// OCSF 1.1 severity scale is 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
    /// 5 Critical, 6 Fatal. ProcessShield never emits 6: nothing this agent observes is
    /// a fatal condition of the monitored system itself.
    /// </summary>
    private static int SeverityId(string level) => level switch
    {
        "QUARANTINE" => 5,
        "WARN" => 3,
        "ACTION" => 2,
        "INFO" => 1,
        _ => 0
    };

    private static string SeverityName(int id) => id switch
    {
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        6 => "Fatal",
        _ => "Unknown"
    };

    /// <summary>
    /// Finding status: 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other. A
    /// response event is Resolved because the agent already acted; a detection is New;
    /// anything else is Other rather than being dressed up as a finding state it is not in.
    /// </summary>
    private static int StatusId(string level, string category)
    {
        if (category == "response" || level == "ACTION") return 4;
        if (level is "WARN" or "QUARANTINE") return 1;
        return 99;
    }

    private static string StatusName(int id) => id switch
    {
        1 => "New",
        2 => "In Progress",
        3 => "Suppressed",
        4 => "Resolved",
        99 => "Other",
        _ => "Unknown"
    };
}

/// <summary>
/// ArcSight Common Event Format (CEF:0).
///
/// The header is seven pipe-delimited fields followed by <c>key=value</c> extensions.
/// The escaping rules differ between the two halves and that asymmetry is where most
/// CEF producers are wrong -- see <see cref="SchemaUtil.CefHeader"/> and
/// <see cref="SchemaUtil.CefValue"/>.
///
/// LIMITATION: CEF's custom string slots (cs1..cs6) are finite, so lists are joined with
/// commas and long values are left intact rather than truncated. Some collectors cap an
/// extension value (commonly 1023 bytes) and will truncate for us; use the ECS or OCSF
/// formatter when full command lines matter.
/// </summary>
public sealed class CefFormatter : IEventFormatter
{
    private static readonly ShieldEvent Fallback = new() { TimeUtc = default };

    private readonly string _hostName;

    public CefFormatter() : this(Environment.MachineName) { }

    /// <summary>Host name injection keeps the formatter pure and testable.</summary>
    public CefFormatter(string hostName) => _hostName = SchemaUtil.S(hostName);

    public string Name => "cef";

    public string Format(ShieldEvent e)
    {
        var ev = e ?? Fallback;
        string level = SchemaUtil.Level(ev);
        var reasons = SchemaUtil.List(ev.Reasons);
        var techniques = SchemaUtil.Techniques(ev.Techniques);
        var ruleIds = SchemaUtil.List(ev.RuleIds);
        var domains = SchemaUtil.List(ev.Domains);
        var endpoints = SchemaUtil.List(ev.RemoteEndpoints);
        var ancestry = SchemaUtil.List(ev.Ancestry);

        var sb = new StringBuilder(256);
        sb.Append("CEF:0|")
          .Append(SchemaUtil.CefHeader(EventFormatters.VendorName)).Append('|')
          .Append(SchemaUtil.CefHeader(EventFormatters.ProductName)).Append('|')
          .Append(SchemaUtil.CefHeader(EventFormatters.AgentVersion)).Append('|')
          .Append(SchemaUtil.CefHeader(SignatureId(ev, ruleIds))).Append('|')
          .Append(SchemaUtil.CefHeader(HeaderName(ev))).Append('|')
          .Append(Severity(level).ToString(CultureInfo.InvariantCulture)).Append('|');

        bool first = true;
        void Ext(string key, string? value)
        {
            string v = SchemaUtil.S(value);
            if (v.Length == 0) return;
            if (!first) sb.Append(' ');
            first = false;
            sb.Append(key).Append('=').Append(SchemaUtil.CefValue(v));
        }

        void ExtNum(string key, long value)
        {
            if (!first) sb.Append(' ');
            first = false;
            sb.Append(key).Append('=').Append(value.ToString(CultureInfo.InvariantCulture));
        }

        // Fixed emission order: a CEF consumer does not care, but a diff-based test and a
        // human reading the log both do.
        ExtNum("rt", SchemaUtil.UnixMs(ev.TimeUtc));
        Ext("dvchost", _hostName);
        Ext("suser", ev.User);
        if (ev.Pid != 0) ExtNum("spid", ev.Pid);
        Ext("sproc", ev.Process);
        Ext("filePath", ev.Image);
        Ext("fname", SchemaUtil.BaseName(ev.Image));
        Ext("fileHash", ev.Sha256);

        if (endpoints.Count == 1)
        {
            bool split = SchemaUtil.TrySplitEndpoint(endpoints[0], out string address, out int port);
            Ext("dst", address);
            if (split) ExtNum("dpt", port);
        }

        Ext("act", ev.Trigger);
        Ext("cat", ev.Category);
        Ext("msg", SchemaUtil.MessageOf(ev));

        ExtNum("cn1", ev.Score);
        Ext("cn1Label", "Score");
        if (ev.ParentPid != 0)
        {
            ExtNum("cn2", ev.ParentPid);
            Ext("cn2Label", "ParentPid");
        }

        if (techniques.Count > 0)
        {
            Ext("cs1", string.Join(",", techniques));
            Ext("cs1Label", "MitreTechniques");
        }
        if (ruleIds.Count > 0)
        {
            Ext("cs2", string.Join(",", ruleIds));
            Ext("cs2Label", "RuleIds");
        }
        if (reasons.Count > 0)
        {
            Ext("cs3", string.Join("; ", reasons));
            Ext("cs3Label", "Reasons");
        }
        if (SchemaUtil.S(ev.IncidentId).Length > 0)
        {
            Ext("cs4", ev.IncidentId);
            Ext("cs4Label", "IncidentId");
        }
        if (domains.Count > 0)
        {
            Ext("cs5", string.Join(",", domains));
            Ext("cs5Label", "Domains");
        }
        if (ancestry.Count > 0)
        {
            Ext("cs6", string.Join(" < ", ancestry));
            Ext("cs6Label", "Ancestry");
        }
        if (endpoints.Count > 1)
        {
            // More than one destination cannot be expressed by dst/dpt, so it goes into a
            // labelled custom slot instead of arbitrarily picking one endpoint.
            Ext("flexString1", string.Join(",", endpoints));
            Ext("flexString1Label", "RemoteEndpoints");
        }

        return sb.ToString();
    }

    private static string SignatureId(ShieldEvent e, IReadOnlyList<string> ruleIds)
    {
        if (ruleIds.Count > 0) return ruleIds[0];
        string slug = SchemaUtil.Slug(e.Trigger);
        if (slug.Length > 0) return slug;
        string category = SchemaUtil.Category(e);
        return category.Length > 0 ? category : "processshield";
    }

    /// <summary>The CEF header's Name field: the shortest description of what happened.</summary>
    private static string HeaderName(ShieldEvent e)
    {
        string trigger = SchemaUtil.S(e.Trigger);
        if (trigger.Length > 0) return trigger;
        string message = SchemaUtil.S(e.Message);
        if (message.Length > 0) return message;
        return SchemaUtil.Summary(e);
    }

    /// <summary>CEF severity is an integer 0-10. Mapped so a WARN clears the common
    /// "severity &gt;= 6" alerting threshold and a quarantine sits just below the reserved
    /// top of the range.</summary>
    private static int Severity(string level) => level switch
    {
        "QUARANTINE" => 9,
        "WARN" => 6,
        "ACTION" => 3,
        "INFO" => 1,
        _ => 0
    };
}

/// <summary>
/// Registry of the wire schemas ProcessShield can emit. Configuration refers to a
/// formatter by name, so this is the one place that maps a config string to an
/// implementation.
/// </summary>
public static class EventFormatters
{
    /// <summary>
    /// Version reported to every downstream schema (ECS <c>agent.version</c> semantics,
    /// OCSF <c>metadata.product.version</c>, the CEF header). Kept as a constant rather
    /// than read from the assembly so a formatter stays pure and its output stays
    /// byte-stable in tests and in golden-file comparisons.
    /// </summary>
    public const string AgentVersion = "2.0.0";

    /// <summary>Product name as it should appear in a SIEM's source list.</summary>
    public const string ProductName = "ProcessShield";

    /// <summary>Vendor name. The project has no vendor, so it names itself.</summary>
    public const string VendorName = "ProcessShield";

    private static readonly NativeFormatter NativeInstance = new();
    private static readonly EcsFormatter EcsInstance = new();
    private static readonly OcsfFormatter OcsfInstance = new();
    private static readonly CefFormatter CefInstance = new();

    private static readonly string[] NameList = { "native", "ecs", "ocsf", "cef" };

    /// <summary>Canonical formatter names, in preference order.</summary>
    public static IReadOnlyList<string> Names => NameList;

    /// <summary>
    /// Resolves a configured name to a formatter, accepting the obvious aliases. An
    /// unknown name falls back to <see cref="NativeFormatter"/> rather than throwing:
    /// a typo in a config file must not stop a security agent from logging. Use
    /// <see cref="TryResolve"/> at config-validation time to surface the typo loudly.
    /// </summary>
    public static IEventFormatter Resolve(string name)
        => TryResolve(name, out var f) ? f : NativeInstance;

    /// <summary>Resolves a name, reporting whether it was recognised.</summary>
    public static bool TryResolve(string? name, out IEventFormatter formatter)
    {
        switch (SchemaUtil.S(name).Trim().ToLowerInvariant())
        {
            case "":
            case "native":
            case "json":
            case "jsonl":
            case "processshield":
                formatter = NativeInstance;
                return true;
            case "ecs":
            case "elastic":
            case "elastic-common-schema":
                formatter = EcsInstance;
                return true;
            case "ocsf":
            case "ocsf-detection-finding":
                formatter = OcsfInstance;
                return true;
            case "cef":
            case "arcsight":
                formatter = CefInstance;
                return true;
            default:
                formatter = NativeInstance;
                return false;
        }
    }
}

/// <summary>
/// Appends each event to a file as one formatted line, in whichever schema the
/// formatter implements. This is what lets an operator point Filebeat, the Splunk
/// universal forwarder or an OCSF loader straight at a ProcessShield file without any
/// parsing configuration.
///
/// Failures are counted, never thrown: a full disk or a revoked ACL must not take down
/// detection, which is the same trade-off <see cref="JsonlSink"/> makes. Check
/// <see cref="Errors"/> if you need to alert on a silently broken sink.
/// </summary>
public sealed class FormattingSink : IEventSink
{
    private readonly object _gate = new();
    private readonly string _path;
    private readonly IEventFormatter _formatter;
    private long _errors;

    /// <summary>Creates a sink writing <paramref name="path"/> in the given schema.</summary>
    public FormattingSink(string path, IEventFormatter formatter)
    {
        _path = path ?? throw new ArgumentNullException(nameof(path));
        _formatter = formatter ?? throw new ArgumentNullException(nameof(formatter));
        try
        {
            string? dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        }
        catch { /* the first Emit will count the failure */ }
    }

    /// <summary>Convenience overload for configuration-driven construction.</summary>
    public FormattingSink(string path, string formatName)
        : this(path, EventFormatters.Resolve(formatName)) { }

    /// <summary>Name of the schema being written.</summary>
    public string FormatName => _formatter.Name;

    /// <summary>Path being appended to.</summary>
    public string FilePath => _path;

    /// <summary>Count of events that could not be formatted or written.</summary>
    public long Errors => Interlocked.Read(ref _errors);

    public void Emit(ShieldEvent e)
    {
        string line;
        try { line = _formatter.Format(e); }
        catch { Interlocked.Increment(ref _errors); return; }

        // One record per line is the whole contract of this file. Formatters in this
        // assembly already guarantee it; folding any stray break here keeps that true for
        // a third-party formatter as well, at the cost of mangling a deliberately
        // multi-line format (there is no such format, and a broken line would be worse).
        if (line.IndexOf('\n') >= 0 || line.IndexOf('\r') >= 0)
            line = line.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ');

        lock (_gate)
        {
            try { File.AppendAllText(_path, line + Environment.NewLine); }
            catch { Interlocked.Increment(ref _errors); }
        }
    }

    public void Dispose() { }
}
