using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using ProcessShield.Core;

namespace ProcessShield.Replay;

/// <summary>
/// One step of a recorded or hand-written trace. <see cref="At"/> is an offset from
/// <see cref="TraceScenario.StartUtc"/> rather than a wall-clock time, so the same file
/// replays identically on any machine on any day -- which is the whole point of the
/// format: a detection regression must fail because the rule changed, never because the
/// test ran in a different timezone or a second later than last time.
/// </summary>
/// <remarks>
/// Named "step" and not "event" on purpose: <c>TraceEvent</c> is the name of a type in
/// Microsoft.Diagnostics.Tracing, which this project already references for ETW. A
/// same-named type in a sibling namespace would be a permanent source of ambiguous
/// reference errors in any file that pulls in both.
/// </remarks>
public sealed record TraceStep(TimeSpan At, Signal Signal);

/// <summary>
/// A parsed trace: metadata, the expectations the scenario asserts, and the ordered
/// steps to feed the engine.
/// </summary>
/// <remarks>
/// Invariant guaranteed by <see cref="TraceFormat.Parse"/> and
/// <see cref="TraceFormat.FromSignals"/>: <see cref="Events"/> is non-decreasing in
/// <see cref="TraceStep.At"/>. Replay advances a <see cref="ManualClock"/> as it walks
/// the list, and a clock that jumps backwards would silently corrupt every
/// correlation-window rule in the engine, so the invariant is enforced at parse time
/// rather than trusted.
/// </remarks>
public sealed record TraceScenario
{
    private readonly DateTime _startUtc = TraceFormat.DefaultStartUtc;

    /// <summary>Scenario id. Taken from the meta line, else the file name.</summary>
    public string Name { get; init; } = "";

    /// <summary>One-paragraph narrative: what an analyst is supposed to be looking at.</summary>
    public string Description { get; init; } = "";

    /// <summary>Expectation strings in the mini-language documented on <see cref="Expectation"/>.</summary>
    public IReadOnlyList<string> Expect { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Wall-clock anchor for offset 0. Normalised to UTC on assignment: a scenario built
    /// in code with <c>new DateTime(2026, 1, 1)</c> is <see cref="DateTimeKind.Unspecified"/>,
    /// and letting that reach <see cref="ManualClock"/> would make replay results depend on
    /// the host's timezone.
    /// </summary>
    public DateTime StartUtc
    {
        get => _startUtc;
        init => _startUtc = value.Kind switch
        {
            DateTimeKind.Utc => value,
            DateTimeKind.Local => value.ToUniversalTime(),
            _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
        };
    }

    /// <summary>Steps in feed order, non-decreasing in <see cref="TraceStep.At"/>.</summary>
    public IReadOnlyList<TraceStep> Events { get; init; } = Array.Empty<TraceStep>();

    /// <summary>Offset of the final step, i.e. how much simulated time the trace covers.</summary>
    public TimeSpan Duration => Events.Count == 0 ? TimeSpan.Zero : Events[^1].At;
}

/// <summary>
/// Reader/writer for the JSON Lines trace format.
///
/// One JSON object per line. Three line shapes:
/// <list type="bullet">
///   <item><description>an object with a <c>"#"</c> property is a comment and is ignored;</description></item>
///   <item><description>an object with a <c>"meta"</c> property carries name, description,
///   start and expect[];</description></item>
///   <item><description>anything else is one <see cref="Signal"/>, with <c>"at"</c> giving the
///   offset in milliseconds from the scenario start.</description></item>
/// </list>
///
/// Robustness rules, and why they are what they are:
/// <list type="bullet">
///   <item><description><see cref="Parse"/> never throws. A trace is authored by hand in a pull
///   request; a single fat-fingered line must degrade to one skipped event plus a warning,
///   not an exception that hides the other 200 good lines from the contributor.</description></item>
///   <item><description>An unknown field is a warning, never an error, so a trace recorded by a
///   newer build still replays on an older one (forward compatibility for the on-disk format).</description></item>
///   <item><description>A line with an unusable <c>kind</c> is skipped rather than guessed at.
///   Guessing would quietly change what a detection test asserts.</description></item>
///   <item><description>The monotonic-clock invariant is enforced on <c>at</c> ONLY. An explicit
///   <c>timestampUtc</c> is stored verbatim, including one that predates the scenario start or
///   the previous step, because that is the only way to round-trip a real capture faithfully
///   (<see cref="FromSignals"/> clamps the offset of an out-of-order arrival but keeps the
///   timestamp the monitor actually reported) and the only way to author a deliberate
///   clock-skew scenario. Such a timestamp is reported through the warnings channel so it is
///   never a silent surprise, and it does not move the replay clock -- <c>TraceReplay</c>
///   advances on <c>at</c>, so a backwards timestamp travels on the signal as data rather
///   than rewinding the engine's correlation windows.</description></item>
/// </list>
/// </summary>
public static class TraceFormat
{
    /// <summary>
    /// Anchor used when a scenario carries no <c>meta.start</c>. Deliberately the same
    /// epoch as <see cref="ManualClock"/>'s parameterless constructor so a scenario and a
    /// hand-built clock in the same test agree without either side saying so.
    /// </summary>
    public static readonly DateTime DefaultStartUtc = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// Largest offset accepted for one step. A trace longer than a month is essentially
    /// always a units mistake (seconds, or a unix timestamp, written into <c>at</c>), and
    /// accepting it would either hang a replay loop or overflow <c>StartUtc + At</c>.
    /// Over-long offsets are clamped with a warning rather than rejected, so the rest of
    /// the trace still runs and the author sees exactly which line is wrong.
    /// </summary>
    public static readonly TimeSpan MaxOffset = TimeSpan.FromDays(30);

    private static readonly long MaxOffsetMs = (long)MaxOffset.TotalMilliseconds;

    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = false,
        // Traces are read and diffed by humans in pull requests. Relaxed escaping keeps
        // '<', '>', '&' and '+' literal instead of \uXXXX, which makes command lines and
        // script bodies reviewable. Backslashes and quotes are still escaped -- that is
        // mandatory JSON, not a choice.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Parse JSON Lines into a scenario. Never throws: every problem is reported through
    /// <paramref name="warnings"/>, each prefixed with its 1-based line number.
    /// </summary>
    /// <param name="lines">The raw lines. A null enumerable is treated as empty.</param>
    /// <param name="name">Fallback scenario name used when the meta line omits one.</param>
    /// <param name="warnings">Everything that was skipped, defaulted, clamped or ignored.</param>
    public static TraceScenario Parse(IEnumerable<string> lines, string name, out IReadOnlyList<string> warnings)
    {
        var warn = new List<string>();
        // The line number rides along because an explicit timestampUtc can only be checked
        // against the scenario start once the whole file has been read, long after the
        // line itself is gone.
        var pending = new List<(long AtMs, Signal Sig, bool ExplicitTime, int LineNo)>();

        string metaName = "";
        string metaDescription = "";
        var metaExpect = new List<string>();
        DateTime start = DefaultStartUtc;
        bool metaSeen = false;

        long prevMs = 0;
        int lineNo = 0;

        foreach (var rawLine in lines ?? Array.Empty<string>())
        {
            lineNo++;
            string line = (rawLine ?? "").Trim();
            if (line.Length == 0) continue;

            // A bare '#' or '//' prefix is accepted as a comment in addition to the
            // {"#": "..."} record shape. Hand-edited traces pick up both conventions and
            // failing on the informal one only produces noise in review.
            if (line[0] == '#' || line.StartsWith("//", StringComparison.Ordinal)) continue;

            // The whole per-line body is guarded, not just JsonDocument.Parse. Reading a
            // value out of a parsed document can still throw (invalid surrogate escapes
            // are the usual culprit), and "Parse never throws" has to hold against a
            // hostile file, not only against a clumsy one.
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    warn.Add($"line {lineNo}: expected a JSON object, found {root.ValueKind}; line skipped");
                    continue;
                }

                if (root.TryGetProperty("#", out _)) continue;   // comment record

                if (root.TryGetProperty("meta", out var meta))
                {
                    if (metaSeen)
                    {
                        warn.Add($"line {lineNo}: duplicate meta line ignored; the first one wins");
                        continue;
                    }
                    metaSeen = true;
                    ReadMeta(meta, lineNo, warn, ref metaName, ref metaDescription, ref start, metaExpect);
                    continue;
                }

                if (TryReadStep(root, lineNo, warn, prevMs, out long atMs, out var sig, out bool explicitTime) && sig is not null)
                {
                    prevMs = atMs;
                    pending.Add((atMs, sig, explicitTime, lineNo));
                }
            }
            catch (JsonException ex)
            {
                warn.Add($"line {lineNo}: not valid JSON ({Trim(ex.Message, 120)}); line skipped");
            }
            catch (Exception ex)
            {
                // Named in the warning rather than swallowed silently: an unexpected type
                // here is a parser bug worth seeing, but it must not cost the other lines.
                warn.Add($"line {lineNo}: unexpected {ex.GetType().Name} while reading this line " +
                         $"({Trim(ex.Message, 120)}); line skipped");
            }
        }

        // Timestamps are resolved after the whole file has been read so that a meta line
        // placed at the bottom still anchors the events above it. Authors do put it last.
        var events = new List<TraceStep>(pending.Count);
        DateTime prevStamp = start;
        foreach (var (atMs, sig, explicitTime, stepLine) in pending)
        {
            var at = TimeSpan.FromMilliseconds(atMs);
            var resolved = explicitTime ? sig : sig with { TimestampUtc = AddSafe(start, at) };

            // An explicit timestamp is kept exactly as written -- see the note on this
            // class about why it is not clamped -- but a backwards one is called out, so
            // that a mistyped year reads as a warning in CI rather than as a scenario
            // whose verdicts could not have occurred on a real host. Implied timestamps
            // need no check: they are start + a non-decreasing offset by construction.
            if (explicitTime)
            {
                if (resolved.TimestampUtc < start)
                    warn.Add($"line {stepLine}: 'timestampUtc' {Iso(resolved.TimestampUtc)} predates the scenario " +
                             $"start ({Iso(start)}); kept as written -- the replay clock follows 'at', not this field");
                else if (resolved.TimestampUtc < prevStamp)
                    warn.Add($"line {stepLine}: 'timestampUtc' {Iso(resolved.TimestampUtc)} is earlier than the " +
                             $"previous step's ({Iso(prevStamp)}); kept as written -- the replay clock follows 'at', " +
                             "so this trace exercises clock skew rather than rewinding the engine");
            }

            prevStamp = resolved.TimestampUtc;
            events.Add(new TraceStep(at, resolved));
        }

        warnings = warn;
        return new TraceScenario
        {
            Name = string.IsNullOrWhiteSpace(metaName) ? (name ?? "").Trim() : metaName,
            Description = metaDescription,
            Expect = metaExpect,
            StartUtc = start,
            Events = events
        };
    }

    /// <summary>
    /// Load a scenario from a <c>.jsonl</c> file, discarding warnings. Use the overload
    /// that surfaces them when the caller is a linter or a CI check.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="Parse"/> this CAN throw: a missing or unreadable file is a
    /// caller mistake, not malformed content, and silently returning an empty scenario
    /// would turn a broken path into a passing regression test.
    /// </remarks>
    public static TraceScenario Load(string path) => Load(path, out _);

    /// <summary>Load a scenario and surface the parser's warnings.</summary>
    public static TraceScenario Load(string path, out IReadOnlyList<string> warnings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Parse(File.ReadLines(path), Path.GetFileNameWithoutExtension(path), out warnings);
    }

    /// <summary>
    /// Render a scenario back to JSON Lines: one meta line, then one line per step.
    /// Default and empty fields are omitted so a hand-review diff shows only what a step
    /// actually asserts.
    /// </summary>
    public static IEnumerable<string> Write(TraceScenario scenario)
    {
        ArgumentNullException.ThrowIfNull(scenario);
        return WriteCore(scenario);
    }

    /// <summary>Write a scenario to disk in the on-disk format.</summary>
    public static void Save(string path, TraceScenario scenario)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(scenario);
        File.WriteAllLines(path, Write(scenario));
    }

    /// <summary>
    /// Turn a live capture into a replayable scenario, anchoring offset 0 at the first
    /// signal's timestamp.
    /// </summary>
    /// <remarks>
    /// Delivery order is preserved and NOT re-sorted by timestamp. Several monitors
    /// (ETW, WMI, the minifilter) feed one engine, and their timestamps can disagree by a
    /// few milliseconds; the engine reacted to the order it was given, so a faithful
    /// recording has to keep it. A timestamp that would move an offset backwards is
    /// clamped to the previous offset instead, which preserves order and keeps the
    /// non-decreasing invariant. That does lose sub-millisecond fidelity on out-of-order
    /// arrivals -- an accepted trade for a monotonic replay clock.
    /// </remarks>
    public static TraceScenario FromSignals(IEnumerable<Signal> signals, string name)
    {
        ArgumentNullException.ThrowIfNull(signals);
        var list = signals.Where(static s => s is not null).ToList();
        if (list.Count == 0)
        {
            return new TraceScenario
            {
                Name = (name ?? "").Trim(),
                Description = "Recorded trace (no signals captured).",
                StartUtc = DefaultStartUtc
            };
        }

        DateTime start = Utc(list[0].TimestampUtc);
        var events = new List<TraceStep>(list.Count);
        long prevMs = 0;

        foreach (var s in list)
        {
            double raw = (Utc(s.TimestampUtc) - start).TotalMilliseconds;
            long ms = raw >= MaxOffsetMs ? MaxOffsetMs
                    : raw <= 0 ? 0
                    : (long)Math.Round(raw);
            if (ms < prevMs) ms = prevMs;
            prevMs = ms;
            events.Add(new TraceStep(TimeSpan.FromMilliseconds(ms), s));
        }

        return new TraceScenario
        {
            Name = (name ?? "").Trim(),
            Description = $"Recorded from {list.Count} live signal(s) starting {start.ToString("O", CultureInfo.InvariantCulture)}.",
            StartUtc = start,
            Events = events
        };
    }

    // ------------------------------------------------------------------ writing

    private static IEnumerable<string> WriteCore(TraceScenario scenario)
    {
        yield return WriteObject(w =>
        {
            w.WriteStartObject("meta");
            w.WriteString("name", scenario.Name);
            w.WriteString("description", scenario.Description);
            w.WriteString("start", Iso(scenario.StartUtc));
            w.WriteStartArray("expect");
            foreach (var e in scenario.Expect) w.WriteStringValue(e);
            w.WriteEndArray();
            w.WriteEndObject();
        });

        foreach (var step in scenario.Events)
        {
            if (step is null) continue;
            var s = step.Signal;
            var implied = AddSafe(scenario.StartUtc, step.At);
            yield return WriteObject(w =>
            {
                w.WriteNumber("at", (long)Math.Round(step.At.TotalMilliseconds));
                w.WriteString("kind", s.Kind.ToString());
                w.WriteNumber("pid", s.Pid);
                if (s.ParentPid != 0) w.WriteNumber("parentPid", s.ParentPid);
                if (s.ProcessName.Length != 0) w.WriteString("processName", s.ProcessName);
                if (s.ImagePath.Length != 0) w.WriteString("imagePath", s.ImagePath);
                if (s.CommandLine.Length != 0) w.WriteString("commandLine", s.CommandLine);
                if (s.FilePath is not null) w.WriteString("filePath", s.FilePath);
                if (s.RemoteAddress is not null) w.WriteString("remoteAddress", s.RemoteAddress);
                if (s.RemotePort != 0) w.WriteNumber("remotePort", s.RemotePort);
                if (s.TargetPid != 0) w.WriteNumber("targetPid", s.TargetPid);
                if (s.DesiredAccess != 0) w.WriteNumber("desiredAccess", s.DesiredAccess);
                if (s.RegistryKey is not null) w.WriteString("registryKey", s.RegistryKey);
                if (s.RegistryValue is not null) w.WriteString("registryValue", s.RegistryValue);
                if (s.Domain is not null) w.WriteString("domain", s.Domain);
                if (s.ScriptText is not null) w.WriteString("scriptText", s.ScriptText);
                if (s.PipeName is not null) w.WriteString("pipeName", s.PipeName);
                if (s.User is not null) w.WriteString("user", s.User);
                if (s.Detail is not null) w.WriteString("detail", s.Detail);
                // Only emitted when it disagrees with StartUtc + At, which is the value a
                // reader would otherwise infer. Keeps the common case one field shorter.
                if (s.TimestampUtc != implied) w.WriteString("timestampUtc", Iso(s.TimestampUtc));
            });
        }
    }

    private static string WriteObject(Action<Utf8JsonWriter> body)
    {
        using var buffer = new MemoryStream(256);
        using (var w = new Utf8JsonWriter(buffer, WriterOptions))
        {
            w.WriteStartObject();
            body(w);
            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    // ------------------------------------------------------------------ reading

    private static void ReadMeta(
        JsonElement meta, int lineNo, List<string> warn,
        ref string name, ref string description, ref DateTime start, List<string> expect)
    {
        if (meta.ValueKind != JsonValueKind.Object)
        {
            warn.Add($"line {lineNo}: 'meta' must be an object, found {meta.ValueKind}; ignored");
            return;
        }

        foreach (var p in meta.EnumerateObject())
        {
            switch (p.Name.ToLowerInvariant())
            {
                case "name":
                    if (TryString(p.Value, "meta.name", lineNo, warn, out var n)) name = n.Trim();
                    break;
                case "description":
                    if (TryString(p.Value, "meta.description", lineNo, warn, out var d)) description = d;
                    break;
                case "start":
                    if (TryTime(p.Value, "meta.start", lineNo, warn, out var s)) start = s;
                    break;
                case "expect":
                    if (p.Value.ValueKind != JsonValueKind.Array)
                    {
                        warn.Add($"line {lineNo}: 'meta.expect' must be an array of strings; ignored");
                        break;
                    }
                    int i = 0;
                    foreach (var item in p.Value.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            string t = (item.GetString() ?? "").Trim();
                            if (t.Length != 0) expect.Add(t);
                            else warn.Add($"line {lineNo}: 'meta.expect[{i}]' is empty; ignored");
                        }
                        else
                        {
                            warn.Add($"line {lineNo}: 'meta.expect[{i}]' must be a string, found {item.ValueKind}; ignored");
                        }
                        i++;
                    }
                    break;
                default:
                    warn.Add($"line {lineNo}: unknown meta field '{p.Name}' ignored");
                    break;
            }
        }
    }

    private static bool TryReadStep(
        JsonElement root, int lineNo, List<string> warn, long prevMs,
        out long atMs, out Signal? signal, out bool explicitTime)
    {
        atMs = prevMs;
        signal = null;
        explicitTime = false;

        SignalKind? kind = null;
        bool badKind = false;
        int pid = 0, parentPid = 0, remotePort = 0, targetPid = 0;
        bool pidSeen = false;
        uint desiredAccess = 0;
        string processName = "", imagePath = "", commandLine = "";
        string? filePath = null, remoteAddress = null, detail = null;
        string? registryKey = null, registryValue = null, domain = null, scriptText = null, pipeName = null, user = null;
        DateTime timestamp = default;

        foreach (var prop in root.EnumerateObject())
        {
            // Field names are matched case-insensitively: Write always emits camelCase,
            // but a trace pasted out of a PascalCase log dump should still replay.
            switch (prop.Name.ToLowerInvariant())
            {
                case "at":
                    if (TryOffset(prop.Value, lineNo, warn, out long v)) atMs = v;
                    break;
                case "kind":
                    if (TryKind(prop.Value, lineNo, warn, out var k)) kind = k; else badKind = true;
                    break;
                case "pid":
                    if (TryInt(prop.Value, "pid", lineNo, warn, out pid)) pidSeen = true;
                    break;
                case "parentpid": TryInt(prop.Value, "parentPid", lineNo, warn, out parentPid); break;
                case "targetpid": TryInt(prop.Value, "targetPid", lineNo, warn, out targetPid); break;
                case "remoteport": TryInt(prop.Value, "remotePort", lineNo, warn, out remotePort); break;
                case "desiredaccess": TryUInt(prop.Value, "desiredAccess", lineNo, warn, out desiredAccess); break;
                case "processname": TryString(prop.Value, "processName", lineNo, warn, out processName); break;
                case "imagepath": TryString(prop.Value, "imagePath", lineNo, warn, out imagePath); break;
                case "commandline": TryString(prop.Value, "commandLine", lineNo, warn, out commandLine); break;
                case "filepath": if (TryString(prop.Value, "filePath", lineNo, warn, out var fp)) filePath = fp; break;
                case "remoteaddress": if (TryString(prop.Value, "remoteAddress", lineNo, warn, out var ra)) remoteAddress = ra; break;
                case "detail": if (TryString(prop.Value, "detail", lineNo, warn, out var de)) detail = de; break;
                case "registrykey": if (TryString(prop.Value, "registryKey", lineNo, warn, out var rk)) registryKey = rk; break;
                case "registryvalue": if (TryString(prop.Value, "registryValue", lineNo, warn, out var rv)) registryValue = rv; break;
                case "domain": if (TryString(prop.Value, "domain", lineNo, warn, out var dm)) domain = dm; break;
                case "scripttext": if (TryString(prop.Value, "scriptText", lineNo, warn, out var st)) scriptText = st; break;
                case "pipename": if (TryString(prop.Value, "pipeName", lineNo, warn, out var pn)) pipeName = pn; break;
                case "user": if (TryString(prop.Value, "user", lineNo, warn, out var us)) user = us; break;
                case "timestamputc":
                    if (TryTime(prop.Value, "timestampUtc", lineNo, warn, out timestamp)) explicitTime = true;
                    break;
                default:
                    warn.Add($"line {lineNo}: unknown field '{prop.Name}' ignored");
                    break;
            }
        }

        if (badKind) return false;                                  // TryKind already explained why
        if (kind is null)
        {
            warn.Add($"line {lineNo}: no 'kind' field; line skipped");
            return false;
        }

        if (atMs < 0)
        {
            warn.Add($"line {lineNo}: 'at' is negative ({atMs}ms); clamped to {prevMs}ms so the replay clock never rewinds");
            atMs = prevMs;
        }
        else if (atMs < prevMs)
        {
            warn.Add($"line {lineNo}: 'at' {atMs}ms is earlier than the previous step ({prevMs}ms); clamped so the replay clock never rewinds");
            atMs = prevMs;
        }
        if (atMs > MaxOffsetMs)
        {
            warn.Add($"line {lineNo}: 'at' {atMs}ms exceeds the {MaxOffset.TotalDays:0}-day cap; clamped (is the value in seconds by mistake?)");
            atMs = MaxOffsetMs;
        }

        if (!pidSeen)
            warn.Add($"line {lineNo}: no 'pid'; treated as unattributed (pid 0)");

        signal = new Signal
        {
            Kind = kind.Value,
            Pid = pid,
            ParentPid = parentPid,
            ProcessName = processName,
            ImagePath = imagePath,
            CommandLine = commandLine,
            FilePath = filePath,
            RemoteAddress = remoteAddress,
            RemotePort = remotePort,
            Detail = detail,
            TimestampUtc = timestamp,
            TargetPid = targetPid,
            DesiredAccess = desiredAccess,
            RegistryKey = registryKey,
            RegistryValue = registryValue,
            Domain = domain,
            ScriptText = scriptText,
            PipeName = pipeName,
            User = user
        };
        return true;
    }

    private static bool TryOffset(JsonElement el, int lineNo, List<string> warn, out long ms)
    {
        ms = 0;
        if (el.ValueKind == JsonValueKind.Number)
        {
            if (el.TryGetInt64(out ms)) return true;
            if (el.TryGetDouble(out double d) && !double.IsNaN(d) && !double.IsInfinity(d) && Math.Abs(d) < 9.0e18)
            {
                ms = (long)Math.Round(d);
                return true;
            }
        }
        warn.Add($"line {lineNo}: 'at' must be a number of milliseconds, found {Describe(el)}; the previous offset is reused");
        return false;
    }

    private static bool TryKind(JsonElement el, int lineNo, List<string> warn, out SignalKind kind)
    {
        kind = default;
        if (el.ValueKind == JsonValueKind.String)
        {
            string s = (el.GetString() ?? "").Trim();
            // Numeric strings are rejected deliberately. "5" would bind to whichever enum
            // member happens to sit at ordinal 5 in today's build, so a trace written
            // against one version would silently mean a different signal in the next.
            bool numeric = s.Length != 0 && s.All(char.IsDigit);
            if (!numeric && Enum.TryParse(s, ignoreCase: true, out SignalKind parsed) && Enum.IsDefined(parsed))
            {
                kind = parsed;
                return true;
            }
        }
        warn.Add($"line {lineNo}: 'kind' must be one of {string.Join("|", Enum.GetNames<SignalKind>())}, found {Describe(el)}; line skipped");
        return false;
    }

    private static bool TryString(JsonElement el, string field, int lineNo, List<string> warn, out string value)
    {
        value = "";
        if (el.ValueKind == JsonValueKind.Null) return false;      // explicit null == absent
        if (el.ValueKind == JsonValueKind.String)
        {
            value = el.GetString() ?? "";
            return true;
        }
        warn.Add($"line {lineNo}: '{field}' must be a string, found {Describe(el)}; ignored");
        return false;
    }

    private static bool TryInt(JsonElement el, string field, int lineNo, List<string> warn, out int value)
    {
        value = 0;
        if (el.ValueKind == JsonValueKind.Null) return false;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out value)) return true;
        value = 0;
        warn.Add($"line {lineNo}: '{field}' must be a 32-bit integer, found {Describe(el)}; ignored");
        return false;
    }

    private static bool TryUInt(JsonElement el, string field, int lineNo, List<string> warn, out uint value)
    {
        value = 0;
        if (el.ValueKind == JsonValueKind.Null) return false;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetUInt32(out value)) return true;
        if (el.ValueKind == JsonValueKind.String)
        {
            // Access masks are quoted hex in most Windows documentation and in Sysmon
            // output ("0x1410"), so accept that spelling as well as a plain number.
            string s = (el.GetString() ?? "").Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                uint.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value)) return true;
            if (uint.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out value)) return true;
        }
        value = 0;
        warn.Add($"line {lineNo}: '{field}' must be an access mask (number, or 0x-prefixed hex string), found {Describe(el)}; ignored");
        return false;
    }

    private static bool TryTime(JsonElement el, string field, int lineNo, List<string> warn, out DateTime value)
    {
        value = default;
        if (el.ValueKind == JsonValueKind.Null) return false;
        if (el.ValueKind == JsonValueKind.String &&
            DateTime.TryParse(el.GetString(), CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var dt))
        {
            value = DateTime.SpecifyKind(dt, DateTimeKind.Utc);
            return true;
        }
        warn.Add($"line {lineNo}: '{field}' must be an ISO-8601 timestamp (assumed UTC), found {Describe(el)}; ignored");
        return false;
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Adds an offset without ever overflowing, which a hostile 'at' could force.</summary>
    private static DateTime AddSafe(DateTime start, TimeSpan at)
        => at.Ticks > (DateTime.MaxValue - start).Ticks ? DateTime.MaxValue : start + at;

    private static DateTime Utc(DateTime t) => t.Kind switch
    {
        DateTimeKind.Utc => t,
        DateTimeKind.Local => t.ToUniversalTime(),
        _ => DateTime.SpecifyKind(t, DateTimeKind.Utc)
    };

    private static string Iso(DateTime t) => Utc(t).ToString("O", CultureInfo.InvariantCulture);

    /// <summary>Short, safe rendering of an offending value for a warning message.</summary>
    private static string Describe(JsonElement el)
        => el.ValueKind switch
        {
            JsonValueKind.String => "'" + Trim(el.GetString() ?? "", 40) + "'",
            JsonValueKind.Object => "an object",
            JsonValueKind.Array => "an array",
            JsonValueKind.Null => "null",
            _ => Trim(el.ToString(), 40)
        };

    private static string Trim(string s, int max)
    {
        s = s.Replace('\r', ' ').Replace('\n', ' ');
        return s.Length <= max ? s : s[..max] + "...";
    }
}
