using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ProcessShield.Telemetry;

/// <summary>Structured event forwarded to every configured sink.</summary>
public sealed record ShieldEvent
{
    public string Level { get; init; } = "INFO";          // INFO | ACTION | WARN | ERROR | QUARANTINE
    public string Category { get; init; } = "system";     // detection | response | system | api
    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;
    public int Pid { get; init; }
    public string Process { get; init; } = "";
    public string Image { get; init; } = "";
    public int Score { get; init; }
    public string Trigger { get; init; } = "";
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> StagedArchives { get; init; } = Array.Empty<string>();
    public string Message { get; init; } = "";

    // --- v2 fields. All defaulted, so every existing emit site is unchanged and
    //     older audit chains keep verifying against the same canonical shape. ---

    /// <summary>Stable id grouping every event raised for one incident.</summary>
    public string IncidentId { get; init; } = "";
    /// <summary>MITRE ATT&amp;CK technique ids implicated by this event.</summary>
    public IReadOnlyList<string> Techniques { get; init; } = Array.Empty<string>();
    /// <summary>Ids of the detection rules that fired.</summary>
    public IReadOnlyList<string> RuleIds { get; init; } = Array.Empty<string>();
    public int ParentPid { get; init; }
    public string CommandLine { get; init; } = "";
    public string User { get; init; } = "";
    /// <summary>Ancestry, nearest parent first.</summary>
    public IReadOnlyList<string> Ancestry { get; init; } = Array.Empty<string>();
    /// <summary>Distinct <c>ip:port</c> destinations seen for the subject process.</summary>
    public IReadOnlyList<string> RemoteEndpoints { get; init; } = Array.Empty<string>();
    /// <summary>Distinct DNS names resolved by the subject process.</summary>
    public IReadOnlyList<string> Domains { get; init; } = Array.Empty<string>();
    /// <summary>SHA-256 of the subject image, when it has been computed.</summary>
    public string Sha256 { get; init; } = "";
}

public interface IEventSink : IDisposable
{
    void Emit(ShieldEvent e);
}

/// <summary>Fans an event out to many sinks, isolating per-sink failures.</summary>
public sealed class CompositeSink : IEventSink
{
    private readonly IEventSink[] _sinks;
    public CompositeSink(IEnumerable<IEventSink> sinks) => _sinks = sinks.ToArray();

    public void Emit(ShieldEvent e)
    {
        foreach (var s in _sinks)
        {
            try { s.Emit(e); } catch { /* isolate */ }
        }
    }

    public void Dispose()
    {
        foreach (var s in _sinks)
        {
            try { s.Dispose(); } catch { }
        }
    }
}

internal static class Json
{
    public static readonly JsonSerializerOptions Compact = new() { WriteIndented = false };
    public static string Event(ShieldEvent e) => JsonSerializer.Serialize(e, Compact);
}

/// <summary>
/// Keeps the most recent events in memory so the control API and the GUI can show a feed
/// without re-reading (and re-parsing) the JSONL file. Bounded and lock-guarded: this is
/// written from every emitting thread and read from HTTP handler threads.
/// </summary>
public sealed class RingBufferSink : IEventSink
{
    private readonly object _gate = new();
    private readonly ShieldEvent[] _buffer;
    private int _next;
    private int _count;

    public RingBufferSink(int capacity = 512)
        => _buffer = new ShieldEvent[Math.Max(16, capacity)];

    public int Count { get { lock (_gate) return _count; } }

    public void Emit(ShieldEvent e)
    {
        lock (_gate)
        {
            _buffer[_next] = e;
            _next = (_next + 1) % _buffer.Length;
            if (_count < _buffer.Length) _count++;
        }
    }

    /// <summary>The most recent events, newest first, capped at <paramref name="limit"/>.</summary>
    public IReadOnlyList<ShieldEvent> Recent(int limit)
    {
        lock (_gate)
        {
            int take = Math.Clamp(limit, 0, _count);
            var list = new List<ShieldEvent>(take);
            for (int i = 0; i < take; i++)
            {
                int idx = (_next - 1 - i + _buffer.Length * 2) % _buffer.Length;
                var e = _buffer[idx];
                if (e is not null) list.Add(e);
            }
            return list;
        }
    }

    public string RecentJson(int limit)
        => JsonSerializer.Serialize(Recent(limit), Json.Compact);

    public void Dispose() { }
}

/// <summary>Appends each event as one JSON line.</summary>
public sealed class JsonlSink : IEventSink
{
    private readonly object _gate = new();
    private readonly string _path;
    public JsonlSink(string path) => _path = path;

    public void Emit(ShieldEvent e)
    {
        var line = Json.Event(e);
        lock (_gate)
        {
            try { File.AppendAllText(_path, line + Environment.NewLine); } catch { }
        }
    }

    public void Dispose() { }
}

/// <summary>Base for network sinks: never blocks Emit; a worker drains a bounded queue.</summary>
public abstract class AsyncSinkBase : IEventSink
{
    private readonly BlockingCollection<ShieldEvent> _queue = new(boundedCapacity: 4096);
    private readonly Thread _worker;
    private long _errors;

    public long Errors => Interlocked.Read(ref _errors);

    protected AsyncSinkBase(string name)
    {
        _worker = new Thread(Loop) { IsBackground = true, Name = name };
        _worker.Start();
    }

    public void Emit(ShieldEvent e)
    {
        try { if (!_queue.TryAdd(e)) Interlocked.Increment(ref _errors); }
        catch (InvalidOperationException) { /* shutting down */ }
    }

    private void Loop()
    {
        try
        {
            foreach (var e in _queue.GetConsumingEnumerable())
            {
                try { Send(e); } catch { Interlocked.Increment(ref _errors); }
            }
        }
        catch { /* ignore */ }
    }

    protected abstract void Send(ShieldEvent e);

    public virtual void Dispose()
    {
        try { _queue.CompleteAdding(); } catch { }
        try { _worker.Join(TimeSpan.FromSeconds(3)); } catch { }
    }
}

/// <summary>RFC 5424 syslog over UDP or TCP (newline framing).</summary>
public sealed class SyslogSink : AsyncSinkBase
{
    private readonly string _host;
    private readonly int _port;
    private readonly bool _tcp;
    private readonly string _appName;
    private readonly Func<ShieldEvent, string> _render;
    private TcpClient? _tcpClient;

    /// <param name="render">
    /// Optional payload renderer, so the same sink can ship ECS/OCSF/CEF instead of the
    /// native shape. Null keeps the historical compact-JSON payload.
    /// </param>
    public SyslogSink(string host, int port, string protocol, string appName,
        Func<ShieldEvent, string>? render = null) : base("Syslog")
    {
        _host = host;
        _port = port;
        _tcp = string.Equals(protocol, "tcp", StringComparison.OrdinalIgnoreCase);
        _appName = string.IsNullOrWhiteSpace(appName) ? "ProcessShield" : appName;
        _render = render ?? Json.Event;
    }

    protected override void Send(ShieldEvent e)
    {
        int severity = e.Level switch
        {
            "QUARANTINE" => 1,   // alert
            "ERROR" => 3,        // error -- agent-internal failures, not detections
            "WARN" => 4,         // warning
            "ACTION" => 5,       // notice
            _ => 6               // info
        };
        int pri = (1 * 8) + severity;  // facility 1 (user)
        string ts = e.TimeUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        string host = Environment.MachineName;
        string msg = $"<{pri}>1 {ts} {host} {_appName} {e.Pid} {e.Category} - {_render(e)}";
        byte[] bytes = Encoding.UTF8.GetBytes(msg);

        if (_tcp) SendTcp(bytes);
        else SendUdp(bytes);
    }

    private void SendUdp(byte[] bytes)
    {
        using var udp = new UdpClient();
        udp.Send(bytes, bytes.Length, _host, _port);
    }

    private void SendTcp(byte[] bytes)
    {
        if (_tcpClient is null || !_tcpClient.Connected)
        {
            _tcpClient?.Dispose();
            _tcpClient = new TcpClient();
            _tcpClient.Connect(_host, _port);
        }
        var stream = _tcpClient.GetStream();
        stream.Write(bytes, 0, bytes.Length);
        stream.WriteByte((byte)'\n');
        stream.Flush();
    }

    public override void Dispose()
    {
        base.Dispose();
        try { _tcpClient?.Dispose(); } catch { }
    }
}

/// <summary>POSTs each event as JSON to a SIEM/webhook endpoint.</summary>
public sealed class WebhookSink : AsyncSinkBase
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _url;
    private readonly Func<ShieldEvent, string> _render;
    private readonly string _contentType;

    public WebhookSink(string url, Func<ShieldEvent, string>? render = null,
        string contentType = "application/json") : base("Webhook")
    {
        _url = url;
        _render = render ?? Json.Event;
        _contentType = contentType;
    }

    protected override void Send(ShieldEvent e)
    {
        using var content = new StringContent(_render(e), Encoding.UTF8, _contentType);
        using var resp = Http.PostAsync(_url, content).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
    }
}

/// <summary>
/// Tamper-EVIDENT audit log. Each record's Hash is an HMAC-SHA256, keyed by a
/// per-install secret, over (prevHash || seq || timeUtc || canonical-event), forming a
/// hash chain. A keyed head-anchor sidecar records the last committed (seq, hash) so
/// tail truncation and full emptying are detectable -- not just interior edits.
///
/// The anchor is a HIGH-WATER MARK and only ever moves forward. On restart the stored
/// anchor is loaded and MAC-verified before the tail is recovered, and an anchor at or
/// below the stored seq is refused, so a restart on a truncated log cannot overwrite the
/// evidence of its own truncation.
///
/// HONEST THREAT MODEL / LIMITATION:
///  - Detects, even against an attacker who lacks the key: interior edits (incl. the
///    logged timestamp), reordering, seq gaps, tail truncation, and full emptying.
///  - Truncation evidence is durable but not permanent: after a truncation the agent
///    resumes numbering from the recovered (lower) seq, so once enough NEW records push
///    the chain past the old anchor, Verify stops reporting the gap. The restart that
///    observed it raises <see cref="IntegrityWarning"/> once -- that alert, or an off-box
///    copy of the events, is what survives.
///  - The key lives in a sibling "&lt;path&gt;.key" file. Anyone who can READ that key can
///    re-forge the entire chain. ProcessShield runs elevated, so a SAME-PRIVILEGE
///    attacker still defeats this; protect the audit directory with an admin-only ACL.
///  - TRUE tamper-resistance against an equal-privilege adversary requires shipping each
///    event off-box to an append-only store (see SyslogSink / WebhookSink) and
///    reconciling the local chain against that remote head. The local chain is evidence,
///    not a guarantee, against an attacker who already owns the host.
/// </summary>
public sealed class AuditLogSink : IEventSink
{
    private const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    private readonly object _gate = new();
    private readonly string _path;
    private readonly string _anchorPath;
    private readonly byte[] _key;
    private string _prevHash;
    private long _seq;

    // High-water mark of the anchor: the furthest (seq, hash) this chain is known to have
    // reached. Guarded by _gate once construction completes. -1 means "no valid anchor yet".
    private long _anchorSeq;
    private string _anchorHash;

    /// <summary>
    /// Non-null when construction found evidence that the chain was tampered with while the
    /// agent was down: the on-disk tail is shorter than the keyed head anchor (records
    /// truncated or deleted), the head hash disagrees with the anchor at the same seq (the
    /// last record was rewritten), or the anchor itself is present but fails its MAC.
    /// Surfaced so the host can alert; the sink still opens, because refusing to log from
    /// here on would only finish the job the attacker started.
    /// </summary>
    public string? IntegrityWarning { get; }

    /// <param name="integrityAlert">
    /// Optional callback invoked once, during construction, if the chain fails its
    /// start-up integrity check. Kept as a parameter rather than a Logger dependency so
    /// Telemetry stays free of a back-reference to Core.
    /// </param>
    public AuditLogSink(string path, Action<string>? integrityAlert = null)
    {
        _path = path;
        _anchorPath = path + ".anchor";
        _key = LoadOrCreateKey(path + ".key");

        // Read the anchor BEFORE recovering the tail. The anchor is the only surviving
        // record of how far the chain got last time, so it has to be loaded first and then
        // never moved backwards: a truncated log recovers to a LOWER seq, and letting the
        // next Emit rewrite the anchor with that lower seq would erase the one piece of
        // evidence that proves the truncation happened.
        bool anchorPresent = false;
        try { anchorPresent = File.Exists(_anchorPath); } catch { }
        if (TryReadAnchor(_anchorPath, _key, out long anchorSeq, out string anchorHash))
        {
            _anchorSeq = anchorSeq;
            _anchorHash = anchorHash;
        }
        else
        {
            _anchorSeq = -1;
            _anchorHash = "";
        }

        (_seq, _prevHash) = RecoverTail(path);

        // _seq is the NEXT seq to write, so the last committed record is _seq - 1.
        long lastSeq = _seq - 1;
        string? warning = null;
        if (_anchorSeq >= 0 && lastSeq < _anchorSeq)
        {
            warning = $"audit chain at '{path}' is SHORTER than its keyed head anchor: the on-disk tail " +
                      $"ends at seq {lastSeq} but the anchor commits seq {_anchorSeq}. " +
                      $"{_anchorSeq - lastSeq} record(s) were truncated or deleted.";
        }
        else if (_anchorSeq >= 0 && lastSeq == _anchorSeq && !HexEquals(_prevHash, _anchorHash))
        {
            warning = $"audit chain at '{path}' ends at the anchored seq {lastSeq} but with a different head " +
                      "hash; the last record was rewritten (its MAC will also fail verification).";
        }
        else if (anchorPresent && _anchorSeq < 0)
        {
            warning = $"audit head anchor '{_anchorPath}' exists but failed its MAC check; it was corrupted, " +
                      "rewritten, or written under a different key. Truncation before this point cannot be proven.";
        }

        IntegrityWarning = warning;
        if (warning is not null)
        {
            try { integrityAlert?.Invoke(warning); } catch { /* an alert must never block audit logging */ }
            try { Console.Error.WriteLine("[AUDIT] " + warning); } catch { }
        }
    }

    public void Emit(ShieldEvent e)
    {
        lock (_gate)
        {
            string canonical = Json.Event(e);
            var recordTime = DateTime.UtcNow;
            string mac = MacHex(_key, ChainInput(_prevHash, _seq, recordTime, canonical));
            var record = new AuditRecord
            {
                Seq = _seq,
                TimeUtc = recordTime,
                PrevHash = _prevHash,
                Hash = mac,
                Event = e
            };
            try
            {
                File.AppendAllText(_path, JsonSerializer.Serialize(record, Json.Compact) + Environment.NewLine);
                _prevHash = mac;
                _seq++;
                WriteAnchor(record.Seq, mac);   // best-effort truncation anchor
            }
            catch { /* best effort */ }
        }
    }

    public void Dispose() { }

    /// <summary>Recomputes the chain and returns true only if every link is intact AND the
    /// on-disk chain reaches (or exceeds) the keyed head anchor. Loads the key + anchor from
    /// sibling files next to <paramref name="path"/>.</summary>
    public static bool Verify(string path, out string error)
    {
        error = "";
        try
        {
            if (!File.Exists(path)) { error = "file not found"; return false; }

            byte[] key;
            try { key = LoadKey(path + ".key"); }
            catch { error = "audit key missing or unreadable; cannot verify integrity"; return false; }

            string prev = Genesis;
            long expectedSeq = 0;
            long count = 0;
            long lastSeq = -1;
            string lastHash = Genesis;

            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                AuditRecord? rec;
                try { rec = JsonSerializer.Deserialize<AuditRecord>(line); }
                catch { error = $"unparsable record at seq {expectedSeq}"; return false; }
                if (rec is null) { error = $"unparsable record at seq {expectedSeq}"; return false; }
                if (rec.Seq != expectedSeq) { error = $"seq gap: expected {expectedSeq}, got {rec.Seq}"; return false; }
                if (rec.PrevHash != prev) { error = $"broken link at seq {rec.Seq}"; return false; }

                string canonical = Json.Event(rec.Event);
                string mac = MacHex(key, ChainInput(rec.PrevHash, rec.Seq, rec.TimeUtc, canonical));
                if (!HexEquals(mac, rec.Hash)) { error = $"tampered record at seq {rec.Seq}"; return false; }

                prev = rec.Hash;
                lastHash = rec.Hash;
                lastSeq = rec.Seq;
                count++;
                expectedSeq++;
            }

            if (count == 0) { error = "audit log is present but empty (all records removed)"; return false; }

            // Truncation / deletion check against the keyed head anchor.
            if (!TryReadAnchor(path + ".anchor", key, out long anchorSeq, out string anchorHash))
            {
                error = "head anchor missing or invalid (possible truncation/deletion)";
                return false;
            }
            if (lastSeq < anchorSeq)
            {
                error = $"tail truncated: chain ends at seq {lastSeq} but anchor expects seq {anchorSeq}";
                return false;
            }
            if (lastSeq == anchorSeq && !HexEquals(lastHash, anchorHash))
            {
                error = $"head hash mismatch at seq {lastSeq}";
                return false;
            }
            // lastSeq > anchorSeq is tolerated: a concurrent Emit appended records after the
            // anchor was last written; each is HMAC-verified above, so it is not forged.
            return true;
        }
        catch (Exception ex) { error = ex.Message; return false; }
    }

    // Bytes covered by the per-record MAC. TimeUtc is included so a logged timestamp
    // cannot be altered without breaking the MAC; Seq binds position defence-in-depth.
    private static string ChainInput(string prevHash, long seq, DateTime timeUtc, string canonical)
        => prevHash + "|" + seq.ToString(CultureInfo.InvariantCulture) + "|" +
           timeUtc.ToString("O", CultureInfo.InvariantCulture) + "|" + canonical;

    /// <summary>
    /// Commits the new head to the anchor sidecar. MONOTONIC BY CONTRACT: the anchor is a
    /// high-water mark, so a seq at or below the one already stored is refused. Without that
    /// guard a restart on a truncated log (which recovers to a lower seq) would overwrite the
    /// anchor with the lower value on the very next Emit and destroy the truncation evidence.
    /// Callers hold <c>_gate</c>, so the compare-then-write is not racy.
    /// </summary>
    private void WriteAnchor(long seq, string hash)
    {
        if (seq <= _anchorSeq) return;
        try
        {
            var a = new AnchorRecord { Seq = seq, Hash = hash, Mac = MacHex(_key, AnchorInput(seq, hash)) };
            string tmp = _anchorPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(a, Json.Compact));
            File.Move(tmp, _anchorPath, overwrite: true);   // atomic replace
            _anchorSeq = seq;
            _anchorHash = hash;
        }
        catch { /* best effort; the next successful Emit re-establishes the anchor */ }
    }

    private static bool TryReadAnchor(string anchorPath, byte[] key, out long seq, out string hash)
    {
        seq = -1; hash = "";
        try
        {
            if (!File.Exists(anchorPath)) return false;
            var a = JsonSerializer.Deserialize<AnchorRecord>(File.ReadAllText(anchorPath));
            if (a is null) return false;
            if (!HexEquals(MacHex(key, AnchorInput(a.Seq, a.Hash)), a.Mac)) return false;
            seq = a.Seq; hash = a.Hash; return true;
        }
        catch { return false; }
    }

    private static string AnchorInput(long seq, string hash)
        => "anchor|" + seq.ToString(CultureInfo.InvariantCulture) + "|" + hash;

    private static (long seq, string prevHash) RecoverTail(string path)
    {
        // Robust recovery: a crash/power-loss can leave a truncated final line, and a
        // transient read error must NOT silently reset an existing chain to (0, Genesis)
        // -- that would renumber from 0 and corrupt the log permanently. Parse line by
        // line, keep the last fully-parsed record, and drop any dangling partial tail so
        // the next append stays clean and verifiable. A genuine IO error propagates (the
        // ctor's caller, BuildSink, disables the audit sink loudly rather than resetting).
        if (!File.Exists(path)) return (0, Genesis);
        byte[] all = File.ReadAllBytes(path);
        if (all.Length == 0) return (0, Genesis);

        string text = Encoding.UTF8.GetString(all);
        AuditRecord? last = null;
        int i = 0, validEnd = 0;
        while (i < text.Length)
        {
            int nl = text.IndexOf('\n', i);
            bool hasNl = nl >= 0;
            int end = hasNl ? nl + 1 : text.Length;
            string line = text.Substring(i, end - i).Trim('\r', '\n', ' ', '\t');
            i = end;
            if (line.Length == 0) { if (hasNl) validEnd = i; continue; }

            AuditRecord? rec = null;
            try { rec = JsonSerializer.Deserialize<AuditRecord>(line); } catch { }
            if (rec is null || !hasNl) break;   // corrupt OR unterminated final line = partial write; stop
            last = rec;
            validEnd = i;
        }

        if (validEnd < all.Length)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None);
                fs.SetLength(Encoding.UTF8.GetByteCount(text[..validEnd]));
            }
            catch { /* keep monotonic seq even if truncation fails; never reset to 0 */ }
        }

        return last is null ? (0, Genesis) : (last.Seq + 1, last.Hash);
    }

    /// <summary>
    /// Loads the per-install audit key, minting a new one ONLY when the key file genuinely
    /// does not exist. A key file that is present but unreadable (ACL'd away, locked) or
    /// malformed is NOT replaced: silently minting a replacement would start a fresh chain
    /// under a new key and permanently mark every previously written record as tampered,
    /// converting "someone attacked my key" into a false verdict that hides the attack.
    /// Throwing instead lets BuildSink disable the audit sink loudly, and the existing
    /// records stay verifiable once the real key is restored from backup.
    /// Existence is probed by reading rather than by File.Exists, because File.Exists also
    /// reports false for a file that exists but is denied to us -- exactly the attack case.
    /// </summary>
    private static byte[] LoadOrCreateKey(string keyPath)
    {
        string? hex = null;
        try { hex = File.ReadAllText(keyPath).Trim(); }
        catch (FileNotFoundException) { /* genuinely absent: fall through and create */ }
        catch (DirectoryNotFoundException) { /* genuinely absent: fall through and create */ }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"audit key '{keyPath}' exists but could not be read; refusing to mint a replacement " +
                "because that would invalidate every existing audit record", ex);
        }

        if (hex is not null)
        {
            if (hex.Length != 64)
                throw new InvalidOperationException(
                    $"audit key '{keyPath}' is malformed (expected 64 hex chars, found {hex.Length}); " +
                    "refusing to mint a replacement because that would invalidate every existing audit record");
            try { return Convert.FromHexString(hex); }
            catch (FormatException ex)
            {
                throw new InvalidOperationException(
                    $"audit key '{keyPath}' is not valid hex; refusing to mint a replacement " +
                    "because that would invalidate every existing audit record", ex);
            }
        }

        byte[] key = RandomNumberGenerator.GetBytes(32);
        try { File.WriteAllText(keyPath, Convert.ToHexString(key)); }
        catch { /* if we can't persist it, later Verify fails loudly rather than passing silently */ }
        return key;
    }

    private static byte[] LoadKey(string keyPath)
    {
        string hex = File.ReadAllText(keyPath).Trim();
        if (hex.Length != 64) throw new InvalidOperationException("audit key has unexpected length");
        return Convert.FromHexString(hex);
    }

    private static string MacHex(byte[] key, string input)
        => Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(input)));

    // Constant-time compare of two hex strings to avoid a timing oracle on the MAC.
    private static bool HexEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(a), Encoding.ASCII.GetBytes(b));
    }

    private sealed class AuditRecord
    {
        public long Seq { get; set; }
        public DateTime TimeUtc { get; set; }
        public string PrevHash { get; set; } = "";
        public string Hash { get; set; } = "";
        public ShieldEvent Event { get; set; } = new();
    }

    private sealed class AnchorRecord
    {
        public long Seq { get; set; }
        public string Hash { get; set; } = "";
        public string Mac { get; set; } = "";
    }
}
