using System.Text;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Memory;
using BruceEDR.Response;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

public class DetectionEngineTests
{
    private static DetectionEngine NewEngine(bool trusted = false)
        => new(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, CorrelationWindow = TimeSpan.FromSeconds(30), TrustDiscount = 30 },
            _ => trusted);

    [Fact]
    public void CollectThenArchive_Reaches_Quarantine()
    {
        var engine = NewEngine();
        var now = DateTime.UtcNow;

        engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 100,
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            TimestampUtc = now
        });

        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 100,
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip",
            TimestampUtc = now
        });

        Assert.Contains(results, r => r.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void Trusted_Process_Does_Not_Quarantine()
    {
        var engine = NewEngine(trusted: true);
        var now = DateTime.UtcNow;

        engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 101,
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            TimestampUtc = now
        });
        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 101,
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip",
            TimestampUtc = now
        });

        Assert.DoesNotContain(results, r => r.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void UnusualParent_And_CommandLine_Ioc_Warn()
    {
        var engine = NewEngine();
        engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 10, ProcessName = "winword.exe" });

        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = 200, ParentPid = 10,
            ProcessName = "powershell.exe", CommandLine = "-enc SQBFAFgA"
        });

        var v = Assert.Single(results);
        Assert.Equal(Verdict.Warn, v.Verdict);
        Assert.Contains(v.Snapshot.Reasons, r => r.Contains("winword.exe -> powershell.exe"));
        Assert.Contains(v.Snapshot.Reasons, r => r.Contains("-enc"));
    }

    [Fact]
    public void ExfilChain_Quarantines()
    {
        var engine = NewEngine();
        var now = DateTime.UtcNow;

        // The verdict can fire at any step once the score crosses the threshold, so
        // aggregate results across the whole chain rather than inspecting one call.
        var all = new List<DetectionResult>();
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 20, ProcessName = "winword.exe" }));
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 300, ParentPid = 20, ProcessName = "powershell.exe", CommandLine = "-nop -w hidden" }));
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 300, FilePath = @"C:\ProgramData\dump.zip", TimestampUtc = now }));
        all.AddRange(engine.Ingest(new Signal { Kind = SignalKind.NetworkConnect, Pid = 300, RemoteAddress = "203.0.113.10", RemotePort = 443, TimestampUtc = now }));

        Assert.Contains(all, r => r.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void MemoryHit_Applied_Off_Thread_Can_Quarantine()
    {
        var engine = NewEngine();

        // Reading a credential store warns (+35) but does not quarantine on its own.
        var first = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 400,
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        });
        Assert.DoesNotContain(first, r => r.Verdict == Verdict.Quarantine);

        // BruceHost claims the scan (once), runs it off the detection thread, then folds
        // the hits back in -- which here pushes the process over the quarantine threshold.
        Assert.True(engine.TryClaimMemoryScan(400));
        var results = engine.ApplyMemoryHits(400, new[] { "stealer", "grabber", "keylog" });
        Assert.Contains(results, r => r.Verdict == Verdict.Quarantine);

        // The claim is one-shot, so the same process is never scanned twice.
        Assert.False(engine.TryClaimMemoryScan(400));
    }

    [Fact]
    public void Reused_Pid_Resets_State_On_ProcessStart()
    {
        var engine = NewEngine();

        // Drive a pid to Contained via the exfil chain.
        engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 500,
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data" });
        var contained = engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 500,
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip" });
        Assert.Contains(contained, r => r.Verdict == Verdict.Quarantine);

        // Windows recycles pid 500 for a fresh, benign process: a new ProcessStart must
        // wipe the inherited Contained/Score state so it starts clean (score 0, warn 40).
        engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 500, ProcessName = "notepad.exe" });
        var snap = engine.SnapshotOne(500);
        Assert.NotNull(snap);
        Assert.False(snap!.Contained);
        Assert.Equal(0, snap.Score);
    }
}

public class NetworkUtilTests
{
    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("203.0.113.5", true)]
    [InlineData("172.32.0.1", true)]
    [InlineData("10.0.0.5", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("2606:4700:4700::1111", true)]   // public IPv6 (Cloudflare)
    [InlineData("::1", false)]                    // IPv6 loopback
    [InlineData("fe80::1", false)]                // IPv6 link-local
    [InlineData("fd00::1", false)]                // IPv6 unique-local (fc00::/7)
    [InlineData("::ffff:10.0.0.1", false)]        // IPv4-mapped RFC1918 (dual-stack socket)
    [InlineData("::ffff:8.8.8.8", true)]          // IPv4-mapped public
    [InlineData("100.64.0.1", false)]             // CGNAT
    [InlineData("224.0.0.251", false)]            // multicast
    [InlineData("0.0.0.0", false)]
    [InlineData("not-an-ip", false)]
    [InlineData("", false)]
    public void RoutableRemote(string ip, bool expected)
        => Assert.Equal(expected, NetworkUtil.IsRoutableRemote(ip));
}

public class PatternMatcherTests
{
    [Fact]
    public void Matches_Ascii_Case_Insensitive()
    {
        var m = new PatternMatcher(new[] { "login data" });
        var buf = Encoding.ASCII.GetBytes("junk  LOGIN DATA  junk");
        Assert.Contains("login data", m.FindAll(buf));
    }

    [Fact]
    public void Matches_Utf16()
    {
        var m = new PatternMatcher(new[] { "wallet.dat" });
        var buf = Encoding.Unicode.GetBytes("path=C:\\x\\wallet.dat;");
        Assert.Contains("wallet.dat", m.FindAll(buf));
    }

    /// <summary>
    /// Checks only that FindInto matches a needle in a window the caller assembled -- the
    /// shape MemoryScanner hands it. It does NOT prove the scanner's overlap works: the two
    /// halves are concatenated back into one contiguous buffer here, so nothing spans a real
    /// chunk boundary. MemoryScannerOverlapTests below is what pins the overlap behaviour.
    /// </summary>
    [Fact]
    public void Matches_Needle_In_A_Caller_Assembled_Window()
    {
        var m = new PatternMatcher(new[] { "cookies.sqlite" });
        var full = Encoding.ASCII.GetBytes("aaaacookies.sqlitebbbb");
        var hits = new HashSet<string>();
        m.FindInto(full, full.Length, hits);
        Assert.Contains("cookies.sqlite", hits);
    }

    /// <summary>
    /// UTF-16 matching is case-insensitive too, because lowercasing runs over raw bytes and
    /// the high byte of an ASCII-range UTF-16 code unit is zero. Also pins that hits are
    /// reported under the LOWERCASED label: DetectionEngine keys scoring off these strings,
    /// so the spelling used in config must not leak through.
    /// </summary>
    [Fact]
    public void Utf16_Match_Is_Case_Insensitive_And_Reports_The_Lowercased_Label()
    {
        var m = new PatternMatcher(new[] { "Wallet.DAT" });
        var buf = Encoding.Unicode.GetBytes("path=C:\\x\\WALLET.dat;");
        Assert.Equal(new[] { "wallet.dat" }, m.FindAll(buf));
    }

    /// <summary>An empty IOC set matches nothing; MemoryScanner.Scan short-circuits on it.</summary>
    [Fact]
    public void Empty_Ioc_Set_Matches_Nothing()
    {
        var m = new PatternMatcher(Array.Empty<string>());
        Assert.Equal(0, m.LabelCount);
        Assert.Empty(m.FindAll(Encoding.ASCII.GetBytes("login data wallet.dat")));
    }

    /// <summary>
    /// Degenerate buffers must return empty rather than throw: a zero-length region and a
    /// buffer shorter than the needle both occur constantly during a live scan.
    /// </summary>
    [Fact]
    public void Empty_Buffer_And_Oversized_Needle_Are_Safe()
    {
        var m = new PatternMatcher(new[] { "a-rather-long-indicator-string" });
        Assert.Empty(m.FindAll(Array.Empty<byte>()));
        Assert.Empty(m.FindAll(Encoding.ASCII.GetBytes("short")));

        var hits = new HashSet<string>();
        m.FindInto(Array.Empty<byte>(), 0, hits);
        Assert.Empty(hits);
    }

    /// <summary>
    /// A label is reported once no matter how often it occurs, and stays reported once across
    /// successive chunks, because the caller carries the hit set. The scanner relies on this
    /// to decide it can stop early once every label has been seen.
    /// </summary>
    [Fact]
    public void Repeated_Needle_Is_Reported_Once()
    {
        var m = new PatternMatcher(new[] { "seed phrase" });
        var buf = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("seed phrase ", 5)));
        Assert.Single(m.FindAll(buf));

        var hits = new HashSet<string>();
        m.FindInto(buf, buf.Length, hits);
        m.FindInto(buf, buf.Length, hits);
        Assert.Single(hits);
    }

    /// <summary>
    /// Only buffer[0..length) is scanned. MemoryScanner passes a window length that can be
    /// shorter than the array it allocated, so honouring it is load-bearing: over-scanning
    /// would match stale bytes left in an under-filled read buffer.
    /// </summary>
    [Fact]
    public void Only_The_First_Length_Bytes_Are_Scanned()
    {
        var m = new PatternMatcher(new[] { "cookies.sqlite" });
        var buf = Encoding.ASCII.GetBytes("aaaacookies.sqlite");

        var hits = new HashSet<string>();
        m.FindInto(buf, 4, hits);
        Assert.Empty(hits);

        m.FindInto(buf, buf.Length, hits);
        Assert.Single(hits);
    }
}

/// <summary>
/// Pins the chunk/tail overlap contract the builtin memory scanner depends on.
/// MemoryScanner.ScanRegion is private and reads a live process through ReadProcessMemory,
/// so it cannot be driven from a test. These tests instead MIRROR its windowing byte for
/// byte -- tail = the last Overlap bytes of the raw chunk, window = tail + next chunk -- and
/// drive the real PatternMatcher through it. So they do verify that hits genuinely accumulate
/// across successive overlapping windows, and they pin exactly how much straddle the overlap
/// buys; they do NOT execute MemoryScanner's own code, so a change to ScanRegion's windowing
/// must be mirrored here by hand.
/// </summary>
public class MemoryScannerOverlapTests
{
    /// <summary>Must stay equal to MemoryScanner.Overlap, which is private and not readable here.</summary>
    private const int ScannerOverlapBytes = 64;

    /// <summary>Replays MemoryScanner.ScanRegion's tail-carrying loop over in-memory chunks.</summary>
    private static HashSet<string> ScanChunks(PatternMatcher m, params byte[][] chunks)
    {
        var hits = new HashSet<string>();
        byte[] tail = Array.Empty<byte>();

        foreach (var chunk in chunks)
        {
            byte[] window;
            if (tail.Length > 0)
            {
                window = new byte[tail.Length + chunk.Length];
                Buffer.BlockCopy(tail, 0, window, 0, tail.Length);
                Buffer.BlockCopy(chunk, 0, window, tail.Length, chunk.Length);
            }
            else
            {
                window = chunk;
            }

            m.FindInto(window, window.Length, hits);

            int keep = Math.Min(ScannerOverlapBytes, chunk.Length);
            tail = chunk[(chunk.Length - keep)..chunk.Length];
        }

        return hits;
    }

    [Fact]
    public void Needle_Straddling_The_Seam_Is_Found_Via_The_Overlap()
    {
        var m = new PatternMatcher(new[] { "cookies.sqlite" });

        // 10 of the needle's 14 bytes end chunk one, the remaining 4 start chunk two.
        // 10 <= 64, so the carried tail still holds the whole prefix.
        var chunkA = Encoding.ASCII.GetBytes(new string('a', 200) + "cookies.sq");
        var chunkB = Encoding.ASCII.GetBytes("lite" + new string('b', 200));

        // Neither chunk contains the needle alone, so a hit can only come from the overlap.
        Assert.Empty(m.FindAll(chunkA));
        Assert.Empty(m.FindAll(chunkB));

        Assert.Contains("cookies.sqlite", ScanChunks(m, chunkA, chunkB));
    }

    /// <summary>
    /// Pins the exact edge: a needle with precisely Overlap bytes on the far side of the seam
    /// is still found. If the tail is ever carried off by one this fails rather than silently
    /// shrinking the scanner's reach.
    /// </summary>
    [Fact]
    public void Needle_With_Exactly_Overlap_Bytes_Before_The_Seam_Is_Found()
    {
        string needle = new string('z', ScannerOverlapBytes) + "-marker";
        var m = new PatternMatcher(new[] { needle });

        var chunkA = Encoding.ASCII.GetBytes(new string('a', 100) + new string('z', ScannerOverlapBytes));
        var chunkB = Encoding.ASCII.GetBytes("-marker" + new string('b', 100));

        Assert.Empty(m.FindAll(chunkA));
        Assert.Empty(m.FindAll(chunkB));

        Assert.Contains(needle, ScanChunks(m, chunkA, chunkB));
    }

    /// <summary>
    /// States the accepted limitation instead of pretending it does not exist: the tail carries
    /// only the last Overlap (64) bytes of the previous chunk, so a needle with MORE than 64 of
    /// its bytes on the far side of a chunk boundary is invisible to the builtin scanner. Real
    /// IOC strings are far shorter than 64 bytes, so this is not reachable by accident -- but it
    /// is a genuine evasion primitive for an attacker who controls where a long marker lands in
    /// memory, and the builtin scanner is documented as one evadable signal among many.
    /// </summary>
    [Fact]
    public void Needle_Longer_Than_The_Overlap_Can_Be_Missed_At_A_Seam()
    {
        string needle = new string('z', ScannerOverlapBytes + 6) + "-marker";
        var m = new PatternMatcher(new[] { needle });

        var chunkA = Encoding.ASCII.GetBytes(new string('a', 100) + new string('z', ScannerOverlapBytes + 6));
        var chunkB = Encoding.ASCII.GetBytes("-marker" + new string('b', 100));

        Assert.Empty(m.FindAll(chunkA));
        Assert.Empty(m.FindAll(chunkB));

        // The tail keeps only 64 of the 70 leading 'z' bytes, so the seam window never holds
        // the whole needle and the hit is lost.
        Assert.DoesNotContain(needle, ScanChunks(m, chunkA, chunkB));
    }
}

public class FirewallRuleNameTests
{
    [Fact]
    public void Strips_Injection_Characters()
    {
        var s = FirewallRuleName.Sanitize("BruceEDR Block a\"b|c;d&e.exe 42");
        Assert.DoesNotContain('"', s);
        Assert.DoesNotContain('|', s);
        Assert.DoesNotContain(';', s);
        Assert.DoesNotContain('&', s);
        Assert.False(string.IsNullOrWhiteSpace(s));
    }

    [Fact]
    public void Falls_Back_When_Everything_Stripped()
        => Assert.Equal("BruceEDR Block", FirewallRuleName.Sanitize("!!!\"\";;"));
}

public class AuditLogTests
{
    private static string NewPath()
        => Path.Combine(Path.GetTempPath(), "bruce_audit_" + Guid.NewGuid().ToString("N") + ".log");

    private static void Cleanup(string path)
    {
        foreach (var p in new[] { path, path + ".key", path + ".anchor", path + ".anchor.tmp" })
            try { File.Delete(p); } catch { }
    }

    [Fact]
    public void Intact_Chain_Verifies_And_Tampering_Is_Detected()
    {
        string path = NewPath();
        try
        {
            var sink = new AuditLogSink(path);
            for (int i = 0; i < 3; i++)
                sink.Emit(new BruceEvent { Level = "QUARANTINE", Category = "detection", Pid = i, Process = "p" + i, Score = 80 });
            sink.Dispose();

            Assert.True(AuditLogSink.Verify(path, out _));

            var lines = File.ReadAllLines(path);
            lines[1] = lines[1].Replace("\"Score\":80", "\"Score\":1");   // tamper a record
            File.WriteAllLines(path, lines);

            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.False(string.IsNullOrEmpty(err));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Tail_Truncation_Is_Detected()
    {
        string path = NewPath();
        try
        {
            var sink = new AuditLogSink(path);
            for (int i = 0; i < 4; i++)
                sink.Emit(new BruceEvent { Level = "QUARANTINE", Pid = i });
            sink.Dispose();

            Assert.True(AuditLogSink.Verify(path, out _));

            // Drop the last two records. The surviving prefix is itself a valid chain,
            // so only the keyed head anchor can catch this.
            var lines = File.ReadAllLines(path);
            File.WriteAllLines(path, lines.Take(2).ToArray());

            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.Contains("truncat", err, StringComparison.OrdinalIgnoreCase);
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Emptied_Log_Is_Detected()
    {
        string path = NewPath();
        try
        {
            var sink = new AuditLogSink(path);
            sink.Emit(new BruceEvent { Level = "QUARANTINE", Pid = 1 });
            sink.Dispose();

            File.WriteAllText(path, "");   // attacker zeroes the file
            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.False(string.IsNullOrEmpty(err));
        }
        finally { Cleanup(path); }
    }

    [Fact]
    public void Altered_Record_Timestamp_Is_Detected()
    {
        string path = NewPath();
        try
        {
            var sink = new AuditLogSink(path);
            sink.Emit(new BruceEvent { Level = "QUARANTINE", Pid = 1 });
            sink.Emit(new BruceEvent { Level = "QUARANTINE", Pid = 2 });
            sink.Dispose();

            // Rewrite ONLY the record-level TimeUtc (the first "TimeUtc" in the line).
            // Because it is folded into the MAC, this must break verification even though
            // the event body is untouched.
            var lines = File.ReadAllLines(path);
            var rx = new System.Text.RegularExpressions.Regex("\"TimeUtc\":\"[^\"]+\"");
            lines[0] = rx.Replace(lines[0], "\"TimeUtc\":\"2000-01-01T00:00:00.0000000Z\"", 1);
            File.WriteAllLines(path, lines);

            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.False(string.IsNullOrEmpty(err));
        }
        finally { Cleanup(path); }
    }

    /// <summary>
    /// Without the key sidecar the chain cannot be checked at all, and Verify must say so
    /// rather than blaming a record: an operator has to be able to tell "the key is gone"
    /// apart from "the log was edited", because the two demand different responses.
    /// </summary>
    [Fact]
    public void Missing_Key_Makes_Verification_Fail_And_Names_The_Key()
    {
        string path = NewPath();
        try
        {
            var sink = new AuditLogSink(path);
            sink.Emit(new BruceEvent { Level = "QUARANTINE", Pid = 1, Score = 80 });
            sink.Dispose();
            Assert.True(AuditLogSink.Verify(path, out _));

            File.Delete(path + ".key");   // the one secret that makes the chain checkable

            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.Contains("key", err, StringComparison.OrdinalIgnoreCase);
        }
        finally { Cleanup(path); }
    }

    /// <summary>
    /// The real "attacker without the key" question. Intact_Chain_Verifies_And_Tampering_Is_Detected
    /// only edits a record and leaves an obviously stale MAC behind, which any checksum would
    /// catch. Here the attacker instead rewrites the log with a chain that is internally
    /// perfect -- correct seq numbering, correct PrevHash links, a MAC on every record -- but
    /// minted under a key they generated themselves because they could not read ours. Rejecting
    /// it is what proves the chain is keyed rather than merely self-consistent.
    /// </summary>
    [Fact]
    public void Chain_Forged_Under_A_Foreign_Key_Is_Rejected()
    {
        string path = NewPath();
        string forged = NewPath();
        try
        {
            var real = new AuditLogSink(path);
            real.Emit(new BruceEvent { Level = "QUARANTINE", Category = "detection", Pid = 1, Process = "evil.exe", Score = 80 });
            real.Dispose();
            Assert.True(AuditLogSink.Verify(path, out _));

            // The attacker builds a self-consistent chain telling a harmless story, signed
            // with their own key. It verifies perfectly -- against that key.
            var attacker = new AuditLogSink(forged);
            attacker.Emit(new BruceEvent { Level = "INFO", Category = "detection", Pid = 1, Process = "evil.exe", Score = 0 });
            attacker.Dispose();
            Assert.True(AuditLogSink.Verify(forged, out _));

            // ...then drops it over the real log, leaving our key and anchor untouched.
            File.Copy(forged, path, overwrite: true);

            Assert.False(AuditLogSink.Verify(path, out var err));
            Assert.Contains("tampered", err, StringComparison.OrdinalIgnoreCase);
        }
        finally { Cleanup(path); Cleanup(forged); }
    }
}

public class ConfigTests
{
    [Fact]
    public void Clamp_Enforces_Threshold_Ordering()
    {
        var cfg = new BruceConfig();
        cfg.Detection.WarnThreshold = 40;
        cfg.Detection.QuarantineThreshold = 5;   // invalid: below warn
        cfg.ClampAndValidate();
        Assert.True(cfg.Detection.QuarantineThreshold > cfg.Detection.WarnThreshold);
    }

    [Fact]
    public void Clamp_Floors_Warn_At_One()
    {
        var cfg = new BruceConfig();
        cfg.Detection.WarnThreshold = 0;
        cfg.ClampAndValidate();
        Assert.True(cfg.Detection.WarnThreshold >= 1);
    }
}

public class ActionResultTests
{
    [Fact]
    public void Success_And_Fail()
    {
        Assert.True(ActionResult.Success("ok").Ok);
        var f = ActionResult.Fail("nope");
        Assert.False(f.Ok);
        Assert.Equal("nope", f.Message);
    }
}
