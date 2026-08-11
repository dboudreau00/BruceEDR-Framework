using System.Text;
using ProcessShield.Configuration;
using ProcessShield.Core;
using ProcessShield.Detection;
using ProcessShield.Memory;
using ProcessShield.Response;
using ProcessShield.Telemetry;
using Xunit;

namespace ProcessShield.Tests;

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

        // ShieldHost claims the scan (once), runs it off the detection thread, then folds
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

    [Fact]
    public void Matches_Across_Chunk_Boundary_With_Overlap()
    {
        var m = new PatternMatcher(new[] { "cookies.sqlite" });
        // Simulate the scanner's tail+chunk overlap window.
        var full = Encoding.ASCII.GetBytes("aaaacookies.sqlitebbbb");
        var tail = full[..7];           // "aaaacoo"
        var chunk = full[7..];          // "kies.sqlitebbbb"
        var window = new byte[tail.Length + chunk.Length];
        Buffer.BlockCopy(tail, 0, window, 0, tail.Length);
        Buffer.BlockCopy(chunk, 0, window, tail.Length, chunk.Length);
        var hits = new HashSet<string>();
        m.FindInto(window, window.Length, hits);
        Assert.Contains("cookies.sqlite", hits);
    }
}

public class FirewallRuleNameTests
{
    [Fact]
    public void Strips_Injection_Characters()
    {
        var s = FirewallRuleName.Sanitize("ProcessShield Block a\"b|c;d&e.exe 42");
        Assert.DoesNotContain('"', s);
        Assert.DoesNotContain('|', s);
        Assert.DoesNotContain(';', s);
        Assert.DoesNotContain('&', s);
        Assert.False(string.IsNullOrWhiteSpace(s));
    }

    [Fact]
    public void Falls_Back_When_Everything_Stripped()
        => Assert.Equal("ProcessShield Block", FirewallRuleName.Sanitize("!!!\"\";;"));
}

public class AuditLogTests
{
    private static string NewPath()
        => Path.Combine(Path.GetTempPath(), "shield_audit_" + Guid.NewGuid().ToString("N") + ".log");

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
                sink.Emit(new ShieldEvent { Level = "QUARANTINE", Category = "detection", Pid = i, Process = "p" + i, Score = 80 });
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
                sink.Emit(new ShieldEvent { Level = "QUARANTINE", Pid = i });
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
            sink.Emit(new ShieldEvent { Level = "QUARANTINE", Pid = 1 });
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
            sink.Emit(new ShieldEvent { Level = "QUARANTINE", Pid = 1 });
            sink.Emit(new ShieldEvent { Level = "QUARANTINE", Pid = 2 });
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

    [Fact]
    public void Reforge_Without_Key_Fails()
    {
        string path = NewPath();
        try
        {
            var sink = new AuditLogSink(path);
            sink.Emit(new ShieldEvent { Level = "QUARANTINE", Pid = 1, Score = 80 });
            sink.Dispose();

            // An attacker who cannot read the key edits a record; without the key they
            // cannot produce a valid HMAC, so verification fails.
            var lines = File.ReadAllLines(path);
            lines[0] = lines[0].Replace("\"Score\":80", "\"Score\":0");
            File.WriteAllLines(path, lines);

            Assert.False(AuditLogSink.Verify(path, out _));
        }
        finally { Cleanup(path); }
    }
}

public class ConfigTests
{
    [Fact]
    public void Clamp_Enforces_Threshold_Ordering()
    {
        var cfg = new ShieldConfig();
        cfg.Detection.WarnThreshold = 40;
        cfg.Detection.QuarantineThreshold = 5;   // invalid: below warn
        cfg.ClampAndValidate();
        Assert.True(cfg.Detection.QuarantineThreshold > cfg.Detection.WarnThreshold);
    }

    [Fact]
    public void Clamp_Floors_Warn_At_One()
    {
        var cfg = new ShieldConfig();
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
