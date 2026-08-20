using ProcessShield.Core;
using ProcessShield.Detection;
using Xunit;

namespace ProcessShield.Tests;

/// <summary>
/// Regression guards for false positives that would fire on an ordinary, clean machine.
///
/// These exist because the suite had 1,969 passing tests while the builtin credential-store
/// rule would suspend and firewall-block the user's browser within milliseconds of it
/// starting. Nothing caught it: the replay corpus was curated so no benign file matched the
/// sensitive fragments at all, which made the "no false positives" scenario vacuous for
/// exactly the case that mattered.
///
/// A false positive here is not cosmetic. Crossing the quarantine threshold suspends a live
/// process and installs a persistent outbound firewall block on its image, and releasing it
/// takes manual analyst action. Treat every failure in this file as a shipping blocker.
/// </summary>
public class FalsePositiveRegressionTests
{
    private const int Warn = 40;
    private const int Quarantine = 70;

    private static DetectionEngine Engine(bool trusted = false) => new(
        new EngineOptions
        {
            WarnThreshold = Warn,
            QuarantineThreshold = Quarantine,
            CorrelationWindow = TimeSpan.FromSeconds(30),
            TrustDiscount = 30
        },
        _ => trusted);

    private static Signal Start(int pid, string name, string image) => new()
    {
        Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name, ImagePath = image
    };

    private static Signal File(int pid, string path) => new()
    {
        Kind = SignalKind.FileCreate, Pid = pid, FilePath = path
    };

    // ------------------------------------------------------ the shipped regression

    /// <summary>
    /// Chrome opening its own profile. This is what every user does every day, and it used
    /// to reach 70 within two file events and freeze the browser.
    /// </summary>
    [Fact]
    public void A_Browser_Reading_Its_Own_Profile_Is_Never_Contained()
    {
        var engine = Engine();
        const int pid = 4242;
        const string root = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\";

        var verdicts = new List<DetectionResult>();
        verdicts.AddRange(engine.Ingest(Start(pid, "chrome.exe", @"C:\Program Files\Google\Chrome\chrome.exe")));

        // A realistic slice of what Chrome touches under User Data during startup.
        foreach (var rel in new[]
                 {
                     "Local State", @"Default\Preferences", @"Default\Login Data",
                     @"Default\Network\Cookies", @"Default\Web Data", @"Default\History",
                     @"Default\Login Data-journal", @"Default\Local Storage\leveldb\CURRENT"
                 })
        {
            verdicts.AddRange(engine.Ingest(File(pid, root + rel)));
        }

        var snap = engine.SnapshotOne(pid);
        Assert.NotNull(snap);
        Assert.False(snap!.Contained,
            $"chrome.exe was contained for reading its own profile (score {snap.Score}): " +
            string.Join(" | ", snap.Reasons));
        Assert.DoesNotContain(verdicts, v => v.Verdict == Verdict.Quarantine);
        Assert.True(snap.Score < Warn,
            $"chrome.exe scored {snap.Score} (warn is {Warn}) on its own profile: " +
            string.Join(" | ", snap.Reasons));
    }

    [Theory]
    [InlineData("msedge.exe", @"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\Default\Login Data")]
    [InlineData("firefox.exe", @"C:\Users\u\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\key4.db")]
    [InlineData("firefox.exe", @"C:\Users\u\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json")]
    [InlineData("exodus.exe", @"C:\Users\u\AppData\Roaming\Exodus\wallet.dat")]
    [InlineData("discord.exe", @"C:\Users\u\AppData\Roaming\discord\Local Storage\leveldb\000003.log")]
    public void The_Owner_Application_Is_Not_Scored_For_Its_Own_Store(string process, string path)
    {
        var engine = Engine();
        const int pid = 900;
        engine.Ingest(Start(pid, process, @"C:\Program Files\" + process));
        engine.Ingest(File(pid, path));

        var snap = engine.SnapshotOne(pid);
        Assert.NotNull(snap);
        Assert.Equal(0, snap!.Score);
    }

    /// <summary>
    /// The flip side: an unrelated process reading the same file is exactly the behaviour the
    /// rule exists to catch, and it must still score. A fix that silenced this would be worse
    /// than the bug.
    /// </summary>
    [Fact]
    public void A_Foreign_Process_Reading_A_Browser_Credential_Store_Still_Scores()
    {
        var engine = Engine();
        const int pid = 1337;
        engine.Ingest(Start(pid, "stealer.exe", @"C:\Users\u\AppData\Local\Temp\stealer.exe"));
        engine.Ingest(File(pid, @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"));

        var snap = engine.SnapshotOne(pid);
        Assert.NotNull(snap);
        Assert.True(snap!.Score >= 35,
            $"credential-store access must still be detected; scored {snap.Score}");
        Assert.Contains(snap.Reasons, r => r.Contains("credential", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Repeated access to the SAME artifact must not compound. Without the de-dup gate, a
    /// process reading Login Data in a loop reached quarantine on volume alone.
    /// </summary>
    [Fact]
    public void Repeated_Access_To_The_Same_Artifact_Scores_Once()
    {
        var engine = Engine();
        const int pid = 1338;
        engine.Ingest(Start(pid, "stealer.exe", @"C:\Temp\stealer.exe"));

        const string target = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data";
        for (int i = 0; i < 25; i++) engine.Ingest(File(pid, target));

        var snap = engine.SnapshotOne(pid);
        Assert.NotNull(snap);
        Assert.True(snap!.Score < Quarantine,
            $"25 reads of one file reached {snap.Score}; the de-dup gate is not holding: " +
            string.Join(" | ", snap.Reasons));
    }

    /// <summary>
    /// Directory membership alone is not evidence. Reading an unrelated file that merely lives
    /// under a browser profile must score nothing.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Preferences")]
    [InlineData(@"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Favicons")]
    [InlineData(@"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\Default\Shortcuts")]
    [InlineData(@"C:\Users\u\AppData\Roaming\Mozilla\Firefox\Profiles\x\places.sqlite")]
    public void A_Non_Secret_File_Under_A_Profile_Directory_Scores_Nothing(string path)
    {
        var engine = Engine();
        const int pid = 777;
        engine.Ingest(Start(pid, "sometool.exe", @"C:\Tools\sometool.exe"));
        engine.Ingest(File(pid, path));

        var snap = engine.SnapshotOne(pid);
        Assert.NotNull(snap);
        Assert.Equal(0, snap!.Score);
    }

    // -------------------------------------------------------------- alert volume

    /// <summary>
    /// Warn used to re-fire on EVERY subsequent signal once a process was above the
    /// threshold, so one noisy process buried the event feed under thousands of duplicates.
    /// </summary>
    [Fact]
    public void Warn_Does_Not_Re_Fire_On_Every_Later_Signal()
    {
        var engine = Engine();
        const int pid = 555;
        engine.Ingest(Start(pid, "powershell.exe", @"C:\Windows\System32\powershell.exe"));

        var all = new List<DetectionResult>();
        // Push it over the warn threshold with command-line IOCs.
        all.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = "powershell.exe",
            CommandLine = "-enc AAA -nop -w hidden"
        }));

        // Then feed 50 further benign-ish signals from the same process.
        for (int i = 0; i < 50; i++)
            all.AddRange(engine.Ingest(File(pid, $@"C:\Users\u\Documents\file{i}.txt")));

        int warns = all.Count(v => v.Verdict == Verdict.Warn);
        Assert.True(warns <= 2, $"expected Warn to be one-shot, got {warns} warn verdicts");
    }

    // --------------------------------------------------- containment re-escalation

    /// <summary>
    /// Containment is marked before it is attempted, so that a failed suspend does not
    /// permanently downgrade the process to log-only. ShieldHost calls this on failure.
    /// </summary>
    [Fact]
    public void A_Failed_Containment_Can_Re_Escalate()
    {
        var engine = Engine();
        const int pid = 606;

        engine.Ingest(Start(pid, "evil.exe", @"C:\Temp\evil.exe"));
        engine.Ingest(File(pid, @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"));
        var contained = engine.Ingest(File(pid, @"C:\Users\u\AppData\Local\Temp\loot.zip"));
        Assert.Contains(contained, v => v.Verdict == Verdict.Quarantine);
        Assert.True(engine.SnapshotOne(pid)!.Contained);

        // Suspend failed -- e.g. access denied on a protected process.
        Assert.True(engine.MarkContainmentFailed(pid));
        Assert.False(engine.SnapshotOne(pid)!.Contained);

        // A later signal must be able to raise Quarantine again rather than being swallowed.
        var again = engine.Ingest(new Signal
        {
            Kind = SignalKind.NetworkConnect, Pid = pid,
            RemoteAddress = "203.0.113.9", RemotePort = 443
        });
        Assert.Contains(again, v => v.Verdict == Verdict.Quarantine);
    }

    /// <summary>An exited process must never be re-contained through archive correlation.</summary>
    [Fact]
    public void An_Exited_Process_Is_Not_Contained_By_Archive_Correlation()
    {
        var engine = Engine();
        const int pid = 707;
        var t = DateTime.UtcNow;

        engine.Ingest(Start(pid, "powershell.exe", @"C:\Windows\System32\powershell.exe"));
        engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = "powershell.exe",
            CommandLine = "-enc AAA", TimestampUtc = t
        });
        engine.Ingest(new Signal { Kind = SignalKind.ProcessStop, Pid = pid, TimestampUtc = t });

        // An unattributed archive lands right after the process exited.
        var results = engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 0,
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip", TimestampUtc = t
        });

        Assert.DoesNotContain(results, v => v.Pid() == pid && v.Verdict == Verdict.Quarantine);
    }
}

internal static class DetectionResultPidExtensions
{
    /// <summary>Convenience so assertions read cleanly.</summary>
    public static int Pid(this DetectionResult r) => r.Snapshot.Pid;
}
