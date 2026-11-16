using BruceEDR.Analysis;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>Who signed a program, where it is installed and whether Windows runs it protected.</summary>
public sealed partial class ScoringNoiseTests
{
    private const uint AllAccess = 0x001F_FFFF;

    private static Func<int, string, ImageStanding> Standing(bool signed, bool adminOnly, bool isProtected = false, string path = "")
        => (_, known) => new ImageStanding(signed, signed ? "Example Publisher" : "", adminOnly, isProtected, path.Length > 0 ? path : known);

    [Fact]
    public void Signed_software_an_administrator_installed_is_not_scored_for_opening_processes()
    {
        var box = new Box(standing: Standing(signed: true, adminOnly: true));
        box.Start(100, 4, "gwctlsrv.exe", @"C:\Program Files\GlassWire\GWCtlSrv.exe");
        for (int target = 300; target < 320; target++) box.Open(100, target, AllAccess);
        Assert.Equal(0, box.Score(100));
    }

    [Theory]
    [InlineData(true, false)]       // signed, but a standard user could have put a DLL beside it
    [InlineData(false, true)]       // admin-only folder, but nothing vouches for the file
    public void Software_that_is_only_signed_or_only_installed_is_still_scored(bool signed, bool adminOnly)
    {
        var box = new Box(standing: Standing(signed, adminOnly));
        box.Start(100, 4, "tool.exe", @"C:\Tools\tool.exe");
        box.Open(100, 300, AllAccess);
        Assert.Equal(25, box.Score(100));
    }

    [Fact]
    public void Nothing_is_scored_for_a_process_windows_runs_protected()
    {
        var box = new Box(standing: Standing(signed: false, adminOnly: false, isProtected: true));
        box.Start(100, 4, "ekrn.exe", @"C:\Program Files\ESET\ESET Security\ekrn.exe");
        box.Open(100, 300, 0x0010_0478);
        box.Feed(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 100, Detail = "open",
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        });
        Assert.Equal(0, box.Score(100));
        Assert.False(box.Listed(100));
    }

    [Fact]
    public void Signed_installed_software_is_not_scored_for_memory_strings()
    {
        var box = new Box(standing: Standing(signed: true, adminOnly: true));
        box.Start(100, 4, "chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe");
        box.Engine.ApplyMemoryHits(100, new[] { "encrypted_key", @"chrome\user data" });
        Assert.Equal(0, box.Score(100));
    }

    [Fact]
    public void Signed_installed_software_is_not_scored_for_its_image_layout()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
        {
            AnalyzeImage = _ => null,
            Standing = Standing(signed: true, adminOnly: true),
        });
        engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = 100, ProcessName = "game.exe",
            ImagePath = @"C:\Program Files\Game\game.exe", TimestampUtc = T0,
        });
        var analysis = FileAnalyzer.AnalyzeBytes(new AnalysisPeBuilder(is64: true)
            .AddSection("UPX0", Array.Empty<byte>(),
                AnalysisPeBuilder.ScnUninitData | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnWrite | AnalysisPeBuilder.ScnExecute,
                virtualSize: 0x10000)
            .Build(), "game.exe");
        Assert.NotEmpty(analysis.PackerIndicators);

        engine.ApplyImageAnalysis(100, analysis);

        Assert.Equal(0, engine.SnapshotOne(100)?.Score ?? 0);
    }

    // ===================================================== what the analyst sees

    [Fact]
    public void A_process_that_started_before_the_agent_gets_its_path_and_signer_from_the_lookup()
    {
        const string Lively = @"C:\Users\u\AppData\Local\Programs\Lively Wallpaper\Lively.exe";
        var box = new Box(standing: Standing(signed: false, adminOnly: false, path: Lively));
        // No ProcessStart: it was running before the agent, and its first events carry a name only.
        box.Open(100, 300, Inject, "lively.exe");
        box.Open(100, 301, Inject, "lively.exe");
        var snapshot = box.Engine.SnapshotOne(100)!;
        Assert.Equal(Lively, snapshot.ImagePath);
        Assert.Equal("unsigned", snapshot.Signature);
    }

    [Fact]
    public void The_signature_line_names_the_publisher()
    {
        var box = new Box(standing: (_, known) => new ImageStanding(true, "Mozilla Corporation", false, false, known));
        box.Start(100, 4, "firefox.exe", @"C:\Users\u\Firefox\firefox.exe");
        box.Open(100, 300, Inject);
        box.Open(100, 301, Inject);
        Assert.Equal("signed by Mozilla Corporation", box.Engine.SnapshotOne(100)!.Signature);
    }
}
