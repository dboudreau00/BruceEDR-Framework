using BruceEDR.Analysis;
using BruceEDR.Core;
using BruceEDR.Detection;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>Console hosts, words in memory, uninitialised data sections and wallet programs.</summary>
public sealed partial class ScoringNoiseTests
{
    private const uint MaximumAllowed = 0x0200_0000;

    [Fact]
    public void A_console_host_scored_after_it_exited_is_still_named_from_its_own_path()
    {
        // Starts and stops are applied ahead of other telemetry, so a console host that lived for one
        // command is already exited when its MAXIMUM_ALLOWED opens of its clients are scored.
        static void Run(Box box)
        {
            box.FeedAt(new Signal { Kind = SignalKind.ProcessStart, Pid = 100, ParentPid = 50, ProcessName = "conhost.exe" }, 0);
            box.FeedAt(new Signal { Kind = SignalKind.ProcessStop, Pid = 100 }, 5);
            box.FeedAt(new Signal { Kind = SignalKind.ImageLoad, Pid = 100, FilePath = @"C:\Windows\System32\conhost.exe" }, 1);
            box.FeedAt(Box.Access(100, 50, MaximumAllowed), 2);
            box.FeedAt(Box.Access(100, 51, MaximumAllowed), 3);
        }

        var named = new Box(platformImage: path =>
            path.Equals(@"C:\Windows\System32\conhost.exe", StringComparison.OrdinalIgnoreCase) ? "conhost.exe" : null);
        Run(named);
        Assert.Equal(0, named.Score(100));

        var unnamed = new Box();                            // what 3.4.1 did
        Run(unnamed);
        Assert.Equal(50, unnamed.Score(100));
    }

    // ===================================================== memory strings

    [Theory]
    [InlineData(new[] { "exfil" }, 0)]
    [InlineData(new[] { "stealer", "exfil" }, 0)]
    [InlineData(new[] { "stealer", "exfil", "keylog" }, 35)]
    [InlineData(new[] { "select * from logins", "keylog" }, 30)]
    [InlineData(new[] { "Infostealer_Generic" }, 25)]                 // a YARA rule
    public void Memory_strings_score_only_when_one_is_specific_or_three_common_ones_appear_together(string[] hits, int points)
    {
        var box = new Box();
        box.Start(100, 4, "app.exe");
        box.Engine.ApplyMemoryHits(100, hits);
        Assert.Equal(points, box.Score(100));
    }

    // ===================================================== rule packs and image analysis

    private static RuleEngine ShippedRules()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = System.IO.Path.Combine(dir.FullName, "rules", "detection");
            if (Directory.Exists(probe) && Directory.GetFiles(probe, "*.json").Length > 0)
                return new RuleEngine(RuleEngine.LoadDirectory(probe));
        }
        throw new InvalidOperationException("the shipped rule packs were not found");
    }

    [Theory]
    [InlineData(@"C:\Users\u\AppData\Local\exodus\Update.exe", false)]
    [InlineData(@"C:\Users\u\AppData\Local\exodus\app-24.1.1\Exodus.exe", false)]
    [InlineData(@"C:\Users\u\AppData\Roaming\Exodus\exodus.wallet\seed.seco", true)]
    [InlineData(@"C:\Users\u\AppData\Roaming\Electrum\wallets\default_wallet", true)]
    [InlineData(@"C:\Users\u\Documents\Monero\wallets\main.keys", true)]
    public void The_wallet_rule_watches_wallet_data_not_the_wallet_programs(string path, bool fires)
    {
        var box = new Box(rules: ShippedRules());
        box.Start(100, 4, "gwctlsrv.exe", @"C:\Program Files\GlassWire\GWCtlSrv.exe");
        box.Feed(new Signal { Kind = SignalKind.FileCreate, Pid = 100, FilePath = path, Detail = "open" });
        var reasons = box.Engine.SnapshotOne(100)?.Reasons ?? Array.Empty<string>();
        Assert.Equal(fires, reasons.Any(r => r.Contains("cryptocurrency wallet", StringComparison.Ordinal)));
    }

    [Fact]
    public void An_uninitialised_data_section_is_not_a_packer_hole()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", new byte[0x200], AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnExecute)
            .AddSection(".bss", Array.Empty<byte>(),
                AnalysisPeBuilder.ScnUninitData | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnWrite, virtualSize: 0x10000);

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "git.exe");

        Assert.DoesNotContain(fa.PackerIndicators, s => s.Contains("no file data"));
    }
}
