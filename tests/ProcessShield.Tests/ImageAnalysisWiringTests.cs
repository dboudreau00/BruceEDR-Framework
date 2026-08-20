using ProcessShield.Analysis;
using ProcessShield.Core;
using ProcessShield.Detection;
using Xunit;

namespace ProcessShield.Tests;

/// <summary>
/// The static image-analysis path.
///
/// FileAnalyzer shipped in v2 as 871 lines that nothing called — the README advertised PE
/// parsing, entropy, imphash and packer detection while no code path reached any of it.
/// These tests lock the wiring in place, and pin the scores low enough that packing alone
/// can never contain a process: legitimate installers and protected commercial software are
/// packed too, so this is corroboration, not a verdict.
/// </summary>
public class ImageAnalysisWiringTests
{
    private const string SamplePath = @"C:\Temp\sample.exe";

    private static DetectionEngine Engine(Func<string, FileAnalysis?> analyzer) => new(
        new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70 },
        _ => false,
        new EngineDependencies { AnalyzeImage = analyzer });

    private static FileAnalysis Pe(string[]? packers = null, string[]? imports = null) => new()
    {
        Path = SamplePath,
        Valid = true,
        IsPeFile = true,
        PackerIndicators = packers ?? Array.Empty<string>(),
        SuspiciousImports = imports ?? Array.Empty<string>()
    };

    private static Signal Start(int pid, string name, string image) => new()
    {
        Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name, ImagePath = image
    };

    [Fact]
    public void The_Analysis_Is_Claimed_Once_And_Only_When_An_Image_Is_Known()
    {
        var engine = Engine(_ => Pe());
        engine.Ingest(Start(10, "sample.exe", SamplePath));

        Assert.True(engine.TryClaimImageAnalysis(10, out string path));
        Assert.Equal(SamplePath, path);

        // One-shot: the host must not re-read the same binary on every signal.
        Assert.False(engine.TryClaimImageAnalysis(10, out _));
        Assert.False(engine.TryClaimImageAnalysis(999, out _));
    }

    [Fact]
    public void A_Packed_Image_Scores_But_Cannot_Contain_On_Its_Own()
    {
        var engine = Engine(_ => Pe(packers: new[] { "UPX0 section" }));
        engine.Ingest(Start(11, "packed.exe", SamplePath));

        var results = engine.ApplyImageAnalysis(11, Pe(packers: new[] { "UPX0 section", "high entropy" }));
        var snap = engine.SnapshotOne(11);

        Assert.NotNull(snap);
        Assert.True(snap!.Score > 0, "packing should contribute a signal");
        Assert.True(snap.Score < 70,
            $"packing alone reached {snap.Score}; legitimate installers are packed too");
        Assert.DoesNotContain(results, r => r.Verdict == Verdict.Quarantine);
        Assert.Contains("T1027.002", snap.Techniques);
    }

    [Fact]
    public void An_Injection_Capable_Import_Set_Scores_Only_Above_A_Threshold()
    {
        var engine = Engine(_ => Pe());
        engine.Ingest(Start(14, "tool.exe", SamplePath));

        // Two suspicious imports is common in ordinary software; it must not score.
        engine.ApplyImageAnalysis(14, Pe(imports: new[] { "VirtualAllocEx", "WriteProcessMemory" }));
        Assert.Equal(0, engine.SnapshotOne(14)!.Score);

        var engine2 = Engine(_ => Pe());
        engine2.Ingest(Start(15, "tool.exe", SamplePath));
        engine2.ApplyImageAnalysis(15, Pe(imports: new[]
        {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookEx"
        }));

        var snap = engine2.SnapshotOne(15);
        Assert.True(snap!.Score > 0);
        Assert.True(snap.Score < 70, $"import analysis alone reached {snap.Score}");
        Assert.Contains("T1055", snap.Techniques);
    }

    [Fact]
    public void Repeated_Analysis_Does_Not_Compound_The_Score()
    {
        var engine = Engine(_ => Pe());
        engine.Ingest(Start(16, "packed.exe", SamplePath));

        for (int i = 0; i < 10; i++)
            engine.ApplyImageAnalysis(16, Pe(packers: new[] { "UPX0 section" }));

        var snap = engine.SnapshotOne(16);
        Assert.True(snap!.Score < 70,
            $"ten analyses of one image reached {snap.Score}; the once-per-process gate is not holding");
    }

    [Fact]
    public void A_Non_Pe_Or_Invalid_Analysis_Scores_Nothing()
    {
        var engine = Engine(_ => null);
        engine.Ingest(Start(12, "script.cmd", @"C:\Temp\script.cmd"));

        engine.ApplyImageAnalysis(12, new FileAnalysis { Valid = false, Error = "not a PE" });
        engine.ApplyImageAnalysis(12, new FileAnalysis { Valid = true, IsPeFile = false });

        Assert.Equal(0, engine.SnapshotOne(12)!.Score);
    }

    [Fact]
    public void Analysis_Is_Skipped_Entirely_When_No_Analyzer_Is_Supplied()
    {
        // The config switch disables this by leaving AnalyzeImage null. The engine must then
        // never claim, so the host never schedules the disk read at all.
        var engine = new DetectionEngine(new EngineOptions(), _ => false, EngineDependencies.Empty);
        engine.Ingest(Start(13, "x.exe", @"C:\Temp\x.exe"));

        Assert.False(engine.TryClaimImageAnalysis(13, out _));
    }
}
