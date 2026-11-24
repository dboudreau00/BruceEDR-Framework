using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Intel;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

public sealed class BrowserAndBaselineTests
{
    private static readonly DateTime T0 = new(2026, 11, 24, 9, 21, 57, DateTimeKind.Utc);

    private static RuleEngine ShippedRules()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "rules", "detection");
            if (Directory.Exists(probe) && Directory.GetFiles(probe, "*.json").Length > 0)
            {
                var set = RuleEngine.LoadDirectory(probe);
                Assert.Empty(set.BlockingErrors.Select(e => e.ToString()));
                return new RuleEngine(set);
            }
        }
        throw new InvalidOperationException("shipped rule packs not found");
    }

    [Theory]
    [InlineData("d2gt2ux04o03l1.cloudfront.net")]
    [InlineData("sgtm-prod-985009374134.us-central1.run.app")]
    [InlineData("r4---sn-a5mekn6z.googlevideo.com")]
    [InlineData("a1843.dscd.akamai.net")]
    [InlineData("afd-prod-b7c8d9e0f1.azurefd.net")]
    [InlineData("sgtm-prod-985009374134.analytics.example.com")]
    public void Managed_Cdn_CloudRun_And_Hyphenated_Service_Names_Do_Not_False_Positive(string domain)
    {
        var v = DomainAnalysis.Analyze(domain);
        Assert.False(v.LikelyDga, $"Expected {domain} not to be flagged as DGA (got score {v.DgaScore:F2}: {v.Explanation})");
        Assert.False(v.LooksLikeDnsTunnel, $"Expected {domain} not to be flagged as DNS tunnel ({v.Explanation})");
    }

    [Fact]
    public void Firefox_Visiting_Google_CloudFront_And_CloudRun_Scores_Zero_And_Never_Flags()
    {
        const int firefoxPid = 27504;
        const string firefoxPath = @"C:\Program Files\Mozilla Firefox\firefox.exe";

        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => true,
            new EngineDependencies
            {
                Rules = ShippedRules(),
                Tree = new ProcessTree(SystemClock.Instance),
                Standing = (_, path) => new ImageStanding(true, "Mozilla Corporation", true, false, path),
                ResolveProcessName = pid => pid == firefoxPid ? "firefox.exe" : "explorer.exe"
            });

        var verdicts = new List<DetectionResult>();
        int tick = 0;
        void Feed(Signal s) => verdicts.AddRange(engine.Ingest(s with { TimestampUtc = T0.AddSeconds(tick++) }));

        Feed(new Signal
        {
            Kind = SignalKind.ProcessStart,
            Pid = firefoxPid,
            ParentPid = 4200,
            ProcessName = "firefox.exe",
            ImagePath = firefoxPath,
            CommandLine = $"\"{firefoxPath}\""
        });

        // Exact domains and Google HTTPS IP from live smoke-test screenshot
        foreach (string domain in new[]
        {
            "www.google.com",
            "d2gt2ux04o03l1.cloudfront.net",
            "sgtm-prod-985009374134.us-central1.run.app",
            "contile.services.mozilla.com",
            "random-adtech-node-kq3v9z7wxr.thirdparty-ads.example"
        })
        {
            Feed(new Signal
            {
                Kind = SignalKind.DnsQuery,
                Pid = firefoxPid,
                ProcessName = "firefox.exe",
                Domain = domain
            });
        }

        Feed(new Signal
        {
            Kind = SignalKind.NetworkConnect,
            Pid = firefoxPid,
            ProcessName = "firefox.exe",
            RemoteAddress = "142.251.152.119",
            RemotePort = 443
        });

        Assert.Empty(verdicts);
        var snap = engine.SnapshotOne(firefoxPid);
        Assert.NotNull(snap);
        Assert.Equal(0, snap!.Score);
        Assert.Contains("www.google.com", snap.Domains);
        Assert.Contains("d2gt2ux04o03l1.cloudfront.net", snap.Domains);
    }

    [Fact]
    public void Fake_Unsigned_Firefox_In_Temp_Resolving_Dga_And_Tunnel_Still_Flags()
    {
        const int fakePid = 31337;
        const string fakePath = @"C:\Users\alice\AppData\Local\Temp\firefox.exe";

        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => false,
            new EngineDependencies
            {
                Rules = ShippedRules(),
                Tree = new ProcessTree(SystemClock.Instance),
                Standing = (_, path) => new ImageStanding(false, "", false, false, path),
                ResolveProcessName = _ => "firefox.exe"
            });

        var verdicts = new List<DetectionResult>();
        verdicts.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart,
            Pid = fakePid,
            ParentPid = 4200,
            ProcessName = "firefox.exe",
            ImagePath = fakePath,
            CommandLine = fakePath,
            TimestampUtc = T0
        }));
        verdicts.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.DnsQuery,
            Pid = fakePid,
            ProcessName = "firefox.exe",
            Domain = "qzxjvbwmkrtn.duckdns.org",
            TimestampUtc = T0.AddSeconds(1)
        }));
        verdicts.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.DnsQuery,
            Pid = fakePid,
            ProcessName = "firefox.exe",
            Domain = "mzxw6ytboi7gk3tdn5sgs3tenfxgo4.t.evil-c2.com",
            TimestampUtc = T0.AddSeconds(2)
        }));

        Assert.Contains(verdicts, v => v.Verdict == Verdict.Quarantine);
    }

    [Fact]
    public void Compromised_Installed_Firefox_Touching_Lsass_And_Ioc_Domain_Still_Flags()
    {
        const int firefoxPid = 27504;
        const string firefoxPath = @"C:\Program Files\Mozilla Firefox\firefox.exe";
        var intel = IocFeed.Parse(new[] { "c2-dropper.badactor.test ; Known-C2" }, "unit-test");

        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => true,
            new EngineDependencies
            {
                Rules = ShippedRules(),
                Intel = intel,
                Tree = new ProcessTree(SystemClock.Instance),
                Standing = (_, path) => new ImageStanding(true, "Mozilla Corporation", true, false, path),
                ResolveProcessName = pid => pid == 680 ? "lsass.exe" : "firefox.exe"
            });

        var verdicts = new List<DetectionResult>();
        verdicts.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart,
            Pid = firefoxPid,
            ParentPid = 4200,
            ProcessName = "firefox.exe",
            ImagePath = firefoxPath,
            TimestampUtc = T0
        }));
        verdicts.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.DnsQuery,
            Pid = firefoxPid,
            ProcessName = "firefox.exe",
            Domain = "c2-dropper.badactor.test",
            TimestampUtc = T0.AddSeconds(1)
        }));
        verdicts.AddRange(engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessAccess,
            Pid = firefoxPid,
            ProcessName = "firefox.exe",
            TargetPid = 680,
            DesiredAccess = 0x001F0FFF,
            Detail = "lsass.exe",
            TimestampUtc = T0.AddSeconds(2)
        }));

        Assert.Contains(verdicts, v => v.Verdict == Verdict.Quarantine);
    }
}
