using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Monitoring;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// What a workstation's own software did to the scores in 3.4.1: an antivirus, a network monitor, a
/// browser, a chat client and every console host reached "would contain" within minutes, on behaviour
/// that is their job. Each test is one of those, next to the attack the rule is there for.
/// </summary>
public sealed partial class ScoringNoiseTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 14, 0, 0, DateTimeKind.Utc);
    private const uint DupHandle = 0x0040;
    private const uint FirefoxHelper = 0x0010_0451;   // SYNCHRONIZE | QUERY_INFORMATION | DUP_HANDLE | VM_READ | TERMINATE
    private const uint Inject = 0x0C3A;               // CREATE_THREAD | VM_OPERATION | VM_WRITE | VM_READ | QUERY | SUSPEND
    private const int Lsass = 640;

    private sealed class Box
    {
        public readonly DetectionEngine Engine;
        private int _tick;

        public Box()
        {
            Engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
            {
                Tree = new ProcessTree(SystemClock.Instance),
                ResolveProcessName = pid => pid == Lsass ? "lsass" : "",
            });
        }

        public IReadOnlyList<DetectionResult> Feed(Signal s) => FeedAt(s, _tick++);

        public IReadOnlyList<DetectionResult> FeedAt(Signal s, double seconds)
            => Engine.Ingest(s with { TimestampUtc = T0.AddSeconds(seconds) });

        public int Score(int pid) => Engine.SnapshotOne(pid)?.Score ?? 0;

        public bool Listed(int pid) => Engine.Snapshot(onlyContained: false).Any(s => s.Pid == pid);

        public void Start(int pid, int parent, string name, string image = "") => Feed(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ParentPid = parent, ProcessName = name, ImagePath = image,
        });

        public IReadOnlyList<DetectionResult> Open(int pid, int target, uint mask, string name = "") => Feed(Access(pid, target, mask, name));

        public static Signal Access(int pid, int target, uint mask, string name = "") => new()
        {
            Kind = SignalKind.ProcessAccess, Pid = pid, ProcessName = name, TargetPid = target, DesiredAccess = mask,
            Detail = "open-process:" + MonitorSupport.DescribeAccessMask(mask),
        };

        public void Connect(int pid, string ip) => Feed(new Signal
        {
            Kind = SignalKind.NetworkConnect, Pid = pid, RemoteAddress = ip, RemotePort = 443,
        });
    }

    // ===================================================== opening other processes

    [Theory]
    [InlineData(DupHandle)]
    [InlineData(FirefoxHelper)]
    public void Duplicating_a_handle_or_reading_is_not_scored_against_an_ordinary_process(uint mask)
    {
        var box = new Box();
        box.Start(100, 4, "ayugram.exe");
        for (int target = 200; target < 210; target++) box.Open(100, target, mask);
        Assert.Equal(0, box.Score(100));
    }

    [Fact]
    public void Duplicating_a_handle_out_of_lsass_is_still_scored()
    {
        var box = new Box();
        box.Start(100, 4, "tool.exe");
        box.Open(100, Lsass, DupHandle);
        Assert.True(box.Score(100) >= 60);
    }

    [Fact]
    public void Opening_the_same_process_again_scores_once_and_three_targets_at_most()
    {
        var box = new Box();
        box.Start(100, 4, "tool.exe");
        for (int i = 0; i < 20; i++) box.Open(100, 300, Inject);
        Assert.Equal(25, box.Score(100));
        for (int target = 301; target < 340; target++) box.Open(100, target, Inject);
        Assert.Equal(75, box.Score(100));
    }

    [Fact]
    public void A_program_writing_into_a_copy_of_itself_it_started_is_not_scored_but_hollowing_another_image_is()
    {
        var box = new Box();
        const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        box.Start(100, 4, "chrome.exe", Chrome);
        box.Start(101, 100, "chrome.exe", Chrome);
        box.Start(102, 101, "chrome.exe");                  // a grandchild the start event named only
        box.Open(100, 101, Inject);
        box.Open(100, 102, Inject);
        Assert.Equal(0, box.Score(100));

        box.Start(200, 4, "dropper.exe", @"C:\Users\u\AppData\Local\Temp\dropper.exe");
        box.Start(201, 200, "svchost.exe", @"C:\Windows\System32\svchost.exe");
        box.Open(200, 201, Inject);
        Assert.Equal(25, box.Score(200));
    }

    [Fact]
    public void A_copy_of_itself_someone_else_started_is_not_the_programs_own_helper()
    {
        var box = new Box();
        box.Start(100, 4, "tool.exe");
        box.Start(300, 4, "tool.exe");                      // same name, not its child
        box.Open(100, 300, Inject);
        Assert.Equal(25, box.Score(100));
    }

    // ===================================================== traffic from a flagged process

    [Fact]
    public void Traffic_from_a_flagged_process_scores_once_per_address_and_three_addresses_at_most()
    {
        var box = new Box();
        box.Start(100, 4, "tool.exe");
        box.Open(100, 300, Inject);
        box.Open(100, 301, Inject);
        int flagged = box.Score(100);
        Assert.Equal(50, flagged);

        for (int i = 0; i < 10; i++) box.Connect(100, "140.82.112.5");
        Assert.Equal(flagged + 15, box.Score(100));
        foreach (var ip in new[] { "140.82.112.6", "52.149.246.39", "74.125.197.95", "142.251.155.7" }) box.Connect(100, ip);
        Assert.Equal(flagged + 45, box.Score(100));
    }
}
