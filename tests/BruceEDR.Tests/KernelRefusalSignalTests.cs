using System.Text.Json;
using System.Text.RegularExpressions;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Driver;
using BruceEDR.Hosting;
using BruceEDR.Memory;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// A refusal by the minifilter is evidence about the process that was refused. These tests
/// cross the seam an engine-only test stops short of: a refusal goes through
/// <see cref="KernelRefusalFeed"/> into a real <see cref="BruceHost"/>, which scores it and
/// decides whether anything is contained. The pids used do not exist, so an attempted suspend
/// shows up as "suspend failed", the line monitor mode must never produce.
/// </summary>
public sealed class KernelRefusalSignalTests : IDisposable
{
    private const string Chrome = @"\Device\HarddiskVolume3\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    private const string Image = @"\Device\HarddiskVolume3\Users\u\Downloads\stealer.exe";

    private readonly List<BruceHost> _hosts = new();
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bruce-refusal-" + Guid.NewGuid().ToString("N"));

    public KernelRefusalSignalTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        foreach (var h in _hosts) { try { h.Dispose(); } catch { } }
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private sealed class RecordingSink : IEventSink
    {
        private readonly List<BruceEvent> _events = new();
        public void Emit(BruceEvent e) { lock (_events) _events.Add(e); }
        public void Dispose() { }
        public bool Any(Func<BruceEvent, bool> match) { lock (_events) return _events.Any(match); }
        public bool Any(string level, string fragment)
            => Any(e => e.Level == level && e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    private BruceHost NewHost(RecordingSink sink, bool monitorOnly)
    {
        var log = new Logger(sink);
        var response = new ResponseManager(log, new AuthenticodeVerifier(new AllowlistConfig()));
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => false,
            new EngineDependencies { ResolveProcessName = null });
        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            StartMonitors = false,
            EnableExtendedMonitors = false,
            MonitorOnly = monitorOnly,
        });
        _hosts.Add(host);
        host.Start();
        return host;
    }

    private static readonly DateTime T0 = DateTime.UtcNow;

    private static void Start(BruceHost host, int pid, string name = "stealer.exe")
        => host.Submit(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name, ImagePath = @"C:\Users\u\Downloads\" + name,
            TimestampUtc = T0
        });

    private static bool Refuse(KernelRefusalFeed feed, int pid, string? store, KernelOperation op = KernelOperation.Open,
        DateTime? at = null, string name = "stealer.exe")
        => feed.Offer(new KernelDenial(op, pid, store is null ? -1 : 0, Chrome, Image), store,
            @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data", @"C:\Users\u\Downloads\" + name,
            at ?? T0.AddSeconds(1));

    private static int ScoreOf(BruceHost host, int pid)
    {
        var info = host.Info(pid);
        Assert.True(info.Ok, info.Message);
        return int.Parse(Regex.Match(info.Message, @"score=(\d+)").Groups[1].Value);
    }

    private static bool WaitFor(Func<bool> condition, int millis = 5000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < millis)
        {
            if (condition()) return true;
            Thread.Sleep(10);
        }
        return condition();
    }

    // ================================================================ scoring

    [Fact]
    public void A_refused_untrusted_process_is_scored_with_the_store_and_the_operation_named()
    {
        const int pid = 880_101;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Assert.True(Refuse(feed, pid, "chrome"));

        Assert.True(WaitFor(() => host.SignalsProcessed >= 2), "the refusal never reached the engine");
        var snap = Assert.Single(host.ListProfiles(onlyContained: false), p => p.Pid == pid);
        Assert.Equal(40, snap.Score);
        Assert.Contains("Kernel refused open of the chrome credential store", snap.Reasons.Single());
        var entry = Assert.Single(snap.ReasonLog);
        Assert.Equal("builtin-kernel-refusal", entry.RuleId);
        Assert.Contains("T1555.003", entry.Techniques);
        Assert.Contains("T1539", entry.Techniques);
        Assert.True(WaitFor(() => sink.Any(e => e.Level == "WARN" && e.Pid == pid && e.Trigger == "KernelRefusal")),
            "a single refusal reaches the warn threshold and is reported");
        Assert.False(sink.Any(e => e.Level == "QUARANTINE"));
    }

    [Theory]
    [InlineData(KernelOperation.Open, "open of")]
    [InlineData(KernelOperation.Rename, "rename of")]
    [InlineData(KernelOperation.Link, "hard link of")]
    [InlineData(KernelOperation.Reopen, "open by id of")]
    public void The_reason_names_the_operation(KernelOperation op, string wording)
    {
        const int pid = 880_102;
        var host = NewHost(new RecordingSink(), monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Refuse(feed, pid, "firefox", op);

        Assert.True(WaitFor(() => host.SignalsProcessed >= 2));
        Assert.Contains($"Kernel refused {wording} the firefox credential store", host.Info(pid).Message);
    }

    [Fact]
    public void A_process_that_started_before_the_agent_is_named_from_the_kernels_image_path()
    {
        const int pid = 880_103;
        var host = NewHost(new RecordingSink(), monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Refuse(feed, pid, "edge");   // no ProcessStart: the agent never saw it begin

        Assert.True(WaitFor(() => host.SignalsProcessed >= 1));
        var info = host.Info(pid).Message;
        Assert.Contains("stealer.exe", info);
        Assert.Contains(@"image: C:\Users\u\Downloads\stealer.exe", info);
        Assert.Equal(40, ScoreOf(host, pid));
    }

    [Fact]
    public void A_copy_named_like_the_owner_is_still_scored_because_the_kernel_judged_its_path()
    {
        // The file rules excuse chrome.exe reading Chrome's own store by name. The driver refused
        // THIS chrome.exe by path, so the engine must not take the name on trust.
        const int pid = 880_104, honest = 880_105;
        var host = NewHost(new RecordingSink(), monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid, "chrome.exe");
        Start(host, honest, "chrome.exe");
        Refuse(feed, pid, "chrome", name: "chrome.exe");
        host.Submit(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = honest, ProcessName = "chrome.exe", TimestampUtc = T0.AddSeconds(1),
            FilePath = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        });

        Assert.True(WaitFor(() => host.SignalsProcessed >= 4));
        Assert.Equal(40, ScoreOf(host, pid));
        Assert.Equal(0, ScoreOf(host, honest));
    }

    [Fact]
    public void Every_guarded_store_is_scored_with_its_own_techniques()
    {
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => false, new EngineDependencies { ResolveProcessName = null });
        int pid = 880_110;
        foreach (var guard in IocDatabase.KernelGuards)
        {
            pid++;
            engine.Ingest(new Signal
            {
                Kind = SignalKind.KernelRefusal, Pid = pid, ProcessName = "x.exe", TimestampUtc = T0,
                Detail = KernelRefusalDetail.Format("open", guard.Name)
            });
            var entry = Assert.Single(engine.SnapshotOne(pid)!.ReasonLog);
            Assert.Contains(guard.Name, entry.Text);
            Assert.True(entry.Techniques.Count >= 2, $"{guard.Name} fell back to the generic technique");
        }
    }

    // ================================================================ correlation

    [Fact]
    public void A_refusal_starts_the_collect_then_stage_window_like_a_credential_read()
    {
        const int pid = 880_120;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Refuse(feed, pid, "chrome");
        host.Submit(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = pid, ProcessName = "stealer.exe", TimestampUtc = T0.AddSeconds(5),
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip"
        });

        Assert.True(WaitFor(() => sink.Any(e => e.Level == "QUARANTINE" && e.Pid == pid)), "40 + 30 + 25 should quarantine");
        Assert.Equal(95, ScoreOf(host, pid));
        Assert.Contains("Archive staged shortly after reading secrets", host.Info(pid).Message);
    }

    [Fact]
    public void A_refusal_for_a_name_the_driver_could_not_resolve_scores_low_and_starts_no_window()
    {
        const int pid = 880_121;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Assert.True(Refuse(feed, pid, store: null, KernelOperation.Reopen));
        host.Submit(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = pid, ProcessName = "stealer.exe", TimestampUtc = T0.AddSeconds(5),
            FilePath = @"C:\Users\u\AppData\Local\Temp\loot.zip"
        });

        Assert.True(WaitFor(() => host.SignalsProcessed >= 3));
        Assert.Equal(10 + 30, ScoreOf(host, pid));   // no +25: nothing says a credential store was involved
        var info = host.Info(pid).Message;
        Assert.Contains("Kernel refused open by id of a name it could not resolve", info);
        Assert.DoesNotContain("shortly after reading secrets", info);
    }

    [Fact]
    public void A_refusal_without_a_resolved_store_does_not_reach_the_warn_threshold()
    {
        const int pid = 880_122;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Refuse(feed, pid, store: null);

        Assert.True(WaitFor(() => host.SignalsProcessed >= 2));
        Assert.Equal(10, ScoreOf(host, pid));
        Assert.DoesNotContain(host.ListProfiles(onlyContained: false), p => p.Pid == pid);
        Assert.False(sink.Any(e => e.Level is "WARN" or "QUARANTINE"));
    }

    // ================================================================ bounds

    [Fact]
    public void Repeated_refusals_of_one_store_never_raise_the_score_past_one_refusal()
    {
        const int pid = 880_130;
        var host = NewHost(new RecordingSink(), monitorOnly: true);
        int submitted = 0;
        var feed = new KernelRefusalFeed(s => { submitted++; host.Submit(s); });

        Start(host, pid);
        for (int i = 0; i < 500; i++) Refuse(feed, pid, "chrome", at: T0.AddSeconds(1));
        Assert.Equal(1, submitted);   // the feed's own window

        // Past the window the feed lets one more through every minute; the engine still scores
        // the store once for the process.
        for (int minute = 1; minute <= 30; minute++)
            Refuse(feed, pid, "chrome", (KernelOperation)(1 + minute % 4), T0.AddMinutes(minute + 1));
        Assert.Equal(31, submitted);

        Assert.True(WaitFor(() => host.SignalsProcessed >= 32), "the signals were not drained");
        Assert.Equal(40, ScoreOf(host, pid));
        Assert.Single(host.ListProfiles(onlyContained: false).Single(p => p.Pid == pid).ReasonLog);
    }

    [Fact]
    public void A_sweep_of_every_store_is_bounded_by_the_number_of_stores()
    {
        const int pid = 880_131;
        var host = NewHost(new RecordingSink(), monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        for (int round = 0; round < 20; round++)
            foreach (var guard in IocDatabase.KernelGuards)
                Refuse(feed, pid, guard.Name, at: T0.AddMinutes(round));
        for (int round = 0; round < 20; round++)
            Refuse(feed, pid, store: null, at: T0.AddMinutes(round));

        Assert.True(WaitFor(() => host.SignalsProcessed >= 1 + 20 * (IocDatabase.KernelGuards.Length + 1)));
        Assert.Equal(40 * IocDatabase.KernelGuards.Length + 10, ScoreOf(host, pid));
    }

    [Fact]
    public void A_storm_is_capped_so_it_cannot_fill_the_queue_every_monitor_shares()
    {
        int submitted = 0;
        var feed = new KernelRefusalFeed(_ => submitted++);

        for (int pid = 1; pid <= KernelRefusalFeed.PerMinute * 4; pid++)
            Refuse(feed, 900_000 + pid, "chrome", at: T0);

        Assert.Equal(KernelRefusalFeed.PerMinute, submitted);
        Assert.True(Refuse(feed, 123, "chrome", at: T0.AddMinutes(2)), "the cap is per window, not for good");
    }

    [Fact]
    public void A_refusal_without_a_pid_is_dropped()
    {
        int submitted = 0;
        var feed = new KernelRefusalFeed(_ => submitted++);

        Assert.False(Refuse(feed, 0, "chrome"));
        Assert.Equal(0, submitted);
    }

    // ================================================================ containment

    [Fact]
    public void Monitor_mode_scores_and_records_the_incident_but_contains_nothing()
    {
        const int pid = 880_140;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: true);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Refuse(feed, pid, "chrome");
        Refuse(feed, pid, "edge");

        Assert.True(WaitFor(() => sink.Any(e => e.Level == "QUARANTINE" && e.Pid == pid)), "the verdict was not recorded");
        Assert.True(WaitFor(() => sink.Any("ACTION", "monitor mode, nothing done")), "monitor mode did not report the verdict");
        var snap = Assert.Single(host.ListProfiles(onlyContained: false), p => p.Pid == pid);
        Assert.Equal(80, snap.Score);
        Assert.False(string.IsNullOrEmpty(snap.IncidentId));
        Assert.True(snap.ContainmentSkipped);
        Assert.False(sink.Any(e => e.Level == "ACTION" &&
                (e.Message.StartsWith($"pid {pid} suspend") || e.Message.Contains("skipped firewall block"))),
            "monitor mode attempted containment");
    }

    [Fact]
    public void Enforce_mode_contains_the_same_refusals_so_the_monitor_result_is_not_vacuous()
    {
        const int pid = 880_141;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: false);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Refuse(feed, pid, "chrome");
        Refuse(feed, pid, "edge");

        Assert.True(WaitFor(() => sink.Any("ACTION", $"pid {pid} suspend failed")), "enforce mode did not attempt containment");
        Assert.False(sink.Any("ACTION", "monitor mode"));
    }

    [Fact]
    public void A_single_refusal_never_contains_in_either_mode()
    {
        const int pid = 880_142;
        var sink = new RecordingSink();
        var host = NewHost(sink, monitorOnly: false);
        var feed = new KernelRefusalFeed(host.Submit);

        Start(host, pid);
        Refuse(feed, pid, "chrome");

        Assert.True(WaitFor(() => sink.Any(e => e.Level == "WARN" && e.Pid == pid)));
        Assert.False(sink.Any(e => e.Level == "ACTION" && e.Message.Contains("suspend", StringComparison.OrdinalIgnoreCase)));
    }

    // ================================================================ the wire

    [Fact]
    public void The_signal_carries_the_drive_letter_paths_and_the_operation_and_store()
    {
        var denial = new KernelDenial(KernelOperation.Link, 4242, 3, Chrome, Image);
        var signal = KernelRefusalFeed.ToSignal(denial, "electrum", @"C:\w\x", @"C:\Users\u\Downloads\stealer.exe", T0);

        Assert.Equal(SignalKind.KernelRefusal, signal.Kind);
        Assert.Equal(4242, signal.Pid);
        Assert.Equal("stealer.exe", signal.ProcessName);
        Assert.Equal(@"C:\Users\u\Downloads\stealer.exe", signal.ImagePath);
        Assert.Equal(@"C:\w\x", signal.PrimaryTarget);
        Assert.Equal("link:electrum", signal.Detail);
        Assert.Equal(("link", "electrum"), KernelRefusalDetail.Parse(signal.Detail));
        Assert.Equal(("open", ""), KernelRefusalDetail.Parse(null));
        Assert.Equal(("open", ""), KernelRefusalDetail.Parse("garbage"));
    }

    [Fact]
    public void A_refusal_with_no_image_leaves_the_name_for_the_engine_to_find()
    {
        var signal = KernelRefusalFeed.ToSignal(new KernelDenial(KernelOperation.Open, 4242, 0, Chrome, ""), "chrome", @"C:\w\x", "", T0);

        Assert.Equal("", signal.ProcessName);
        Assert.Equal("", signal.ImagePath);
    }

    [Fact]
    public void A_rule_pack_can_match_a_refusal_by_kind_and_detail()
    {
        Assert.Contains("KernelRefusal", Enum.GetNames<SignalKind>());
        Assert.Equal(SignalKind.KernelRefusal, Enum.Parse<SignalKind>("KernelRefusal"));
    }

    // ================================================================ the composition

    private sealed class CaptureSink : IEventSink
    {
        private readonly List<BruceEvent> _events = new();
        public void Emit(BruceEvent e) { lock (_events) _events.Add(e); }
        public BruceEvent[] Snapshot() { lock (_events) return _events.ToArray(); }
        public void Dispose() { }
    }

    private Composition BuildComposition(CaptureSink sink)
    {
        string config = Path.Combine(_dir, "bruce.config.json");
        File.WriteAllText(config, JsonSerializer.Serialize(new
        {
            detection = new { enableRuleEngine = false },
            intel = new { enabled = false },
            response = new { mode = "monitor", useEncryptedVault = false, isolationAllowlist = Array.Empty<string>() },
            watchlist = new { enabled = false },
            telemetry = new { jsonlPath = Path.Combine(_dir, "incidents.jsonl"), auditPath = Path.Combine(_dir, "audit.log") },
        }));
        return Composition.Build(config, sink);
    }

    [Fact]
    public void The_composition_feeds_every_refusal_to_the_engine_and_logs_it_once()
    {
        // The host is not started, so nothing drains: the queue depth is what crossed the seam.
        var sink = new CaptureSink();
        using var comp = BuildComposition(sink);
        comp.SetKernelStores(IocDatabase.KernelGuards);

        var first = new KernelDenial(KernelOperation.Open, 4242, 0, Chrome, Image);
        for (int i = 0; i < 100; i++) comp.OnKernelDenial(first);
        Assert.Equal(1, comp.Host.StatsSnapshot().SignalsQueued);
        Assert.Single(sink.Snapshot(), e => e.Level == "ACTION" && e.Message.Contains("kernel refused open of"));

        comp.OnKernelDenial(first with { StoreIndex = 1 });
        comp.OnKernelDenial(first with { ProcessId = 4243 });
        comp.OnKernelDenial(first with { StoreIndex = -1 });
        Assert.Equal(4, comp.Host.StatsSnapshot().SignalsQueued);
    }

    [Fact]
    public void The_event_throttle_does_not_starve_the_engine()
    {
        var sink = new CaptureSink();
        using var comp = BuildComposition(sink);
        comp.SetKernelStores(IocDatabase.KernelGuards);

        // 200 distinct paths: the ACTION throttle admits 60 a minute, the engine must see each
        // distinct process and store once, and here that is one pid and one store.
        for (int i = 0; i < 200; i++)
            comp.OnKernelDenial(new KernelDenial(KernelOperation.Open, 4242, 0, Chrome + i, Image));
        for (int pid = 5000; pid < 5100; pid++)
            comp.OnKernelDenial(new KernelDenial(KernelOperation.Open, pid, 0, Chrome, Image));

        Assert.Equal(1 + 100, comp.Host.StatsSnapshot().SignalsQueued);
        Assert.Equal(60, sink.Snapshot().Count(e => e.Level == "ACTION" && e.Message.Contains("kernel refused")));
    }

    [Fact]
    public void A_store_index_the_policy_no_longer_has_is_reported_as_unresolved()
    {
        var sink = new CaptureSink();
        using var comp = BuildComposition(sink);
        comp.SetKernelStores(IocDatabase.KernelGuards.Take(2).ToList());

        comp.OnKernelDenial(new KernelDenial(KernelOperation.Open, 4242, 5, Chrome, Image));

        Assert.Equal(1, comp.Host.StatsSnapshot().SignalsQueued);
        Assert.Contains(sink.Snapshot(), e => e.Message.Contains("a name it could not resolve"));
    }
}
