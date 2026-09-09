using System.Net;
using BruceEDR.Api;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Hosting;
using BruceEDR.Memory;
using BruceEDR.Response;
using BruceEDR.Security;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Regression tests for the defects found by two external reviews of 3.0.0. The critical
/// one -- a watchlist Quarantine that never froze anything -- was invisible to the suite
/// because every watchlist test stopped at the engine and every host test started
/// without a watchlist. The first tests here cross that seam on purpose.
/// </summary>
public sealed class ReviewRegressionTests : IDisposable
{
    private readonly List<BruceHost> _hosts = new();
    private readonly List<string> _tempDirs = new();

    public void Dispose()
    {
        foreach (var h in _hosts) { try { h.Dispose(); } catch { } }
        foreach (var d in _tempDirs) { try { Directory.Delete(d, recursive: true); } catch { } }
    }

    private string TempDir()
    {
        string d = Path.Combine(Path.GetTempPath(), "bruce-review-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        _tempDirs.Add(d);
        return d;
    }

    /// <summary>Captures everything the logger emits, so a test can assert what the host DID.</summary>
    private sealed class RecordingSink : IEventSink
    {
        public readonly List<BruceEvent> Events = new();
        public void Emit(BruceEvent e) { lock (Events) Events.Add(e); }
        public void Dispose() { }
        public bool Any(string level, string fragment)
        {
            lock (Events)
                return Events.Any(e => e.Level == level && e.Message.Contains(fragment, StringComparison.OrdinalIgnoreCase));
        }
    }

    private sealed class NullScanner : IMemoryScanner
    {
        public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();
    }

    private static WatchlistEntryConfig Entry(string value, string match = "name", string action = "quarantine")
        => new() { Value = value, Match = match, Action = action };

    private static Signal Sig(int pid, string name, SignalKind kind = SignalKind.ProcessStart,
        string image = "", int atSeconds = 0, string cmd = "")
        => new()
        {
            Kind = kind, Pid = pid, ProcessName = name, ImagePath = image, CommandLine = cmd,
            TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(atSeconds),
        };

    private BruceHost NewHost(RecordingSink sink, Watchlist watchlist, bool trusted)
    {
        var log = new Logger(sink);
        var verifier = new AuthenticodeVerifier(new AllowlistConfig());
        var response = new ResponseManager(log, verifier);
        var engine = new DetectionEngine(
            new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70, TrustDiscount = 30 },
            _ => trusted,
            new EngineDependencies { Watchlist = watchlist, ResolveProcessName = null });
        var host = new BruceHost(engine, response, new NullScanner(), log, new BruceHostOptions
        {
            StartMonitors = false,
            EnableExtendedMonitors = false,
        });
        _hosts.Add(host);
        host.Start();
        return host;
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

    // ================================================================ the seam

    [Fact]
    public void Watchlist_quarantine_on_a_score_zero_process_reaches_the_containment_primitives()
    {
        // Before: score 0 matched no playbook rule, the host logged "selected no containment
        // action" and returned. The pid here does not exist, so the suspend itself fails --
        // what this proves is that the host ATTEMPTED it, which it never used to.
        var sink = new RecordingSink();
        var host = NewHost(sink, Watchlist.Compile(new[] { Entry("evil.exe") }), trusted: false);

        host.Submit(Sig(777_777, "evil.exe", image: @"C:\t\evil.exe"));

        Assert.True(WaitFor(() => sink.Any("ACTION", "Suspend")), "no containment action was selected for a watchlist hit");
        Assert.True(WaitFor(() => sink.Any("ACTION", "suspend failed")), "suspend was never attempted");
        Assert.False(sink.Any("ACTION", "selected no containment action"));
        Assert.True(sink.Any("ACTION", "watchlist:"));
    }

    [Fact]
    public void Watchlist_quarantine_beats_a_trusted_signature_all_the_way_to_the_host()
    {
        // The playbook's containment rules all require an UNTRUSTED process. A signed
        // binary the operator named by hand therefore fell through to observe -> Log.
        var sink = new RecordingSink();
        var host = NewHost(sink, Watchlist.Compile(new[] { Entry("teamviewer.exe") }), trusted: true);

        host.Submit(Sig(777_778, "teamviewer.exe", image: @"C:\t\teamviewer.exe"));

        Assert.True(WaitFor(() => sink.Any("ACTION", "Suspend")), "a signed watchlisted binary was not sent for containment");
        Assert.False(sink.Any("ACTION", "selected no containment action"));
    }

    [Fact]
    public void Snapshot_carries_the_forced_containment_across_the_seam()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(new[] { Entry("m.exe") }), ResolveProcessName = null });

        var r = Assert.Single(engine.Ingest(Sig(1, "m.exe")));

        Assert.True(r.Snapshot.ContainmentRequired);
        Assert.NotEqual("", r.Snapshot.ForcedBy);
        Assert.Equal(0, r.Snapshot.Score);
    }

    // ================================================================ pid lifecycle

    [Fact]
    public void A_stop_older_than_the_current_tenant_does_not_mark_it_exited()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { ResolveProcessName = null });

        engine.Ingest(Sig(5, "a.exe", atSeconds: 10));
        engine.Ingest(Sig(5, "a.exe", SignalKind.ProcessStop, atSeconds: 5));   // the previous occupant's stop, late

        // still live: a later signal must still be scored against THIS profile
        engine.Ingest(Sig(5, "", SignalKind.NetworkConnect, atSeconds: 11));
        Assert.NotNull(engine.SnapshotOne(5));

        engine.Ingest(Sig(5, "a.exe", SignalKind.ProcessStop, atSeconds: 12));  // its own stop
        engine.Ingest(Sig(5, "", SignalKind.NetworkConnect, atSeconds: 13));
        // an exited row is replaced, so whatever answers now is a fresh, clean profile
        var after = engine.SnapshotOne(5);
        Assert.True(after is null || (!after.Contained && after.Score == 0));
    }

    [Fact]
    public void A_recycled_pid_does_not_inherit_containment_when_the_start_was_dropped()
    {
        // Watchlist-contain evil.exe, let it exit, then see the pid emit with no
        // ProcessStart (the fail-open case). The old Contained profile must not answer.
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { Watchlist = Watchlist.Compile(new[] { Entry("evil.exe") }), ResolveProcessName = null });

        Assert.Single(engine.Ingest(Sig(9, "evil.exe", atSeconds: 1)));
        Assert.True(engine.SnapshotOne(9)!.Contained);

        engine.Ingest(Sig(9, "evil.exe", SignalKind.ProcessStop, atSeconds: 2));
        engine.Ingest(Sig(9, "", SignalKind.FileCreate, atSeconds: 3));      // new tenant, start lost

        var snap = engine.SnapshotOne(9);
        Assert.NotNull(snap);
        Assert.False(snap!.Contained);
        Assert.False(snap.ContainmentRequired);
    }

    [Fact]
    public void An_async_result_claimed_under_a_previous_tenant_is_discarded()
    {
        var engine = new DetectionEngine(new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70 }, _ => false,
            new EngineDependencies { ResolveProcessName = null });

        // Enough builtin score to make the memory scan claimable.
        engine.Ingest(Sig(4, "powershell.exe", cmd: "-enc AAAA -nop -w hidden", atSeconds: 1));
        Assert.True(engine.TryClaimMemoryScan(4, out long gen), "scan should be claimable at this score");

        engine.Ingest(Sig(4, "notepad.exe", atSeconds: 2));                  // pid recycled
        int before = engine.SnapshotOne(4)!.Score;

        var results = engine.ApplyMemoryHits(4, new[] { "mimikatz" }, gen);

        Assert.Empty(results);
        Assert.Equal(before, engine.SnapshotOne(4)!.Score);
    }

    // ================================================================ image path + target name

    [Fact]
    public void The_main_image_load_promotes_a_bare_name_to_a_full_path()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { ResolveProcessName = null });

        engine.Ingest(Sig(7, "tool.exe", image: "tool.exe"));                 // what kernel ProcessStart carries
        engine.Ingest(new Signal { Kind = SignalKind.ImageLoad, Pid = 7, FilePath = @"C:\bin\other.dll" });
        Assert.Equal("tool.exe", engine.SnapshotOne(7)!.ImagePath);          // a DLL must not rewrite it

        engine.Ingest(new Signal { Kind = SignalKind.ImageLoad, Pid = 7, FilePath = @"C:\bin\tool.exe" });
        Assert.Equal(@"C:\bin\tool.exe", engine.SnapshotOne(7)!.ImagePath);
    }

    [Fact]
    public void A_path_watchlist_entry_fires_once_the_real_path_is_known()
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies
            {
                Watchlist = Watchlist.Compile(new[] { Entry(@"\temp\", match: "path") }),
                ResolveProcessName = null,
            });

        Assert.Empty(engine.Ingest(Sig(8, "x.exe", image: "x.exe")));
        var r = engine.Ingest(new Signal { Kind = SignalKind.ImageLoad, Pid = 8, FilePath = @"C:\Users\a\AppData\Local\Temp\x.exe" });
        Assert.Contains(r, v => v.Verdict == Verdict.Quarantine);
    }

    [Theory]
    [InlineData(0x0010u)]        // PROCESS_VM_READ
    [InlineData(0x02000000u)]    // MAXIMUM_ALLOWED -- the documented way to open LSASS without naming VM_READ
    [InlineData(0x80000000u)]    // GENERIC_READ
    [InlineData(0x10000000u)]    // GENERIC_ALL
    public void Opening_lsass_is_recognised_by_name_and_by_evasive_masks(uint mask)
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { ResolveProcessName = pid => pid == 640 ? "lsass" : null });

        engine.Ingest(Sig(3, "dumper.exe"));
        engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessAccess, Pid = 3, TargetPid = 640, DesiredAccess = mask,
            Detail = "open-process:" + (mask == 0x0010u ? "PROCESS_VM_READ" : "0x" + mask.ToString("X")),
        });

        var snap = engine.SnapshotOne(3)!;
        Assert.Contains(snap.Reasons, r => r.Contains("LSASS", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("T1003.001", snap.Techniques);
    }

    [Fact]
    public void Target_name_is_written_into_detail_for_the_json_rules()
    {
        // The shipped lsass rules regex the target name out of `detail`; the monitor
        // never put it there. This rule can only fire if the engine enriched the detail
        // with the resolved target name before evaluating rules.
        var rules = new RuleEngine(RuleEngine.ParseJson("""
            [{"id":"probe","title":"probe","severity":"low","score":1,"kinds":["ProcessAccess"],
              "detection":[{"all":[{"field":"detail","op":"regex","value":"(?i)open-process:lsass\\.exe:"}]}]}]
            """, "probe"));
        var engine = new DetectionEngine(new EngineOptions(), _ => false,
            new EngineDependencies { ResolveProcessName = pid => "lsass", Rules = rules });

        engine.Ingest(Sig(3, "dumper.exe"));
        engine.Ingest(new Signal { Kind = SignalKind.ProcessAccess, Pid = 3, TargetPid = 640, DesiredAccess = 0x10, Detail = "open-process:PROCESS_VM_READ" });

        Assert.Contains(engine.SnapshotOne(3)!.ReasonLog, r => r.RuleId == "probe");
    }

    // ================================================================ scoring semantics

    [Fact]
    public void Negative_scores_bank_a_persistent_allowance()
    {
        var p = new ThreatProfile(1);
        p.Add(10, "a");
        p.Add(-50, "allowlist");
        Assert.Equal(0, p.Score);
        Assert.Equal(40, p.Allowance);

        p.Add(30, "b");
        Assert.Equal(0, p.Score);
        Assert.Equal(10, p.Allowance);

        p.Add(20, "c");
        Assert.Equal(10, p.Score);
        Assert.Equal(0, p.Allowance);
    }

    [Fact]
    public void An_unattributed_archive_charges_one_process_not_every_flagged_one()
    {
        var engine = new DetectionEngine(new EngineOptions { WarnThreshold = 40, QuarantineThreshold = 70 }, _ => false,
            new EngineDependencies { ResolveProcessName = null });

        engine.Ingest(Sig(11, "powershell.exe", cmd: "-enc AAAA", atSeconds: 1));
        engine.Ingest(Sig(12, "powershell.exe", cmd: "-enc BBBB", atSeconds: 2));
        int s11 = engine.SnapshotOne(11)!.Score, s12 = engine.SnapshotOne(12)!.Score;

        engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 0, FilePath = @"C:\Users\a\AppData\Local\Temp\loot.zip",
                                   TimestampUtc = new DateTime(2026, 1, 1, 0, 0, 3, DateTimeKind.Utc) });

        int charged = (engine.SnapshotOne(11)!.Score > s11 ? 1 : 0) + (engine.SnapshotOne(12)!.Score > s12 ? 1 : 0);
        Assert.Equal(1, charged);
    }

    // ================================================================ playbook

    [Fact]
    public void A_required_parent_technique_is_satisfied_by_its_sub_technique()
    {
        var snap = new ProfileSnapshot
        {
            Pid = 1, ProcessName = "mimikatz.exe", ImagePath = "", Score = 95, Trusted = false, Contained = false,
            SuspendedByAnalyst = false, Terminated = false, Reasons = Array.Empty<string>(),
            StagedArchives = Array.Empty<string>(), FirstSeenUtc = DateTime.UtcNow, LastUpdatedUtc = DateTime.UtcNow,
            Techniques = new[] { "T1003.001" },
        };

        var d = Playbook.Default().Decide(snap);
        Assert.Equal("credential-theft-critical", d.MatchedRule);
        Assert.Contains(PlaybookAction.Kill, d.Actions);
    }

    // ================================================================ watchlist breadth + protection

    [Theory]
    [InlineData("*exe", "name")]
    [InlineData("*", "name")]
    [InlineData("windows", "path")]
    [InlineData("c:", "path")]
    [InlineData(@"\", "path")]
    [InlineData("-e", "cmdline")]
    [InlineData("cmd", "cmdline")]
    public void Patterns_that_match_most_of_the_machine_are_refused(string value, string match)
    {
        var errors = new List<string>();
        var list = Watchlist.Compile(new[] { Entry(value, match) }, errors.Add);
        Assert.Equal(0, list.Count);
        Assert.Contains(errors, e => e.Contains("too broad"));
    }

    [Theory]
    [InlineData("mimikatz", "name")]
    [InlineData("psexec*", "name")]
    [InlineData(@"\appdata\local\temp\", "path")]
    [InlineData("evil.dll", "path")]
    [InlineData("-nop", "cmdline")]
    [InlineData("-ep", "cmdline")]
    [InlineData("frombase64string", "cmdline")]
    public void Specific_patterns_still_compile(string value, string match)
        => Assert.Equal(1, Watchlist.Compile(new[] { Entry(value, match) }).Count);

    [Fact]
    public void Switch_style_command_line_entries_match_on_token_boundaries()
    {
        var list = Watchlist.Compile(new[] { Entry("-ep", match: "cmdline", action: "warn") });
        Assert.NotNull(list.Match("powershell.exe", "", "powershell.exe -ep bypass", null));
        Assert.Null(list.Match("chrome.exe", "", "chrome.exe --ep-foo=1", null));
    }

    [Theory]
    [InlineData("explorer.exe")]
    [InlineData("MsMpEng.exe")]
    [InlineData("SecurityHealthService.exe")]
    [InlineData("RuntimeBroker.exe")]
    public void The_shell_and_the_security_stack_are_never_contained(string name)
        => Assert.True(Watchlist.IsProtected(name));

    // ================================================================ isolation, addresses, urls

    [Theory]
    [InlineData("0.0.0.0-255.255.255.255")]
    [InlineData("10.0.0.50-10.0.0.1")]
    public void Whole_space_and_inverted_ranges_cannot_isolate(string range)
        => Assert.False(NetworkIsolation.IsValidRemoteAddress(range));

    [Theory]
    [InlineData("169.254.169.254", false, false)]   // cloud metadata via a rebinding name
    [InlineData("10.0.0.5", false, false)]
    [InlineData("fd00::1", false, false)]
    [InlineData("127.0.0.1", true, true)]           // asked for localhost, got loopback: fine
    [InlineData("127.0.0.1", false, false)]         // asked for a public name, got loopback: rebinding
    [InlineData("93.184.216.34", false, true)]
    public void Resolved_addresses_are_policed_after_dns(string ip, bool hostIsLoopback, bool expected)
    {
        // No address literals in this allowlist: the explicit-literal case is tested below.
        var policy = new ApiSafetyPolicy { AllowedHosts = new[] { "api.example.com", "localhost" } };
        Assert.Equal(expected, policy.IsAddressPermitted(IPAddress.Parse(ip), hostIsLoopback));
    }

    [Fact]
    public void An_explicitly_allowlisted_internal_address_is_permitted()
    {
        var policy = new ApiSafetyPolicy { AllowedHosts = new[] { "10.0.0.5" } };
        Assert.True(policy.IsAddressPermitted(IPAddress.Parse("10.0.0.5"), requestHostIsLoopback: false));
        Assert.False(policy.IsAddressPermitted(IPAddress.Parse("10.0.0.6"), requestHostIsLoopback: false));
    }

    [Fact]
    public void File_bodies_are_confined_to_the_configured_root()
    {
        string root = TempDir();
        string inside = Path.Combine(root, "payload.bin");
        File.WriteAllBytes(inside, new byte[] { 1, 2, 3 });
        string outside = Path.Combine(TempDir(), "secret.txt");
        File.WriteAllText(outside, "x");

        Assert.Null(ApiClient.ValidateBodyFilePath(inside, root));
        Assert.Null(ApiClient.ValidateBodyFilePath("payload.bin", root));                 // relative resolves under root
        Assert.NotNull(ApiClient.ValidateBodyFilePath(outside, root));
        Assert.NotNull(ApiClient.ValidateBodyFilePath(@"\\attacker\share\x", root));
        Assert.NotNull(ApiClient.ValidateBodyFilePath(Path.Combine(root, "..", "up.txt"), root));
        Assert.Contains("disabled", ApiClient.ValidateBodyFilePath(inside, "") ?? "");
    }

    [Fact]
    public void A_file_body_with_no_root_configured_is_refused_before_the_path_is_touched()
    {
        var request = new ApiRequest { Body = new ApiBody { Kind = ApiBodyKind.File, FilePath = @"\\attacker\share\x" } };
        Assert.False(ApiClient.TryBuildBody(request, "b", out _, out _, out string error));
        Assert.Contains("fileBodyRoot", error);
    }

    // ================================================================ files, keys, ids

    [Fact]
    public void Protected_files_are_created_with_inheritance_disabled()
    {
        string path = Path.Combine(TempDir(), "k.key");
        SecretFiles.CreateProtected(path, new byte[] { 1 });
        Assert.True(SecretFiles.IsProtected(path));
    }

    [Theory]
    [InlineData("20260101120000-1-abcd", true)]
    [InlineData(@"..\..\x", false)]
    [InlineData("a/b", false)]
    [InlineData("", false)]
    public void Vault_ids_that_could_leave_the_blob_directory_are_refused(string id, bool ok)
        => Assert.Equal(ok, QuarantineVault.IsSafeId(id));

    [Fact]
    public void Missing_audit_anchor_over_a_populated_log_is_an_integrity_failure_until_acknowledged()
    {
        string dir = TempDir();
        string log = Path.Combine(dir, "audit.log");

        using (var first = new AuditLogSink(log))
        {
            first.Emit(new BruceEvent { Level = "INFO", Message = "one" });
            first.Emit(new BruceEvent { Level = "INFO", Message = "two" });
        }
        Assert.True(File.Exists(log + ".anchor"));
        File.Delete(log + ".anchor");                 // the attack: hide a truncation by removing its evidence

        using var second = new AuditLogSink(log);
        Assert.NotNull(second.IntegrityWarning);
        Assert.True(second.AnchorLocked);

        second.Emit(new BruceEvent { Level = "INFO", Message = "three" });
        Assert.False(File.Exists(log + ".anchor"), "a replacement anchor was minted without acknowledgement");

        second.AcknowledgeIntegrityWarning();
        Assert.True(File.Exists(log + ".anchor"));
        Assert.False(second.AnchorLocked);
    }

    // ================================================================ config + install

    [Fact]
    public void A_malformed_config_refuses_to_start_instead_of_disarming()
    {
        string path = Path.Combine(TempDir(), "bruce.config.json");
        File.WriteAllText(path, "{ \"detection\": { \"warnThreshold\": ");   // truncated mid-save

        Assert.Throws<InvalidOperationException>(() => ConfigLoader.Load(path));
        Assert.NotNull(ConfigLoader.Load(path, strict: false));               // the watchdog's mode
        Assert.NotNull(ConfigLoader.Load(Path.Combine(TempDir(), "absent.json")));   // missing = first run
    }

    [Fact]
    public void A_service_is_only_installed_from_a_location_users_cannot_write()
    {
        string pf = Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
        Assert.True(ServiceControl.IsProtectedInstallLocation(Path.Combine(pf, "BruceEDR", "BruceEDR.exe"), out _));
        Assert.False(ServiceControl.IsProtectedInstallLocation(Path.Combine(Path.GetTempPath(), "BruceEDR.exe"), out string why));
        Assert.Contains("SYSTEM", why);
    }

    [Fact]
    public void Url_redaction_masks_a_bare_token_in_userinfo()
        => Assert.DoesNotContain("s3cret", ReportsRedaction.Redact("https://s3cret@host/path?x=1"));
}

internal static class ReportsRedaction
{
    public static string Redact(string url) => ApiReports.RedactUrl(url);
}
