using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Driver;
using BruceEDR.Memory;
using BruceEDR.Monitoring;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The false positives that kept enforce mode from being usable on a clean Windows machine, taken from
/// two freshly installed lab VMs (Windows 10 21H2 LTSC and Windows 11 22H2, nothing on them but VMware
/// Tools and the agent). Each test feeds the shape of the events the VMs produced through a real
/// <see cref="DetectionEngine"/> with the shipped rule packs, and pairs it with the attack the rule
/// exists for, which must still reach its score: the exemption is for the system's own behaviour, not
/// for the mask, the name or the key.
/// </summary>
public sealed class EnforceFalsePositiveTests
{
    private const uint ProcessVmRead = 0x0010;
    private const uint QueryRead = 0x0410;                // QUERY_INFORMATION + VM_READ: WmiPrvSE, mimikatz
    private const uint GenericRead = 0x80000000;
    private const uint MaximumAllowed = 0x02000000;
    private const uint AllAccess = 0x001FFFFF;
    private const int LsassPid = 640;
    private static readonly DateTime T0 = new(2026, 11, 14, 14, 0, 0, DateTimeKind.Utc);

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
        throw new InvalidOperationException("the shipped rule packs were not found");
    }

    private sealed class Box
    {
        public readonly DetectionEngine Engine;
        public readonly List<DetectionResult> Verdicts = new();
        private int _tick;

        public Box(Dictionary<int, string>? platform = null, int self = 0, bool rules = true)
        {
            Engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
            {
                Rules = rules ? ShippedRules() : null,
                ResolveProcessName = pid => pid == LsassPid ? "lsass" : "notepad",
                IdentifyPlatform = platform is null ? null : pid => platform.GetValueOrDefault(pid),
                SelfPid = self,
            });
        }

        public void Feed(Signal s) => Verdicts.AddRange(Engine.Ingest(s with { TimestampUtc = T0.AddSeconds(_tick++) }));

        public int Score(int pid) => Engine.SnapshotOne(pid)?.Score ?? 0;

        public bool Quarantined(int pid) => Verdicts.Any(v => v.Verdict == Verdict.Quarantine && v.Snapshot.Pid == pid);

        public bool Flagged(int pid) => Verdicts.Any(v => v.Snapshot.Pid == pid);

        public string Why(int pid) => string.Join(" | ", Engine.SnapshotOne(pid)?.Reasons ?? Array.Empty<string>());

        public void Open(int pid, string name, int target, uint mask) => Feed(new Signal
        {
            Kind = SignalKind.ProcessAccess, Pid = pid, ProcessName = name, TargetPid = target, DesiredAccess = mask,
            Detail = "open-process:" + MonitorSupport.DescribeAccessMask(mask),
        });

        public void Registry(int pid, string name, string key, string? value, string action) => Feed(new Signal
        {
            Kind = SignalKind.RegistryWrite, Pid = pid, ProcessName = name, RegistryKey = key,
            RegistryValue = value, Detail = action,
        });

        public void File(int pid, string path, string name = "") => Feed(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = pid, FilePath = path, ProcessName = name,
        });

        public void Start(int pid, string name, string image) => Feed(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = pid, ProcessName = name, ImagePath = image,
        });
    }

    // ===================================================== Windows opening processes (csrss, svchost, ...)

    [Theory]
    [InlineData("csrss", "csrss.exe", AllAccess)]               // every new process, full rights
    [InlineData("csrss", "csrss.exe", MaximumAllowed)]
    [InlineData("svchost", "svchost.exe", 0x1478u)]
    [InlineData("svchost", "svchost.exe", 0x0040u)]             // PROCESS_DUP_HANDLE
    [InlineData("lsass", "lsass.exe", 0x0478u)]
    [InlineData("MsMpEng", "msmpeng.exe", 0x0418u)]             // VM_OPERATION
    [InlineData("conhost", "conhost.exe", MaximumAllowed)]      // its console clients
    [InlineData("Widgets", "widgets.exe", 0x0640u)]
    [InlineData("msedgewebview2", "msedgewebview2.exe", 0x1F0FFFu)]
    [InlineData("explorer", "explorer.exe", 0x0040u)]
    public void A_verified_Windows_component_opening_processes_is_not_an_injector(string reported, string platform, uint mask)
    {
        var box = new Box(new Dictionary<int, string> { [900] = platform });
        for (int target = 1000; target < 1006; target++) box.Open(900, reported, target, mask);

        Assert.Equal(0, box.Score(900));
        Assert.False(box.Flagged(900));
    }

    [Theory]
    [InlineData("csrss", AllAccess)]
    [InlineData("svchost", 0x1478u)]
    [InlineData("MsMpEng", 0x0418u)]
    [InlineData("conhost", MaximumAllowed)]
    public void The_same_name_without_the_verified_image_is_still_an_injector(string reported, uint mask)
    {
        // A copy under another folder (or any process that merely calls itself this) identifies as nothing.
        var box = new Box(new Dictionary<int, string>());
        for (int target = 1000; target < 1004; target++) box.Open(900, reported, target, mask);

        Assert.True(box.Score(900) >= 75, box.Why(900));
        Assert.True(box.Quarantined(900));
    }

    [Fact]
    public void The_System_process_asking_for_maximum_rights_is_not_scored()
    {
        var box = new Box(new Dictionary<int, string> { [4] = "system" });
        foreach (int target in new[] { 4620, 408, 3124, 2392 }) box.Open(4, "System", target, MaximumAllowed);
        Assert.Equal(0, box.Score(4));
    }

    [Fact]
    public void A_non_Windows_process_with_write_and_thread_rights_over_three_processes_still_quarantines()
    {
        var box = new Box(new Dictionary<int, string> { [900] = "svchost.exe" });   // someone else's pid is a component
        box.Start(777, "inject.exe", @"C:\Users\u\AppData\Local\Temp\inject.exe");
        foreach (int target in new[] { 1000, 1001, 1002 }) box.Open(777, "inject.exe", target, 0x002A);   // VM_WRITE | CREATE_THREAD-class

        Assert.True(box.Quarantined(777), box.Why(777));
    }

    [Fact]
    public void Identification_is_per_process_so_a_component_does_not_clear_its_pid_neighbour()
    {
        var box = new Box(new Dictionary<int, string> { [900] = "svchost.exe" });
        for (int target = 1000; target < 1004; target++)
        {
            box.Open(900, "svchost", target, 0x0020);
            box.Open(901, "svchost", target, 0x0020);
        }
        Assert.Equal(0, box.Score(900));
        Assert.True(box.Quarantined(901));
    }

    [Fact]
    public void A_pid_that_has_exited_is_never_identified_because_its_number_may_be_someone_elses()
    {
        var box = new Box(new Dictionary<int, string> { [900] = "svchost.exe" });
        box.Start(900, "svchost.exe", @"C:\Windows\System32\svchost.exe");
        box.Feed(new Signal { Kind = SignalKind.ProcessStop, Pid = 900 });
        // Late telemetry stamped before the stop belongs to the exited process; the lookup by pid would
        // describe whatever runs under that number now.
        box.Engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessAccess, Pid = 900, TargetPid = 1000, DesiredAccess = 0x20,
            TimestampUtc = T0.AddSeconds(-1),
        });
        Assert.Equal(25, box.Score(900));
    }

    // ===================================================== LSASS: WmiPrvSE and the Defender engine

    [Theory]
    [InlineData("WmiPrvSE", "wmiprvse.exe", QueryRead)]
    [InlineData("WmiPrvSE", "wmiprvse.exe", ProcessVmRead)]
    [InlineData("NisSrv", "nissrv.exe", GenericRead)]
    [InlineData("MsMpEng", "msmpeng.exe", QueryRead)]
    public void The_genuine_WMI_host_and_Defender_reading_LSASS_is_not_a_credential_dump(string reported, string platform, uint mask)
    {
        var box = new Box(new Dictionary<int, string> { [900] = platform });
        box.Open(900, reported, LsassPid, mask);

        Assert.Equal(0, box.Score(900));
        Assert.False(box.Flagged(900));
    }

    [Theory]
    [InlineData(QueryRead)]       // mimikatz sekurlsa
    [InlineData(0x1410u)]
    [InlineData(0x1010u)]
    [InlineData(GenericRead)]
    public void A_dumper_reading_LSASS_with_the_same_mask_still_quarantines(uint mask)
    {
        // Even carrying the WMI host's name: it is not the genuine image, so it identifies as nothing.
        foreach (string name in new[] { "dumper", "WmiPrvSE" })
        {
            var box = new Box(new Dictionary<int, string>());
            box.Open(900, name, LsassPid, mask);
            Assert.True(box.Score(900) >= 70, $"{name} {mask:X}: " + box.Why(900));
            Assert.True(box.Quarantined(900));
        }
    }

    [Fact]
    public void The_genuine_WMI_host_asking_LSASS_for_rights_that_change_it_is_still_scored()
    {
        var box = new Box(new Dictionary<int, string> { [900] = "wmiprvse.exe" });
        box.Open(900, "WmiPrvSE", LsassPid, 0x0020);   // PROCESS_VM_WRITE
        Assert.True(box.Quarantined(900), box.Why(900));
    }

    [Theory]
    [InlineData(0x0020u)]            // PROCESS_VM_WRITE
    [InlineData(0x0002u)]            // PROCESS_CREATE_THREAD
    [InlineData(MaximumAllowed)]     // the documented way to open LSASS without naming a right
    [InlineData(AllAccess)]
    public void The_builtin_rule_scores_a_write_or_wide_mask_on_LSASS_from_the_genuine_WMI_host(uint mask)
    {
        var box = new Box(new Dictionary<int, string> { [900] = "wmiprvse.exe" }, rules: false);
        box.Open(900, "WmiPrvSE", LsassPid, mask);
        Assert.Equal(60, box.Score(900));
    }

    [Fact]
    public void A_component_that_does_not_read_LSASS_for_a_living_is_not_excused_for_reading_it()
    {
        // svchost has no business reading LSASS memory: the exemption is a short list, not "any Windows binary".
        var box = new Box(new Dictionary<int, string> { [900] = "svchost.exe" });
        box.Open(900, "svchost", LsassPid, QueryRead);
        Assert.True(box.Score(900) >= 60, box.Why(900));
    }

    [Fact]
    public void Every_platform_name_the_lsass_rule_excludes_is_one_the_table_lets_read_LSASS()
    {
        var rule = ShippedRuleSet().Rules.Single(r => r.Id == "lsass-handle-with-vm-read");
        var listed = rule.Detection.SelectMany(c => c.None)
            .Where(c => c.Field.Equals("platform", StringComparison.OrdinalIgnoreCase))
            .SelectMany(c => c.Values).ToArray();

        Assert.NotEmpty(listed);
        Assert.All(listed, n => Assert.True(PlatformImages.ReadsLsass(n), n + " is excluded by the rule but is not a component that reads LSASS"));
    }

    private static RuleSet ShippedRuleSet()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "rules", "detection");
            if (Directory.Exists(probe)) return RuleEngine.LoadDirectory(probe);
        }
        throw new InvalidOperationException("the shipped rule packs were not found");
    }

    // ===================================================== names the way ETW reports them

    [Fact]
    public void A_process_name_reported_without_its_extension_still_meets_the_name_exclusions()
    {
        // The registry monitor reports "svchost"; the Tasks rule excludes "svchost.exe". The last signal to
        // arrive used to decide whether the exclusion held.
        const string tasks = @"C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate\Scheduled Start";
        var box = new Box();
        box.Registry(1144, "svchost", @"HKLM\SYSTEM\CurrentControlSet\Services\wuauserv", null, "create-key");
        box.File(1144, tasks);
        Assert.Equal(0, box.Score(1144));

        box.File(1145, tasks, "evil");
        Assert.True(box.Score(1145) >= 55, box.Why(1145));
    }

    [Theory]
    [InlineData("sihost", "sihost.exe")]
    [InlineData("WmiPrvSE.exe", "WmiPrvSE.exe")]
    [InlineData("Memory Compression", "Memory Compression.exe")]
    [InlineData("", "")]
    public void Process_names_take_the_file_name_form(string reported, string expected)
        => Assert.Equal(expected, DetectionEngine.NormaliseProcessName(reported));

    [Fact]
    public void The_browser_owner_exclusion_holds_when_the_name_came_from_the_registry_monitor()
    {
        var box = new Box(rules: false);
        box.Registry(900, "msedge", @"HKCU\Software\Microsoft\Edge\Foo", null, "set-value");
        box.File(900, @"C:\Users\u\AppData\Local\Microsoft\Edge\User Data\Default\Login Data");
        Assert.Equal(0, box.Score(900));
    }

    // ===================================================== Run keys (sihost, driver installer)

    [Theory]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "create-key")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification", "create-key")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification", "set-value")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "create-key")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "delete-value")]
    public void Opening_or_deleting_an_autostart_key_and_keys_that_only_start_with_Run_are_not_persistence(string key, string action)
    {
        var box = new Box();
        box.Registry(3076, "sihost", key, null, action);
        Assert.Equal(0, box.Score(3076));
    }

    [Theory]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "Updater", "set-value")]
    [InlineData(@"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\x", "x", "set-value")]
    [InlineData(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater", "free-text from a trace")]
    public void A_value_written_into_a_Run_key_still_scores(string key, string value, string action)
    {
        var box = new Box();
        box.Registry(900, "dropper", key, value, action);
        Assert.True(box.Score(900) >= 65, box.Why(900));   // builtin 40 + rule pack 25
    }

    [Fact]
    public void A_script_host_writing_a_Run_value_still_reaches_the_lolbin_rule()
    {
        var box = new Box();
        box.Registry(900, "powershell", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "Updater", "set-value");
        Assert.True(box.Score(900) >= 115, box.Why(900));   // 40 + 25 + 50
        Assert.True(box.Quarantined(900));
    }

    // ===================================================== Startup folder and Tasks folder opens

    [Fact]
    public void Opening_the_Startup_folder_itself_is_not_a_drop_but_a_file_in_it_is()
    {
        var box = new Box();
        box.File(900, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\", "sihost");
        Assert.Equal(0, box.Score(900));

        box.File(901, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk", "dropper");
        Assert.True(box.Score(901) >= 45, box.Why(901));
        box.File(902, @"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.vbs", "dropper");
        Assert.True(box.Score(902) >= 45, box.Why(902));
    }

    [Fact]
    public void The_genuine_search_indexer_reading_the_Tasks_folder_is_not_a_task_drop_a_renamed_copy_is()
    {
        const string tasks = @"C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate";
        var box = new Box(new Dictionary<int, string> { [900] = "searchindexer.exe" });
        box.File(900, tasks, "SearchIndexer");
        box.File(900, @"C:\Windows\System32\Tasks\Microsoft\Windows\", "SearchIndexer");
        Assert.Equal(0, box.Score(900));

        box.File(901, tasks, "SearchIndexer");   // the name alone, from a folder a user could write
        Assert.True(box.Score(901) >= 55, box.Why(901));
    }

    // ===================================================== WebView2 (Widgets, Search, Start on Windows 11)

    private const string WebViewStore =
        @"C:\Users\lab\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView\Default\Network\Cookies";
    private const string WebViewLocalState =
        @"C:\Users\lab\AppData\Local\Packages\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy\LocalState\EBWebView\Local State";

    [Fact]
    public void The_genuine_WebView2_runtime_reading_its_hosts_store_is_not_a_cookie_theft()
    {
        var box = new Box(new Dictionary<int, string> { [900] = "msedgewebview2.exe" });
        box.File(900, WebViewStore, "msedgewebview2");
        box.File(900, WebViewLocalState, "msedgewebview2");
        Assert.Equal(0, box.Score(900));
    }

    [Fact]
    public void A_program_called_msedgewebview2_reading_that_store_still_scores()
    {
        var box = new Box(new Dictionary<int, string>());
        box.File(900, WebViewStore, "msedgewebview2");
        box.File(900, WebViewLocalState, "msedgewebview2");
        Assert.True(box.Score(900) >= 75, box.Why(900));   // cookie rule 40 + Local State 35
    }

    [Fact]
    public void The_genuine_WebView2_runtime_reading_another_browsers_store_still_scores()
    {
        var box = new Box(new Dictionary<int, string> { [900] = "msedgewebview2.exe" });
        box.File(900, @"C:\Users\lab\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies", "msedgewebview2");
        box.File(900, @"C:\Users\lab\AppData\Local\Google\Chrome\User Data\Default\Login Data", "msedgewebview2");
        Assert.True(box.Score(900) >= 70, box.Why(900));
    }

    // ===================================================== the agent itself

    [Fact]
    public void The_agents_own_triage_files_and_memory_do_not_score_it()
    {
        var box = new Box(self: 2916);
        for (int i = 0; i < 5; i++)
            box.File(2916, $@"C:\Windows\TEMP\BruceEDR-triage-{i}\processes.csv", "bruceedr");
        Assert.Equal(0, box.Score(2916));
        Assert.Null(box.Engine.SnapshotOne(2916));
        Assert.Empty(box.Engine.ApplyMemoryHits(2916, IocDatabase.MemoryStringIocs));
    }

    [Fact]
    public void Another_process_writing_the_same_csv_in_the_same_place_is_scored()
    {
        var box = new Box(self: 2916);
        box.File(500, @"C:\Windows\TEMP\BruceEDR-triage-x\processes.csv", "other");
        Assert.True(box.Score(500) >= 15, box.Why(500));
    }

    // ===================================================== memory scan

    [Fact]
    public void The_incident_text_does_not_hold_a_string_the_scanner_looks_for()
    {
        var box = new Box(rules: false);
        box.Open(900, "reader", 1000, 0x20);
        box.Open(900, "reader", 1001, 0x20);
        box.Engine.ApplyMemoryHits(900, IocDatabase.MemoryStringIocs);

        var reasons = box.Engine.SnapshotOne(900)!.Reasons.Single(r => r.Contains("Memory IOC"));
        Assert.Contains("[", reasons);

        var matcher = new PatternMatcher(IocDatabase.MemoryStringIocs);
        Assert.Empty(matcher.FindAll(System.Text.Encoding.ASCII.GetBytes(reasons)));
        Assert.Empty(matcher.FindAll(System.Text.Encoding.Unicode.GetBytes(reasons)));
        Assert.Empty(matcher.FindAll(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", box.Engine.SnapshotOne(900)!.Reasons))));
    }

    [Fact]
    public void Only_the_builtin_strings_are_defanged_a_rule_id_is_left_alone()
    {
        Assert.Equal("s[t]ealer", DetectionEngine.DefangMemoryHit("stealer"));
        Assert.Equal("s[e]lect * from logins", DetectionEngine.DefangMemoryHit("select * from logins"));
        Assert.Equal("Infostealer_Generic", DetectionEngine.DefangMemoryHit("Infostealer_Generic"));
    }

    [Fact]
    public void A_memory_hit_still_adds_its_points()
    {
        var box = new Box(rules: false);
        box.Open(900, "x", 1000, 0x20);
        int before = box.Score(900);
        box.Engine.ApplyMemoryHits(900, new[] { "stealer", "keylog" });
        Assert.Equal(before + 30, box.Score(900));
    }

    // Regions of another process: private memory is where an attacker's code lives; an unmodified image page
    // is the file on disk and carries user32's export names.
    private const uint Commit = 0x1000, Reserve = 0x2000;
    private const uint Private = 0x20000, Mapped = 0x40000, Image = 0x1000000;

    [Theory]
    [InlineData(Commit, 0x04u, Private, true)]            // heap, VirtualAlloc'd payload
    [InlineData(Commit, 0x40u, Private, true)]            // RWX
    [InlineData(Commit, 0x02u, Private, true)]            // read-only private memory
    [InlineData(Commit, 0x20u, Private, true)]
    [InlineData(Commit, 0x02u, Image, false)]             // .rdata: user32's export names
    [InlineData(Commit, 0x20u, Image, false)]             // .text
    [InlineData(Commit, 0x08u, Image, false)]             // .data not yet written (copy-on-write)
    [InlineData(Commit, 0x80u, Image, false)]
    [InlineData(Commit, 0x04u, Image, true)]              // an image page that has been written
    [InlineData(Commit, 0x40u, Image, true)]              // patched or stomped code
    [InlineData(Commit, 0x02u, Mapped, false)]            // a file mapped read-only (fonts, indexes)
    [InlineData(Commit, 0x04u, Mapped, true)]             // shared memory
    [InlineData(Commit, 0x20u, Mapped, true)]             // section-mapped code
    [InlineData(Commit, 0x01u, Private, false)]           // PAGE_NOACCESS
    [InlineData(Commit, 0x104u, Private, false)]          // PAGE_GUARD | READWRITE
    [InlineData(Commit, 0x10u, Private, false)]           // PAGE_EXECUTE, not readable
    [InlineData(Reserve, 0x04u, Private, false)]          // reserved, not committed
    public void Which_memory_regions_are_scanned(uint state, uint protect, uint type, bool expected)
        => Assert.Equal(expected, ScanRegions.ShouldScan(state, protect, type));

    // The claim behind the filter, checked on a real loaded system DLL: user32's export table names
    // SetWindowsHookExW, and the page that holds the name is an image page the scan skips.
    [Fact]
    public void The_export_names_of_a_loaded_system_dll_sit_in_pages_the_scan_skips()
    {
        IntPtr module = System.Runtime.InteropServices.NativeLibrary.Load("user32.dll");
        try
        {
            using var me = System.Diagnostics.Process.GetCurrentProcess();
            var user32 = me.Modules.Cast<System.Diagnostics.ProcessModule>()
                .Single(m => m.ModuleName.Equals("user32.dll", StringComparison.OrdinalIgnoreCase));
            var needle = System.Text.Encoding.ASCII.GetBytes("SetWindowsHookExW");
            uint size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Native.NativeMethods.MEMORY_BASIC_INFORMATION>();

            bool found = false;
            long at = (long)user32.BaseAddress, end = at + user32.ModuleMemorySize;
            while (at < end && Native.NativeMethods.VirtualQueryEx(me.Handle, new IntPtr(at), out var mbi, size) != 0)
            {
                long regionEnd = Math.Min((long)mbi.BaseAddress + (long)mbi.RegionSize, end);
                bool readable = (mbi.State & Commit) != 0 && (mbi.Protect & Native.NativeMethods.PAGE_READABLE_MASK) != 0
                                && (mbi.Protect & (Native.NativeMethods.PAGE_NOACCESS | Native.NativeMethods.PAGE_GUARD)) == 0;
                var buffer = new byte[regionEnd - at];
                if (readable && Native.NativeMethods.ReadProcessMemory(me.Handle, new IntPtr(at), buffer, buffer.Length, out var read)
                    && (long)read > 0 && new ReadOnlySpan<byte>(buffer, 0, (int)read).IndexOf(needle) >= 0)
                {
                    found = true;
                    Assert.Equal(Image, mbi.Type);
                    Assert.False(ScanRegions.ShouldScan(mbi.State, mbi.Protect, mbi.Type),
                        $"the export name sits in a region the scan reads (protect 0x{mbi.Protect:X})");
                }
                at = regionEnd;
            }
            Assert.True(found, "user32.dll does not hold the name of its own export in memory");
        }
        finally { System.Runtime.InteropServices.NativeLibrary.Free(module); }
    }

    // ===================================================== the table

    private static readonly PlatformImages.Roots Roots = new(@"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData");
    private static readonly Func<string, string?> AdminOnly = _ => null;
    private static readonly Func<string, string?> UserWritable = p => p + " can be changed by Users";

    [Theory]
    [InlineData(@"C:\Windows\System32\csrss.exe", "csrss.exe")]
    [InlineData(@"C:\WINDOWS\system32\SVCHOST.EXE", "svchost.exe")]
    [InlineData(@"C:\Windows\System32\wbem\WmiPrvSE.exe", "wmiprvse.exe")]
    [InlineData(@"C:\Windows\SysWOW64\wbem\WmiPrvSE.exe", "wmiprvse.exe")]
    [InlineData(@"C:\Windows\explorer.exe", "explorer.exe")]
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe", "msmpeng.exe")]
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\NisSrv.exe", "nissrv.exe")]
    [InlineData(@"C:\Program Files\Windows Defender\MsMpEng.exe", "msmpeng.exe")]
    [InlineData(@"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe", "mssense.exe")]
    [InlineData(@"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe", "searchhost.exe")]
    [InlineData(@"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe", "startmenuexperiencehost.exe")]
    [InlineData(@"C:\Windows\System32\RuntimeBroker.exe", "runtimebroker.exe")]
    [InlineData(@"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\157.0.4341.46\msedgewebview2.exe", "msedgewebview2.exe")]
    [InlineData(@"C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_423.3300.0.0_x64__cw5n1h2txyewy\Dashboard\Widgets.exe", "widgets.exe")]
    public void A_component_is_known_by_its_own_file_in_its_own_folder(string path, string expected)
        => Assert.Equal(expected, PlatformImages.Identify(path, Roots, AdminOnly));

    [Theory]
    [InlineData(@"C:\Users\u\AppData\Local\Temp\svchost.exe")]
    [InlineData(@"C:\Users\Public\csrss.exe")]
    [InlineData(@"D:\Windows\System32\svchost.exe")]                                   // another drive
    [InlineData(@"C:\Windows\System32\Tasks\svchost.exe")]                              // a folder below the right one
    [InlineData(@"C:\Windows\System32\wbem\svchost.exe")]                               // the right folder for another name
    [InlineData(@"C:\Windows\System32\..\Temp\svchost.exe")]
    [InlineData(@"\\attacker\share\svchost.exe")]
    [InlineData(@"C:\Windows\WmiPrvSE.exe")]
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe")]    // no version folder
    [InlineData(@"C:\ProgramData\Microsoft\Windows Defender\Platform\a\b\MsMpEng.exe")]
    [InlineData(@"C:\Program Files\WindowsApps\Other.App_1.0_x64__x\Dashboard\Widgets.exe")]
    [InlineData(@"svchost.exe")]
    [InlineData(@"")]
    public void A_look_alike_is_not_a_component(string path)
        => Assert.Null(PlatformImages.Identify(path, Roots, AdminOnly));

    [Fact]
    public void A_file_a_standard_user_could_have_planted_is_not_a_component_even_in_the_right_folder()
        => Assert.Null(PlatformImages.Identify(@"C:\Windows\System32\svchost.exe", Roots, UserWritable));

    [Theory]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData(@"C:\Windows\System32\cmd.exe")]
    [InlineData(@"C:\Windows\System32\rundll32.exe")]
    [InlineData(@"C:\Windows\System32\mshta.exe")]
    [InlineData(@"C:\Windows\System32\regsvr32.exe")]
    [InlineData(@"C:\Windows\System32\wscript.exe")]
    [InlineData(@"C:\Windows\System32\cscript.exe")]
    [InlineData(@"C:\Windows\System32\certutil.exe")]
    [InlineData(@"C:\Windows\System32\bitsadmin.exe")]
    [InlineData(@"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe")]
    [InlineData(@"C:\Windows\System32\curl.exe")]
    [InlineData(@"C:\Windows\System32\wmic.exe")]
    public void A_program_that_runs_whatever_it_is_given_never_gets_an_exemption_from_its_path(string path)
        => Assert.Null(PlatformImages.Identify(path, Roots, AdminOnly));

    [Fact]
    public void No_LOLBin_the_engine_knows_is_in_the_table()
        => Assert.Empty(PlatformImages.Names.Intersect(IocDatabase.LolBins, StringComparer.OrdinalIgnoreCase));

    [Fact]
    public void The_table_covers_every_Windows_process_the_containment_guard_keeps_alive()
    {
        // The guard refuses to contain these; a verdict against one is a false verdict by definition.
        // Kernel pseudo-processes have no image file to check and are handled by pid.
        var kernelOnly = new[] { "system", "idle", "registry", "memcompression", "memory compression", "ntoskrnl.exe" };
        var missing = Watchlist.ProtectedProcesses
            .Where(n => !kernelOnly.Contains(n, StringComparer.OrdinalIgnoreCase))
            .Where(n => !PlatformImages.Names.Contains(n, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        Assert.Empty(missing);
    }

    [Fact]
    public void Only_WMI_and_Defender_read_LSASS()
    {
        var readers = PlatformImages.Names.Where(PlatformImages.ReadsLsass).OrderBy(n => n).ToArray();
        Assert.Equal(new[] { "msmpeng.exe", "nissrv.exe", "wmiprvse.exe" }, readers);
        Assert.False(PlatformImages.ReadsLsass(null));
        Assert.False(PlatformImages.ReadsLsass("csrss.exe"));
    }

    [Fact]
    public void The_System_process_is_pid_4_and_nothing_else_is()
    {
        Assert.Equal("system", PlatformImages.Identify(4));
        Assert.Null(PlatformImages.Identify(0));
        Assert.Null(PlatformImages.Identify(-1));
        Assert.Null(PlatformImages.Identify(Environment.ProcessId));   // the test host is not a Windows component
    }

    // The real folders of this machine: the ACL walk has to pass on what Windows ships, or the table
    // identifies nothing in production. Only what is installed here is asserted.
    [Theory]
    [InlineData(@"System32\csrss.exe")]
    [InlineData(@"System32\svchost.exe")]
    [InlineData(@"System32\services.exe")]
    [InlineData(@"System32\lsass.exe")]
    [InlineData(@"System32\conhost.exe")]
    [InlineData(@"System32\sihost.exe")]
    [InlineData(@"System32\SearchIndexer.exe")]
    [InlineData(@"System32\wbem\WmiPrvSE.exe")]
    [InlineData(@"System32\RuntimeBroker.exe")]
    [InlineData(@"System32\lsaiso.exe")]
    [InlineData(@"System32\LogonUI.exe")]
    [InlineData(@"System32\SecurityHealthService.exe")]
    [InlineData(@"SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe")]
    [InlineData(@"SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe")]
    [InlineData(@"explorer.exe")]
    public void The_real_Windows_files_on_this_machine_are_identified(string relative)
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), relative);
        if (!File.Exists(path)) return;
        Assert.Equal(Path.GetFileName(path).ToLowerInvariant(), PlatformImages.Identify(path, PlatformImages.Roots.Current(), KernelPolicy.WriteRisk));
    }

    [Fact]
    public void The_real_Defender_and_WebView2_files_on_this_machine_are_identified()
    {
        var roots = PlatformImages.Roots.Current();
        string platform = Path.Combine(roots.ProgramData, "Microsoft", "Windows Defender", "Platform");
        var searched = new List<(string Dir, string Exe)>();
        if (Directory.Exists(platform))
            foreach (var version in Directory.GetDirectories(platform))
                foreach (var exe in new[] { "MsMpEng.exe", "NisSrv.exe" })
                    searched.Add((version, exe));
        string webview = Path.Combine(roots.ProgramFilesX86, "Microsoft", "EdgeWebView", "Application");
        if (Directory.Exists(webview))
            foreach (var version in Directory.GetDirectories(webview))
                searched.Add((version, "msedgewebview2.exe"));

        foreach (var (dir, exe) in searched)
        {
            string path = Path.Combine(dir, exe);
            if (!File.Exists(path)) continue;
            Assert.Equal(exe.ToLowerInvariant(), PlatformImages.Identify(path, roots, KernelPolicy.WriteRisk));
        }
    }

    [Fact]
    public void A_copy_of_a_Windows_binary_in_a_user_folder_is_not_identified_on_the_real_disk()
    {
        string dir = Path.Combine(Path.GetTempPath(), "bruce-platform-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string copy = Path.Combine(dir, "svchost.exe");
            File.WriteAllBytes(copy, new byte[] { 0x4D, 0x5A });
            Assert.Null(PlatformImages.Identify(copy, PlatformImages.Roots.Current(), KernelPolicy.WriteRisk));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ===================================================== a clean machine, start to finish

    [Fact]
    public void A_clean_Windows_session_produces_no_incident()
    {
        var names = new Dictionary<int, string>
        {
            [4] = "system", [440] = "csrss.exe", [700] = "lsass.exe", [1624] = "svchost.exe", [2740] = "msmpeng.exe",
            [4700] = "nissrv.exe", [4256] = "wmiprvse.exe", [3336] = "conhost.exe", [3200] = "sihost.exe",
            [2100] = "searchindexer.exe", [3900] = "msedgewebview2.exe", [4000] = "widgets.exe",
        };
        var box = new Box(names, self: 2916);

        foreach (int t in new[] { 4620, 408, 3124, 2392 }) box.Open(4, "System", t, MaximumAllowed);
        foreach (int t in new[] { 4356, 3976, 5932 }) box.Open(440, "csrss", t, AllAccess);
        foreach (int t in new[] { 4356, 5932 }) box.Open(1624, "svchost", t, 0x1478);
        foreach (int t in new[] { 2916, 2892 }) box.Open(700, "lsass", t, 0x478);
        box.Open(2740, "MsMpEng", 2916, 0x418);
        foreach (int t in new[] { 2892, 576, 5532 }) box.Open(3336, "conhost", t, MaximumAllowed);
        foreach (int t in new[] { 1004, 1132, 1348 }) box.Open(4256, "WmiPrvSE", t, QueryRead);
        box.Open(4256, "WmiPrvSE", LsassPid, QueryRead);
        box.Open(4700, "NisSrv", LsassPid, GenericRead);
        foreach (int t in new[] { 4000, 3900, 3800 }) box.Open(3900, "msedgewebview2", t, 0x1F0FFF);

        box.Registry(3200, "sihost", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunNotification", null, "create-key");
        box.Registry(3200, "sihost", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", null, "create-key");
        box.Registry(3076, "drvinst", @"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", null, "create-key");
        box.File(3200, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\");
        box.File(2100, @"C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate");
        box.File(2100, @"C:\Windows\System32\Tasks\Microsoft\Windows\");
        box.File(1624, @"C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate\Scheduled Start", "svchost");
        box.File(3900, WebViewStore, "msedgewebview2");
        box.File(3900, WebViewLocalState, "msedgewebview2");
        box.File(2916, @"C:\Windows\TEMP\BruceEDR-triage-ad51\processes.csv", "bruceedr");

        foreach (int pid in new[] { 4, 440, 700, 1624, 2740, 4700, 4256, 3336, 3200, 3076, 2100, 3900, 4000, 2916 })
            Assert.True(box.Score(pid) < 40, $"pid {pid} scored {box.Score(pid)}: " + box.Why(pid));
        Assert.Empty(box.Verdicts);
    }

    [Fact]
    public void The_same_session_with_an_attacker_in_it_flags_the_attacker_and_only_the_attacker()
    {
        var names = new Dictionary<int, string> { [440] = "csrss.exe", [4256] = "wmiprvse.exe" };
        var box = new Box(names);

        foreach (int t in new[] { 4356, 3976, 5932 }) box.Open(440, "csrss", t, AllAccess);
        foreach (int t in new[] { 1004, 1132 }) box.Open(4256, "WmiPrvSE", t, QueryRead);
        box.Open(4256, "WmiPrvSE", LsassPid, QueryRead);

        box.Start(7001, "svchost.exe", @"C:\Users\u\AppData\Local\Temp\svchost.exe");   // renamed dumper
        box.Open(7001, "svchost", LsassPid, 0x1410);
        box.Start(7002, "inject.exe", @"C:\Users\u\Downloads\inject.exe");
        foreach (int t in new[] { 440, 1624, 3200 }) box.Open(7002, "inject.exe", t, 0x002A);
        box.Registry(7003, "dropper", @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "Updater", "set-value");
        box.File(7004, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk", "dropper2");

        Assert.False(box.Flagged(440));
        Assert.False(box.Flagged(4256));
        Assert.True(box.Quarantined(7001), box.Why(7001));
        Assert.True(box.Quarantined(7002), box.Why(7002));
        Assert.True(box.Score(7003) >= 65, box.Why(7003));
        Assert.True(box.Score(7004) >= 45, box.Why(7004));
    }
}
