using BruceEDR.Analysis;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Driver;
using BruceEDR.Intel;
using BruceEDR.Monitoring;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

public sealed class NotepadAndTuningTests
{
    private static readonly DateTime T0 = new(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

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

    [Fact]
    public void Catalog_Signed_System32_Notepad_Is_Verified_And_Trusted()
    {
        string sysNotepad = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(sysNotepad)) return;

        string? publisher = AuthenticodeVerifier.PublisherOf(sysNotepad);
        Assert.NotNull(publisher);
        Assert.Contains("Microsoft", publisher, StringComparison.OrdinalIgnoreCase);

        var allow = new AllowlistConfig
        {
            AllowSubjectMatch = true,
            Publishers = new[] { "Microsoft Corporation", "Microsoft Windows" }
        };
        var verifier = new AuthenticodeVerifier(allow);
        Assert.True(verifier.IsTrustedFile(sysNotepad), $"Expected catalog/Authenticode trust for {sysNotepad} (publisher: {publisher})");
    }

    [Fact]
    public void WindowsApps_Packaged_Notepad_Passes_WriteRisk_When_Installed()
    {
        const string windowsApps = @"C:\Program Files\WindowsApps";
        if (!Directory.Exists(windowsApps)) return;

        string? packagedNotepad;
        try
        {
            packagedNotepad = Directory.EnumerateDirectories(windowsApps, "Microsoft.WindowsNotepad_*")
                .Select(d => Path.Combine(d, "Notepad", "Notepad.exe"))
                .FirstOrDefault(File.Exists);
        }
        catch (UnauthorizedAccessException)
        {
            // Non-elevated callers cannot enumerate WindowsApps subdirectories directly.
            return;
        }

        if (packagedNotepad is null) return;

        Assert.Null(KernelPolicy.WriteRisk(packagedNotepad));
        var standing = ImageStanding.Of(0, packagedNotepad);
        Assert.True(standing.Installed, $"Expected MSIX Notepad standing Installed=true, got publisher='{standing.Publisher}'");
    }

    [Fact]
    public void Benign_Windows11_Notepad_Session_Scores_Zero_And_Never_Flags()
    {
        const int stubPid = 4100;
        const int appPid = 4104;
        const string stubPath = @"C:\Windows\System32\notepad.exe";
        const string msixPath = @"C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2609.11.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe";

        var tree = new ProcessTree(SystemClock.Instance);
        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => true,
            new EngineDependencies
            {
                Rules = ShippedRules(),
                Tree = tree,
                Standing = (_, path) => new ImageStanding(true, "Microsoft Corporation", true, false, path),
                ResolveProcessName = pid => pid is stubPid or appPid ? "notepad.exe" : "explorer.exe"
            });

        var verdicts = new List<DetectionResult>();
        int tick = 0;
        void Feed(Signal s) => verdicts.AddRange(engine.Ingest(s with { TimestampUtc = T0.AddSeconds(tick++) }));

        // 1. User launches System32 notepad.exe stub, which spawns packaged WindowsApps Notepad.exe
        Feed(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = stubPid, ParentPid = 1200,
            ProcessName = "notepad.exe", ImagePath = stubPath,
            CommandLine = @"notepad.exe C:\Users\alice\AppData\Local\Temp\notes.csv"
        });
        Feed(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = appPid, ParentPid = stubPid,
            ProcessName = "notepad.exe", ImagePath = msixPath,
            CommandLine = $"\"{msixPath}\" C:\\Users\\alice\\AppData\\Local\\Temp\\notes.csv"
        });

        // 2. Single-instance tab handoff opens child Notepad with full process rights
        Feed(new Signal
        {
            Kind = SignalKind.ProcessAccess, Pid = stubPid, ProcessName = "notepad.exe",
            TargetPid = appPid, DesiredAccess = 0x001FFFFF,
            Detail = "open-process:PROCESS_ALL_ACCESS"
        });

        // 3. PE static analysis runs on Windows 11 Notepad's real import table
        var notepadPe = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", new byte[0x400], AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("kernel32.dll", "IsDebuggerPresent", "GetTickCount64", "OutputDebugStringA")
            .AddImport("user32.dll", "GetClipboardData", "SetClipboardData", "GetKeyboardState", "SetWindowsHookExW")
            .AddImport("gdi32.dll", "BitBlt")
            .AddImport("advapi32.dll", "CreateProcessAsUserW")
            .AddImport("ntdll.dll", "NtQueryInformationProcess")
            .Build();
        var analysis = FileAnalyzer.AnalyzeBytes(notepadPe, msixPath);
        Assert.DoesNotContain("IsDebuggerPresent", analysis.SuspiciousImports);
        Assert.DoesNotContain("GetClipboardData", analysis.SuspiciousImports);
        Assert.DoesNotContain("BitBlt", analysis.SuspiciousImports);
        verdicts.AddRange(engine.ApplyImageAnalysis(appPid, analysis));

        // 4. User opens existing files (.csv, .rtf, .pdf, .zip) and directories in Temp & Startup (ETW Detail = "open" / "dir")
        foreach (string path in new[]
        {
            @"C:\Users\alice\AppData\Local\Temp\report-1.csv",
            @"C:\Users\alice\AppData\Local\Temp\report-2.csv",
            @"C:\Users\alice\AppData\Local\Temp\report-3.rtf",
            @"C:\Users\alice\AppData\Local\Temp\export-4.pdf",
            @"C:\Users\alice\AppData\Local\Temp\logs.zip",
            @"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\readme.txt"
        })
        {
            Feed(new Signal
            {
                Kind = SignalKind.FileCreate, Pid = appPid, ProcessName = "notepad.exe",
                FilePath = path, Detail = "open"
            });
        }

        Feed(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = appPid, ProcessName = "notepad.exe",
            FilePath = @"C:\Users\alice\AppData\Local\Temp\archive.zip", Detail = "dir"
        });

        Assert.Empty(verdicts);
        Assert.Equal(0, engine.SnapshotOne(stubPid)?.Score ?? 0);
        Assert.Equal(0, engine.SnapshotOne(appPid)?.Score ?? 0);
    }

    [Fact]
    public void Compromised_Hollowed_Notepad_Stealing_Secrets_Or_Dumping_Lsass_Is_Quarantined()
    {
        const int lsassPid = 640;
        const int injectedNotepadPid = 5200;

        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => true, // Even signed by Microsoft, real credential theft + exfil or LSASS dump must be caught!
            new EngineDependencies
            {
                Rules = ShippedRules(),
                Standing = (_, path) => new ImageStanding(true, "Microsoft Windows", true, false, path),
                ResolveProcessName = pid => pid == lsassPid ? "lsass.exe" : "notepad.exe"
            });

        var verdicts = new List<DetectionResult>();
        int tick = 0;
        void Feed(Signal s) => verdicts.AddRange(engine.Ingest(s with { TimestampUtc = T0.AddSeconds(tick++) }));

        Feed(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = injectedNotepadPid, ParentPid = 1200,
            ProcessName = "notepad.exe", ImagePath = @"C:\Windows\System32\notepad.exe"
        });

        // Hollowed notepad opens LSASS with VM_READ + QUERY_INFORMATION (0x0410) and stages + exfiltrates Chrome Login Data
        Feed(new Signal
        {
            Kind = SignalKind.ProcessAccess, Pid = injectedNotepadPid, ProcessName = "notepad.exe",
            TargetPid = lsassPid, DesiredAccess = 0x0410,
            Detail = "open-process:PROCESS_QUERY_INFORMATION|PROCESS_VM_READ"
        });
        Feed(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = injectedNotepadPid, ProcessName = "notepad.exe",
            FilePath = @"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            Detail = "open"
        });
        Feed(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = injectedNotepadPid, ProcessName = "notepad.exe",
            FilePath = @"C:\Users\alice\AppData\Local\Temp\loot.zip",
            Detail = "create"
        });

        Assert.Contains(verdicts, v => v.Verdict == Verdict.Quarantine && v.Snapshot.Pid == injectedNotepadPid);
    }

    [Fact]
    public void Live_Etw_ImageLoad_Promotes_Bare_ProcessStart_Path_And_Matches_Intel_Hash()
    {
        const string sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const string fullPath = @"C:\Users\alice\Downloads\stealer.exe";

        var feed = IocFeed.Parse(new[] { $"{sha} ; RedLine-Sample" }, "test-feed");
        int hashCalls = 0;

        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => false,
            new EngineDependencies
            {
                Intel = feed,
                ImageHash = path =>
                {
                    hashCalls++;
                    // Live ETW ProcessStart only supplies "stealer.exe", which is not a valid file in cwd
                    return path == fullPath ? sha : null;
                }
            });

        // 1. Kernel ProcessStart arrives with bare image filename
        engine.Ingest(new Signal
        {
            Kind = SignalKind.ProcessStart, Pid = 7100, ProcessName = "stealer.exe",
            ImagePath = "stealer.exe", TimestampUtc = T0
        });
        Assert.Equal(0, engine.SnapshotOne(7100)?.Score ?? 0);

        // 2. Main image ImageLoad arrives with full path -> promotes ImagePath and matches intel-hash
        engine.Ingest(new Signal
        {
            Kind = SignalKind.ImageLoad, Pid = 7100, ProcessName = "stealer.exe",
            FilePath = fullPath, TimestampUtc = T0.AddMilliseconds(10)
        });
        Assert.True((engine.SnapshotOne(7100)?.Score ?? 0) >= 60);
        Assert.Contains(engine.SnapshotOne(7100)!.ReasonLog, r => r.RuleId == "intel-hash");

        // 3. Subsequent DLL ImageLoad events do not re-hash the main executable
        int callsAfterMainImage = hashCalls;
        engine.Ingest(new Signal
        {
            Kind = SignalKind.ImageLoad, Pid = 7100, ProcessName = "stealer.exe",
            FilePath = @"C:\Windows\System32\ntdll.dll", TimestampUtc = T0.AddMilliseconds(20)
        });
        Assert.Equal(callsAfterMainImage, hashCalls);
    }

    [Fact]
    public void Tuned_Rules_Catch_Discord_LocalStorage_ControlSet001_And_Hku_ComHijack()
    {
        var engine = new DetectionEngine(
            new EngineOptions(),
            _ => false,
            new EngineDependencies { Rules = ShippedRules() });

        // 1. Non-owner reading Discord Local Storage\leveldb scores builtin-credential-store; Discord PTB reading its own does not
        engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 8001, ProcessName = "python.exe",
            FilePath = @"C:\Users\alice\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb",
            Detail = "open", TimestampUtc = T0
        });
        Assert.Contains(engine.SnapshotOne(8001)!.ReasonLog, r => r.RuleId == "builtin-credential-store");

        engine.Ingest(new Signal
        {
            Kind = SignalKind.FileCreate, Pid = 8002, ProcessName = "discordptb.exe",
            FilePath = @"C:\Users\alice\AppData\Roaming\discordptb\Local Storage\leveldb\000005.ldb",
            Detail = "open", TimestampUtc = T0
        });
        Assert.Equal(0, engine.SnapshotOne(8002)?.Score ?? 0);

        // 2. ControlSet001 service ImagePath write fires service-imagepath-write
        engine.Ingest(new Signal
        {
            Kind = SignalKind.RegistryWrite, Pid = 8003, ProcessName = "reg.exe",
            RegistryKey = @"HKLM\SYSTEM\ControlSet001\Services\EvilSvc",
            RegistryValue = "ImagePath", Detail = "set-value", TimestampUtc = T0
        });
        Assert.Contains(engine.SnapshotOne(8003)!.ReasonLog, r => r.RuleId == "service-imagepath-write");

        // 3. Live ETW HKU\<SID> COM CLSID InprocServer32 hijack fires com-hijack-user-hive
        engine.Ingest(new Signal
        {
            Kind = SignalKind.RegistryWrite, Pid = 8004, ProcessName = "rundll32.exe",
            RegistryKey = @"HKU\S-1-5-21-123456789-1001\Software\Classes\CLSID\{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}\InprocServer32",
            RegistryValue = "(Default)", Detail = "set-value", TimestampUtc = T0
        });
        Assert.Contains(engine.SnapshotOne(8004)!.ReasonLog, r => r.RuleId == "com-hijack-user-hive");
    }
}
