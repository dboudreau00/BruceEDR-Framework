using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Driver;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// What the agent tells the minifilter to guard and whom to trust. The builder runs against a
/// fake machine; the permission and path checks run read-only against real files.
/// </summary>
public sealed class KernelPolicyTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bruce-kernel-" + Guid.NewGuid().ToString("N"));

    public KernelPolicyTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static KernelPolicyEnvironment Machine(Dictionary<string, string[]> owners, Func<string, string?>? risk = null) => new()
    {
        FindOwner = exe => owners.TryGetValue(exe, out var paths) ? paths : Array.Empty<string>(),
        Resolve = path => (path, @"\Device\HarddiskVolume3" + path[2..], null),
        WriteRisk = risk ?? (_ => null)
    };

    private const string Chrome = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
    private const string Edge = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";

    [Fact]
    public void Every_Store_Is_A_Fragment_The_Driver_Accepts()
    {
        var guards = IocDatabase.KernelGuards;
        Assert.InRange(guards.Length, 1, MinifilterClient.MaxStores);
        Assert.Equal(guards.Length, guards.Select(g => g.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(guards.Length, guards.Select(g => g.Fragment).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var g in guards)
        {
            // BruceFilterPolicy.c: a separator at each end, two named characters between them.
            Assert.True(MinifilterClient.IsWireText(g.Fragment), g.Fragment);
            Assert.StartsWith(@"\", g.Fragment);
            Assert.EndsWith(@"\", g.Fragment);
            Assert.True(g.Fragment.Count(c => c != '\\') >= 2, g.Fragment);
            Assert.Equal(g.Fragment.ToLowerInvariant(), g.Fragment);
            Assert.Equal(g.Name.ToLowerInvariant(), g.Name);
            Assert.NotEmpty(g.Owners);
            Assert.All(g.Owners, o => Assert.EndsWith(".exe", o));
        }
    }

    private static bool Guarded(string path) =>
        IocDatabase.KernelGuards.Any(g => (path.ToLowerInvariant() + @"\").Contains(g.Fragment));

    [Theory]
    [InlineData(@"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data")]
    [InlineData(@"C:\Users\bob\AppData\Local\Microsoft\Edge\User Data\Local State")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Electrum\wallets\default_wallet")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\Exodus\exodus.wallet\seed.seco")]
    [InlineData(@"C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000003.log")]
    public void The_Stores_Themselves_Are_Guarded(string path) => Assert.True(Guarded(path), path);

    [Theory]
    [InlineData(@"C:\Users\bob\AppData\Local\exodus\app-24.41.3\Exodus.exe")]
    [InlineData(@"C:\Users\bob\AppData\Local\exodus\Update.exe")]
    [InlineData(@"C:\Users\bob\AppData\Local\Discord\app-1.0.9170\Discord.exe")]
    [InlineData(@"C:\Program Files\Google\Chrome\Application\chrome.exe")]
    [InlineData(@"C:\Program Files\Mozilla Firefox\firefox.exe")]
    [InlineData(@"C:\Users\bob\Documents\Exodus notes.txt")]
    public void The_Programs_That_Own_Them_Are_Not(string path) => Assert.False(Guarded(path), path);

    [Fact]
    public void An_Owner_From_App_Paths_Is_Trusted_For_Its_Own_Store_Only()
    {
        var plan = KernelPolicy.Build(new DetectionConfig(), Machine(new()
        {
            ["chrome.exe"] = new[] { Chrome },
            ["msedge.exe"] = new[] { Edge }
        }));

        Assert.Equal(new[] { "chrome", "edge", "firefox", "electrum", "exodus", "discord", "discordptb", "discordcanary" },
            plan.Stores.Select(s => s.Name));
        Assert.Equal(2, plan.Trusted.Count);
        var chrome = Assert.Single(plan.Trusted, t => t.Path == Chrome);
        Assert.Equal(0, chrome.StoreIndex);
        Assert.Equal(@"\Device\HarddiskVolume3\Program Files\Google\Chrome\Application\chrome.exe", chrome.NtPath);
        Assert.Equal(1, Assert.Single(plan.Trusted, t => t.Path == Edge).StoreIndex);
        // Firefox, Electrum, Exodus and the three Discord builds have no trusted reader, and the plan says so.
        Assert.Equal(6, plan.Notes.Count(n => n.Contains("nothing trusted")));
        Assert.Contains(plan.Notes, n => n.StartsWith("discord: nothing trusted") && n.Contains("discord.exe included"));
    }

    // Two lab VMs had msedge.exe installed machine-wide and no App Paths key in either view.
    [Fact]
    public void An_Owner_Without_An_App_Paths_Key_Is_Found_In_Its_Install_Folder()
    {
        const string edge = @"C:\PF86\Microsoft\Edge\Application\msedge.exe";
        var roots = new[] { @"C:\PF", @"C:\PF86" };

        Assert.Equal(new[] { edge }, KernelPolicy.Owners("msedge.exe", Array.Empty<string>(), roots, p => p == edge));
        Assert.Single(KernelPolicy.Owners("MSEDGE.EXE", new[] { edge.ToUpperInvariant() }, roots, p => p == edge));
        Assert.Empty(KernelPolicy.Owners("msedge.exe", Array.Empty<string>(), roots, _ => false));
        Assert.Empty(KernelPolicy.Owners("discord.exe", Array.Empty<string>(), roots, _ => true));
    }

    [Fact]
    public void An_Owner_A_Standard_User_Could_Replace_Is_Not_Trusted()
    {
        var plan = KernelPolicy.Build(new DetectionConfig(), Machine(
            new() { ["chrome.exe"] = new[] { Chrome } },
            path => path == Chrome ? @"C:\Program Files\Google can be changed by BUILTIN\Users" : null));

        Assert.Empty(plan.Trusted);
        Assert.Contains(plan.Notes, n => n.Contains(Chrome + " not trusted") && n.Contains(@"BUILTIN\Users"));
        Assert.Contains(plan.Notes, n => n.StartsWith("chrome: nothing trusted"));
    }

    [Fact]
    public void App_Paths_Naming_Another_Program_Trusts_Nothing()
    {
        var plan = KernelPolicy.Build(new DetectionConfig(), Machine(new()
        {
            ["chrome.exe"] = new[] { @"C:\Program Files\Something\launcher.exe" }
        }));
        Assert.Empty(plan.Trusted);
        Assert.Contains(plan.Notes, n => n.Contains("names") && n.Contains("launcher.exe"));
    }

    [Fact]
    public void An_Unresolvable_Image_Is_Not_Trusted()
    {
        var env = new KernelPolicyEnvironment
        {
            FindOwner = exe => exe == "chrome.exe" ? new[] { Chrome } : Array.Empty<string>(),
            Resolve = _ => (null, null, "not on a local volume"),
            WriteRisk = _ => null
        };
        var plan = KernelPolicy.Build(new DetectionConfig(), env);
        Assert.Empty(plan.Trusted);
        Assert.Contains(plan.Notes, n => n.Contains("not on a local volume"));
    }

    [Fact]
    public void Exempt_Stores_Are_Left_Out_And_Unknown_Names_Reported()
    {
        var d = new DetectionConfig { KernelExemptStores = new[] { "Discord", "exodus", "icq" } };
        var plan = KernelPolicy.Build(d, Machine(new()));
        // Exempting "discord" leaves the PTB and Canary stores guarded: each is its own store.
        Assert.Equal(new[] { "chrome", "edge", "firefox", "electrum", "discordptb", "discordcanary" }, plan.Stores.Select(s => s.Name));
        Assert.Contains(plan.Notes, n => n.Contains("'icq' is not a guarded store"));
        Assert.Contains(plan.Notes, n => n.Contains("not guarded") && n.Contains("discord") && n.Contains("exodus"));
    }

    [Fact]
    public void A_Configured_Image_Is_Scoped_To_Its_Stores_Or_Trusted_For_All()
    {
        const string backup = @"C:\Program Files\Backup\agent.exe";
        const string wallet = @"C:\Program Files (x86)\Electrum\electrum-4.5.8.exe";
        var d = new DetectionConfig
        {
            KernelExemptStores = new[] { "discord" },
            KernelTrustedImages = new[]
            {
                new KernelTrustedImageConfig { Image = backup },
                new KernelTrustedImageConfig { Image = wallet, Stores = new[] { "Electrum", "discord", "nowhere" } },
                new KernelTrustedImageConfig { Image = "  " }
            }
        };
        var plan = KernelPolicy.Build(d, Machine(new()));

        Assert.Equal(-1, Assert.Single(plan.Trusted, t => t.Path == backup).StoreIndex);
        Assert.Equal(3, Assert.Single(plan.Trusted, t => t.Path == wallet).StoreIndex);   // electrum, by name
        Assert.Contains(plan.Notes, n => n.Contains("'nowhere' is not a guarded store"));
        Assert.DoesNotContain(plan.Notes, n => n.Contains("'discord'"));   // exempted, so not a mistake
        Assert.Contains(plan.Notes, n => n.Contains("an entry has no image"));
        // Trusted for every store, the backup agent leaves no store without a reader.
        Assert.DoesNotContain(plan.Notes, n => n.Contains("nothing trusted"));
    }

    [Fact]
    public void Trusted_Images_Stop_At_The_Driver_Limit()
    {
        var d = new DetectionConfig
        {
            KernelTrustedImages = Enumerable.Range(0, MinifilterClient.MaxTrusted + 5)
                .Select(i => new KernelTrustedImageConfig { Image = $@"C:\Program Files\Tool{i}\tool.exe" }).ToArray()
        };
        var plan = KernelPolicy.Build(d, Machine(new()));
        Assert.Equal(MinifilterClient.MaxTrusted, plan.Trusted.Count);
        Assert.Equal(5, plan.Notes.Count(n => n.Contains("holds 64 trusted images")));
    }

    [Fact]
    public void The_Same_Image_Is_Pushed_Once_Per_Scope()
    {
        var d = new DetectionConfig
        {
            KernelTrustedImages = new[]
            {
                new KernelTrustedImageConfig { Image = Chrome, Stores = new[] { "chrome" } },
                new KernelTrustedImageConfig { Image = Chrome.ToUpperInvariant(), Stores = new[] { "CHROME" } }
            }
        };
        var plan = KernelPolicy.Build(d, Machine(new() { ["chrome.exe"] = new[] { Chrome } }));
        Assert.Single(plan.Trusted);
    }

    [Theory]
    [InlineData("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")]
    [InlineData("\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\"", "C:\\Program Files\\Mozilla Firefox\\firefox.exe")]
    [InlineData("  \"C:\\x\\y.exe\" --flag", "C:\\x\\y.exe")]
    [InlineData("chrome.exe", null)]
    [InlineData("\\\\server\\share\\chrome.exe", null)]
    [InlineData("\"C:\\unterminated", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void An_App_Paths_Value_Becomes_A_Full_Local_Path_Or_Nothing(string? value, string? expected) =>
        Assert.Equal(expected, KernelPolicy.CleanAppPath(value));

    [Fact]
    public void App_Paths_Values_Expand_Variables()
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "x.exe");
        Assert.Equal(expected, KernelPolicy.CleanAppPath(@"%ProgramFiles%\x.exe"), ignoreCase: true);
    }

    [Fact]
    public void A_File_In_A_User_Folder_Is_Not_Safe_To_Trust()
    {
        var file = Path.Combine(_dir, "tool.exe");
        File.WriteAllBytes(file, new byte[] { 0x4D, 0x5A });
        var risk = KernelPolicy.WriteRisk(file);
        Assert.NotNull(risk);
    }

    [Fact]
    public void A_Windows_Binary_Is_Safe_To_Trust()
    {
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        if (!File.Exists(cmd)) return;
        Assert.Null(KernelPolicy.WriteRisk(cmd));
    }

    [Fact]
    public void A_Local_File_Resolves_To_Its_NT_Path()
    {
        var cmd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe");
        if (!File.Exists(cmd)) return;
        var (path, nt, problem) = KernelPolicy.ResolveImage(cmd);
        Assert.Null(problem);
        Assert.Equal(cmd, path, ignoreCase: true);
        Assert.StartsWith(@"\Device\", nt);
        Assert.EndsWith(@"\Windows\System32\cmd.exe", nt, StringComparison.OrdinalIgnoreCase);
        // The display map turns it back into the path people know.
        Assert.Equal(cmd, DosDeviceMap.Current().ToDos(nt!), ignoreCase: true);
    }

    [Theory]
    [InlineData("cmd.exe", "not a full local path")]
    [InlineData("\\\\server\\share\\tool.exe", "not a full local path")]
    [InlineData("C:\\definitely\\not\\here\\tool.exe", "no such file")]
    public void Only_An_Existing_Local_File_Resolves(string path, string problem) =>
        Assert.Equal(problem, KernelPolicy.ResolveImage(path).Problem);

    [Fact]
    public void The_Display_Map_Matches_Whole_Device_Names_Only()
    {
        var map = new DosDeviceMap(new[] { (@"\Device\HarddiskVolume3", "C:"), (@"\Device\HarddiskVolume30", "Z:") });
        Assert.Equal(@"C:\Users\x", map.ToDos(@"\Device\HarddiskVolume3\Users\x"));
        Assert.Equal(@"Z:\x", map.ToDos(@"\Device\HarddiskVolume30\x"));
        Assert.Equal(@"\Device\HarddiskVolume4\x", map.ToDos(@"\Device\HarddiskVolume4\x"));
        Assert.Equal(@"\Device\HarddiskVolume3", map.ToDos(@"\Device\HarddiskVolume3"));
        Assert.Equal("", map.ToDos(""));
    }

    [Fact]
    public void A_Refusal_Storm_Is_Logged_Once_Per_Subject_And_Counted()
    {
        var throttle = new KernelDenialThrottle(TimeSpan.FromMinutes(1), perWindow: 3);
        var t0 = new DateTime(2026, 11, 14, 8, 0, 0, DateTimeKind.Utc);

        Assert.True(throttle.Admit("1|1|a", t0, out int held));
        Assert.Equal(0, held);
        Assert.False(throttle.Admit("1|1|a", t0.AddSeconds(5), out _));   // same subject, same minute
        Assert.False(throttle.Admit("1|1|A", t0.AddSeconds(6), out _));   // paths compare without case
        Assert.True(throttle.Admit("1|1|b", t0.AddSeconds(7), out held));
        Assert.Equal(2, held);                                            // reported with the next one
        Assert.True(throttle.Admit("2|1|a", t0.AddSeconds(8), out _));
        Assert.False(throttle.Admit("3|1|a", t0.AddSeconds(9), out _));   // three a minute in all

        Assert.True(throttle.Admit("1|1|a", t0.AddMinutes(1), out held)); // a new minute
        Assert.Equal(1, held);
        Assert.False(throttle.Admit("1|1|a", t0.AddMinutes(1).AddSeconds(1), out _));
        Assert.Equal(1, throttle.TakeHeld());
        Assert.Equal(0, throttle.TakeHeld());
    }

    // Found in review: with the minute's budget spent, every refusal after the clock stepped back
    // was held until the clock caught up again.
    [Fact]
    public void A_Clock_Stepped_Back_Does_Not_Silence_Refusals()
    {
        var throttle = new KernelDenialThrottle(TimeSpan.FromMinutes(1), perWindow: 2);
        var t0 = new DateTime(2026, 11, 14, 8, 0, 0, DateTimeKind.Utc);

        Assert.True(throttle.Admit("a", t0, out _));
        Assert.True(throttle.Admit("b", t0, out _));
        Assert.False(throttle.Admit("c", t0, out _));
        Assert.True(throttle.Admit("d", t0.AddMinutes(-5), out _));
        Assert.True(throttle.Admit("a", t0.AddMinutes(-60), out _));   // its last log is now in the future
    }

    [Fact]
    public void The_Kernel_Settings_Load_From_The_Config_File()
    {
        var path = Path.Combine(_dir, "bruce.config.json");
        File.WriteAllText(path, """
        {
          "detection": {
            "kernelBlocking": true,
            "kernelExemptStores": [ "discord" ],
            "kernelTrustedImages": [
              { "image": "C:\\Program Files\\Backup\\agent.exe" },
              { "image": "C:\\Program Files (x86)\\Electrum\\electrum.exe", "stores": [ "electrum" ] },
              null,
              { "image": null, "stores": null }
            ]
          }
        }
        """);
        var cfg = ConfigLoader.Load(path);
        Assert.True(cfg.Detection.KernelBlocking);
        Assert.Equal(new[] { "discord" }, cfg.Detection.KernelExemptStores);
        Assert.Equal(3, cfg.Detection.KernelTrustedImages.Length);   // the null entry is dropped
        Assert.Empty(cfg.Detection.KernelTrustedImages[0].Stores);
        Assert.Equal(new[] { "electrum" }, cfg.Detection.KernelTrustedImages[1].Stores);
        Assert.Equal("", cfg.Detection.KernelTrustedImages[2].Image);
        Assert.Empty(cfg.Detection.KernelTrustedImages[2].Stores);

        File.WriteAllText(path, """{ "detection": { "kernelExemptStores": null, "kernelTrustedImages": null } }""");
        cfg = ConfigLoader.Load(path);
        Assert.Empty(cfg.Detection.KernelExemptStores);
        Assert.Empty(cfg.Detection.KernelTrustedImages);
    }

    [Fact]
    public void By_Default_Nothing_Is_Exempt_And_Nothing_Extra_Is_Trusted()
    {
        var d = new BruceConfig().Detection;
        Assert.False(d.KernelBlocking);
        Assert.Empty(d.KernelExemptStores);
        Assert.Empty(d.KernelTrustedImages);
    }
}
