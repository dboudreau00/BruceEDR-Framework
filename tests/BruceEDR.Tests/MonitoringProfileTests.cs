using System.Text.Json;
using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Detection;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The aggressive and neutral monitoring profiles. Neutral lets a program read a folder named after itself (an
/// Electron app's own cookies); both profiles still flag it for reading anyone else's.
/// </summary>
public sealed class MonitoringProfileTests
{
    private static readonly DateTime T0 = new(2026, 11, 24, 12, 0, 0, DateTimeKind.Utc);
    private const string BotExe = @"C:\Users\u\AppData\Local\Programs\Example Bot\Example Bot.exe";
    private const string OwnCookies = @"C:\Users\u\AppData\Roaming\Example Bot\Network\Cookies";
    private const string ChromeCookies = @"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies";
    private const string DiscordCookies = @"C:\Users\u\AppData\Roaming\discord\Network\Cookies";

    // ===================================================== who owns a folder

    [Theory]
    [InlineData("Example Bot.exe", BotExe, OwnCookies, true)]
    [InlineData("Example Bot.exe", "", OwnCookies, true)]                                   // named by the process alone
    [InlineData("examplebot.exe", "", @"C:\Users\u\AppData\Roaming\Example-Bot\Network\Cookies", true)]   // spaces and dashes do not matter
    [InlineData("Example Bot.exe", BotExe, @"C:\ProgramData\Example Bot\Session\Cookies", true)]
    [InlineData("Example Bot.exe", BotExe, ChromeCookies, false)]                           // a browser's store
    [InlineData("Example Bot.exe", BotExe, DiscordCookies, false)]                          // another app's store
    [InlineData("Example Bot.exe", BotExe, @"C:\Users\u\Documents\Example Bot\Network\Cookies", false)]   // not under AppData or ProgramData
    [InlineData("Example Bot.exe", BotExe, @"C:\Users\u\AppData\Roaming\Other\examplebot.sqlite", false)] // named like the file, not the folder
    [InlineData("tool.exe", @"C:\Tools\tool.exe", @"C:\Users\u\AppData\Roaming\Network\Cookies", false)] // generic folder names own nothing
    [InlineData("app.exe", @"C:\Program Files\App\app.exe", @"C:\Users\u\AppData\Roaming\app\Network\Cookies", false)] // too short to be a name
    [InlineData("", "", OwnCookies, false)]
    [InlineData("Example Bot.exe", BotExe, "", false)]
    public void A_program_owns_the_AppData_folder_named_after_it_and_no_other(string process, string image, string file, bool own)
        => Assert.Equal(own, OwnStores.IsOwn(process, image, file));

    [Fact]
    public void The_installed_folder_name_counts_when_the_executable_is_called_something_else()
    {
        const string Image = @"C:\Users\u\AppData\Local\Programs\Example Bot\launcher.exe";
        Assert.True(OwnStores.IsOwn("launcher.exe", Image, OwnCookies));
        Assert.False(OwnStores.IsOwn("launcher.exe", @"C:\Tools\launcher.exe", OwnCookies));
    }

    // ===================================================== the profiles

    [Theory]
    [InlineData(null, "aggressive")]
    [InlineData("", "aggressive")]
    [InlineData("balanced", "aggressive")]
    [InlineData("Aggressive", "aggressive")]
    [InlineData("neutral", "neutral")]
    [InlineData(" NEUTRAL ", "neutral")]
    public void A_missing_or_unknown_profile_is_the_behaviour_before_profiles(string? id, string expected)
        => Assert.Equal(expected, MonitoringProfiles.Normalize(id));

    [Fact]
    public void The_presets_fill_scores_that_the_config_accepts()
    {
        foreach (var preset in MonitoringProfiles.All)
        {
            Assert.InRange(preset.WarnAt, 1, 99);
            Assert.InRange(preset.ContainAt, preset.WarnAt + 1, 100);
            Assert.Equal(preset.Id == MonitoringProfiles.Neutral, preset.OwnStores);
        }
        Assert.Equal((40, 70), (MonitoringProfiles.AggressivePreset.WarnAt, MonitoringProfiles.AggressivePreset.ContainAt));   // today's defaults
        Assert.True(MonitoringProfiles.NeutralPreset.WarnAt > MonitoringProfiles.AggressivePreset.WarnAt);
    }

    [Fact]
    public void A_config_without_a_profile_loads_as_aggressive_and_one_with_neutral_keeps_it()
    {
        string dir = Path.Combine(Path.GetTempPath(), "bruce-profile-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string path = Path.Combine(dir, "bruce.config.json");
            File.WriteAllText(path, JsonSerializer.Serialize(new { detection = new { enableRuleEngine = false } }));
            Assert.Equal(MonitoringProfiles.Aggressive, ConfigLoader.Load(path).Detection.Profile);

            File.WriteAllText(path, JsonSerializer.Serialize(new { detection = new { profile = "Neutral" } }));
            var loaded = ConfigLoader.Load(path);
            Assert.Equal(MonitoringProfiles.Neutral, loaded.Detection.Profile);

            ConfigLoader.Save(loaded, path);
            Assert.Equal(MonitoringProfiles.Neutral, ConfigLoader.Load(path).Detection.Profile);
        }
        finally { try { Directory.Delete(dir, recursive: true); } catch { } }
    }

    // ===================================================== what the engine does with them

    private static RuleEngine ShippedRules()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "rules", "detection");
            if (Directory.Exists(probe) && Directory.GetFiles(probe, "*.json").Length > 0)
                return new RuleEngine(RuleEngine.LoadDirectory(probe));
        }
        throw new InvalidOperationException("the shipped rule packs were not found");
    }

    private static bool FlaggedForCookies(bool neutral, string file, string process = "Example Bot.exe", string image = BotExe)
    {
        var engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
        {
            Rules = ShippedRules(),
            OwnStoreExemption = () => neutral,
        });
        engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 100, ProcessName = process, ImagePath = image, TimestampUtc = T0 });
        engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 100, FilePath = file, Detail = "open", TimestampUtc = T0.AddSeconds(1) });
        var reasons = engine.SnapshotOne(100)?.Reasons ?? Array.Empty<string>();
        return reasons.Any(r => r.Contains("cookie store", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Aggressive_flags_a_program_reading_its_own_cookies_as_it_always_has()
        => Assert.True(FlaggedForCookies(neutral: false, OwnCookies));

    [Fact]
    public void Neutral_does_not_flag_a_program_reading_its_own_cookies()
        => Assert.False(FlaggedForCookies(neutral: true, OwnCookies));

    [Theory]
    [InlineData(ChromeCookies)]
    [InlineData(DiscordCookies)]
    public void Neutral_still_flags_the_same_program_reading_another_programs_cookies(string file)
        => Assert.True(FlaggedForCookies(neutral: true, file));

    [Fact]
    public void Neutral_does_not_excuse_a_program_for_a_folder_named_after_a_different_program()
        => Assert.True(FlaggedForCookies(neutral: true, OwnCookies, process: "stealer.exe", image: @"C:\Users\u\Downloads\stealer.exe"));

    [Fact]
    public void The_profile_is_read_on_every_signal_so_a_change_applies_live()
    {
        bool neutral = false;
        var engine = new DetectionEngine(new EngineOptions(), _ => false, new EngineDependencies
        {
            Rules = ShippedRules(),
            OwnStoreExemption = () => neutral,
        });
        engine.Ingest(new Signal { Kind = SignalKind.ProcessStart, Pid = 100, ProcessName = "Example Bot.exe", ImagePath = BotExe, TimestampUtc = T0 });
        neutral = true;
        engine.Ingest(new Signal { Kind = SignalKind.FileCreate, Pid = 100, FilePath = OwnCookies, Detail = "open", TimestampUtc = T0.AddSeconds(1) });
        Assert.Equal(0, engine.SnapshotOne(100)?.Score ?? 0);
    }
}
