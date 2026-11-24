using BruceEDR.Configuration;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>"Set up again": the set-up choices go back to a fresh install's, the rest of the config stays, and a backup is made first.</summary>
public sealed class SetupResetTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bruce-reset-" + Guid.NewGuid().ToString("N"));
    private string ConfigPath => Path.Combine(_dir, "bruce.config.json");

    public SetupResetTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private static WatchlistEntryConfig Entry(string value, string action, string note)
        => new() { Match = "path", Value = value, Action = action, Note = note };

    /// <summary>A config an operator has tuned: enforce, neutral, own scores, extra publishers, their own rules and trust marks.</summary>
    private void WriteTunedConfig()
    {
        var c = new BruceConfig();
        c.Response.Mode = ResponseModes.Enforce;
        c.Detection.Profile = MonitoringProfiles.Neutral;
        c.Detection.WarnThreshold = 55;
        c.Detection.QuarantineThreshold = 85;
        c.Detection.TrustDiscount = 20;
        c.Allowlist.Publishers = new[] { "Microsoft Windows", "Example Corp" };
        c.Telemetry.JsonlPath = Path.Combine(_dir, "my-incidents.jsonl");
        c.Watchlist.Entries = new[]
        {
            Entry(@"C:\Tools\mimikatz.exe", "quarantine", "red-team tooling"),
            Entry(@"C:\Program Files\A\a.exe", "allow", "[baseline] Trusted by path (A)"),
            Entry(@"C:\Program Files\B\b.exe", "quarantine", "[baseline] Marked untrusted during setup (B)"),
            Entry(new string('a', 64), "allow", @"C:\Users\u\x.exe, Allowed from the dashboard on 2026-11-24"),
        };
        ConfigLoader.Save(c, ConfigPath);
    }

    [Fact]
    public void The_set_up_choices_go_back_to_a_fresh_install_and_nothing_else_moves()
    {
        WriteTunedConfig();

        SetupReset.Run(ConfigPath, clearTrustMarks: false);

        var c = ConfigLoader.Load(ConfigPath);
        Assert.Equal(ResponseModes.Monitor, c.Response.Mode);
        Assert.Equal(MonitoringProfiles.Aggressive, c.Detection.Profile);
        Assert.Equal((40, 70), (c.Detection.WarnThreshold, c.Detection.QuarantineThreshold));
        Assert.Equal(new BruceConfig().Allowlist.Publishers, c.Allowlist.Publishers);
        // Not set-up choices: left alone.
        Assert.Equal(20, c.Detection.TrustDiscount);
        Assert.Equal(Path.Combine(_dir, "my-incidents.jsonl"), c.Telemetry.JsonlPath);
        Assert.Equal(4, c.Watchlist.Entries.Length);
    }

    [Fact]
    public void Clearing_trust_marks_removes_the_baseline_and_dashboard_ones_but_never_the_operators_own_rule()
    {
        WriteTunedConfig();

        var result = SetupReset.Run(ConfigPath, clearTrustMarks: true);

        Assert.Equal(3, result.TrustEntriesRemoved);
        var left = ConfigLoader.Load(ConfigPath).Watchlist.Entries;
        var only = Assert.Single(left);
        Assert.Equal(@"C:\Tools\mimikatz.exe", only.Value);
        Assert.Equal("quarantine", only.Action);
    }

    [Fact]
    public void An_operators_allow_entry_without_a_trust_mark_note_is_not_cleared()
    {
        var c = new BruceConfig();
        c.Watchlist.Entries = new[] { Entry(@"C:\Tools\backup.exe", "allow", "approved by the security officer") };
        ConfigLoader.Save(c, ConfigPath);

        var result = SetupReset.Run(ConfigPath, clearTrustMarks: true);

        Assert.Equal(0, result.TrustEntriesRemoved);
        Assert.Single(ConfigLoader.Load(ConfigPath).Watchlist.Entries);
    }

    [Fact]
    public void The_old_config_is_copied_first_under_a_dated_name_and_a_second_reset_does_not_overwrite_it()
    {
        WriteTunedConfig();
        string before = File.ReadAllText(ConfigPath);
        var moment = new DateTime(2026, 11, 24, 15, 30, 5);

        var first = SetupReset.Run(ConfigPath, clearTrustMarks: false, moment);
        var second = SetupReset.Run(ConfigPath, clearTrustMarks: false, moment);

        Assert.EndsWith(".bak-20261124-153005", first.BackupPath);
        Assert.Equal(before, File.ReadAllText(first.BackupPath));            // the tuned config, byte for byte
        Assert.NotEqual(first.BackupPath, second.BackupPath);                 // the first backup survives
        Assert.True(File.Exists(first.BackupPath) && File.Exists(second.BackupPath));
    }

    [Fact]
    public void A_config_that_cannot_be_read_is_left_alone_and_no_backup_is_made()
    {
        File.WriteAllText(ConfigPath, "{ this is not json");

        Assert.ThrowsAny<Exception>(() => SetupReset.Run(ConfigPath, clearTrustMarks: true));

        Assert.Equal("{ this is not json", File.ReadAllText(ConfigPath));
        Assert.Empty(Directory.GetFiles(_dir, "*.bak-*"));
    }

    [Fact]
    public void The_note_the_dashboard_writes_is_the_one_the_reset_looks_for()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        string? source = null;
        for (int i = 0; i < 10 && dir is not null && source is null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "gui", "BruceEDR.Gui", "ViewModels", "WatchlistViewModel.cs");
            if (File.Exists(probe)) source = File.ReadAllText(probe);
        }
        Assert.NotNull(source);
        Assert.Contains(SetupReset.DashboardAllowNote + " on ", source);
        // ...and the baseline scan's tag is the shared constant, not a second copy.
        Assert.Contains("SetupReset.BaselineNoteTag", File.ReadAllText(FindFile("Security", "BaselineScanner.cs")));
    }

    private static string FindFile(params string[] parts)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 10 && dir is not null; i++, dir = dir.Parent)
        {
            var probe = Path.Combine(new[] { dir.FullName }.Concat(parts).ToArray());
            if (File.Exists(probe)) return probe;
        }
        throw new FileNotFoundException(string.Join("/", parts));
    }
}
