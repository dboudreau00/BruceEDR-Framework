using BruceEDR.Configuration;
using BruceEDR.Detection;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>A watchlist <c>allow</c> entry, which the dashboard's Allow button writes.</summary>
public sealed partial class ScoringNoiseTests
{
    private static Watchlist Allow(params (string Match, string Value)[] entries)
        => Watchlist.Compile(entries.Select(e => new WatchlistEntryConfig { Match = e.Match, Value = e.Value, Action = "allow" }));

    [Fact]
    public void An_allow_entry_for_the_exact_path_stops_scoring_and_keeps_the_process_off_the_list()
    {
        const string Path = @"C:\Users\u\AppData\Local\Programs\Lively Wallpaper\Lively.exe";
        var list = Allow(("path", Path));
        var box = new Box(watchlist: () => list);
        box.Start(100, 4, "lively.exe", Path);
        for (int target = 300; target < 310; target++)
            Assert.Empty(box.Open(100, target, Inject));
        Assert.Equal(0, box.Score(100));
        Assert.False(box.Listed(100));
    }

    [Fact]
    public void Allowing_a_flagged_process_takes_it_off_the_list_and_removing_the_entry_brings_it_back()
    {
        Watchlist current = Watchlist.Empty;
        var box = new Box(watchlist: () => current);
        box.Start(100, 4, "tool.exe", @"C:\Tools\tool.exe");
        box.Open(100, 300, Inject);
        box.Open(100, 301, Inject);
        Assert.True(box.Listed(100));

        current = Allow(("path", @"C:\Tools\tool.exe"));
        Assert.Empty(box.Open(100, 302, Inject));       // the next signal sees the new list
        Assert.False(box.Listed(100));
        Assert.Equal(50, box.Score(100));               // nothing more was added

        current = Watchlist.Empty;
        box.Open(100, 303, Inject);
        Assert.True(box.Listed(100));
        Assert.Equal(75, box.Score(100));
    }

    [Fact]
    public void An_allow_hash_matches_the_file_wherever_it_is()
    {
        string sha = new('a', 64);
        var list = Allow(("hash", sha));
        Assert.Equal(WatchAction.Allow, list.Match("x.exe", @"C:\anywhere\x.exe", "", sha)!.Action);
    }

    [Fact]
    public void An_allow_path_matches_the_whole_path_and_nothing_under_or_beside_it()
    {
        var list = Allow(("path", @"C:\Tools\tool.exe"));
        Assert.NotNull(list.Match("tool.exe", @"C:\Tools\tool.exe", "", null));
        Assert.NotNull(list.Match("tool.exe", @"c:\tools\TOOL.EXE", "", null));
        Assert.Null(list.Match("tool.exe", @"C:\Tools\tool.exe.old", "", null));
        Assert.Null(list.Match("tool.exe", @"D:\Copy\C:\Tools\tool.exe", "", null));
    }

    [Theory]
    [InlineData("name", "lively.exe")]
    [InlineData("cmdline", "--service")]
    [InlineData("path", @"C:\Program Files\*")]
    [InlineData("path", "lively.exe")]
    public void An_allow_entry_must_name_one_exact_file(string match, string value)
    {
        var errors = new List<string>();
        var list = Watchlist.Compile(new[] { new WatchlistEntryConfig { Match = match, Value = value, Action = "allow" } }, errors.Add);
        Assert.Equal(0, list.Count);
        Assert.Single(errors);
    }
}
