using BruceEDR.Monitoring;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>The kernel file monitor's decisions, apart from the trace session.</summary>
public sealed class FileEventsTests
{
    [Theory]
    [InlineData(0, "create")]    // supersede
    [InlineData(1, "open")]      // open existing
    [InlineData(2, "create")]    // create new
    [InlineData(3, "open")]      // open always: cannot tell
    [InlineData(4, "create")]    // truncate
    [InlineData(5, "create")]    // create always
    public void The_create_detail_follows_the_disposition(int disposition, string expected)
        => Assert.Equal(expected, FileEvents.CreateDetail(disposition));

    [Theory]
    [InlineData(0x1000u, true)]
    [InlineData(0x1020u, true)]
    [InlineData(0x0020u, false)]
    [InlineData(0u, false)]
    public void Delete_on_close_is_the_nt_option_bit(uint options, bool expected)
        => Assert.Equal(expected, FileEvents.IsDeleteOnClose(options));

    [Fact]
    public void The_name_cache_returns_what_it_stored_and_never_another_files_name()
    {
        var cache = new FileNameCache(slots: 16);
        cache.Put(0x1000, @"C:\a.exe");
        cache.Put(0x2000, @"C:\b.exe");
        Assert.Equal(@"C:\a.exe", cache.Get(0x1000));
        Assert.Null(cache.Get(0x3000));
        Assert.Null(cache.Get(0));

        // Fill every slot with other objects: a collided key is a miss, not someone else's name.
        for (ulong k = 0x10_0000; k < 0x10_0000 + 16 * 16; k += 16) cache.Put(k, "x" + k);
        Assert.True(cache.Get(0x1000) is null or @"C:\a.exe");
        Assert.Throws<ArgumentException>(() => new FileNameCache(slots: 12));
    }

    [Theory]
    [InlineData(@"C:\Users\u\Downloads\a.exe", true)]
    [InlineData(@"C:\Users\u\Downloads\loot.ZIP", true)]
    [InlineData(@"C:\Users\u\Downloads\run.PS1", true)]
    [InlineData(@"C:\Users\u\AppData\Local\Temp\tmp8F2.tmp", false)]
    [InlineData(@"C:\Users\u\notes.txt", false)]
    [InlineData("", false)]
    public void The_folder_watcher_reports_only_the_kinds_of_file_an_intrusion_drops_runs_or_stages(string path, bool watched)
        => Assert.Equal(watched, FileEvents.IsWatched(path));

    [Theory]
    [InlineData(2, 0x0, "create")]
    [InlineData(1, 0x0, "open")]
    [InlineData(1, 0x1, "dir")]      // FILE_DIRECTORY_FILE: a folder being listed
    [InlineData(2, 0x1021, "dir")]   // a directory made, whatever else the open asked for
    [InlineData(2, 0x1000, "create")] // delete-on-close is about the file, not a directory
    public void A_directory_open_is_told_apart_from_a_file_open(int disposition, uint options, string detail)
        => Assert.Equal(detail, FileEvents.CreateDetail(disposition, options));
}
