using BruceEDR.Activity;
using BruceEDR.Core;
using Xunit;

namespace BruceEDR.Tests;

public sealed class InsightsDataTests
{
    private static readonly DateTime T0 = new(2026, 11, 14, 12, 0, 0, DateTimeKind.Utc);

    private static Signal Start(int pid, int ppid, string name, double at)
        => new() { Kind = SignalKind.ProcessStart, Pid = pid, ParentPid = ppid, ProcessName = name, TimestampUtc = T0.AddSeconds(at) };
    private static Signal Stop(int pid, double at) => new() { Kind = SignalKind.ProcessStop, Pid = pid, TimestampUtc = T0.AddSeconds(at) };
    private static Signal Create(int pid, string path, double at, string detail = "create")
        => new() { Kind = SignalKind.FileCreate, Pid = pid, FilePath = path, Detail = detail, TimestampUtc = T0.AddSeconds(at) };
    private static Signal Net(int pid, string ip, double at)
        => new() { Kind = SignalKind.NetworkConnect, Pid = pid, RemoteAddress = ip, RemotePort = 443, TimestampUtc = T0.AddSeconds(at) };

    private static ActivitySnapshot Snap(params Signal[] signals)
    {
        var m = new ActivityModel();
        foreach (var s in signals) m.Observe(s);
        return m.Snapshot();
    }

    [Theory]
    [InlineData(0, 1, 1)]
    [InlineData(1, 1, 1)]
    [InlineData(4, 1, 4)]
    [InlineData(5, 2, 6)]
    [InlineData(9, 5, 10)]
    [InlineData(10, 5, 10)]
    [InlineData(41, 20, 60)]
    [InlineData(1000, 500, 1000)]
    public void The_value_axis_steps_in_whole_numbers_from_the_one_two_five_series(int peak, int step, int top)
    {
        var (s, t) = AxisScale.Nice(peak);
        Assert.Equal(step, s);
        Assert.Equal(top, t);
        Assert.True(t >= peak && t % s == 0 && t / s <= 4 + 1);
    }

    [Fact]
    public void Binning_regroups_the_seconds_into_the_lanes_and_loses_nothing()
    {
        var snap = Snap(Start(1, 0, "a.exe", 0), Create(1, @"C:\x\a.bin", 1), Create(1, @"C:\x\r.dat", 2, "open"), Net(1, "10.0.0.1", 3), Net(1, "10.0.0.1", 9));
        var b = InsightsData.Bin(snap, 5);

        int lane(Lane l) => b.Bins.Sum(x => x[(int)l]);
        Assert.Equal(1, lane(Lane.Processes));
        Assert.Equal(1, lane(Lane.FileChanges));
        Assert.Equal(1, lane(Lane.FileOpens));
        Assert.Equal(2, lane(Lane.Network));
        Assert.Equal(5, b.Bins.Sum(x => x.Sum()));
        Assert.True(b.Peak >= 1);
        Assert.Equal(T0, b.StartUtc);
    }

    [Fact]
    public void Fewer_seconds_than_bins_gives_one_bin_per_second_and_an_empty_session_gives_empty_bins()
    {
        var b = InsightsData.Bin(Snap(Start(1, 0, "a.exe", 0), Start(2, 0, "b.exe", 3)), 60);
        Assert.Equal(4, b.Count);
        Assert.Equal(TimeSpan.FromSeconds(1), b.Step);

        var empty = InsightsData.Bin(ActivitySnapshot.Empty, 10);
        Assert.Equal(10, empty.Count);
        Assert.Equal(0, empty.Peak);
    }

    [Fact]
    public void Top_processes_rank_by_the_chosen_metric_and_leave_out_zeros()
    {
        var snap = Snap(
            Start(1, 0, "chatty.exe", 0), Start(2, 0, "quiet.exe", 0), Start(3, 0, "net.exe", 0),
            Create(1, @"C:\a", 1), Create(1, @"C:\b", 2), Create(1, @"C:\c", 3), Create(2, @"C:\d", 4),
            Net(3, "1.1.1.1", 5), Net(3, "1.1.1.1", 6));

        var files = InsightsData.TopProcesses(snap, ProcessMetric.FileChanges, 5);
        Assert.Equal(new[] { "chatty.exe", "quiet.exe" }, files.Select(r => r.Label));
        Assert.Equal(new long[] { 3, 1 }, files.Select(r => r.Value));
        Assert.Equal("net.exe", InsightsData.TopProcesses(snap, ProcessMetric.Network, 5).Single().Label);
        Assert.Empty(InsightsData.TopProcesses(snap, ProcessMetric.Score, 5));
    }

    [Fact]
    public void Lifetimes_are_offsets_from_the_start_with_flagged_processes_kept_when_cut()
    {
        var snap = Snap(Start(1, 0, "a.exe", 0), Start(2, 1, "b.exe", 2), Stop(2, 7), Start(3, 1, "c.exe", 3), Start(4, 0, "d.exe", 4));
        snap = snap with { Processes = snap.Processes.Select(p => p.Pid == 4 ? p with { Level = "threat", Score = 90 } : p).ToList() };
        var rows = InsightsData.Lifetimes(snap, max: 2);

        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, r => r.Process.Pid == 4);
        var all = InsightsData.Lifetimes(snap, max: 10);
        var b = all.Single(r => r.Process.Pid == 2);
        Assert.Equal(2, b.Start, 6);
        Assert.Equal(7, b.End, 6);
        Assert.False(b.Open);
        Assert.Equal(1, b.Depth);
        Assert.True(all.Single(r => r.Process.Pid == 1).Open);
    }

    [Fact]
    public void The_file_mix_and_extension_ranking_describe_only_the_files_that_count()
    {
        const string Cache = @"C:\u\AppData\Local\Google\Chrome\User Data\Default\Cache\f1";
        var snap = Snap(Start(1, 0, "a.exe", 0), Create(1, @"C:\x\a.exe", 1), Create(1, @"C:\x\b.exe", 2), Create(1, @"C:\x\c.txt", 3), Create(1, Cache, 4));
        var mix = InsightsData.FileFates(snap);
        var ext = InsightsData.Extensions(snap, 5);

        Assert.Equal(3, mix.Single().Value);
        Assert.Equal(".exe", ext[0].Label);
        Assert.Equal(2, ext[0].Value);
        Assert.DoesNotContain(ext, e => e.Label == "(none)");
    }

    [Fact]
    public void The_heatmap_has_a_row_per_kind_that_happened_and_a_cell_where_it_did()
    {
        var snap = Snap(Start(1, 0, "a.exe", 0), Create(1, @"C:\x\a", 10), Create(1, @"C:\x\b", 10.5), Net(1, "10.0.0.1", 20));
        var h = InsightsData.Heatmap(snap, 21);

        Assert.Equal(3, h.Rows.Count);
        Assert.Contains("Network", h.Rows);
        Assert.Equal(2, h.Max);
        var created = h.Cells.Where(c => h.Rows[c.Row] == "File created").ToList();
        Assert.Single(created);
        Assert.Equal(2, created[0].Value);
        Assert.Empty(InsightsData.Heatmap(ActivitySnapshot.Empty, 10).Rows);
    }

    [Fact]
    public void A_destination_list_becomes_a_ranking()
    {
        var snap = Snap(Net(1, "10.0.0.1", 1), Net(1, "10.0.0.1", 2), Net(1, "10.0.0.2", 3));
        var top = InsightsData.Top(snap.Destinations, 5);

        Assert.Equal("10.0.0.1:443", top[0].Label);
        Assert.Equal(2, top[0].Value);
    }
}
