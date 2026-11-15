namespace BruceEDR.Activity;

/// <summary>The lanes of the stacked timeline: kinds that read as one thing to a person.</summary>
public enum Lane { Processes, FileChanges, FileOpens, Network, System }

public sealed record Binned(DateTime StartUtc, TimeSpan Step, IReadOnlyList<int[]> Bins, int Peak)
{
    public int Count => Bins.Count;
    public DateTime EdgeOf(int bin) => StartUtc + TimeSpan.FromTicks(Step.Ticks * bin);
}

public sealed record Ranked(string Label, long Value, string Level, string Detail = "");

public sealed record Lifetime(ProcessInfo Process, double Start, double End, bool Open, int Depth);

public sealed record Slice(string Label, long Value, string Level);

public sealed record HeatCell(int Row, int Column, int Value);

public sealed record Heat(IReadOnlyList<string> Rows, int Columns, DateTime StartUtc, TimeSpan Step, IReadOnlyList<HeatCell> Cells, int Max);

public enum ProcessMetric { Events, FileChanges, Network, Score }

/// <summary>What the Insights charts draw, worked out from a snapshot: bins, rankings, lifetimes, a heatmap.</summary>
public static class InsightsData
{
    public static Lane LaneOf(ActivityKind k) => k switch
    {
        ActivityKind.ProcessStart or ActivityKind.ProcessStop or ActivityKind.ImageLoad => Lane.Processes,
        ActivityKind.FileCreate or ActivityKind.FileDelete or ActivityKind.FileRename => Lane.FileChanges,
        ActivityKind.FileOpen => Lane.FileOpens,
        ActivityKind.Network or ActivityKind.Dns => Lane.Network,
        _ => Lane.System
    };

    public static string Label(Lane l) => l switch
    {
        Lane.Processes => "Processes and modules",
        Lane.FileChanges => "Files made, moved, deleted",
        Lane.FileOpens => "Files opened",
        Lane.Network => "Network and DNS",
        _ => "Registry and system"
    };

    private static readonly long UnixEpochTicks = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

    private static DateTime FromSecond(long sec) => new(UnixEpochTicks + sec * TimeSpan.TicksPerSecond, DateTimeKind.Utc);

    /// <summary>The per-second counts regrouped into <paramref name="bins"/> equal slices of the session, one count per lane.</summary>
    public static Binned Bin(ActivitySnapshot snap, int bins)
    {
        bins = Math.Clamp(bins, 1, 600);
        var lanes = Enum.GetValues<Lane>().Length;
        if (snap.Series.Count == 0)
            return new Binned(snap.StartedUtc, TimeSpan.FromSeconds(1), Enumerable.Range(0, bins).Select(_ => new int[lanes]).ToList(), 0);

        long first = snap.Series[0].Second, last = snap.Series[^1].Second;
        long seconds = Math.Max(1, last - first + 1);
        double per = Math.Max(1.0, (double)seconds / bins);
        int n = (int)Math.Ceiling(seconds / per);
        var data = Enumerable.Range(0, n).Select(_ => new int[lanes]).ToList();
        foreach (var point in snap.Series)
        {
            int bin = Math.Min(n - 1, (int)((point.Second - first) / per));
            for (int k = 0; k < point.Counts.Count && k < ActivityKinds.Count; k++)
                data[bin][(int)LaneOf((ActivityKind)k)] += point.Counts[k];
        }
        int peak = data.Count == 0 ? 0 : data.Max(b => b.Sum());
        return new Binned(FromSecond(first), TimeSpan.FromSeconds(per), data, peak);
    }

    public static IReadOnlyList<Ranked> TopProcesses(ActivitySnapshot snap, ProcessMetric metric, int n)
    {
        long Of(ProcessInfo p) => metric switch
        {
            ProcessMetric.Score => p.PeakScore > 0 ? p.PeakScore : p.Score,
            ProcessMetric.Network => p.Count(ActivityKind.Network) + p.Count(ActivityKind.Dns),
            ProcessMetric.FileChanges => p.Count(ActivityKind.FileCreate) + p.Count(ActivityKind.FileDelete) + p.Count(ActivityKind.FileRename),
            _ => p.Counts.Sum(c => (long)c) - p.Count(ActivityKind.FileOpen) - p.Count(ActivityKind.ImageLoad)
        };
        return snap.Processes.Select(p => (p, v: Of(p))).Where(x => x.v > 0)
            .OrderByDescending(x => x.v).ThenBy(x => x.p.StartUtc).Take(n)
            .Select(x => new Ranked(x.p.Name.Length > 0 ? x.p.Name : $"pid {x.p.Pid}", x.v, x.p.Level, $"pid {x.p.Pid}")).ToList();
    }

    /// <summary>Process lifetimes as offsets in seconds from the session start, flagged and long-lived ones first, depth from the tree.</summary>
    public static IReadOnlyList<Lifetime> Lifetimes(ActivitySnapshot snap, int max)
    {
        if (snap.Processes.Count == 0) return Array.Empty<Lifetime>();
        var byId = snap.Processes.ToDictionary(p => p.Id);
        DateTime origin = snap.StartedUtc != default ? snap.StartedUtc : snap.Processes.Min(p => p.StartUtc);
        DateTime end = snap.EndedUtc > origin ? snap.EndedUtc : snap.Processes.Max(p => p.ExitUtc ?? p.StartUtc);

        int DepthOf(ProcessInfo p)
        {
            int d = 0;
            for (var up = p; up.ParentId != 0 && byId.TryGetValue(up.ParentId, out var parent) && d < 12; up = parent) d++;
            return d;
        }

        return snap.Processes
            .OrderByDescending(p => p.Flagged).ThenByDescending(p => ((p.ExitUtc ?? end) - p.StartUtc).TotalSeconds)
            .Take(Math.Max(1, max))
            .OrderBy(p => p.StartUtc).ThenBy(p => p.Id)
            .Select(p => new Lifetime(p, Math.Max(0, (p.StartUtc - origin).TotalSeconds),
                Math.Max(0, ((p.ExitUtc ?? end) - origin).TotalSeconds), p.ExitUtc is null, DepthOf(p)))
            .ToList();
    }

    public static IReadOnlyList<Slice> FileFates(ActivitySnapshot snap)
    {
        var c = FileMapBuilder.Count(snap);
        return new[]
        {
            new Slice(FileMapBuilder.Title(FileFate.Melted), c.Melted, "ember"),
            new Slice(FileMapBuilder.Title(FileFate.AfterRun), c.AfterRun, "watch"),
            new Slice(FileMapBuilder.Title(FileFate.Dropped), c.Dropped, "drop"),
            new Slice(FileMapBuilder.Title(FileFate.Deleted), c.Deleted, "deleted"),
            new Slice(FileMapBuilder.Title(FileFate.Renamed), c.Renamed, "renamed"),
            new Slice(FileMapBuilder.Title(FileFate.Created), c.Created, "created")
        }.Where(s => s.Value > 0).ToList();
    }

    public static IReadOnlyList<Ranked> Extensions(ActivitySnapshot snap, int n)
        => snap.Files.Where(f => !f.Noisy).GroupBy(f => f.Ext.Length == 0 ? "(none)" : f.Ext)
            .Select(g => new Ranked(g.Key, g.Count(), g.Any(f => f.IsMelted) ? "ember" : g.Any(f => f.Dropped) ? "drop" : "info",
                $"{g.Count(f => f.Deleted)} deleted"))
            .OrderByDescending(r => r.Value).ThenBy(r => r.Label, StringComparer.OrdinalIgnoreCase).Take(n).ToList();

    public static IReadOnlyList<Ranked> Top(IReadOnlyList<Destination> list, int n, string level = "info")
        => list.Take(n).Select(d => new Ranked(d.Name, d.Count, level)).ToList();

    /// <summary>Activity kinds against time: how busy each kind was when. Only kinds that happened get a row.</summary>
    public static Heat Heatmap(ActivitySnapshot snap, int columns)
    {
        columns = Math.Clamp(columns, 1, 240);
        var kinds = Enum.GetValues<ActivityKind>().Where(k => snap.Total(k) > 0).ToList();
        if (kinds.Count == 0 || snap.Series.Count == 0)
            return new Heat(Array.Empty<string>(), columns, snap.StartedUtc, TimeSpan.FromSeconds(1), Array.Empty<HeatCell>(), 0);

        long first = snap.Series[0].Second, last = snap.Series[^1].Second;
        double per = Math.Max(1.0, (double)Math.Max(1, last - first + 1) / columns);
        int n = (int)Math.Ceiling(Math.Max(1, last - first + 1) / per);
        var grid = new int[kinds.Count, n];
        foreach (var point in snap.Series)
        {
            int col = Math.Min(n - 1, (int)((point.Second - first) / per));
            for (int r = 0; r < kinds.Count; r++)
                if ((int)kinds[r] < point.Counts.Count) grid[r, col] += point.Counts[(int)kinds[r]];
        }
        var cells = new List<HeatCell>();
        int max = 0;
        for (int r = 0; r < kinds.Count; r++)
            for (int c = 0; c < n; c++)
                if (grid[r, c] > 0) { cells.Add(new HeatCell(r, c, grid[r, c])); max = Math.Max(max, grid[r, c]); }
        return new Heat(kinds.Select(ActivityKinds.Label).ToList(), n, FromSecond(first), TimeSpan.FromSeconds(per), cells, max);
    }
}

/// <summary>A chart's value axis: whole-number steps from the 1-2-5 series, so the labels read 0, 2, 4, 6 and the top gridline is a label too.</summary>
public static class AxisScale
{
    /// <summary>The step between gridlines and the top of the axis (a multiple of the step at or above the peak).</summary>
    public static (int Step, int Top) Nice(int peak, int maxSteps = 4)
    {
        peak = Math.Max(1, peak);
        maxSteps = Math.Max(1, maxSteps);
        for (long magnitude = 1; magnitude < int.MaxValue / 10; magnitude *= 10)
            foreach (int m in new[] { 1, 2, 5 })
            {
                long step = m * magnitude;
                if (peak <= step * maxSteps)
                    return ((int)step, (int)(((peak + step - 1) / step) * step));
            }
        return (peak, peak);
    }
}
