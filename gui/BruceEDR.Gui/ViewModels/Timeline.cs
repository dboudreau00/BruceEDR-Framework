namespace BruceEDR.Gui.ViewModels;

/// <summary>Event counts for one slice of the activity timeline.</summary>
public sealed record ActivityBucket(DateTime StartLocal, int Threat, int Warn, int Action, int Info)
{
    public int Total => Threat + Warn + Action + Info;
}

/// <summary>
/// Rolling per-level event counts in fixed-width slices, newest last. Counting happens as
/// events arrive, including while the feed is paused, so the chart shows what happened rather
/// than what was on screen.
/// </summary>
public sealed class ActivityTimeline
{
    public const int SliceCount = 80;
    public static readonly TimeSpan SliceWidth = TimeSpan.FromSeconds(3);

    private readonly int[,] _counts = new int[SliceCount, 4];
    private long _newestSlice = long.MinValue;

    public void Record(string level, DateTime utc)
    {
        long slice = SliceOf(utc);
        Advance(slice);
        long age = _newestSlice - slice;
        if (age < 0 || age >= SliceCount) return;
        int lane = level switch
        {
            "QUARANTINE" or "ERROR" => 0,
            "WARN" => 1,
            "ACTION" => 2,
            _ => 3,
        };
        _counts[Index(slice), lane]++;
    }

    /// <summary>Oldest first, ending at the slice that contains <paramref name="nowUtc"/>.</summary>
    public ActivityBucket[] Snapshot(DateTime nowUtc)
    {
        Advance(SliceOf(nowUtc));
        var result = new ActivityBucket[SliceCount];
        for (int i = 0; i < SliceCount; i++)
        {
            long slice = _newestSlice - (SliceCount - 1 - i);
            int ix = Index(slice);
            var start = new DateTime(slice * SliceWidth.Ticks, DateTimeKind.Utc).ToLocalTime();
            result[i] = new ActivityBucket(start, _counts[ix, 0], _counts[ix, 1], _counts[ix, 2], _counts[ix, 3]);
        }
        return result;
    }

    public void Clear()
    {
        Array.Clear(_counts);
        _newestSlice = long.MinValue;
    }

    private static long SliceOf(DateTime utc) => utc.ToUniversalTime().Ticks / SliceWidth.Ticks;

    private static int Index(long slice) => (int)(((slice % SliceCount) + SliceCount) % SliceCount);

    private void Advance(long slice)
    {
        if (_newestSlice == long.MinValue) { _newestSlice = slice; return; }
        if (slice <= _newestSlice) return;
        long steps = Math.Min(slice - _newestSlice, SliceCount);
        for (long s = 1; s <= steps; s++)
        {
            int ix = Index(_newestSlice + s);
            for (int lane = 0; lane < 4; lane++) _counts[ix, lane] = 0;
        }
        _newestSlice = slice;
    }
}
