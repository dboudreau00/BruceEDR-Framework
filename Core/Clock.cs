namespace BruceEDR.Core;

/// <summary>
/// Injectable time source. The detection engine, beacon analyzer and score-decay
/// logic all read time through this, so a replayed trace or a unit test can drive
/// hours of behaviour deterministically in milliseconds instead of sleeping.
/// </summary>
public interface IClock
{
    DateTime UtcNow { get; }
}

/// <summary>Real wall clock. The default everywhere outside tests and replay.</summary>
public sealed class SystemClock : IClock
{
    public static readonly SystemClock Instance = new();
    public DateTime UtcNow => DateTime.UtcNow;
}

/// <summary>
/// Manually advanced clock. Thread-safe because replay feeds the engine from one
/// thread while assertions may read the clock from another.
/// </summary>
public sealed class ManualClock : IClock
{
    private long _ticks;

    public ManualClock(DateTime startUtc) => _ticks = startUtc.ToUniversalTime().Ticks;

    public ManualClock() : this(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)) { }

    public DateTime UtcNow => new(Interlocked.Read(ref _ticks), DateTimeKind.Utc);

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);

    public void Set(DateTime utc) => Interlocked.Exchange(ref _ticks, utc.ToUniversalTime().Ticks);
}
