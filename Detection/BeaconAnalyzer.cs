using System.Globalization;
using BruceEDR.Core;

namespace BruceEDR.Detection;

/// <summary>
/// The result of testing one (process, destination) pair for beacon-like cadence.
/// </summary>
/// <remarks>
/// Every numeric field is finite and JSON-safe on purpose: these verdicts are
/// serialised into <c>BruceEvent</c> and the API, and <c>System.Text.Json</c>
/// throws on <c>NaN</c>/<c>Infinity</c> by default. <see cref="JitterRatio"/> is
/// therefore clamped rather than allowed to diverge.
/// </remarks>
public sealed record BeaconVerdict
{
    /// <summary>Normalised destination, e.g. <c>203.0.113.10:443</c>. Lower-cased and trimmed.</summary>
    public required string Endpoint { get; init; }

    /// <summary>Number of observations inside the analysis window (not the lifetime total).</summary>
    public required int Connections { get; init; }

    /// <summary>Median inter-arrival gap. <see cref="TimeSpan.Zero"/> when fewer than two samples.</summary>
    public required TimeSpan MedianInterval { get; init; }

    /// <summary>
    /// Median absolute deviation of the inter-arrival gaps divided by the median gap:
    /// 0 is a perfect metronome, 0.25 means the typical gap strays a quarter of the
    /// period. Clamped to <see cref="MaxReportedJitter"/> so the value stays finite.
    /// </summary>
    public required double JitterRatio { get; init; }

    /// <summary>0..1. See <see cref="BeaconAnalyzer"/> for the exact formula.</summary>
    public required double Confidence { get; init; }

    /// <summary>True only when the sample count, the cadence band and the jitter gate all pass.</summary>
    public required bool IsBeaconing { get; init; }

    /// <summary>Analyst-facing sentence explaining the verdict, including why it did NOT fire.</summary>
    public required string Explanation { get; init; }

    /// <summary>Earliest observation inside the window.</summary>
    public required DateTime FirstUtc { get; init; }

    /// <summary>Latest observation inside the window; also the window anchor.</summary>
    public required DateTime LastUtc { get; init; }
}

/// <summary>
/// Detects command-and-control beaconing: a process that contacts the same
/// destination on a regular cadence.
///
/// WHY A ROBUST DISPERSION MEASURE, NOT "EQUAL INTERVALS":
/// no real implant sleeps for exactly N seconds. Cobalt Strike, Sliver, Havoc and
/// friends all apply a jitter percentage to the sleep, and the network adds its own
/// noise, so an equality test (or even a standard deviation test) fails. Standard
/// deviation is additionally useless here because a single missed check-in doubles
/// one gap, and one such outlier is enough to blow up a mean-based statistic. We
/// therefore use the MEDIAN inter-arrival gap and the MEDIAN ABSOLUTE DEVIATION
/// around it: both have a 50% breakdown point, so half the samples can be garbage
/// (retries, a laptop lid closing, an operator issuing interactive tasks) and the
/// estimate still describes the underlying sleep interval.
///
/// WHAT THIS CANNOT DO -- read before trusting it:
///  * An implant that randomises its sleep uniformly over a wide range (say 30s to
///    600s) has a MAD/median near 0.35-0.5 and simply will not trip the gate. This
///    is a known, cheap and widely deployed evasion; the analyzer is a cost imposer,
///    not a guarantee.
///  * A long-sleep beacon (24h check-ins) never accumulates <c>minConnections</c>
///    samples inside the window, so it is invisible by construction. Widening the
///    window trades detection latency and memory for that coverage.
///  * Domain fronting, CDN reuse and pooled proxies mean many implants never present
///    a stable endpoint string at all. Series are keyed on the endpoint as the caller
///    reports it; if the caller reports a rotating IP, nothing here correlates them.
///  * Plenty of benign software beacons perfectly: update checkers, telemetry agents,
///    NTP, monitoring probes, IMAP idle refreshes. A positive verdict is a lead that
///    must be joined with process reputation and destination reputation, which is why
///    this class scores nothing on its own and returns evidence instead of a verdict
///    the responder acts on.
///
/// THREADING: not thread-safe, by deliberate design. Like <c>DetectionEngine</c>'s
/// profile store this is owned by the single detection thread, so it carries no locks.
///
/// TIME: never reads <c>DateTime.UtcNow</c>. Observations carry their own timestamp and
/// the injected <see cref="IClock"/> is used only by <see cref="Prune"/>, so a replayed
/// trace analyses byte-identically to a live run.
/// </summary>
public sealed class BeaconAnalyzer
{
    /// <summary>
    /// Jitter ceiling for a positive verdict. 0.25 corresponds roughly to the
    /// "20-30% jitter" default that off-the-shelf C2 frameworks ship with, which is
    /// where the useful part of the ROC curve sits: tighter and common implant presets
    /// slip through, looser and ordinary bursty user traffic starts to qualify.
    /// </summary>
    public const double JitterThreshold = 0.25;

    /// <summary>Shortest median cadence that can be a beacon. Below this it is a burst, not a schedule.</summary>
    public static readonly TimeSpan MinBeaconInterval = TimeSpan.FromSeconds(1);

    /// <summary>Longest median cadence that can be a beacon within a practical window.</summary>
    public static readonly TimeSpan MaxBeaconInterval = TimeSpan.FromHours(24);

    /// <summary>Upper bound reported for <see cref="BeaconVerdict.JitterRatio"/>, keeping it finite.</summary>
    public const double MaxReportedJitter = 10.0;

    /// <summary>Timestamps retained per series. 256 samples of a 60s beacon is over four hours of history.</summary>
    private const int SeriesCapacity = 256;

    /// <summary>Extra samples past the minimum at which the sample-count term saturates.</summary>
    private const double SampleSaturation = 12.0;

    private readonly IClock _clock;
    private readonly int _minConnections;
    private readonly TimeSpan _window;
    private readonly int _maxEndpointsPerPid;

    private readonly Dictionary<int, Dictionary<string, Series>> _byPid = new();

    /// <param name="clock">Time source. Used only by <see cref="Prune"/>; analysis is data-driven.</param>
    /// <param name="minConnections">
    /// Samples required before a cadence claim is made. Floored at 3, because two
    /// samples yield a single gap, and a single gap has no dispersion to measure --
    /// reporting "0% jitter" off one interval would be a confident lie.
    /// </param>
    /// <param name="window">
    /// How far back from the newest sample the analysis looks. Defaults to 24h, which
    /// covers the hourly-to-minutely cadences that dominate real implant configs.
    /// </param>
    /// <param name="maxTrackedEndpointsPerPid">
    /// Per-process series cap. Bounds memory against a process that touches thousands
    /// of destinations (a browser, a scanner) at the cost of a real evasion: an
    /// attacker who sprays more than this many distinct endpoints evicts the genuine
    /// beacon series. The cap is a memory-safety control, not a detection control.
    /// </param>
    public BeaconAnalyzer(IClock clock, int minConnections = 6, TimeSpan? window = null, int maxTrackedEndpointsPerPid = 64)
    {
        _clock = clock;
        _minConnections = Math.Max(3, minConnections);
        var w = window ?? TimeSpan.FromHours(24);
        // Clamp rather than throw: a bad config value must degrade the analyzer, not
        // take the sensor down. One second is the smallest window that can hold a
        // measurable cadence; 30 days is past any sane retention for in-memory series.
        if (w < TimeSpan.FromSeconds(1)) w = TimeSpan.FromSeconds(1);
        if (w > TimeSpan.FromDays(30)) w = TimeSpan.FromDays(30);
        _window = w;
        _maxEndpointsPerPid = Math.Max(1, maxTrackedEndpointsPerPid);
    }

    /// <summary>Total number of (pid, endpoint) series currently held, across all processes.</summary>
    public int TrackedSeries
    {
        get
        {
            int n = 0;
            foreach (var series in _byPid.Values) n += series.Count;
            return n;
        }
    }

    /// <summary>
    /// Record one connection. Cheap and allocation-free on the hot path once the series
    /// exists. Malformed input (non-positive pid, blank endpoint) is dropped silently:
    /// a monitor that occasionally cannot attribute a socket must not be able to throw
    /// out of the detection thread.
    ///
    /// Note there is no global cap on the number of tracked PIDs. The owner is expected
    /// to call <see cref="Forget"/> on process exit and <see cref="Prune"/> periodically;
    /// without either, memory grows with the number of processes ever observed.
    /// </summary>
    public void Observe(int pid, string endpoint, DateTime whenUtc)
    {
        if (pid <= 0) return;
        string key = Normalize(endpoint);
        if (key.Length == 0) return;

        if (!_byPid.TryGetValue(pid, out var series))
            _byPid[pid] = series = new Dictionary<string, Series>(StringComparer.Ordinal);

        if (!series.TryGetValue(key, out var s))
        {
            if (series.Count >= _maxEndpointsPerPid) EvictLeastRecent(series);
            series[key] = s = new Series();
        }

        s.Add(ToUtcTicks(whenUtc));
    }

    /// <summary>
    /// Verdicts for every destination tracked for <paramref name="pid"/>, including the
    /// negative ones -- an analyst asking "is this thing beaconing" is served better by
    /// "12 connections, 87% jitter, no" than by an empty list. Ordered most interesting
    /// first (confidence, then sample count, then endpoint) so the ordering is stable
    /// across runs. Unknown pid yields an empty list, never null.
    /// </summary>
    public IReadOnlyList<BeaconVerdict> Analyze(int pid)
    {
        if (!_byPid.TryGetValue(pid, out var series) || series.Count == 0)
            return Array.Empty<BeaconVerdict>();

        var list = new List<BeaconVerdict>(series.Count);
        foreach (var (endpoint, s) in series) list.Add(Judge(endpoint, s));

        list.Sort(static (a, b) =>
        {
            int c = b.Confidence.CompareTo(a.Confidence);
            if (c != 0) return c;
            c = b.Connections.CompareTo(a.Connections);
            if (c != 0) return c;
            return string.CompareOrdinal(a.Endpoint, b.Endpoint);
        });
        return list;
    }

    /// <summary>
    /// Verdict for one destination, or null when nothing has ever been observed for that
    /// (pid, endpoint). Null means "no data"; a verdict with <c>IsBeaconing == false</c>
    /// means "data, but not a beacon" -- callers must not conflate the two.
    /// </summary>
    public BeaconVerdict? AnalyzeEndpoint(int pid, string endpoint)
    {
        string key = Normalize(endpoint);
        if (key.Length == 0) return null;
        if (!_byPid.TryGetValue(pid, out var series)) return null;
        return series.TryGetValue(key, out var s) ? Judge(key, s) : null;
    }

    /// <summary>Drop every series for a process. Call on ProcessStop, and on PID reuse.</summary>
    public void Forget(int pid) => _byPid.Remove(pid);

    /// <summary>
    /// Drop series whose newest sample is older than <paramref name="olderThan"/> relative
    /// to the injected clock. This is the only clock-dependent method in the class.
    /// </summary>
    public void Prune(TimeSpan olderThan)
    {
        if (olderThan < TimeSpan.Zero) olderThan = TimeSpan.Zero;
        long cutoff = _clock.UtcNow.Ticks - olderThan.Ticks;

        List<int>? emptyPids = null;
        foreach (var (pid, series) in _byPid)
        {
            List<string>? dead = null;
            foreach (var (endpoint, s) in series)
                if (s.NewestTicks < cutoff) (dead ??= new List<string>()).Add(endpoint);

            if (dead is not null)
                foreach (var e in dead) series.Remove(e);

            if (series.Count == 0) (emptyPids ??= new List<int>()).Add(pid);
        }

        if (emptyPids is not null)
            foreach (var pid in emptyPids) _byPid.Remove(pid);
    }

    // ---------------------------------------------------------------- internals

    /// <summary>
    /// Core statistic. Extracted so the scoring is one readable block rather than
    /// smeared across the public methods.
    /// </summary>
    private BeaconVerdict Judge(string endpoint, Series s)
    {
        long[] ticks = s.SortedCopy();
        // Monitors deliver events from buffered ETW sessions and from several providers,
        // so a handful of out-of-order timestamps per second is normal. Sorting before
        // differencing avoids negative gaps that would otherwise poison the median.

        if (ticks.Length == 0)
            return Negative(endpoint, 0, DateTime.MinValue, DateTime.MinValue,
                "no observations retained for this destination.");

        long anchor = ticks[^1];
        // The window is anchored on the NEWEST SAMPLE rather than on wall-clock now, so a
        // replayed capture from last month produces exactly the verdict the live sensor
        // produced at the time. Staleness is expressed by Prune, not by silently emptying
        // the window.
        long cutoff = anchor >= _window.Ticks ? anchor - _window.Ticks : long.MinValue;

        int start = 0;
        while (start < ticks.Length && ticks[start] < cutoff) start++;
        int n = ticks.Length - start;

        var firstUtc = new DateTime(ticks[start], DateTimeKind.Utc);
        var lastUtc = new DateTime(anchor, DateTimeKind.Utc);

        if (n < 2)
            return Negative(endpoint, n, firstUtc, lastUtc,
                $"only {n} connection(s) inside the {Describe(_window)} window; a cadence needs at least two.");

        var gaps = new long[n - 1];
        for (int i = 0; i < gaps.Length; i++) gaps[i] = ticks[start + i + 1] - ticks[start + i];

        long medianTicks = Median(gaps);
        var median = TimeSpan.FromTicks(medianTicks);

        // Median absolute deviation: median(|gap - median|). Half the gaps may be
        // outliers without moving it.
        var deviations = new long[gaps.Length];
        for (int i = 0; i < gaps.Length; i++) deviations[i] = Math.Abs(gaps[i] - medianTicks);
        long madTicks = Median(deviations);

        // A zero median means every retained sample landed in the same tick bucket: a
        // burst, not a schedule. MAD/median is undefined there, so we report the maximum
        // jitter rather than 0 -- reporting 0 would read downstream as "perfect metronome",
        // which is the exact opposite of the truth.
        double jitter = medianTicks > 0
            ? Math.Min(MaxReportedJitter, (double)madTicks / medianTicks)
            : MaxReportedJitter;

        bool enoughSamples = n >= _minConnections;
        bool inBand = median >= MinBeaconInterval && median <= MaxBeaconInterval;
        bool regular = jitter < JitterThreshold;

        // CONFIDENCE, exact formula:
        //     sampleTerm = clamp01((n - minConnections + 1) / 12)
        //     regularity = clamp01(1 - jitter / 0.25)
        //     confidence = inBand ? clamp01(0.35 * sampleTerm + 0.65 * regularity) : 0
        // Rationale for the weights: regularity is the actual discriminator, so it carries
        // most of the mass; sample count only tells you how much to trust the regularity
        // estimate, and its value saturates quickly (12 samples past the minimum is already
        // a solid MAD estimate, more adds little). Confidence is forced to 0 outside the
        // cadence band because there is no beacon hypothesis to be confident about: a
        // 40-millisecond or a 3-day median is not a check-in schedule.
        double sampleTerm = Clamp01((n - _minConnections + 1) / SampleSaturation);
        double regularity = Clamp01(1.0 - (jitter / JitterThreshold));
        double confidence = inBand ? Clamp01((0.35 * sampleTerm) + (0.65 * regularity)) : 0.0;
        confidence = Math.Round(confidence, 3);

        bool beaconing = enoughSamples && inBand && regular;

        string explanation;
        if (beaconing)
        {
            explanation =
                $"{n} connections to {endpoint} on a {Describe(median)} median cadence with " +
                $"{Pct(jitter)} jitter (MAD/median), spanning {Describe(lastUtc - firstUtc)}; " +
                "consistent with an automated check-in. Benign updaters and telemetry agents " +
                "look identical, so correlate with process and destination reputation.";
        }
        else if (!inBand)
        {
            explanation =
                $"{n} connections to {endpoint} at a {Describe(median)} median gap, outside the " +
                $"{Describe(MinBeaconInterval)}-{Describe(MaxBeaconInterval)} beacon band; " +
                (median < MinBeaconInterval
                    ? "this is a burst of traffic, not a schedule."
                    : "too slow to characterise from this window.");
        }
        else if (!regular)
        {
            explanation =
                $"{n} connections to {endpoint} at a {Describe(median)} median gap, but jitter is " +
                $"{Pct(jitter)}, above the {Pct(JitterThreshold)} ceiling; irregular enough to be " +
                "ordinary traffic. Note that an implant randomising its sleep this widely also lands here.";
        }
        else
        {
            explanation =
                $"{n} connections to {endpoint} at a steady {Describe(median)} cadence " +
                $"({Pct(jitter)} jitter) but below the {_minConnections}-sample minimum; " +
                "not yet enough evidence to call it.";
        }

        return new BeaconVerdict
        {
            Endpoint = endpoint,
            Connections = n,
            MedianInterval = median,
            JitterRatio = Math.Round(jitter, 4),
            Confidence = confidence,
            IsBeaconing = beaconing,
            Explanation = explanation,
            FirstUtc = firstUtc,
            LastUtc = lastUtc
        };
    }

    private static BeaconVerdict Negative(string endpoint, int n, DateTime first, DateTime last, string why) => new()
    {
        Endpoint = endpoint,
        Connections = n,
        MedianInterval = TimeSpan.Zero,
        JitterRatio = MaxReportedJitter,
        Confidence = 0.0,
        IsBeaconing = false,
        Explanation = why,
        FirstUtc = first,
        LastUtc = last
    };

    /// <summary>Evicts the series with the oldest newest-sample, i.e. the least recently active.</summary>
    private static void EvictLeastRecent(Dictionary<string, Series> series)
    {
        string? victim = null;
        long oldest = long.MaxValue;
        foreach (var (endpoint, s) in series)
        {
            // Ordinal tie-break keeps eviction deterministic when two series share a
            // newest timestamp, which happens constantly at coarse timer resolution.
            if (s.NewestTicks < oldest || (s.NewestTicks == oldest && (victim is null || string.CompareOrdinal(endpoint, victim) < 0)))
            {
                oldest = s.NewestTicks;
                victim = endpoint;
            }
        }
        if (victim is not null) series.Remove(victim);
    }

    /// <summary>Median of an array that this method is allowed to reorder in place.</summary>
    private static long Median(long[] values)
    {
        Array.Sort(values);
        int m = values.Length / 2;
        // Even counts average the two central values. Kept as a signed division on
        // ticks, which is exact for the magnitudes involved.
        return (values.Length % 2 == 1) ? values[m] : (values[m - 1] + values[m]) / 2;
    }

    private static double Clamp01(double v) => v < 0 ? 0 : v > 1 ? 1 : v;

    /// <summary>Endpoints arrive from several monitors with inconsistent casing; key on one form.</summary>
    private static string Normalize(string? endpoint)
        => string.IsNullOrWhiteSpace(endpoint) ? "" : endpoint.Trim().ToLowerInvariant();

    /// <summary>
    /// Coerces any incoming DateTime to UTC ticks. Unspecified kind is treated as
    /// already-UTC because every BruceEDR monitor produces UTC; a Local value is
    /// converted so a caller that passes wall-clock time does not silently shift the
    /// whole series by the UTC offset.
    /// </summary>
    private static long ToUtcTicks(DateTime when)
        => when.Kind == DateTimeKind.Local ? when.ToUniversalTime().Ticks : when.Ticks;

    private static string Pct(double ratio)
        => (ratio * 100.0).ToString("0.#", CultureInfo.InvariantCulture) + "%";

    private static string Describe(TimeSpan t)
    {
        double s = t.TotalSeconds;
        if (s < 90) return s.ToString("0.##", CultureInfo.InvariantCulture) + "s";
        if (s < 5400) return t.TotalMinutes.ToString("0.##", CultureInfo.InvariantCulture) + "m";
        if (s < 172800) return t.TotalHours.ToString("0.##", CultureInfo.InvariantCulture) + "h";
        return t.TotalDays.ToString("0.##", CultureInfo.InvariantCulture) + "d";
    }

    /// <summary>
    /// Fixed-size ring of observation timestamps. A ring rather than a growing list
    /// because a chatty process would otherwise let a single series consume unbounded
    /// memory, and because the oldest samples are the least useful for judging the
    /// CURRENT cadence -- an implant that changed its sleep an hour ago should be judged
    /// on what it is doing now.
    /// </summary>
    private sealed class Series
    {
        private readonly long[] _ticks = new long[SeriesCapacity];
        private int _count;
        private int _next;

        /// <summary>Largest timestamp ever added, used for LRU eviction and pruning.</summary>
        public long NewestTicks { get; private set; } = long.MinValue;

        public void Add(long ticks)
        {
            _ticks[_next] = ticks;
            _next = (_next + 1) % SeriesCapacity;
            if (_count < SeriesCapacity) _count++;
            if (ticks > NewestTicks) NewestTicks = ticks;
        }

        /// <summary>Ascending copy of the retained timestamps. Never aliases the ring.</summary>
        public long[] SortedCopy()
        {
            var a = new long[_count];
            for (int i = 0; i < _count; i++)
                a[i] = _ticks[(_next - _count + i + SeriesCapacity) % SeriesCapacity];
            Array.Sort(a);
            return a;
        }
    }
}
