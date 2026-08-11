using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using ProcessShield.Core;

namespace ProcessShield.Telemetry;

/// <summary>
/// Immutable point-in-time reading of <see cref="ShieldMetrics"/>.
///
/// A snapshot is taken under no lock, so counters are individually consistent but not
/// mutually consistent: <c>Signals</c> may already include an event whose detection has
/// not been counted yet. For operational monitoring that skew (microseconds) is
/// irrelevant, and the alternative -- a global lock on the hot ingest path -- is not.
/// </summary>
public sealed record MetricsSnapshot
{
    /// <summary>Signals accepted from the monitors.</summary>
    public long Signals { get; init; }

    /// <summary>Signals discarded because a queue was full. A non-zero value means the
    /// agent is blind to part of the telemetry stream, which is a detection gap, not a
    /// performance note.</summary>
    public long Dropped { get; init; }

    /// <summary>Detections that reached the warn threshold.</summary>
    public long Warns { get; init; }

    /// <summary>Detections that reached the quarantine threshold.</summary>
    public long Quarantines { get; init; }

    /// <summary>Response actions that reported success.</summary>
    public long ResponsesOk { get; init; }

    /// <summary>Response actions that failed (usually a privilege or race failure).</summary>
    public long ResponsesFailed { get; init; }

    /// <summary>Median detection latency over the reservoir, in milliseconds.</summary>
    public double LatencyP50Ms { get; init; }

    /// <summary>95th percentile detection latency over the reservoir, in milliseconds.</summary>
    public double LatencyP95Ms { get; init; }

    /// <summary>99th percentile detection latency over the reservoir, in milliseconds.</summary>
    public double LatencyP99Ms { get; init; }

    /// <summary>Total latency observations ever recorded. Larger than the reservoir once
    /// it has wrapped; exposed so Prometheus can publish a true <c>_count</c>.</summary>
    public long LatencySamples { get; init; }

    /// <summary>Sum of every latency observation ever recorded, in milliseconds. Together
    /// with <see cref="LatencySamples"/> this gives an exact mean, which the percentiles
    /// cannot.</summary>
    public double LatencySumMs { get; init; }

    /// <summary>Free-form gauges, ordinal-sorted so rendering is deterministic.</summary>
    public IReadOnlyDictionary<string, double> Gauges { get; init; }
        = new SortedDictionary<string, double>(StringComparer.Ordinal);

    /// <summary>When the snapshot was taken, read from the injected clock.</summary>
    public DateTime CollectedUtc { get; init; }
}

/// <summary>
/// Lock-free counters for the agent's own health.
///
/// WHY this exists: an EDR that has silently stopped ingesting is worse than no EDR,
/// because it still looks installed. Exposing signal/drop counts, detection rates,
/// response success and detection latency in Prometheus text format means an existing
/// monitoring stack can alarm on "ProcessShield stopped seeing events" without anyone
/// writing a bespoke health check.
///
/// Every member is safe to call from any thread. Counters use <see cref="Interlocked"/>,
/// gauges live in a <see cref="ConcurrentDictionary{TKey,TValue}"/>, and the latency
/// reservoir is a fixed-size ring written with atomic double exchanges. Nothing here
/// ever throws or blocks: metrics collection must never be able to break detection.
/// </summary>
public sealed class ShieldMetrics
{
    /// <summary>
    /// Number of latency samples retained. A power of two, sized so a busy agent keeps
    /// roughly the last few seconds of activity.
    /// </summary>
    public const int ReservoirSize = 1024;

    private readonly IClock _clock;

    // NaN marks a slot that has never been written. Using NaN rather than 0 avoids the
    // classic lock-free reservoir bug where a reader counts a slot that a writer has
    // reserved but not yet stored, and folds a phantom 0 ms sample into the percentiles.
    private readonly double[] _latencyMs = new double[ReservoirSize];

    private readonly ConcurrentDictionary<string, double> _gauges = new(StringComparer.Ordinal);

    private long _signals;
    private long _dropped;
    private long _warns;
    private long _quarantines;
    private long _responsesOk;
    private long _responsesFailed;
    private long _latencySamples;
    private long _latencyTicks;
    private long _reservoirCursor = -1;

    /// <summary>
    /// <paramref name="clock"/> is injected so <see cref="Snapshot"/> is deterministic in
    /// tests and in replay; it defaults to the real clock.
    /// </summary>
    public ShieldMetrics(IClock? clock = null)
    {
        _clock = clock ?? SystemClock.Instance;
        for (int i = 0; i < _latencyMs.Length; i++) _latencyMs[i] = double.NaN;
    }

    /// <summary>Counts telemetry signals accepted from the monitors.</summary>
    public void IncSignals(long n = 1) => Interlocked.Add(ref _signals, n);

    /// <summary>Counts telemetry discarded because a bounded queue was full.</summary>
    public void IncDropped(long n = 1) => Interlocked.Add(ref _dropped, n);

    /// <summary>
    /// Counts a detection by its verdict level. Only WARN and QUARANTINE are counted:
    /// INFO and ACTION are not detections, and inventing a bucket for them would make
    /// "detections per hour" meaningless. Unrecognised or null levels are ignored rather
    /// than mis-filed.
    /// </summary>
    public void IncDetections(string level)
    {
        switch ((level ?? "").Trim().ToUpperInvariant())
        {
            case "WARN": Interlocked.Increment(ref _warns); break;
            case "QUARANTINE": Interlocked.Increment(ref _quarantines); break;
        }
    }

    /// <summary>Counts the outcome of one response action.</summary>
    public void IncResponses(bool ok)
    {
        if (ok) Interlocked.Increment(ref _responsesOk);
        else Interlocked.Increment(ref _responsesFailed);
    }

    /// <summary>
    /// Records how long a detection took. A negative duration (a clock that stepped
    /// backwards between the two reads that produced it) is clamped to zero instead of
    /// poisoning the percentiles with a nonsensical value.
    /// </summary>
    public void ObserveDetectionLatency(TimeSpan d)
    {
        long ticks = d.Ticks < 0 ? 0 : d.Ticks;
        double ms = ticks / (double)TimeSpan.TicksPerMillisecond;

        long cursor = Interlocked.Increment(ref _reservoirCursor);
        int slot = (int)((ulong)cursor % (ulong)ReservoirSize);
        Interlocked.Exchange(ref _latencyMs[slot], ms);

        Interlocked.Add(ref _latencyTicks, ticks);
        Interlocked.Increment(ref _latencySamples);
    }

    /// <summary>
    /// Sets a named gauge, replacing any previous value. Blank names are ignored: a
    /// metrics facade is not the place to throw at a caller that is itself usually inside
    /// a catch block.
    /// </summary>
    public void SetGauge(string name, double value)
    {
        if (string.IsNullOrWhiteSpace(name)) return;
        _gauges[name.Trim()] = value;
    }

    /// <summary>Reads every counter into an immutable snapshot.</summary>
    public MetricsSnapshot Snapshot()
    {
        double[] samples = ReadReservoir();
        Array.Sort(samples);

        var gauges = new SortedDictionary<string, double>(StringComparer.Ordinal);
        foreach (var kv in _gauges) gauges[kv.Key] = kv.Value;

        long ticks = Interlocked.Read(ref _latencyTicks);

        return new MetricsSnapshot
        {
            Signals = Interlocked.Read(ref _signals),
            Dropped = Interlocked.Read(ref _dropped),
            Warns = Interlocked.Read(ref _warns),
            Quarantines = Interlocked.Read(ref _quarantines),
            ResponsesOk = Interlocked.Read(ref _responsesOk),
            ResponsesFailed = Interlocked.Read(ref _responsesFailed),
            LatencyP50Ms = Percentile(samples, 0.50),
            LatencyP95Ms = Percentile(samples, 0.95),
            LatencyP99Ms = Percentile(samples, 0.99),
            LatencySamples = Interlocked.Read(ref _latencySamples),
            LatencySumMs = ticks / (double)TimeSpan.TicksPerMillisecond,
            Gauges = gauges,
            CollectedUtc = _clock.UtcNow
        };
    }

    /// <summary>
    /// Renders the current snapshot as Prometheus text exposition format (version 0.0.4).
    ///
    /// Blocks are emitted in ordinal name order and lines are terminated with a bare LF
    /// (a scraper rejects CRLF), so the whole string is byte-stable for a given snapshot
    /// and a test can assert on it in full.
    /// </summary>
    public string ToPrometheusText()
    {
        var snap = Snapshot();
        var blocks = new List<(string Name, string Text)>(8 + snap.Gauges.Count);

        blocks.Add(("processshield_signals_total", Counter(
            "processshield_signals_total",
            "Telemetry signals accepted from the monitors since start.",
            snap.Signals)));

        blocks.Add(("processshield_signals_dropped_total", Counter(
            "processshield_signals_dropped_total",
            "Telemetry signals discarded because a bounded queue was full.",
            snap.Dropped)));

        blocks.Add(("processshield_detections_total", Block(
            "processshield_detections_total",
            "Detections raised, by verdict level.",
            "counter",
            new[]
            {
                Line("processshield_detections_total", "level", "quarantine", snap.Quarantines),
                Line("processshield_detections_total", "level", "warn", snap.Warns)
            })));

        blocks.Add(("processshield_responses_total", Block(
            "processshield_responses_total",
            "Response actions attempted, by outcome.",
            "counter",
            new[]
            {
                Line("processshield_responses_total", "result", "failed", snap.ResponsesFailed),
                Line("processshield_responses_total", "result", "ok", snap.ResponsesOk)
            })));

        blocks.Add(("processshield_detection_latency_ms", Block(
            "processshield_detection_latency_ms",
            "Detection latency in milliseconds. Quantiles are approximated over a sliding " +
            "reservoir of the last " + ReservoirSize.ToString(CultureInfo.InvariantCulture) +
            " observations, not over all samples.",
            "summary",
            new[]
            {
                Line("processshield_detection_latency_ms", "quantile", "0.5", snap.LatencyP50Ms),
                Line("processshield_detection_latency_ms", "quantile", "0.95", snap.LatencyP95Ms),
                Line("processshield_detection_latency_ms", "quantile", "0.99", snap.LatencyP99Ms),
                "processshield_detection_latency_ms_count " + Num(snap.LatencySamples),
                "processshield_detection_latency_ms_sum " + Num(snap.LatencySumMs)
            })));

        // Seeded with the built-in names (and the summary's derived suffixes) so a gauge
        // can never shadow a core metric or emit a second block under the same name.
        var emitted = new HashSet<string>(StringComparer.Ordinal)
        {
            "processshield_signals_total",
            "processshield_signals_dropped_total",
            "processshield_detections_total",
            "processshield_responses_total",
            "processshield_detection_latency_ms",
            "processshield_detection_latency_ms_count",
            "processshield_detection_latency_ms_sum"
        };

        foreach (var kv in snap.Gauges)
        {
            string metric = GaugeMetricName(kv.Key);
            if (metric.Length == 0) continue;
            // Two free-form gauge names can collapse onto the same Prometheus name once
            // illegal characters are replaced. Duplicate metric lines break scrapers, so
            // the first name in ordinal order wins and the collision is dropped. Choose
            // gauge names from [a-zA-Z0-9_] to avoid this entirely.
            if (!emitted.Add(metric)) continue;
            // Pass the RAW name: Block escapes the help text itself, and escaping here as
            // well turned a single backslash into four.
            blocks.Add((metric, Block(
                metric,
                "Gauge '" + kv.Key + "' reported by ProcessShield.",
                "gauge",
                new[] { metric + " " + Num(kv.Value) })));
        }

        blocks.Sort(static (a, b) => string.CompareOrdinal(a.Name, b.Name));

        var sb = new StringBuilder(1024);
        foreach (var b in blocks) sb.Append(b.Text);
        return sb.ToString();
    }

    // --- internals ---------------------------------------------------------

    private double[] ReadReservoir()
    {
        var kept = new List<double>(ReservoirSize);
        for (int i = 0; i < _latencyMs.Length; i++)
        {
            // CompareExchange with a 0 comparand is an atomic read: it only writes when
            // the slot already holds 0, which is a no-op. A plain read of a double field
            // is not guaranteed atomic on every architecture the CLR targets.
            double v = Interlocked.CompareExchange(ref _latencyMs[i], 0d, 0d);
            if (!double.IsNaN(v)) kept.Add(v);
        }
        return kept.ToArray();
    }

    /// <summary>
    /// Nearest-rank percentile over the retained samples. This is an approximation of the
    /// true percentile in two ways, both deliberate: it only sees the last
    /// <see cref="ReservoirSize"/> observations, and it reports an actual observed sample
    /// rather than interpolating between the two straddling it.
    /// </summary>
    private static double Percentile(double[] sorted, double p)
    {
        if (sorted.Length == 0) return 0;
        int index = (int)Math.Ceiling(p * sorted.Length) - 1;
        if (index < 0) index = 0;
        if (index >= sorted.Length) index = sorted.Length - 1;
        return sorted[index];
    }

    private static string Counter(string name, string help, long value)
        => Block(name, help, "counter", new[] { name + " " + Num(value) });

    private static string Block(string name, string help, string type, IReadOnlyList<string> lines)
    {
        var sb = new StringBuilder(128);
        sb.Append("# HELP ").Append(name).Append(' ').Append(EscapeHelp(help)).Append('\n');
        sb.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
        foreach (var l in lines) sb.Append(l).Append('\n');
        return sb.ToString();
    }

    private static string Line(string name, string label, string labelValue, double value)
        => name + "{" + label + "=\"" + EscapeLabel(labelValue) + "\"} " + Num(value);

    private static string Line(string name, string label, string labelValue, long value)
        => name + "{" + label + "=\"" + EscapeLabel(labelValue) + "\"} " + Num(value);

    /// <summary>HELP text may not contain a raw newline, and a backslash must be escaped
    /// or a scraper mis-reads the following line.</summary>
    private static string EscapeHelp(string s)
        => (s ?? "").Replace("\\", "\\\\").Replace("\r", "").Replace("\n", "\\n");

    /// <summary>Label values escape backslash, double quote and newline.</summary>
    private static string EscapeLabel(string s)
        => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "\\n");

    private static string Num(long value) => value.ToString(CultureInfo.InvariantCulture);

    /// <summary>Formats a double the way the exposition format expects, including its
    /// spellings for the non-finite values.</summary>
    private static string Num(double value)
    {
        if (double.IsNaN(value)) return "NaN";
        if (double.IsPositiveInfinity(value)) return "+Inf";
        if (double.IsNegativeInfinity(value)) return "-Inf";
        if (value == 0d) return "0";   // also normalises negative zero
        return value.ToString("0.######", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// Maps a free-form gauge name onto the Prometheus name grammar
    /// (<c>[a-zA-Z_:][a-zA-Z0-9_:]*</c>) under the shared <c>processshield_</c> prefix.
    /// Returns an empty string when nothing usable survives.
    /// </summary>
    private static string GaugeMetricName(string raw)
    {
        var sb = new StringBuilder(raw.Length + 16);
        foreach (char c in raw)
        {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == ':')
                sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '_')
                sb.Append('_');
        }

        string body = sb.ToString().Trim('_');
        if (body.Length == 0) return "";
        return body.StartsWith("processshield_", StringComparison.Ordinal)
            ? body
            : "processshield_" + body;
    }
}
