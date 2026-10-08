using BruceEDR.Detection;
using BruceEDR.Telemetry;

namespace BruceEDR.Core;

/// <summary>
/// Thread-safe console writer plus a fan-out to a structured event sink (JSONL,
/// syslog, webhook, audit). Console writes are serialised; colour is skipped when
/// output is redirected. The sink is swappable for hot-reload.
///
/// Every level except <see cref="Raw"/> reaches the sink. That matters because under the
/// Windows Service host there is no console at all: if <see cref="Info"/> and
/// <see cref="Error"/> only wrote to stdout, startup failures, monitors that refused to
/// start, and the generated control-plane bearer token would be lost with no trace.
/// <see cref="Raw"/> stays console-only on purpose -- it echoes interactive analyst-console
/// output that is already derived from events the sink has seen.
///
/// LIMITATION: sink failures are swallowed, so a broken sink degrades to console-only
/// silently. Anything that must not be lost also needs an off-box sink (syslog/webhook).
///
/// The console echo is rate limited (<see cref="ConsoleLinesPerSecond"/>); the sink never
/// is. A flood of lines is unreadable, and every console write happens under the lock
/// that the detection thread also takes, so a slow or blocked console stalls the agent.
/// </summary>
public sealed class Logger
{
    /// <summary>Console lines shown per second before the rest are counted and summarised.</summary>
    internal const int ConsoleLinesPerSecond = 40;

    private readonly object _gate = new();
    private readonly TextWriter? _console;     // null: Console.Out, resolved at write time
    private readonly Func<long> _millis;
    private volatile IEventSink? _sink;

    // Echo budget, guarded by _gate.
    private bool _windowOpen;
    private long _windowStart;
    private int _shownInWindow;
    private int _suppressedInWindow;

    public Logger(IEventSink? sink = null) : this(sink, null, null) { }

    /// <summary>Test seam: a captured console and a fake millisecond clock.</summary>
    internal Logger(IEventSink? sink, TextWriter? console, Func<long>? millis)
    {
        _sink = sink;
        _console = console;
        _millis = millis ?? (() => Environment.TickCount64);
    }

    public void SetSink(IEventSink? sink) => _sink = sink;

    public void Info(string message)
    {
        WriteLine(ConsoleColor.Gray, "[*] " + message);
        Emit(new BruceEvent { Level = "INFO", Category = "system", Message = message });
    }

    /// <summary>Console-only echo for interactive analyst-console output. Not forwarded.</summary>
    public void Raw(string text)
    {
        lock (_gate)
        {
            // The analyst is reading now: report anything the budget held back first, rather
            // than waiting for the next log line to roll the window over.
            FlushSuppressed();
            SafeWrite(text);
        }
    }

    public void Action(string message)
    {
        WriteLine(ConsoleColor.Cyan, "    -> " + message);
        Emit(new BruceEvent { Level = "ACTION", Category = "response", Message = message });
    }

    public void Error(string context, Exception ex)
    {
        string message = $"{context}: {ex.GetType().Name}: {ex.Message}";
        WriteLine(ConsoleColor.Magenta, "[ERR] " + message, always: true);
        Emit(new BruceEvent { Level = "ERROR", Category = "system", Message = message });
    }

    public void Warn(DetectionResult d)
    {
        var s = d.Snapshot;
        WriteLine(ConsoleColor.Yellow, $"[WARN] pid {s.Pid} {s.ProcessName} score={s.Score} :: {d.Trigger}");
        Emit(ToEvent("WARN", d));
    }

    public void Quarantine(DetectionResult d)
    {
        var s = d.Snapshot;
        lock (_gate)
        {
            if (AdmitConsoleLine(always: true))
            {
                SetColor(ConsoleColor.Red);
                SafeWrite($"[QUARANTINE] pid {s.Pid} {s.ProcessName} score={s.Score} :: {d.Trigger}");
                foreach (var r in s.Reasons) SafeWrite("    " + r);
                ResetColor();
            }
        }
        Emit(ToEvent("QUARANTINE", d));
    }

    private static BruceEvent ToEvent(string level, DetectionResult d)
    {
        var s = d.Snapshot;
        return new BruceEvent
        {
            Level = level,
            Category = "detection",
            Pid = s.Pid,
            Process = s.ProcessName,
            Image = s.ImagePath,
            Score = s.Score,
            Trigger = d.Trigger,
            Reasons = s.Reasons,
            StagedArchives = s.StagedArchives
        };
    }

    // Deliberately swallows everything and never calls back into Info/Error: a sink that
    // throws on every event would otherwise recurse forever now that errors are forwarded.
    private void Emit(BruceEvent e)
    {
        var sink = _sink;
        if (sink is null) return;
        try { sink.Emit(e); } catch { /* never let telemetry break the agent */ }
    }

    private void WriteLine(ConsoleColor color, string message, bool always = false)
    {
        lock (_gate)
        {
            if (!AdmitConsoleLine(always)) return;
            SetColor(color);
            SafeWrite(message);
            ResetColor();
        }
    }

    // Caller holds _gate. One-second windows: the first ConsoleLinesPerSecond entries print,
    // the rest are counted and reported when the next window opens. Raw is never limited,
    // and neither are QUARANTINE and ERROR lines (always), which an operator must see.
    // Redirected output is a file or a pipe being read by a program, so it gets everything.
    private bool AdmitConsoleLine(bool always = false)
    {
        if (_console is null && Console.IsOutputRedirected) return true;
        long now = _millis();
        if (!_windowOpen || now - _windowStart >= 1000)
        {
            FlushSuppressed();
            _windowOpen = true;
            _windowStart = now;
            _shownInWindow = 0;
        }
        if (always) return true;
        if (_shownInWindow < ConsoleLinesPerSecond)
        {
            _shownInWindow++;
            return true;
        }
        _suppressedInWindow++;
        return false;
    }

    // Caller holds _gate.
    private void FlushSuppressed()
    {
        if (_suppressedInWindow == 0) return;
        SafeWrite($"[*] console: {_suppressedInWindow} line(s) not shown to keep up; every event still reached the log sinks");
        _suppressedInWindow = 0;
    }

    private void SafeWrite(string text)
    {
        try { (_console ?? Console.Out).WriteLine(text); } catch { }
    }

    private void SetColor(ConsoleColor c)
    {
        if (_console is not null || Console.IsOutputRedirected) return;
        try { Console.ForegroundColor = c; } catch { }
    }

    private void ResetColor()
    {
        if (_console is not null || Console.IsOutputRedirected) return;
        try { Console.ResetColor(); } catch { }
    }
}
