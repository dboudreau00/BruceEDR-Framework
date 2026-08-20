using ProcessShield.Detection;
using ProcessShield.Telemetry;

namespace ProcessShield.Core;

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
/// </summary>
public sealed class Logger
{
    private readonly object _gate = new();
    private volatile IEventSink? _sink;

    public Logger(IEventSink? sink = null) => _sink = sink;

    public void SetSink(IEventSink? sink) => _sink = sink;

    public void Info(string message)
    {
        WriteLine(ConsoleColor.Gray, "[*] " + message);
        Emit(new ShieldEvent { Level = "INFO", Category = "system", Message = message });
    }

    /// <summary>Console-only echo for interactive analyst-console output. Not forwarded.</summary>
    public void Raw(string text) { lock (_gate) { SafeWrite(text); } }

    public void Action(string message)
    {
        WriteLine(ConsoleColor.Cyan, "    -> " + message);
        Emit(new ShieldEvent { Level = "ACTION", Category = "response", Message = message });
    }

    public void Error(string context, Exception ex)
    {
        string message = $"{context}: {ex.GetType().Name}: {ex.Message}";
        WriteLine(ConsoleColor.Magenta, "[ERR] " + message);
        Emit(new ShieldEvent { Level = "ERROR", Category = "system", Message = message });
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
            SetColor(ConsoleColor.Red);
            SafeWrite($"[QUARANTINE] pid {s.Pid} {s.ProcessName} score={s.Score} :: {d.Trigger}");
            foreach (var r in s.Reasons) SafeWrite("    " + r);
            ResetColor();
        }
        Emit(ToEvent("QUARANTINE", d));
    }

    private static ShieldEvent ToEvent(string level, DetectionResult d)
    {
        var s = d.Snapshot;
        return new ShieldEvent
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
    private void Emit(ShieldEvent e)
    {
        var sink = _sink;
        if (sink is null) return;
        try { sink.Emit(e); } catch { /* never let telemetry break the agent */ }
    }

    private void WriteLine(ConsoleColor color, string message)
    {
        lock (_gate)
        {
            SetColor(color);
            SafeWrite(message);
            ResetColor();
        }
    }

    private static void SafeWrite(string text)
    {
        try { Console.WriteLine(text); } catch { }
    }

    private static void SetColor(ConsoleColor c)
    {
        if (Console.IsOutputRedirected) return;
        try { Console.ForegroundColor = c; } catch { }
    }

    private static void ResetColor()
    {
        if (Console.IsOutputRedirected) return;
        try { Console.ResetColor(); } catch { }
    }
}
