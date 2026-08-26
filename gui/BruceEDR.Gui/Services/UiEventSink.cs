using BruceEDR.Telemetry;

namespace BruceEDR.Gui.Services;

/// <summary>An IEventSink that hands each event to a callback (marshaled to the UI thread by the caller).</summary>
public sealed class UiEventSink : IEventSink
{
    private readonly Action<BruceEvent> _onEvent;
    public UiEventSink(Action<BruceEvent> onEvent) => _onEvent = onEvent;
    public void Emit(BruceEvent e) { try { _onEvent(e); } catch { /* never break the pipeline */ } }
    public void Dispose() { }
}
