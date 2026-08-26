using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using BruceEDR.Core;

namespace BruceEDR.Monitoring;

/// <summary>
/// Surfaces script and macro bodies that the Antimalware Scan Interface handed to a
/// registered scanner, via the <c>Microsoft-Antimalware-Scan-Interface</c> provider.
/// This is the only place a user-mode agent gets to see PowerShell, VBA, JScript and
/// WMI content AFTER the caller has de-obfuscated it, which is exactly what makes it
/// worth the extra session.
///
/// This is a manifest (user-mode) provider, so like <c>DnsMonitor</c> it needs its own
/// user-mode session; a kernel session cannot host it.
///
/// What this monitor genuinely cannot do -- read this before trusting its silence:
/// <list type="bullet">
/// <item><description>The provider only emits while an AMSI provider is REGISTERED and
/// scanning. With Defender disabled, or with third-party AV that never registers an
/// AMSI provider, this monitor produces nothing at all.</description></item>
/// <item><description>In-process AMSI bypasses -- patching <c>AmsiScanBuffer</c>,
/// corrupting the context, forcing an initialisation failure -- suppress the event
/// before ETW ever sees it. Content that never reaches AMSI cannot be observed
/// here.</description></item>
/// <item><description>Content is TRUNCATED by the provider itself: large buffers are
/// clipped before they are written to the trace, so <c>ScriptText</c> is a prefix, not
/// the whole script. It is truncated a second time by
/// <see cref="MonitorSupport.TruncateScript"/> to bound our own memory.</description></item>
/// <item><description>The buffer may be UTF-16 or UTF-8 depending on the caller, and on
/// some builds it arrives as raw bytes rather than a decoded string. Both cases are
/// handled, but a mis-detected encoding produces mojibake rather than an
/// error.</description></item>
/// <item><description>PID is the SCANNING process. For an Office macro that is
/// <c>winword.exe</c>, not the child the macro later spawns.</description></item>
/// </list>
/// </summary>
public sealed class AmsiMonitor : IDisposable
{
    private const string SessionName = "BruceEDR-Amsi";

    /// <summary>Microsoft-Antimalware-Scan-Interface.</summary>
    private static readonly Guid AmsiProvider = new("2A576B87-09A7-520E-C21A-4942F0271D67");

    /// <summary>
    /// Upper bound on the script body carried on a signal. AMSI can present multi-
    /// megabyte buffers and the agent keeps signals alive per process, so an unbounded
    /// copy is a memory-pressure denial of service against the agent itself.
    /// </summary>
    private const int MaxScriptChars = 8192;

    /// <summary>
    /// The same script is often scanned several times in a row (once per AMSI stage,
    /// once per re-entry). Suppressing an identical body per process for a few seconds
    /// stops one paste from scoring three times.
    /// </summary>
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(5);

    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private readonly SignalDeduplicator _dedupe;
    private TraceEventSession? _session;
    private Thread? _pump;

    /// <param name="emit">Sink for produced signals. Called on the ETW pump thread.</param>
    /// <param name="log">Diagnostics.</param>
    /// <param name="clock">Time source for duplicate suppression; defaults to the wall clock.</param>
    public AmsiMonitor(Action<Signal> emit, Logger log, IClock? clock = null)
    {
        _emit = emit;
        _log = log;
        _dedupe = new SignalDeduplicator(clock ?? SystemClock.Instance, DedupeWindow);
    }

    /// <summary>
    /// Starts a user-mode session bound to the AMSI provider. Throws only when the
    /// session cannot be created, so the host can run without script visibility.
    /// Note that a successful start does NOT mean events will arrive -- see the class
    /// remarks about AMSI providers having to be registered.
    /// </summary>
    public void Start()
    {
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("AMSI ETW requires Administrator");

        EtwSessionSupport.ClearStaleSession(SessionName, _log);

        TraceEventSession? session = null;
        try
        {
            session = new TraceEventSession(SessionName) { StopOnDispose = true };
            session.EnableProvider(AmsiProvider, TraceEventLevel.Verbose);
            session.Source.Dynamic.All += data => Guard(() => OnEvent(data));

            _session = session;
            _pump = new Thread(PumpEvents) { IsBackground = true, Name = "BruceEDR-ETW-Amsi" };
            _pump.Start();
        }
        catch
        {
            try { session?.Dispose(); } catch { }
            throw;   // let the host continue without AMSI telemetry
        }
    }

    private void OnEvent(TraceEvent data)
    {
        if (data.ProviderGuid != AmsiProvider) return;

        string? script = DecodeContent(EtwSessionSupport.Payload(data, "content", "Content", "buffer", "Buffer"))
                         ?? DecodeContent(EtwSessionSupport.PayloadLike(data, "content"));

        string appName = EtwSessionSupport.GetString(data, "appname", "AppName", "app") ?? "";
        string contentName = EtwSessionSupport.GetString(data, "contentname", "ContentName") ?? "";

        // Without a body there is nothing to score. The event still tells us a scan
        // happened, but a bodyless ScriptContent signal would only add noise.
        if (string.IsNullOrWhiteSpace(script)) return;

        string body = MonitorSupport.TruncateScript(script, MaxScriptChars);
        bool obfuscated = MonitorSupport.LooksObfuscatedScript(body);

        // Keyed on the body, not the whole event: the same script re-scanned under a
        // different content name is still the same script.
        if (!_dedupe.ShouldEmit($"{data.ProcessID}|{body.GetHashCode(StringComparison.Ordinal)}|{body.Length}")) return;

        var detail = new StringBuilder("amsi");
        if (appName.Length > 0) detail.Append(";app=").Append(appName);
        if (contentName.Length > 0) detail.Append(";content=").Append(contentName);
        if (obfuscated) detail.Append(";obfuscated");

        _emit(new Signal
        {
            Kind = SignalKind.ScriptContent,
            Pid = data.ProcessID,
            ProcessName = data.ProcessName ?? "",
            ScriptText = body,
            Detail = detail.ToString(),
            TimestampUtc = data.TimeStamp.ToUniversalTime()
        });
    }

    /// <summary>
    /// AMSI content arrives either already decoded as a string or as the raw scan
    /// buffer. For raw bytes the encoding is not declared anywhere in the event, so it
    /// is inferred: a WCHAR buffer of mostly-ASCII text has a zero in every second
    /// byte, which UTF-8 text essentially never does. A wrong guess yields unreadable
    /// text, never an exception -- both decoders are configured to substitute rather
    /// than throw.
    /// </summary>
    private static string? DecodeContent(object? value)
    {
        switch (value)
        {
            case null:
                return null;
            case string s:
                return s.Length == 0 ? null : s;
            case byte[] bytes when bytes.Length > 0:
                return LooksUtf16(bytes)
                    ? Encoding.Unicode.GetString(bytes)
                    : Encoding.UTF8.GetString(bytes);
            default:
                return null;
        }
    }

    private static bool LooksUtf16(byte[] bytes)
    {
        if (bytes.Length < 4) return false;

        // Sample at most the first 512 bytes; that is more than enough to decide and
        // keeps the check off the critical path for large buffers.
        int limit = Math.Min(bytes.Length & ~1, 512);
        int oddZeros = 0, oddTotal = 0;
        for (int i = 1; i < limit; i += 2)
        {
            oddTotal++;
            if (bytes[i] == 0) oddZeros++;
        }
        return oddTotal > 0 && oddZeros > oddTotal * 0.7;
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            _log.Error("AMSI ETW pump stopped", ex);
        }
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) { _log.Error("AMSI ETW event handler", ex); }
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
