using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using ProcessShield.Core;

namespace ProcessShield.Monitoring;

/// <summary>
/// Reports the DNS names each process resolves, from the
/// <c>Microsoft-Windows-DNS-Client</c> provider. Domains are the most durable
/// indicator a C2 implant leaves behind: infrastructure IPs rotate, DGA names repeat,
/// and DNS tunnelling shows up here long before any TCP connect does.
///
/// This monitor exists as its own class for a hard technical reason, not for tidiness:
/// DNS-Client is a MANIFEST (user-mode) provider, and a kernel-mode trace session
/// cannot host user-mode providers. It therefore needs a second, user-mode
/// <see cref="TraceEventSession"/> that is entirely separate from the kernel session
/// in <c>EtwMonitor</c>.
///
/// Attribution and coverage caveats, stated plainly:
/// <list type="bullet">
/// <item><description>The provider fires inside <c>dnsapi.dll</c> in the CALLING
/// process, so the PID is usually correct. But work funnelled through the DNS Client
/// service is attributed to <c>svchost.exe</c>, not the requester.</description></item>
/// <item><description>Anything that does not use the Windows resolver is invisible
/// here: DNS-over-HTTPS in browsers, a statically linked resolver, hard-coded IPs, or
/// a raw UDP/53 socket. Absence of a DnsQuery signal is not evidence of no
/// resolution.</description></item>
/// <item><description>Payload field names differ across Windows builds, so every field
/// is read by name with fallbacks and a last-resort name scan.</description></item>
/// </list>
/// </summary>
public sealed class DnsMonitor : IDisposable
{
    private const string SessionName = "ProcessShield-Dns";

    /// <summary>Microsoft-Windows-DNS-Client.</summary>
    private static readonly Guid DnsClientProvider = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    /// <summary>
    /// EVENT_DNS_QUERY_INITIATED. Carries the queried name and the requesting process,
    /// which is the behavioural fact we care about.
    /// </summary>
    private const int EventQueryInitiated = 3006;

    /// <summary>
    /// EVENT_DNS_QUERY_COMPLETED. Handled only for FAILED lookups: a burst of
    /// NXDOMAINs is the classic fingerprint of a domain-generation algorithm hunting
    /// for its live rendezvous point. Successful completions are skipped because they
    /// merely repeat the name from 3006 and would double-score every resolution.
    /// </summary>
    private const int EventQueryCompleted = 3008;

    /// <summary>
    /// Applications retry aggressively and the resolver re-queries per address family,
    /// so the same name arrives several times a second. Ten seconds of suppression per
    /// (pid, name) keeps a beaconing implant visible without flooding the engine.
    /// </summary>
    private static readonly TimeSpan DedupeWindow = TimeSpan.FromSeconds(10);

    private readonly Action<Signal> _emit;
    private readonly Logger _log;
    private readonly SignalDeduplicator _dedupe;
    private readonly string _machineName;
    private TraceEventSession? _session;
    private Thread? _pump;

    /// <param name="emit">Sink for produced signals. Called on the ETW pump thread.</param>
    /// <param name="log">Diagnostics.</param>
    /// <param name="clock">Time source for duplicate suppression; defaults to the wall clock.</param>
    public DnsMonitor(Action<Signal> emit, Logger log, IClock? clock = null)
    {
        _emit = emit;
        _log = log;
        _dedupe = new SignalDeduplicator(clock ?? SystemClock.Instance, DedupeWindow);

        // Captured once. Reading it per event would be a syscall on the hot path, and
        // the machine name cannot change while the agent is running.
        _machineName = SafeMachineName();
    }

    /// <summary>
    /// Starts a user-mode session bound to the DNS-Client provider and begins pumping.
    /// Throws only when DNS telemetry genuinely cannot be collected, so the host can
    /// degrade to running without domain visibility.
    /// </summary>
    public void Start()
    {
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("DNS ETW requires Administrator");

        EtwSessionSupport.ClearStaleSession(SessionName, _log);

        TraceEventSession? session = null;
        try
        {
            session = new TraceEventSession(SessionName) { StopOnDispose = true };

            // Enabled by GUID rather than by name: the friendly name resolves through a
            // registry lookup that can fail on a stripped or policy-locked image, and a
            // GUID cannot be shadowed by a rogue registration.
            session.EnableProvider(DnsClientProvider, TraceEventLevel.Informational);

            // Dynamic covers manifest providers registered with the OS, which is what
            // DNS-Client is. Subscribing to All and filtering by provider GUID is
            // cheaper and more version-proof than binding to a generated parser.
            session.Source.Dynamic.All += data => Guard(() => OnEvent(data));

            _session = session;
            _pump = new Thread(PumpEvents) { IsBackground = true, Name = "ProcessShield-ETW-Dns" };
            _pump.Start();
        }
        catch
        {
            try { session?.Dispose(); } catch { }
            throw;   // let the host continue without DNS telemetry
        }
    }

    private void OnEvent(TraceEvent data)
    {
        if (data.ProviderGuid != DnsClientProvider) return;

        int id = (int)data.ID;
        if (id != EventQueryInitiated && id != EventQueryCompleted) return;

        string? raw = EtwSessionSupport.GetString(data, "QueryName", "Name", "DnsQueryName")
                      ?? EtwSessionSupport.PayloadLike(data, "queryname") as string
                      ?? EtwSessionSupport.PayloadLike(data, "name") as string;

        string domain = MonitorSupport.NormalizeDomain(raw);
        if (domain.Length == 0) return;
        if (MonitorSupport.IsIgnorableDomain(domain, _machineName)) return;

        // QueryStatus is a Win32/DNS error code; 0 means the lookup succeeded.
        // Absent on 3006 and on builds that renamed it, in which case we treat the
        // lookup as successful rather than inventing a failure.
        uint status = EtwSessionSupport.GetUInt32(data, 0, "QueryStatus", "Status", "QueryResult");
        bool failed = status != 0;

        if (id == EventQueryCompleted && !failed) return;

        string detail = failed
            ? $"dns-failed:{status}"
            : "dns-query";

        uint type = EtwSessionSupport.GetUInt32(data, 0, "QueryType", "Type");
        if (type != 0) detail += $";type={type}";

        // Separate dedupe namespaces for the query and the failure, so a failing name
        // is reported once as a query and once as a failure rather than losing the
        // NXDOMAIN evidence to the earlier 3006.
        string bucket = failed ? "fail" : "query";
        if (!_dedupe.ShouldEmit($"{data.ProcessID}|{bucket}|{domain}")) return;

        _emit(new Signal
        {
            Kind = SignalKind.DnsQuery,
            Pid = data.ProcessID,
            ProcessName = data.ProcessName ?? "",
            Domain = domain,
            Detail = detail,
            TimestampUtc = data.TimeStamp.ToUniversalTime()
        });
    }

    private static string SafeMachineName()
    {
        try { return Environment.MachineName; }
        catch { return ""; }
    }

    private void PumpEvents()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            _log.Error("DNS ETW pump stopped", ex);
        }
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) { _log.Error("DNS ETW event handler", ex); }
    }

    public void Dispose()
    {
        try { _session?.Dispose(); } catch { }
        _session = null;
    }
}
