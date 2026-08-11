using System.Globalization;
using System.Text;
using ProcessShield.Core;

namespace ProcessShield.Api;

// ---------------------------------------------------------------------------
// The EDR-native half of API Studio.
//
// A generic HTTP client makes you type a URL in. An EDR already knows which
// URLs matter, because it watched the machine contact them. This file turns the
// NetworkConnect + DnsQuery telemetry ProcessShield already collects into an
// inventory of the network/API surface the box actually uses, so the analyst
// starts from observed behaviour and only then inspects an endpoint.
//
// Nothing here performs I/O, resolves names, or opens sockets: it is a pure
// in-memory projection of signals, which keeps it deterministic and testable
// with no network and no privileges.
// ---------------------------------------------------------------------------

/// <summary>
/// One remote destination a monitored process was observed contacting, with the
/// DNS names that were plausibly being resolved for it and any beacon verdict
/// the detection engine attached.
/// </summary>
public sealed record SurfaceEndpoint
{
    /// <summary>
    /// The best available name for the destination: a correlated DNS name when one
    /// exists, otherwise the literal address. This is what the analyst reads, and
    /// what <see cref="ApiSurfaceInventory.ToCollection"/> puts in the request URL,
    /// because probing by name exercises virtual hosting and SNI the way the
    /// original process did.
    /// </summary>
    public required string Host { get; init; }

    /// <summary>The literal remote IP as reported by the monitor. Never inferred.</summary>
    public required string Address { get; init; }

    public required int Port { get; init; }

    /// <summary>
    /// <c>https</c>, <c>http</c> or <c>tcp</c>, derived purely from the port number.
    /// A port number is a guess about protocol, not evidence: real C2 happily serves
    /// TLS on 8080 and plaintext on 443. See <see cref="ApiSurfaceInventory.SchemeForPort"/>.
    /// </summary>
    public required string Scheme { get; init; }

    public int Pid { get; init; }
    public string ProcessName { get; init; } = "";
    public string ImagePath { get; init; } = "";

    /// <summary>How many NetworkConnect signals were folded into this endpoint.</summary>
    public int Connections { get; init; }

    public DateTime FirstSeenUtc { get; init; }
    public DateTime LastSeenUtc { get; init; }

    /// <summary>Mirror of the owning process's signature-trust verdict, for triage ordering.</summary>
    public bool Trusted { get; init; }

    /// <summary>Set by <see cref="ApiSurfaceInventory.MarkBeaconing"/> from the beacon analyzer.</summary>
    public bool Beaconing { get; init; }

    /// <summary>Beacon confidence in [0,1]. Zero when <see cref="Beaconing"/> is false.</summary>
    public double BeaconConfidence { get; init; }

    /// <summary>
    /// DNS names the same process resolved shortly before this connection, newest
    /// first. This is a temporal heuristic, not an answer-to-address mapping — see
    /// the class comment on <see cref="ApiSurfaceInventory"/>.
    /// </summary>
    public IReadOnlyList<string> ResolvedFrom { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Stable identity of the endpoint: process + literal address + port. Deliberately
    /// excludes <see cref="Host"/> and <see cref="Scheme"/>, both of which can be
    /// refined after the endpoint is created (a late DNS correlation renames the host);
    /// keying on them would split one destination into several rows.
    /// </summary>
    public string Key => KeyFor(Pid, Address, Port);

    internal static string KeyFor(int pid, string address, int port) =>
        pid.ToString(CultureInfo.InvariantCulture) + "|" +
        address.ToLowerInvariant() + "|" +
        port.ToString(CultureInfo.InvariantCulture);
}

/// <summary>
/// Bounded, in-memory inventory of every remote endpoint the agent has observed,
/// built from <see cref="SignalKind.NetworkConnect"/> and enriched from
/// <see cref="SignalKind.DnsQuery"/>.
///
/// NOT THREAD-SAFE, by design. Like <see cref="ThreatProfile"/> and the rest of the
/// detection state it is mutated only by the single owner thread in ShieldHost, so it
/// carries no locks. Call <see cref="All"/> to obtain immutable snapshots for other
/// threads (the console, the GUI, the control server).
///
/// DNS CORRELATION IS A HEURISTIC, AND THIS MATTERS:
/// Windows does not hand user-mode ETW consumers a "this answer produced this address
/// for this query" mapping that is safe to rely on, so this class associates a
/// connection with the domains the same PID resolved inside a short preceding window
/// (default 60s). Under heavy concurrent resolution — a browser, or a process
/// deliberately resolving decoy names alongside its real C2 — the association WILL
/// mis-attribute, and an attacker who knows this can poison it on purpose by
/// interleaving lookups. Treat <see cref="SurfaceEndpoint.ResolvedFrom"/> as a lead,
/// never as proof, and note that it says nothing at all about connections made to a
/// hard-coded IP with no lookup, or names resolved over DoH inside the process.
/// </summary>
public sealed class ApiSurfaceInventory
{
    /// <summary>Cap on names carried per endpoint. Beyond a handful the list is noise.</summary>
    private const int MaxResolvedNames = 4;

    /// <summary>Cap on remembered lookups per process, so a DNS flood cannot grow the table.</summary>
    private const int MaxDnsPerPid = 32;

    private readonly IClock _clock;
    private readonly int _max;
    private readonly TimeSpan _dnsWindow;

    // Most-recently-seen first. The LRU list gives O(1) eviction and doubles as the
    // display order, so All() needs no sort and is stable for callers diffing output.
    private readonly LinkedList<Entry> _lru = new();
    private readonly Dictionary<string, LinkedListNode<Entry>> _byKey = new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<int, List<DnsHit>> _dns = new();
    private readonly Dictionary<int, ProcInfo> _procs = new();

    /// <param name="clock">
    /// Time source for first/last-seen stamps and the DNS window. The inventory reads
    /// time from here rather than from <see cref="Signal.TimestampUtc"/> on purpose:
    /// the ETW, WMI and minifilter monitors stamp signals from different clocks, and
    /// mixing them makes the correlation window behave differently depending on which
    /// monitor happened to produce the event. A replayer injects a ManualClock.
    /// </param>
    /// <param name="maxEndpoints">Hard cap on retained endpoints; least-recently-seen is evicted.</param>
    /// <param name="dnsWindow">
    /// How far back a lookup may be and still be associated with a connection.
    /// Longer windows catch cached-then-reused names but mis-attribute far more often.
    /// </param>
    public ApiSurfaceInventory(IClock clock, int maxEndpoints = 4096, TimeSpan? dnsWindow = null)
    {
        if (maxEndpoints <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxEndpoints), "the inventory must be allowed at least one endpoint");

        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _max = maxEndpoints;
        var window = dnsWindow ?? TimeSpan.FromSeconds(60);
        _dnsWindow = window < TimeSpan.Zero ? TimeSpan.Zero : window;
    }

    /// <summary>Number of endpoints currently retained.</summary>
    public int Count => _byKey.Count;

    /// <summary>
    /// Protocol guess from the port alone. 443/8443 read as https, 80/8080 as http, and
    /// everything else as tcp. This is presentation, not detection: it never influences
    /// scoring, precisely because a port number is trivially chosen by the attacker.
    /// </summary>
    public static string SchemeForPort(int port) => port switch
    {
        443 or 8443 => "https",
        80 or 8080 => "http",
        _ => "tcp"
    };

    /// <summary>
    /// Fold one telemetry signal into the inventory. Only NetworkConnect and DnsQuery
    /// are meaningful here; every other kind is ignored rather than rejected so the
    /// host can hand the inventory its whole signal stream without filtering.
    /// </summary>
    public void Observe(Signal signal)
    {
        if (signal is null) return;

        switch (signal.Kind)
        {
            case SignalKind.DnsQuery:
                ObserveDns(signal);
                break;
            case SignalKind.NetworkConnect:
                ObserveConnect(signal);
                break;
            default:
                // ProcessStop deliberately does NOT drop a process's endpoints: the
                // analyst usually starts looking only after the process is gone.
                // Use Forget or Prune to reclaim.
                break;
        }
    }

    /// <summary>
    /// Attach a beacon verdict from the detection engine.
    /// <paramref name="endpoint"/> accepts <c>address</c>, <c>address:port</c>,
    /// <c>[v6addr]:port</c> or <c>scheme://address:port</c>; the bare-address form marks
    /// every port seen for that process, which is what a per-destination beacon verdict
    /// means. Unknown pids and unmatched endpoints are a silent no-op — the analyzer and
    /// the inventory prune independently, so a miss is expected, not an error.
    /// Confidence is clamped to [0,1] and only ever ratchets upward, so a later weaker
    /// observation cannot erase an earlier strong one within the same endpoint's life.
    /// </summary>
    public void MarkBeaconing(int pid, string endpoint, double confidence)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return;
        if (!TryParseEndpointSpec(endpoint, out string address, out int port)) return;

        double c = double.IsNaN(confidence) ? 0.0 : Math.Clamp(confidence, 0.0, 1.0);

        foreach (var node in _byKey.Values)
        {
            var e = node.Value;
            if (e.Pid != pid) continue;
            if (!string.Equals(e.Address, address, StringComparison.OrdinalIgnoreCase)) continue;
            if (port != 0 && e.Port != port) continue;

            e.Beaconing = e.Beaconing || c > 0.0;
            if (c > e.BeaconConfidence) e.BeaconConfidence = c;
        }
    }

    /// <summary>
    /// Record authoritative process identity and the Authenticode trust verdict, and
    /// back-fill every endpoint already recorded for that pid. Signals carry a process
    /// name too, but signature verification happens later and asynchronously, so this
    /// is the only path that can set <see cref="SurfaceEndpoint.Trusted"/>.
    /// Empty name/image arguments do not erase what is already known; trust always applies.
    /// </summary>
    public void SetProcessInfo(int pid, string name, string imagePath, bool trusted)
    {
        var now = _clock.UtcNow;
        var p = GetOrAddProc(pid, now);

        if (!string.IsNullOrWhiteSpace(name)) p.Name = name;
        if (!string.IsNullOrWhiteSpace(imagePath)) p.ImagePath = imagePath;
        p.Trusted = trusted;
        p.TouchedUtc = now;

        Backfill(pid, p);
    }

    /// <summary>
    /// Drop everything remembered about a process: its endpoints, its pending DNS
    /// lookups and its identity. Called on pid reuse, which Windows does aggressively —
    /// keeping stale state would attribute a new process's traffic to a dead one.
    /// </summary>
    public void Forget(int pid)
    {
        var doomed = new List<string>();
        foreach (var kv in _byKey)
            if (kv.Value.Value.Pid == pid) doomed.Add(kv.Key);

        foreach (var key in doomed)
        {
            if (!_byKey.TryGetValue(key, out var node)) continue;
            _lru.Remove(node);
            _byKey.Remove(key);
        }

        _dns.Remove(pid);
        _procs.Remove(pid);
    }

    /// <summary>All endpoints, most recently seen first. Snapshots, safe to hand off.</summary>
    public IReadOnlyList<SurfaceEndpoint> All()
    {
        var list = new List<SurfaceEndpoint>(_lru.Count);
        foreach (var e in _lru) list.Add(e.ToRecord());
        return list;
    }

    /// <summary>Endpoints for one process, most recently seen first.</summary>
    public IReadOnlyList<SurfaceEndpoint> ForPid(int pid)
    {
        var list = new List<SurfaceEndpoint>();
        foreach (var e in _lru)
            if (e.Pid == pid) list.Add(e.ToRecord());
        return list;
    }

    /// <summary>
    /// Endpoints whose port suggests HTTP(S). These are the ones API Studio can inspect
    /// meaningfully; a tcp endpoint on 4444 is interesting to a hunter but not to an
    /// HTTP client.
    /// </summary>
    public IReadOnlyList<SurfaceEndpoint> HttpEndpoints()
    {
        var list = new List<SurfaceEndpoint>();
        foreach (var e in _lru)
            if (e.Scheme is "http" or "https") list.Add(e.ToRecord());
        return list;
    }

    /// <summary>
    /// Project endpoints into an API Studio collection: exactly one GET per distinct
    /// scheme + host + port root, so the analyst can open a discovered destination and
    /// look at it immediately. Requests get deterministic ids derived from the root, so
    /// re-running discovery produces a reviewable diff instead of a wall of new GUIDs.
    ///
    /// Two honest caveats, both restated in the collection description:
    ///  * Running these requests CONTACTS the host. On live malware infrastructure that
    ///    is an observable action. The collection is inert until something runs it, and
    ///    the runner's <see cref="ApiSafetyPolicy"/> still has to allow the host.
    ///  * A non-HTTP (tcp) endpoint is emitted as a speculative http:// probe, because a
    ///    GET is the only thing this tool can send. Expect it to fail on a real
    ///    non-HTTP service; that failure is information, not a bug.
    /// </summary>
    public ApiCollection ToCollection(string name, IReadOnlyList<SurfaceEndpoint> endpoints)
    {
        var order = new List<string>();
        var groups = new Dictionary<string, Group>(StringComparer.OrdinalIgnoreCase);

        foreach (var ep in endpoints ?? Array.Empty<SurfaceEndpoint>())
        {
            if (ep is null) continue;
            if (ep.Port <= 0 || ep.Port > 65535) continue;

            string host = StripBrackets((string.IsNullOrWhiteSpace(ep.Host) ? ep.Address : ep.Host).Trim());
            if (host.Length == 0) continue;

            string scheme = string.IsNullOrWhiteSpace(ep.Scheme)
                ? SchemeForPort(ep.Port)
                : ep.Scheme.Trim().ToLowerInvariant();

            string gk = scheme + "|" + host.ToLowerInvariant() + "|" + ep.Port.ToString(CultureInfo.InvariantCulture);
            if (!groups.TryGetValue(gk, out var g))
            {
                g = new Group { Scheme = scheme, Host = host, Port = ep.Port };
                groups[gk] = g;
                order.Add(gk);
            }

            g.Connections += ep.Connections;
            if (!g.Pids.Contains(ep.Pid)) g.Pids.Add(ep.Pid);
            if (g.ProcessName.Length == 0 && !string.IsNullOrWhiteSpace(ep.ProcessName)) g.ProcessName = ep.ProcessName;
            if (ep.Beaconing) g.Beaconing = true;
            if (ep.BeaconConfidence > g.BeaconConfidence) g.BeaconConfidence = ep.BeaconConfidence;
            if (!ep.Trusted) g.AnyUntrusted = true;

            foreach (var d in ep.ResolvedFrom)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                if (!g.ResolvedFrom.Contains(d, StringComparer.OrdinalIgnoreCase)) g.ResolvedFrom.Add(d);
            }
        }

        var requests = new List<ApiRequest>(order.Count);
        foreach (var gk in order)
        {
            var g = groups[gk];
            string url = RootUrl(g.Scheme, g.Host, g.Port);
            string label = g.Port is 80 or 443
                ? g.Host
                : g.Host + ":" + g.Port.ToString(CultureInfo.InvariantCulture);

            requests.Add(new ApiRequest
            {
                Id = "surface-" + Slug(g.Scheme + "-" + g.Host + "-" + g.Port.ToString(CultureInfo.InvariantCulture)),
                Name = g.ProcessName.Length == 0 ? label : g.ProcessName + " -> " + label,
                Method = "GET",
                Url = url,
                Description = Describe(g)
            });
        }

        return new ApiCollection
        {
            Name = string.IsNullOrWhiteSpace(name) ? "Discovered API surface" : name.Trim(),
            Description =
                "Generated from ProcessShield network telemetry: one GET per distinct scheme/host/port " +
                "that a monitored process was observed contacting. Nothing here has been requested yet — " +
                "sending these probes contacts the hosts, which is observable by whoever owns them, and " +
                "the run-time safety policy must still allow each host. Ports imply the scheme, so a " +
                "non-HTTP service is probed over http:// and is expected to fail.",
            Root = new ApiFolder { Name = "Discovered", Requests = requests }
        };
    }

    /// <summary>
    /// Drop endpoints (and remembered lookups) untouched for longer than
    /// <paramref name="olderThan"/>. A negative span puts the cutoff in the future and
    /// therefore clears everything, which is a legitimate way to reset the inventory.
    /// </summary>
    public void Prune(TimeSpan olderThan)
    {
        var cutoff = _clock.UtcNow - olderThan;

        var doomed = new List<string>();
        foreach (var kv in _byKey)
            if (kv.Value.Value.LastSeenUtc < cutoff) doomed.Add(kv.Key);

        foreach (var key in doomed)
        {
            if (!_byKey.TryGetValue(key, out var node)) continue;
            _lru.Remove(node);
            _byKey.Remove(key);
        }

        var deadPids = new List<int>();
        foreach (var kv in _dns)
        {
            kv.Value.RemoveAll(h => h.AtUtc < cutoff);
            if (kv.Value.Count == 0) deadPids.Add(kv.Key);
        }
        foreach (var pid in deadPids) _dns.Remove(pid);

        var deadProcs = new List<int>();
        foreach (var kv in _procs)
            if (kv.Value.TouchedUtc < cutoff) deadProcs.Add(kv.Key);
        foreach (var pid in deadProcs) _procs.Remove(pid);
    }

    // ------------------------------------------------------------------ internals

    private void ObserveDns(Signal signal)
    {
        string domain = NormalizeDomain(signal.Domain);
        if (domain.Length == 0) return;

        var now = _clock.UtcNow;
        if (!_dns.TryGetValue(signal.Pid, out var list))
        {
            list = new List<DnsHit>();
            _dns[signal.Pid] = list;
        }

        list.RemoveAll(h => now - h.AtUtc > _dnsWindow);
        list.RemoveAll(h => string.Equals(h.Domain, domain, StringComparison.Ordinal));
        list.Insert(0, new DnsHit(domain, now));
        if (list.Count > MaxDnsPerPid) list.RemoveRange(MaxDnsPerPid, list.Count - MaxDnsPerPid);

        TrimDnsTable();
    }

    private void ObserveConnect(Signal signal)
    {
        string address = StripBrackets((signal.RemoteAddress ?? "").Trim());
        if (address.Length == 0) return;

        int port = signal.RemotePort;
        if (port <= 0 || port > 65535) return;

        var now = _clock.UtcNow;
        var proc = TouchProc(signal, now);
        string key = SurfaceEndpoint.KeyFor(signal.Pid, address, port);

        Entry entry;
        if (_byKey.TryGetValue(key, out var node))
        {
            entry = node.Value;
            entry.Connections++;
            entry.LastSeenUtc = now;
            _lru.Remove(node);
            _lru.AddFirst(node);
        }
        else
        {
            entry = new Entry
            {
                Pid = signal.Pid,
                Address = address,
                Port = port,
                Scheme = SchemeForPort(port),
                Host = address,
                Connections = 1,
                FirstSeenUtc = now,
                LastSeenUtc = now
            };
            var added = _lru.AddFirst(entry);
            _byKey[key] = added;
            EvictIfOverCapacity();
        }

        entry.ProcessName = proc.Name;
        entry.ImagePath = proc.ImagePath;
        entry.Trusted = proc.Trusted;

        ApplyDns(entry, signal.Pid, now);
    }

    private void ApplyDns(Entry entry, int pid, DateTime now)
    {
        if (!_dns.TryGetValue(pid, out var list) || list.Count == 0) return;

        var fresh = new List<string>();
        foreach (var hit in list)   // already newest-first
        {
            if (now - hit.AtUtc > _dnsWindow) continue;
            fresh.Add(hit.Domain);
            if (fresh.Count >= MaxResolvedNames) break;
        }
        if (fresh.Count == 0) return;

        var toAdd = new List<string>();
        foreach (var d in fresh)
            if (!entry.ResolvedFrom.Contains(d, StringComparer.OrdinalIgnoreCase))
                toAdd.Add(d);

        if (toAdd.Count > 0)
        {
            entry.ResolvedFrom.InsertRange(0, toAdd);
            if (entry.ResolvedFrom.Count > MaxResolvedNames)
                entry.ResolvedFrom.RemoveRange(MaxResolvedNames, entry.ResolvedFrom.Count - MaxResolvedNames);
        }

        // Host is named once and then left alone. Re-pointing it at whatever was
        // resolved most recently would make the same destination change identity
        // between reports, which is exactly the instability an analyst cannot work
        // around. Later names are still visible in ResolvedFrom.
        if (!entry.HostFromDns)
        {
            entry.Host = fresh[0];
            entry.HostFromDns = true;
        }
    }

    private ProcInfo TouchProc(Signal signal, DateTime now)
    {
        var p = GetOrAddProc(signal.Pid, now);
        bool changed = false;

        if (p.Name.Length == 0 && !string.IsNullOrWhiteSpace(signal.ProcessName))
        {
            p.Name = signal.ProcessName;
            changed = true;
        }
        if (p.ImagePath.Length == 0 && !string.IsNullOrWhiteSpace(signal.ImagePath))
        {
            p.ImagePath = signal.ImagePath;
            changed = true;
        }
        p.TouchedUtc = now;

        // Only back-fill on a transition from unknown to known; doing it on every
        // connect would be an O(endpoints) walk per packet-ish event.
        if (changed) Backfill(signal.Pid, p);
        return p;
    }

    private ProcInfo GetOrAddProc(int pid, DateTime now)
    {
        if (_procs.TryGetValue(pid, out var p)) return p;

        p = new ProcInfo { TouchedUtc = now };
        _procs[pid] = p;
        TrimProcTable();
        return p;
    }

    private void Backfill(int pid, ProcInfo p)
    {
        // Metadata refresh is not activity: it must not reorder the LRU, or a
        // signature-verification sweep would keep dead endpoints alive forever.
        foreach (var node in _byKey.Values)
        {
            var e = node.Value;
            if (e.Pid != pid) continue;
            e.ProcessName = p.Name;
            e.ImagePath = p.ImagePath;
            e.Trusted = p.Trusted;
        }
    }

    private void EvictIfOverCapacity()
    {
        while (_byKey.Count > _max)
        {
            var last = _lru.Last;
            if (last is null) return;
            _lru.RemoveLast();
            _byKey.Remove(SurfaceEndpoint.KeyFor(last.Value.Pid, last.Value.Address, last.Value.Port));
        }
    }

    private void TrimDnsTable()
    {
        if (_dns.Count <= _max) return;

        int victim = 0;
        var oldest = DateTime.MaxValue;
        foreach (var kv in _dns)
        {
            var stamp = kv.Value.Count == 0 ? DateTime.MinValue : kv.Value[0].AtUtc;
            if (stamp < oldest) { oldest = stamp; victim = kv.Key; }
        }
        _dns.Remove(victim);
    }

    private void TrimProcTable()
    {
        if (_procs.Count <= _max) return;

        int victim = 0;
        var oldest = DateTime.MaxValue;
        foreach (var kv in _procs)
            if (kv.Value.TouchedUtc < oldest) { oldest = kv.Value.TouchedUtc; victim = kv.Key; }
        _procs.Remove(victim);
    }

    private static string NormalizeDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return "";
        string d = domain.Trim().TrimEnd('.').Trim();
        return d.ToLowerInvariant();
    }

    private static string StripBrackets(string value) =>
        value.Length >= 2 && value[0] == '[' && value[^1] == ']' ? value[1..^1] : value;

    /// <summary>
    /// Parse a beacon-analyzer endpoint string. Returns port 0 for the bare-address
    /// form, which callers treat as "any port for this address".
    /// </summary>
    internal static bool TryParseEndpointSpec(string spec, out string address, out int port)
    {
        address = "";
        port = 0;
        if (string.IsNullOrWhiteSpace(spec)) return false;

        string s = spec.Trim();

        int scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];

        int slash = s.IndexOf('/');
        if (slash >= 0) s = s[..slash];
        if (s.Length == 0) return false;

        if (s[0] == '[')
        {
            int close = s.IndexOf(']');
            if (close < 0) return false;
            address = s[1..close];
            string tail = s[(close + 1)..];
            if (tail.Length > 0)
            {
                if (tail[0] != ':') return false;
                if (!int.TryParse(tail[1..], NumberStyles.None, CultureInfo.InvariantCulture, out port)) return false;
            }
        }
        else
        {
            int colon = s.LastIndexOf(':');
            // More than one colon and no brackets means a bare IPv6 literal, which has
            // no unambiguous port suffix; treat the whole thing as the address.
            bool v6 = s.IndexOf(':') != colon;
            if (colon > 0 && !v6 &&
                int.TryParse(s[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int parsed))
            {
                address = s[..colon];
                port = parsed;
            }
            else
            {
                address = s;
            }
        }

        if (address.Length == 0) return false;
        if (port is < 0 or > 65535) { port = 0; return false; }
        return true;
    }

    private static string RootUrl(string scheme, string host, int port)
    {
        // A GET is all this tool can send, so a non-HTTP port is probed over http.
        string probe = scheme is "http" or "https" ? scheme : "http";
        string authority = host.Contains(':') ? "[" + host + "]" : host;
        bool defaultPort = (probe == "https" && port == 443) || (probe == "http" && port == 80);
        return defaultPort
            ? probe + "://" + authority + "/"
            : probe + "://" + authority + ":" + port.ToString(CultureInfo.InvariantCulture) + "/";
    }

    private static string Describe(Group g)
    {
        var sb = new StringBuilder();
        sb.Append("Discovered from ProcessShield network telemetry: ")
          .Append(g.Connections.ToString(CultureInfo.InvariantCulture))
          .Append(g.Connections == 1 ? " connection from " : " connections from ");

        sb.Append(g.Pids.Count == 1 ? "pid " : "pids ");
        for (int i = 0; i < g.Pids.Count; i++)
        {
            if (i > 0) sb.Append(", ");
            sb.Append(g.Pids[i].ToString(CultureInfo.InvariantCulture));
        }
        if (g.ProcessName.Length > 0) sb.Append(" (").Append(g.ProcessName).Append(')');
        sb.Append('.');

        if (g.ResolvedFrom.Count > 0)
            sb.Append(" Possibly resolved from ").Append(string.Join(", ", g.ResolvedFrom))
              .Append(" (heuristic time-window association, not a DNS answer mapping).");

        if (g.Beaconing)
            sb.Append(" Beaconing suspected, confidence ")
              .Append(g.BeaconConfidence.ToString("0.00", CultureInfo.InvariantCulture)).Append('.');

        if (!g.AnyUntrusted)
            sb.Append(" Every observing process is signature-trusted.");

        if (g.Scheme is not ("http" or "https"))
            sb.Append(" Port ").Append(g.Port.ToString(CultureInfo.InvariantCulture))
              .Append(" is not a known HTTP port; this GET is a speculative probe and may legitimately fail.");

        return sb.ToString();
    }

    private static string Slug(string value)
    {
        var sb = new StringBuilder(value.Length);
        bool lastDash = false;
        foreach (char ch in value.ToLowerInvariant())
        {
            bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
            if (ok) { sb.Append(ch); lastDash = false; }
            else if (!lastDash) { sb.Append('-'); lastDash = true; }
        }
        return sb.ToString().Trim('-');
    }

    private readonly record struct DnsHit(string Domain, DateTime AtUtc);

    private sealed class ProcInfo
    {
        public string Name = "";
        public string ImagePath = "";
        public bool Trusted;
        public DateTime TouchedUtc;
    }

    private sealed class Group
    {
        public string Scheme = "tcp";
        public string Host = "";
        public int Port;
        public int Connections;
        public string ProcessName = "";
        public bool Beaconing;
        public double BeaconConfidence;
        public bool AnyUntrusted;
        public readonly List<int> Pids = new();
        public readonly List<string> ResolvedFrom = new();
    }

    /// <summary>Mutable interior form; <see cref="SurfaceEndpoint"/> is the public snapshot.</summary>
    private sealed class Entry
    {
        public int Pid;
        public string Address = "";
        public int Port;
        public string Scheme = "tcp";
        public string Host = "";
        public string ProcessName = "";
        public string ImagePath = "";
        public int Connections;
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public bool Trusted;
        public bool Beaconing;
        public double BeaconConfidence;
        public bool HostFromDns;
        public readonly List<string> ResolvedFrom = new();

        public SurfaceEndpoint ToRecord() => new()
        {
            Host = Host,
            Address = Address,
            Port = Port,
            Scheme = Scheme,
            Pid = Pid,
            ProcessName = ProcessName,
            ImagePath = ImagePath,
            Connections = Connections,
            FirstSeenUtc = FirstSeenUtc,
            LastSeenUtc = LastSeenUtc,
            Trusted = Trusted,
            Beaconing = Beaconing,
            BeaconConfidence = BeaconConfidence,
            ResolvedFrom = ResolvedFrom.ToArray()
        };
    }
}
