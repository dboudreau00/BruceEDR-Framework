using BruceEDR.Analysis;
using BruceEDR.Api;
using BruceEDR.Detection;

namespace BruceEDR.Gui.ViewModels;

/// <summary>
/// One observed network/API endpoint in the Surface table. The severity string drives the
/// row colour exactly like <see cref="ThreatRow"/> does, so the two tables read the same
/// way at a glance.
/// </summary>
public sealed class SurfaceRow : ViewModelBase
{
    public string Key { get; }
    public int Pid { get; private set; }
    public string Process { get; private set; } = "";
    public string Host { get; private set; } = "";
    public string Address { get; private set; } = "";
    public int Port { get; private set; }
    public string Scheme { get; private set; } = "";
    public int Connections { get; private set; }
    public bool Beaconing { get; private set; }
    public bool Trusted { get; private set; }
    public string LastSeen { get; private set; } = "";
    public string ResolvedFrom { get; private set; } = "";

    /// <summary>Where the destination block is registered. Never a network lookup; see GeoIpDatabase.</summary>
    public GeoLocation Geo { get; private set; } = GeoLocation.Unknown;

    /// <summary>Encrypted transport, inferred from the port. See the caveat on <see cref="Transport"/>.</summary>
    public bool IsTls => string.Equals(Scheme, "https", StringComparison.OrdinalIgnoreCase);

    /// <summary>Cleartext HTTP — the case an analyst most wants picked out of a list.</summary>
    public bool IsPlaintext => string.Equals(Scheme, "http", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Short transport label for the map. Derived from the PORT, so it is a convention,
    /// not an observation: BruceEDR does not inspect the bytes on the wire, and real
    /// C2 serves TLS on 8080 and cleartext on 443 whenever it suits.
    /// </summary>
    public string Transport => IsTls ? "TLS" : IsPlaintext ? "HTTP" : Scheme.ToUpperInvariant();

    private bool _isHighlighted;
    /// <summary>Set while the analyst hovers this row, or the map marker it belongs to.</summary>
    public bool IsHighlighted { get => _isHighlighted; set => Set(ref _isHighlighted, value); }

    /// <summary>Country name, or the reason there isn't one.</summary>
    public string Location => Geo.IsPrivate ? "Local network"
                            : Geo.CountryCode.Length > 0 ? Geo.Country
                            : "Unplaced";

    /// <summary>Rendered endpoint, preferring the DNS name when one was correlated.</summary>
    public string Endpoint => Host == Address || string.IsNullOrEmpty(Host)
        ? $"{Address}:{Port}"
        : $"{Host}:{Port}";

    public string Detail => Host == Address || string.IsNullOrEmpty(Host) ? "" : Address;

    public string Cadence => Beaconing ? "beaconing" : "—";

    /// <summary>safe | watch | threat — beaconing to an untrusted process is the alarming case.</summary>
    public string Severity => Beaconing && !Trusted ? "threat"
                            : Beaconing ? "watch"
                            : Trusted ? "safe"
                            : "watch";

    public SurfaceRow(SurfaceEndpoint e, GeoIpDatabase? geo = null)
    {
        Key = e.Key;
        Update(e, geo);
    }

    public void Update(SurfaceEndpoint e, GeoIpDatabase? geo = null)
    {
        Pid = e.Pid;
        Process = e.ProcessName;
        Host = e.Host;
        Address = e.Address;
        Port = e.Port;
        Scheme = e.Scheme;
        Connections = e.Connections;
        Beaconing = e.Beaconing;
        Trusted = e.Trusted;
        LastSeen = e.LastSeenUtc.ToLocalTime().ToString("HH:mm:ss");
        ResolvedFrom = string.Join(", ", e.ResolvedFrom);
        Geo = geo?.Locate(e.Address) ?? GeoLocation.Unknown;

        OnPropertyChanged(nameof(Pid));
        OnPropertyChanged(nameof(Process));
        OnPropertyChanged(nameof(Host));
        OnPropertyChanged(nameof(Address));
        OnPropertyChanged(nameof(Port));
        OnPropertyChanged(nameof(Scheme));
        OnPropertyChanged(nameof(Connections));
        OnPropertyChanged(nameof(Beaconing));
        OnPropertyChanged(nameof(Trusted));
        OnPropertyChanged(nameof(LastSeen));
        OnPropertyChanged(nameof(ResolvedFrom));
        OnPropertyChanged(nameof(Endpoint));
        OnPropertyChanged(nameof(Detail));
        OnPropertyChanged(nameof(Cadence));
        OnPropertyChanged(nameof(Severity));
        OnPropertyChanged(nameof(Geo));
        OnPropertyChanged(nameof(IsTls));
        OnPropertyChanged(nameof(IsPlaintext));
        OnPropertyChanged(nameof(Transport));
        OnPropertyChanged(nameof(Location));
    }
}

/// <summary>
/// One MITRE ATT&amp;CK technique in the coverage table: how many loaded rules can detect
/// it, and how many processes on this host have actually exhibited it.
/// </summary>
public sealed class TechniqueRow
{
    public string Id { get; }
    public string Name { get; }
    public string Tactic { get; }
    public string Url { get; }
    public int Rules { get; }
    public int Observed { get; }

    /// <summary>Observed beats covered: an active technique is what an analyst needs to see first.</summary>
    public string Severity => Observed > 0 ? "threat" : Rules > 0 ? "safe" : "watch";

    public string Status => Observed > 0 ? $"seen on {Observed} process(es)"
                          : Rules > 0 ? $"{Rules} rule(s)"
                          : "no coverage";

    public TechniqueRow(string id, int rules, int observed)
    {
        var t = AttackCatalog.Lookup(id);
        Id = t.Id;
        Name = t.Name;
        Tactic = t.Tactic;
        Url = t.Url;
        Rules = rules;
        Observed = observed;
    }
}
