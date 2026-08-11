using ProcessShield.Api;
using ProcessShield.Detection;

namespace ProcessShield.Gui.ViewModels;

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

    public SurfaceRow(SurfaceEndpoint e)
    {
        Key = e.Key;
        Update(e);
    }

    public void Update(SurfaceEndpoint e)
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
