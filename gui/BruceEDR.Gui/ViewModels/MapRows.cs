using BruceEDR.Analysis;
using BruceEDR.Api;

namespace BruceEDR.Gui.ViewModels;

/// <summary>
/// One plotted destination on the network map: a country the processes on this host have
/// been observed connecting to, with the endpoints folded into it.
///
/// Markers are aggregated by country rather than per endpoint because a busy host produces
/// hundreds of connections to a handful of places, and 400 overlapping dots on one city is
/// not a map, it is a smudge.
/// </summary>
public sealed class MapMarker : ViewModelBase
{
    public string CountryCode { get; }
    public string Country { get; }
    public double Latitude { get; }
    public double Longitude { get; }

    /// <summary>Endpoints folded into this marker, worst-first.</summary>
    public IReadOnlyList<SurfaceRow> Endpoints { get; private set; } = Array.Empty<SurfaceRow>();

    public int EndpointCount { get; private set; }
    public int Connections { get; private set; }
    public int ProcessCount { get; private set; }
    public bool HasBeaconing { get; private set; }

    /// <summary>Any endpoint here reached over plaintext HTTP — worth calling out on its own.</summary>
    public bool HasPlaintext { get; private set; }
    public bool HasTls { get; private set; }

    /// <summary>safe | watch | threat — drives the marker colour, same vocabulary as every other view.</summary>
    public string Severity { get; private set; } = "safe";

    /// <summary>Marker radius, grown by traffic volume but clamped so one chatty host cannot fill the map.</summary>
    public double Radius { get; private set; } = 4;

    private bool _isHighlighted;
    /// <summary>Set while the analyst hovers this marker or a row that belongs to it.</summary>
    public bool IsHighlighted { get => _isHighlighted; set => Set(ref _isHighlighted, value); }

    /// <summary>Projected position, recomputed by the view whenever the canvas resizes.</summary>
    private double _x, _y;
    public double X { get => _x; set => Set(ref _x, value); }
    public double Y { get => _y; set => Set(ref _y, value); }

    public MapMarker(string code, string country, double lat, double lon)
    {
        CountryCode = code;
        Country = country;
        Latitude = lat;
        Longitude = lon;
    }

    public void Update(IReadOnlyList<SurfaceRow> endpoints)
    {
        Endpoints = endpoints;
        EndpointCount = endpoints.Count;
        Connections = endpoints.Sum(e => e.Connections);
        ProcessCount = endpoints.Select(e => e.Pid).Distinct().Count();
        HasBeaconing = endpoints.Any(e => e.Beaconing);
        HasPlaintext = endpoints.Any(e => e.IsPlaintext);
        HasTls = endpoints.Any(e => e.IsTls);

        Severity = endpoints.Any(e => e.Severity == "threat") ? "threat"
                 : endpoints.Any(e => e.Severity == "watch") ? "watch"
                 : "safe";

        // sqrt keeps a 1000-connection destination visually larger than a 10-connection one
        // without letting it swallow the continent.
        Radius = Math.Clamp(4 + Math.Sqrt(Connections) * 1.1, 4, 16);

        OnPropertyChanged(nameof(Endpoints));
        OnPropertyChanged(nameof(EndpointCount));
        OnPropertyChanged(nameof(Connections));
        OnPropertyChanged(nameof(ProcessCount));
        OnPropertyChanged(nameof(HasBeaconing));
        OnPropertyChanged(nameof(HasPlaintext));
        OnPropertyChanged(nameof(HasTls));
        OnPropertyChanged(nameof(Severity));
        OnPropertyChanged(nameof(Radius));
        OnPropertyChanged(nameof(Tooltip));
        OnPropertyChanged(nameof(Summary));
    }

    public string Summary
    {
        get
        {
            var parts = new List<string>
            {
                $"{EndpointCount} endpoint{(EndpointCount == 1 ? "" : "s")}",
                $"{ProcessCount} process{(ProcessCount == 1 ? "" : "es")}",
                $"{Connections} conn",
            };
            if (HasBeaconing) parts.Add("beaconing");
            return string.Join(" · ", parts);
        }
    }

    public string Tooltip
    {
        get
        {
            var top = Endpoints.Take(6).Select(e => $"  {e.Process} → {e.Endpoint} ({e.Scheme})");
            string more = EndpointCount > 6 ? $"\n  … {EndpointCount - 6} more" : "";
            return $"{Country}\n{Summary}\n" + string.Join("\n", top) + more;
        }
    }
}

/// <summary>
/// Endpoints that could not be placed: IPv6, unallocated space, and anything on the local
/// network. Kept visible in its own tray so the map never silently drops traffic — a
/// destination missing from the picture is exactly what an analyst must not be misled about.
/// </summary>
public sealed class UnplacedGroup : ViewModelBase
{
    private int _local, _unknown;

    public int LocalCount { get => _local; set => Set(ref _local, value); }
    public int UnknownCount { get => _unknown; set => Set(ref _unknown, value); }
    public bool HasAny => _local + _unknown > 0;

    public void Set(int local, int unknown)
    {
        LocalCount = local;
        UnknownCount = unknown;
        OnPropertyChanged(nameof(HasAny));
    }
}
