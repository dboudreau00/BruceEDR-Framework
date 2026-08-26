using System.Globalization;

namespace ProcessShield.Analysis;

/// <summary>
/// Simplified world landmass outlines in lon/lat degrees, for drawing an equirectangular
/// map. Derived from Natural Earth 110m admin-0 (public domain) and reduced with
/// Douglas-Peucker, so it carries continent shape without coastal detail no one can see
/// at dashboard size.
/// </summary>
public sealed class WorldMap
{
    /// <summary>One closed outline: an ISO-2 code (may be empty) and its lon/lat points.</summary>
    public sealed record Ring(string CountryCode, IReadOnlyList<(double Lon, double Lat)> Points);

    public static readonly WorldMap Empty = new(Array.Empty<Ring>());

    public IReadOnlyList<Ring> Rings { get; }
    public bool IsLoaded => Rings.Count > 0;

    private WorldMap(IReadOnlyList<Ring> rings) => Rings = rings;

    /// <summary>
    /// Loads <c>world.txt</c> (one ring per line: <c>ISO|lon,lat lon,lat ...</c>). A missing
    /// or malformed file yields <see cref="Empty"/>; the map view then draws its graticule
    /// and markers without landmasses rather than failing.
    /// </summary>
    public static WorldMap Load(string path, Action<string>? warn = null)
    {
        try
        {
            if (!File.Exists(path))
            {
                warn?.Invoke($"world outline not found at '{path}'");
                return Empty;
            }

            var rings = new List<Ring>();
            foreach (var line in File.ReadLines(path))
            {
                if (line.Length == 0) continue;
                int bar = line.IndexOf('|');
                if (bar < 0) continue;

                string iso = line[..bar];
                var pts = new List<(double, double)>();
                foreach (var pair in line[(bar + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    int comma = pair.IndexOf(',');
                    if (comma < 0) continue;
                    if (double.TryParse(pair[..comma], NumberStyles.Float, CultureInfo.InvariantCulture, out var lon) &&
                        double.TryParse(pair[(comma + 1)..], NumberStyles.Float, CultureInfo.InvariantCulture, out var lat))
                        pts.Add((lon, lat));
                }
                if (pts.Count >= 3) rings.Add(new Ring(iso, pts));
            }

            if (rings.Count == 0) warn?.Invoke("world outline contained no usable rings");
            return rings.Count == 0 ? Empty : new WorldMap(rings);
        }
        catch (Exception ex)
        {
            warn?.Invoke("world outline load failed: " + ex.Message);
            return Empty;
        }
    }

    /// <summary>
    /// Equirectangular (plate carrée) projection into a width x height pixel box.
    /// Chosen over anything fancier because it is exactly invertible and trivially
    /// verifiable, which matters more here than area fidelity.
    /// </summary>
    public static (double X, double Y) Project(double lon, double lat, double width, double height)
    {
        double x = (Math.Clamp(lon, -180, 180) + 180.0) / 360.0 * width;
        double y = (90.0 - Math.Clamp(lat, -90, 90)) / 180.0 * height;
        return (x, y);
    }
}
