using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace ProcessShield.Analysis;

/// <summary>Where an endpoint appears to be, plus how much that claim is worth.</summary>
public sealed record GeoLocation
{
    /// <summary>ISO 3166-1 alpha-2, or "" when the address could not be placed.</summary>
    public required string CountryCode { get; init; }
    public required string Country { get; init; }
    public required double Latitude { get; init; }
    public required double Longitude { get; init; }
    /// <summary>True for RFC1918 / loopback / link-local / CGNAT — on this network, not on the map.</summary>
    public required bool IsPrivate { get; init; }

    public static readonly GeoLocation Unknown = new()
    {
        CountryCode = "", Country = "Unknown", Latitude = 0, Longitude = 0, IsPrivate = false,
    };

    public static readonly GeoLocation Local = new()
    {
        CountryCode = "", Country = "Local network", Latitude = 0, Longitude = 0, IsPrivate = true,
    };
}

/// <summary>
/// Offline, coarse IPv4 geolocation.
///
/// IMPORTANT, and stated plainly because a map invites over-trust: this resolves the
/// country the address block was ALLOCATED to, per the RIR delegation statistics. It is
/// not where the packet went. A CDN, an anycast address or a VPS reseller will place a
/// marker on the wrong continent, and it is /16-granular, so a small allocation inside a
/// larger foreign block inherits the larger block's country.
///
/// It is deliberately offline: an EDR agent must not phone a geo-IP service, because that
/// leaks exactly which infrastructure the defender is investigating, to a third party, in
/// real time. A wrong dot on a map is a smaller problem than that.
///
/// IPv6 is not mapped at all (returns Unknown) rather than guessed at.
/// </summary>
public sealed class GeoIpDatabase
{
    private const int BlockCount = 65536;   // one entry per /16

    private readonly ushort[] _blocks;
    private readonly string[] _codes;
    private readonly string[] _names;
    private readonly double[] _lat;
    private readonly double[] _lon;

    /// <summary>An empty database. Every lookup returns Unknown (or Local for private space).</summary>
    public static readonly GeoIpDatabase Empty = new(
        new ushort[BlockCount], new[] { "" }, new[] { "Unknown" }, new[] { 0d }, new[] { 0d });

    public int CountryCount => Math.Max(0, _codes.Length - 1);
    public bool IsLoaded => CountryCount > 0;

    private GeoIpDatabase(ushort[] blocks, string[] codes, string[] names, double[] lat, double[] lon)
    {
        _blocks = blocks;
        _codes = codes;
        _names = names;
        _lat = lat;
        _lon = lon;
    }

    /// <summary>
    /// Loads the table from a directory holding <c>ipv4-country.bin</c> and
    /// <c>countries.csv</c>. Any problem yields <see cref="Empty"/> and a warning: the map
    /// is a convenience, and nothing about detection may depend on it loading.
    /// </summary>
    public static GeoIpDatabase Load(string directory, Action<string>? warn = null)
    {
        try
        {
            string bin = Path.Combine(directory, "ipv4-country.bin");
            string csv = Path.Combine(directory, "countries.csv");
            if (!File.Exists(bin) || !File.Exists(csv))
            {
                warn?.Invoke($"geo database not found in '{directory}'; the map will show endpoints as unplaced");
                return Empty;
            }

            var raw = File.ReadAllBytes(bin);
            if (raw.Length != BlockCount * 2)
            {
                warn?.Invoke($"geo table has unexpected size {raw.Length}; ignoring");
                return Empty;
            }

            var blocks = new ushort[BlockCount];
            Buffer.BlockCopy(raw, 0, blocks, 0, raw.Length);

            // index 0 is reserved for "unknown", so the arrays are 1-based by construction.
            var codes = new List<string> { "" };
            var names = new List<string> { "Unknown" };
            var lats = new List<double> { 0 };
            var lons = new List<double> { 0 };

            foreach (var line in File.ReadLines(csv).Skip(1))
            {
                var f = SplitCsv(line);
                if (f.Length < 5) continue;
                if (!int.TryParse(f[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out int idx)) continue;
                if (idx != codes.Count)
                {
                    warn?.Invoke("geo country table is not contiguous; ignoring");
                    return Empty;
                }
                codes.Add(f[1]);
                names.Add(f[2]);
                lats.Add(double.Parse(f[3], CultureInfo.InvariantCulture));
                lons.Add(double.Parse(f[4], CultureInfo.InvariantCulture));
            }

            if (codes.Count <= 1)
            {
                warn?.Invoke("geo country table is empty; ignoring");
                return Empty;
            }

            // A block index pointing past the country table would throw on lookup, so
            // clamp once here rather than bounds-checking on every packet.
            for (int i = 0; i < blocks.Length; i++)
                if (blocks[i] >= codes.Count) blocks[i] = 0;

            return new GeoIpDatabase(blocks, codes.ToArray(), names.ToArray(), lats.ToArray(), lons.ToArray());
        }
        catch (Exception ex)
        {
            warn?.Invoke("geo database load failed: " + ex.Message);
            return Empty;
        }
    }

    /// <summary>Locates a dotted-quad address. Never throws.</summary>
    public GeoLocation Locate(string? address)
    {
        if (string.IsNullOrWhiteSpace(address)) return GeoLocation.Unknown;
        string s = address.Trim();

        // IPAddress.TryParse accepts historical shorthand: "1.2.3" parses as 1.2.0.3, and
        // "16909060" as 1.2.3.4. Both would place a marker for an address nobody wrote.
        // Monitors always emit full dotted quads, so anything with dots must have four
        // parts or it is malformed and stays unplaced.
        if (s.Contains('.'))
        {
            var parts = s.Split('.');
            if (parts.Length != 4) return GeoLocation.Unknown;
        }
        else if (!s.Contains(':'))
        {
            return GeoLocation.Unknown;   // bare integer form
        }

        if (!IPAddress.TryParse(s, out var ip)) return GeoLocation.Unknown;
        return Locate(ip);
    }

    public GeoLocation Locate(IPAddress ip)
    {
        try
        {
            if (IsPrivate(ip)) return GeoLocation.Local;
            if (ip.AddressFamily != AddressFamily.InterNetwork) return GeoLocation.Unknown;

            var b = ip.GetAddressBytes();
            int block = (b[0] << 8) | b[1];
            int idx = _blocks[block];
            if (idx == 0) return GeoLocation.Unknown;

            return new GeoLocation
            {
                CountryCode = _codes[idx],
                Country = _names[idx],
                Latitude = _lat[idx],
                Longitude = _lon[idx],
                IsPrivate = false,
            };
        }
        catch { return GeoLocation.Unknown; }
    }

    /// <summary>
    /// Address space that never belongs on a world map: loopback, RFC1918, link-local,
    /// CGNAT, documentation and multicast. Mirrors NetworkUtil.IsRoutableRemote's intent,
    /// but reports "local" rather than merely filtering, so the UI can say so.
    /// </summary>
    public static bool IsPrivate(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast
                || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.IPv6None);

        if (ip.AddressFamily != AddressFamily.InterNetwork) return false;

        var b = ip.GetAddressBytes();
        return b[0] switch
        {
            0 or 10 or 127 => true,
            100 => b[1] >= 64 && b[1] <= 127,             // 100.64/10 CGNAT
            169 => b[1] == 254,                            // link-local
            172 => b[1] >= 16 && b[1] <= 31,
            192 => (b[1] == 168) || (b[1] == 0 && b[2] == 2),
            198 => (b[1] == 18 || b[1] == 19) || (b[1] == 51 && b[2] == 100),
            203 => b[1] == 0 && b[2] == 113,
            >= 224 => true,                                // multicast + reserved + broadcast
            _ => false,
        };
    }

    /// <summary>Minimal CSV field splitter honouring double-quoted fields (country names have commas).</summary>
    private static string[] SplitCsv(string line)
    {
        var fields = new List<string>();
        var cur = new System.Text.StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quoted)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; }
                    else quoted = false;
                }
                else cur.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(cur.ToString()); cur.Clear(); }
            else cur.Append(c);
        }
        fields.Add(cur.ToString());
        return fields.ToArray();
    }
}
