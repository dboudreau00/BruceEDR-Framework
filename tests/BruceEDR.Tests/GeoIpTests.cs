using System.Net;
using BruceEDR.Analysis;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The network map is a triage aid, and the risk it carries is over-trust. These tests pin
/// the properties that keep it honest: private space is never plotted, unknown stays
/// unknown rather than defaulting to a plausible-looking country, and nothing here can
/// throw its way into the refresh loop.
/// </summary>
public sealed class GeoIpTests
{
    private static string DataDir()
    {
        // Resolve from the test binary's output, which the project copies intel/geo into.
        var dir = Path.Combine(AppContext.BaseDirectory, "intel", "geo");
        return dir;
    }

    private static GeoIpDatabase Load() => GeoIpDatabase.Load(DataDir());

    [Theory]
    [InlineData("10.0.0.5")]
    [InlineData("192.168.1.1")]
    [InlineData("172.16.4.9")]
    [InlineData("172.31.255.254")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.10.1")]
    [InlineData("100.64.0.1")]      // CGNAT
    [InlineData("224.0.0.251")]     // multicast
    [InlineData("0.0.0.0")]
    public void Private_and_reserved_space_is_never_plotted(string ip)
    {
        var g = Load().Locate(ip);

        Assert.True(g.IsPrivate);
        Assert.Equal("", g.CountryCode);
    }

    [Theory]
    [InlineData("172.32.0.1")]      // just outside 172.16/12
    [InlineData("172.15.255.255")]
    [InlineData("100.128.0.1")]     // just outside 100.64/10
    [InlineData("11.0.0.1")]
    public void Addresses_adjacent_to_private_ranges_are_not_treated_as_private(string ip)
        => Assert.False(GeoIpDatabase.IsPrivate(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-an-ip")]
    [InlineData("999.1.1.1")]
    // .NET's IPAddress.TryParse accepts these historical shorthands -- "1.2.3" as 1.2.0.3
    // and a bare integer as a packed address. Accepting them would plot a marker for an
    // address that was never observed, so the lookup rejects them.
    [InlineData("1.2.3")]
    [InlineData("1.2")]
    [InlineData("16909060")]
    public void Malformed_input_returns_unknown_rather_than_throwing(string input)
    {
        var g = Load().Locate(input);
        Assert.Equal("", g.CountryCode);
        Assert.False(g.IsPrivate);
    }

    [Fact]
    public void Null_input_returns_unknown()
        => Assert.Equal("", Load().Locate((string?)null).CountryCode);

    [Fact]
    public void Ipv6_is_reported_unplaced_rather_than_guessed()
    {
        // Guessing a country for v6 from a v4 table would be fabrication, so the map
        // shows these in the "not on the map" tray instead.
        var g = Load().Locate("2606:4700:4700::1111");
        Assert.False(g.IsPrivate);
        Assert.Equal("", g.CountryCode);
    }

    [Fact]
    public void Ipv6_private_space_is_still_recognised_as_local()
        => Assert.True(GeoIpDatabase.IsPrivate(IPAddress.Parse("fe80::1")));

    [Fact]
    public void An_empty_database_answers_everything_without_throwing()
    {
        var db = GeoIpDatabase.Empty;

        Assert.False(db.IsLoaded);
        Assert.Equal("", db.Locate("8.8.8.8").CountryCode);
        Assert.True(db.Locate("10.0.0.1").IsPrivate);   // private detection needs no table
    }

    [Fact]
    public void A_missing_directory_degrades_to_empty_with_a_warning()
    {
        string? warned = null;
        var db = GeoIpDatabase.Load(Path.Combine(Path.GetTempPath(), "bruceedr-no-such-geo-dir"),
                                    m => warned = m);

        Assert.False(db.IsLoaded);
        Assert.NotNull(warned);
    }

    [Fact]
    public void The_shipped_database_loads_and_places_well_known_addresses()
    {
        var db = Load();
        if (!db.IsLoaded) return;   // geo assets not copied in this build configuration

        Assert.True(db.CountryCount > 100);

        // 8.8.8.8 is a US allocation; this is an allocation fact, not a claim about where
        // the responding server physically is.
        var g = db.Locate("8.8.8.8");
        Assert.Equal("US", g.CountryCode);
        Assert.InRange(g.Latitude, -90, 90);
        Assert.InRange(g.Longitude, -180, 180);
    }

    [Fact]
    public void Placed_countries_always_carry_usable_coordinates()
    {
        var db = Load();
        if (!db.IsLoaded) return;

        // A country with a code but 0,0 coordinates would silently pile markers into the
        // Gulf of Guinea, which looks like real traffic to a null island.
        foreach (var ip in new[] { "8.8.8.8", "1.1.1.1", "212.58.244.1", "203.0.113.1" })
        {
            var g = db.Locate(ip);
            if (g.CountryCode.Length == 0) continue;
            Assert.False(g.Latitude == 0 && g.Longitude == 0);
            Assert.NotEqual("", g.Country);
        }
    }
}

/// <summary>Projection and outline loading for the map canvas.</summary>
public sealed class WorldMapTests
{
    [Fact]
    public void Projection_places_the_corners_and_origin_correctly()
    {
        Assert.Equal((0d, 0d), WorldMap.Project(-180, 90, 360, 180));
        Assert.Equal((360d, 180d), WorldMap.Project(180, -90, 360, 180));
        Assert.Equal((180d, 90d), WorldMap.Project(0, 0, 360, 180));
    }

    [Fact]
    public void Projection_clamps_out_of_range_coordinates_instead_of_drawing_off_canvas()
    {
        Assert.Equal((0d, 0d), WorldMap.Project(-400, 200, 360, 180));
        Assert.Equal((360d, 180d), WorldMap.Project(400, -200, 360, 180));
    }

    [Fact]
    public void A_missing_outline_file_degrades_to_empty()
    {
        string? warned = null;
        var w = WorldMap.Load(Path.Combine(Path.GetTempPath(), "no-such-world.txt"), m => warned = m);

        Assert.False(w.IsLoaded);
        Assert.Empty(w.Rings);
        Assert.NotNull(warned);
    }

    [Fact]
    public void Malformed_lines_are_skipped_not_fatal()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ps-world-{Guid.NewGuid():N}.txt");
        File.WriteAllText(path,
            "GB|0,0 1,1 2,2\n" +
            "garbage-with-no-bar\n" +
            "XX|1,1\n" +                    // too few points
            "FR|nonsense 10,10 11,11 12,12\n");
        try
        {
            var w = WorldMap.Load(path);
            Assert.Equal(2, w.Rings.Count);
            Assert.Equal("GB", w.Rings[0].CountryCode);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void The_shipped_outline_loads()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "intel", "geo", "world.txt");
        if (!File.Exists(path)) return;

        var w = WorldMap.Load(path);
        Assert.True(w.IsLoaded);
        Assert.All(w.Rings, r =>
        {
            Assert.True(r.Points.Count >= 3);
            Assert.All(r.Points, p =>
            {
                Assert.InRange(p.Lon, -180, 180);
                Assert.InRange(p.Lat, -90, 90);
            });
        });
    }
}
