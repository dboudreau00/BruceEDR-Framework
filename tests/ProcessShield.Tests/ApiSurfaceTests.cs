using ProcessShield.Api;
using ProcessShield.Core;
using Xunit;

namespace ProcessShield.Tests;

// ---------------------------------------------------------------------------
// Tests for the EDR-native half of API Studio: the observed-surface inventory
// (Api/ApiSurface.cs) and the loopback control plane's pure routing table
// (Api/ControlServer.cs).
//
// Nothing here touches the network, binds a socket or needs a privilege. The
// single Start() test uses a prefix that must be REFUSED before any bind is
// attempted, which is exactly the behaviour under test.
// ---------------------------------------------------------------------------

public class ApiSurfaceInventoryTests
{
    private static readonly DateTime T0 = new(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc);

    private static Signal Connect(int pid, string address, int port, string name = "", string image = "") => new()
    {
        Kind = SignalKind.NetworkConnect,
        Pid = pid,
        RemoteAddress = address,
        RemotePort = port,
        ProcessName = name,
        ImagePath = image
    };

    private static Signal Dns(int pid, string domain) => new()
    {
        Kind = SignalKind.DnsQuery,
        Pid = pid,
        Domain = domain
    };

    // --------------------------------------------------------------- basics

    [Theory]
    [InlineData(443, "https")]
    [InlineData(8443, "https")]
    [InlineData(80, "http")]
    [InlineData(8080, "http")]
    [InlineData(22, "tcp")]
    [InlineData(4444, "tcp")]
    [InlineData(53, "tcp")]
    public void SchemeForPort_Maps_Only_The_Documented_Ports(int port, string expected)
        => Assert.Equal(expected, ApiSurfaceInventory.SchemeForPort(port));

    [Fact]
    public void Constructor_Rejects_A_Zero_Capacity_Inventory()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new ApiSurfaceInventory(new ManualClock(T0), 0));

    [Fact]
    public void Constructor_Rejects_A_Negative_Capacity_Inventory()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new ApiSurfaceInventory(new ManualClock(T0), -5));

    [Fact]
    public void NetworkConnect_Creates_One_Endpoint_With_Signal_Identity()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(1234, "93.184.216.34", 443, "curl.exe", @"C:\Windows\System32\curl.exe"));

        var ep = Assert.Single(inv.All());
        Assert.Equal("93.184.216.34", ep.Address);
        Assert.Equal("93.184.216.34", ep.Host);          // no DNS correlation yet
        Assert.Equal(443, ep.Port);
        Assert.Equal("https", ep.Scheme);
        Assert.Equal(1234, ep.Pid);
        Assert.Equal("curl.exe", ep.ProcessName);
        Assert.Equal(@"C:\Windows\System32\curl.exe", ep.ImagePath);
        Assert.Equal(1, ep.Connections);
        Assert.Equal(T0, ep.FirstSeenUtc);
        Assert.Equal(T0, ep.LastSeenUtc);
        Assert.False(ep.Trusted);
        Assert.False(ep.Beaconing);
        Assert.Empty(ep.ResolvedFrom);
    }

    [Fact]
    public void Repeated_Connections_Fold_Into_One_Endpoint_And_Move_LastSeen()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Connect(10, "1.1.1.1", 443));
        clock.Advance(TimeSpan.FromSeconds(5));
        inv.Observe(Connect(10, "1.1.1.1", 443));
        clock.Advance(TimeSpan.FromSeconds(5));
        inv.Observe(Connect(10, "1.1.1.1", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal(3, ep.Connections);
        Assert.Equal(T0, ep.FirstSeenUtc);
        Assert.Equal(T0.AddSeconds(10), ep.LastSeenUtc);
        Assert.Equal(1, inv.Count);
    }

    [Fact]
    public void Endpoints_Are_Keyed_Per_Process_So_Two_Pids_Do_Not_Merge()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(1, "1.1.1.1", 443));
        inv.Observe(Connect(2, "1.1.1.1", 443));

        Assert.Equal(2, inv.Count);
        Assert.Equal(2, inv.All().Select(e => e.Key).Distinct().Count());
    }

    [Fact]
    public void Key_Is_Stable_When_A_Late_Dns_Correlation_Renames_The_Host()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Connect(7, "5.5.5.5", 443));
        string before = inv.All()[0].Key;

        inv.Observe(Dns(7, "c2.example.net"));
        inv.Observe(Connect(7, "5.5.5.5", 443));

        Assert.Equal(before, inv.All()[0].Key);
        Assert.Equal("c2.example.net", inv.All()[0].Host);
        Assert.Equal(1, inv.Count);
    }

    [Theory]
    [InlineData(SignalKind.ProcessStart)]
    [InlineData(SignalKind.FileCreate)]
    [InlineData(SignalKind.RegistryWrite)]
    [InlineData(SignalKind.ProcessStop)]
    [InlineData(SignalKind.ScriptContent)]
    public void Irrelevant_Signal_Kinds_Are_Ignored_Not_Rejected(SignalKind kind)
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(new Signal { Kind = kind, Pid = 9, RemoteAddress = "1.2.3.4", RemotePort = 443 });
        Assert.Equal(0, inv.Count);
    }

    [Fact]
    public void A_DnsQuery_Alone_Creates_No_Endpoint()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Dns(3, "example.com"));
        Assert.Equal(0, inv.Count);
    }

    [Theory]
    [InlineData("", 443)]
    [InlineData("   ", 443)]
    [InlineData(null, 443)]
    [InlineData("1.2.3.4", 0)]
    [InlineData("1.2.3.4", -1)]
    [InlineData("1.2.3.4", 65536)]
    [InlineData("1.2.3.4", 1000000)]
    public void Malformed_Connections_Are_Dropped(string? address, int port)
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(5, address!, port));
        Assert.Equal(0, inv.Count);
    }

    [Fact]
    public void Bracketed_Ipv6_Literals_Are_Normalised_Once()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(11, "[2001:db8::1]", 8443));
        inv.Observe(Connect(11, "2001:db8::1", 8443));

        var ep = Assert.Single(inv.All());
        Assert.Equal("2001:db8::1", ep.Address);
        Assert.Equal(2, ep.Connections);
    }

    [Fact]
    public void Null_Signal_Is_Tolerated()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(null!);
        Assert.Equal(0, inv.Count);
    }

    // ------------------------------------------------------- DNS correlation

    [Fact]
    public void A_Lookup_Inside_The_Window_Names_The_Endpoint()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Dns(42, "api.example.com"));
        clock.Advance(TimeSpan.FromSeconds(30));
        inv.Observe(Connect(42, "93.184.216.34", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal("api.example.com", ep.Host);
        Assert.Equal(new[] { "api.example.com" }, ep.ResolvedFrom);
    }

    [Fact]
    public void A_Lookup_Exactly_At_The_Window_Edge_Still_Correlates()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock, dnsWindow: TimeSpan.FromSeconds(60));

        inv.Observe(Dns(42, "edge.example.com"));
        clock.Advance(TimeSpan.FromSeconds(60));
        inv.Observe(Connect(42, "1.2.3.4", 443));

        Assert.Equal("edge.example.com", inv.All()[0].Host);
    }

    [Fact]
    public void A_Lookup_One_Tick_Past_The_Window_Does_Not_Correlate()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock, dnsWindow: TimeSpan.FromSeconds(60));

        inv.Observe(Dns(42, "stale.example.com"));
        clock.Advance(TimeSpan.FromSeconds(60) + TimeSpan.FromTicks(1));
        inv.Observe(Connect(42, "1.2.3.4", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal("1.2.3.4", ep.Host);
        Assert.Empty(ep.ResolvedFrom);
    }

    [Fact]
    public void A_Lookup_By_Another_Process_Never_Bleeds_Across()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Dns(1, "not-mine.example.com"));
        inv.Observe(Connect(2, "1.2.3.4", 443));

        Assert.Empty(inv.All()[0].ResolvedFrom);
    }

    [Fact]
    public void Concurrent_Lookups_Are_Recorded_Newest_First()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Dns(8, "first.example.com"));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Dns(8, "second.example.com"));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(8, "1.2.3.4", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal(new[] { "second.example.com", "first.example.com" }, ep.ResolvedFrom);
        Assert.Equal("second.example.com", ep.Host);   // the heuristic picks the most recent
    }

    [Fact]
    public void ResolvedFrom_Is_Capped_So_A_Lookup_Flood_Cannot_Grow_A_Record()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        for (int i = 0; i < 20; i++)
        {
            inv.Observe(Dns(9, $"n{i}.example.com"));
            clock.Advance(TimeSpan.FromMilliseconds(10));
        }
        inv.Observe(Connect(9, "1.2.3.4", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal(4, ep.ResolvedFrom.Count);
        Assert.Equal("n19.example.com", ep.ResolvedFrom[0]);
    }

    [Fact]
    public void Domains_Are_Lowercased_And_Trailing_Dots_Removed_Before_Dedupe()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Dns(4, "EXAMPLE.COM."));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Dns(4, "example.com"));
        inv.Observe(Connect(4, "1.2.3.4", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal(new[] { "example.com" }, ep.ResolvedFrom);
    }

    [Fact]
    public void Host_Is_Named_Once_And_Later_Names_Only_Extend_ResolvedFrom()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Dns(6, "first.example.com"));
        inv.Observe(Connect(6, "1.2.3.4", 443));
        clock.Advance(TimeSpan.FromSeconds(2));
        inv.Observe(Dns(6, "second.example.com"));
        inv.Observe(Connect(6, "1.2.3.4", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal("first.example.com", ep.Host);
        Assert.Equal(new[] { "second.example.com", "first.example.com" }, ep.ResolvedFrom);
    }

    [Fact]
    public void An_Empty_Or_Whitespace_Domain_Is_Ignored()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Dns(1, ""));
        inv.Observe(Dns(1, "   "));
        inv.Observe(Dns(1, "."));
        inv.Observe(Connect(1, "1.2.3.4", 443));

        Assert.Empty(inv.All()[0].ResolvedFrom);
    }

    // ------------------------------------------------------- process identity

    [Fact]
    public void SetProcessInfo_Backfills_Endpoints_Recorded_Before_Verification_Finished()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(77, "1.2.3.4", 443));

        inv.SetProcessInfo(77, "svchost.exe", @"C:\Windows\System32\svchost.exe", trusted: true);

        var ep = Assert.Single(inv.All());
        Assert.Equal("svchost.exe", ep.ProcessName);
        Assert.Equal(@"C:\Windows\System32\svchost.exe", ep.ImagePath);
        Assert.True(ep.Trusted);
    }

    [Fact]
    public void SetProcessInfo_Applies_To_Endpoints_Recorded_Afterwards()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.SetProcessInfo(88, "beacon.exe", @"C:\Temp\beacon.exe", trusted: false);
        inv.Observe(Connect(88, "1.2.3.4", 8080));

        var ep = Assert.Single(inv.All());
        Assert.Equal("beacon.exe", ep.ProcessName);
        Assert.Equal(@"C:\Temp\beacon.exe", ep.ImagePath);
    }

    [Fact]
    public void SetProcessInfo_With_Empty_Strings_Does_Not_Erase_Known_Identity()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.SetProcessInfo(5, "known.exe", @"C:\known.exe", trusted: false);
        inv.SetProcessInfo(5, "", "", trusted: true);
        inv.Observe(Connect(5, "1.2.3.4", 443));

        var ep = Assert.Single(inv.All());
        Assert.Equal("known.exe", ep.ProcessName);
        Assert.Equal(@"C:\known.exe", ep.ImagePath);
        Assert.True(ep.Trusted);
    }

    [Fact]
    public void A_Signal_Name_Never_Overrides_A_Verified_Identity()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.SetProcessInfo(5, "real.exe", @"C:\real.exe", trusted: true);
        inv.Observe(Connect(5, "1.2.3.4", 443, "spoofed.exe", @"C:\spoofed.exe"));

        var ep = Assert.Single(inv.All());
        Assert.Equal("real.exe", ep.ProcessName);
        Assert.True(ep.Trusted);
    }

    [Fact]
    public void A_Name_Learned_Later_From_A_Signal_Backfills_Earlier_Endpoints()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(12, "1.2.3.4", 443));                       // no name yet
        inv.Observe(Connect(12, "5.6.7.8", 80, "late.exe", @"C:\l.exe"));

        Assert.All(inv.All(), e => Assert.Equal("late.exe", e.ProcessName));
    }

    // ------------------------------------------------------------- beaconing

    [Theory]
    [InlineData("1.2.3.4:443")]
    [InlineData("https://1.2.3.4:443")]
    [InlineData("https://1.2.3.4:443/some/path")]
    [InlineData("1.2.3.4")]
    public void MarkBeaconing_Accepts_Every_Documented_Endpoint_Form(string spec)
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));

        inv.MarkBeaconing(3, spec, 0.75);

        var ep = Assert.Single(inv.All());
        Assert.True(ep.Beaconing);
        Assert.Equal(0.75, ep.BeaconConfidence, 6);
    }

    [Fact]
    public void MarkBeaconing_With_A_Port_Marks_Only_That_Port()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));
        inv.Observe(Connect(3, "1.2.3.4", 8080));

        inv.MarkBeaconing(3, "1.2.3.4:443", 0.9);

        Assert.True(inv.All().Single(e => e.Port == 443).Beaconing);
        Assert.False(inv.All().Single(e => e.Port == 8080).Beaconing);
    }

    [Fact]
    public void MarkBeaconing_Without_A_Port_Marks_Every_Port_For_That_Destination()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));
        inv.Observe(Connect(3, "1.2.3.4", 8080));
        inv.Observe(Connect(3, "9.9.9.9", 443));

        inv.MarkBeaconing(3, "1.2.3.4", 0.5);

        Assert.Equal(2, inv.All().Count(e => e.Beaconing));
        Assert.False(inv.All().Single(e => e.Address == "9.9.9.9").Beaconing);
    }

    [Fact]
    public void MarkBeaconing_Handles_Bracketed_Ipv6()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "2001:db8::1", 443));

        inv.MarkBeaconing(3, "[2001:db8::1]:443", 0.4);

        Assert.True(inv.All()[0].Beaconing);
    }

    [Fact]
    public void MarkBeaconing_Handles_A_Bare_Ipv6_Literal_As_A_Wildcard()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "2001:db8::1", 443));
        inv.Observe(Connect(3, "2001:db8::1", 8080));

        inv.MarkBeaconing(3, "2001:db8::1", 0.4);

        Assert.Equal(2, inv.All().Count(e => e.Beaconing));
    }

    [Theory]
    [InlineData(5.0, 1.0)]
    [InlineData(-3.0, 0.0)]
    [InlineData(double.NaN, 0.0)]
    public void MarkBeaconing_Clamps_Confidence(double given, double expected)
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));

        inv.MarkBeaconing(3, "1.2.3.4:443", given);

        var ep = Assert.Single(inv.All());
        Assert.Equal(expected, ep.BeaconConfidence, 6);
        Assert.Equal(expected > 0.0, ep.Beaconing);
    }

    [Fact]
    public void MarkBeaconing_Ratchets_Upward_So_A_Weaker_Later_Score_Cannot_Erase_It()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));

        inv.MarkBeaconing(3, "1.2.3.4:443", 0.9);
        inv.MarkBeaconing(3, "1.2.3.4:443", 0.1);

        var ep = Assert.Single(inv.All());
        Assert.True(ep.Beaconing);
        Assert.Equal(0.9, ep.BeaconConfidence, 6);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("://")]
    [InlineData("/onlypath")]
    public void MarkBeaconing_Ignores_Junk_Without_Throwing(string spec)
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));

        inv.MarkBeaconing(3, spec, 1.0);

        Assert.False(inv.All()[0].Beaconing);
    }

    [Fact]
    public void MarkBeaconing_On_An_Unknown_Pid_Is_A_Silent_NoOp()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));

        inv.MarkBeaconing(9999, "1.2.3.4:443", 1.0);

        Assert.False(inv.All()[0].Beaconing);
    }

    [Fact]
    public void MarkBeaconing_Rejects_An_Out_Of_Range_Port_Rather_Than_Wildcarding()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(3, "1.2.3.4", 443));

        inv.MarkBeaconing(3, "1.2.3.4:70000", 1.0);

        Assert.False(inv.All()[0].Beaconing);
    }

    // ------------------------------------------------------ bounds and views

    [Fact]
    public void Capacity_Evicts_The_Least_Recently_Seen_Endpoint()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock, maxEndpoints: 2);

        inv.Observe(Connect(1, "1.1.1.1", 443));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(1, "2.2.2.2", 443));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(1, "3.3.3.3", 443));

        Assert.Equal(2, inv.Count);
        Assert.DoesNotContain(inv.All(), e => e.Address == "1.1.1.1");
    }

    [Fact]
    public void Re_Observing_An_Endpoint_Rescues_It_From_Eviction()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock, maxEndpoints: 2);

        inv.Observe(Connect(1, "1.1.1.1", 443));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(1, "2.2.2.2", 443));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(1, "1.1.1.1", 443));    // touch the oldest
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(1, "3.3.3.3", 443));

        Assert.Equal(2, inv.Count);
        Assert.Contains(inv.All(), e => e.Address == "1.1.1.1");
        Assert.DoesNotContain(inv.All(), e => e.Address == "2.2.2.2");
    }

    [Fact]
    public void All_Returns_Most_Recently_Seen_First()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Connect(1, "1.1.1.1", 443));
        clock.Advance(TimeSpan.FromSeconds(1));
        inv.Observe(Connect(1, "2.2.2.2", 443));

        Assert.Equal(new[] { "2.2.2.2", "1.1.1.1" }, inv.All().Select(e => e.Address).ToArray());
    }

    [Fact]
    public void ForPid_Filters_To_One_Process()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(1, "1.1.1.1", 443));
        inv.Observe(Connect(2, "2.2.2.2", 443));

        var mine = inv.ForPid(2);
        Assert.Equal("2.2.2.2", Assert.Single(mine).Address);
        Assert.Empty(inv.ForPid(4242));
    }

    [Fact]
    public void HttpEndpoints_Excludes_Non_Http_Ports()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(1, "1.1.1.1", 443));
        inv.Observe(Connect(1, "2.2.2.2", 8080));
        inv.Observe(Connect(1, "3.3.3.3", 4444));

        var http = inv.HttpEndpoints();
        Assert.Equal(2, http.Count);
        Assert.DoesNotContain(http, e => e.Address == "3.3.3.3");
    }

    [Fact]
    public void Forget_Removes_Only_That_Process_And_Clears_Its_Dns_Memory()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Dns(1, "gone.example.com"));
        inv.Observe(Connect(1, "1.1.1.1", 443));
        inv.Observe(Connect(2, "2.2.2.2", 443));

        inv.Forget(1);

        Assert.Equal(1, inv.Count);
        Assert.Equal(2, inv.All()[0].Pid);

        inv.Observe(Connect(1, "1.1.1.1", 443));    // pid reused
        Assert.Empty(inv.ForPid(1)[0].ResolvedFrom);
    }

    [Fact]
    public void Prune_Drops_Stale_Endpoints_And_Keeps_Fresh_Ones()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Connect(1, "1.1.1.1", 443));
        clock.Advance(TimeSpan.FromMinutes(10));
        inv.Observe(Connect(1, "2.2.2.2", 443));

        inv.Prune(TimeSpan.FromMinutes(5));

        Assert.Equal(1, inv.Count);
        Assert.Equal("2.2.2.2", inv.All()[0].Address);
    }

    [Fact]
    public void Prune_Zero_Keeps_An_Endpoint_Seen_At_This_Instant()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(1, "1.1.1.1", 443));

        inv.Prune(TimeSpan.Zero);

        Assert.Equal(1, inv.Count);
    }

    [Fact]
    public void Prune_With_A_Negative_Span_Clears_Everything()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        inv.Observe(Connect(1, "1.1.1.1", 443));

        inv.Prune(TimeSpan.FromMinutes(-1));

        Assert.Equal(0, inv.Count);
    }

    [Fact]
    public void Time_Comes_From_The_Injected_Clock_Not_The_Signal_Or_The_Wall_Clock()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));

        // The signal carries its own (wall-clock) stamp; the inventory must ignore it,
        // because monitors stamp signals from clocks that do not agree with each other.
        inv.Observe(Connect(1, "1.1.1.1", 443) with { TimestampUtc = new DateTime(1999, 1, 1, 0, 0, 0, DateTimeKind.Utc) });

        var ep = Assert.Single(inv.All());
        Assert.Equal(T0, ep.FirstSeenUtc);
        Assert.Equal(T0, ep.LastSeenUtc);
    }

    // ---------------------------------------------------------- ToCollection

    private static SurfaceEndpoint Ep(
        string host, int port, string scheme, string process = "curl.exe", int pid = 100,
        int connections = 1, bool beaconing = false, double confidence = 0.0,
        string? address = null, string[]? resolvedFrom = null) => new()
        {
            Host = host,
            Address = address ?? host,
            Port = port,
            Scheme = scheme,
            Pid = pid,
            ProcessName = process,
            Connections = connections,
            Beaconing = beaconing,
            BeaconConfidence = confidence,
            ResolvedFrom = resolvedFrom ?? Array.Empty<string>()
        };

    [Fact]
    public void ToCollection_Emits_One_Get_Per_Distinct_Root()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("run", new[]
        {
            Ep("api.example.com", 443, "https", pid: 1),
            Ep("api.example.com", 443, "https", pid: 2),   // same root, other process
            Ep("api.example.com", 8443, "https", pid: 1)   // different port, own root
        });

        Assert.Equal(2, col.RequestCount);
        Assert.All(col.Requests(), r => Assert.Equal("GET", r.Method));
        Assert.Equal("run", col.Name);
    }

    [Theory]
    [InlineData("api.example.com", 443, "https", "https://api.example.com/")]
    [InlineData("api.example.com", 80, "http", "http://api.example.com/")]
    [InlineData("api.example.com", 8443, "https", "https://api.example.com:8443/")]
    [InlineData("api.example.com", 8080, "http", "http://api.example.com:8080/")]
    [InlineData("1.2.3.4", 4444, "tcp", "http://1.2.3.4:4444/")]
    public void ToCollection_Builds_The_Expected_Root_Url(string host, int port, string scheme, string expected)
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[] { Ep(host, port, scheme) });

        Assert.Equal(expected, col.Requests().Single().Url);
    }

    [Fact]
    public void ToCollection_Brackets_An_Ipv6_Host()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[] { Ep("2001:db8::1", 8443, "https") });

        Assert.Equal("https://[2001:db8::1]:8443/", col.Requests().Single().Url);
    }

    [Fact]
    public void ToCollection_Names_Each_Request_After_The_Process_And_Host()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[]
        {
            Ep("api.example.com", 443, "https", process: "powershell.exe"),
            Ep("evil.example.net", 8443, "https", process: "rundll32.exe")
        });

        var names = col.Requests().Select(r => r.Name).ToArray();
        Assert.Contains("powershell.exe -> api.example.com", names);
        Assert.Contains("rundll32.exe -> evil.example.net:8443", names);
    }

    [Fact]
    public void ToCollection_Ids_Are_Deterministic_So_Reruns_Diff_Cleanly()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var endpoints = new[] { Ep("api.example.com", 443, "https") };

        var a = inv.ToCollection("x", endpoints);
        var b = inv.ToCollection("x", endpoints);

        Assert.Equal("surface-https-api-example-com-443", a.Requests().Single().Id);
        Assert.Equal(a.Requests().Single().Id, b.Requests().Single().Id);
    }

    [Fact]
    public void ToCollection_Description_Aggregates_Every_Observing_Process()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[]
        {
            Ep("api.example.com", 443, "https", pid: 11, connections: 3),
            Ep("api.example.com", 443, "https", pid: 22, connections: 4)
        });

        string desc = col.Requests().Single().Description;
        Assert.Contains("7 connections", desc);
        Assert.Contains("11", desc);
        Assert.Contains("22", desc);
    }

    [Fact]
    public void ToCollection_Admits_That_A_NonHttp_Port_Is_A_Speculative_Probe()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[] { Ep("1.2.3.4", 4444, "tcp") });

        Assert.Contains("speculative", col.Requests().Single().Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ToCollection_Reports_A_Beacon_Verdict_And_The_Heuristic_Caveat()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[]
        {
            Ep("c2.example.net", 443, "https", beaconing: true, confidence: 0.82,
               address: "5.5.5.5", resolvedFrom: new[] { "c2.example.net" })
        });

        string desc = col.Requests().Single().Description;
        Assert.Contains("0.82", desc);
        Assert.Contains("heuristic", desc, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ToCollection_Falls_Back_To_The_Address_When_No_Name_Was_Correlated()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[] { Ep("", 443, "https", address: "5.5.5.5") });

        Assert.Equal("https://5.5.5.5/", col.Requests().Single().Url);
    }

    [Fact]
    public void ToCollection_Skips_Endpoints_It_Cannot_Address()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("x", new[]
        {
            Ep("", 443, "https", address: ""),
            Ep("ok.example.com", 443, "https")
        });

        Assert.Equal(1, col.RequestCount);
    }

    [Fact]
    public void ToCollection_On_An_Empty_List_Produces_A_Named_But_Empty_Collection()
    {
        var inv = new ApiSurfaceInventory(new ManualClock(T0));
        var col = inv.ToCollection("  ", Array.Empty<SurfaceEndpoint>());

        Assert.Equal("Discovered API surface", col.Name);
        Assert.Equal(0, col.RequestCount);
        Assert.Contains("contacts the hosts", col.Description);
    }

    [Fact]
    public void ToCollection_Round_Trips_The_Live_Inventory()
    {
        var clock = new ManualClock(T0);
        var inv = new ApiSurfaceInventory(clock);

        inv.Observe(Dns(1, "api.example.com"));
        inv.Observe(Connect(1, "93.184.216.34", 443, "curl.exe"));
        inv.Observe(Connect(1, "10.0.0.5", 4444, "curl.exe"));

        var col = inv.ToCollection("hunt", inv.HttpEndpoints());

        var request = Assert.Single(col.Requests());
        Assert.Equal("https://api.example.com/", request.Url);
    }
}

/// <summary>
/// Scriptable <see cref="IControlBackend"/>. Records what the routing table asked for
/// and can be told to throw, so the 500 path is exercised without a real agent.
/// </summary>
internal sealed class ApiControlFakeBackend : IControlBackend
{
    /// <summary>Stand-in for the kind of internal detail an exception message can carry.</summary>
    internal const string Secret = @"secret detail C:\ProgramData\ProcessShield\audit.log.key";

    public string VersionValue { get; set; } = "9.9.9-test";

    public bool Throw { get; set; }
    public bool ActionSucceeds { get; set; } = true;
    public bool AuditOk { get; set; } = true;
    public string EmptyBodyFor { get; set; } = "";

    public bool? LastOnlyContained { get; private set; }
    public int? LastProfilePid { get; private set; }
    public int? LastEventLimit { get; private set; }
    public string? LastActionVerb { get; private set; }
    public int? LastActionPid { get; private set; }

    public string AgentVersion => Throw ? throw new InvalidOperationException(Secret) : VersionValue;

    private string Body(string name)
    {
        if (Throw) throw new InvalidOperationException(Secret);
        return EmptyBodyFor == name ? "" : "{\"route\":\"" + name + "\"}";
    }

    public string Status() => Body("status");
    public string Surface() => Body("surface");
    public string Metrics() => Body("metrics");
    public string Rules() => Body("rules");
    public string AttackCoverage() => Body("attack");

    public string Profiles(bool onlyContained)
    {
        LastOnlyContained = onlyContained;
        return Body("profiles");
    }

    public string Profile(int pid)
    {
        LastProfilePid = pid;
        return Body("profile");
    }

    public string Events(int limit)
    {
        LastEventLimit = limit;
        return Body("events");
    }

    public (bool ok, string message) Action(string verb, int pid)
    {
        LastActionVerb = verb;
        LastActionPid = pid;
        if (Throw) throw new InvalidOperationException(Secret);
        return ActionSucceeds ? (true, "done") : (false, "pid is already gone");
    }

    public (bool ok, string message) VerifyAudit()
    {
        if (Throw) throw new InvalidOperationException(Secret);
        return AuditOk ? (true, "chain intact") : (false, "tampered record at seq 7");
    }
}

public class ApiControlServerRouteTests
{
    private static (int status, string contentType, string body) Get(
        string path, string? query = null, ApiControlFakeBackend? backend = null, bool allowActions = false)
        => ControlServer.Route("GET", path, query, backend ?? new ApiControlFakeBackend(), allowActions);

    // --------------------------------------------------------------- routing

    [Theory]
    [InlineData("/api/v1/status", "status")]
    [InlineData("/api/v1/surface", "surface")]
    [InlineData("/api/v1/metrics", "metrics")]
    [InlineData("/api/v1/rules", "rules")]
    [InlineData("/api/v1/attack", "attack")]
    public void Read_Only_Routes_Return_The_Backend_Body(string path, string marker)
    {
        var (status, contentType, body) = Get(path);

        Assert.Equal(200, status);
        Assert.Equal("application/json; charset=utf-8", contentType);
        Assert.Contains(marker, body);
    }

    [Fact]
    public void Health_Reports_The_Agent_Version()
    {
        var (status, _, body) = Get("/health");

        Assert.Equal(200, status);
        Assert.Contains("\"status\":\"ok\"", body);
        Assert.Contains("9.9.9-test", body);
    }

    [Fact]
    public void Health_Is_Also_Reachable_Under_The_Versioned_Prefix()
        => Assert.Equal(200, Get("/api/v1/health").status);

    [Fact]
    public void An_Unknown_Route_Is_A_Json_404()
    {
        var (status, contentType, body) = Get("/api/v1/nope");

        Assert.Equal(404, status);
        Assert.Equal("application/json; charset=utf-8", contentType);
        Assert.Contains("\"error\"", body);
    }

    [Fact]
    public void A_Route_Outside_The_Api_Prefix_Is_A_404()
        => Assert.Equal(404, Get("/").status);

    [Fact]
    public void An_Unversioned_Route_Is_A_404()
        => Assert.Equal(404, Get("/status").status);

    [Fact]
    public void Trailing_Slashes_Are_Tolerated()
        => Assert.Equal(200, Get("/api/v1/status/").status);

    [Fact]
    public void Paths_Are_Matched_Case_Insensitively()
        => Assert.Equal(200, Get("/API/V1/Status").status);

    [Fact]
    public void A_Percent_Encoded_Path_Falls_Through_To_404_Rather_Than_Being_Decoded()
        => Assert.Equal(404, Get("/api/v1/%73tatus").status);

    [Fact]
    public void Posting_To_A_Read_Only_Route_Is_405()
    {
        var (status, _, body) = ControlServer.Route("POST", "/api/v1/status", null, new ApiControlFakeBackend(), true);

        Assert.Equal(405, status);
        Assert.Contains("method not allowed", body);
    }

    [Fact]
    public void An_Exotic_Method_On_A_Known_Route_Is_405()
        => Assert.Equal(405, ControlServer.Route("DELETE", "/api/v1/profiles", null, new ApiControlFakeBackend(), true).status);

    // -------------------------------------------------------------- profiles

    [Theory]
    [InlineData("contained=true", true)]
    [InlineData("?contained=true", true)]
    [InlineData("contained=TRUE", true)]
    [InlineData("contained=1", true)]
    [InlineData("contained=false", false)]
    [InlineData("contained=", false)]
    [InlineData("other=true", false)]
    [InlineData(null, false)]
    public void Profiles_Parses_The_Contained_Flag_Conservatively(string? query, bool expected)
    {
        var backend = new ApiControlFakeBackend();
        Get("/api/v1/profiles", query, backend);

        Assert.Equal(expected, backend.LastOnlyContained);
    }

    [Fact]
    public void A_Duplicated_Query_Parameter_Cannot_Override_The_First()
    {
        var backend = new ApiControlFakeBackend();
        Get("/api/v1/profiles", "contained=false&contained=true", backend);

        Assert.False(backend.LastOnlyContained);
    }

    [Fact]
    public void Profile_By_Pid_Passes_The_Pid_Through()
    {
        var backend = new ApiControlFakeBackend();
        var (status, _, _) = Get("/api/v1/profiles/4242", backend: backend);

        Assert.Equal(200, status);
        Assert.Equal(4242, backend.LastProfilePid);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("-1")]
    [InlineData("+1")]
    [InlineData("0")]
    [InlineData("1.5")]
    [InlineData("99999999999999999999")]
    [InlineData("")]
    public void A_Malformed_Pid_Is_A_400_Not_A_Crash(string pid)
    {
        var (status, _, body) = Get("/api/v1/profiles/" + pid);

        // An empty segment collapses to the collection route, which is a legal 200.
        if (pid.Length == 0) { Assert.Equal(200, status); return; }
        Assert.Equal(400, status);
        Assert.Contains("pid", body);
    }

    [Fact]
    public void An_Extra_Path_Segment_After_The_Pid_Is_A_404()
        => Assert.Equal(404, Get("/api/v1/profiles/123/extra").status);

    // ---------------------------------------------------------------- events

    [Fact]
    public void Events_Defaults_Its_Limit_When_None_Is_Given()
    {
        var backend = new ApiControlFakeBackend();
        Get("/api/v1/events", backend: backend);

        Assert.Equal(ControlServer.DefaultEventLimit, backend.LastEventLimit);
    }

    [Fact]
    public void Events_Honours_An_Explicit_Limit()
    {
        var backend = new ApiControlFakeBackend();
        Get("/api/v1/events", "limit=5", backend);

        Assert.Equal(5, backend.LastEventLimit);
    }

    [Fact]
    public void Events_Clamps_A_Huge_Limit_Instead_Of_Rendering_Everything()
    {
        var backend = new ApiControlFakeBackend();
        Get("/api/v1/events", "limit=1000000", backend);

        Assert.Equal(ControlServer.MaxEventLimit, backend.LastEventLimit);
    }

    [Theory]
    [InlineData("limit=abc")]
    [InlineData("limit=0")]
    [InlineData("limit=-3")]
    [InlineData("limit=")]
    [InlineData("limit=1e3")]
    public void An_Unusable_Limit_Is_A_400_And_The_Backend_Is_Never_Called(string query)
    {
        var backend = new ApiControlFakeBackend();
        var (status, _, body) = Get("/api/v1/events", query, backend);

        Assert.Equal(400, status);
        Assert.Contains("limit", body);
        Assert.Null(backend.LastEventLimit);
    }

    // --------------------------------------------------------------- actions

    [Fact]
    public void Actions_Are_Refused_With_403_When_The_Gate_Is_Closed()
    {
        var backend = new ApiControlFakeBackend();
        var (status, _, body) = ControlServer.Route("POST", "/api/v1/actions/suspend/100", null, backend, allowActions: false);

        Assert.Equal(403, status);
        Assert.Contains("allowActions", body);
        Assert.Null(backend.LastActionVerb);
    }

    [Fact]
    public void An_Allowed_Action_Reaches_The_Backend()
    {
        var backend = new ApiControlFakeBackend();
        var (status, _, body) = ControlServer.Route("POST", "/api/v1/actions/suspend/100", null, backend, allowActions: true);

        Assert.Equal(200, status);
        Assert.Equal("suspend", backend.LastActionVerb);
        Assert.Equal(100, backend.LastActionPid);
        Assert.Contains("\"ok\":true", body);
    }

    [Fact]
    public void A_Refused_Action_Is_409_And_Carries_The_Reason()
    {
        var backend = new ApiControlFakeBackend { ActionSucceeds = false };
        var (status, _, body) = ControlServer.Route("POST", "/api/v1/actions/terminate/100", null, backend, allowActions: true);

        Assert.Equal(409, status);
        Assert.Contains("\"ok\":false", body);
        Assert.Contains("already gone", body);
    }

    [Fact]
    public void A_Get_On_An_Action_Route_Is_405_Even_When_Actions_Are_Allowed()
        => Assert.Equal(405, Get("/api/v1/actions/suspend/100", allowActions: true).status);

    [Theory]
    [InlineData("/api/v1/actions/susp end/100")]
    [InlineData("/api/v1/actions/susp;end/100")]
    [InlineData("/api/v1/actions/../100")]
    [InlineData("/api/v1/actions/aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd/100")]   // 40 chars, over the cap
    public void A_Malformed_Action_Verb_Is_A_400(string path)
    {
        var backend = new ApiControlFakeBackend();
        var (status, _, _) = ControlServer.Route("POST", path, null, backend, allowActions: true);

        Assert.Equal(400, status);
        Assert.Null(backend.LastActionVerb);
    }

    [Fact]
    public void An_Action_With_A_Malformed_Pid_Is_A_400()
        => Assert.Equal(400, ControlServer.Route("POST", "/api/v1/actions/suspend/xyz", null,
            new ApiControlFakeBackend(), allowActions: true).status);

    [Fact]
    public void An_Action_Path_With_The_Wrong_Arity_Is_A_404()
        => Assert.Equal(404, ControlServer.Route("POST", "/api/v1/actions/suspend", null,
            new ApiControlFakeBackend(), allowActions: true).status);

    // ----------------------------------------------------------- audit/verify

    [Fact]
    public void An_Intact_Audit_Chain_Verifies_With_200_And_Ok_True()
    {
        var (status, _, body) = Get("/api/v1/audit/verify");

        Assert.Equal(200, status);
        Assert.Contains("\"ok\":true", body);
    }

    [Fact]
    public void A_Tampered_Audit_Chain_Is_A_200_With_Ok_False_Not_A_Server_Error()
    {
        var (status, _, body) = Get("/api/v1/audit/verify", backend: new ApiControlFakeBackend { AuditOk = false });

        Assert.Equal(200, status);
        Assert.Contains("\"ok\":false", body);
        Assert.Contains("tampered record at seq 7", body);
    }

    // ----------------------------------------------------------- failure modes

    [Theory]
    [InlineData("/api/v1/status")]
    [InlineData("/api/v1/profiles")]
    [InlineData("/api/v1/profiles/1")]
    [InlineData("/api/v1/events")]
    [InlineData("/api/v1/surface")]
    [InlineData("/api/v1/metrics")]
    [InlineData("/api/v1/rules")]
    [InlineData("/api/v1/attack")]
    [InlineData("/api/v1/audit/verify")]
    public void A_Backend_Exception_Becomes_A_Generic_500(string path)
    {
        var (status, _, body) = Get(path, backend: new ApiControlFakeBackend { Throw = true });

        Assert.Equal(500, status);
        Assert.Equal("{\"error\":\"internal error\"}", body);
    }

    [Fact]
    public void A_Failing_Action_Backend_Also_Yields_A_Generic_500()
    {
        var (status, _, body) = ControlServer.Route("POST", "/api/v1/actions/suspend/1", null,
            new ApiControlFakeBackend { Throw = true }, allowActions: true);

        Assert.Equal(500, status);
        Assert.DoesNotContain("audit.log.key", body);
    }

    [Fact]
    public void A_Throwing_AgentVersion_Still_Yields_A_Healthy_Liveness_Answer()
    {
        var (status, _, body) = Get("/health", backend: new ApiControlFakeBackend { Throw = true });

        Assert.Equal(200, status);
        Assert.Contains("\"status\":\"ok\"", body);
    }

    [Fact]
    public void An_Empty_Backend_Body_Is_Replaced_With_Valid_Json()
    {
        var (status, _, body) = Get("/api/v1/status", backend: new ApiControlFakeBackend { EmptyBodyFor = "status" });

        Assert.Equal(200, status);
        Assert.Equal("{}", body);
    }

    [Fact]
    public void A_Null_Backend_Is_A_500_Rather_Than_A_NullReference()
        => Assert.Equal(500, ControlServer.Route("GET", "/api/v1/status", null, null!, false).status);

    [Fact]
    public void Every_Response_Declares_Json()
    {
        foreach (string path in new[] { "/health", "/api/v1/status", "/api/v1/nope", "/api/v1/profiles/x" })
            Assert.Equal("application/json; charset=utf-8", Get(path).contentType);
    }
}

public class ApiControlServerSecurityTests
{
    private const string Token = "0123456789abcdef0123456789abcdef";

    private static (int status, string contentType, string body) Handle(
        string? authHeader, string path = "/api/v1/status", string expected = Token)
        => ControlServer.Handle("GET", path, null, authHeader, expected, new ApiControlFakeBackend(), false);

    // ------------------------------------------------------------------ token

    [Fact]
    public void A_Correct_Bearer_Token_Is_Accepted()
        => Assert.Equal(200, Handle("Bearer " + Token).status);

    [Fact]
    public void The_Bearer_Scheme_Is_Case_Insensitive()
        => Assert.Equal(200, Handle("bearer " + Token).status);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("Bearer")]
    [InlineData("Bearer ")]
    [InlineData("Basic " + Token)]
    [InlineData(Token)]                              // no scheme at all
    [InlineData("Bearer wrong")]
    [InlineData("Bearer 0123456789abcdef0123456789abcde")]   // one char short
    [InlineData("Bearer 0123456789abcdef0123456789abcdef0")] // one char long
    [InlineData("Bearer 0123456789ABCDEF0123456789ABCDEF")]  // token itself is case-sensitive
    public void A_Missing_Or_Wrong_Token_Is_401(string? header)
    {
        var (status, contentType, body) = Handle(header);

        Assert.Equal(401, status);
        Assert.Equal("application/json; charset=utf-8", contentType);
        Assert.Equal("{\"error\":\"unauthorized\"}", body);
    }

    [Fact]
    public void An_Empty_Expected_Token_Fails_Closed()
    {
        Assert.False(ControlServer.IsAuthorized("", "Bearer anything"));
        Assert.False(ControlServer.IsAuthorized("", null));
        Assert.Equal(401, Handle("Bearer anything", expected: "").status);
    }

    [Fact]
    public void Health_Is_The_Only_Route_Reachable_Without_A_Token()
    {
        Assert.Equal(200, Handle(null, "/health").status);
        Assert.Equal(200, Handle("Bearer nonsense", "/health").status);
        Assert.Equal(200, Handle(null, "/api/v1/health").status);
        Assert.Equal(401, Handle(null, "/api/v1/metrics").status);
        Assert.Equal(401, Handle(null, "/api/v1/nope").status);   // even 404s stay behind auth
    }

    [Fact]
    public void An_Unauthenticated_Caller_Cannot_Reach_The_Backend_At_All()
    {
        var backend = new ApiControlFakeBackend();
        ControlServer.Handle("GET", "/api/v1/profiles", "contained=true", null, Token, backend, false);

        Assert.Null(backend.LastOnlyContained);
    }

    [Fact]
    public void Surrounding_Whitespace_In_The_Header_Is_Tolerated()
        => Assert.Equal(200, Handle("  Bearer   " + Token + "  ").status);

    // ------------------------------------------------------- response headers

    [Fact]
    public void Security_Headers_Include_Nosniff_And_No_Store()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        ControlServer.ApplySecurityHeaders((k, v) => headers[k] = v);

        Assert.Equal("nosniff", headers["X-Content-Type-Options"]);
        Assert.Equal("no-store", headers["Cache-Control"]);
        Assert.Equal("DENY", headers["X-Frame-Options"]);
        Assert.Equal("no-referrer", headers["Referrer-Policy"]);
        Assert.Contains("default-src 'none'", headers["Content-Security-Policy"]);
    }

    [Fact]
    public void A_Header_Sink_That_Throws_Does_Not_Break_The_Response()
    {
        int seen = 0;
        var ex = Record.Exception(() => ControlServer.ApplySecurityHeaders((_, _) =>
        {
            seen++;
            throw new InvalidOperationException("restricted header");
        }));

        Assert.Null(ex);
        Assert.Equal(ControlServer.SecurityHeaders.Count, seen);
    }

    [Fact]
    public void A_Null_Header_Sink_Is_Tolerated()
        => Assert.Null(Record.Exception(() => ControlServer.ApplySecurityHeaders(null!)));

    // -------------------------------------------------------------- binding

    [Theory]
    [InlineData("http://127.0.0.1:8787/")]
    [InlineData("http://127.0.0.5:8787/")]
    [InlineData("http://localhost:8787/")]
    [InlineData("http://LOCALHOST:8787/")]
    [InlineData("https://127.0.0.1:8443/")]
    [InlineData("http://[::1]:8787/")]
    [InlineData("http://localhost/")]
    public void Loopback_Prefixes_Are_Accepted(string prefix)
    {
        Assert.True(ControlServer.IsLoopbackPrefix(prefix, out string reason), reason);
        Assert.Equal("", reason);
    }

    [Theory]
    [InlineData("http://+:8787/")]
    [InlineData("http://*:8787/")]
    [InlineData("http://0.0.0.0:8787/")]
    [InlineData("http://192.168.1.5:8787/")]
    [InlineData("http://example.com:8787/")]
    [InlineData("http://[2001:db8::1]:8787/")]
    [InlineData("http://user@127.0.0.1:8787/")]
    [InlineData("http://127.0.0.1:8787")]      // HttpListener demands the trailing slash
    [InlineData("http://127.0.0.1:0/")]
    [InlineData("http://127.0.0.1:99999/")]
    [InlineData("http://127.0.0.1:abc/")]
    [InlineData("ftp://127.0.0.1:8787/")]
    [InlineData("127.0.0.1:8787")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Non_Loopback_Or_Malformed_Prefixes_Are_Refused_With_A_Reason(string? prefix)
    {
        Assert.False(ControlServer.IsLoopbackPrefix(prefix, out string reason));
        Assert.NotEqual("", reason);
    }

    [Fact]
    public void Start_Refuses_A_Non_Loopback_Prefix_Without_Binding()
    {
        var options = new ControlServerOptions
        {
            Enabled = true,
            Prefix = "http://0.0.0.0:8787/",
            Token = Token
        };
        using var server = new ControlServer(options, new ApiControlFakeBackend(), new Logger());

        Assert.False(server.Start());
        Assert.False(server.Running);
        Assert.Equal("", server.Token);
    }

    [Fact]
    public void Start_Is_A_NoOp_While_The_Control_Plane_Is_Disabled()
    {
        var options = new ControlServerOptions { Enabled = false, Prefix = "http://127.0.0.1:8787/" };
        using var server = new ControlServer(options, new ApiControlFakeBackend(), new Logger());

        Assert.False(server.Start());
        Assert.False(server.Running);
    }

    [Fact]
    public void Stop_And_Dispose_Are_Safe_On_A_Server_That_Never_Started()
    {
        var server = new ControlServer(new ControlServerOptions(), new ApiControlFakeBackend(), new Logger());

        Assert.Null(Record.Exception(() => { server.Stop(); server.Dispose(); server.Dispose(); }));
    }

    [Fact]
    public void The_Constructor_Rejects_Missing_Collaborators()
    {
        Assert.Throws<ArgumentNullException>(() => new ControlServer(null!, new ApiControlFakeBackend(), new Logger()));
        Assert.Throws<ArgumentNullException>(() => new ControlServer(new ControlServerOptions(), null!, new Logger()));
        Assert.Throws<ArgumentNullException>(() => new ControlServer(new ControlServerOptions(), new ApiControlFakeBackend(), null!));
    }

    [Fact]
    public void The_Default_Options_Are_The_Safe_Ones()
    {
        var options = new ControlServerOptions();

        Assert.False(options.Enabled);
        Assert.False(options.AllowActions);
        Assert.Equal("", options.Token);
        Assert.True(ControlServer.IsLoopbackPrefix(options.Prefix, out _));
    }

    // ------------------------------------------------------------ query parser

    [Theory]
    [InlineData("a=1", "a", "1")]
    [InlineData("?a=1", "a", "1")]
    [InlineData("a=1&b=2", "b", "2")]
    [InlineData("A=1", "a", "1")]
    [InlineData("a=", "a", "")]
    [InlineData("a", "a", "")]
    [InlineData("a=hello%20world", "a", "hello world")]
    [InlineData("a=1", "b", null)]
    [InlineData("", "a", null)]
    [InlineData(null, "a", null)]
    [InlineData("&&a=1&&", "a", "1")]
    public void QueryValue_Handles_The_Shapes_A_Client_Can_Send(string? query, string name, string? expected)
        => Assert.Equal(expected, ControlServer.QueryValue(query, name));
}
