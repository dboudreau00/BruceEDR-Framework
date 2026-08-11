using ProcessShield.Core;
using ProcessShield.Detection;
using Xunit;

namespace ProcessShield.Tests;

/// <summary>
/// Cadence analysis. Every case drives explicit timestamps, so nothing here sleeps,
/// touches the network, or depends on wall-clock time.
/// </summary>
public class BehaviourBeaconAnalyzerTests
{
    private static readonly DateTime T0 = new(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc);

    private static BeaconAnalyzer New(int min = 6, TimeSpan? window = null, int maxEndpoints = 64)
        => new(new ManualClock(T0), min, window, maxEndpoints);

    private static void Feed(BeaconAnalyzer a, int pid, string endpoint, params double[] offsetSeconds)
    {
        foreach (double s in offsetSeconds) a.Observe(pid, endpoint, T0.AddSeconds(s));
    }

    /// <summary>Cumulative timestamps built from a gap sequence, which is how a beacon actually arrives.</summary>
    private static double[] FromGaps(params double[] gaps)
    {
        var offsets = new double[gaps.Length + 1];
        for (int i = 0; i < gaps.Length; i++) offsets[i + 1] = offsets[i] + gaps[i];
        return offsets;
    }

    [Fact]
    public void PerfectMetronome_Is_Beaconing_With_High_Confidence()
    {
        var a = New();
        Feed(a, 100, "203.0.113.10:443", FromGaps(60, 60, 60, 60, 60, 60, 60, 60, 60));

        var v = a.AnalyzeEndpoint(100, "203.0.113.10:443");
        Assert.NotNull(v);
        Assert.True(v!.IsBeaconing);
        Assert.Equal(10, v.Connections);
        Assert.Equal(TimeSpan.FromSeconds(60), v.MedianInterval);
        Assert.Equal(0.0, v.JitterRatio);
        Assert.True(v.Confidence > 0.70, $"confidence was {v.Confidence}");
        Assert.Contains("cadence", v.Explanation);
    }

    [Fact]
    public void Small_Jitter_Still_Beaconing_Because_Mad_Is_Robust()
    {
        // Real implants jitter their sleep. A few-second wobble around 60s must survive.
        var a = New();
        Feed(a, 101, "c2.example:8443", FromGaps(58, 62, 59, 61, 60, 57, 63, 60, 59, 61, 60));

        var v = a.AnalyzeEndpoint(101, "c2.example:8443")!;
        Assert.True(v.IsBeaconing);
        Assert.Equal(TimeSpan.FromSeconds(60), v.MedianInterval);
        Assert.True(v.JitterRatio < BeaconAnalyzer.JitterThreshold);
    }

    [Fact]
    public void One_Wild_Outlier_Does_Not_Break_The_Median()
    {
        // The whole reason for MAD over standard deviation: a single missed check-in
        // (a laptop lid closing) must not destroy the estimate.
        var a = New();
        Feed(a, 102, "c2.example:443", FromGaps(60, 60, 60, 3600, 60, 60, 60, 60, 60));

        var v = a.AnalyzeEndpoint(102, "c2.example:443")!;
        Assert.Equal(TimeSpan.FromSeconds(60), v.MedianInterval);
        Assert.True(v.IsBeaconing);
    }

    [Fact]
    public void Wide_Uniform_Jitter_Defeats_The_Detector()
    {
        // Documents the known evasion honestly: randomising the sleep over a wide range
        // is cheap and it works.
        var a = New();
        Feed(a, 103, "c2.example:443", FromGaps(30, 600, 45, 320, 90, 500, 60, 210, 400, 75));

        var v = a.AnalyzeEndpoint(103, "c2.example:443")!;
        Assert.Equal(11, v.Connections);
        Assert.False(v.IsBeaconing);
        Assert.True(v.JitterRatio > BeaconAnalyzer.JitterThreshold);
        Assert.Contains("jitter", v.Explanation);
    }

    [Fact]
    public void Below_Minimum_Sample_Count_Is_Not_Beaconing()
    {
        var a = New(min: 6);
        Feed(a, 104, "c2.example:443", FromGaps(60, 60, 60));

        var v = a.AnalyzeEndpoint(104, "c2.example:443")!;
        Assert.Equal(4, v.Connections);
        Assert.False(v.IsBeaconing);
        Assert.Contains("minimum", v.Explanation);
    }

    [Fact]
    public void Sub_Second_Burst_Is_Not_A_Schedule()
    {
        var a = New();
        Feed(a, 105, "cdn.example:443", FromGaps(0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1));

        var v = a.AnalyzeEndpoint(105, "cdn.example:443")!;
        Assert.False(v.IsBeaconing);
        Assert.Equal(0.0, v.Confidence);
        Assert.Contains("burst", v.Explanation);
    }

    [Fact]
    public void Identical_Timestamps_Report_Max_Jitter_Not_Zero()
    {
        // A zero median makes MAD/median undefined. Reporting 0 would read downstream as
        // "perfect metronome", the exact opposite of the truth.
        var a = New();
        for (int i = 0; i < 10; i++) a.Observe(106, "x:443", T0);

        var v = a.AnalyzeEndpoint(106, "x:443")!;
        Assert.False(v.IsBeaconing);
        Assert.Equal(BeaconAnalyzer.MaxReportedJitter, v.JitterRatio);
        Assert.True(double.IsFinite(v.JitterRatio));
        Assert.True(double.IsFinite(v.Confidence));
    }

    [Fact]
    public void Cadence_Slower_Than_The_Band_Is_Rejected()
    {
        var a = New(window: TimeSpan.FromDays(30));
        Feed(a, 107, "slow.example:443", FromGaps(90000, 90000, 90000, 90000, 90000, 90000, 90000));

        var v = a.AnalyzeEndpoint(107, "slow.example:443")!;
        Assert.True(v.MedianInterval > BeaconAnalyzer.MaxBeaconInterval);
        Assert.False(v.IsBeaconing);
        Assert.Equal(0.0, v.Confidence);
    }

    [Fact]
    public void Confidence_Rises_With_Sample_Count()
    {
        var few = New();
        Feed(few, 108, "e:443", FromGaps(60, 60, 60, 60, 60));      // 6 samples
        var many = New();
        Feed(many, 109, "e:443", FromGaps(Enumerable.Repeat(60.0, 40).ToArray()));

        double a = few.AnalyzeEndpoint(108, "e:443")!.Confidence;
        double b = many.AnalyzeEndpoint(109, "e:443")!.Confidence;
        Assert.True(b > a, $"{b} should exceed {a}");
    }

    [Fact]
    public void Confidence_Falls_With_Jitter()
    {
        var tight = New();
        Feed(tight, 110, "e:443", FromGaps(60, 60, 60, 60, 60, 60, 60, 60, 60));
        var loose = New();
        Feed(loose, 111, "e:443", FromGaps(52, 68, 51, 69, 53, 67, 54, 66, 60));

        double a = tight.AnalyzeEndpoint(110, "e:443")!.Confidence;
        double b = loose.AnalyzeEndpoint(111, "e:443")!.Confidence;
        Assert.True(a > b, $"{a} should exceed {b}");
    }

    [Fact]
    public void Unknown_Pid_And_Endpoint_Are_Safe()
    {
        var a = New();
        Assert.Empty(a.Analyze(9999));
        Assert.Null(a.AnalyzeEndpoint(9999, "x:443"));

        Feed(a, 112, "known:443", 0, 60, 120);
        Assert.Null(a.AnalyzeEndpoint(112, "unknown:443"));
        Assert.NotNull(a.AnalyzeEndpoint(112, "known:443"));
    }

    [Theory]
    [InlineData("HOST:443")]
    [InlineData("  host:443  ")]
    [InlineData("Host:443")]
    public void Endpoints_Are_Normalised(string variant)
    {
        var a = New();
        Feed(a, 113, variant, 0, 60, 120);
        var v = a.AnalyzeEndpoint(113, "host:443");
        Assert.NotNull(v);
        Assert.Equal("host:443", v!.Endpoint);
        Assert.Equal(1, a.TrackedSeries);
    }

    [Theory]
    [InlineData(0, "x:443")]
    [InlineData(-1, "x:443")]
    [InlineData(1, "")]
    [InlineData(1, "   ")]
    public void Malformed_Observations_Are_Dropped(int pid, string endpoint)
    {
        var a = New();
        a.Observe(pid, endpoint, T0);
        Assert.Equal(0, a.TrackedSeries);
    }

    [Fact]
    public void Observation_Null_Endpoint_Is_Dropped()
    {
        var a = New();
        a.Observe(1, null!, T0);
        Assert.Equal(0, a.TrackedSeries);
    }

    [Fact]
    public void Ring_Buffer_Caps_Retained_Samples()
    {
        var a = New();
        for (int i = 0; i < 400; i++) a.Observe(114, "e:443", T0.AddSeconds(i * 60));

        var v = a.AnalyzeEndpoint(114, "e:443")!;
        Assert.Equal(256, v.Connections);
        Assert.True(v.IsBeaconing);
        // The retained window is the MOST RECENT 256, so the first sample is dropped.
        Assert.True(v.FirstUtc > T0);
        Assert.Equal(T0.AddSeconds(399 * 60), v.LastUtc);
    }

    [Fact]
    public void Out_Of_Order_Timestamps_Are_Sorted_Before_Differencing()
    {
        // ETW delivers from buffered sessions; a few reordered events per second is normal.
        var a = New();
        int[] order = { 5, 0, 8, 3, 1, 9, 2, 7, 4, 6 };
        foreach (int i in order) a.Observe(115, "e:443", T0.AddSeconds(i * 60));

        var v = a.AnalyzeEndpoint(115, "e:443")!;
        Assert.Equal(10, v.Connections);
        Assert.Equal(TimeSpan.FromSeconds(60), v.MedianInterval);
        Assert.True(v.IsBeaconing);
        Assert.Equal(T0, v.FirstUtc);
    }

    [Fact]
    public void Window_Is_Anchored_On_The_Newest_Sample()
    {
        var a = New(window: TimeSpan.FromMinutes(5));
        for (int i = 0; i < 10; i++) a.Observe(116, "e:443", T0.AddSeconds(i * 60));

        var v = a.AnalyzeEndpoint(116, "e:443")!;
        Assert.Equal(6, v.Connections);                       // minutes 4..9 inclusive
        Assert.Equal(T0.AddMinutes(4), v.FirstUtc);
        Assert.Equal(T0.AddMinutes(9), v.LastUtc);
        Assert.True(v.IsBeaconing);
    }

    [Fact]
    public void Endpoint_Cap_Evicts_The_Least_Recently_Active_Series()
    {
        // Documents the memory/evasion trade-off: spraying endpoints pushes the real one out.
        var a = New(maxEndpoints: 2);
        a.Observe(117, "a:443", T0);
        a.Observe(117, "b:443", T0.AddSeconds(10));
        a.Observe(117, "c:443", T0.AddSeconds(20));

        Assert.Equal(2, a.TrackedSeries);
        Assert.Null(a.AnalyzeEndpoint(117, "a:443"));
        Assert.NotNull(a.AnalyzeEndpoint(117, "b:443"));
        Assert.NotNull(a.AnalyzeEndpoint(117, "c:443"));
    }

    [Fact]
    public void Forget_Drops_Every_Series_For_A_Pid()
    {
        var a = New();
        Feed(a, 118, "a:443", 0, 60);
        Feed(a, 118, "b:443", 0, 60);
        Feed(a, 119, "a:443", 0, 60);
        Assert.Equal(3, a.TrackedSeries);

        a.Forget(118);
        Assert.Equal(1, a.TrackedSeries);
        Assert.Empty(a.Analyze(118));
        Assert.Single(a.Analyze(119));
    }

    [Fact]
    public void Prune_Removes_Only_Stale_Series()
    {
        var clock = new ManualClock(T0);
        var a = new BeaconAnalyzer(clock);
        a.Observe(120, "old:443", T0);
        clock.Advance(TimeSpan.FromHours(2));
        a.Observe(120, "fresh:443", clock.UtcNow);

        a.Prune(TimeSpan.FromHours(1));
        Assert.Equal(1, a.TrackedSeries);
        Assert.Null(a.AnalyzeEndpoint(120, "old:443"));
        Assert.NotNull(a.AnalyzeEndpoint(120, "fresh:443"));
    }

    [Fact]
    public void Prune_With_Generous_Retention_Keeps_Everything()
    {
        var clock = new ManualClock(T0);
        var a = new BeaconAnalyzer(clock);
        a.Observe(121, "e:443", T0);
        clock.Advance(TimeSpan.FromHours(2));

        a.Prune(TimeSpan.FromHours(3));
        Assert.Equal(1, a.TrackedSeries);
    }

    [Fact]
    public void Prune_Drops_The_Pid_Bucket_When_It_Empties()
    {
        var clock = new ManualClock(T0);
        var a = new BeaconAnalyzer(clock);
        a.Observe(122, "e:443", T0);
        clock.Advance(TimeSpan.FromDays(1));

        a.Prune(TimeSpan.Zero);
        Assert.Equal(0, a.TrackedSeries);
        Assert.Empty(a.Analyze(122));
    }

    [Fact]
    public void Analyze_Returns_Negative_Verdicts_Too_Ordered_By_Confidence()
    {
        var a = New();
        Feed(a, 123, "beacon:443", FromGaps(60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60));
        Feed(a, 123, "noisy:443", FromGaps(30, 600, 45, 320, 90, 500, 60, 210, 400, 75));

        var all = a.Analyze(123);
        Assert.Equal(2, all.Count);
        Assert.Equal("beacon:443", all[0].Endpoint);
        Assert.True(all[0].IsBeaconing);
        Assert.Equal("noisy:443", all[1].Endpoint);
        Assert.False(all[1].IsBeaconing);
        Assert.True(all[0].Confidence >= all[1].Confidence);
    }

    [Fact]
    public void Local_Kind_Timestamps_Are_Converted_Not_Reinterpreted()
    {
        var a = New();
        var localStart = new DateTime(2026, 3, 1, 12, 0, 0, DateTimeKind.Local);
        for (int i = 0; i < 8; i++) a.Observe(124, "e:443", localStart.AddSeconds(i * 60));

        var v = a.AnalyzeEndpoint(124, "e:443")!;
        Assert.True(v.IsBeaconing);
        Assert.Equal(DateTimeKind.Utc, v.FirstUtc.Kind);
        Assert.Equal(localStart.ToUniversalTime(), v.FirstUtc);
    }

    [Fact]
    public void MinConnections_Is_Floored_So_A_Single_Gap_Cannot_Be_Called_A_Cadence()
    {
        var a = New(min: 1);
        Feed(a, 125, "e:443", 0, 60);   // two samples, one gap

        var v = a.AnalyzeEndpoint(125, "e:443")!;
        Assert.Equal(2, v.Connections);
        Assert.False(v.IsBeaconing);
    }

    [Fact]
    public void Window_Argument_Is_Clamped_Rather_Than_Rejected()
    {
        // A bad config value must degrade the analyzer, not take the sensor down.
        var negative = New(window: TimeSpan.FromSeconds(-500));
        negative.Observe(126, "e:443", T0);
        Assert.Equal(1, negative.TrackedSeries);

        var enormous = New(window: TimeSpan.FromDays(9999));
        for (int i = 0; i < 8; i++) enormous.Observe(127, "e:443", T0.AddDays(i));
        Assert.Equal(8, enormous.AnalyzeEndpoint(127, "e:443")!.Connections);
    }

    [Fact]
    public void TrackedSeries_Counts_Across_Processes()
    {
        var a = New();
        Feed(a, 128, "a:443", 0);
        Feed(a, 128, "b:443", 0);
        Feed(a, 129, "a:443", 0);
        Assert.Equal(3, a.TrackedSeries);
    }
}

/// <summary>
/// DNS name heuristics. Assertions are directional (above/below the documented
/// threshold) rather than exact scores, except where the exact value is the contract.
/// </summary>
public class BehaviourDomainAnalysisTests
{
    [Theory]
    [InlineData("google.com")]
    [InlineData("microsoft.com")]
    [InlineData("github.com")]
    [InlineData("stackoverflow.com")]
    [InlineData("cloudfront.net")]
    [InlineData("en.wikipedia.org")]
    [InlineData("mail.google.com")]
    [InlineData("amazon.co.uk")]
    [InlineData("outlook.office365.com")]
    public void Ordinary_Names_Are_Not_Flagged_As_Dga(string domain)
    {
        var v = DomainAnalysis.Analyze(domain);
        Assert.False(v.LikelyDga);
        Assert.True(v.DgaScore < DomainAnalysis.DgaThreshold, $"{domain} scored {v.DgaScore}");
        Assert.False(v.LooksLikeDnsTunnel);
    }

    [Theory]
    [InlineData("xwzvbnmqrtplk.com")]
    [InlineData("qzxjvbwmkrtn.net")]
    [InlineData("kq3v9z7wxr.com")]
    public void Random_Looking_Labels_Are_Flagged_As_Dga(string domain)
    {
        var v = DomainAnalysis.Analyze(domain);
        Assert.True(v.LikelyDga, $"{domain} scored {v.DgaScore}");
        Assert.True(v.DgaScore >= DomainAnalysis.DgaThreshold);
        Assert.Contains("DGA", v.Explanation);
    }

    [Fact]
    public void Dga_In_A_Subdomain_Of_A_Benign_Provider_Is_Still_Caught()
    {
        // The registrable name here is "duckdns", which is perfectly pronounceable; only
        // the left-most label is attacker-chosen, so scoring the registrable name alone
        // would miss the whole family.
        var v = DomainAnalysis.Analyze("qzxjvbwmkrtn.duckdns.org");
        Assert.True(v.LikelyDga);
        Assert.True(v.IsDynamicDns);
        Assert.Equal("duckdns.org", v.RegistrableDomain);
        Assert.Equal(3, v.LabelCount);
    }

    [Fact]
    public void Short_Labels_Are_Gated_Out_Because_They_Carry_Too_Little_Signal()
    {
        var v = DomainAnalysis.Analyze("qzxk.com");
        Assert.False(v.LikelyDga);
    }

    [Theory]
    [InlineData("abc.duckdns.org", true)]
    [InlineData("duckdns.org", true)]
    [InlineData("home.no-ip.org", true)]
    [InlineData("x.ddns.net", true)]
    [InlineData("demo.ngrok.io", true)]
    [InlineData("something.trycloudflare.com", true)]
    [InlineData("app.herokuapp.com", true)]
    [InlineData("evilduckdns.org", false)]
    [InlineData("example.com", false)]
    [InlineData("notngrok.io.example.com", false)]
    [InlineData("", false)]
    public void Dynamic_Dns_Providers_Match_On_A_Suffix_Boundary(string domain, bool expected)
        => Assert.Equal(expected, DomainAnalysis.IsDynamicDnsProvider(domain));

    [Theory]
    [InlineData("www.example.com", "example.com")]
    [InlineData("example.com", "example.com")]
    [InlineData("com", "com")]
    [InlineData("localhost", "localhost")]
    [InlineData("a.b.example.co.uk", "example.co.uk")]
    [InlineData("shop.example.com.au", "example.com.au")]
    [InlineData("example.co.uk", "example.co.uk")]
    [InlineData("co.uk", "co.uk")]
    [InlineData("WWW.Example.COM.", "example.com")]
    [InlineData("  spaced.example.org  ", "example.org")]
    [InlineData("", "")]
    public void RegistrableDomain_Handles_Multipart_Suffixes(string input, string expected)
        => Assert.Equal(expected, DomainAnalysis.RegistrableDomain(input));

    [Fact]
    public void RegistrableDomain_Of_An_Ip_Literal_Is_The_Literal()
        => Assert.Equal("203.0.113.5", DomainAnalysis.RegistrableDomain("203.0.113.5"));

    [Fact]
    public void Punycode_Labels_Are_Reported()
    {
        var v = DomainAnalysis.Analyze("xn--80ak6aa92e.com");
        Assert.True(v.IsPunycode);
        Assert.Contains("IDNA", v.Explanation);
    }

    [Fact]
    public void Ascii_Names_Are_Not_Reported_As_Punycode()
        => Assert.False(DomainAnalysis.Analyze("apple.com").IsPunycode);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(".")]
    [InlineData("...")]
    public void Empty_Input_Yields_A_Safe_Verdict(string domain)
    {
        var v = DomainAnalysis.Analyze(domain);
        Assert.False(v.LikelyDga);
        Assert.False(v.LooksLikeDnsTunnel);
        Assert.Equal(0, v.LabelCount);
        Assert.False(string.IsNullOrWhiteSpace(v.Explanation));
    }

    [Fact]
    public void Null_Input_Does_Not_Throw()
    {
        var v = DomainAnalysis.Analyze(null!);
        Assert.Equal("", v.Domain);
        Assert.False(v.LikelyDga);
    }

    [Theory]
    [InlineData("203.0.113.5")]
    [InlineData("8.8.8.8")]
    [InlineData("2606:4700:4700::1111")]
    public void Ip_Literals_Are_Not_Scored_As_Domains(string literal)
    {
        var v = DomainAnalysis.Analyze(literal);
        Assert.False(v.LikelyDga);
        Assert.False(v.LooksLikeDnsTunnel);
        Assert.Equal(0.0, v.DgaScore);
        Assert.Contains("IP address", v.Explanation);
    }

    [Fact]
    public void Very_Long_Left_Label_Reads_As_Tunnelling()
    {
        string label = new('a', 45);
        var v = DomainAnalysis.Analyze(label + ".tunnel.example.com");
        Assert.True(v.LooksLikeDnsTunnel);
        Assert.Contains("tunnel", v.Explanation);
    }

    [Fact]
    public void Base32_Left_Label_Reads_As_Tunnelling()
    {
        var v = DomainAnalysis.Analyze("mzxw6ytboi7gk3tdn5sgs3tenfxgo4.t.example.com");
        Assert.True(v.LooksLikeDnsTunnel);
    }

    [Fact]
    public void Hex_Left_Label_Reads_As_Tunnelling()
    {
        var v = DomainAnalysis.Analyze("d41d8cd98f00b204e9800998ecf8427e.lookup.example.com");
        Assert.True(v.LooksLikeDnsTunnel);
    }

    [Fact]
    public void Many_Long_Labels_Read_As_Chunked_Tunnelling()
    {
        var v = DomainAnalysis.Analyze("aaaabbbbcc.ddddeeeeff.gggghhhhii.jjjjkkkkll.mmmmnnnnoo.ppppqqqqrr.ssssttttuu.vvvvwwwwxx.example.com");
        Assert.True(v.LooksLikeDnsTunnel);
        Assert.True(v.LabelCount >= 7);
    }

    [Theory]
    [InlineData("www.google.com")]
    [InlineData("cdn.example.co.uk")]
    [InlineData("api.v2.service.example.com")]
    [InlineData("a.b.c.d.e.example.com")]
    public void Ordinary_Names_Do_Not_Read_As_Tunnelling(string domain)
        => Assert.False(DomainAnalysis.Analyze(domain).LooksLikeDnsTunnel);

    [Fact]
    public void An_All_Alphabetic_Long_Label_Is_Not_Called_Base32()
    {
        // Requiring at least one 2-7 digit stops every long English-ish label from being
        // called an encoded payload.
        var v = DomainAnalysis.Analyze("supercalifragilistic.example.com");
        Assert.False(v.LooksLikeDnsTunnel);
    }

    [Fact]
    public void Hostile_Oversized_Input_Is_Truncated_Not_Fatal()
    {
        string monster = new string('a', 100_000) + ".com";
        var v = DomainAnalysis.Analyze(monster);
        Assert.Contains("truncated", v.Explanation);
        Assert.True(v.DgaScore is >= 0.0 and <= 1.0);
    }

    [Fact]
    public void Consecutive_And_Leading_Dots_Are_Tolerated()
    {
        var v = DomainAnalysis.Analyze("..example..com..");
        Assert.Equal(2, v.LabelCount);
        Assert.Equal("example.com", v.RegistrableDomain);
        Assert.Equal("com", v.Tld);
    }

    [Fact]
    public void Label_Count_And_Tld_Are_Reported()
    {
        var v = DomainAnalysis.Analyze("a.b.c.example.com");
        Assert.Equal(5, v.LabelCount);
        Assert.Equal("com", v.Tld);
        Assert.Equal("example.com", v.RegistrableDomain);
    }

    [Fact]
    public void Entropy_Is_The_Shannon_Entropy_Of_The_Scored_Label()
    {
        // "abab" has two symbols at equal probability: exactly one bit per character.
        var v = DomainAnalysis.Analyze("abab.com");
        Assert.Equal(1.0, v.Entropy, 3);
    }

    [Fact]
    public void Ratios_Are_Reported_For_The_Scored_Label()
    {
        var v = DomainAnalysis.Analyze("ab12.com");
        Assert.Equal(0.5, v.DigitRatio, 3);
        Assert.Equal(0.5, v.ConsonantRatio, 3);   // 'b' of {a, b}
    }

    [Theory]
    [InlineData("google.com")]
    [InlineData("xwzvbnmqrtplk.com")]
    [InlineData("1234567890.com")]
    [InlineData("----------.com")]
    [InlineData("a.com")]
    [InlineData("xn--fsq.com")]
    [InlineData("_acme-challenge.example.com")]
    [InlineData("_sip._tcp.example.com")]
    public void Scores_Stay_Finite_And_In_Range(string domain)
    {
        var v = DomainAnalysis.Analyze(domain);
        Assert.True(double.IsFinite(v.DgaScore) && v.DgaScore is >= 0.0 and <= 1.0);
        Assert.True(double.IsFinite(v.Entropy) && v.Entropy >= 0.0);
        Assert.True(v.ConsonantRatio is >= 0.0 and <= 1.0);
        Assert.True(v.DigitRatio is >= 0.0 and <= 1.0);
        Assert.False(string.IsNullOrWhiteSpace(v.Explanation));
    }

    [Fact]
    public void Hyphenated_Infrastructure_Names_Are_Not_Punished()
    {
        // Hyphens break bigram pairs and consonant runs on purpose.
        var v = DomainAnalysis.Analyze("s3-us-west-2.amazonaws.com");
        Assert.False(v.LikelyDga);
    }

    [Fact]
    public void Case_And_Trailing_Root_Dot_Are_Normalised()
    {
        var v = DomainAnalysis.Analyze("WWW.EXAMPLE.COM.");
        Assert.Equal("www.example.com", v.Domain);
        Assert.Equal(3, v.LabelCount);
    }
}

/// <summary>
/// Lineage. Each of the four correctness requirements (PID reuse, cycles, bounded
/// memory, unknown pids) has dedicated cases here.
/// </summary>
public class BehaviourProcessTreeTests
{
    private static readonly DateTime T0 = new(2026, 3, 1, 9, 0, 0, DateTimeKind.Utc);

    private static ProcessTree New(int maxNodes = 8192, ManualClock? clock = null)
        => new(clock ?? new ManualClock(T0), maxNodes);

    private static void Start(ProcessTree t, int pid, int ppid, string name, double atSeconds)
        => t.OnStart(pid, ppid, name, @"C:\Windows\System32\" + name, name + " /c", T0.AddSeconds(atSeconds));

    [Fact]
    public void Lineage_Renders_Root_First()
    {
        var t = New();
        Start(t, 100, 0, "winword.exe", 0);
        Start(t, 200, 100, "cmd.exe", 1);
        Start(t, 300, 200, "powershell.exe", 2);

        Assert.Equal("winword.exe -> cmd.exe -> powershell.exe", t.Lineage(300));
    }

    [Fact]
    public void Ancestors_Are_Nearest_Parent_First()
    {
        var t = New();
        Start(t, 100, 0, "winword.exe", 0);
        Start(t, 200, 100, "cmd.exe", 1);
        Start(t, 300, 200, "powershell.exe", 2);

        var a = t.Ancestors(300);
        Assert.Equal(2, a.Count);
        Assert.Equal("cmd.exe", a[0].Name);
        Assert.Equal("winword.exe", a[1].Name);
    }

    [Fact]
    public void Unknown_Pid_Queries_Return_Empty_Never_Null()
    {
        var t = New();
        Assert.Empty(t.Ancestors(4242));
        Assert.Empty(t.Children(4242));
        Assert.Empty(t.Descendants(4242));
        Assert.Equal("", t.Lineage(4242));
        Assert.Null(t.Get(4242));
    }

    [Fact]
    public void Reused_Pid_Replaces_The_Node_And_Detaches_It_From_The_Old_Parent()
    {
        var t = New();
        Start(t, 100, 0, "winword.exe", 0);
        Start(t, 200, 100, "cmd.exe", 1);
        Assert.Single(t.Children(100));

        Start(t, 200, 999, "evil.exe", 5);   // Windows recycled pid 200

        Assert.Empty(t.Children(100));
        var node = t.Get(200)!;
        Assert.Equal("evil.exe", node.Name);
        Assert.Equal(999, node.ParentPid);
        Assert.Equal(T0.AddSeconds(5), node.StartUtc);
    }

    [Fact]
    public void Reused_Parent_Pid_Does_Not_Lend_Its_Ancestry_To_An_Existing_Child()
    {
        var t = New();
        Start(t, 100, 0, "winword.exe", 0);
        Start(t, 200, 100, "cmd.exe", 1);
        Start(t, 300, 200, "powershell.exe", 2);
        Assert.Equal(2, t.Ancestors(300).Count);

        // pid 200 is recycled by an unrelated process that started AFTER pid 300.
        Start(t, 200, 0, "chrome.exe", 10);

        Assert.Empty(t.Ancestors(300));
        Assert.Equal("powershell.exe", t.Lineage(300));
    }

    [Fact]
    public void Reused_Pid_Starts_With_An_Empty_Child_List()
    {
        var t = New();
        Start(t, 100, 0, "svchost.exe", 0);
        Start(t, 200, 100, "child.exe", 1);
        Start(t, 100, 0, "recycled.exe", 5);

        Assert.Empty(t.Children(100));
        Assert.Empty(t.Descendants(100));
    }

    [Fact]
    public void Two_Node_Parent_Cycle_Terminates()
    {
        var t = New();
        t.OnStart(1, 2, "a.exe", "", "", T0);
        t.OnStart(2, 1, "b.exe", "", "", T0);

        // Each walk stops at the first repeat rather than looping forever.
        var a = t.Ancestors(2);
        Assert.Single(a);
        Assert.Equal("a.exe", a[0].Name);
        Assert.Equal("b.exe -> a.exe", t.Lineage(1));
        Assert.Equal("a.exe -> b.exe", t.Lineage(2));
        Assert.Empty(t.Descendants(2));
    }

    [Fact]
    public void Self_Parenting_Terminates()
    {
        var t = New();
        t.OnStart(5, 5, "self.exe", "", "", T0);

        Assert.Empty(t.Ancestors(5));
        Assert.Empty(t.Children(5));
        Assert.Equal("self.exe", t.Lineage(5));
    }

    [Fact]
    public void Long_Chain_Is_Capped_By_MaxDepth()
    {
        var t = New();
        Start(t, 1, 0, "p1.exe", 0);
        for (int i = 2; i <= 30; i++) Start(t, i, i - 1, "p" + i + ".exe", i);

        Assert.Equal(5, t.Ancestors(30, maxDepth: 5).Count);
        Assert.Equal(16, t.Ancestors(30).Count);         // default depth
        Assert.Equal(29, t.Ancestors(30, maxDepth: 100).Count);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-7)]
    public void Nonsense_MaxDepth_Still_Returns_Something_Bounded(int depth)
    {
        var t = New();
        Start(t, 1, 0, "a.exe", 0);
        Start(t, 2, 1, "b.exe", 1);
        Start(t, 3, 2, "c.exe", 2);

        Assert.Single(t.Ancestors(3, depth));            // clamped to 1
        Assert.Single(t.Descendants(1, depth));
    }

    [Fact]
    public void Children_Are_Direct_Only_And_In_Attach_Order()
    {
        var t = New();
        Start(t, 100, 0, "root.exe", 0);
        Start(t, 200, 100, "a.exe", 1);
        Start(t, 300, 100, "b.exe", 2);
        Start(t, 400, 200, "grandchild.exe", 3);

        var kids = t.Children(100);
        Assert.Equal(2, kids.Count);
        Assert.Equal("a.exe", kids[0].Name);
        Assert.Equal("b.exe", kids[1].Name);
    }

    [Fact]
    public void Descendants_Are_Breadth_First()
    {
        var t = New();
        Start(t, 100, 0, "winword.exe", 0);
        Start(t, 200, 100, "cmd.exe", 1);
        Start(t, 300, 200, "powershell.exe", 2);
        Start(t, 400, 100, "notepad.exe", 3);

        var d = t.Descendants(100);
        Assert.Equal(new[] { "cmd.exe", "notepad.exe", "powershell.exe" }, d.Select(n => n.Name).ToArray());
        Assert.Equal(2, t.Descendants(100, maxDepth: 1).Count);
    }

    [Fact]
    public void A_Parent_That_Started_After_Its_Claimed_Child_Is_Not_Attached()
    {
        var t = New();
        Start(t, 20, 10, "child.exe", 60);
        Start(t, 10, 0, "recycled-parent.exe", 120);

        Assert.Empty(t.Children(10));
        Assert.Empty(t.Ancestors(20));
    }

    [Fact]
    public void Eviction_Prefers_The_Oldest_Exited_Node()
    {
        var t = New(maxNodes: 4);
        Start(t, 1, 0, "a.exe", 0);
        Start(t, 2, 0, "b.exe", 1);
        Start(t, 3, 0, "c.exe", 2);
        Start(t, 4, 0, "d.exe", 3);
        t.OnExit(3, T0.AddSeconds(4));

        Start(t, 5, 0, "e.exe", 5);

        Assert.Equal(4, t.Count);
        Assert.Null(t.Get(3));
        Assert.NotNull(t.Get(1));
        Assert.NotNull(t.Get(5));
    }

    [Fact]
    public void Eviction_Falls_Back_To_The_Oldest_Live_Node()
    {
        var t = New(maxNodes: 4);
        Start(t, 1, 0, "a.exe", 0);
        Start(t, 2, 0, "b.exe", 1);
        Start(t, 3, 0, "c.exe", 2);
        Start(t, 4, 0, "d.exe", 3);

        Start(t, 5, 0, "e.exe", 4);

        Assert.Equal(4, t.Count);
        Assert.Null(t.Get(1));
        Assert.NotNull(t.Get(2));
        Assert.NotNull(t.Get(5));
    }

    [Fact]
    public void Eviction_Detaches_The_Victim_From_Its_Parent()
    {
        var t = New(maxNodes: 4);
        Start(t, 1, 0, "root.exe", 0);
        Start(t, 2, 1, "a.exe", 1);
        Start(t, 3, 1, "b.exe", 2);
        Start(t, 4, 1, "c.exe", 3);
        t.OnExit(2, T0.AddSeconds(4));

        Start(t, 5, 1, "d.exe", 5);

        Assert.Null(t.Get(2));
        Assert.DoesNotContain(t.Children(1), n => n.Pid == 2);
        Assert.Contains(t.Children(1), n => n.Pid == 3);
    }

    [Fact]
    public void Eviction_Never_Exceeds_The_Cap_Under_Sustained_Churn()
    {
        var t = New(maxNodes: 8);
        for (int pid = 1; pid <= 500; pid++)
        {
            Start(t, pid, pid - 1, "p.exe", pid);
            if (pid % 3 == 0) t.OnExit(pid, T0.AddSeconds(pid + 0.5));
            Assert.True(t.Count <= 8);
        }
        Assert.Equal(8, t.Count);
    }

    [Fact]
    public void Prune_Removes_Exited_Nodes_Past_Retention()
    {
        var clock = new ManualClock(T0);
        var t = New(clock: clock);
        Start(t, 1, 0, "root.exe", 0);
        Start(t, 2, 1, "child.exe", 1);
        t.OnExit(2, T0.AddSeconds(2));

        clock.Advance(TimeSpan.FromHours(2));
        t.Prune(TimeSpan.FromHours(1));

        Assert.Equal(1, t.Count);
        Assert.Null(t.Get(2));
        Assert.Empty(t.Children(1));
    }

    [Fact]
    public void Prune_Never_Removes_A_Live_Node_However_Old()
    {
        var clock = new ManualClock(T0);
        var t = New(clock: clock);
        Start(t, 1, 0, "services.exe", 0);

        clock.Advance(TimeSpan.FromDays(365));
        t.Prune(TimeSpan.Zero);

        Assert.Equal(1, t.Count);
        Assert.NotNull(t.Get(1));
    }

    [Fact]
    public void Prune_Keeps_Recently_Exited_Nodes()
    {
        var clock = new ManualClock(T0);
        var t = New(clock: clock);
        Start(t, 1, 0, "a.exe", 0);
        t.OnExit(1, T0.AddSeconds(1));

        clock.Advance(TimeSpan.FromMinutes(5));
        t.Prune(TimeSpan.FromHours(1));

        Assert.Equal(1, t.Count);
    }

    [Fact]
    public void Exit_For_An_Unknown_Pid_Is_Ignored()
    {
        var t = New();
        t.OnExit(777, T0);
        Assert.Equal(0, t.Count);
        Assert.Null(t.Get(777));
    }

    [Fact]
    public void Duplicate_Exit_Keeps_The_First_Timestamp()
    {
        var t = New();
        Start(t, 1, 0, "a.exe", 0);
        t.OnExit(1, T0.AddSeconds(10));
        t.OnExit(1, T0.AddSeconds(999));

        Assert.Equal(T0.AddSeconds(10), t.Get(1)!.ExitUtc);
    }

    [Fact]
    public void Exited_Is_Derived_From_ExitUtc()
    {
        var t = New();
        Start(t, 1, 0, "a.exe", 0);
        Assert.False(t.Get(1)!.Exited);

        t.OnExit(1, T0.AddSeconds(1));
        Assert.True(t.Get(1)!.Exited);
        Assert.Equal(T0.AddSeconds(1), t.Get(1)!.ExitUtc);
    }

    [Fact]
    public void Restarting_An_Exited_Pid_Clears_The_Exit_State()
    {
        var t = New();
        Start(t, 1, 0, "a.exe", 0);
        t.OnExit(1, T0.AddSeconds(1));
        Start(t, 1, 0, "b.exe", 2);

        var node = t.Get(1)!;
        Assert.False(node.Exited);
        Assert.Equal("b.exe", node.Name);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void Non_Positive_Pids_Are_Rejected(int pid)
    {
        var t = New();
        t.OnStart(pid, 1, "a.exe", "", "", T0);
        t.OnExit(pid, T0);
        Assert.Equal(0, t.Count);
    }

    [Fact]
    public void Name_Falls_Back_To_The_Image_File_Name()
    {
        var t = New();
        t.OnStart(7, 0, "", @"C:\Windows\System32\cmd.exe", "", T0);
        Assert.Equal("cmd.exe", t.Get(7)!.Name);
    }

    [Fact]
    public void Nameless_Nodes_Render_As_Their_Pid()
    {
        var t = New();
        t.OnStart(50, 0, "", "", "", T0);
        Assert.Equal("pid:50", t.Lineage(50));
    }

    [Fact]
    public void Local_Kind_Start_Times_Are_Converted_To_Utc()
    {
        var t = New();
        var local = new DateTime(2026, 3, 1, 9, 0, 0, DateTimeKind.Local);
        t.OnStart(9, 0, "a.exe", "", "", local);

        var node = t.Get(9)!;
        Assert.Equal(DateTimeKind.Utc, node.StartUtc.Kind);
        Assert.Equal(local.ToUniversalTime(), node.StartUtc);
    }

    [Fact]
    public void Count_Tracks_Starts_But_Not_Exits()
    {
        var t = New();
        Assert.Equal(0, t.Count);
        Start(t, 1, 0, "a.exe", 0);
        Start(t, 2, 1, "b.exe", 1);
        Assert.Equal(2, t.Count);

        t.OnExit(2, T0.AddSeconds(2));
        Assert.Equal(2, t.Count);   // retained for post-mortem lineage
    }

    [Fact]
    public void Null_Strings_Are_Tolerated()
    {
        var t = New();
        t.OnStart(1, 0, null!, null!, null!, T0);

        var node = t.Get(1)!;
        Assert.Equal("", node.Name);
        Assert.Equal("", node.ImagePath);
        Assert.Equal("", node.CommandLine);
    }

    [Fact]
    public void Ancestry_Stops_At_An_Evicted_Parent_Instead_Of_Guessing()
    {
        var t = New(maxNodes: 4);
        Start(t, 1, 0, "root.exe", 0);
        Start(t, 2, 1, "mid.exe", 1);
        Start(t, 3, 2, "leaf.exe", 2);
        Start(t, 4, 3, "leaf2.exe", 3);
        Start(t, 5, 4, "leaf3.exe", 4);   // evicts pid 1

        Assert.Null(t.Get(1));
        var a = t.Ancestors(3);
        Assert.Single(a);
        Assert.Equal("mid.exe", a[0].Name);
    }
}
