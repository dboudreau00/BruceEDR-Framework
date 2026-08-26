using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace BruceEDR.Intel;

/// <summary>Kind of indicator a feed line described.</summary>
public enum IocType
{
    /// <summary>64 hex characters. Matched against a file's SHA-256.</summary>
    Sha256,
    /// <summary>32 hex characters. Matched against a file's MD5.</summary>
    Md5,
    /// <summary>A DNS name. Matches the name itself and every subdomain of it.</summary>
    Domain,
    /// <summary>A single IPv4 or IPv6 literal.</summary>
    IpAddress,
    /// <summary>An IPv4 or IPv6 CIDR block.</summary>
    IpRange,
    /// <summary>A case-insensitive substring of a URL, written <c>url:&lt;substring&gt;</c>.</summary>
    UrlFragment
}

/// <summary>
/// One matched indicator, carrying enough provenance for an analyst to work out where
/// the intel came from and why it fired.
/// </summary>
/// <param name="Type">Which indicator family matched.</param>
/// <param name="Indicator">The stored (normalised) indicator, not the observed value.</param>
/// <param name="Label">Operator-supplied description after the <c>;</c>, or empty.</param>
/// <param name="Source">Feed file the indicator came from, relative to the feed directory.</param>
public sealed record IocHit(IocType Type, string Indicator, string Label, string Source);

/// <summary>
/// An operator-editable indicator set loaded from plain text files.
///
/// WHY PLAIN TEXT: every commercial and community feed can be flattened to one
/// indicator per line, so an operator can wire BruceEDR to their own intel with
/// <c>curl</c> and a cron job instead of an integration. Format per line, with the type
/// auto-detected so no column headers are needed:
/// <code>
///   # comment lines and blank lines are ignored
///   d41d8cd98f00b204e9800998ecf8427e            ; md5, 32 hex
///   e3b0c44298fc1c149afbf4c8996fb924...         ; sha256, 64 hex
///   evil.example.com                            ; domain (also matches subdomains)
///   *.evil.example.com                          ; wildcard form, stored as the parent
///   198.51.100.7                                ; IPv4 or IPv6 literal
///   198.51.100.0/24                             ; CIDR, either family
///   url:/gate.php?id=                           ; case-insensitive URL substring
///   1.2.3.4 ; label shown to the analyst
/// </code>
///
/// PERFORMANCE: feeds routinely hold millions of lines, so hashes, domains and single
/// addresses are dictionary lookups, and CIDR containment costs one masked lookup per
/// DISTINCT prefix length present in the feed (typically under ten), never a scan of
/// the ranges. URL fragments are the one exception -- substring matching cannot be
/// hashed, so <see cref="MatchUrl"/> is linear in the number of URL fragments. Keep
/// that list in the hundreds, not the millions.
///
/// THREAD SAFETY: an instance is immutable once a factory method returns, so it can be
/// published to the monitor threads with a single volatile write and swapped wholesale
/// on reload. Nothing mutates it after construction.
/// </summary>
public sealed class IocFeed
{
    // Feed lines are normalised to lowercase before they become keys, so ordinal
    // comparison is both correct and the fastest option.
    private readonly Dictionary<string, IocHit> _sha256 = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IocHit> _md5 = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IocHit> _domains = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IocHit> _addresses = new(StringComparer.Ordinal);
    private readonly Dictionary<string, IocHit> _rangesByCidr = new(StringComparer.Ordinal);

    // prefix length -> masked-network-bytes (hex) -> hit. SortedDictionary with a
    // descending comparer so the most specific matching block wins.
    private readonly SortedDictionary<int, Dictionary<string, IocHit>> _v4 = new(DescendingInt.Instance);
    private readonly SortedDictionary<int, Dictionary<string, IocHit>> _v6 = new(DescendingInt.Instance);

    private readonly List<KeyValuePair<string, IocHit>> _urlFragments = new();
    private readonly HashSet<string> _urlSeen = new(StringComparer.Ordinal);

    // Insertion-ordered view of everything stored, so All() and Merge() are deterministic
    // regardless of hash-table internals.
    private readonly List<IocHit> _all = new();

    private static readonly Regex DomainPattern = new(
        @"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
        TimeSpan.FromMilliseconds(250));

    private static readonly string[] FeedExtensions = { ".txt", ".ioc", ".csv" };

    /// <summary>Creates an empty feed. Useful as the "no intel configured" default.</summary>
    public IocFeed() { }

    /// <summary>Total distinct indicators held across every family.</summary>
    public int Count => _all.Count;

    /// <summary>Every stored indicator, in the order it was loaded.</summary>
    public IReadOnlyList<IocHit> All => _all;

    /// <summary>
    /// Load every <c>*.txt</c>, <c>*.ioc</c> and <c>*.csv</c> under
    /// <paramref name="dir"/> (recursively, so operators can group feeds into
    /// subfolders). Never throws: a missing directory or an unreadable file is reported
    /// through <paramref name="warn"/> and skipped, because losing one feed must not
    /// stop the agent from starting.
    ///
    /// Files are processed in sorted path order so that "first definition wins" on
    /// duplicate indicators is reproducible across machines.
    /// </summary>
    public static IocFeed LoadDirectory(string dir, Action<string>? warn = null)
    {
        var feed = new IocFeed();
        try
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            {
                warn?.Invoke($"ioc feed directory not found: {dir}");
                return feed;
            }

            // Enumerate once and filter on the real extension. A Windows search pattern
            // of "*.txt" also matches "notes.txtx" through legacy 8.3 name matching, and
            // silently ingesting an unintended file as intel would be a nasty surprise.
            var files = Directory
                .EnumerateFiles(dir, "*", SearchOption.AllDirectories)
                .Where(f => FeedExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase))
                .ToList();
            files.Sort(StringComparer.OrdinalIgnoreCase);

            foreach (var f in files)
            {
                string source;
                try { source = Path.GetRelativePath(dir, f); }
                catch { source = Path.GetFileName(f); }

                try { feed.ParseInto(File.ReadLines(f), source, warn); }
                catch (Exception ex) { warn?.Invoke($"ioc feed unreadable: {f}: {ex.Message}"); }
            }
        }
        catch (Exception ex)
        {
            warn?.Invoke("ioc feed load failed: " + ex.Message);
        }
        return feed;
    }

    /// <summary>Parse indicator lines from any source (a file, an HTTP body, a test).</summary>
    public static IocFeed Parse(IEnumerable<string> lines, string source)
    {
        var feed = new IocFeed();
        feed.ParseInto(lines, source, null);
        return feed;
    }

    /// <summary>
    /// Combine two feeds into a new one. On a duplicate indicator THIS feed's entry wins,
    /// so a local override file layered over a downloaded feed keeps the operator's own
    /// label. Neither input is modified.
    /// </summary>
    public IocFeed Merge(IocFeed? other)
    {
        var merged = new IocFeed();
        foreach (var h in _all) merged.AddHit(h);
        if (other is not null)
            foreach (var h in other._all) merged.AddHit(h);
        return merged;
    }

    // ---- matching ----------------------------------------------------------------

    /// <summary>
    /// Match a hex digest against the SHA-256 or MD5 sets, chosen by length. Input is
    /// trimmed and lower-cased, so either case works. Returns null for anything that is
    /// not 32 or 64 hex characters.
    /// </summary>
    public IocHit? MatchHash(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex)) return null;
        string h = hex.Trim().ToLowerInvariant();
        if (!IsHex(h)) return null;
        if (h.Length == 64) return _sha256.TryGetValue(h, out var s) ? s : null;
        if (h.Length == 32) return _md5.TryGetValue(h, out var m) ? m : null;
        return null;
    }

    /// <summary>
    /// Match a DNS name exactly, then against each parent domain, so a feed entry of
    /// <c>evil.com</c> catches <c>a.b.evil.com</c>. Label-wise stripping is what keeps
    /// <c>notevil.com</c> from matching <c>evil.com</c>, which a naive
    /// <c>EndsWith</c> would get wrong.
    /// </summary>
    public IocHit? MatchDomain(string? domain)
    {
        string d = NormalizeDomain(domain);
        if (d.Length == 0) return null;

        // Bounded: DNS allows at most 127 labels, and a hostile input must not turn one
        // lookup into an unbounded loop.
        for (int guard = 0; guard < 128 && d.Length > 0; guard++)
        {
            if (_domains.TryGetValue(d, out var hit)) return hit;
            int dot = d.IndexOf('.');
            if (dot < 0) break;
            d = d[(dot + 1)..];
        }
        return null;
    }

    /// <summary>
    /// Match a literal address, then any CIDR block containing it, most specific first.
    ///
    /// Parsing here is deliberately PERMISSIVE (plain <see cref="IPAddress.TryParse"/>),
    /// the opposite of feed parsing: observed telemetry should be canonicalised and
    /// matched even when it arrives in an odd form, whereas an operator's config file
    /// should be rejected rather than silently reinterpreted.
    /// </summary>
    public IocHit? MatchIp(string? ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return null;
        if (!IPAddress.TryParse(ip.Trim(), out var parsed)) return null;

        var hit = MatchParsedIp(parsed);
        if (hit is not null) return hit;

        // "::ffff:198.51.100.7" and "198.51.100.7" are the same host, and a dual-stack
        // socket reports the former. Fall back to the IPv4 view so a v4 feed entry still
        // fires. Feeds are otherwise matched strictly within one family.
        if (parsed.AddressFamily == AddressFamily.InterNetworkV6 && parsed.IsIPv4MappedToIPv6)
        {
            try { return MatchParsedIp(parsed.MapToIPv4()); }
            catch { return null; }
        }
        return null;
    }

    private IocHit? MatchParsedIp(IPAddress parsed)
    {
        byte[] bytes = parsed.GetAddressBytes();

        // Rebuild from bytes to drop any IPv6 scope id ("fe80::1%12") before comparing.
        string norm = new IPAddress(bytes).ToString().ToLowerInvariant();
        if (_addresses.TryGetValue(norm, out var exact)) return exact;

        var table = parsed.AddressFamily == AddressFamily.InterNetworkV6 ? _v6 : _v4;
        foreach (var kv in table)   // descending prefix length: longest match wins
        {
            string key = Convert.ToHexString(MaskBytes(bytes, kv.Key));
            if (kv.Value.TryGetValue(key, out var hit)) return hit;
        }
        return null;
    }

    /// <summary>
    /// Match a URL against the <c>url:</c> substring set, case-insensitively. Linear in
    /// the number of fragments (see the class remarks); the first fragment added that
    /// matches is returned, so ordering is stable.
    /// </summary>
    public IocHit? MatchUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || _urlFragments.Count == 0) return null;
        string u = url.ToLowerInvariant();
        foreach (var kv in _urlFragments)
        {
            if (u.Contains(kv.Key, StringComparison.Ordinal)) return kv.Value;
        }
        return null;
    }

    // ---- parsing -----------------------------------------------------------------

    private void ParseInto(IEnumerable<string> lines, string source, Action<string>? warn)
    {
        source ??= "";
        int lineNo = 0;
        foreach (var raw in lines)
        {
            lineNo++;
            if (raw is null) continue;

            string line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;

            // "<indicator> ; <label>". Split on the FIRST ';' so a label may itself
            // contain semicolons; the cost is that an indicator may not, which only
            // constrains url: fragments in practice.
            string label = "";
            int sc = line.IndexOf(';');
            if (sc >= 0)
            {
                label = line[(sc + 1)..].Trim();
                line = line[..sc].Trim();
            }
            if (line.Length == 0) continue;

            if (!AddLine(line, label, source))
                warn?.Invoke($"{source}:{lineNo}: unrecognised indicator '{Clip(line)}'");
        }
    }

    private bool AddLine(string indicator, string label, string source)
    {
        if (indicator.StartsWith("url:", StringComparison.OrdinalIgnoreCase))
        {
            string frag = indicator[4..].Trim().ToLowerInvariant();
            if (frag.Length == 0) return false;
            return AddUrlFragment(frag, label, source);
        }

        string lower = indicator.ToLowerInvariant();

        if (lower.Length == 64 && IsHex(lower)) return Store(_sha256, IocType.Sha256, lower, label, source);
        if (lower.Length == 32 && IsHex(lower)) return Store(_md5, IocType.Md5, lower, label, source);

        if (lower.Contains('/')) return AddCidr(lower, label, source);

        // Strict address parsing BEFORE the domain test, and strict on purpose: the BCL
        // happily reads "12345" as 0.0.48.57 and "010.0.0.1" as octal-ish, so an operator
        // typo would become a silently wrong indicator. Reject instead of guessing.
        if (TryParseAddressStrict(lower, out var addr))
        {
            string norm = new IPAddress(addr.GetAddressBytes()).ToString().ToLowerInvariant();
            return Store(_addresses, IocType.IpAddress, norm, label, source);
        }

        string domain = NormalizeDomain(lower);
        if (domain.Length > 0 && IsDomain(domain))
            return Store(_domains, IocType.Domain, domain, label, source);

        return false;
    }

    private bool AddUrlFragment(string fragment, string label, string source)
    {
        if (!_urlSeen.Add(fragment)) return true;   // duplicate: already covered
        var hit = new IocHit(IocType.UrlFragment, fragment, label, source);
        _urlFragments.Add(new KeyValuePair<string, IocHit>(fragment, hit));
        _all.Add(hit);
        return true;
    }

    private bool AddCidr(string cidr, string label, string source)
    {
        if (!TryParseCidr(cidr, out byte[] network, out int prefix, out bool isV6, out string canonical))
            return false;

        if (_rangesByCidr.ContainsKey(canonical)) return true;   // duplicate

        var hit = new IocHit(IocType.IpRange, canonical, label, source);
        _rangesByCidr[canonical] = hit;

        var table = isV6 ? _v6 : _v4;
        if (!table.TryGetValue(prefix, out var inner))
            table[prefix] = inner = new Dictionary<string, IocHit>(StringComparer.Ordinal);

        string key = Convert.ToHexString(network);
        if (!inner.ContainsKey(key)) inner[key] = hit;

        _all.Add(hit);
        return true;
    }

    private bool Store(Dictionary<string, IocHit> bucket, IocType type, string key, string label, string source)
    {
        if (bucket.ContainsKey(key)) return true;   // first definition wins
        var hit = new IocHit(type, key, label, source);
        bucket[key] = hit;
        _all.Add(hit);
        return true;
    }

    // Re-insert an already-normalised hit (used only by Merge, where the indicator text
    // came out of another feed and is therefore canonical already).
    private void AddHit(IocHit h)
    {
        switch (h.Type)
        {
            case IocType.Sha256: StoreExisting(_sha256, h); break;
            case IocType.Md5: StoreExisting(_md5, h); break;
            case IocType.Domain: StoreExisting(_domains, h); break;
            case IocType.IpAddress: StoreExisting(_addresses, h); break;
            case IocType.IpRange: AddCidr(h.Indicator, h.Label, h.Source); break;
            case IocType.UrlFragment: AddUrlFragment(h.Indicator, h.Label, h.Source); break;
        }
    }

    private void StoreExisting(Dictionary<string, IocHit> bucket, IocHit h)
    {
        if (bucket.ContainsKey(h.Indicator)) return;
        bucket[h.Indicator] = h;
        _all.Add(h);
    }

    // ---- helpers -----------------------------------------------------------------

    private static bool IsHex(string s)
    {
        if (s.Length == 0) return false;
        foreach (char c in s)
        {
            bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    private static bool IsDomain(string candidate)
    {
        try { return DomainPattern.IsMatch(candidate); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    /// <summary>
    /// Lowercase, drop a trailing root dot, and drop a leading <c>*.</c> wildcard.
    /// Wildcards collapse to the parent because parent matching already covers every
    /// subdomain, which keeps one code path instead of two.
    /// </summary>
    private static string NormalizeDomain(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return "";
        string d = domain.Trim().ToLowerInvariant();
        if (d.StartsWith("*.", StringComparison.Ordinal)) d = d[2..];
        d = d.TrimEnd('.');
        return d;
    }

    /// <summary>
    /// Strict literal-address parse for feed input. IPv6 must contain a colon; IPv4 must
    /// be four decimal octets with no leading zeros (a leading zero is octal in some
    /// parsers and decimal in others, so it is ambiguous and refused).
    /// </summary>
    private static bool TryParseAddressStrict(string s, out IPAddress addr)
    {
        addr = IPAddress.None;
        if (s.Length == 0) return false;

        if (s.Contains(':'))
        {
            if (!IPAddress.TryParse(s, out IPAddress? v6)) return false;
            if (v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            addr = v6;
            return true;
        }

        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        var octets = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            string p = parts[i];
            if (p.Length is < 1 or > 3) return false;
            if (p.Length > 1 && p[0] == '0') return false;                 // ambiguous leading zero
            foreach (char c in p) if (c < '0' || c > '9') return false;
            if (!int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out int v)) return false;
            if (v > 255) return false;
            octets[i] = (byte)v;
        }
        addr = new IPAddress(octets);
        return true;
    }

    /// <summary>
    /// Parse <c>network/prefix</c> for either family and return the MASKED network so
    /// that <c>10.1.2.3/8</c> and <c>10.0.0.0/8</c> become the same stored block.
    /// </summary>
    private static bool TryParseCidr(string s, out byte[] network, out int prefix, out bool isV6, out string canonical)
    {
        network = Array.Empty<byte>();
        prefix = 0;
        isV6 = false;
        canonical = "";

        int slash = s.IndexOf('/');
        if (slash <= 0 || slash == s.Length - 1) return false;

        string host = s[..slash].Trim();
        string len = s[(slash + 1)..].Trim();

        if (!TryParseAddressStrict(host, out var addr)) return false;
        if (!int.TryParse(len, NumberStyles.None, CultureInfo.InvariantCulture, out prefix)) return false;

        isV6 = addr.AddressFamily == AddressFamily.InterNetworkV6;
        int max = isV6 ? 128 : 32;
        if (prefix < 0 || prefix > max) return false;

        network = MaskBytes(addr.GetAddressBytes(), prefix);
        canonical = new IPAddress(network).ToString().ToLowerInvariant() + "/" +
                    prefix.ToString(CultureInfo.InvariantCulture);
        return true;
    }

    /// <summary>Zero every bit past <paramref name="prefixBits"/>, byte by byte.</summary>
    private static byte[] MaskBytes(byte[] addr, int prefixBits)
    {
        var masked = new byte[addr.Length];
        int whole = prefixBits / 8;
        int rem = prefixBits % 8;
        for (int i = 0; i < whole && i < masked.Length; i++) masked[i] = addr[i];
        if (rem != 0 && whole < masked.Length)
            masked[whole] = (byte)(addr[whole] & (0xFF << (8 - rem)));
        return masked;
    }

    private static string Clip(string s) => s.Length <= 80 ? s : s[..80] + "...";

    private sealed class DescendingInt : IComparer<int>
    {
        public static readonly DescendingInt Instance = new();
        public int Compare(int x, int y) => y.CompareTo(x);
    }
}
