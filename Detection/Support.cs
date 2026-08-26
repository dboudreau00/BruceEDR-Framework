using System.Net;

namespace BruceEDR.Detection;

/// <summary>Pluggable memory-scan backend (builtin substring or YARA).</summary>
public interface IMemoryScanner
{
    IReadOnlyList<string> Scan(int pid);
}

internal static class NetworkUtil
{
    /// <summary>True if the address is a routable, non-private IPv4/IPv6 destination.</summary>
    public static bool IsRoutableRemote(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip, out var addr)) return false;
        if (IPAddress.IsLoopback(addr)) return false;           // 127/8 (IPv4) or ::1 (IPv6)
        var b = addr.GetAddressBytes();
        if (b.Length != 4)
        {
            // IPv6: private/non-routable ranges are NOT external. Loopback (::1) is
            // already handled above; also exclude link-local (fe80::/10), the
            // deprecated site-local (fec0::/10) and unique-local (fc00::/7).
            if (addr.IsIPv6LinkLocal || addr.IsIPv6SiteLocal) return false;
            if ((b[0] & 0xFE) == 0xFC) return false;            // fc00::/7 unique-local
            return true;
        }
        if (b[0] == 127) return false;                          // loopback
        if (b[0] == 10) return false;                           // 10/8
        if (b[0] == 192 && b[1] == 168) return false;           // 192.168/16
        if (b[0] == 172 && b[1] is >= 16 and <= 31) return false; // 172.16/12
        if (b[0] == 169 && b[1] == 254) return false;           // link-local
        return true;
    }
}
