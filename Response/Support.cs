namespace BruceEDR.Response;

/// <summary>Sanitises a Windows Firewall rule name to a safe character set.</summary>
internal static class FirewallRuleName
{
    public static string Sanitize(string name)
    {
        var kept = name.Where(c => char.IsLetterOrDigit(c) || c is ' ' or '.' or '_' or '-').ToArray();
        var cleaned = new string(kept).Trim();
        return cleaned.Length == 0 ? "BruceEDR Block" : cleaned;
    }
}
