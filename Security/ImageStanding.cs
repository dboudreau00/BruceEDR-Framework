using System.Collections.Concurrent;
using BruceEDR.Driver;

namespace BruceEDR.Security;

/// <summary>
/// What can be said about a process's image without taking its name on trust: whether a valid
/// Authenticode signature covers the file and who it names (any publisher, unlike the allowlist),
/// whether only SYSTEM, Administrators or TrustedInstaller could have put the file where it is, and
/// whether Windows runs the process protected (PPL), which only Windows and signed security software
/// can be.
///
/// It is not a discount. A handful of rules ask it one question, <see cref="Installed"/>: is this
/// software an administrator installed and a publisher signed? That is what antivirus, network
/// monitors, overlays and accessibility tools are, and opening every other process with full rights
/// is their job. Malware can be signed too, with a stolen certificate, but it then also needs an
/// administrator to have put it in Program Files, by which point it has the machine anyway.
/// </summary>
public sealed record ImageStanding(bool Signed, string Publisher, bool AdminOnly, bool Protected, string ImagePath = "")
{
    public static readonly ImageStanding Unknown = new(false, "", false, false);

    /// <summary>Signed by a publisher and installed where only administrators can write, or run protected.</summary>
    public bool Installed => Protected || (Signed && AdminOnly);

    /// <summary>One line for the analyst: who signed the image, or that nobody did.</summary>
    public string Describe() => Protected && !Signed ? "protected process"
        : Signed ? "signed by " + Publisher
        : "unsigned";

    private static readonly ConcurrentDictionary<string, (string? Publisher, bool AdminOnly, long Tick)> Cache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly long CacheTtlMs = (long)TimeSpan.FromMinutes(10).TotalMilliseconds;
    private const int CacheLimit = 1024;

    /// <summary>
    /// The standing of the process running as <paramref name="pid"/>. Pass pid 0 for a process that has
    /// exited: its pid may belong to something else by now, so only <paramref name="knownImagePath"/>
    /// (the path its own start and image-load events gave) is judged, and it cannot count as protected.
    /// </summary>
    public static ImageStanding Of(int pid, string? knownImagePath)
    {
        try
        {
            string? path = null;
            bool isProtected = false;
            if (pid > 4)
            {
                var live = Response.ContainmentGuard.Describe(pid);
                path = live?.ImagePath;
                isProtected = live?.Protected == true;
            }
            if (string.IsNullOrEmpty(path) && !string.IsNullOrEmpty(knownImagePath) && Path.IsPathFullyQualified(knownImagePath))
                path = knownImagePath;
            if (string.IsNullOrEmpty(path)) return isProtected ? new ImageStanding(false, "", false, true) : Unknown;

            var (publisher, adminOnly) = FileStanding(path);
            return new ImageStanding(publisher is not null, publisher ?? "", adminOnly, isProtected, path);
        }
        catch { return Unknown; }
    }

    private static (string? Publisher, bool AdminOnly) FileStanding(string path)
    {
        long now = Environment.TickCount64;
        if (Cache.TryGetValue(path, out var hit) && now - hit.Tick < CacheTtlMs) return (hit.Publisher, hit.AdminOnly);
        string? publisher = AuthenticodeVerifier.PublisherOf(path);
        bool adminOnly = KernelPolicy.WriteRisk(path) is null;
        if (Cache.Count >= CacheLimit) Cache.Clear();
        Cache[path] = (publisher, adminOnly, now);
        return (publisher, adminOnly);
    }
}
