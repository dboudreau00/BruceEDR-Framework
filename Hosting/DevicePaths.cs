using BruceEDR.Driver;

namespace BruceEDR.Hosting;

/// <summary>
/// Turns the kernel's device paths (<c>\Device\HarddiskVolume3\...</c>) into drive-letter paths for the
/// activity views. The drive map is read once and again every few minutes, since a USB drive or a mounted
/// image comes and goes; a path already in drive-letter form is returned untouched without a lookup.
/// </summary>
internal sealed class DevicePaths
{
    private static readonly TimeSpan Refresh = TimeSpan.FromMinutes(5);
    private readonly object _gate = new();
    private DosDeviceMap _map = DosDeviceMap.Current();
    private DateTime _loadedUtc = DateTime.UtcNow;

    public string ToDos(string path)
    {
        if (path.Length < 9 || path[0] != '\\' || !path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase)) return path;
        DosDeviceMap map;
        lock (_gate)
        {
            if (DateTime.UtcNow - _loadedUtc > Refresh)
            {
                try { _map = DosDeviceMap.Current(); } catch { /* keep the old map */ }
                _loadedUtc = DateTime.UtcNow;
            }
            map = _map;
        }
        return map.ToDos(path);
    }
}
