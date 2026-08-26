using System.Text;
using static BruceEDR.Native.NativeMethods;

namespace BruceEDR.Memory;

/// <summary>
/// Pure, testable substring matcher for the builtin scanner. Matches a set of IOC
/// strings in both ASCII and UTF-16, case-insensitively, against a raw byte buffer.
/// </summary>
internal sealed class PatternMatcher
{
    private readonly string[] _labels;
    private readonly byte[][] _ascii;
    private readonly byte[][] _wide;

    public int LabelCount => _labels.Length;

    public PatternMatcher(IEnumerable<string> iocs)
    {
        _labels = iocs.Select(s => s.ToLowerInvariant()).ToArray();
        _ascii = _labels.Select(Encoding.ASCII.GetBytes).ToArray();
        _wide = _labels.Select(Encoding.Unicode.GetBytes).ToArray();
    }

    /// <summary>Adds any label found in buffer[0..length) to <paramref name="hits"/>.</summary>
    public void FindInto(byte[] buffer, int length, HashSet<string> hits)
    {
        if (length <= 0) return;
        var work = new byte[length];
        Buffer.BlockCopy(buffer, 0, work, 0, length);
        LowerAsciiInPlace(work);

        for (int i = 0; i < _labels.Length; i++)
        {
            if (hits.Contains(_labels[i])) continue;
            if (IndexOf(work, _ascii[i]) >= 0 || IndexOf(work, _wide[i]) >= 0)
                hits.Add(_labels[i]);
        }
    }

    public IReadOnlyList<string> FindAll(byte[] buffer)
    {
        var hits = new HashSet<string>();
        FindInto(buffer, buffer.Length, hits);
        return hits.ToArray();
    }

    private static void LowerAsciiInPlace(byte[] b)
    {
        for (int i = 0; i < b.Length; i++)
            if (b[i] >= (byte)'A' && b[i] <= (byte)'Z') b[i] += 32;
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length) return -1;
        int last = haystack.Length - needle.Length;
        for (int i = 0; i <= last; i++)
        {
            int j = 0;
            while (j < needle.Length && haystack[i + j] == needle[j]) j++;
            if (j == needle.Length) return i;
        }
        return -1;
    }
}

/// <summary>
/// Walks a target process's committed, readable memory and yields whole regions
/// (capped) for engines that scan contiguous buffers, e.g. YARA. Bounded by a
/// wall-clock deadline and a total-bytes budget.
/// </summary>
internal static class ProcessMemoryReader
{
    private const long MaxRegionBytes = 64L * 1024 * 1024;
    private const long MaxTotalBytes = 256L * 1024 * 1024;
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(2);

    /// <summary>Invokes onRegion(buffer, length); return false from it to stop early.</summary>
    public static void ReadRegions(int pid, Func<byte[], int, bool> onRegion)
    {
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        long budget = MaxTotalBytes;

        try
        {
            IntPtr addr = IntPtr.Zero;
            uint mbiSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            while ((long)addr < (long)MaxUserAddress)
            {
                if (sw.Elapsed > Deadline || budget <= 0) break;
                if (VirtualQueryEx(h, addr, out var mbi, mbiSize) == 0) break;

                long regionSize = (long)mbi.RegionSize;
                if (regionSize <= 0) break;

                bool committed = (mbi.State & MEM_COMMIT) != 0;
                bool readable = mbi.Protect != 0
                                && (mbi.Protect & PAGE_NOACCESS) == 0
                                && (mbi.Protect & PAGE_GUARD) == 0;

                if (committed && readable)
                {
                    int want = (int)Math.Min(Math.Min(regionSize, MaxRegionBytes), budget);
                    if (want > 0)
                    {
                        var buf = new byte[want];
                        if (ReadProcessMemory(h, mbi.BaseAddress, buf, want, out var read) && (long)read > 0)
                        {
                            int got = (int)read;
                            budget -= got;
                            if (!onRegion(buf, got)) break;
                        }
                    }
                }

                long next = (long)mbi.BaseAddress + regionSize;
                if (next <= (long)addr) break;
                addr = new IntPtr(next);
            }
        }
        catch { /* never let a scan crash the agent */ }
        finally { CloseHandle(h); }
    }
}
