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
/// Which regions of another process are worth scanning for strings. The scan looks for what an
/// attacker put in memory, so it leaves out what Windows put there: an image-backed page that
/// has not been written is the file on disk, and its strings (the export table of user32.dll
/// names SetWindowsHookEx, GetAsyncKeyState and keybd_event in every process that has a window)
/// say nothing about the process. Scanning them put +40 on every ordinary process once anything
/// else had scored it.
/// </summary>
internal static class ScanRegions
{
    private const uint Written = PAGE_READWRITE | PAGE_EXECUTE_READWRITE;

    /// <summary>
    /// Committed, readable, and not an unmodified image page or a file mapped read-only. Private
    /// memory is always scanned (where unpacked and injected code lives), and so is an image page
    /// that is now writable (copy-on-write was triggered: patched or stomped code), and a mapped
    /// section that is writable or executable (section-mapping injection).
    ///
    /// HONEST LIMIT: protection is a proxy for "modified". A payload written into an image-backed
    /// page whose protection was then set back to read-only or execute-read is not scanned.
    /// QueryWorkingSetEx tells private copies from shared pages exactly and would close this.
    /// </summary>
    public static bool ShouldScan(uint state, uint protect, uint type)
    {
        if ((state & MEM_COMMIT) == 0) return false;
        // "Not NOACCESS and not GUARD" is not "readable": it also passed PAGE_EXECUTE (no read)
        // and reserved-but-uncommitted protections, and a ReadProcessMemory on those fails and
        // aborted the whole region. Require a protection that actually grants read.
        if ((protect & PAGE_READABLE_MASK) == 0 || (protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) return false;
        if (type == MEM_IMAGE) return (protect & Written) != 0;
        if (type == MEM_MAPPED) return (protect & (PAGE_READABLE_MASK & ~PAGE_READONLY)) != 0;
        return true;
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

                if (ScanRegions.ShouldScan(mbi.State, mbi.Protect, mbi.Type))
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
