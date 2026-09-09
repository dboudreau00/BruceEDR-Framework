using System.Diagnostics;
using System.Runtime.InteropServices;
using BruceEDR.Detection;
using static BruceEDR.Native.NativeMethods;

namespace BruceEDR.Memory;

/// <summary>
/// Builtin point-in-time scanner: walks committed, readable memory and matches IOC
/// strings via PatternMatcher (ASCII + UTF-16). Bounded by time / per-region /
/// total-bytes budgets. Evadable by packing/encryption, so it is one signal among
/// many. For deeper coverage select the YARA engine in config.
/// </summary>
public sealed class MemoryScanner : IMemoryScanner
{
    private const int ChunkSize = 1 << 20;
    private const int Overlap = 64;
    private const long MaxRegionBytes = 64L * 1024 * 1024;
    private const long MaxTotalBytes = 256L * 1024 * 1024;
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(2);

    private readonly PatternMatcher _matcher;

    public MemoryScanner(IEnumerable<string> stringIocs) => _matcher = new PatternMatcher(stringIocs);

    public IReadOnlyList<string> Scan(int pid)
    {
        if (_matcher.LabelCount == 0) return Array.Empty<string>();

        var hits = new HashSet<string>();
        IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (h == IntPtr.Zero) return Array.Empty<string>();

        var sw = Stopwatch.StartNew();
        long budget = MaxTotalBytes;

        try
        {
            IntPtr addr = IntPtr.Zero;
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            while ((long)addr < (long)MaxUserAddress)
            {
                if (sw.Elapsed > Deadline || budget <= 0) break;
                if (VirtualQueryEx(h, addr, out var mbi, mbiSize) == 0) break;

                long regionSize = (long)mbi.RegionSize;
                if (regionSize <= 0) break;

                bool committed = (mbi.State & MEM_COMMIT) != 0;
                // "Not NOACCESS and not GUARD" is not "readable": it also passed
                // PAGE_EXECUTE (no read) and reserved-but-uncommitted protections, and a
                // ReadProcessMemory on those fails and aborted the whole region. Require
                // a protection that actually grants read.
                bool readable = (mbi.Protect & PAGE_READABLE_MASK) != 0
                                && (mbi.Protect & PAGE_NOACCESS) == 0
                                && (mbi.Protect & PAGE_GUARD) == 0;

                if (committed && readable)
                {
                    long scanSize = Math.Min(Math.Min(regionSize, MaxRegionBytes), budget);
                    budget -= ScanRegion(h, mbi.BaseAddress, scanSize, hits, sw);
                }

                long next = (long)mbi.BaseAddress + regionSize;
                if (next <= (long)addr) break;
                addr = new IntPtr(next);

                if (hits.Count == _matcher.LabelCount) break;
            }
        }
        catch { /* defensive */ }
        finally { CloseHandle(h); }

        return hits.Count == 0 ? Array.Empty<string>() : hits.ToArray();
    }

    private long ScanRegion(IntPtr h, IntPtr baseAddr, long size, HashSet<string> hits, Stopwatch sw)
    {
        long offset = 0;
        long consumed = 0;
        byte[] tail = Array.Empty<byte>();

        while (offset < size)
        {
            if (sw.Elapsed > Deadline) break;

            int want = (int)Math.Min(ChunkSize, size - offset);
            var buf = new byte[want];

            if (!ReadProcessMemory(h, new IntPtr((long)baseAddr + offset), buf, want, out var read)
                || (long)read == 0)
                break;

            int got = (int)read;
            consumed += got;

            // Prepend the previous chunk's tail so needles spanning the boundary match.
            byte[] window;
            int windowLen;
            if (tail.Length > 0)
            {
                window = new byte[tail.Length + got];
                Buffer.BlockCopy(tail, 0, window, 0, tail.Length);
                Buffer.BlockCopy(buf, 0, window, tail.Length, got);
                windowLen = window.Length;
            }
            else
            {
                window = buf;
                windowLen = got;
            }

            _matcher.FindInto(window, windowLen, hits);

            int keep = Math.Min(Overlap, got);
            tail = buf[(got - keep)..got];
            offset += got;
        }

        return consumed;
    }
}
