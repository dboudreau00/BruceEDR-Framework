using System.Security.Cryptography;
using System.Text;
using BruceEDR.Analysis;
using BruceEDR.Intel;
using Xunit;

namespace BruceEDR.Tests;

// -----------------------------------------------------------------------------------
// Entropy
// -----------------------------------------------------------------------------------

public class AnalysisEntropyTests
{
    [Fact]
    public void Shannon_Empty_Is_Zero()
    {
        Assert.Equal(0.0, Entropy.Shannon(ReadOnlySpan<byte>.Empty));
        Assert.Equal(0.0, Entropy.Shannon(""));
        Assert.Equal(0.0, Entropy.Shannon((string?)null));
    }

    [Fact]
    public void Shannon_Single_Repeated_Byte_Is_Exactly_Zero_Not_NegativeZero()
    {
        var buf = new byte[4096];   // all zero
        double h = Entropy.Shannon(buf);
        Assert.Equal(0.0, h);
        Assert.False(double.IsNegative(h));   // -0.0 would format as "-0" in an alert
    }

    [Fact]
    public void Shannon_Uniform_Byte_Distribution_Is_Eight_Bits()
    {
        var buf = new byte[256];
        for (int i = 0; i < 256; i++) buf[i] = (byte)i;
        Assert.Equal(8.0, Entropy.Shannon(buf), 9);
    }

    [Fact]
    public void Shannon_Two_Equally_Likely_Symbols_Is_One_Bit()
    {
        var buf = new byte[100];
        for (int i = 0; i < 100; i++) buf[i] = (byte)(i % 2 == 0 ? 'a' : 'b');
        Assert.Equal(1.0, Entropy.Shannon(buf), 9);
    }

    [Fact]
    public void Shannon_String_Overload_Agrees_With_Utf8_Bytes()
    {
        const string s = "the quick brown fox jumps over the lazy dog";
        Assert.Equal(Entropy.Shannon(Encoding.UTF8.GetBytes(s)), Entropy.Shannon(s), 12);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(37)]
    [InlineData(1024)]
    [InlineData(65537)]
    public void Shannon_Never_Leaves_The_Zero_To_Eight_Range(int length)
    {
        var rng = new Random(1234 + length);
        var buf = new byte[length];
        rng.NextBytes(buf);
        double h = Entropy.Shannon(buf);
        Assert.InRange(h, 0.0, Entropy.MaxBitsPerByte);
    }

    [Theory]
    [InlineData(0.0, false)]
    [InlineData(6.5, false)]
    [InlineData(7.1999, false)]
    [InlineData(7.2, true)]
    [InlineData(7.9, true)]
    [InlineData(8.0, true)]
    public void IsLikelyEncryptedOrPacked_Uses_The_Documented_Threshold(double entropy, bool expected)
        => Assert.Equal(expected, Entropy.IsLikelyEncryptedOrPacked(entropy));

    [Fact]
    public void ChiSquare_Empty_Is_Zero() => Assert.Equal(0.0, Entropy.ChiSquare(ReadOnlySpan<byte>.Empty));

    [Fact]
    public void ChiSquare_Perfectly_Uniform_Is_Zero()
    {
        var buf = new byte[256];
        for (int i = 0; i < 256; i++) buf[i] = (byte)i;
        Assert.Equal(0.0, Entropy.ChiSquare(buf), 9);
    }

    [Fact]
    public void ChiSquare_Degenerate_Buffer_Is_Large()
    {
        // All one symbol: maximally non-uniform, so the statistic must be enormous even
        // though a naive "looks random" check on a short buffer could be fooled.
        var buf = new byte[2560];
        Assert.True(Entropy.ChiSquare(buf) > 100_000, "single-symbol buffer must be wildly non-uniform");
    }

    [Fact]
    public void ChiSquare_Catches_Ordered_Data_That_Entropy_Calls_Perfect()
    {
        // A 0..255 ramp scores a perfect 8.0 bits/byte, which is exactly why entropy on
        // its own is not enough; chi-square flags it as suspiciously uniform (0).
        var ramp = new byte[4096];
        for (int i = 0; i < ramp.Length; i++) ramp[i] = (byte)(i % 256);
        Assert.Equal(8.0, Entropy.Shannon(ramp), 9);
        Assert.Equal(0.0, Entropy.ChiSquare(ramp), 9);
    }

    [Fact]
    public void PrintableRatio_Handles_Empty_Text_Binary_And_Mixed()
    {
        Assert.Equal(0.0, Entropy.PrintableRatio(ReadOnlySpan<byte>.Empty));
        Assert.Equal(1.0, Entropy.PrintableRatio(Encoding.ASCII.GetBytes("hello\tworld\r\n")));
        Assert.Equal(0.0, Entropy.PrintableRatio(new byte[] { 0x00, 0x01, 0xFF, 0x80 }));
        Assert.Equal(0.5, Entropy.PrintableRatio(new byte[] { (byte)'A', 0x00, (byte)'B', 0x1B }), 9);
    }

    [Fact]
    public void PrintableRatio_Of_Utf16_Text_Is_About_Half_Because_It_Counts_Bytes()
    {
        var wide = Encoding.Unicode.GetBytes("ABCDEFGH");
        Assert.Equal(0.5, Entropy.PrintableRatio(wide), 9);
    }
}

// -----------------------------------------------------------------------------------
// PE builder used by the FileAnalyzer tests
// -----------------------------------------------------------------------------------

/// <summary>
/// Synthesises well-formed (and, on request, deliberately broken) PE images in memory so
/// the analyzer can be tested without shipping binary fixtures or reading real system
/// files, which would make the suite depend on the host's Windows build.
/// </summary>
internal sealed class AnalysisPeBuilder
{
    private const uint FileAlign = 0x200;
    private const uint SectAlign = 0x1000;
    private const uint HeadersSize = 0x400;
    private const int Lfanew = 0x80;

    public const uint ScnCode = 0x00000020;
    public const uint ScnInitData = 0x00000040;
    public const uint ScnUninitData = 0x00000080;
    public const uint ScnExecute = 0x20000000;
    public const uint ScnRead = 0x40000000;
    public const uint ScnWrite = 0x80000000;

    private readonly bool _is64;
    private readonly List<SecSpec> _sections = new();
    private readonly List<(string Dll, List<object> Funcs)> _imports = new();

    public uint EntryPointRva = 0x1000;
    public ushort Characteristics = 0x0102;      // EXECUTABLE_IMAGE | 32BIT_MACHINE
    public uint TimeDateStamp = 1_600_000_000;
    public uint Checksum = 0x0000ABCD;
    public ushort Subsystem = 3;                 // windows-cui
    public bool WithSignatureDirectory;
    public bool BreakImportNameRva;
    public ushort SectionCountOverride;          // 0 = write the real count

    private sealed record SecSpec(string Name, byte[] Data, uint Chars, uint VirtualSize);

    public AnalysisPeBuilder(bool is64) => _is64 = is64;

    /// <summary>File offset of the first IMAGE_SECTION_HEADER, for truncation tests.</summary>
    public static int SectionTableOffset(bool is64) => Lfanew + 4 + 20 + (is64 ? 0xF0 : 0xE0);

    public AnalysisPeBuilder AddSection(string name, byte[] data, uint chars, uint virtualSize = 0)
    {
        _sections.Add(new SecSpec(name, data, chars, virtualSize));
        return this;
    }

    public AnalysisPeBuilder AddImport(string dll, params string[] funcs)
    {
        _imports.Add((dll, funcs.Cast<object>().ToList()));
        return this;
    }

    public AnalysisPeBuilder AddOrdinalImport(string dll, params int[] ordinals)
    {
        _imports.Add((dll, ordinals.Cast<object>().ToList()));
        return this;
    }

    private readonly record struct Placed(string Name, uint Va, uint VSize, uint RawSize, uint PtrRaw, uint Chars, byte[] Data);

    public byte[] Build()
    {
        int optSize = _is64 ? 0xF0 : 0xE0;
        int coff = Lfanew + 4;
        int optional = coff + 20;
        int secBase = optional + optSize;

        var placed = new List<Placed>();
        uint va = SectAlign;
        uint rawCursor = HeadersSize;

        foreach (var s in _sections)
        {
            uint rawSize = AlignUp((uint)s.Data.Length, FileAlign);
            uint ptr = rawSize == 0 ? 0u : rawCursor;
            uint vsize = s.VirtualSize != 0 ? s.VirtualSize : (uint)s.Data.Length;
            placed.Add(new Placed(s.Name, va, vsize, rawSize, ptr, s.Chars, s.Data));
            rawCursor += rawSize;
            va = AlignUp(va + Math.Max(vsize, rawSize), SectAlign);
        }

        uint importDirRva = 0;
        if (_imports.Count > 0)
        {
            byte[] blob = BuildImportBlob(va);
            uint rawSize = AlignUp((uint)blob.Length, FileAlign);
            placed.Add(new Placed(".idata", va, (uint)blob.Length, rawSize, rawCursor, ScnInitData | ScnRead, blob));
            importDirRva = va;
            rawCursor += rawSize;
        }

        var file = new byte[Math.Max(rawCursor, HeadersSize)];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        W32(file, 0x3C, Lfanew);
        file[Lfanew] = (byte)'P';
        file[Lfanew + 1] = (byte)'E';

        W16(file, coff + 0, (ushort)(_is64 ? 0x8664 : 0x014C));
        W16(file, coff + 2, SectionCountOverride != 0 ? SectionCountOverride : (ushort)placed.Count);
        W32(file, coff + 4, TimeDateStamp);
        W16(file, coff + 16, (ushort)optSize);
        W16(file, coff + 18, Characteristics);

        W16(file, optional + 0, (ushort)(_is64 ? 0x20B : 0x10B));
        W32(file, optional + 16, EntryPointRva);
        W32(file, optional + 60, HeadersSize);
        W32(file, optional + 64, Checksum);
        W16(file, optional + 68, Subsystem);

        int numDirsOff = _is64 ? optional + 108 : optional + 92;
        int dirBase = _is64 ? optional + 112 : optional + 96;
        W32(file, numDirsOff, 16);
        if (importDirRva != 0)
        {
            W32(file, dirBase + 8, importDirRva);
            W32(file, dirBase + 12, (uint)((_imports.Count + 1) * 20));
        }
        if (WithSignatureDirectory)
        {
            W32(file, dirBase + 32, 0x9000);
            W32(file, dirBase + 36, 0x1000);
        }

        for (int i = 0; i < placed.Count; i++)
        {
            int h = secBase + i * 40;
            var p = placed[i];
            var nameBytes = Encoding.ASCII.GetBytes(p.Name);
            for (int k = 0; k < Math.Min(8, nameBytes.Length); k++) file[h + k] = nameBytes[k];
            W32(file, h + 8, p.VSize);
            W32(file, h + 12, p.Va);
            W32(file, h + 16, p.RawSize);
            W32(file, h + 20, p.PtrRaw);
            W32(file, h + 36, p.Chars);
            if (p.Data.Length > 0) Buffer.BlockCopy(p.Data, 0, file, (int)p.PtrRaw, p.Data.Length);
        }

        return file;
    }

    private byte[] BuildImportBlob(uint baseVa)
    {
        int step = _is64 ? 8 : 4;
        int n = _imports.Count;
        int descBytes = (n + 1) * 20;

        var iltOff = new int[n];
        int cursor = descBytes;
        for (int i = 0; i < n; i++)
        {
            iltOff[i] = cursor;
            cursor += (_imports[i].Funcs.Count + 1) * step;
        }

        int stringsBase = cursor;
        var strings = new List<byte>();
        var dllNameOff = new int[n];
        var funcOff = new int[n][];

        for (int i = 0; i < n; i++)
        {
            dllNameOff[i] = stringsBase + strings.Count;
            strings.AddRange(Encoding.ASCII.GetBytes(_imports[i].Dll));
            strings.Add(0);

            funcOff[i] = new int[_imports[i].Funcs.Count];
            for (int j = 0; j < _imports[i].Funcs.Count; j++)
            {
                if (_imports[i].Funcs[j] is string name)
                {
                    funcOff[i][j] = stringsBase + strings.Count;
                    strings.Add(0);
                    strings.Add(0);                       // IMAGE_IMPORT_BY_NAME.Hint
                    strings.AddRange(Encoding.ASCII.GetBytes(name));
                    strings.Add(0);
                    if (strings.Count % 2 != 0) strings.Add(0);
                }
                else
                {
                    funcOff[i][j] = -1;                   // ordinal import: no name record
                }
            }
        }

        var blob = new byte[stringsBase + strings.Count];
        for (int i = 0; i < n; i++)
        {
            int d = i * 20;
            W32(blob, d + 0, (uint)(baseVa + iltOff[i]));
            W32(blob, d + 12, BreakImportNameRva && i == 0 ? 0xDEADBEEF : (uint)(baseVa + dllNameOff[i]));
            W32(blob, d + 16, (uint)(baseVa + iltOff[i]));

            for (int j = 0; j < _imports[i].Funcs.Count; j++)
            {
                int e = iltOff[i] + j * step;
                if (_imports[i].Funcs[j] is int ord)
                {
                    if (_is64) W64(blob, e, 0x8000000000000000UL | (uint)ord);
                    else W32(blob, e, 0x80000000u | (uint)ord);
                }
                else
                {
                    uint rva = (uint)(baseVa + funcOff[i][j]);
                    if (_is64) W64(blob, e, rva);
                    else W32(blob, e, rva);
                }
            }
        }

        Buffer.BlockCopy(strings.ToArray(), 0, blob, stringsBase, strings.Count);
        return blob;
    }

    private static uint AlignUp(uint v, uint a) => v == 0 ? 0u : (v + a - 1) / a * a;
    private static void W16(byte[] b, int o, ushort v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }
    private static void W32(byte[] b, int o, uint v)
    {
        b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
    }
    private static void W64(byte[] b, int o, ulong v) { W32(b, o, (uint)v); W32(b, o + 4, (uint)(v >> 32)); }

    /// <summary>Deterministic "high entropy" filler: a 0..255 ramp reaches exactly 8 bits/byte.</summary>
    public static byte[] Ramp(int length)
    {
        var buf = new byte[length];
        for (int i = 0; i < length; i++) buf[i] = (byte)(i % 256);
        return buf;
    }

    public static byte[] Fill(int length, byte value)
    {
        var buf = new byte[length];
        Array.Fill(buf, value);
        return buf;
    }
}

// -----------------------------------------------------------------------------------
// FileAnalyzer
// -----------------------------------------------------------------------------------

public class AnalysisFileAnalyzerTests : IDisposable
{
    private const string EmptySha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private const string EmptyMd5 = "d41d8cd98f00b204e9800998ecf8427e";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ps-fa-" + Guid.NewGuid().ToString("N"));

    public AnalysisFileAnalyzerTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); }
        catch { /* a temp dir left behind must never fail a test run */ }
    }

    private static AnalysisPeBuilder Benign64()
        => new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("KERNEL32.dll", "GetLastError");

    // ---- degenerate and hostile input ----

    [Fact]
    public void AnalyzeBytes_Empty_Buffer_Is_Valid_And_Not_A_Pe()
    {
        var fa = FileAnalyzer.AnalyzeBytes(Array.Empty<byte>(), "empty.bin");
        Assert.True(fa.Valid);
        Assert.Equal("", fa.Error);
        Assert.False(fa.IsPeFile);
        Assert.Equal(0, fa.SizeBytes);
        Assert.Equal(EmptySha256, fa.Sha256);
        Assert.Equal(EmptyMd5, fa.Md5);
        Assert.Equal(0.0, fa.OverallEntropy);
        Assert.Empty(fa.Sections);
        Assert.Equal("", fa.Imphash);
    }

    [Fact]
    public void AnalyzeBytes_Null_Buffer_Is_Treated_As_Empty()
    {
        var fa = FileAnalyzer.AnalyzeBytes(null, "null.bin");
        Assert.True(fa.Valid);
        Assert.Equal(EmptySha256, fa.Sha256);
    }

    [Fact]
    public void AnalyzeBytes_Plain_Text_Is_Valid_And_Not_A_Pe()
    {
        var fa = FileAnalyzer.AnalyzeBytes(Encoding.ASCII.GetBytes("#!/bin/sh\necho hi\n"), "script.sh");
        Assert.True(fa.Valid);
        Assert.False(fa.IsPeFile);
        Assert.Equal(0, fa.SuspicionScore);
    }

    [Fact]
    public void AnalyzeBytes_Mz_Only_Reports_A_Truncated_Dos_Header()
    {
        var fa = FileAnalyzer.AnalyzeBytes(Encoding.ASCII.GetBytes("MZ"), "stub.bin");
        Assert.False(fa.Valid);
        Assert.Contains("DOS header", fa.Error);
        Assert.False(fa.IsPeFile);
    }

    [Fact]
    public void AnalyzeBytes_Lfanew_Past_End_Of_File_Is_Rejected()
    {
        var buf = new byte[0x100];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        buf[0x3C] = 0xFF; buf[0x3D] = 0xFF; buf[0x3E] = 0xFF; buf[0x3F] = 0x7F;   // 0x7FFFFFFF
        var fa = FileAnalyzer.AnalyzeBytes(buf, "bad.bin");
        Assert.False(fa.Valid);
        Assert.False(fa.IsPeFile);
        Assert.Contains("outside the file", fa.Error);
    }

    [Fact]
    public void AnalyzeBytes_Negative_Looking_Lfanew_Is_Rejected_Not_Wrapped()
    {
        // 0xFFFFFFFF would become -1 under a naive int cast and index before the buffer.
        var buf = new byte[0x100];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        for (int i = 0x3C; i < 0x40; i++) buf[i] = 0xFF;
        var fa = FileAnalyzer.AnalyzeBytes(buf, "bad.bin");
        Assert.False(fa.Valid);
        Assert.Contains("out of range", fa.Error);
    }

    [Fact]
    public void AnalyzeBytes_Mz_Without_Pe_Signature_Is_Rejected()
    {
        var buf = new byte[0x100];
        buf[0] = (byte)'M'; buf[1] = (byte)'Z';
        buf[0x3C] = 0x80;
        var fa = FileAnalyzer.AnalyzeBytes(buf, "dos.exe");
        Assert.False(fa.Valid);
        Assert.False(fa.IsPeFile);
        Assert.Contains("PE signature", fa.Error);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(0x3F)]
    [InlineData(0x40)]
    [InlineData(0x83)]
    [InlineData(0x97)]
    [InlineData(0x187)]
    public void AnalyzeBytes_Never_Throws_On_A_Truncated_Valid_Image(int keepBytes)
    {
        byte[] full = Benign64().Build();
        byte[] cut = full.Take(Math.Min(keepBytes, full.Length)).ToArray();
        var fa = FileAnalyzer.AnalyzeBytes(cut, "cut.exe");
        Assert.NotNull(fa);
        Assert.True(fa.Sections.Count <= 96);
    }

    [Fact]
    public void AnalyzeBytes_Truncated_Section_Table_Is_Invalid_But_Still_Reported_As_Pe()
    {
        byte[] full = Benign64().Build();
        int secBase = AnalysisPeBuilder.SectionTableOffset(is64: true);
        byte[] cut = full.Take(secBase + 20).ToArray();
        var fa = FileAnalyzer.AnalyzeBytes(cut, "cut.exe");
        Assert.True(fa.IsPeFile);
        Assert.False(fa.Valid);
        Assert.Contains("truncated", fa.Error);
    }

    [Fact]
    public void AnalyzeBytes_Absurd_Section_Count_Is_Capped_And_Flagged()
    {
        var b = Benign64();
        b.SectionCountOverride = 65535;
        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "many.exe");
        Assert.False(fa.Valid);
        Assert.True(fa.Sections.Count <= 96, "the loader ceiling must bound how much we parse");
    }

    [Fact]
    public void AnalyzeBytes_Broken_Import_Name_Rva_Degrades_Instead_Of_Throwing()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("KERNEL32.dll", "CreateFileW");
        b.BreakImportNameRva = true;

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "brokenimports.exe");
        Assert.False(fa.Valid);
        Assert.Contains("unreadable library name", fa.Error);
        Assert.Contains("(unknown)", fa.ImportedDlls);
    }

    [Fact]
    public void AnalyzeBytes_Survives_Single_Byte_Corruption_Anywhere()
    {
        byte[] pristine = Benign64().Build();
        var rng = new Random(20260810);
        for (int i = 0; i < 400; i++)
        {
            byte[] mutated = (byte[])pristine.Clone();
            int at = rng.Next(mutated.Length);
            mutated[at] ^= (byte)(1 << rng.Next(8));

            var fa = FileAnalyzer.AnalyzeBytes(mutated, "fuzz.exe");
            Assert.NotNull(fa);
            Assert.InRange(fa.SuspicionScore, 0, 100);
            Assert.True(fa.Sections.Count <= 96);
        }
    }

    [Fact]
    public void AnalyzeBytes_Survives_Structured_Garbage()
    {
        var cases = new[]
        {
            AnalysisPeBuilder.Fill(4096, 0xFF),
            AnalysisPeBuilder.Ramp(4096),
            Encoding.ASCII.GetBytes("MZ" + new string('\0', 60) + "PE\0\0"),
            Encoding.ASCII.GetBytes("MZPE\0\0"),
            new byte[] { (byte)'M', (byte)'Z' }
        };
        foreach (var c in cases)
        {
            var fa = FileAnalyzer.AnalyzeBytes(c, "garbage.bin");
            Assert.NotNull(fa);
            Assert.InRange(fa.SuspicionScore, 0, 100);
        }
    }

    // ---- well-formed images ----

    [Fact]
    public void AnalyzeBytes_Parses_A_Minimal_Pe32Plus()
    {
        var fa = FileAnalyzer.AnalyzeBytes(Benign64().Build(), @"C:\tmp\benign.exe");

        Assert.True(fa.Valid);
        Assert.Equal("", fa.Error);
        Assert.True(fa.IsPeFile);
        Assert.True(fa.Is64Bit);
        Assert.False(fa.IsDll);
        Assert.Equal("amd64", fa.Machine);
        Assert.Equal("windows-cui", fa.Subsystem);
        Assert.Equal(0x1000u, fa.EntryPointRva);
        Assert.Equal(0x0000ABCDu, fa.Checksum);
        Assert.Equal(@"C:\tmp\benign.exe", fa.Path);
        Assert.False(fa.HasDigitalSignatureDirectory);
    }

    [Fact]
    public void AnalyzeBytes_Parses_A_Minimal_Pe32()
    {
        var b = new AnalysisPeBuilder(is64: false)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("kernel32.dll", "ExitProcess");
        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "x86.exe");

        Assert.True(fa.Valid);
        Assert.True(fa.IsPeFile);
        Assert.False(fa.Is64Bit);
        Assert.Equal("i386", fa.Machine);
        Assert.Contains("kernel32.dll!ExitProcess", fa.ImportedFunctions);
    }

    [Fact]
    public void AnalyzeBytes_Detects_A_Dll_And_A_Signature_Directory()
    {
        var b = Benign64();
        b.Characteristics = 0x2102;          // + IMAGE_FILE_DLL
        b.Subsystem = 2;                     // windows-gui
        b.WithSignatureDirectory = true;
        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "thing.dll");

        Assert.True(fa.IsDll);
        Assert.Equal("windows-gui", fa.Subsystem);
        Assert.True(fa.HasDigitalSignatureDirectory);
    }

    [Fact]
    public void AnalyzeBytes_Reads_The_Coff_Timestamp_And_Treats_Zero_As_Absent()
    {
        var withStamp = Benign64();
        withStamp.TimeDateStamp = 1_600_000_000;
        var a = FileAnalyzer.AnalyzeBytes(withStamp.Build(), "a.exe");
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_600_000_000).UtcDateTime, a.TimestampUtc);

        var noStamp = Benign64();
        noStamp.TimeDateStamp = 0;
        Assert.Null(FileAnalyzer.AnalyzeBytes(noStamp.Build(), "b.exe").TimestampUtc);
    }

    [Fact]
    public void AnalyzeBytes_Reports_Section_Geometry_And_Permissions()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddSection(".data", AnalysisPeBuilder.Fill(0x200, 0x41),
                AnalysisPeBuilder.ScnInitData | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnWrite);

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "two.exe");
        Assert.True(fa.Valid);
        Assert.Equal(2, fa.Sections.Count);

        var text = fa.Sections[0];
        Assert.Equal(".text", text.Name);
        Assert.Equal(0x1000u, text.VirtualAddress);
        Assert.Equal(0x200u, text.RawSize);
        Assert.True(text.IsExecutable);
        Assert.False(text.IsWritable);
        Assert.Equal(0.0, text.Entropy);          // 0x200 identical bytes

        var data = fa.Sections[1];
        Assert.Equal(".data", data.Name);
        Assert.False(data.IsExecutable);
        Assert.True(data.IsWritable);
    }

    [Fact]
    public void AnalyzeBytes_Computes_Section_Entropy_From_On_Disk_Bytes()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".rsrc", AnalysisPeBuilder.Ramp(0x1000),
                AnalysisPeBuilder.ScnInitData | AnalysisPeBuilder.ScnRead);
        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "res.exe");
        Assert.Equal(8.0, fa.Sections[0].Entropy, 6);
    }

    // ---- imports and imphash ----

    [Fact]
    public void AnalyzeBytes_Parses_Named_And_Ordinal_Imports()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("KERNEL32.dll", "VirtualAllocEx", "WriteProcessMemory")
            .AddOrdinalImport("WS2_32.dll", 23);

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "inject.exe");

        Assert.True(fa.Valid);
        Assert.Equal(new[] { "kernel32.dll", "ws2_32.dll" }, fa.ImportedDlls);
        Assert.Equal(
            new[] { "kernel32.dll!VirtualAllocEx", "kernel32.dll!WriteProcessMemory", "ws2_32.dll!#23" },
            fa.ImportedFunctions);
    }

    [Fact]
    public void Imphash_Follows_The_Documented_Pefile_Construction()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("KERNEL32.dll", "VirtualAllocEx", "WriteProcessMemory")
            .AddOrdinalImport("WS2_32.dll", 23);

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "inject.exe");

        const string expectedInput = "kernel32.virtualallocex,kernel32.writeprocessmemory,ws2_32.ord23";
        string expected = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(expectedInput))).ToLowerInvariant();
        Assert.Equal(expected, fa.Imphash);
        Assert.Equal(32, fa.Imphash.Length);
    }

    [Theory]
    [InlineData("advapi32.dll", "advapi32.regsetvalueexw")]
    [InlineData("mscomctl.ocx", "mscomctl.regsetvalueexw")]
    [InlineData("wdfilter.sys", "wdfilter.regsetvalueexw")]
    [InlineData("payload.exe", "payload.exe.regsetvalueexw")]   // .exe is NOT stripped by pefile
    [InlineData("nodots", "nodots.regsetvalueexw")]
    public void Imphash_Strips_Only_Dll_Ocx_And_Sys_Extensions(string dll, string expectedPart)
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport(dll, "RegSetValueExW");

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "x.exe");
        string expected = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(expectedPart))).ToLowerInvariant();
        Assert.Equal(expected, fa.Imphash);
    }

    [Fact]
    public void Imphash_Is_Empty_When_There_Are_No_Imports()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead);
        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "noimports.exe");
        Assert.True(fa.Valid);
        Assert.Equal("", fa.Imphash);
        Assert.Empty(fa.ImportedDlls);
    }

    [Fact]
    public void Imphash_Is_Case_Insensitive_On_Both_Library_And_Function()
    {
        byte[] a = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90), AnalysisPeBuilder.ScnRead)
            .AddImport("KERNEL32.DLL", "CreateFileW").Build();
        byte[] b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90), AnalysisPeBuilder.ScnRead)
            .AddImport("kernel32.dll", "createfilew").Build();

        Assert.Equal(FileAnalyzer.AnalyzeBytes(a, "a").Imphash, FileAnalyzer.AnalyzeBytes(b, "b").Imphash);
    }

    // ---- indicators and scoring ----

    [Fact]
    public void SuspiciousImports_Lists_Injection_Apis_And_Ignores_Ubiquitous_Ones()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead)
            .AddImport("kernel32.dll", "LoadLibraryA", "GetProcAddress", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
            .AddImport("crypt32.dll", "CryptUnprotectData");

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "rat.exe");

        Assert.Contains("VirtualAllocEx", fa.SuspiciousImports);
        Assert.Contains("WriteProcessMemory", fa.SuspiciousImports);
        Assert.Contains("CreateRemoteThread", fa.SuspiciousImports);
        Assert.Contains("CryptUnprotectData", fa.SuspiciousImports);
        Assert.DoesNotContain("LoadLibraryA", fa.SuspiciousImports);
        Assert.DoesNotContain("GetProcAddress", fa.SuspiciousImports);
        Assert.True(fa.SuspicionScore >= 24);
    }

    [Fact]
    public void PackerIndicators_Flags_A_Upx_Shaped_Image()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection("UPX0", Array.Empty<byte>(),
                AnalysisPeBuilder.ScnUninitData | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnWrite | AnalysisPeBuilder.ScnExecute,
                virtualSize: 0x10000)
            .AddSection("UPX1", AnalysisPeBuilder.Ramp(0x1000),
                AnalysisPeBuilder.ScnInitData | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnWrite | AnalysisPeBuilder.ScnExecute);

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "packed.exe");

        Assert.Contains(fa.PackerIndicators, s => s.Contains("packer section name 'UPX0'"));
        Assert.Contains(fa.PackerIndicators, s => s.Contains("packer section name 'UPX1'"));
        Assert.Contains(fa.PackerIndicators, s => s.Contains("no file data"));
        Assert.Contains(fa.PackerIndicators, s => s.Contains("writable and executable"));
        Assert.Contains(fa.PackerIndicators, s => s.Contains("packed or encrypted code"));
        Assert.InRange(fa.SuspicionScore, 45, 100);
    }

    [Fact]
    public void PackerIndicators_Flags_An_Entry_Point_Outside_Every_Section()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".text", AnalysisPeBuilder.Fill(0x200, 0x90),
                AnalysisPeBuilder.ScnCode | AnalysisPeBuilder.ScnExecute | AnalysisPeBuilder.ScnRead);
        b.EntryPointRva = 0x900000;

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "oddentry.exe");
        Assert.Contains(fa.PackerIndicators, s => s.Contains("outside every section"));
    }

    [Fact]
    public void PackerIndicators_Flags_Few_Imports_Combined_With_High_Entropy()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection(".data", AnalysisPeBuilder.Ramp(0x40000),
                AnalysisPeBuilder.ScnInitData | AnalysisPeBuilder.ScnRead)
            .AddImport("kernel32.dll", "GetLastError");

        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "stub.exe");

        Assert.True(fa.OverallEntropy > 7.2, $"expected a high-entropy file, got {fa.OverallEntropy}");
        Assert.Contains(fa.PackerIndicators, s => s.Contains("imported function"));
    }

    [Fact]
    public void A_Plain_Benign_Image_Scores_Zero()
    {
        var fa = FileAnalyzer.AnalyzeBytes(Benign64().Build(), "benign.exe");
        Assert.True(fa.Valid);
        Assert.Empty(fa.PackerIndicators);
        Assert.Empty(fa.SuspiciousImports);
        Assert.Equal(0, fa.SuspicionScore);
    }

    [Fact]
    public void A_Packed_Image_Scores_Higher_Than_A_Benign_One()
    {
        var packed = new AnalysisPeBuilder(is64: true)
            .AddSection("UPX1", AnalysisPeBuilder.Ramp(0x2000),
                AnalysisPeBuilder.ScnInitData | AnalysisPeBuilder.ScnRead | AnalysisPeBuilder.ScnWrite | AnalysisPeBuilder.ScnExecute)
            .Build();

        int benign = FileAnalyzer.AnalyzeBytes(Benign64().Build(), "b.exe").SuspicionScore;
        int hot = FileAnalyzer.AnalyzeBytes(packed, "p.exe").SuspicionScore;

        Assert.True(hot > benign, $"packed {hot} should outrank benign {benign}");
        Assert.InRange(hot, 0, 100);
    }

    [Fact]
    public void Section_Names_Are_Sanitised_So_They_Cannot_Inject_Control_Characters()
    {
        var b = new AnalysisPeBuilder(is64: true)
            .AddSection("\u001b[31mX", AnalysisPeBuilder.Fill(0x200, 1), AnalysisPeBuilder.ScnRead);
        var fa = FileAnalyzer.AnalyzeBytes(b.Build(), "ansi.exe");
        Assert.DoesNotContain('\u001b', fa.Sections[0].Name);
        Assert.StartsWith("?", fa.Sections[0].Name);
    }

    // ---- file-backed paths ----

    [Fact]
    public void Analyze_Missing_File_Returns_An_Error_Instead_Of_Throwing()
    {
        var fa = FileAnalyzer.Analyze(Path.Combine(_dir, "does-not-exist.exe"));
        Assert.False(fa.Valid);
        Assert.NotEqual("", fa.Error);
    }

    [Fact]
    public void Analyze_Empty_Path_Is_Rejected()
    {
        var fa = FileAnalyzer.Analyze("   ");
        Assert.False(fa.Valid);
        Assert.Equal("empty path", fa.Error);
    }

    [Fact]
    public void Analyze_Reads_A_Real_File_And_Agrees_With_Sha256File()
    {
        string path = Path.Combine(_dir, "sample.exe");
        byte[] bytes = Benign64().Build();
        File.WriteAllBytes(path, bytes);

        var fa = FileAnalyzer.Analyze(path);
        Assert.True(fa.Valid);
        Assert.True(fa.IsPeFile);
        Assert.Equal(bytes.Length, fa.SizeBytes);
        Assert.Equal(FileAnalyzer.AnalyzeBytes(bytes, path).Sha256, fa.Sha256);
        Assert.Equal(FileAnalyzer.Sha256File(path), fa.Sha256);
        Assert.Equal(fa.Sha256.ToLowerInvariant(), fa.Sha256);
    }

    [Fact]
    public void Analyze_Above_The_Size_Limit_Still_Hashes_But_Does_Not_Parse()
    {
        string path = Path.Combine(_dir, "big.bin");
        File.WriteAllBytes(path, AnalysisPeBuilder.Ramp(4096));

        var fa = FileAnalyzer.Analyze(path, maxBytes: 1024);
        Assert.False(fa.Valid);
        Assert.Contains("analysis limit", fa.Error);
        Assert.Equal(4096, fa.SizeBytes);
        Assert.Equal(FileAnalyzer.Sha256File(path), fa.Sha256);
        Assert.False(fa.IsPeFile);
        Assert.Empty(fa.Sections);
    }

    [Fact]
    public void Sha256File_Of_An_Empty_File_Is_The_Known_Vector()
    {
        string path = Path.Combine(_dir, "zero.bin");
        File.WriteAllBytes(path, Array.Empty<byte>());
        Assert.Equal(EmptySha256, FileAnalyzer.Sha256File(path));
    }
}

// -----------------------------------------------------------------------------------
// IocFeed
// -----------------------------------------------------------------------------------

public class IntelIocFeedTests : IDisposable
{
    private const string Sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    private const string Md5 = "5d41402abc4b2a76b9719d911017c592";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ps-ioc-" + Guid.NewGuid().ToString("N"));

    public IntelIocFeedTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); }
        catch { }
    }

    private static IocFeed Feed(params string[] lines) => IocFeed.Parse(lines, "unit");

    [Fact]
    public void Empty_Feed_Matches_Nothing()
    {
        var f = new IocFeed();
        Assert.Equal(0, f.Count);
        Assert.Null(f.MatchHash(Sha));
        Assert.Null(f.MatchDomain("evil.com"));
        Assert.Null(f.MatchIp("1.2.3.4"));
        Assert.Null(f.MatchUrl("http://x/"));
    }

    [Fact]
    public void Parse_Auto_Detects_Every_Supported_Type()
    {
        var f = Feed(
            Sha,
            Md5,
            "evil.example.com",
            "198.51.100.7",
            "2001:db8::1",
            "203.0.113.0/24",
            "url:/gate.php?id=");

        Assert.Equal(7, f.Count);
        Assert.Equal(IocType.Sha256, f.MatchHash(Sha)!.Type);
        Assert.Equal(IocType.Md5, f.MatchHash(Md5)!.Type);
        Assert.Equal(IocType.Domain, f.MatchDomain("evil.example.com")!.Type);
        Assert.Equal(IocType.IpAddress, f.MatchIp("198.51.100.7")!.Type);
        Assert.Equal(IocType.IpAddress, f.MatchIp("2001:db8::1")!.Type);
        Assert.Equal(IocType.IpRange, f.MatchIp("203.0.113.99")!.Type);
        Assert.Equal(IocType.UrlFragment, f.MatchUrl("https://host/gate.php?id=7")!.Type);
    }

    [Fact]
    public void Comments_Blank_Lines_And_Whitespace_Are_Ignored()
    {
        var f = Feed("", "   ", "# a comment", "\t# indented comment", "  evil.com  ");
        Assert.Equal(1, f.Count);
        Assert.NotNull(f.MatchDomain("evil.com"));
    }

    [Fact]
    public void Labels_And_Source_Are_Carried_Through()
    {
        var f = IocFeed.Parse(new[] { "evil.com ; APT-99 staging domain" }, "apt99.txt");
        var hit = f.MatchDomain("evil.com");
        Assert.NotNull(hit);
        Assert.Equal("APT-99 staging domain", hit!.Label);
        Assert.Equal("apt99.txt", hit.Source);
        Assert.Equal("evil.com", hit.Indicator);
    }

    [Fact]
    public void MatchHash_Is_Case_Insensitive_And_Length_Aware()
    {
        var f = Feed(Sha.ToUpperInvariant(), Md5.ToUpperInvariant());
        Assert.NotNull(f.MatchHash(Sha));
        Assert.NotNull(f.MatchHash(Sha.ToUpperInvariant()));
        Assert.NotNull(f.MatchHash("  " + Md5 + "  "));
        Assert.Null(f.MatchHash("deadbeef"));            // wrong length
        Assert.Null(f.MatchHash("zz" + Sha[2..]));       // not hex
        Assert.Null(f.MatchHash(""));
        Assert.Null(f.MatchHash(null));
    }

    [Fact]
    public void MatchDomain_Matches_The_Name_And_Every_Parent()
    {
        var f = Feed("evil.com");
        Assert.NotNull(f.MatchDomain("evil.com"));
        Assert.NotNull(f.MatchDomain("a.evil.com"));
        Assert.NotNull(f.MatchDomain("a.b.c.evil.com"));
        Assert.NotNull(f.MatchDomain("A.B.EVIL.COM"));
        Assert.NotNull(f.MatchDomain("a.evil.com."));    // trailing root dot
    }

    [Fact]
    public void MatchDomain_Does_Not_Match_A_Lookalike_Suffix()
    {
        // The bug a naive EndsWith would introduce: "notevil.com" is a different company.
        var f = Feed("evil.com");
        Assert.Null(f.MatchDomain("notevil.com"));
        Assert.Null(f.MatchDomain("xevil.com"));
        Assert.Null(f.MatchDomain("evil.com.attacker.net"));
        Assert.Null(f.MatchDomain("com"));
    }

    [Fact]
    public void Wildcard_Entries_Collapse_To_The_Parent_Domain()
    {
        var f = Feed("*.evil.com");
        Assert.Equal("evil.com", f.All[0].Indicator);
        Assert.NotNull(f.MatchDomain("evil.com"));
        Assert.NotNull(f.MatchDomain("deep.sub.evil.com"));
    }

    [Fact]
    public void MatchIp_Handles_Exact_V4_And_V6_Including_Odd_Spellings()
    {
        var f = Feed("198.51.100.7", "2001:0db8:0000:0000:0000:0000:0000:0001");
        Assert.NotNull(f.MatchIp("198.51.100.7"));
        Assert.NotNull(f.MatchIp(" 198.51.100.7 "));
        Assert.NotNull(f.MatchIp("2001:db8::1"));          // canonicalised on both sides
        Assert.NotNull(f.MatchIp("2001:DB8:0:0:0:0:0:1"));
        Assert.Null(f.MatchIp("198.51.100.8"));
        Assert.Null(f.MatchIp("not-an-ip"));
        Assert.Null(f.MatchIp(null));
    }

    [Fact]
    public void MatchIp_Resolves_An_Ipv4_Mapped_Ipv6_Address_To_The_V4_Entry()
    {
        var f = Feed("198.51.100.7");
        Assert.NotNull(f.MatchIp("::ffff:198.51.100.7"));
    }

    [Fact]
    public void Cidr_Containment_Covers_The_Whole_Block_And_Nothing_Else()
    {
        var f = Feed("203.0.113.0/24");
        Assert.NotNull(f.MatchIp("203.0.113.0"));
        Assert.NotNull(f.MatchIp("203.0.113.1"));
        Assert.NotNull(f.MatchIp("203.0.113.255"));
        Assert.Null(f.MatchIp("203.0.112.255"));
        Assert.Null(f.MatchIp("203.0.114.0"));
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("192.168.1.128/25", "192.168.1.200", true)]
    [InlineData("192.168.1.128/25", "192.168.1.127", false)]
    [InlineData("0.0.0.0/0", "8.8.8.8", true)]
    [InlineData("198.51.100.42/32", "198.51.100.42", true)]
    [InlineData("198.51.100.42/32", "198.51.100.43", false)]
    public void Cidr_Prefix_Boundaries_Are_Exact(string cidr, string probe, bool expected)
    {
        var f = Feed(cidr);
        Assert.Equal(expected, f.MatchIp(probe) is not null);
    }

    [Theory]
    [InlineData("2001:db8::/32", "2001:db8:1234:5678::1", true)]
    [InlineData("2001:db8::/32", "2001:db9::1", false)]
    [InlineData("fe80::/10", "fe80::abcd", true)]
    [InlineData("::/0", "2606:4700::1111", true)]
    public void Ipv6_Cidr_Containment_Works_Byte_Wise(string cidr, string probe, bool expected)
    {
        var f = Feed(cidr);
        Assert.Equal(expected, f.MatchIp(probe) is not null);
    }

    [Fact]
    public void Cidr_Is_Normalised_To_Its_Network_Address()
    {
        var f = Feed("10.1.2.3/8 ; sloppy but common");
        Assert.Equal("10.0.0.0/8", f.All[0].Indicator);
        Assert.NotNull(f.MatchIp("10.9.9.9"));
    }

    [Fact]
    public void The_Most_Specific_Matching_Block_Wins()
    {
        var f = Feed("10.0.0.0/8 ; broad", "10.1.2.0/24 ; narrow");
        Assert.Equal("narrow", f.MatchIp("10.1.2.5")!.Label);
        Assert.Equal("broad", f.MatchIp("10.9.9.9")!.Label);
    }

    [Fact]
    public void Ip_Families_Do_Not_Cross_Match()
    {
        var f = Feed("10.0.0.0/8");
        Assert.Null(f.MatchIp("2001:db8::1"));
    }

    [Theory]
    [InlineData("1.2.3.4/33")]
    [InlineData("2001:db8::/129")]
    [InlineData("1.2.3.4/-1")]
    [InlineData("1.2.3.4/")]
    [InlineData("/24")]
    [InlineData("1.2.3.4/abc")]
    public void Malformed_Cidr_Lines_Are_Rejected(string line)
    {
        Assert.Equal(0, Feed(line).Count);
    }

    [Theory]
    [InlineData("12345")]              // BCL would read this as 0.0.48.57
    [InlineData("10")]
    [InlineData("010.0.0.1")]          // ambiguous leading zero (octal in some parsers)
    [InlineData("1.2.3")]
    [InlineData("1.2.3.4.5")]
    [InlineData("256.1.1.1")]
    [InlineData("evil")]               // no dot, so not a domain either
    [InlineData("http://evil.com/x")]
    [InlineData("....")]
    public void Adversarial_Or_Ambiguous_Lines_Are_Refused_Rather_Than_Guessed(string line)
    {
        Assert.Equal(0, Feed(line).Count);
    }

    [Fact]
    public void MatchUrl_Is_A_Case_Insensitive_Substring_Test()
    {
        var f = Feed("url:/GaTe.php?id=");
        Assert.NotNull(f.MatchUrl("https://cdn.example/GATE.PHP?ID=1"));
        Assert.NotNull(f.MatchUrl("http://x/gate.php?id="));
        Assert.Null(f.MatchUrl("http://x/index.php"));
        Assert.Null(f.MatchUrl(""));
        Assert.Null(f.MatchUrl(null));
    }

    [Fact]
    public void Duplicate_Indicators_Are_Stored_Once_And_The_First_Definition_Wins()
    {
        var f = Feed("evil.com ; first", "EVIL.COM ; second", "evil.com");
        Assert.Equal(1, f.Count);
        Assert.Equal("first", f.MatchDomain("evil.com")!.Label);
    }

    [Fact]
    public void Merge_Unions_Both_Feeds_And_Prefers_The_Receiver_On_Conflict()
    {
        var local = IocFeed.Parse(new[] { "evil.com ; local override", "10.0.0.0/8 ; local range" }, "local.txt");
        var vendor = IocFeed.Parse(new[] { "evil.com ; vendor", "bad.net ; vendor", Sha }, "vendor.txt");

        var merged = local.Merge(vendor);

        Assert.Equal(4, merged.Count);
        Assert.Equal("local override", merged.MatchDomain("evil.com")!.Label);
        Assert.Equal("vendor", merged.MatchDomain("bad.net")!.Label);
        Assert.NotNull(merged.MatchHash(Sha));
        Assert.NotNull(merged.MatchIp("10.1.1.1"));

        // Inputs must be untouched: the caller may still be serving lookups from them.
        Assert.Equal(2, local.Count);
        Assert.Equal(3, vendor.Count);
    }

    [Fact]
    public void Merge_With_Null_Is_A_Copy()
    {
        var f = Feed("evil.com");
        var m = f.Merge(null);
        Assert.Equal(1, m.Count);
        Assert.NotNull(m.MatchDomain("sub.evil.com"));
    }

    [Fact]
    public void LoadDirectory_Reads_Supported_Extensions_Recursively_And_Warns_On_Junk()
    {
        File.WriteAllLines(Path.Combine(_dir, "a.txt"), new[] { "evil.com", "# note", "definitely not an indicator" });
        File.WriteAllLines(Path.Combine(_dir, "b.ioc"), new[] { Sha });
        File.WriteAllLines(Path.Combine(_dir, "c.csv"), new[] { "198.51.100.7 ; c2" });
        File.WriteAllLines(Path.Combine(_dir, "ignored.md"), new[] { "9.9.9.9" });
        File.WriteAllLines(Path.Combine(_dir, "notes.txtx"), new[] { "8.8.8.8" });   // 8.3 wildcard trap

        string sub = Path.Combine(_dir, "vendor");
        Directory.CreateDirectory(sub);
        File.WriteAllLines(Path.Combine(sub, "d.txt"), new[] { "203.0.113.0/24" });

        var warnings = new List<string>();
        var feed = IocFeed.LoadDirectory(_dir, warnings.Add);

        Assert.Equal(4, feed.Count);
        Assert.NotNull(feed.MatchDomain("x.evil.com"));
        Assert.NotNull(feed.MatchHash(Sha));
        Assert.Equal("c2", feed.MatchIp("198.51.100.7")!.Label);
        Assert.NotNull(feed.MatchIp("203.0.113.9"));
        Assert.Null(feed.MatchIp("9.9.9.9"));
        Assert.Null(feed.MatchIp("8.8.8.8"));

        Assert.Single(warnings);
        Assert.Contains("definitely not an indicator", warnings[0]);
        Assert.Contains("a.txt", warnings[0]);
    }

    [Fact]
    public void LoadDirectory_On_A_Missing_Directory_Warns_And_Returns_An_Empty_Feed()
    {
        var warnings = new List<string>();
        var feed = IocFeed.LoadDirectory(Path.Combine(_dir, "nope"), warnings.Add);
        Assert.Equal(0, feed.Count);
        Assert.Single(warnings);
        Assert.Contains("not found", warnings[0]);
    }

    [Fact]
    public void A_Large_Feed_Stays_Correct_And_Fast_To_Query()
    {
        // Not a benchmark -- this asserts the lookup does not degrade into a scan by
        // querying a feed big enough that a linear implementation would be obvious.
        var lines = new List<string>(60_000);
        for (int i = 0; i < 50_000; i++) lines.Add($"host{i}.malware.test");
        for (int i = 0; i < 200; i++) lines.Add($"10.{i}.0.0/16");

        var f = IocFeed.Parse(lines, "big");
        Assert.Equal(50_200, f.Count);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 20_000; i++)
        {
            Assert.NotNull(f.MatchDomain("host49999.malware.test"));
            Assert.Null(f.MatchDomain("host50001.malware.test"));
            Assert.NotNull(f.MatchIp("10.199.4.5"));
        }
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"lookups took {sw.Elapsed}");
    }
}

// -----------------------------------------------------------------------------------
// SecretScanner
// -----------------------------------------------------------------------------------

public class IntelSecretScannerTests
{
    private static string B64Url(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Jwt(string header) =>
        B64Url(header) + "." + B64Url("{\"sub\":\"1234567890\",\"name\":\"Jane Doe\"}") +
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";

    private static SecretMatch Single(string text, string expectedRuleId)
    {
        var hits = SecretScanner.Scan(text);
        var m = Assert.Single(hits, h => h.RuleId == expectedRuleId);
        return m;
    }

    // ---- provider formats ----

    [Fact]
    public void Detects_An_Aws_Access_Key_Id()
    {
        const string key = "AKIA" + "IOSFODNN7EXAMPLE";
        var m = Single("aws_access_key_id = " + key, "aws-access-key-id");
        Assert.Equal(FindingConfidence.High, m.Confidence);
        Assert.Equal("AKIA...LE", m.Redacted);
    }

    [Fact]
    public void Aws_Access_Key_Id_Rule_Is_Case_Sensitive()
    {
        Assert.Empty(SecretScanner.Scan("akiaiosfodnn7example"));
    }

    [Fact]
    public void Detects_An_Aws_Secret_Access_Key()
    {
        const string secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEK";   // 39
        var m = Single("aws_secret_access_key=" + secret + "Y", "aws-secret-access-key");
        Assert.Equal(FindingConfidence.High, m.Confidence);
    }

    [Fact]
    public void Detects_A_Github_Token()
    {
        const string tok = "ghp" + "_16C7e42F292c6912E7710c838347Ae178B4a";
        var m = Single("git remote set-url origin https://" + tok + "@github.com/x/y", "github-token");
        Assert.Equal(FindingConfidence.High, m.Confidence);
    }

    [Fact]
    public void Detects_A_Slack_Token()
        => Assert.Equal(FindingConfidence.High,
            Single("token: xoxb" + "-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", "slack-token").Confidence);

    [Fact]
    public void Detects_A_Slack_Webhook_Url()
        => Assert.Equal(FindingConfidence.High,
            Single("POST https://hooks.slack.com/services" + "/T00000000/B00000000/XXXXXXXXXXXXyyyyzzzz1234", "slack-webhook").Confidence);

    [Fact]
    public void Detects_A_Google_Api_Key()
        => Assert.Equal(FindingConfidence.High,
            Single("key=AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", "google-api-key").Confidence);

    [Fact]
    public void Detects_A_Stripe_Live_Key()
        => Assert.Equal(FindingConfidence.High,
            Single("STRIPE=sk_live" + "_4eC39HqLyjWDarjtT1zdp7dc", "stripe-live-key").Confidence);

    [Fact]
    public void Detects_An_Npm_Token()
        => Assert.Equal(FindingConfidence.High,
            Single("npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "npm-token").Confidence);

    [Theory]
    [InlineData("-----BEGIN PRIVATE KEY-----")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----")]
    [InlineData("-----BEGIN EC PRIVATE KEY-----")]
    [InlineData("-----BEGIN OPENSSH PRIVATE KEY-----")]
    [InlineData("-----BEGIN ENCRYPTED PRIVATE KEY-----")]
    [InlineData("-----BEGIN PGP PRIVATE KEY BLOCK-----")]
    public void Detects_Pem_Private_Key_Headers(string header)
    {
        var m = Single(header + "\nMIIEvQIBADANBg...\n", "private-key-pem");
        Assert.Equal(FindingConfidence.High, m.Confidence);
    }

    [Fact]
    public void Detects_An_Azure_Storage_Connection_String()
    {
        const string b64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
        var m = Single("DefaultEndpointsProtocol=https;AccountName=store;AccountKey=" + b64 + ";EndpointSuffix=core.windows.net",
            "azure-storage-connection-string");
        Assert.Equal(FindingConfidence.High, m.Confidence);
    }

    [Fact]
    public void Detects_An_Authorization_Basic_Header()
    {
        string header = "Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:supersecret123"));
        var m = Single(header, "authorization-basic");
        Assert.Equal(FindingConfidence.High, m.Confidence);
    }

    [Fact]
    public void Detects_An_Authorization_Bearer_Header()
    {
        var m = Single("Authorization: Bearer 7f3a9c2e5b8d1f4a6c0e2b7d9f1a3c5e", "authorization-bearer");
        Assert.Equal(FindingConfidence.Medium, m.Confidence);
    }

    [Fact]
    public void Detects_A_Connection_String_Password()
    {
        var m = Single("Server=tcp:db.internal,1433;Initial Catalog=payroll;User ID=sa;Password=Wq7!zPl2_Kd9;", "connection-string-password");
        Assert.Equal(FindingConfidence.High, m.Confidence);
    }

    [Fact]
    public void Detects_Credentials_Embedded_In_A_Uri()
    {
        var m = Single("git clone https://svcacct:Tr0ub4dor3xK@intranet.corp.example/repo.git", "uri-embedded-credentials");
        Assert.Equal(FindingConfidence.Medium, m.Confidence);
    }

    // ---- JWT ----

    [Fact]
    public void Detects_A_Jwt_With_A_Decodable_Header()
    {
        string jwt = Jwt("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        var m = Single("Cookie: session=" + jwt, "jwt");
        Assert.Equal(FindingConfidence.High, m.Confidence);
        Assert.True(SecretScanner.LooksLikeJwt(jwt));
    }

    [Fact]
    public void LooksLikeJwt_Rejects_Anything_Whose_Header_Is_Not_Json_With_An_Alg()
    {
        Assert.False(SecretScanner.LooksLikeJwt(null));
        Assert.False(SecretScanner.LooksLikeJwt(""));
        Assert.False(SecretScanner.LooksLikeJwt("abc.def"));                        // two segments
        Assert.False(SecretScanner.LooksLikeJwt("abc.def.ghi.jkl"));                // four segments
        Assert.False(SecretScanner.LooksLikeJwt("QUJDREVG.QUJDREVG.QUJDREVG"));     // decodes, not JSON
        Assert.False(SecretScanner.LooksLikeJwt(B64Url("{\"typ\":\"JWT\"}") + ".QQ.QQ"));   // no alg
        Assert.False(SecretScanner.LooksLikeJwt(B64Url("[1,2,3]") + ".QQ.QQ"));     // JSON but not an object
        Assert.False(SecretScanner.LooksLikeJwt("." + B64Url("{\"alg\":\"none\"}") + ".x"));   // empty header
        Assert.False(SecretScanner.LooksLikeJwt("ey!.ey!.ey!"));                    // not base64url
    }

    [Fact]
    public void LooksLikeJwt_Accepts_An_Unsecured_Alg_None_Token()
    {
        string t = B64Url("{\"alg\":\"none\"}") + "." + B64Url("{\"sub\":\"admin\"}") + ".";
        Assert.True(SecretScanner.LooksLikeJwt(t));
    }

    [Fact]
    public void A_Dot_Separated_Base64_Blob_That_Is_Not_A_Jwt_Does_Not_Fire_The_Jwt_Rule()
    {
        // Shape alone is not enough: this is why the rule decodes the header.
        string blob = "eyJub3RhandlIjoxfQ" + ".aGVsbG8" + ".d29ybGQ";
        Assert.DoesNotContain(SecretScanner.Scan(blob), h => h.RuleId == "jwt");
    }

    // ---- generic rule and its gates ----

    [Fact]
    public void A_Weak_Password_In_A_Comment_Does_Not_Fire()
    {
        Assert.Empty(SecretScanner.Scan("// legacy default\npassword=hunter2\n"));
    }

    [Fact]
    public void A_Long_Random_Assignment_Fires_The_Generic_Rule()
    {
        const string value = "kJ8xQ2vB7nR4tY6uP1sD3fG5" + "hL0zX9cV8mN2wE4r";
        var m = Single("api_key = \"" + value + "\"", "generic-high-entropy-assignment");
        Assert.Equal(FindingConfidence.Medium, m.Confidence);
        Assert.True(m.Entropy >= 4.2, $"entropy was {m.Entropy}");
        Assert.Equal("kJ8x...4r", m.Redacted);
    }

    [Theory]
    [InlineData("api_key=${MY_SECRET_VALUE_GOES_HERE}")]
    [InlineData("api_key={{ vault_api_key_lookup_here }}")]
    [InlineData("secret=REPLACE_WITH_YOUR_ACTUAL_SECRET_TOKEN_XYZ")]
    [InlineData("token=xxxxxxxxxxxxxxxxxxxxxxxx")]
    [InlineData("password=%DEPLOYMENT_PASSWORD_VARIABLE%")]
    [InlineData("apikey=<your-api-key-goes-right-here>")]
    [InlineData("token=process.env.GITHUB_ACCESS_TOKEN")]
    public void Placeholder_Shaped_Values_Do_Not_Fire(string line)
    {
        Assert.DoesNotContain(SecretScanner.Scan(line), h => h.RuleId == "generic-high-entropy-assignment");
    }

    [Fact]
    public void Ordinary_Prose_And_Code_Produce_Nothing()
    {
        const string text = """
            public static void Main()
            {
                Console.WriteLine("hello world");
                var total = items.Where(i => i.Active).Sum(i => i.Price);
            }
            // See the deployment guide for how secrets are injected at runtime.
            """;
        Assert.Empty(SecretScanner.Scan(text));
    }

    // ---- redaction ----

    [Fact]
    public void Redact_Masks_Short_Values_Entirely()
    {
        Assert.Equal("", SecretScanner.Redact(null));
        Assert.Equal("", SecretScanner.Redact(""));
        Assert.Equal("*", SecretScanner.Redact("a"));
        Assert.Equal("***", SecretScanner.Redact("abc"));
        Assert.Equal("***********", SecretScanner.Redact("12345678901"));   // 11 chars
    }

    [Fact]
    public void Redact_Keeps_Only_First_Four_And_Last_Two_Once_Long_Enough()
    {
        Assert.Equal("1234...12", SecretScanner.Redact("123456789012"));    // 12 chars
        Assert.Equal("AKIA...LE", SecretScanner.Redact("AKIA" + "IOSFODNN7EXAMPLE"));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(6)]
    [InlineData(11)]
    [InlineData(12)]
    [InlineData(40)]
    [InlineData(4096)]
    public void Redact_Never_Reveals_More_Than_Six_Real_Characters(int length)
    {
        string secret = string.Concat(Enumerable.Range(0, length).Select(i => (char)('a' + i % 26)));
        string red = SecretScanner.Redact(secret);
        int real = red.Count(c => c != '*' && c != '.');
        Assert.True(real <= 6, $"leaked {real} characters for length {length}");
        Assert.DoesNotContain(secret, red);
    }

    [Fact]
    public void No_Field_Of_A_Finding_Ever_Contains_The_Raw_Secret()
    {
        const string secret = "kJ8xQ2vB7nR4tY6uP1sD3fG5" + "hL0zX9cV8mN2wE4r";
        string text = "client_secret=" + secret + "\nAuthorization: Bearer " + secret;

        var hits = SecretScanner.Scan(text);
        Assert.NotEmpty(hits);
        foreach (var h in hits)
        {
            Assert.DoesNotContain(secret, h.Redacted);
            Assert.DoesNotContain(secret, h.RuleId);
            Assert.DoesNotContain(secret, h.Description);
        }
    }

    // ---- scan mechanics ----

    [Fact]
    public void Scan_Of_Nothing_Is_Empty()
    {
        Assert.Empty(SecretScanner.Scan(null));
        Assert.Empty(SecretScanner.Scan(""));
        Assert.Empty(SecretScanner.Scan("AKIA" + "IOSFODNN7EXAMPLE", maxMatches: 0));
        Assert.Empty(SecretScanner.Scan("AKIA" + "IOSFODNN7EXAMPLE", maxMatches: -5));
    }

    [Fact]
    public void Offsets_Point_At_The_Matched_Value()
    {
        const string key = "AKIA" + "IOSFODNN7EXAMPLE";
        string text = "prefix text -> " + key + " <- suffix";
        var m = Single(text, "aws-access-key-id");
        Assert.Equal(text.IndexOf(key, StringComparison.Ordinal), m.Offset);
        Assert.Equal(key, text.Substring(m.Offset, key.Length));
    }

    [Fact]
    public void Results_Are_Ordered_By_Offset_Regardless_Of_Rule_Order()
    {
        // github-token is evaluated after aws-access-key-id, but appears first in the text.
        string text = "ghp" + "_16C7e42F292c6912E7710c838347Ae178B4a and later AKIA" + "IOSFODNN7EXAMPLE";
        var hits = SecretScanner.Scan(text);
        Assert.Equal(2, hits.Count);
        Assert.Equal("github-token", hits[0].RuleId);
        Assert.Equal("aws-access-key-id", hits[1].RuleId);
        Assert.True(hits[0].Offset < hits[1].Offset);
    }

    [Fact]
    public void The_Same_Secret_Repeated_Is_Reported_Once()
    {
        string text = string.Join("\n", Enumerable.Repeat("key=AKIA" + "IOSFODNN7EXAMPLE", 50));
        var hits = SecretScanner.Scan(text);
        Assert.Single(hits, h => h.RuleId == "aws-access-key-id");
    }

    [Fact]
    public void Two_Different_Secrets_From_One_Rule_Are_Both_Reported()
    {
        string text = "AKIA" + "IOSFODNN7EXAMPLE and AKIA" + "J7SQ4RBEXAMPLE22";
        var hits = SecretScanner.Scan(text).Where(h => h.RuleId == "aws-access-key-id").ToList();
        Assert.Equal(2, hits.Count);
    }

    [Fact]
    public void MaxMatches_Caps_The_Result()
    {
        string text = "AKIA" + "IOSFODNN7EXAMPLE ghp" + "_16C7e42F292c6912E7710c838347Ae178B4a " +
                      "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY sk_live" + "_4eC39HqLyjWDarjtT1zdp7dc";
        Assert.True(SecretScanner.Scan(text).Count >= 3);
        Assert.Equal(2, SecretScanner.Scan(text, maxMatches: 2).Count);
        Assert.Single(SecretScanner.Scan(text, maxMatches: 1));
    }

    [Fact]
    public void Content_Beyond_The_Scan_Limit_Is_Not_Inspected()
    {
        // The truncation is a documented limitation, so it is pinned by a test rather
        // than left as a surprise for whoever debugs a missed detection.
        string filler = string.Concat(Enumerable.Repeat("lorem ipsum dolor sit amet ", 60_000));
        Assert.True(filler.Length > SecretScanner.MaxScanChars);

        string text = "AKIA" + "IOSFODNN7EXAMPLE " + filler + " AKIA" + "J7SQ4RBEXAMPLE22";
        var hits = SecretScanner.Scan(text);

        Assert.Contains(hits, h => h.RuleId == "aws-access-key-id" && h.Offset == 0);
        Assert.Single(hits, h => h.RuleId == "aws-access-key-id");
    }

    [Fact]
    public void Pathological_Input_Does_Not_Hang_The_Scanner()
    {
        // Long unbroken runs are the classic backtracking trigger; the per-rule timeout
        // must contain them rather than stalling the caller's thread indefinitely.
        string nasty = new string('a', 60_000) + "=" + new string('b', 60_000) +
                       "password=" + new string('c', 60_000);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var hits = SecretScanner.Scan(nasty);
        sw.Stop();

        Assert.NotNull(hits);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"scan took {sw.Elapsed}");
    }

    [Fact]
    public void Entropy_Is_Reported_For_Every_Finding()
    {
        var hits = SecretScanner.Scan("api_key = kJ8xQ2vB7nR4tY6uP1sD3fG5" + "hL0zX9cV8mN2wE4r");
        Assert.NotEmpty(hits);
        foreach (var h in hits) Assert.InRange(h.Entropy, 0.0, 8.0);
    }
}
