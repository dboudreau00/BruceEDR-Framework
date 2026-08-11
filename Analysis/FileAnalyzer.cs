using System.Security.Cryptography;
using System.Text;

namespace ProcessShield.Analysis;

/// <summary>One parsed PE section header, plus the entropy of its on-disk bytes.</summary>
public sealed record PeSection
{
    /// <summary>Section name from the 8-byte header field, sanitised to printable ASCII.</summary>
    public string Name { get; init; } = "";
    /// <summary>RVA the section is mapped at, relative to the image base.</summary>
    public uint VirtualAddress { get; init; }
    /// <summary>Size the section occupies once mapped. May exceed <see cref="RawSize"/>.</summary>
    public uint VirtualSize { get; init; }
    /// <summary>Bytes present in the file. Zero means the section is allocated but empty on disk.</summary>
    public uint RawSize { get; init; }
    /// <summary>Raw IMAGE_SECTION_HEADER.Characteristics bit field.</summary>
    public uint Characteristics { get; init; }
    /// <summary>Shannon entropy of the section's on-disk bytes, 0 when it has none.</summary>
    public double Entropy { get; init; }
    /// <summary>IMAGE_SCN_MEM_EXECUTE.</summary>
    public bool IsExecutable { get; init; }
    /// <summary>IMAGE_SCN_MEM_WRITE.</summary>
    public bool IsWritable { get; init; }
}

/// <summary>
/// Static analysis of one file: content hashes plus, when the file is a PE image, a
/// bounds-checked parse of the headers, sections and import table.
///
/// The contract that matters most: this record is ALWAYS returned, never an exception.
/// <see cref="Valid"/> is false with <see cref="Error"/> set when the file could not be
/// read or its PE structures did not survive validation; the other fields then hold
/// whatever was parsed before the failure, which is still useful for triage.
/// </summary>
public sealed record FileAnalysis
{
    /// <summary>Path as supplied by the caller. Not canonicalised or resolved.</summary>
    public string Path { get; init; } = "";
    /// <summary>Size in bytes of the file (or of the buffer, for <see cref="FileAnalyzer.AnalyzeBytes"/>).</summary>
    public long SizeBytes { get; init; }
    /// <summary>Lowercase hex SHA-256 of the file content. Empty if it could not be computed.</summary>
    public string Sha256 { get; init; } = "";
    /// <summary>
    /// Lowercase hex MD5. Kept only because threat-intel feeds and imphash still speak
    /// MD5; it is not relied on for any integrity decision. Empty under FIPS policy,
    /// where the runtime refuses to provide MD5 at all.
    /// </summary>
    public string Md5 { get; init; } = "";
    /// <summary>False when the file could not be read or a PE structure failed validation.</summary>
    public bool Valid { get; init; } = true;
    /// <summary>Human-readable reason <see cref="Valid"/> is false. Empty when valid.</summary>
    public string Error { get; init; } = "";

    /// <summary>True only after both the MZ and the PE\0\0 signatures were found in range.</summary>
    public bool IsPeFile { get; init; }
    /// <summary>PE32+ (optional header magic 0x20B).</summary>
    public bool Is64Bit { get; init; }
    /// <summary>IMAGE_FILE_DLL is set in the COFF characteristics.</summary>
    public bool IsDll { get; init; }
    /// <summary>COFF machine type as a short name, e.g. <c>amd64</c>, <c>i386</c>, or <c>0x1234</c>.</summary>
    public string Machine { get; init; } = "";
    /// <summary>
    /// COFF TimeDateStamp as UTC, null when the field is zero or unparsable.
    ///
    /// ATTACKER-CONTROLLABLE: this is a plain 32-bit field in the header that any linker
    /// flag or hex editor can set, and Go/Rust reproducible builds legitimately zero it.
    /// Useful for clustering samples from the same build, worthless as evidence of when
    /// a file was actually created.
    /// </summary>
    public DateTime? TimestampUtc { get; init; }
    /// <summary>Optional-header Subsystem as a short name, e.g. <c>windows-gui</c>.</summary>
    public string Subsystem { get; init; } = "";
    /// <summary>AddressOfEntryPoint (an RVA, not a file offset). Zero for most DLL-less images.</summary>
    public uint EntryPointRva { get; init; }
    /// <summary>Optional-header CheckSum field as stored. Not recomputed or verified.</summary>
    public uint Checksum { get; init; }

    public IReadOnlyList<PeSection> Sections { get; init; } = Array.Empty<PeSection>();
    /// <summary>DLL names from the import directory, in directory order, lowercased.</summary>
    public IReadOnlyList<string> ImportedDlls { get; init; } = Array.Empty<string>();
    /// <summary>
    /// Imported functions as <c>dll.dll!Function</c>, in import-table order. Ordinal-only
    /// imports appear as <c>dll.dll!#17</c>.
    /// </summary>
    public IReadOnlyList<string> ImportedFunctions { get; init; } = Array.Empty<string>();
    /// <summary>Lowercase hex imphash, or empty when the image imports nothing. See <see cref="FileAnalyzer"/>.</summary>
    public string Imphash { get; init; } = "";
    /// <summary>
    /// The Certificate Table data directory (index 4) is populated.
    ///
    /// This says a signature BLOB is attached. It says nothing about whether the
    /// signature is valid, covers the file's bytes, or chains to a trusted root --
    /// use <c>ProcessShield.Security.AuthenticodeVerifier</c> for that. A tampered
    /// binary keeps its (now-invalid) certificate table and still reports true here.
    /// </summary>
    public bool HasDigitalSignatureDirectory { get; init; }

    /// <summary>Shannon entropy of the whole file.</summary>
    public double OverallEntropy { get; init; }
    /// <summary>Human-readable packing/obfuscation observations. See <see cref="FileAnalyzer"/>.</summary>
    public IReadOnlyList<string> PackerIndicators { get; init; } = Array.Empty<string>();
    /// <summary>Imported APIs commonly used for injection, credential theft or evasion.</summary>
    public IReadOnlyList<string> SuspiciousImports { get; init; } = Array.Empty<string>();
    /// <summary>Coarse 0-100 triage score. Not a verdict; see <see cref="FileAnalyzer"/> for the formula.</summary>
    public int SuspicionScore { get; init; }
}

/// <summary>
/// Dependency-free PE reader and file hasher.
///
/// WHY HAND-ROLLED: this code is pointed at files chosen by an attacker. Every offset
/// is validated against the buffer length before it is dereferenced, malformed
/// structures degrade to a partial result instead of an exception, and the parse is
/// bounded (section count, descriptor count, import count, string length) so a crafted
/// header cannot turn analysis into a denial of service on the agent. It runs entirely
/// on a byte[] with no OS loader involvement, so it is safe to point at a quarantined
/// sample and is fully unit-testable from synthesised bytes.
///
/// IMPHASH: computed the way pefile/VirusTotal do it. For each import descriptor in
/// table order, and each thunk in that descriptor in order, emit
/// <c>{dll}.{function}</c> where <c>dll</c> is the lowercased library name with a
/// trailing <c>.dll</c>, <c>.ocx</c> or <c>.sys</c> removed, and <c>function</c> is the
/// lowercased imported name, or <c>ord{N}</c> for an ordinal import. Join with commas
/// and take the MD5.
/// KNOWN DIVERGENCE: pefile substitutes real names for well-known ordinals in
/// <c>ws2_32.dll</c>/<c>wsock32.dll</c>; this implementation does not, so an imphash
/// for a binary that imports winsock BY ORDINAL will differ from VirusTotal's. Imphash
/// is in any case a clustering aid, not an identity -- two unrelated programs built
/// with the same toolchain and libraries share one, and repacking changes it.
/// </summary>
public static class FileAnalyzer
{
    /// <summary>Default read budget: large enough for real installers, small enough to bound memory.</summary>
    public const long DefaultMaxBytes = 128L * 1024 * 1024;

    // A byte[] is indexed by int, so no request may exceed this regardless of maxBytes.
    private const long HardMaxBytes = 512L * 1024 * 1024;

    private const uint ScnMemExecute = 0x20000000;
    private const uint ScnMemWrite = 0x80000000;
    private const uint FileDll = 0x2000;

    private const int MaxSections = 96;          // the Windows loader's own ceiling
    private const int MaxImportDescriptors = 4096;
    private const int MaxImportsPerDll = 4096;
    private const int MaxImportsTotal = 8192;
    private const int MaxNameLength = 256;

    /// <summary>
    /// Read and analyse a file. Never throws: any IO or parse failure comes back as a
    /// record with <see cref="FileAnalysis.Valid"/> false.
    ///
    /// Files larger than <paramref name="maxBytes"/> are still hashed (by streaming) but
    /// not parsed, because holding an arbitrarily large attacker-chosen file in memory is
    /// itself the denial of service this analyzer exists to avoid.
    /// </summary>
    public static FileAnalysis Analyze(string path, long maxBytes = DefaultMaxBytes)
    {
        if (string.IsNullOrWhiteSpace(path))
            return new FileAnalysis { Path = path ?? "", Valid = false, Error = "empty path" };

        long cap = Math.Clamp(maxBytes, 0, HardMaxBytes);

        try
        {
            // FileShare.ReadWrite | Delete: an EDR must be able to hash an image that the
            // running process still holds open, and must not block a delete while doing so.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);

            long len = fs.Length;
            if (len > cap)
            {
                string sha = "", md5 = "";
                try { sha = HashStream(fs, SHA256.Create()); } catch { }
                try { fs.Position = 0; md5 = HashStream(fs, MD5.Create()); } catch { }
                return new FileAnalysis
                {
                    Path = path,
                    SizeBytes = len,
                    Sha256 = sha,
                    Md5 = md5,
                    Valid = false,
                    Error = $"file is {len} bytes, above the {cap} byte analysis limit; hashed but not parsed"
                };
            }

            var bytes = new byte[len];
            fs.ReadExactly(bytes, 0, (int)len);
            return AnalyzeBytes(bytes, path);
        }
        catch (Exception ex)
        {
            return new FileAnalysis
            {
                Path = path,
                Valid = false,
                Error = ex.GetType().Name + ": " + ex.Message
            };
        }
    }

    /// <summary>
    /// Analyse an in-memory buffer. This is the whole engine; <see cref="Analyze"/> is
    /// only the file-reading wrapper, which is what makes the parser testable against
    /// synthesised and deliberately corrupt images without touching the filesystem.
    ///
    /// A non-PE buffer (including an empty one) is NOT an error: the result is valid with
    /// <see cref="FileAnalysis.IsPeFile"/> false and the hashes and entropy filled in.
    /// </summary>
    public static FileAnalysis AnalyzeBytes(byte[]? bytes, string displayPath)
    {
        byte[] b = bytes ?? Array.Empty<byte>();
        displayPath ??= "";

        string sha = "", md5 = "";
        try { sha = Hex(SHA256.HashData(b)); } catch { }
        try { md5 = Hex(MD5.HashData(b)); } catch { }

        double overall = Entropy.Shannon(b);

        var pe = new PeInfo();
        try { ParsePe(b, pe); }
        catch (Exception ex)
        {
            // Defence in depth. ParsePe is written not to throw; if it ever does, the
            // agent still gets a usable record instead of an unhandled exception on a
            // monitor thread.
            if (pe.Error.Length == 0) pe.Error = "unexpected parse failure: " + ex.GetType().Name;
        }

        var packer = BuildPackerIndicators(pe, overall);
        var suspicious = BuildSuspiciousImports(pe);
        int score = Score(pe, overall, packer.Count, suspicious.Count);

        return new FileAnalysis
        {
            Path = displayPath,
            SizeBytes = b.LongLength,
            Sha256 = sha,
            Md5 = md5,
            Valid = pe.Error.Length == 0,
            Error = pe.Error,
            IsPeFile = pe.IsPe,
            Is64Bit = pe.Is64Bit,
            IsDll = pe.IsDll,
            Machine = pe.Machine,
            TimestampUtc = pe.TimestampUtc,
            Subsystem = pe.Subsystem,
            EntryPointRva = pe.EntryPointRva,
            Checksum = pe.Checksum,
            Sections = pe.Sections,
            ImportedDlls = pe.Dlls,
            ImportedFunctions = pe.Functions,
            Imphash = pe.Imphash,
            HasDigitalSignatureDirectory = pe.HasSignatureDirectory,
            OverallEntropy = overall,
            PackerIndicators = packer,
            SuspiciousImports = suspicious,
            SuspicionScore = score
        };
    }

    /// <summary>
    /// Lowercase hex SHA-256 of a file, streamed so size does not matter. Unlike
    /// <see cref="Analyze"/> this DOES propagate IO exceptions, because a caller asking
    /// only for a hash needs to know it did not get one.
    /// </summary>
    public static string Sha256File(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        return HashStream(fs, SHA256.Create());
    }

    private static string HashStream(Stream s, HashAlgorithm alg)
    {
        using (alg) return Hex(alg.ComputeHash(s));
    }

    // Lowercase hex: threat-intel feeds, VirusTotal and sandbox reports all publish
    // lowercase, and IocFeed normalises to lowercase, so emitting it here removes a
    // whole class of "hash did not match" bugs at the seams.
    private static string Hex(byte[] raw) => Convert.ToHexString(raw).ToLowerInvariant();

    // ---- PE parsing -------------------------------------------------------------

    /// <summary>Mutable scratch for the parse; converted to the immutable record at the end.</summary>
    private sealed class PeInfo
    {
        public bool IsPe;
        public bool Is64Bit;
        public bool IsDll;
        public string Machine = "";
        public DateTime? TimestampUtc;
        public string Subsystem = "";
        public uint EntryPointRva;
        public uint Checksum;
        public uint SizeOfHeaders;
        public bool HasSignatureDirectory;
        public string Imphash = "";
        public string Error = "";
        public readonly List<PeSection> Sections = new();
        public readonly List<SecMap> Map = new();
        public readonly List<string> Dlls = new();
        public readonly List<string> Functions = new();

        public void Fail(string reason)
        {
            if (Error.Length == 0) Error = reason;
        }
    }

    /// <summary>Just enough of a section header to translate an RVA to a file offset.</summary>
    private readonly record struct SecMap(uint Va, uint VSize, uint RawSize, uint PtrRaw);

    private static void ParsePe(byte[] b, PeInfo pe)
    {
        if (b.Length < 2 || b[0] != (byte)'M' || b[1] != (byte)'Z') return;   // not a PE: not an error

        if (!TryU32(b, 0x3C, out uint lfanewRaw)) { pe.Fail("truncated DOS header (no e_lfanew)"); return; }
        if (lfanewRaw > int.MaxValue) { pe.Fail("e_lfanew out of range"); return; }
        int lfanew = (int)lfanewRaw;

        // Need signature (4) + COFF header (20) fully in range before reading either.
        if (lfanew < 0 || lfanew > b.Length - 24) { pe.Fail("e_lfanew points outside the file"); return; }
        if (!(b[lfanew] == (byte)'P' && b[lfanew + 1] == (byte)'E' && b[lfanew + 2] == 0 && b[lfanew + 3] == 0))
        {
            pe.Fail("MZ present but PE signature missing");
            return;
        }

        pe.IsPe = true;
        int coff = lfanew + 4;

        // The range check above guarantees the whole 20-byte COFF header is present, so
        // these five reads cannot fail; the Try* form is kept so the bounds check is still
        // executed rather than assumed.
        TryU16(b, coff + 0, out ushort machine);
        TryU16(b, coff + 2, out ushort numSections);
        TryU32(b, coff + 4, out uint timeDateStamp);
        TryU16(b, coff + 16, out ushort sizeOfOptional);
        TryU16(b, coff + 18, out ushort characteristics);

        pe.Machine = MachineName(machine);
        pe.IsDll = (characteristics & FileDll) != 0;
        pe.TimestampUtc = timeDateStamp is 0 or 0xFFFFFFFF
            ? null
            : DateTimeOffset.FromUnixTimeSeconds(timeDateStamp).UtcDateTime;

        uint importRva = 0;
        int optional = coff + 20;
        bool optionalUsable = false;

        if (sizeOfOptional == 0)
        {
            // Legal for an object file, never for an image. Sections may still be readable.
            pe.Fail("optional header is absent (object file, not an image)");
        }
        else if (!TryU16(b, optional, out ushort magic))
        {
            pe.Fail("truncated optional header");
        }
        else if (magic != 0x10B && magic != 0x20B)
        {
            // 0x107 is a ROM image; anything else is corruption. Do not trust offsets
            // derived from it, but keep parsing sections, which live past this header.
            pe.Fail($"unrecognised optional header magic 0x{magic:X4}");
        }
        else
        {
            pe.Is64Bit = magic == 0x20B;
            optionalUsable = true;

            TryU32(b, optional + 16, out uint entry);
            TryU32(b, optional + 60, out uint sizeOfHeaders);
            TryU32(b, optional + 64, out uint checksum);
            TryU16(b, optional + 68, out ushort subsystem);

            pe.EntryPointRva = entry;
            pe.SizeOfHeaders = sizeOfHeaders;
            pe.Checksum = checksum;
            pe.Subsystem = SubsystemName(subsystem);

            // Data directory layout differs only by the width of the four 64-bit
            // stack/heap fields that precede it in PE32+.
            int numDirsOffset = pe.Is64Bit ? optional + 108 : optional + 92;
            int dirBase = pe.Is64Bit ? optional + 112 : optional + 96;

            if (TryU32(b, numDirsOffset, out uint numDirs))
            {
                uint dirs = Math.Min(numDirs, 16u);
                if (dirs > 1 && TryU32(b, dirBase + 8, out uint impVa))
                {
                    // The directory's declared Size is deliberately ignored: packers
                    // routinely understate it, and the table is self-terminating with an
                    // all-zero descriptor, which the bounded loop below relies on instead.
                    importRva = impVa;
                }
                if (dirs > 4 && TryU32(b, dirBase + 32, out uint secVa) && TryU32(b, dirBase + 36, out uint secSize))
                {
                    // Note: the Certificate Table entry is the one data directory whose
                    // "VirtualAddress" is really a FILE OFFSET, because the blob is not
                    // mapped. We only test that it is populated, so it does not matter here.
                    pe.HasSignatureDirectory = secVa != 0 && secSize != 0;
                }
            }
        }

        // ---- section headers ----
        int secBase = coff + 20 + sizeOfOptional;
        if (numSections > MaxSections)
            pe.Fail($"section count {numSections} exceeds the loader maximum of {MaxSections}");

        int take = Math.Min((int)numSections, MaxSections);
        for (int i = 0; i < take; i++)
        {
            int h = secBase + i * 40;
            if (!TryU32(b, h + 8, out uint vsize) ||
                !TryU32(b, h + 12, out uint va) ||
                !TryU32(b, h + 16, out uint rawSize) ||
                !TryU32(b, h + 20, out uint ptrRaw) ||
                !TryU32(b, h + 36, out uint chars))
            {
                pe.Fail($"section header {i} is truncated");
                break;
            }

            string name = ReadFixedAscii(b, h, 8);

            double sectionEntropy = 0.0;
            if (ptrRaw < (uint)b.Length && rawSize > 0)
            {
                long avail = Math.Min(rawSize, b.Length - (long)ptrRaw);
                if (avail < rawSize)
                    pe.Fail($"section '{name}' claims {rawSize} raw bytes but only {avail} are present");
                if (avail > 0)
                    sectionEntropy = Entropy.Shannon(b.AsSpan((int)ptrRaw, (int)avail));
            }
            else if (rawSize > 0)
            {
                pe.Fail($"section '{name}' raw data pointer 0x{ptrRaw:X} is outside the file");
            }

            pe.Sections.Add(new PeSection
            {
                Name = name,
                VirtualAddress = va,
                VirtualSize = vsize,
                RawSize = rawSize,
                Characteristics = chars,
                Entropy = sectionEntropy,
                IsExecutable = (chars & ScnMemExecute) != 0,
                IsWritable = (chars & ScnMemWrite) != 0
            });
            pe.Map.Add(new SecMap(va, vsize, rawSize, ptrRaw));
        }

        if (optionalUsable && importRva != 0)
            ParseImports(b, pe, importRva);
    }

    private static void ParseImports(byte[] b, PeInfo pe, uint importRva)
    {
        if (!TryRvaToOffset(b, pe, importRva, out int dirOff))
        {
            pe.Fail($"import directory RVA 0x{importRva:X} does not map into the file");
            return;
        }

        // An IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the directory ends at an all-zero one.
        int thunkStep = pe.Is64Bit ? 8 : 4;
        ulong ordinalFlag = pe.Is64Bit ? 0x8000000000000000UL : 0x80000000UL;

        var imphashParts = new List<string>();
        int totalFunctions = 0;

        for (int i = 0; i < MaxImportDescriptors; i++)
        {
            int d = dirOff + i * 20;
            if (!TryU32(b, d + 0, out uint origFirstThunk) ||
                !TryU32(b, d + 12, out uint nameRva) ||
                !TryU32(b, d + 16, out uint firstThunk))
            {
                pe.Fail("import descriptor table is truncated");
                break;
            }
            if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;   // terminator

            string dll = "";
            if (nameRva != 0 && TryRvaToOffset(b, pe, nameRva, out int nameOff))
                dll = ReadAsciiZ(b, nameOff, MaxNameLength).ToLowerInvariant();

            if (dll.Length == 0)
            {
                pe.Fail($"import descriptor {i} has an unreadable library name");
                dll = "(unknown)";
            }
            pe.Dlls.Add(dll);

            // Prefer the Import Lookup Table: on a file that has already been loaded and
            // dumped, FirstThunk holds resolved addresses rather than name RVAs, and only
            // the ILT still carries the original names.
            uint thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
            if (thunkRva == 0) continue;
            if (!TryRvaToOffset(b, pe, thunkRva, out int thunkOff))
            {
                pe.Fail($"thunk array for '{dll}' at RVA 0x{thunkRva:X} does not map into the file");
                continue;
            }

            string imphashDll = StripLibraryExtension(dll);

            for (int j = 0; j < MaxImportsPerDll && totalFunctions < MaxImportsTotal; j++)
            {
                ulong entry;
                if (pe.Is64Bit)
                {
                    if (!TryU64(b, thunkOff + j * thunkStep, out entry)) { pe.Fail($"thunk array for '{dll}' is truncated"); break; }
                }
                else
                {
                    if (!TryU32(b, thunkOff + j * thunkStep, out uint e32)) { pe.Fail($"thunk array for '{dll}' is truncated"); break; }
                    entry = e32;
                }
                if (entry == 0) break;   // terminator

                string func;
                if ((entry & ordinalFlag) != 0)
                {
                    ushort ordinal = (ushort)(entry & 0xFFFF);
                    pe.Functions.Add($"{dll}!#{ordinal}");
                    func = "ord" + ordinal.ToString(System.Globalization.CultureInfo.InvariantCulture);
                }
                else
                {
                    uint hintNameRva = (uint)(entry & 0x7FFFFFFF);
                    if (!TryRvaToOffset(b, pe, hintNameRva, out int hintOff))
                    {
                        pe.Fail($"import name RVA 0x{hintNameRva:X} in '{dll}' does not map into the file");
                        break;
                    }
                    string raw = ReadAsciiZ(b, hintOff + 2, MaxNameLength);   // skip the 2-byte hint
                    if (raw.Length == 0)
                    {
                        pe.Fail($"empty import name in '{dll}'");
                        break;
                    }
                    pe.Functions.Add($"{dll}!{raw}");
                    func = raw.ToLowerInvariant();
                }

                imphashParts.Add(imphashDll + "." + func);
                totalFunctions++;
            }

            if (totalFunctions >= MaxImportsTotal)
            {
                pe.Fail($"import table exceeds the {MaxImportsTotal} function parse budget; truncated");
                break;
            }
        }

        if (imphashParts.Count > 0)
        {
            try
            {
                string joined = string.Join(",", imphashParts);
                pe.Imphash = Hex(MD5.HashData(Encoding.ASCII.GetBytes(joined)));
            }
            catch
            {
                pe.Imphash = "";   // FIPS policy blocks MD5; imphash is simply unavailable
            }
        }
    }

    // pefile strips exactly these three extensions before hashing, and nothing else.
    // Reproducing the quirk (rather than stripping any extension) is what keeps the
    // value comparable with published imphashes.
    private static string StripLibraryExtension(string dll)
    {
        if (dll.EndsWith(".dll", StringComparison.Ordinal) ||
            dll.EndsWith(".ocx", StringComparison.Ordinal) ||
            dll.EndsWith(".sys", StringComparison.Ordinal))
            return dll[..^4];
        return dll;
    }

    /// <summary>
    /// Translate an RVA to a file offset using the parsed section map. Returns false
    /// rather than guessing whenever the RVA lands in virtual-only padding, outside every
    /// section, or past the end of the buffer.
    /// </summary>
    private static bool TryRvaToOffset(byte[] b, PeInfo pe, uint rva, out int offset)
    {
        offset = 0;
        foreach (var s in pe.Map)
        {
            ulong span = Math.Max(s.VSize, s.RawSize);
            if (span == 0) continue;
            if (rva < s.Va || rva >= s.Va + span) continue;

            ulong delta = rva - (ulong)s.Va;
            if (delta >= s.RawSize) return false;      // mapped but not backed by file bytes
            ulong o = s.PtrRaw + delta;
            if (o >= (ulong)b.Length) return false;
            offset = (int)o;
            return true;
        }

        // Hand-built and packed images sometimes place directories inside the headers,
        // where the mapping is the identity because headers are mapped at RVA 0.
        if (rva != 0 && rva < pe.SizeOfHeaders && rva < (uint)b.Length)
        {
            offset = (int)rva;
            return true;
        }
        return false;
    }

    // ---- indicators and scoring --------------------------------------------------

    // Section names published by common packers and protectors. Matching on the name is
    // trivially evaded (every one of these can be renamed at build time), so a miss here
    // means nothing; a hit is a strong hint.
    private static readonly HashSet<string> PackerSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "UPX0", "UPX1", "UPX2", "UPX!", ".UPX0", ".UPX1", ".UPX2",
        ".aspack", ".adata", ".ASPack", ".packed", ".pklstb",
        ".themida", "Themida", ".winlice", ".vmp0", ".vmp1", ".vmp2",
        ".enigma1", ".enigma2", ".petite", ".MPRESS1", ".MPRESS2",
        "MEW", "FSG!", ".nsp0", ".nsp1", ".nsp2", ".Upack", ".ByDwing",
        "PEBundle", "PEPACK!!", "PESHiELD", "PELOCKnt", "ProCrypt",
        ".RLPack", ".RPCrypt", ".neolite", ".neolit", ".perplex",
        ".spack", ".svkp", ".taz", ".tsuarch", ".tsustub", ".WWP32",
        ".yP", ".y0da", "kkrunchy", ".boom", ".ccg", ".charmve", ".pec", ".pec1", "Shrinker3"
    };

    // APIs that carry real signal for injection, credential access, keylogging, token
    // manipulation and anti-analysis. Deliberately EXCLUDES LoadLibrary/GetProcAddress/
    // VirtualAlloc/CreateFile and friends: they appear in almost every binary ever built,
    // so listing them would bury the entries that matter. A packer that resolves
    // everything dynamically imports none of these -- that case is covered by the
    // "few imports + high entropy" packer indicator instead.
    private static readonly HashSet<string> SuspiciousApiNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // remote process manipulation / injection
        "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx", "RtlCreateUserThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection", "ZwMapViewOfSection",
        "NtCreateThreadEx", "ZwCreateThreadEx", "QueueUserAPC", "NtQueueApcThread",
        "SetThreadContext", "Wow64SetThreadContext", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
        // credential access
        "CryptUnprotectData", "MiniDumpWriteDump", "LsaRetrievePrivateData", "LsaOpenPolicy",
        "SamConnect", "NetUserGetInfo", "CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW",
        // token / privilege manipulation
        "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
        "DuplicateTokenEx", "ImpersonateLoggedOnUser", "SetTokenInformation",
        "CreateProcessWithTokenW", "CreateProcessAsUserW",
        // input capture / spying
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyboardState",
        "AttachThreadInput", "BlockInput", "keybd_event", "mouse_event",
        "GetClipboardData", "SetClipboardData", "BitBlt",
        // anti-analysis
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "NtSetInformationThread", "GetTickCount64",
        // persistence / lateral movement / staging
        "CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW",
        "NetUserAdd", "WNetAddConnection2A", "WNetAddConnection2W",
        "URLDownloadToFileA", "URLDownloadToFileW", "WinExec",
        "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW", "EnumProcesses"
    };

    /// <summary>
    /// Packing/obfuscation observations, each phrased so it can be shown verbatim to an
    /// analyst. Every one of these is evadeable; they are collected because a real packed
    /// sample usually trips several at once, not because any single one is conclusive.
    /// </summary>
    private static List<string> BuildPackerIndicators(PeInfo pe, double overallEntropy)
    {
        var list = new List<string>();
        if (!pe.IsPe) return list;

        foreach (var s in pe.Sections)
        {
            if (s.Name.Length > 0 && PackerSectionNames.Contains(s.Name))
                list.Add($"packer section name '{s.Name}'");
        }

        if (pe.Sections.Count > 0 && pe.EntryPointRva != 0)
        {
            bool inside = pe.Sections.Any(s =>
            {
                ulong span = Math.Max(s.VirtualSize, s.RawSize);
                return span != 0 && pe.EntryPointRva >= s.VirtualAddress && pe.EntryPointRva < s.VirtualAddress + span;
            });
            if (!inside)
                list.Add($"entry point RVA 0x{pe.EntryPointRva:X} falls outside every section");
        }

        foreach (var s in pe.Sections)
        {
            // Classic UPX shape: UPX0 is a large empty hole the stub unpacks into.
            if (s.RawSize == 0 && s.VirtualSize >= 0x1000)
                list.Add($"section '{s.Name}' has no file data but reserves {s.VirtualSize} bytes");
            if (s.IsWritable && s.IsExecutable)
                list.Add($"section '{s.Name}' is both writable and executable");
            if (s.IsExecutable && s.RawSize > 0 && Entropy.IsLikelyEncryptedOrPacked(s.Entropy))
                list.Add($"executable section '{s.Name}' entropy {s.Entropy:0.00} suggests packed or encrypted code");
        }

        // A PE that imports next to nothing resolves its API surface at runtime. On its
        // own that is also how some legitimate loaders and .NET stubs behave, so it only
        // counts alongside high whole-file entropy.
        if (pe.Functions.Count <= 5 && Entropy.IsLikelyEncryptedOrPacked(overallEntropy))
            list.Add($"only {pe.Functions.Count} imported function(s) with whole-file entropy {overallEntropy:0.00}");

        return list;
    }

    private static List<string> BuildSuspiciousImports(PeInfo pe)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<string>();
        foreach (var qualified in pe.Functions)
        {
            int bang = qualified.IndexOf('!');
            string func = bang >= 0 ? qualified[(bang + 1)..] : qualified;
            if (SuspiciousApiNames.Contains(func) && seen.Add(func)) list.Add(func);
        }
        return list;
    }

    /// <summary>
    /// Coarse triage score in [0, 100]:
    /// 15 per packer indicator (capped at 45), 6 per distinct suspicious import (capped
    /// at 36), +10 for whole-file entropy at or above the packed threshold, +9 when the
    /// section containing the entry point is writable (self-modifying stub).
    ///
    /// The weights are judgement, not measurement. The score exists to ORDER a queue of
    /// files for a human, and a legitimately packed installer will score highly by
    /// design. Nothing in ProcessShield should act on this number alone.
    /// </summary>
    private static int Score(PeInfo pe, double overallEntropy, int packerCount, int suspiciousCount)
    {
        int score = 0;
        score += Math.Min(packerCount * 15, 45);
        score += Math.Min(suspiciousCount * 6, 36);
        if (Entropy.IsLikelyEncryptedOrPacked(overallEntropy)) score += 10;

        if (pe.IsPe && pe.EntryPointRva != 0)
        {
            foreach (var s in pe.Sections)
            {
                ulong span = Math.Max(s.VirtualSize, s.RawSize);
                if (span == 0) continue;
                if (pe.EntryPointRva >= s.VirtualAddress && pe.EntryPointRva < s.VirtualAddress + span)
                {
                    if (s.IsWritable) score += 9;
                    break;
                }
            }
        }

        return Math.Clamp(score, 0, 100);
    }

    // ---- bounds-checked primitives ------------------------------------------------

    private static bool TryU16(byte[] b, int off, out ushort v)
    {
        v = 0;
        if (off < 0 || off > b.Length - 2) return false;
        v = (ushort)(b[off] | (b[off + 1] << 8));
        return true;
    }

    private static bool TryU32(byte[] b, int off, out uint v)
    {
        v = 0;
        if (off < 0 || off > b.Length - 4) return false;
        v = (uint)b[off] | ((uint)b[off + 1] << 8) | ((uint)b[off + 2] << 16) | ((uint)b[off + 3] << 24);
        return true;
    }

    private static bool TryU64(byte[] b, int off, out ulong v)
    {
        v = 0;
        if (off < 0 || off > b.Length - 8) return false;
        if (!TryU32(b, off, out uint lo) || !TryU32(b, off + 4, out uint hi)) return false;
        v = lo | ((ulong)hi << 32);
        return true;
    }

    /// <summary>
    /// Read a NUL-terminated ASCII string, capped at <paramref name="maxLen"/> bytes.
    /// Non-printable bytes become '?' so a crafted name cannot inject control characters
    /// or ANSI escapes into a console alert or a log line.
    /// </summary>
    private static string ReadAsciiZ(byte[] b, int off, int maxLen)
    {
        if (off < 0 || off >= b.Length) return "";
        int limit = (int)Math.Min((long)b.Length, (long)off + maxLen);
        var sb = new StringBuilder(32);
        for (int i = off; i < limit; i++)
        {
            byte c = b[i];
            if (c == 0) break;
            sb.Append(c >= 0x20 && c < 0x7F ? (char)c : '?');
        }
        return sb.ToString();
    }

    /// <summary>Read a fixed-width, optionally NUL-padded ASCII field (section names).</summary>
    private static string ReadFixedAscii(byte[] b, int off, int len)
    {
        if (off < 0 || off >= b.Length) return "";
        int limit = (int)Math.Min((long)b.Length, (long)off + len);
        var sb = new StringBuilder(len);
        for (int i = off; i < limit; i++)
        {
            byte c = b[i];
            if (c == 0) break;
            sb.Append(c >= 0x20 && c < 0x7F ? (char)c : '?');
        }
        return sb.ToString().TrimEnd();
    }

    private static string MachineName(ushort machine) => machine switch
    {
        0x0000 => "unknown",
        0x014C => "i386",
        0x0162 => "r3000",
        0x0166 => "r4000",
        0x0169 => "wcemipsv2",
        0x01A2 => "sh3",
        0x01C0 => "arm",
        0x01C2 => "thumb",
        0x01C4 => "armnt",
        0x01F0 => "powerpc",
        0x0200 => "ia64",
        0x0266 => "mips16",
        0x0EBC => "efi-bytecode",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        0x8664 => "amd64",
        0xAA64 => "arm64",
        _ => "0x" + machine.ToString("X4")
    };

    private static string SubsystemName(ushort subsystem) => subsystem switch
    {
        0 => "unknown",
        1 => "native",
        2 => "windows-gui",
        3 => "windows-cui",
        5 => "os2-cui",
        7 => "posix-cui",
        8 => "native-windows",
        9 => "windows-ce-gui",
        10 => "efi-application",
        11 => "efi-boot-service-driver",
        12 => "efi-runtime-driver",
        13 => "efi-rom",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => subsystem.ToString(System.Globalization.CultureInfo.InvariantCulture)
    };
}
