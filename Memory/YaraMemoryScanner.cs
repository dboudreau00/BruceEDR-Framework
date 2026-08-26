#if YARA_ENABLED
using dnYara;
#endif
using BruceEDR.Detection;

namespace BruceEDR.Memory;

/// <summary>
/// YARA-backed memory scanner. The real implementation is compiled in ONLY when the
/// project is built with -p:EnableYara=true (which adds the dnYara package and
/// defines YARA_ENABLED). Otherwise this is a stub whose <see cref="Available"/> is
/// false, so the composition root transparently falls back to the builtin scanner.
/// This keeps the default build free of any dependency on dnYara's API surface,
/// whose exact method names vary across versions.
/// </summary>
public sealed class YaraMemoryScanner : IMemoryScanner, IDisposable
{
#if YARA_ENABLED
    private readonly YaraContext? _ctx;
    private readonly CompiledRules? _rules;
    private readonly Scanner? _scanner;

    public bool Available { get; }

    public YaraMemoryScanner(string rulesPath, Action<string> log)
    {
        try
        {
            var files = Directory.Exists(rulesPath)
                ? Directory.GetFiles(rulesPath, "*.yar", SearchOption.AllDirectories)
                : Array.Empty<string>();

            if (files.Length == 0)
            {
                log($"yara: no .yar rules found under '{rulesPath}'; using builtin scanner");
                Available = false;
                return;
            }

            _ctx = new YaraContext();
            using var compiler = new Compiler();   // dispose the native YR_COMPILER after Compile()
            foreach (var f in files) compiler.AddRuleFile(f);
            _rules = compiler.Compile();
            _scanner = new Scanner();
            Available = _rules != null;
            if (Available) log($"yara: compiled {files.Length} rule file(s)");
        }
        catch (Exception ex)
        {
            log($"yara init failed ({ex.Message}); using builtin scanner");
            Available = false;
        }
    }

    public IReadOnlyList<string> Scan(int pid)
    {
        if (!Available || _scanner is null || _rules is null) return Array.Empty<string>();

        var hits = new HashSet<string>();
        ProcessMemoryReader.ReadRegions(pid, (buf, len) =>
        {
            try
            {
                byte[] slice = len == buf.Length ? buf : buf[..len];
                var results = _scanner.ScanMemory(ref slice, _rules);
                foreach (var r in results)
                    if (r.MatchingRule?.Identifier is { } id) hits.Add(id);
            }
            catch { /* skip this region */ }
            return hits.Count < 64;
        });

        return hits.Count == 0 ? Array.Empty<string>() : hits.ToArray();
    }

    public void Dispose()
    {
        try { _rules?.Dispose(); } catch { }
        try { _ctx?.Dispose(); } catch { }
    }
#else
    public bool Available => false;

    public YaraMemoryScanner(string rulesPath, Action<string> log)
        => log("yara engine not compiled in (rebuild with -p:EnableYara=true); using builtin scanner");

    public IReadOnlyList<string> Scan(int pid) => Array.Empty<string>();

    public void Dispose() { }
#endif
}
