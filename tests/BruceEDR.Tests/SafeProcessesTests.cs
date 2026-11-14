using BruceEDR.Configuration;
using BruceEDR.Core;
using BruceEDR.Hosting;
using BruceEDR.Response;
using BruceEDR.Telemetry;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// The safe-process lists: programs containment leaves alone. An entry must not become a way to
/// put a program beyond containment, so every shortcut is refused here.
/// </summary>
public sealed class SafeProcessesTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "bruce-safe-" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _notes = new();

    public SafeProcessesTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    private IReadOnlyList<string> Parse(string json) => SafeProcesses.Parse("test.json", json, _notes.Add);

    [Fact]
    public void Entries_are_full_paths_with_environment_variables_expanded()
    {
        var images = Parse("""
            { "processes": [
                { "image": "%SystemRoot%\\System32\\wbem\\WmiPrvSE.exe", "why": "WMI" },
                { "image": "C:/Program Files/Vendor/../Vendor/agent.exe" }
            ] }
            """);

        Assert.Equal(new[]
        {
            Path.Combine(Environment.GetEnvironmentVariable("SystemRoot")!, @"System32\wbem\WmiPrvSE.exe"),
            @"C:\Program Files\Vendor\agent.exe",
        }, images);
        Assert.Empty(_notes);
    }

    [Theory]
    [InlineData("WmiPrvSE.exe")]
    [InlineData("wbem\\WmiPrvSE.exe")]
    [InlineData("%NoSuchVariable%\\agent.exe")]
    [InlineData("")]
    public void A_name_or_a_partial_path_is_ignored(string image)
    {
        var images = Parse($$"""{ "processes": [ { "image": "{{image.Replace("\\", "\\\\")}}" } ] }""");

        Assert.Empty(images);
        Assert.Contains(_notes, n => n.Contains("not a full image path"));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData(@"C:\Windows\System32\cmd.exe")]
    [InlineData(@"C:\Windows\System32\rundll32.exe")]
    [InlineData(@"C:\Windows\SysWOW64\mshta.exe")]
    public void A_script_host_can_never_be_safe(string image)
    {
        var images = Parse($$"""{ "processes": [ { "image": "{{image.Replace("\\", "\\\\")}}" } ] }""");

        Assert.Empty(images);
        Assert.Contains(_notes, n => n.Contains("can never be safe"));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("""{ "programs": [] }""")]
    public void A_file_that_is_not_a_list_loads_nothing_and_says_so(string json)
    {
        Assert.Empty(Parse(json));
        Assert.Contains(_notes, n => n.Contains("not loaded"));
    }

    [Fact]
    public void Matching_ignores_case_and_path_spelling()
    {
        var safe = SafeProcesses.Of(@"%SystemRoot%\System32\SearchIndexer.exe");
        string root = Environment.GetEnvironmentVariable("SystemRoot")!;

        Assert.True(safe.Contains(Path.Combine(root, @"system32\searchindexer.exe").ToUpperInvariant()));
        Assert.True(safe.Contains(Path.Combine(root, @"System32\..\System32\SearchIndexer.exe")));
        Assert.False(safe.Contains(Path.Combine(root, @"SysWOW64\SearchIndexer.exe")));
        Assert.False(safe.Contains(null));
        Assert.False(safe.Contains("SearchIndexer.exe"));
    }

    [Fact]
    public void A_list_file_a_standard_user_could_edit_is_not_loaded()
    {
        File.WriteAllText(Path.Combine(_dir, "a.json"), """{ "processes": [ { "image": "C:\\Tools\\a.exe" } ] }""");
        File.WriteAllText(Path.Combine(_dir, "b.json"), """{ "processes": [ { "image": "C:\\Tools\\b.exe" } ] }""");

        var safe = SafeProcesses.Load(_dir, f => f.EndsWith("b.json") ? "b.json can be changed by Users" : null, _notes.Add);

        Assert.Equal(new[] { @"C:\Tools\a.exe" }, safe.Images);
        Assert.Contains("b.json not loaded: b.json can be changed by Users", _notes);
    }

    [Fact]
    public void The_agent_skips_a_list_folder_a_standard_user_can_write()
    {
        // A temp folder is the user's own, so its lists must not reach the SYSTEM agent.
        File.WriteAllText(Path.Combine(_dir, "planted.json"),
            """{ "processes": [ { "image": "%SystemRoot%\\System32\\wbem\\WmiPrvSE.exe" } ] }""");
        var sink = new CaptureSink();

        var safe = Composition.LoadSafeProcesses(new ResponseConfig { SafeProcessesPath = _dir }, new Logger(sink));

        Assert.Equal(0, safe.Count);
        Assert.Contains(sink.Messages, m => m.Contains("planted.json not loaded"));
    }

    [Fact]
    public void An_empty_path_turns_the_lists_off()
        => Assert.Equal(0, Composition.LoadSafeProcesses(new ResponseConfig { SafeProcessesPath = "" }, new Logger(new CaptureSink())).Count);

    [Fact]
    public void Every_shipped_list_parses_without_a_note()
    {
        var shipped = FindShippedFolder();
        var files = Directory.GetFiles(shipped, "*.json");
        Assert.NotEmpty(files);
        foreach (var file in files)
        {
            var images = SafeProcesses.Parse(Path.GetFileName(file), File.ReadAllText(file), _notes.Add);
            Assert.NotEmpty(images);
        }
        Assert.Empty(_notes);
    }

    private static string FindShippedFolder()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var probe = Path.Combine(dir.FullName, "safe-processes");
            if (Directory.Exists(probe) && File.Exists(Path.Combine(dir.FullName, "BruceEDR.sln"))) return probe;
        }
        throw new DirectoryNotFoundException("safe-processes was not found next to BruceEDR.sln above " + AppContext.BaseDirectory);
    }

    private sealed class CaptureSink : IEventSink
    {
        private readonly List<string> _messages = new();
        public void Emit(BruceEvent e) { lock (_messages) _messages.Add(e.Message); }
        public void Dispose() { }
        public string[] Messages { get { lock (_messages) return _messages.ToArray(); } }
    }
}
