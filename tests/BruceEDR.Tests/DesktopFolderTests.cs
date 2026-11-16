using BruceEDR.Assistant;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// H3: the elevated desktop app keeps triage records and assistant keys under %LOCALAPPDATA%,
/// which the analyst's own non-elevated processes can rearrange. A folder or file there that
/// is a link must be refused, never followed by an elevated write, delete or DACL change.
/// </summary>
public sealed class DesktopFolderTests : IDisposable
{
    private readonly string _root = Links.NewDir();

    public void Dispose() => Links.Clean(_root);

    private string Victim()
    {
        string dir = Path.Combine(_root, "ProgramFiles");
        Directory.CreateDirectory(dir);
        string victim = Path.Combine(dir, "BruceEDR.exe");
        File.WriteAllText(victim, "binary");
        return victim;
    }

    [Fact]
    public void Plain_folders_work_as_before()
    {
        var triage = new TriageStore(Path.Combine(_root, "triage"));
        triage.SaveIncident(new IncidentCase { Key = "k1", UpdatedUtc = DateTime.UtcNow });
        triage.SaveIncident(new IncidentCase { Key = "k1", UpdatedUtc = DateTime.UtcNow, Pid = 7 });
        Assert.Equal(7, Assert.Single(triage.LoadIncidents()).Pid);
        triage.DeleteIncident("k1");
        Assert.Empty(triage.LoadIncidents());

        var keys = new ApiKeyStore(Path.Combine(_root, "assistant"));
        Assert.False(keys.Has(LlmProvider.Claude));
        keys.Delete(LlmProvider.Claude);   // nothing there: no throw
    }

    [Fact]
    public void A_triage_folder_swapped_for_a_link_is_refused()
    {
        string target = Path.GetDirectoryName(Victim())!;
        string? link = Links.DirectoryLink(Path.Combine(_root, "triage"), target);
        if (link is null) return;   // no symlink privilege on this machine

        Assert.ThrowsAny<IOException>(() => new TriageStore(link));
        Assert.False(Directory.Exists(Path.Combine(target, "incidents")), "a folder was created through the link");
    }

    [Fact]
    public void A_key_folder_swapped_for_a_link_is_refused()
    {
        string target = Path.GetDirectoryName(Victim())!;
        string? link = Links.DirectoryLink(Path.Combine(_root, "assistant"), target);
        if (link is null) return;

        Assert.ThrowsAny<IOException>(() => new ApiKeyStore(link));
    }

    [Fact]
    public void Clearing_incidents_removes_a_planted_link_not_its_target()
    {
        string victim = Victim();
        var triage = new TriageStore(Path.Combine(_root, "triage"));
        if (Links.FileLink(Path.Combine(triage.Root, "incidents", "planted.json"), victim) is null) return;

        triage.Clear();
        Assert.Equal("binary", File.ReadAllText(victim));
    }

    [Fact]
    public void Saving_an_incident_never_writes_through_a_planted_link()
    {
        string victim = Victim();
        var triage = new TriageStore(Path.Combine(_root, "triage"));
        if (Links.FileLink(Path.Combine(triage.Root, "incidents", "k2.json"), victim) is null) return;

        try { triage.SaveIncident(new IncidentCase { Key = "k2", UpdatedUtc = DateTime.UtcNow }); }
        catch (IOException) { /* refusing is as good as replacing the link */ }
        Assert.Equal("binary", File.ReadAllText(victim));
    }

    [Fact]
    public void Deleting_a_key_removes_a_planted_link_not_its_target()
    {
        string victim = Victim();
        string dir = Path.Combine(_root, "assistant");
        var keys = new ApiKeyStore(dir);
        if (Links.FileLink(Path.Combine(dir, "claude.key"), victim) is null) return;

        keys.Delete(LlmProvider.Claude);
        Assert.Equal("binary", File.ReadAllText(victim));
    }

    // ------------------------------------------------------------ Windows only

    [Fact]
    public void Windows_a_triage_folder_swapped_for_a_junction_is_refused_and_the_target_DACL_kept()
    {
        if (!OperatingSystem.IsWindows()) return;
        string target = Path.GetDirectoryName(Victim())!;
        string? junction = Links.Junction(Path.Combine(_root, "triage"), target);
        Assert.NotNull(junction);

        Assert.ThrowsAny<IOException>(() => new TriageStore(junction!));
        Assert.False(BruceEDR.Security.SecretFiles.IsProtected(target), "the junction's target was re-ACLed");
        Assert.False(Directory.Exists(Path.Combine(target, "incidents")));
    }
}
