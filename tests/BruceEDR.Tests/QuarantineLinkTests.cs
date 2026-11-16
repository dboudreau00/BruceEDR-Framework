using System.Diagnostics;
using BruceEDR.Response;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// H2: the archive path a quarantine acts on is chosen by the suspect process. Store must read
/// and delete the file the path names and nothing else, and Restore must not write through a
/// link into somewhere the analyst never chose.
/// </summary>
public sealed class QuarantineLinkTests : IDisposable
{
    private readonly string _root = Links.NewDir();

    public void Dispose() => Links.Clean(_root);

    private string Sub(string name)
    {
        string p = Path.Combine(_root, name);
        Directory.CreateDirectory(p);
        return p;
    }

    private string Victim()
    {
        string protectedDir = Sub("protected");
        string victim = Path.Combine(protectedDir, "victim.dll");
        File.WriteAllText(victim, "system file");
        return victim;
    }

    [Fact]
    public void A_plain_archive_is_stored_deleted_and_restorable()
    {
        string src = Path.Combine(Sub("staging"), "loot.zip");
        File.WriteAllText(src, "payload");
        using var vault = new QuarantineVault(Sub("vault"));

        var entry = vault.Store(src, "r", 1, "p.exe", true, out string error);
        Assert.NotNull(entry);
        Assert.Equal("", error);
        Assert.False(File.Exists(src));

        string restored = Path.Combine(_root, "restore", "loot.zip");
        Assert.True(vault.Restore(entry!.Id, restored, out error), error);
        Assert.Equal("payload", File.ReadAllText(restored));
    }

    [Fact]
    public void An_archive_that_is_a_link_is_refused_and_its_target_kept()
    {
        string victim = Victim();
        string? link = Links.FileLink(Path.Combine(Sub("staging"), "loot.zip"), victim);
        if (link is null) return;   // no symlink privilege on this machine
        using var vault = new QuarantineVault(Sub("vault"));

        Assert.Null(vault.Store(link, "r", 1, "p.exe", true, out string error));
        Assert.Contains("link", error);
        Assert.Equal("system file", File.ReadAllText(victim));
        Assert.Empty(vault.List());
    }

    [Fact]
    public void An_archive_whose_folder_is_a_link_is_refused_and_the_target_kept()
    {
        string victim = Victim();
        string? link = Links.DirectoryLink(Path.Combine(_root, "staging"), Path.GetDirectoryName(victim)!);
        if (link is null) return;
        using var vault = new QuarantineVault(Sub("vault"));

        Assert.Null(vault.Store(Path.Combine(link, "victim.dll"), "r", 1, "p.exe", true, out string error));
        Assert.Contains("link", error);
        Assert.Equal("system file", File.ReadAllText(victim));
    }

    [Fact]
    public void Restore_never_writes_through_a_linked_folder()
    {
        string src = Path.Combine(Sub("staging"), "loot.zip");
        File.WriteAllText(src, "payload");
        using var vault = new QuarantineVault(Sub("vault"));
        var entry = vault.Store(src, "r", 1, "p.exe", true, out _);
        Assert.NotNull(entry);

        string target = Sub("System32");
        string? link = Links.DirectoryLink(Path.Combine(_root, "Downloads"), target);
        if (link is null) return;

        Assert.False(vault.Restore(entry!.Id, Path.Combine(link, "loot.zip"), out string error));
        Assert.Contains("link", error);
        Assert.Empty(Directory.GetFiles(target));
    }

    [Fact]
    public void Restore_never_follows_a_link_planted_at_the_destination_name()
    {
        string src = Path.Combine(Sub("staging"), "loot.zip");
        File.WriteAllText(src, "payload");
        using var vault = new QuarantineVault(Sub("vault"));
        var entry = vault.Store(src, "r", 1, "p.exe", true, out _);
        Assert.NotNull(entry);

        // A dangling link: File.Exists says no, but writing to the name would create the target.
        string target = Path.Combine(Sub("System32"), "evil.dll");
        string? link = Links.FileLink(Path.Combine(Sub("Downloads"), "loot.zip"), target);
        if (link is null) return;

        Assert.False(vault.Restore(entry!.Id, link, out _));
        Assert.False(File.Exists(target));
    }

    [Fact]
    public void A_vault_folder_that_is_a_link_is_refused()
    {
        string target = Sub("elsewhere");
        string? link = Links.DirectoryLink(Path.Combine(_root, "vault"), target);
        if (link is null) return;

        Assert.ThrowsAny<IOException>(() => new QuarantineVault(link));
        Assert.Empty(Directory.GetFileSystemEntries(target));
    }

    // ------------------------------------------------------------ Windows only

    [Fact]
    public void Windows_an_archive_behind_a_junction_is_refused_and_the_target_kept()
    {
        if (!OperatingSystem.IsWindows()) return;
        string victim = Victim();
        string? junction = Links.Junction(Path.Combine(_root, "staging"), Path.GetDirectoryName(victim)!);
        Assert.NotNull(junction);
        using var vault = new QuarantineVault(Sub("vault"));

        Assert.Null(vault.Store(Path.Combine(junction!, "victim.dll"), "r", 1, "p.exe", true, out string error));
        Assert.Contains("resolves to", error);
        Assert.Equal("system file", File.ReadAllText(victim));
    }

    [Fact]
    public void Windows_an_archive_with_a_second_hard_link_is_refused_and_both_names_kept()
    {
        if (!OperatingSystem.IsWindows()) return;
        string victim = Victim();
        string hard = Path.Combine(Sub("staging"), "loot.zip");
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        { UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in new[] { "/c", "mklink", "/H", hard, victim }) psi.ArgumentList.Add(a);
        using (var p = Process.Start(psi)!) p.WaitForExit(10_000);
        Assert.True(File.Exists(hard));
        using var vault = new QuarantineVault(Sub("vault"));

        Assert.Null(vault.Store(hard, "r", 1, "p.exe", true, out string error));
        Assert.Contains("hard link", error);
        Assert.True(File.Exists(hard));
        Assert.Equal("system file", File.ReadAllText(victim));
    }
}
