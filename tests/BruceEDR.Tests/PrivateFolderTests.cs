using System.Diagnostics;
using BruceEDR.Activity;
using BruceEDR.Hosting;
using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Links for the tests below. Symbolic links need a privilege (or Developer Mode) on Windows,
/// junctions need Windows; a helper that cannot make its link returns null and the test that
/// needed it returns early, so these tests prove what the platform lets them prove and pass
/// elsewhere. The junction tests are the Windows half: they only assert on Windows.
/// </summary>
internal static class Links
{
    public static string NewDir()
    {
        string d = Path.Combine(Path.GetTempPath(), "bruce-links-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    public static string? DirectoryLink(string link, string target)
    {
        try { Directory.CreateSymbolicLink(link, target); return link; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException) { return null; }
    }

    public static string? FileLink(string link, string target)
    {
        try { File.CreateSymbolicLink(link, target); return link; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException) { return null; }
    }

    /// <summary>A directory junction (Windows only; no privilege needed), or null.</summary>
    public static string? Junction(string link, string target)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            foreach (var a in new[] { "/c", "mklink", "/J", link, target }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            p.WaitForExit(10_000);
            return p.ExitCode == 0 && Directory.Exists(link) ? link : null;
        }
        catch { return null; }
    }

    public static void Clean(string dir)
    {
        try
        {
            // Remove links first so a recursive delete can never walk into a target.
            foreach (var e in Directory.EnumerateFileSystemEntries(dir, "*", SearchOption.TopDirectoryOnly))
            {
                var attr = File.GetAttributes(e);
                if ((attr & FileAttributes.ReparsePoint) != 0)
                {
                    if ((attr & FileAttributes.Directory) != 0) Directory.Delete(e); else File.Delete(e);
                }
            }
            Directory.Delete(dir, recursive: true);
        }
        catch { }
    }
}

/// <summary>
/// H1: the agent writes, deletes and re-ACLs files in ProgramData\BruceEDR as SYSTEM, a folder a
/// standard user can create first. Every such step must refuse a link instead of following it.
/// </summary>
public sealed class PrivateFolderTests : IDisposable
{
    private readonly List<string> _dirs = new();

    private string Dir()
    {
        var d = Links.NewDir();
        _dirs.Add(d);
        return d;
    }

    public void Dispose()
    {
        foreach (var d in _dirs) Links.Clean(d);
    }

    private static ActivitySnapshot Snapshot() => new()
    {
        Name = "t",
        StartedUtc = DateTime.UtcNow.AddMinutes(-1),
        EndedUtc = DateTime.UtcNow
    };

    [Fact]
    public void A_private_folder_is_created_and_a_plain_one_accepted()
    {
        string dir = Path.Combine(Dir(), "private");
        Assert.Null(SafePaths.EnsurePrivateDirectory(dir, requireAdministrativeOwner: false));
        Assert.True(Directory.Exists(dir));
        Assert.Null(SafePaths.EnsurePrivateDirectory(dir, requireAdministrativeOwner: false));   // idempotent
    }

    [Fact]
    public void A_folder_that_is_a_link_is_refused_not_followed()
    {
        string root = Dir();
        string target = Path.Combine(root, "elsewhere");
        Directory.CreateDirectory(target);
        string? link = Links.DirectoryLink(Path.Combine(root, "BruceEDR"), target);
        if (link is null) return;   // no symlink privilege on this machine

        Assert.NotNull(SafePaths.FindLink(Path.Combine(link, "heartbeat")));
        Assert.Contains("link", SafePaths.EnsurePrivateDirectory(link, requireAdministrativeOwner: false));
        Assert.Contains("link", SafePaths.EnsurePrivateDirectory(Path.Combine(link, "sessions"), requireAdministrativeOwner: false));
        Assert.False(Directory.Exists(Path.Combine(target, "sessions")), "a folder was created through the link");
    }

    [Fact]
    public void A_session_is_not_saved_through_a_linked_folder()
    {
        string root = Dir();
        string target = Path.Combine(root, "elsewhere");
        Directory.CreateDirectory(target);
        string? link = Links.DirectoryLink(Path.Combine(root, "sessions"), target);
        if (link is null) return;

        Assert.Throws<IOException>(() => SessionStore.Save(link, Snapshot()));
        Assert.Empty(Directory.GetFiles(target));
    }

    [Fact]
    public void Deleting_a_session_named_by_a_link_removes_the_link_not_its_target()
    {
        string root = Dir();
        string victim = Path.Combine(root, "victim.txt");
        File.WriteAllText(victim, "keep me");
        string? link = Links.FileLink(Path.Combine(root, "old" + SessionStore.Extension), victim);
        if (link is null) return;

        SessionStore.Delete(link);
        Assert.Equal("keep me", File.ReadAllText(victim));
    }

    [Fact]
    public void A_heartbeat_name_planted_as_a_link_is_never_written_through()
    {
        string root = Dir();
        string victim = Path.Combine(root, "victim.txt");
        File.WriteAllText(victim, "keep me");
        string? link = Links.FileLink(Path.Combine(root, "heartbeat"), victim);
        if (link is null) return;

        try { SafePaths.WritePrivateFile(link, new byte[] { (byte)'1' }); }
        catch (IOException) { /* refusing is as good as replacing the link */ }
        Assert.Equal("keep me", File.ReadAllText(victim));
    }

    [Fact]
    public void A_heartbeat_folder_that_cannot_be_trusted_falls_back_beside_the_agent()
    {
        string root = Dir();
        string target = Path.Combine(root, "elsewhere");
        Directory.CreateDirectory(target);
        string? link = Links.DirectoryLink(Path.Combine(root, "BruceEDR"), target);
        if (link is null) return;

        string? resolved = Watchdog.ResolveHeartbeatPath(Path.Combine(link, "heartbeat"));
        Assert.NotNull(resolved);
        Assert.StartsWith(Path.Combine(AppContext.BaseDirectory, "state"), resolved);
    }

    [Fact]
    public void Plain_files_are_written_and_deleted_by_the_safe_helpers()
    {
        string file = Path.Combine(Dir(), "heartbeat");
        SafePaths.WritePrivateFile(file, new byte[] { (byte)'1' });
        SafePaths.WritePrivateFile(file, new byte[] { (byte)'2', (byte)'2' });
        Assert.Equal("22", File.ReadAllText(file));
        Assert.True(SafePaths.DeleteFile(file));
        Assert.False(File.Exists(file));
        Assert.False(SafePaths.DeleteFile(file));
    }

    // ------------------------------------------------------------ Windows only: junctions

    [Fact]
    public void Windows_a_junction_in_place_of_the_folder_is_refused_and_its_target_untouched()
    {
        if (!OperatingSystem.IsWindows()) return;
        string root = Dir();
        string target = Path.Combine(root, "elsewhere");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "victim" + SessionStore.Extension), "keep me");
        string? junction = Links.Junction(Path.Combine(root, "sessions"), target);
        Assert.NotNull(junction);

        Assert.NotNull(SafePaths.EnsurePrivateDirectory(junction!, requireAdministrativeOwner: false));
        Assert.Throws<IOException>(() => SessionStore.Save(junction!, Snapshot()));
        Assert.Throws<IOException>(() => SafePaths.DeleteFile(Path.Combine(junction!, "victim" + SessionStore.Extension)));
        Assert.Equal("keep me", File.ReadAllText(Path.Combine(target, "victim" + SessionStore.Extension)));
        Assert.False(SecretFiles.IsProtected(target), "the junction's target was re-ACLed");
    }
}
