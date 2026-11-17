using BruceEDR.Security;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// 3.4.3 made the elevated desktop app refuse any folder an administrator did not own, and its own
/// folders sit under the analyst's profile, so it could not start. The analyst's own account may own
/// those; the agent's ProgramData folders still need an administrative owner.
/// </summary>
public sealed class AnalystFolderTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "bruce-analyst-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    [Fact]
    public void A_folder_the_analyst_owns_under_the_profile_is_accepted_for_the_desktop_app()
    {
        if (!OperatingSystem.IsWindows()) return;
        string dir = Path.Combine(_root, "triage");
        Assert.Null(SafePaths.EnsurePrivateDirectory(dir, requireAdministrativeOwner: true, allowCurrentUserOwner: true));
        // A second start finds the folder it made (or one a previous version made) and still accepts it.
        Assert.Null(SafePaths.EnsurePrivateDirectory(dir, requireAdministrativeOwner: true, allowCurrentUserOwner: true));
    }

    [Fact]
    public void The_agents_folder_still_needs_an_administrative_owner()
    {
        if (!OperatingSystem.IsWindows() || SafePaths.ProcessIsAdministrative) return;   // an admin owns what it creates
        string dir = Path.Combine(_root, "agent");
        Assert.NotNull(SafePaths.EnsurePrivateDirectory(dir, requireAdministrativeOwner: true));
    }
}
