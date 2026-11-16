using BruceEDR.Configuration;
using BruceEDR.Driver;
using BruceEDR.Hosting;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// H4: the config file steers the SYSTEM service (response mode, kernel exemptions, the control
/// token) and is hot-reloaded, so it must be as admin-only as the exe. The install location must
/// be admin-only by its ACLs, not just by its prefix: %SystemRoot%\Temp is under the Windows
/// directory and writable by every user.
/// </summary>
public sealed class ConfigTrustTests : IDisposable
{
    private readonly string _root = Links.NewDir();

    public void Dispose() => Links.Clean(_root);

    [Fact]
    public void A_config_whose_acl_lets_a_user_write_is_not_trusted()
    {
        string cfg = Path.Combine(_root, "bruce.config.json");
        File.WriteAllText(cfg, "{}");

        string? problem = ConfigLoader.TrustProblem(cfg, _ => @"C:\Users\bob is owned by bob");
        Assert.NotNull(problem);
        Assert.Contains("not admin-only", problem);
        Assert.Contains("owned by bob", problem);
        Assert.Null(ConfigLoader.TrustProblem(cfg, _ => null));
    }

    [Fact]
    public void The_check_is_made_on_the_full_path()
    {
        string? seen = null;
        ConfigLoader.TrustProblem("relative.json", p => { seen = p; return null; });
        Assert.Equal(Path.GetFullPath("relative.json"), seen);
    }

    [Fact]
    public void A_config_reached_through_a_link_is_not_trusted()
    {
        string real = Path.Combine(_root, "real");
        Directory.CreateDirectory(real);
        File.WriteAllText(Path.Combine(real, "bruce.config.json"), "{}");
        string? link = Links.DirectoryLink(Path.Combine(_root, "linked"), real);
        if (link is null) return;   // no symlink privilege on this machine

        string? problem = ConfigLoader.TrustProblem(Path.Combine(link, "bruce.config.json"), _ => null);
        Assert.NotNull(problem);
        Assert.Contains("link", problem);
    }

    [Fact]
    public void Off_Windows_there_are_no_acls_to_refuse_on()
    {
        if (OperatingSystem.IsWindows()) return;
        Assert.Null(ConfigLoader.TrustProblem(Path.Combine(_root, "bruce.config.json")));
    }

    [Fact]
    public void An_install_location_outside_the_protected_roots_is_refused_whatever_its_acl()
    {
        Assert.False(ServiceControl.IsProtectedInstallLocation(Path.Combine(_root, "BruceEDR.exe"), out string why, _ => null));
        Assert.Contains("SYSTEM", why);
    }

    // ------------------------------------------------------------ Windows only

    [Fact]
    public void Windows_an_install_location_under_a_protected_root_must_also_pass_the_acl_check()
    {
        if (!OperatingSystem.IsWindows()) return;
        string pf = Environment.GetEnvironmentVariable("ProgramFiles")!;
        string exe = Path.Combine(pf, "BruceEDR", "BruceEDR.exe");

        Assert.True(ServiceControl.IsProtectedInstallLocation(exe, out _, _ => null));
        Assert.False(ServiceControl.IsProtectedInstallLocation(exe, out string why, _ => "BUILTIN\\Users can write it"));
        Assert.Contains("Users can write", why);
    }

    [Fact]
    public void Windows_the_user_writable_Windows_Temp_is_not_a_protected_install_location()
    {
        if (!OperatingSystem.IsWindows()) return;
        string temp = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot")!, "Temp", "BruceEDR", "BruceEDR.exe");
        Assert.False(ServiceControl.IsProtectedInstallLocation(temp, out _));
    }

    [Fact]
    public void Windows_a_config_in_the_users_temp_folder_is_not_trusted()
    {
        if (!OperatingSystem.IsWindows()) return;
        string cfg = Path.Combine(_root, "bruce.config.json");
        File.WriteAllText(cfg, "{}");
        Assert.NotNull(KernelPolicy.WriteRiskOfNearest(cfg));
        Assert.NotNull(ConfigLoader.TrustProblem(cfg));
        Assert.NotNull(ConfigLoader.TrustProblem(Path.Combine(_root, "missing.json")));   // users could create it
    }
}
