using BruceEDR.Hosting;
using Xunit;

namespace BruceEDR.Tests;

/// <summary>
/// Pins what one start of BruceEDR.exe does. The incident behind this: double-clicking the
/// console exe went straight to a live agent in a console window. A bare launch must open
/// the desktop app, and only an explicit --console may run the agent there.
/// </summary>
public class LaunchModeTests
{
    private static LaunchMode Resolve(params string[] args) => LaunchModes.Resolve(args, runningAsService: false);

    [Fact]
    public void A_double_click_opens_the_desktop_app()
        => Assert.Equal(LaunchMode.DesktopApp, Resolve());

    [Fact]
    public void An_old_shortcut_passing_only_a_config_still_opens_the_desktop_app()
        => Assert.Equal(LaunchMode.DesktopApp, Resolve("--config", @"C:\bruce\bruce.config.json"));

    [Theory]
    [InlineData("--console")]
    [InlineData("--CONSOLE")]
    public void Only_an_explicit_console_flag_runs_the_live_agent_in_a_console(string flag)
    {
        Assert.Equal(LaunchMode.Console, Resolve(flag));
        Assert.Equal(LaunchMode.Console, Resolve("--config", "x.json", flag));
    }

    [Fact]
    public void Unknown_arguments_never_fall_through_to_the_live_agent()
        => Assert.Equal(LaunchMode.DesktopApp, Resolve("--run", "--start", "-c", "console"));

    [Fact]
    public void The_service_host_is_unaffected_by_the_console_gate()
    {
        // The SCM starts the exe as `BruceEDR.exe --config <path>`, with no --console.
        Assert.Equal(LaunchMode.Service, LaunchModes.Resolve(new[] { "--config", "c.json" }, runningAsService: true));
    }

    [Theory]
    [InlineData(LaunchMode.Help, "--help")]
    [InlineData(LaunchMode.Help, "-h")]
    [InlineData(LaunchMode.SelfTest, "--selftest")]
    [InlineData(LaunchMode.Install, "--install")]
    [InlineData(LaunchMode.Uninstall, "--uninstall")]
    [InlineData(LaunchMode.Watchdog, "--watchdog")]
    [InlineData(LaunchMode.Cleanup, "--cleanup")]
    public void Maintenance_commands_keep_their_meaning(LaunchMode expected, string flag)
    {
        Assert.Equal(expected, Resolve(flag));
        // ...and win over --console, exactly as the old if-chain ordered them.
        Assert.Equal(expected, Resolve("--console", flag));
    }
}
