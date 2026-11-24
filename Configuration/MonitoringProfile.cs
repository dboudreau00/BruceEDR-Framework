namespace BruceEDR.Configuration;

/// <summary>
/// The ready-made monitoring profiles offered on the set-up screen. A profile is a starting point: the
/// scores it sets can still be edited, and the only part of it the engine reads at run time is
/// <see cref="Preset.OwnStores"/>.
/// </summary>
public static class MonitoringProfiles
{
    /// <summary>Everything unusual counts, including a program reading its own data. How 3.4.5 and earlier behave.</summary>
    public const string Aggressive = "aggressive";

    /// <summary>A program reading a folder named after itself is not flagged for it, and a score needs more evidence to list.</summary>
    public const string Neutral = "neutral";

    public sealed record Preset(string Id, string Title, string Summary, int WarnAt, int ContainAt, bool OwnStores);

    public static readonly Preset AggressivePreset = new(Aggressive, "Aggressive",
        "Flags anything unusual, including a program reading its own cookies or settings. Expect more to review.",
        WarnAt: 40, ContainAt: 70, OwnStores: false);

    public static readonly Preset NeutralPreset = new(Neutral, "Neutral",
        "A program reading a folder named after itself is not flagged. Scores need a little more evidence before they list.",
        WarnAt: 50, ContainAt: 80, OwnStores: true);

    public static IReadOnlyList<Preset> All { get; } = new[] { AggressivePreset, NeutralPreset };

    /// <summary>The canonical id for whatever a config says. Anything unknown, or missing, is Aggressive: the behaviour before profiles.</summary>
    public static string Normalize(string? id)
        => string.Equals(id?.Trim(), Neutral, StringComparison.OrdinalIgnoreCase) ? Neutral : Aggressive;

    public static Preset Get(string? id) => Normalize(id) == Neutral ? NeutralPreset : AggressivePreset;

    /// <summary>True when the profile exempts a program from store rules for its own folder.</summary>
    public static bool ExemptsOwnStores(string? id) => Get(id).OwnStores;
}
