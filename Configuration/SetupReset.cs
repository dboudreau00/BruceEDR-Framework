namespace BruceEDR.Configuration;

/// <summary>
/// "Set up again": puts the choices the set-up screen makes back to how a fresh install starts, without
/// uninstalling. Only those choices move (response mode, monitoring profile and its scores, trusted publishers
/// and, if asked, the trust marks made from the baseline scan and the Allow button). Everything else in the
/// config, such as telemetry paths, the Assistant, API Studio, kernel settings and the operator's own
/// watchlist rules, is left as it is. The config is copied to a dated backup first.
/// </summary>
public static class SetupReset
{
    /// <summary>Written by the baseline scan on every entry it adds.</summary>
    public const string BaselineNoteTag = "[baseline]";

    /// <summary>The start of the note the Dashboard's Allow button writes.</summary>
    public const string DashboardAllowNote = "Allowed from the dashboard";

    public sealed record Result(string BackupPath, int TrustEntriesRemoved);

    /// <summary>
    /// Resets the set-up choices in <paramref name="configPath"/> and returns where the backup went. Throws if the
    /// config cannot be read or written, having changed nothing.
    /// </summary>
    public static Result Run(string configPath, bool clearTrustMarks, DateTime? now = null)
    {
        var config = ConfigLoader.Load(configPath);

        // Backup first: a failure here must stop everything, so the config is never changed without one.
        string stamp = (now ?? DateTime.Now).ToString("yyyyMMdd-HHmmss");
        string backup = configPath + ".bak-" + stamp;
        for (int i = 2; File.Exists(backup); i++) backup = configPath + ".bak-" + stamp + "-" + i;
        File.Copy(configPath, backup);

        var fresh = new BruceConfig();   // what a new install starts with
        config.Response.Mode = fresh.Response.Mode;
        config.Detection.Profile = fresh.Detection.Profile;
        config.Detection.WarnThreshold = fresh.Detection.WarnThreshold;
        config.Detection.QuarantineThreshold = fresh.Detection.QuarantineThreshold;
        config.Allowlist.Publishers = fresh.Allowlist.Publishers;

        int removed = 0;
        if (clearTrustMarks)
        {
            var kept = (config.Watchlist.Entries ?? Array.Empty<WatchlistEntryConfig>())
                .Where(e => !IsTrustMark(e)).ToArray();
            removed = (config.Watchlist.Entries?.Length ?? 0) - kept.Length;
            config.Watchlist.Entries = kept;
        }

        ConfigLoader.Save(config, configPath);
        return new Result(backup, removed);
    }

    /// <summary>An entry made by a trust choice (baseline scan, or the Allow button) rather than written by the operator.</summary>
    public static bool IsTrustMark(WatchlistEntryConfig e)
    {
        string note = e.Note ?? "";
        if (note.Contains(BaselineNoteTag, StringComparison.OrdinalIgnoreCase)) return true;
        return string.Equals(e.Action, "allow", StringComparison.OrdinalIgnoreCase)
               && note.Contains(DashboardAllowNote, StringComparison.OrdinalIgnoreCase);
    }
}
