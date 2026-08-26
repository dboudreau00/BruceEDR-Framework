using System.Text;
using ProcessShield.Core;
using ProcessShield.Telemetry;

namespace ProcessShield.Gui.ViewModels;

/// <summary>A single process in the threat table. Severity drives the row signal colour.</summary>
public sealed class ThreatRow : ViewModelBase
{
    public int Pid { get; }
    public string Name { get; private set; } = "";
    public int Score { get; private set; }
    public int PeakScore { get; private set; }
    public string State { get; private set; } = "";
    public string Severity { get; private set; } = "watch";   // safe | watch | threat
    public bool Trusted { get; private set; }
    public string Trust => Trusted ? "signed" : "—";
    public string ImagePath { get; private set; } = "";
    public string CommandLine { get; private set; } = "";
    public string IncidentId { get; private set; } = "";
    public string FirstSeen { get; private set; } = "";
    public IReadOnlyList<string> Reasons { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> StagedArchives { get; private set; } = Array.Empty<string>();
    /// <summary>MITRE ATT&amp;CK technique ids observed for this process, for detail chips.</summary>
    public IReadOnlyList<string> Techniques { get; private set; } = Array.Empty<string>();
    /// <summary>Ancestry rendered nearest-parent-first, e.g. "explorer.exe → cmd.exe".</summary>
    public string Ancestry { get; private set; } = "";
    public bool HasAncestry => Ancestry.Length > 0;
    public bool HasCommandLine => CommandLine.Length > 0;
    public bool HasTechniques => Techniques.Count > 0;

    public ThreatRow(ProfileSnapshot s)
    {
        Pid = s.Pid;
        Update(s);
    }

    public void Update(ProfileSnapshot s)
    {
        Name = s.ProcessName;
        Score = s.Score;
        PeakScore = s.PeakScore;
        Trusted = s.Trusted;
        ImagePath = s.ImagePath;
        CommandLine = s.CommandLine;
        IncidentId = s.IncidentId;
        FirstSeen = s.FirstSeenUtc.ToLocalTime().ToString("HH:mm:ss");
        Reasons = s.Reasons;
        StagedArchives = s.StagedArchives;
        Techniques = s.Techniques;
        Ancestry = s.Ancestry.Count > 0
            ? string.Join(" → ", s.Ancestry.Reverse().Append(s.ProcessName))
            : "";
        State = s.Terminated ? "Terminated"
              : s.SuspendedByAnalyst ? "Suspended"
              : s.Contained ? "Contained"
              : "Flagged";
        Severity = s.Terminated ? "safe"
                 : s.Contained ? "threat"
                 : s.Trusted ? "safe"
                 : s.Score >= 70 ? "threat"
                 : "watch";

        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Score));
        OnPropertyChanged(nameof(PeakScore));
        OnPropertyChanged(nameof(State));
        OnPropertyChanged(nameof(Severity));
        OnPropertyChanged(nameof(Trusted));
        OnPropertyChanged(nameof(Trust));
        OnPropertyChanged(nameof(ImagePath));
        OnPropertyChanged(nameof(CommandLine));
        OnPropertyChanged(nameof(IncidentId));
        OnPropertyChanged(nameof(FirstSeen));
        OnPropertyChanged(nameof(Reasons));
        OnPropertyChanged(nameof(StagedArchives));
        OnPropertyChanged(nameof(Techniques));
        OnPropertyChanged(nameof(Ancestry));
        OnPropertyChanged(nameof(HasAncestry));
        OnPropertyChanged(nameof(HasCommandLine));
        OnPropertyChanged(nameof(HasTechniques));
    }

    /// <summary>True when the search text matches the name, pid, path or state.</summary>
    public bool Matches(string needle)
        => needle.Length == 0
        || Name.Contains(needle, StringComparison.OrdinalIgnoreCase)
        || State.Contains(needle, StringComparison.OrdinalIgnoreCase)
        || ImagePath.Contains(needle, StringComparison.OrdinalIgnoreCase)
        || Pid.ToString().Contains(needle, StringComparison.Ordinal);

    /// <summary>Plain-text incident report for the clipboard (analyst hand-off).</summary>
    public string ToReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"ProcessShield incident report — {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"process   : {Name} (pid {Pid})");
        if (IncidentId.Length > 0) sb.AppendLine($"incident  : {IncidentId}");
        sb.AppendLine($"state     : {State}   score {Score} (peak {PeakScore})   {(Trusted ? "signed" : "unsigned")}");
        sb.AppendLine($"image     : {ImagePath}");
        if (HasCommandLine) sb.AppendLine($"cmdline   : {CommandLine}");
        if (HasAncestry) sb.AppendLine($"ancestry  : {Ancestry}");
        if (HasTechniques) sb.AppendLine($"techniques: {string.Join(", ", Techniques)}");
        if (Reasons.Count > 0)
        {
            sb.AppendLine("why it flagged:");
            foreach (var r in Reasons) sb.AppendLine("  - " + r);
        }
        if (StagedArchives.Count > 0)
        {
            sb.AppendLine("staged archives:");
            foreach (var a in StagedArchives) sb.AppendLine("  - " + a);
        }
        return sb.ToString();
    }
}

/// <summary>A line in the live event feed. Keeps the raw event for export and copy.</summary>
public sealed class EventRow
{
    public ShieldEvent Raw { get; }
    public string Time { get; }
    public string Level { get; }       // QUARANTINE | WARN | ACTION | ERROR | INFO
    public string Category { get; }
    public string Text { get; }

    /// <summary>Everything worth grepping, so the search box finds rules/techniques too.</summary>
    public string SearchText { get; }

    /// <summary>Hover detail: category plus the rule/technique context the row elides.</summary>
    public string Tooltip { get; }

    public EventRow(ShieldEvent e)
    {
        Raw = e;
        Time = e.TimeUtc.ToLocalTime().ToString("HH:mm:ss");
        Level = e.Level;
        Category = e.Category;
        Text = e.Pid > 0
            ? $"pid {e.Pid} {e.Process} — {(string.IsNullOrEmpty(e.Trigger) ? e.Message : e.Trigger)}"
              + (e.Score > 0 ? $"  (score {e.Score})" : "")
            : e.Message;

        SearchText = string.Join(' ',
            Text, e.Category, e.Image,
            string.Join(' ', e.Techniques), string.Join(' ', e.RuleIds));

        var sb = new StringBuilder();
        sb.Append(e.Category);
        if (e.Techniques.Count > 0) sb.Append("  ·  ").Append(string.Join(", ", e.Techniques));
        if (e.RuleIds.Count > 0) sb.Append("  ·  rules: ").Append(string.Join(", ", e.RuleIds));
        if (!string.IsNullOrEmpty(e.Image)) sb.Append('\n').Append(e.Image);
        Tooltip = sb.ToString();
    }

    /// <summary>One clipboard-ready line.</summary>
    public string ToClipboardLine()
        => $"{Raw.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} [{Level}] {Category} {Text}";
}
