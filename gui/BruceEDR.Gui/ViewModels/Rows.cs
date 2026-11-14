using System.Text;
using BruceEDR.Core;
using BruceEDR.Detection;
using BruceEDR.Telemetry;

namespace BruceEDR.Gui.ViewModels;

/// <summary>An ATT&amp;CK id with its catalogue name, for detail chips.</summary>
public sealed record TechniqueChip(string Id, string Name, string Url);

/// <summary>One process in the ancestry chain; the last one is the flagged process itself.</summary>
public sealed record LineageStep(string Name, bool IsSubject);

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
    public string Trust => Trusted ? "signed" : "unsigned";
    public string ImagePath { get; private set; } = "";
    public string CommandLine { get; private set; } = "";
    public string IncidentId { get; private set; } = "";
    public string FirstSeen { get; private set; } = "";
    public IReadOnlyList<string> Reasons { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> StagedArchives { get; private set; } = Array.Empty<string>();
    /// <summary>MITRE ATT&amp;CK technique ids observed for this process.</summary>
    public IReadOnlyList<string> Techniques { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<TechniqueChip> TechniqueChips { get; private set; } = Array.Empty<TechniqueChip>();
    /// <summary>Ancestry rendered oldest-first, e.g. "explorer.exe > cmd.exe > this.exe".</summary>
    public string Ancestry { get; private set; } = "";
    public IReadOnlyList<LineageStep> Lineage { get; private set; } = Array.Empty<LineageStep>();
    public bool HasAncestry => Lineage.Count > 1;
    public bool HasCommandLine => CommandLine.Length > 0;
    public bool HasTechniques => Techniques.Count > 0;
    public bool HasIncident => IncidentId.Length > 0;

    public ThreatRow(ProfileSnapshot s, int containAt)
    {
        Pid = s.Pid;
        Update(s, containAt);
    }

    public void Update(ProfileSnapshot s, int containAt)
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
        if (!Techniques.SequenceEqual(s.Techniques))
        {
            Techniques = s.Techniques;
            TechniqueChips = s.Techniques
                .Select(id => { var t = AttackCatalog.Lookup(id); return new TechniqueChip(t.Id, t.Name, t.Url); })
                .ToArray();
        }
        var chain = s.Ancestry.Reverse().Append(s.ProcessName).ToArray();
        string ancestry = s.Ancestry.Count > 0 ? string.Join(" > ", chain) : "";
        if (ancestry != Ancestry)
        {
            Ancestry = ancestry;
            Lineage = chain.Select((n, i) => new LineageStep(n, i == chain.Length - 1)).ToArray();
        }
        State = s.Terminated ? "Terminated"
              : s.SuspendedByAnalyst ? "Suspended"
              : s.Contained ? (s.ContainmentSkipped ? "Would contain" : "Contained")
              : "Flagged";
        Severity = s.Terminated ? "safe"
                 : s.Contained ? "threat"
                 : s.Trusted ? "safe"
                 : s.Score >= containAt ? "threat"
                 : "watch";

        OnPropertyChanged(string.Empty);
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
        sb.AppendLine($"BruceEDR incident report, {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"process   : {Name} (pid {Pid})");
        if (IncidentId.Length > 0) sb.AppendLine($"incident  : {IncidentId}");
        sb.AppendLine($"state     : {State}   score {Score} (peak {PeakScore})   {Trust}");
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
    public BruceEvent Raw { get; }
    public string Time { get; }
    public string Level { get; }       // QUARANTINE | WARN | ACTION | ERROR | INFO
    public string LevelLabel { get; }
    public string Category { get; }
    public string Text { get; }

    public bool HasProcess { get; }
    public string Process { get; }
    public int Pid { get; }
    public string Detail { get; }
    public int Score { get; }
    public bool HasScore => Score > 0;

    private readonly DateTime _arrivedUtc = DateTime.UtcNow;
    /// <summary>True for a couple of seconds after arrival, so only new rows flash, not a re-filtered list.</summary>
    public bool IsFresh => DateTime.UtcNow - _arrivedUtc < TimeSpan.FromSeconds(2);

    /// <summary>Everything worth grepping, so the search box finds rules/techniques too.</summary>
    public string SearchText { get; }

    /// <summary>Hover detail: category plus the rule/technique context the row elides.</summary>
    public string Tooltip { get; }

    public EventRow(BruceEvent e)
    {
        Raw = e;
        Time = e.TimeUtc.ToLocalTime().ToString("HH:mm:ss");
        Level = e.Level;
        LevelLabel = e.Level switch
        {
            "QUARANTINE" => "QUARANTINE",
            "WARN" => "WARN",
            "ACTION" => "ACTION",
            "ERROR" => "ERROR",
            _ => "INFO",
        };
        Category = e.Category;
        HasProcess = e.Pid > 0;
        Pid = e.Pid;
        Process = e.Process;
        Detail = HasProcess && !string.IsNullOrEmpty(e.Trigger) ? e.Trigger : e.Message;
        Score = e.Score;
        Text = HasProcess
            ? $"pid {e.Pid} {e.Process}: {Detail}" + (e.Score > 0 ? $"  (score {e.Score})" : "")
            : e.Message;

        SearchText = string.Join(' ',
            Text, e.Category, e.Image,
            string.Join(' ', e.Techniques), string.Join(' ', e.RuleIds));

        var sb = new StringBuilder();
        sb.Append(e.Category);
        if (e.Techniques.Count > 0) sb.Append("  ·  ").Append(string.Join(", ", e.Techniques));
        if (e.RuleIds.Count > 0) sb.Append("  ·  rules: ").Append(string.Join(", ", e.RuleIds));
        if (HasProcess && !string.IsNullOrEmpty(e.Trigger) && e.Message != e.Trigger) sb.Append('\n').Append(e.Message);
        if (!string.IsNullOrEmpty(e.Image)) sb.Append('\n').Append(e.Image);
        Tooltip = sb.ToString();
    }

    /// <summary>One clipboard-ready line.</summary>
    public string ToClipboardLine()
        => $"{Raw.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} [{Level}] {Category} {Text}";
}
