using System.Windows.Input;
using BruceEDR.Activity;

namespace BruceEDR.Gui.ViewModels;

public sealed record StatCard(string Label, string Value, string Sub, string Level);

public sealed record ChartChoice(string Key, string Title, string Blurb);

/// <summary>
/// Insights: the same activity as the maps, as charts. One chart at a time, picked from a short list, each
/// with a line saying what it shows, over a row of numbers for the whole session.
/// </summary>
public sealed class InsightsViewModel : ViewModelBase
{
    private readonly ActivityHub _hub;
    private ActivitySnapshot _snap = ActivitySnapshot.Empty;

    public static IReadOnlyList<ChartChoice> Choices { get; } = new[]
    {
        new ChartChoice("Timeline", "Activity", "How much happened, second by second, and of what kind. Hover a bar for the numbers."),
        new ChartChoice("Heatmap", "Heatmap", "Each kind of activity against time: where it was quiet and where it surged."),
        new ChartChoice("Lifetimes", "Process lifetimes", "Every process as a bar from start to end. Short bars that cluster are things that ran together."),
        new ChartChoice("Processes", "Top processes", "Who did the most. Switch the measure to see who touched files, used the network, or scored highest."),
        new ChartChoice("Files", "Files", "What became of the files that were made, moved or removed, and the kinds of file involved."),
        new ChartChoice("Network", "Network", "Where connections went and which names were looked up.")
    };

    public static IReadOnlyList<ChartChoice> Measures { get; } = new[]
    {
        new ChartChoice("Events", "Everything", ""), new ChartChoice("FileChanges", "File changes", ""),
        new ChartChoice("Network", "Network", ""), new ChartChoice("Score", "Score", "")
    };

    public InsightsViewModel(ActivityHub hub)
    {
        _hub = hub;
        SetChartCommand = new RelayCommandP(p => { if (p is string s) Chart = s; });
        SetMeasureCommand = new RelayCommandP(p => { if (Enum.TryParse<ProcessMetric>(p as string, out var m)) Measure = m; });
        hub.Changed += OnHubChanged;
        OnHubChanged();
    }

    public ActivityHub Hub => _hub;
    public ICommand SetChartCommand { get; }
    public ICommand SetMeasureCommand { get; }

    private string _chart = "Timeline";
    public string Chart
    {
        get => _chart;
        set { if (Set(ref _chart, value)) { OnPropertyChanged(nameof(Blurb)); OnPropertyChanged(nameof(Title)); } }
    }
    public string Title => Choices.FirstOrDefault(c => c.Key == _chart)?.Title ?? "";
    public string Blurb => Choices.FirstOrDefault(c => c.Key == _chart)?.Blurb ?? "";

    private ProcessMetric _measure = ProcessMetric.Events;
    public ProcessMetric Measure
    {
        get => _measure;
        set { if (Set(ref _measure, value)) { OnPropertyChanged(nameof(MeasureKey)); TopProcesses = InsightsData.TopProcesses(_snap, _measure, 15); } }
    }
    public string MeasureKey => _measure.ToString();

    public bool IsEmpty => _snap.IsEmpty;
    public bool HasData => !IsEmpty;

    private IReadOnlyList<StatCard> _cards = Array.Empty<StatCard>();
    public IReadOnlyList<StatCard> Cards { get => _cards; private set => Set(ref _cards, value); }

    private Binned? _timeline;
    public Binned? Timeline { get => _timeline; private set => Set(ref _timeline, value); }
    private Heat? _heat;
    public Heat? Heatmap { get => _heat; private set => Set(ref _heat, value); }
    private IReadOnlyList<Lifetime> _lifetimes = Array.Empty<Lifetime>();
    public IReadOnlyList<Lifetime> Lifetimes { get => _lifetimes; private set => Set(ref _lifetimes, value); }
    private IReadOnlyList<Ranked> _topProcesses = Array.Empty<Ranked>();
    public IReadOnlyList<Ranked> TopProcesses { get => _topProcesses; private set { if (Set(ref _topProcesses, value)) OnPropertyChanged(nameof(NoTopProcesses)); } }
    public bool NoTopProcesses => _topProcesses.Count == 0;
    private IReadOnlyList<Slice> _fileMix = Array.Empty<Slice>();
    public IReadOnlyList<Slice> FileMix { get => _fileMix; private set { if (Set(ref _fileMix, value)) OnPropertyChanged(nameof(NoFiles)); } }
    public bool NoFiles => _fileMix.Count == 0;
    private IReadOnlyList<Ranked> _extensions = Array.Empty<Ranked>();
    public IReadOnlyList<Ranked> Extensions { get => _extensions; private set => Set(ref _extensions, value); }
    private IReadOnlyList<Ranked> _destinations = Array.Empty<Ranked>();
    public IReadOnlyList<Ranked> Destinations { get => _destinations; private set { if (Set(ref _destinations, value)) OnPropertyChanged(nameof(NoNetwork)); } }
    private IReadOnlyList<Ranked> _domains = Array.Empty<Ranked>();
    public IReadOnlyList<Ranked> Domains { get => _domains; private set => Set(ref _domains, value); }
    public bool NoNetwork => _destinations.Count == 0 && _domains.Count == 0;

    private void OnHubChanged()
    {
        _snap = _hub.Snapshot;
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(HasData));
        Timeline = InsightsData.Bin(_snap, 90);
        Heatmap = InsightsData.Heatmap(_snap, 72);
        Lifetimes = InsightsData.Lifetimes(_snap, 45);
        TopProcesses = InsightsData.TopProcesses(_snap, _measure, 15);
        FileMix = InsightsData.FileFates(_snap);
        Extensions = InsightsData.Extensions(_snap, 12);
        Destinations = InsightsData.Top(_snap.Destinations, 12, "watch");
        Domains = InsightsData.Top(_snap.Domains, 12, "renamed");
        Cards = CardsFor(_snap);
    }

    private static IReadOnlyList<StatCard> CardsFor(ActivitySnapshot s)
    {
        if (s.IsEmpty) return Array.Empty<StatCard>();
        var counts = FileMapBuilder.Count(s);
        int flagged = s.Processes.Count(p => p.Flagged), threats = s.Processes.Count(p => p.Level == "threat");
        long net = s.Total(ActivityKind.Network);
        return new[]
        {
            new StatCard("Duration", s.Span.TotalSeconds >= 1 ? ProcessMapBuilder.Duration(s.Span) : "-", s.StartedUtc == default ? "" : "from " + s.StartedUtc.ToLocalTime().ToString("HH:mm:ss"), "info"),
            new StatCard("Processes", s.Processes.Count.ToString("N0"), $"{s.Processes.Count(p => p.ExitUtc is null):N0} still running", "info"),
            new StatCard("Flagged", flagged.ToString("N0"), threats > 0 ? $"{threats} over the contain threshold" : "none over the contain threshold", threats > 0 ? "threat" : flagged > 0 ? "watch" : "safe"),
            new StatCard("Files changed", (counts.Total).ToString("N0"), $"{counts.Deleted + counts.Melted + counts.AfterRun:N0} deleted", "created"),
            new StatCard("Melted", counts.Melted.ToString("N0"), counts.Melted == 0 ? "no program removed itself" : "removed themselves after they ran", counts.Melted > 0 ? "ember" : "safe"),
            new StatCard("Network", net.ToString("N0"), s.Destinations.Count == 0 ? "no connections" : $"to {s.Destinations.Count:N0} destination{(s.Destinations.Count == 1 ? "" : "s")}", "watch")
        };
    }
}
