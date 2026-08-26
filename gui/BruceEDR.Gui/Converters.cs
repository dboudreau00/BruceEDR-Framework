using System.Globalization;
using System.Windows.Data;
using BruceEDR.Gui.ViewModels;

namespace BruceEDR.Gui;

/// <summary>
/// "Is this value equal to the parameter" — drives the selected state of filter chips
/// (EventFilter == "WARN" etc.) without a dedicated bool per chip.
/// </summary>
public sealed class EqualsConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => string.Equals(value?.ToString(), parameter?.ToString(), StringComparison.Ordinal);

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Multi-value form of <see cref="EqualsConverter"/> for chips whose key comes from
/// their own Tag (so it cannot be a ConverterParameter): [activeFilter, chipKey] → bool.
/// </summary>
public sealed class ChipSelectedConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
        => values.Length == 2 && string.Equals(values[0]?.ToString(), values[1]?.ToString(), StringComparison.Ordinal);

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Group-header summary for the tactic-grouped coverage list:
/// "6 of 8 covered · 2 active on this host".
/// </summary>
public sealed class TacticSummaryConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var rows = Rows(value);
        if (rows.Count == 0) return "";
        int covered = rows.Count(t => t.Rules > 0);
        int observed = rows.Count(t => t.Observed > 0);
        var s = $"{covered} of {rows.Count} covered";
        if (observed > 0) s += observed == 1 ? " · 1 active on this host" : $" · {observed} active on this host";
        return s;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();

    internal static List<TechniqueRow> Rows(object? value)
        => value is System.Collections.IEnumerable e
            ? e.OfType<TechniqueRow>().ToList()
            : new List<TechniqueRow>();
}

/// <summary>Coverage fraction (0..100) of a tactic group, for the header progress bar.</summary>
public sealed class TacticProgressConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var rows = TacticSummaryConverter.Rows(value);
        if (rows.Count == 0) return 0d;
        return 100d * rows.Count(t => t.Rules > 0) / rows.Count;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
