using System.Globalization;
using System.Text.RegularExpressions;
using System.Windows.Data;
using BruceEDR.Assistant;

namespace BruceEDR.Gui.Views;

/// <summary>[speed, chip tag] to bool: marks the speed chip that matches the playback speed.</summary>
public sealed class TriageSpeedConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object? parameter, CultureInfo culture)
        => values.Length == 2 && values[0] is double speed
           && double.TryParse(values[1]?.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out double chip)
           && Math.Abs(speed - chip) < 0.001;

    public object[] ConvertBack(object value, Type[] targetTypes, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Splits the line the model is writing into its key and its words: "STEP 3: The script" reads
/// as "STEP 3" (parameter "label") and "The script". A key still being typed shows nothing.
/// </summary>
public sealed class TriageTypingConverter : IValueConverter
{
    private static readonly Regex Prefix = new(@"^(HEADLINE|IMPACT|NEXT|STEP\s*\d{1,2}|\d{1,2})\s*[:.)\-]\s*",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        string line = value as string ?? "";
        bool label = parameter as string == "label";
        var m = Prefix.Match(line);
        if (m.Success)
        {
            if (!label) return line[m.Length..];
            string key = m.Groups[1].Value.ToUpperInvariant();
            return char.IsDigit(key[0]) ? "STEP " + key : Regex.Replace(key, @"\s+", " ");
        }
        if (label) return "";
        return line.Length <= 12 && line.All(c => char.IsUpper(c) || char.IsDigit(c) || c == ' ') ? "" : line;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>The running score after each step of an incident, for the library sparkline.</summary>
public sealed class TriageScoreTrailConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is IncidentCase c ? c.Steps.Select(s => (double)s.ScoreAfter).Prepend(0d).ToArray() : null;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
