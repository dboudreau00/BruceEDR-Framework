using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using BruceEDR.Activity;

namespace BruceEDR.Gui.Views;

/// <summary>The colour of each level the maps and charts speak in, in one place.</summary>
internal static class LevelColors
{
    public static Color Of(string level) => level switch
    {
        "threat" => Color.FromRgb(0xF2, 0x55, 0x5A),
        "watch" => Color.FromRgb(0xF2, 0xB3, 0x3D),
        "safe" => Color.FromRgb(0x34, 0xD3, 0x99),
        "ember" => Color.FromRgb(0xFF, 0x8A, 0x3D),
        "drop" => Color.FromRgb(0xA7, 0x8B, 0xFA),
        "deleted" => Color.FromRgb(0x8A, 0x93, 0xA8),
        "renamed" => Color.FromRgb(0x38, 0xBD, 0xF8),
        "created" => Color.FromRgb(0x34, 0xD3, 0x99),
        "accent" => Color.FromRgb(0x7C, 0x6C, 0xFF),
        _ => Color.FromRgb(0x4C, 0x8D, 0xFF)
    };

    public static Color OfLane(Lane lane) => lane switch
    {
        Lane.Processes => Color.FromRgb(0x4C, 0x8D, 0xFF),
        Lane.FileChanges => Color.FromRgb(0xA7, 0x8B, 0xFA),
        Lane.FileOpens => Color.FromRgb(0x3A, 0x45, 0x63),
        Lane.Network => Color.FromRgb(0xF2, 0xB3, 0x3D),
        _ => Color.FromRgb(0x34, 0xD3, 0x99)
    };

    public static Brush Brush(Color c, byte alpha = 255)
    {
        var b = new SolidColorBrush(Color.FromArgb(alpha, c.R, c.G, c.B));
        b.Freeze();
        return b;
    }
}

/// <summary>What every Insights chart shares: a drawn surface, theme brushes, a hover card.</summary>
public abstract class ChartBase : FrameworkElement
{
    protected static readonly Brush PaperB = LevelColors.Brush(Color.FromRgb(0xE8, 0xEC, 0xF5));
    protected static readonly Brush MistB = LevelColors.Brush(Color.FromRgb(0x99, 0xA2, 0xB8));
    protected static readonly Brush FaintB = LevelColors.Brush(Color.FromRgb(0x5C, 0x64, 0x79));
    protected static readonly Brush CardB = LevelColors.Brush(Color.FromRgb(0x0B, 0x0E, 0x18), 0xF2);
    protected static readonly Pen GridPen = Frozen(new Pen(LevelColors.Brush(Color.FromRgb(0x23, 0x29, 0x38), 0xB0), 1));
    protected static readonly Pen CardPen = Frozen(new Pen(LevelColors.Brush(Color.FromRgb(0x2A, 0x31, 0x44)), 1));

    protected Point Mouse = new(-1, -1);
    protected bool Over;

    protected static Pen Frozen(Pen p) { p.Freeze(); return p; }

    protected ChartBase()
    {
        ClipToBounds = true;
        Focusable = false;
    }

    protected FormattedText Text(string s, double size, Brush brush, bool mono = false, bool bold = false)
        => ChartInk.Text(this, s, size, brush, mono, bold ? FontWeights.SemiBold : FontWeights.Normal);

    protected override void OnMouseMove(MouseEventArgs e) { Mouse = e.GetPosition(this); Over = true; InvalidateVisual(); }
    protected override void OnMouseLeave(MouseEventArgs e) { Over = false; InvalidateVisual(); }

    protected void Tip(DrawingContext dc, string title, IReadOnlyList<(Brush? Swatch, string Text)> rows)
    {
        var head = Text(title, 12, PaperB, bold: true);
        var lines = rows.Select(r => Text(r.Text, 11, MistB, mono: true)).ToList();
        double w = Math.Max(head.Width, lines.Count == 0 ? 0 : lines.Max(l => l.Width + 16)) + 24;
        double h = head.Height + lines.Sum(l => l.Height + 2) + 20;
        double x = Mouse.X + 16, y = Mouse.Y + 14;
        if (x + w > ActualWidth - 6) x = Mouse.X - w - 12;
        if (y + h > ActualHeight - 6) y = Mouse.Y - h - 10;
        var card = new Rect(Math.Max(6, x), Math.Max(6, y), w, h);
        dc.DrawRoundedRectangle(CardB, CardPen, card, 8, 8);
        dc.DrawText(head, new Point(card.X + 12, card.Y + 9));
        double ly = card.Y + 9 + head.Height + 4;
        for (int i = 0; i < lines.Count; i++)
        {
            if (rows[i].Swatch is { } sw) dc.DrawEllipse(sw, null, new Point(card.X + 16, ly + lines[i].Height / 2), 3.5, 3.5);
            dc.DrawText(lines[i], new Point(card.X + (rows[i].Swatch is null ? 12 : 26), ly));
            ly += lines[i].Height + 2;
        }
    }

    protected static string Clock(DateTime utc, TimeSpan span)
        => utc.ToLocalTime().ToString(span.TotalMinutes < 3 ? "HH:mm:ss" : "HH:mm", CultureInfo.InvariantCulture);

    protected static string Nice(long n) => n >= 10_000 ? (n / 1000.0).ToString("0.#", CultureInfo.InvariantCulture) + "k" : n.ToString("N0", CultureInfo.InvariantCulture);
}

/// <summary>Activity over time, stacked by what kind of thing happened.</summary>
public sealed class StackedTimeline : ChartBase
{
    public static readonly DependencyProperty DataProperty = DependencyProperty.Register(
        nameof(Data), typeof(Binned), typeof(StackedTimeline), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public Binned? Data { get => (Binned?)GetValue(DataProperty); set => SetValue(DataProperty, value); }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        var data = Data;
        if (data is null || data.Count == 0 || w < 80 || h < 60) return;

        const double left = 44, top = 14, bottom = 30;
        double plotW = w - left - 12, plotH = h - top - bottom;
        if (plotW <= 2 || plotH <= 2) return;
        // Whole-number gridlines (0, 2, 4, 6), and the bars are scaled to the top one so they line up with the labels.
        var (step, peak) = AxisScale.Nice(data.Peak);
        for (int value = 0; value <= peak; value += step)
        {
            double y = top + plotH - plotH * value / peak;
            dc.DrawLine(GridPen, new Point(left, y), new Point(w - 12, y));
            var t = Text(Nice(value), 10, FaintB, mono: true);
            dc.DrawText(t, new Point(left - t.Width - 8, y - t.Height / 2));
        }

        double slot = plotW / data.Count, bar = Math.Max(1.5, slot - (slot > 6 ? 1.5 : 0.4));
        var lanes = Enum.GetValues<Lane>();
        int hot = Over && Mouse.X >= left && Mouse.X <= left + plotW ? Math.Min(data.Count - 1, (int)((Mouse.X - left) / slot)) : -1;
        for (int b = 0; b < data.Count; b++)
        {
            double x = left + b * slot + (slot - bar) / 2, y = top + plotH;
            if (b == hot) dc.DrawRoundedRectangle(LevelColors.Brush(Color.FromRgb(0x7C, 0x6C, 0xFF), 0x20), null, new Rect(left + b * slot, top, slot, plotH), 3, 3);
            foreach (var lane in lanes)
            {
                int v = data.Bins[b][(int)lane];
                if (v == 0) continue;
                double hh = Math.Max(1, plotH * v / peak);
                y -= hh;
                dc.DrawRoundedRectangle(LevelColors.Brush(LevelColors.OfLane(lane)), null, new Rect(x, y, bar, hh), Math.Min(1.5, bar / 2), Math.Min(1.5, bar / 2));
            }
        }

        // The time axis: start, middle, end.
        var span = TimeSpan.FromTicks(data.Step.Ticks * data.Count);
        foreach (double f in new[] { 0.0, 0.5, 1.0 })
        {
            var label = Text(Clock(data.EdgeOf((int)Math.Round(f * data.Count)), span), 10, FaintB, mono: true);
            double x = left + plotW * f - (f == 0 ? 0 : f == 1 ? label.Width : label.Width / 2);
            dc.DrawText(label, new Point(x, top + plotH + 8));
        }

        if (hot >= 0)
        {
            var rows = lanes.Where(l => data.Bins[hot][(int)l] > 0)
                            .Select(l => ((Brush?)LevelColors.Brush(LevelColors.OfLane(l)), $"{data.Bins[hot][(int)l],8:N0}  {InsightsData.Label(l)}")).ToList();
            Tip(dc, Clock(data.EdgeOf(hot), span) + (data.Step.TotalSeconds >= 2 ? $"  (+{data.Step.TotalSeconds:0} s)" : ""), rows);
        }
    }
}

/// <summary>How busy each kind of activity was, when: a row per kind, a cell per slice of time.</summary>
public sealed class HeatmapChart : ChartBase
{
    public static readonly DependencyProperty DataProperty = DependencyProperty.Register(
        nameof(Data), typeof(Heat), typeof(HeatmapChart), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public Heat? Data { get => (Heat?)GetValue(DataProperty); set => SetValue(DataProperty, value); }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        var heat = Data;
        if (heat is null || heat.Columns <= 0 || heat.Rows.Count == 0 || w < 120) return;

        var labels = heat.Rows.Select(r => Text(r, 11, MistB)).ToList();
        double left = labels.Max(l => l.Width) + 22, top = 8, bottom = 28;
        double plotW = w - left - 12, rowH = Math.Min(34, (h - top - bottom) / heat.Rows.Count);
        if (plotW <= 4 || h - top <= 4 || rowH <= 4) return;
        double cell = plotW / heat.Columns;
        var accent = Color.FromRgb(0x7C, 0x6C, 0xFF);

        for (int r = 0; r < heat.Rows.Count; r++)
        {
            double y = top + r * rowH;
            dc.DrawText(labels[r], new Point(left - labels[r].Width - 10, y + (rowH - labels[r].Height) / 2));
            dc.DrawRoundedRectangle(LevelColors.Brush(Color.FromRgb(0x14, 0x19, 0x27)), null, new Rect(left, y + 2, plotW, Math.Max(1, rowH - 4)), 4, 4);
        }

        HeatCell? hot = null;
        foreach (var c in heat.Cells)
        {
            double x = left + c.Column * cell, y = top + c.Row * rowH;
            double t = Math.Pow(c.Value / (double)Math.Max(1, heat.Max), 0.55);
            var rect = new Rect(x, y + 2, Math.Max(1, cell - 0.6), Math.Max(1, rowH - 4));
            dc.DrawRectangle(LevelColors.Brush(accent, (byte)(40 + 215 * t)), null, rect);
            if (Over && rect.Contains(Mouse)) hot = c;
        }

        var span = TimeSpan.FromTicks(heat.Step.Ticks * heat.Columns);
        foreach (double f in new[] { 0.0, 0.5, 1.0 })
        {
            var label = Text(Clock(heat.StartUtc + TimeSpan.FromTicks((long)(span.Ticks * f)), span), 10, FaintB, mono: true);
            double x = left + plotW * f - (f == 0 ? 0 : f == 1 ? label.Width : label.Width / 2);
            dc.DrawText(label, new Point(x, top + heat.Rows.Count * rowH + 8));
        }

        if (hot is { } cellHit)
            Tip(dc, heat.Rows[cellHit.Row], new (Brush?, string)[]
            {
                (null, $"{cellHit.Value:N0} in this slice"),
                (null, Clock(heat.StartUtc + TimeSpan.FromTicks(heat.Step.Ticks * cellHit.Column), span))
            });
    }
}

/// <summary>Each process as a bar from when it started to when it ended, so what ran together is visible at once.</summary>
public sealed class LifetimeChart : ChartBase
{
    public static readonly DependencyProperty DataProperty = DependencyProperty.Register(
        nameof(Data), typeof(IReadOnlyList<Lifetime>), typeof(LifetimeChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender));
    public IReadOnlyList<Lifetime>? Data { get => (IReadOnlyList<Lifetime>?)GetValue(DataProperty); set => SetValue(DataProperty, value); }

    private const double RowH = 26, Top = 26;

    protected override Size MeasureOverride(Size availableSize)
        => new(double.IsInfinity(availableSize.Width) ? 400 : availableSize.Width, Top + 8 + (Data?.Count ?? 0) * RowH);

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, ActualHeight));
        var rows = Data;
        if (rows is null || rows.Count == 0 || w < 200) return;

        double end = Math.Max(1, rows.Max(r => r.End));
        const double labelW = 170, right = 14;
        double plotL = labelW + 12, plotW = w - plotL - right;
        if (plotW <= 4 || RowH <= 4) return;
        double X(double s) => plotL + plotW * s / end;

        for (int i = 0; i <= 4; i++)
        {
            double x = plotL + plotW * i / 4;
            dc.DrawLine(GridPen, new Point(x, Top - 6), new Point(x, ActualHeight - 4));
            var t = Text(ProcessMapBuilder.Duration(TimeSpan.FromSeconds(end * i / 4)), 10, FaintB, mono: true);
            dc.DrawText(t, new Point(Math.Min(x - t.Width / 2, w - t.Width), 2));
        }

        Lifetime? hot = null;
        for (int i = 0; i < rows.Count; i++)
        {
            var r = rows[i];
            double y = Top + i * RowH;
            var c = LevelColors.Of(r.Process.Level);
            var name = Text(Shorten(r.Process.Name.Length > 0 ? r.Process.Name : $"pid {r.Process.Pid}", 22), 11.5,
                r.Process.Flagged ? PaperB : MistB, bold: r.Process.Flagged);
            double indent = Math.Min(r.Depth, 6) * 7;
            dc.DrawText(name, new Point(8 + indent, y + (RowH - name.Height) / 2));

            double x0 = X(r.Start), x1 = Math.Max(x0 + 3, X(r.End));
            var bar = new Rect(x0, y + 5, x1 - x0, RowH - 10);
            bool flagged = r.Process.Flagged;
            dc.DrawRoundedRectangle(LevelColors.Brush(c, (byte)(flagged ? 0xD0 : 0x7A)), null, bar, 4, 4);
            if (r.Open)
                dc.DrawGeometry(LevelColors.Brush(c), null, Arrow(bar));
            if (Over && Mouse.Y >= y && Mouse.Y < y + RowH) { hot = r; dc.DrawRectangle(LevelColors.Brush(Color.FromRgb(0x7C, 0x6C, 0xFF), 0x14), null, new Rect(0, y, w, RowH)); }
        }

        if (hot is { } l)
        {
            var p = l.Process;
            var tip = new List<(Brush?, string)> { (null, $"pid {p.Pid}  ·  {(l.Open ? "still running" : "ran " + ProcessMapBuilder.Duration(TimeSpan.FromSeconds(l.End - l.Start)))}") };
            if (p.Score > 0) tip.Add((null, $"score {p.Score}"));
            if (p.Image.Length > 0) tip.Add((null, Shorten(p.Image, 56)));
            Tip(dc, p.Name.Length > 0 ? p.Name : $"pid {p.Pid}", tip);
        }
    }

    private static Geometry Arrow(Rect bar)
    {
        var g = new StreamGeometry();
        using (var c = g.Open())
        {
            c.BeginFigure(new Point(bar.Right, bar.Top + 1), true, true);
            c.LineTo(new Point(bar.Right + 7, bar.Top + bar.Height / 2), true, false);
            c.LineTo(new Point(bar.Right, bar.Bottom - 1), true, false);
        }
        g.Freeze();
        return g;
    }

    private static string Shorten(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";
}

/// <summary>A ranking as horizontal bars: the top processes, destinations, domains, extensions.</summary>
public sealed class BarList : ChartBase
{
    public static readonly DependencyProperty ItemsProperty = DependencyProperty.Register(
        nameof(Items), typeof(IReadOnlyList<Ranked>), typeof(BarList),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender));
    public IReadOnlyList<Ranked>? Items { get => (IReadOnlyList<Ranked>?)GetValue(ItemsProperty); set => SetValue(ItemsProperty, value); }

    private const double RowH = 34;

    protected override Size MeasureOverride(Size availableSize)
        => new(double.IsInfinity(availableSize.Width) ? 300 : availableSize.Width, Math.Max(40, (Items?.Count ?? 0) * RowH + 6));

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, ActualHeight));
        var items = Items;
        if (items is null || items.Count == 0 || w < 120) return;

        long max = Math.Max(1, items.Max(i => i.Value));
        double valueW = items.Max(i => Text(Nice(i.Value), 11, MistB, mono: true).Width) + 8;
        double trackW = w - valueW - 10;
        if (trackW <= 2) return;
        Ranked? hotItem = null;
        double hotY = 0;
        for (int i = 0; i < items.Count; i++)
        {
            var it = items[i];
            double y = 3 + i * RowH;
            var c = LevelColors.Of(it.Level);
            var label = Text(it.Label, 12, PaperB);
            label.MaxTextWidth = Math.Max(40, w - valueW - 24);
            label.MaxLineCount = 1;
            label.Trimming = TextTrimming.CharacterEllipsis;
            dc.DrawText(label, new Point(2, y));

            double bw = trackW;
            dc.DrawRoundedRectangle(LevelColors.Brush(Color.FromRgb(0x14, 0x19, 0x27)), null, new Rect(2, y + 19, bw, 7), 3.5, 3.5);
            double fill = Math.Max(4, bw * it.Value / max);
            if (fill > 0) dc.DrawRoundedRectangle(LevelColors.Brush(c), null, new Rect(2, y + 19, Math.Min(fill, bw), 7), 3.5, 3.5);
            var val = Text(Nice(it.Value), 11, MistB, mono: true);
            dc.DrawText(val, new Point(w - val.Width - 2, y + 1));

            if (Over && Mouse.Y >= y - 2 && Mouse.Y < y + RowH - 2 && it.Detail.Length > 0) { hotItem = it; hotY = y; }
        }
        // The card goes last, so the rows below the hovered one cannot paint over it.
        if (hotItem is { } hit)
            Tip(dc, hit.Label, new (Brush?, string)[] { (null, $"{hit.Value:N0}  ·  {hit.Detail}") });
    }
}

/// <summary>A ring split into shares, with the total in the middle and a key beside it.</summary>
public sealed class DonutChart : ChartBase
{
    public static readonly DependencyProperty SlicesProperty = DependencyProperty.Register(
        nameof(Slices), typeof(IReadOnlyList<Slice>), typeof(DonutChart), new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));
    public static readonly DependencyProperty CaptionProperty = DependencyProperty.Register(
        nameof(Caption), typeof(string), typeof(DonutChart), new FrameworkPropertyMetadata("files", FrameworkPropertyMetadataOptions.AffectsRender));
    public IReadOnlyList<Slice>? Slices { get => (IReadOnlyList<Slice>?)GetValue(SlicesProperty); set => SetValue(SlicesProperty, value); }
    public string Caption { get => (string)GetValue(CaptionProperty); set => SetValue(CaptionProperty, value); }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        var slices = Slices;
        if (slices is null || slices.Count == 0 || w < 160 || h < 100) return;

        long total = slices.Sum(s => s.Value);
        if (total <= 0) return;
        double size = Math.Min(h - 8, w * 0.5);
        var center = new Point(size / 2 + 6, h / 2);
        double outer = size / 2, inner = outer * 0.64, mid = (outer + inner) / 2;
        double angle = -90;
        int hot = -1;
        if (Over)
        {
            var d = Mouse - center;
            double r = d.Length;
            if (r >= inner && r <= outer)
            {
                double a = (Math.Atan2(d.Y, d.X) * 180 / Math.PI + 90 + 360) % 360, run = 0;
                for (int i = 0; i < slices.Count; i++) { run += 360.0 * slices[i].Value / total; if (a < run) { hot = i; break; } }
            }
        }

        for (int i = 0; i < slices.Count; i++)
        {
            double sweep = 360.0 * slices[i].Value / total;
            var c = LevelColors.Of(slices[i].Level);
            double gap = slices.Count > 1 ? Math.Min(2.2, sweep / 3) : 0;
            var pen = Frozen(new Pen(LevelColors.Brush(c, (byte)(i == hot ? 255 : 220)), (outer - inner) * (i == hot ? 1.0 : 0.9)) { StartLineCap = PenLineCap.Flat, EndLineCap = PenLineCap.Flat });
            // One slice covering the whole ring is a degenerate 360-degree arc that WPF draws as nothing: use a circle.
            if (sweep - gap >= 359.5) dc.DrawEllipse(null, pen, center, mid, mid);
            else dc.DrawGeometry(null, pen, Arc(center, mid, angle + gap / 2, Math.Max(0.5, sweep - gap)));
            angle += sweep;
        }

        var num = Text(Nice(total), 22, PaperB, mono: true, bold: true);
        var cap = Text(Caption, 11, MistB);
        dc.DrawText(num, new Point(center.X - num.Width / 2, center.Y - num.Height / 2 - 6));
        dc.DrawText(cap, new Point(center.X - cap.Width / 2, center.Y + num.Height / 2 - 8));

        const double pitch = 36;
        double ky = Math.Max(8, h / 2 - slices.Count * pitch / 2), kx = size + 34;
        for (int i = 0; i < slices.Count; i++)
        {
            var c = LevelColors.Of(slices[i].Level);
            double top = ky + i * pitch;
            dc.DrawEllipse(LevelColors.Brush(c), null, new Point(kx, top + 9), 5, 5);
            var name = Text(slices[i].Label, 12, i == hot ? PaperB : MistB);
            var val = Text($"{slices[i].Value:N0}  ({100.0 * slices[i].Value / total:0}%)", 10.5, FaintB, mono: true);
            dc.DrawText(name, new Point(kx + 14, top));
            dc.DrawText(val, new Point(kx + 14, top + name.Height + 1));
        }
    }

    private static Geometry Arc(Point c, double r, double startDeg, double sweepDeg)
    {
        sweepDeg = Math.Min(sweepDeg, 359.99);
        Point P(double deg) => new(c.X + r * Math.Cos(deg * Math.PI / 180), c.Y + r * Math.Sin(deg * Math.PI / 180));
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(P(startDeg), false, false);
            ctx.ArcTo(P(startDeg + sweepDeg), new Size(r, r), 0, sweepDeg > 180, SweepDirection.Clockwise, true, false);
        }
        g.Freeze();
        return g;
    }
}
